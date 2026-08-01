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
- KP #57 dump pull pending; its crash signature (trylock +0x12c vs
  get_task_struct +0x4a4 vs another vmemmap scribble) tells which
  tenant the walk actually found in the target page this time.

## Files Modified

All S9280-related changes are uncommitted working-tree changes (the
checkout is CRLF, so plain `git diff` shows whole-file noise — use
`git diff -w`). Do not commit yet.

| File | Changes |
|------|---------|
| `src/targets/e3q-S9280ZCS6DZF2/` | New target (untracked): header, fingerprint; `P0_ORACLE_GATE_PAGE_OFF` 0x0e80 -> 0x1e80 (fix #15); `KSNITCH_COLLISIONS` 4 -> 6 (fix #27) |
| `src/common.h` | `MM_STRUCT_SLAB_SZ`; runtime knobs (`SKB_RECLAIM_SENDS`, `MM_DRAIN_TRIGGERS`, `KSNITCH_DEFAULT_PROFILE`); `exploit_core()` declaration; `KSNITCH_COLLISIONS` now `#ifndef`-guarded (fix #27) |
| `src/fops.c` | Shift-aware `prepare_pselect_fdsets`, pipe fill before pselect, consumer completion wait |
| `src/util.c` | KernelSnitch bruteforce stride `MM_STRUCT_SZ` -> `MM_STRUCT_SLAB_SZ` (fix #9); `EXPLOIT_CORE`/`exploit_core()`; cleanup before sends; knob plumbing; `SKB_SNDBUF` env override; `P0_ORACLE_PARENT_PIPEBUF` reclaim-vs-walk diagnostic knob; fix #19 reclaim ordering (neighbours freed before drain pressure; supersedes reverted fix #18); fix #21 `LATE_NEIGHBOUR_FREE` (drains first, `close(memfd_leak)` last so the empty target slab is discarded to the buddy allocator); fix #22 `COMPACT_PAYLOAD` (4 KB walk image + anon-fault reclaim, shelved); fix #23 `SKB_RECLAIM_SOCKS` (up to 8 socketpairs multiplying the queued frag volume); fix #26 `DGRAM_RECLAIM` (content-controlled dgram data kmalloc spray); fix #28 `SLABINFO_DIAG` (three-point slab census); fix #29 `RECLAIM_WAVES` (periodic reclaim bursts across the arming window); fix #30 `RECLAIM_WAVE_ANON` (per-wave 2 MB anon image faults + 4 MB wave SO_SNDBUF) |
| `src/pipe.c` | `objs_per_slab` uses `MM_STRUCT_SLAB_SZ`; pipe page child lifecycle aligned with `prepare_kernel_page` (fix #10); gate diagnostic continues past tee/read failures with `tee_failures` counter (fix #13); fix #31 gate tenant identification dump (non-zero byte count + qwords at +0x40/+0x980/+0x9C0/+0xA20 on marker miss) |
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
