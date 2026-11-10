# Linux session 3 (2026-11-10) — the game DOES launch; stage 8 deadlocks it on wine

**Bottom line:** the operator's "doesn't boot" was never a launch failure. On wine 10 the boot
stalls at `Main.txt` line 18 only when `AOE2LAN_STAGE=8` (the in-DLL login shim) is active; with
the shim off (stage 1 DLL inert, stage 7 IAT only) the game reaches the main menu in under a
minute on `pfx-wine10` (operator saw it twice and quit after launching; greyed Multiplayer is
correct there — no login server runs at those stages). The stage-8 stall is a wine-side
busy-poll: a game thread spins `fsync_msgwait` ~4,000×/s against wineserver (397k requests in
100 s, that thread does *nothing else*), wineserver burns ~35% CPU, every other game thread
parks waiting on wineserver, and our own DLL threads go silent on wine (`hb alive` = 0 vs 29 on
Windows). The poller exists **only** when the stage-8 server is active: a stage-7 `+server`
trace has zero `fsync_msgwait` lines in 120 MB. The fix lives in W1's DLL (threading/wait model
vs wine's fsync+wineserver); see 3h.

## 3a. Run A — stage 8 default (wine10 + pfx-wine10 + DLL), the "doesn't boot" run

- Operator symptom: game never shows a window; run 2's log showed the boot stopping at
  `Main.txt` line 18. Reproduced: with stage 8 the game stalls at line 18 on wine 10.
- `Main.txt` line 18 = `[Main.txt] ... setup chat` — the boot stops mid-`Main.txt` setup, before
  the window appears.

## 3b. Audio-backend hypothesis — dead

- `Audio=null` (no audio backend) changes nothing: stage 8 still stalls at 18, stage 7 still
  boots. The audio backend is not the trigger.

## 3c. Bisect ladder (oracle = `Main.txt` line count > 18; each run killed by me)

| stage | what runs | result on wine 10 |
|---|---|---|
| 1 | DLL inert | boots to main menu (<60 s); operator saw it, quit after launching |
| 7 | IAT only | boots to main menu (<60 s); operator saw it, quit after launching |
| 8 | login shim | stalls at `Main.txt` 18; no window |

- So the culprit is the stage-8 in-DLL server, not the IAT, not the DLL load, not the prefix.

## 3d. Run D forensics — the deadlock is inside wine's server loop, not the network

- wineserver at ~35% CPU spinning but *responsive* (a `wine reg query` in the same prefix answers
  in 0.26 s); sockets fully idle; no network wait anywhere.
- Our own DLL threads go silent on wine after a few seconds: `hb alive` = 0 in the stall run vs
  29 in a Windows run that boots. The silence is wine-side, not our code going quiet on Windows.

## 3e. Run F — `WINEDEBUG=+server` names the spin: `fsync_msgwait` busy-poll

- Stage-8 trace (692,666 lines): thread `0144` polls `fsync_msgwait` ~4,000×/s (397k requests in
  100 s). The poll starts right after `0144: get_message() = PENDING` +
  `get_window_info(00010042)` — window `0x10042` is owned by thread `00e8`; `0144` msg-waits on a
  window another thread owns. `fsync_msgwait() = 0` returns immediately, forever: the loop never
  blocks. On Windows this wait blocks properly; under wine fsync it spins.
- Stage-7 trace (120 MB, operator quit after launching): **zero** `fsync_msgwait` lines. Top
  requests: `set_queue_mask` 138k, `enum_key_value` 118k, `close_handle` 102k, `select` 41k — a
  healthy wine run has no msgwait poller at all.
- => the poller exists only when the stage-8 in-DLL server is active. The parked-thread chain:
  the window's owner (`00e8`) never posts the message `0144` waits for, so `0144` polls and the
  boot stalls.

## 3f. Tooling notes for the next Linux session

- `pgrep -f 'AoE2DE_s.exe'` matches the python launcher — use `pgrep -x`.
- No `xwininfo`/`xdotool` on this box (use `import` + `identify` for window screenshots).
- The shim's 900/1400-line log caps are burned by t≈3.6 s on Linux; post-boot visibility needs
  strace or `WINEDEBUG=+server` (the `+server` trace is what named the poller).
- Interim boot without login: `AOE2LAN_STAGE=1` or `7` on `pfx-wine10` reaches the menu; use it
  to test anything menu-side.

## 3g. Corrected conclusions

1. The game launches on wine 10; stage 8 deadlocks the boot at `Main.txt` 18.
2. Two measured signatures of the stall: (a) a game thread spins `fsync_msgwait` ~4k/s on a
   window owned by another thread (wine fsync returns immediately instead of blocking);
   (b) every other game thread parks waiting on wineserver while wineserver spins at ~35% CPU.
3. The poller is server-triggered: stage 7 has zero `fsync_msgwait` in 120 MB.
4. Exonerated: the IAT swap (stage 7 boots), the audio backend (`Audio=null` changes nothing),
   ntsync on/off, and the prefix/DLL mismatch theory for run 2 remains an artifact.
5. The fix lives in W1's DLL (threading/wait model vs wine's fsync+wineserver).

## 3h. Asks for W1 (Windows worker)

- Which thread msg-waits on window `0x10042` (owned by thread `00e8`), and why under wine fsync
  that wait becomes an immediate-return spin instead of a block? The parked-thread chain:
  `00e8` never posts the message `0144` waits for — what posts it on Windows?
- Why do our own DLL threads go silent on wine (`hb alive` = 0 vs 29 on Windows) after a few
  seconds, even in runs that boot? Suspects: the wait model vs wine's fsync+wineserver.
- The stage-8 in-DLL server is the trigger for the poller (stage 7 has none): what does the
  server thread do at boot that creates the cross-thread message wait?
