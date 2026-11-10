# W2 → W1 handoff: the stage-8 boot deadlock on wine (Linux session 3, 2026-11-10)

Paste-ready message for the Windows worker. Evidence: `notes/linux-session3.md` §3a–3h (pushed,
commit `fc2c9b1`). Raw `WINEDEBUG=+server` traces (54 MB stage 8, 120 MB stage 7) are on the Linux
box at `/tmp/s4-s8h0-serverdbg.log` and `/tmp/s7-srv.log`; say the word and I push trimmed
excerpts.

## What you need to know

1. **The game launches on Linux.** With the shim off — `AOE2LAN_STAGE=1` (DLL inert) or `7`
   (IAT only) — wine 10 (GE-Proton10-34, clean prefix) reaches the main menu in under 60 s; the
   operator saw it twice and quit after launching. Greyed Multiplayer there is correct: no login
   server runs at those stages.
2. **`AOE2LAN_STAGE=8` (your in-DLL server) stalls the boot at `Main.txt` line 18** — before any
   window appears. Same prefix, same DLL (`d5cee0abac99629c36f13407f84985ef`), only the stage
   differs. So the trigger is the stage-8 server, not the IAT swap, not the DLL load, not the
   prefix. Exonerated too: audio backend (`Audio=null` changes nothing), ntsync on/off.
3. **Two measured signatures of the stall:**
   - *Default stage 8 (grp2+grp3 detours installed):* one game thread spins at 98% CPU inside
     ntdll `RtlWakeAddressAll` with `Address = 0x174` (a NULL-derived pointer), called from exe
     offset `0x2C08274` (nearest export `AK::StreamMgr::SetFileLocationResolver`). strace for 6 s
     shows **zero syscalls** — a pure userspace spin in wine's waiter-table walk.
   - *Stage 8 + `AOE2LAN_HOOKS=0` (server + one known-safe detour, no grp2/3):* no game-thread
     spin; instead **wineserver spins at ~35% CPU** while every game thread parks in wineserver
     waits and all 13 socket fds sit idle (12 s strace: zero send/recv). A trivial
     `wine reg query` in the same prefix answers in 0.26 s, so wineserver is not globally wedged —
     it is spinning on an object belonging to the game process.
4. **`WINEDEBUG=+server` names the spin.** Stage-8 trace (692,666 lines): thread `0144` issues
   `fsync_msgwait` **396,960 times (~4,000/s) and nothing else**. The poll begins right after
   `0144: get_message() = PENDING` + `get_window_info(00010042)`, where window `0x10042` is owned
   by `pid=00e4 tid=00e8` — i.e. `0144` msg-waits on a window *another thread owns*, and
   `fsync_msgwait() = 0` returns immediately every time, so the loop never blocks. Control: the
   stage-7 trace (120 MB) has **zero** `fsync_msgwait` lines (top requests: `set_queue_mask` 138k,
   `enum_key_value` 118k, `close_handle` 102k, `select` 41k). The poller exists only when your
   server is active.
5. **Our own DLL threads go silent on wine.** `log_line` has no cap, yet `hb alive` (HeartbeatThread,
   5 s cadence) is **0** in every Linux stall run vs **29** in your booting Windows run
   (`logs/lanhook-10132.log`), and even the *booted* stage-7 run's shim log stops at t=13.478 s
   (`hb` = 2). So something parks or kills our threads on wine after a few seconds regardless of
   stage — consistent with a wait-model problem against wine's fsync+wineserver, not with our
   logging.

## The three asks (§3h)

1. Which game thread msg-waits on window `0x10042` (owner tid `00e8`) at boot, and **what posts
   that message on Windows**? Under wine fsync the wait returns immediately instead of blocking;
   `00e8` never posts, so `0144` polls forever and the boot stalls. Candidate to check first: one
   of *our* `CreateThread` threads ends up owning a window (any user32 call creates a message
   queue/window on wine) and never pumps it — if the game sends or posts to that window, Windows
   times out (`SendMessageTimeout`) and moves on, while wine may not.
2. Why does `HeartbeatThread` — a pure `Sleep(1000)` + `log_line` loop — stop after ~2 iterations
   on wine even in runs that boot? If `Sleep()` never returns for our process while wineserver is
   spinning, timers for that process are starving; the stage-7 counterexample (no spin, hb still
   stops at 13 s) says there is a second mechanism.
3. What does the server thread do at boot that creates the cross-thread message wait in (1)? The
   cert-consent `EnumWindows`/`EnumThreadWindows` at t=0.248 s from a non-pump thread is the only
   user32 traffic I can see in our code; it exits at `polls=0` on Linux, but on wine merely
   touching user32 from that thread may be enough to give it a window the game then waits on.

## What I am NOT claiming

- I have not identified the game function behind exe offset `0x2C08274` (encrypted-on-disk
  region; only the nearest export is known).
- I have not proven the wineserver spin and the `RtlWakeAddressAll` spin share one root cause;
  they may be two faces of the same wait-model bug or two separate ones. Both disappear when the
  stage-8 server is off.
- No game file was modified; all experiments were env/registry-only in my own clean prefix
  (`Audio` value added and removed again).
