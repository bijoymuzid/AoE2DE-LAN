# Linux session 3 (2026-11-10) — the game DOES launch; stage 8 deadlocks it on wine

Box: Arch/KDE/Wayland, DISPLAY=:0. DLL `d5cee0abac99629c36f13407f84985ef` (W1 session-49 build)
staged in the game dir. Prefixes: `pfx-wine10` (GE-Proton10-34, wine 10.0, clean, `drive_c/Games`
symlinked to the real game dir), `pfx-wine9` (GE-Proton9-27), `winepfx` (wine 11, shared).
Pre-flight: `/etc/hosts` block present, `ip_unprivileged_port_start=0`, exe md5
`affb19f03ca96965abf9e56775cab688` untouched, 105 G free. **tailscaled was dead**
(`systemctl status tailscaled` = inactive/disabled) → `lanhub peers` falls back to ini seeds
("tailscale CLI unavailable"); needs `sudo systemctl start tailscaled` (operator).

Headline, correcting session 2: **the game launches on wine 10.** What looks like "doesn't boot"
is a deadlock/livelock that only happens with the shim *active* (`AOE2LAN_STAGE=8`). With the DLL
inert (stage 1) or IAT-only (stage 7) the game reaches the main menu in under a minute.

## 3a. Run A — stage 8 default (wine10 + pfx-wine10 + DLL), the "doesn't boot" run

Launch 14:54:38 via `linux/launch.sh` (`AOE2LAN_PFX=~/Games/aoe/pfx-wine10`,
`AOE2LAN_PROTON=~/Games/aoe/GE-Proton10-34/proton`). Shim log `lanhook-220.log`: 68/68 IAT slots,
cert ok, `srv: H1 login server listening on 127.0.0.1:443 (TLS)`, `/game/login/platformlogin`,
`getAvailableLeaderboards`, `WS: 101 Switching Protocols`, WS TEXT op0 — i.e. the login shim works
exactly as on Windows. `BattleServer.exe` spawned.

Then nothing. Window = 640x480 loading splash (capture `/tmp/s4-shot-1.png`), unchanged md5 for
5+ min. `Main.txt` = **18 lines**, last = `...success! About to setup communications handler...`,
unchanged at 19 min. One thread (LWP 8955) at 98% CPU, `wchan=0`, **zero syscalls in 6 s of
strace** = pure userspace spin.

gdb (`thread 25`, pid 8751):

```
#0  RtlWakeAddressAll ()            from ntdll.dll        (wine builtin)
#1  AoE2DE_s!?SetFileLocationResolver@StreamMgr@AK@@YAXPEAV...@Z ()  from AoE2DE_s.exe
#2  0x0
```

Frame #0 disassembly: the spin is *inside* wine's `RtlWakeAddressAll` waiter-table walk
(`pause; lock cmpxchg $-1,(%rdi)` loop), called with `Address = rcx = 0x174` — a NULL-derived
pointer (NULL+0x174). No other thread is in `RtlWaitOnAddress`; every other thread is idle.
So the game's Wwise/AK init wake-alls a sync object that was never created, forever.
Return-address offset from game base = `0x2C08274` (base `0x6ffffa240000`).

`Main.txt` on Windows (m0-findings 8c) continues past line 18 to `Game::setup() after hotkeys`
→ `endMovieFunction complete` (menu). We never get line 19.

## 3b. Audio-backend hypothesis — dead

`reg add HKCU\Software\Wine\Drivers /v Audio /d null` in pfx-wine10, same launch: identical
18-line stall, 97% spinner at ~100 s. Value deleted afterwards. pipewire + pipewire-pulse are
healthy on this box (`pactl info` ok), and the stage-1 run (3d) completes
`.oO Wwise Audio - Init Finished Oo.` — so Wwise init itself is fine without the active shim.

## 3c. Bisect ladder (oracle = `Main.txt` line count > 18; each run killed by me)

| run | config | result |
|---|---|---|
| B | stage 1 (DLL inert: no IAT, no server, no hooks) | **BOOTED**: menu in <45 s. Operator saw the menu, Multiplayer greyed (expected: no login server), quit cleanly. `Main.txt` 49 lines: `sound system` → `Wwise Audio - Init Finished` → intro video `...failed! Abort...` → `Advance to main menu` → `endMovieFunction complete` → profile load → `Game::setup() after hotkeys` → `exiting` |
| C | stage 7 (IAT swap only, no server, no hooks) | **BOOTED** past the wall: 46 lines at t=15 s, `Wwise Audio - Init Finished` present. IAT swap exonerated |
| D | stage 8 + `AOE2LAN_HOOKS=0` (IAT + server + one Windows-proven-safe detour, no grp2/grp3) | STUCK at 18 lines, **no** game-thread spin; **wineserver at 34.8% CPU** (fsync build) |
| E | stage 8 + HOOKS=0 + `WINEESYNC=1 WINEFSYNC=0` | Proton ignores both (`fsync: up and running.`); STUCK at 18 lines, zero CPU anywhere = clean deadlock |

So: stage 1 and 7 boot; stage 8 stalls at the same line with two different signatures
(grp2/grp3 detours → the AK `RtlWakeAddressAll` spin; HOOKS=0 → wineserver spin / deadlock).
The operator's "this class of run reached the menu" memory from the matrix was the stage-1/7
class, not stage 8.

## 3d. Run D forensics — the deadlock is inside wine's server loop, not the network

- gdb all-threads: every game thread parked in `server_select`/`wait_select_reply`
  (wineserver roundtrip); main thread inside `NtQueryDirectoryFile` → `get_file_info`.
  Only non-idle frame anywhere: `alsa_midi_notify_wait` (winealsa, normal idle).
- `strace -f -e trace=sendto,recvfrom,send,recv,read,write` on the game for 12 s: **zero**
  socket syscalls; 13 socket fds open, all quiet. The game is not waiting for network data.
- While stuck, a trivial `wine reg query` in the *same prefix* answers in **0.26 s**
  (with matching `WINEFSYNC=1`) → wineserver is not globally wedged; it spins on some object
  of the game process while still servicing new clients.
- Our DLL's own threads go silent on wine: `log_line` (hookcore.c:30) has **no** size cap, yet
  the stuck run's log ends at t=4.001 s and contains **0** `hb alive` lines, while Windows
  `logs/lanhook-10132.log` has 29 (`hb alive sec=5,10,...`). Even the BOOTED stage-7 run's log
  stops at t=13.478 s after 2 hb lines. HeartbeatThread (lanhook.c:1042) is a plain
  `Sleep(1000)` loop, so on wine our threads stop being scheduled/serviced a few seconds in.

## 3e. Run F — `WINEDEBUG=+server` names the spin: `fsync_msgwait` busy-poll

Stage 8 + HOOKS=0 + `WINEDEBUG=+server`, 100 s, 54 MB trace (`/tmp/s4-s8h0-serverdbg.log`).
Request histogram (whole file):

```
397770 fsync_msgwait(          <- thread 0144: 396960 of these and NOTHING else
 74788 enum_key_value(
 28780 close_handle(
 17392 get_key_value(
 16676 read_process_memory(
  8394 set_timer(
  7790 select(
```

Thread `0144` issues ~4,000 `fsync_msgwait`/s and no other request ever: a message-pump thread
whose blocking wait returns immediately, forever. Our DLL contains **no** message pump
(`grep MsgWait|PeekMessage|GetMessage` over dev/lanhook/*.c = empty), so 0144 is a game thread;
with the shim active its `MsgWaitForMultipleObjects`-style wait degenerates into an immediate-return
poll under wine fsync. That poll is the wineserver 35% CPU. During this perturbed run the game
`terminate_process(self, exit_code=0)`'d on its own (Main.txt still 18 lines) — the wine-10
equivalent of the wine-11 protection exit, triggered by the timing change.

## 3f. Tooling notes for the next Linux session

- `pgrep -f 'AoE2DE_s.exe'` matches the **python launcher** (its cmdline contains the exe name).
  Use `pgrep -x 'AoE2DE_s.exe'`. Same trap for pkill: bracket the pattern or you kill your own shell.
- No `xwininfo`/`xdotool` on this box. Window change detector = `import -window $W f.png` +
  `identify -format '%wx%h'` + md5.
- gdb/strace attach to the game pid works; attaching to **wineserver** is refused
  (`kernel.yama.ptrace_scope=1`).
- The shim's request-side log cap (`g_IatReqCap=900`, `g_IatRespCap=1400`, iathook.c:182-183) is
  burned by t≈3.6 s on Linux (CRYPT32 root-enum + hex dumps of the game's real TLS traffic to
  `20.51.14.110` = Microsoft telemetry/servicebus). Everything after that is invisible in
  `lanhook-*.log`; use strace/`WINEDEBUG=+server`/Main.txt instead.
- Shim log names are `lanhook-<winepid>.log` and wine pids get reused (220/224 across runs) —
  always pair a log with its launch time.

## 3g. Corrected conclusions

1. Session 2's "clean exit at 3.5 s" is wine-11-only. On wine 9/10 the game does not exit; with
   the shim inactive it loads to the menu in <60 s.
2. The Linux boot blocker is **stage 8 itself**, in two independent signatures:
   (a) grp2/grp3 E9 detours → game thread spins in wine's `RtlWakeAddressAll` waiter walk with
   `Address=0x174` (NULL-derived) inside AK StreamMgr init;
   (b) server active → a game thread busy-polls `fsync_msgwait` at ~4k/s (wineserver 35% CPU) and
   the rest of the process parks; our own DLL threads stop logging after a few seconds.
3. Neither is audio (null driver changes nothing), neither is the IAT swap (stage 7 boots),
   neither is ntsync vs fsync (run 7 / run E), neither is a network wait (zero socket syscalls).
4. Interim playable-on-Linux path: `AOE2LAN_STAGE=1` or `7` boots to the main menu — no login, so
   Multiplayer stays grey. The product path (stage 8) needs W1's eyes on 3e/3d.

## 3h. Asks for W1 (Windows worker)

- Which game thread at boot does a `MsgWaitForMultipleObjects`-style pump (server-thread 0144
  here)? Does anything in our DllMain/thread creation (crash filter, cert consent EnumWindows at
  t=0.248, the in-process TLS server thread) change that thread's wait semantics?
- Why do our own threads (HeartbeatThread's `Sleep(1000)` loop) stop logging after ~4-13 s under
  wine while the process lives? Suspects: `log_line`'s `InterlockedCompareExchange`+`Sleep(0)`
  spinlock under wine fsync, or `WriteFile` on the log handle blocking.
- The `RtlWakeAddressAll(0x174)` spin: exe offset `0x2C08274` from image base (VA
  `0x142C08274`, i.e. `gametext.bin` file offset `0x2C07274`) — please identify the function in
  the decrypted dump and what NULL object it dereferences; on Windows the same code completes.
