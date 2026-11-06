# AoE2DE-LAN

Working repo for **AoE2LAN** — making LAN-style multiplayer work in a cracked AoE2:DE (RUNE
`steam_emu`, AppID 813780) whose Multiplayer button is greyed out, so friends on one Tailscale
tailnet can play co-op vs AI and PvP on Windows and Linux/Proton.

Not a netcode project. The engine already contains LAN multiplayer; only the login/lobby plane is dead.

## Current state (session 30)

| Area | Status |
|---|---|
| RelicLink login (`POST /game/login/platformlogin`) | **done** — served by our in-DLL TLS/HTTP/WS server on `127.0.0.1:443` |
| Profile selection, service sweep, PlayFab login | **done** |
| **Multiplayer button (M1)** | **DONE** — button is live and the Multiplayer screen opens. The last missing piece was `getAvailableLeaderboards` returning a well-formed object **with a non-empty `matchTypes` list**: the game installs its leaderboard definitions from that list, and an object with those lists empty parses cleanly and installs nothing |
| Hosting a lobby | **open bug** — Host Game → Create Lobby fails with `Could not create game. Server Error. AdvertisementJoinEvent Error Code: 0x1`. The game picked *online* hosting and sent no advertisement request at all. The create dialog's Server dropdown does offer **`Use Local Lan Server`** (measured session 30); selecting it is the next test |
| M2 (LAN lobby + relay) | not started |

## Read this first

- `PLAN.md` — mission, evidence, architecture, milestones, component contracts (§6.1 is the login-shim contract)
- `notes/m1-session30.md` — current state, supersedes everything older
- `notes/m1-session29.md` — M1 result (button live) + the hosting failure and its evidence
- `notes/m0-findings.md` — M0: PE facts, strings, RTTI survey, relay protocol

## Repo layout

```
PLAN.md                      plan + evidence (start here)
notes/                       session notes, findings, analysis scripts (session notes are the state)
dev/lanhook/                 the shim: dbghelp.dll proxy -> in-DLL TLS/HTTP/WS server + IAT hooks
  loginsrv.c                 H1 login server: TLS 127.0.0.1:443, DNS redirect, login reply builder
  lanhook.c, iathook.c       IAT hook set, cert trust injection, wire logging, read-only rule probes
  hookcore.c, hooks.asm      hook plumbing, stubs
  srvclient.py               offline conformance test for the login server (must print PASS)
  hooktest.c                 offline self-test of the hook set (must print 68/68)
  aoe2re.py, dz.py, rr.py, cx.py   static-analysis helpers (strings, disasm, xrefs)
  work/                      raw disassembly dumps and field maps used to derive the reply shapes
dev/fwdtest/, dev/memcheck/  earlier probes (loader forwarding, memory checks)
logs/                        reference runs: lanhook-<pid>.log + the telemetry NDJSON snapshots
```

## Build & validate (Windows, MSVC 14.4x + WinSDK 10.0.26100)

```
dev\lanhook\build.cmd            :: dbghelp.dll + hooktest.exe + srvtest.exe
dev\lanhook\hooktest.exe         :: expect "game-image iat walk: swapped 68 of 68"
dev\lanhook\srvtest.exe          :: then, in another shell:
python dev\lanhook\srvclient.py  :: expect PASS
```

Before any in-game run, confirm nothing is already listening on `127.0.0.1:443` (kill stale
`srvtest.exe`). Then run `PLAY-stage8-LOGIN.cmd`.

## The oracle

The game's own verdicts are on disk and are readable without hooking game code:

- `%USERPROFILE%\Games\Age of Empires 2 DE\telemetry\TelemetryEventsNormalPriority.json` — NDJSON,
  appended even with telemetry muted. `ScreenChange` events carry `ScreenHistory` (widget paths) and
  `InputHistory` (`WPFG:<Widget[Text]>:(button):1` click lines).
- `TelemetryEventsHighPriority.json` — `PlayerLogin` / `StatusUpdate` / `PlayerSession*` / `Lifecycle`.
- `logs/lanhook-<pid>.log` — the rlink-side view: every HTTP/WS request the client makes, every
  `LogHelper`/`LogWarn` string with its arguments.

Game-side log calls go through `0x14101bb50`, **not** rlink's `LogHelper`, so hooks cannot see game
account lines; telemetry plus our log together are the full picture.

## Working on this from Linux

**Two people work on this repo now.** The split, the file-ownership table and both workstreams are
in `PLAN.md` §17. If you are the Linux worker, read `notes/prompt-linux-worker.md` first — it is the
whole brief. Your paths are `lanhub/**`, `linux/**` and `notes/linux-*.md`; the rest belongs to the
Windows worker.

The shim and the launchers are Windows-only today (`dbghelp.dll` proxy + MSVC build), so a Linux
machine runs the **game** under Proton, not the build. What is useful and doable from Arch without
Windows:

- **Analysis.** Everything in `notes/*.py` and `dev/lanhook/*.py` is plain CPython 3: `pip install
  capstone numpy`, then `python fn.py <hexaddr> --dump`, `python xr.py <hexaddr>`. The disassembly
  source is the decrypted `.text` dump (`gametext.bin`, git-ignored, VA = `0x140001000 + offset`);
  `.rdata` strings are read straight out of `AoE2DE_s.exe`.
- **The native hub.** `lanhub` (peer enumeration via `tailscale status --json`, gossip on 47101,
  the game-side control protocol on `127.0.0.1:47100`) is a new component with no Windows
  dependency. It can be written and unit-tested on Linux against the protocol in `PLAN.md` §5.
- **Running the game.** One Proton prefix shared by game, relay and launcher; `WINEDLLOVERRIDES="dbghelp=n"`
  so our proxy is used instead of Wine's builtin.

If you want to build the DLL itself on Linux, the build is `ml64` + `cl`, so it needs mingw-w64
cross-compilation or a Windows VM — nobody has done it yet, and it is not on the critical path.

## Ground rules that keep this reproducible

- Never hook or patch encrypted-on-disk game code; hook ids 4/5 (LogHelper/LogHelper2) and 13 (LogWarn) only.
- Never raw-deref process memory from our own threads.
- `purge_aoe2lan_roots()` must run before every cert add — stale same-DN roots once crashed the client
  inside its cert-store build.
- Keep the 68/68 IAT slot set; keep `AoE2DE_s.exe` untouched; do not use ageLANServer in any form.
- Static analysis: `git`-ignored `gametext.bin` (decrypted `.text`, VA = `0x140001000 + offset`) is the
  disassembly source; `.rdata` strings are read from `AoE2DE_s.exe` directly.