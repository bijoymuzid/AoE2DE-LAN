# AoE2DE-LAN

Working repo for **AoE2LAN** — making LAN-style multiplayer work in a cracked AoE2:DE (RUNE
`steam_emu`, AppID 813780) whose Multiplayer button is greyed out, so friends on one Tailscale
tailnet can play co-op vs AI and PvP on Windows and Linux/Proton.

Not a netcode project. The engine already contains LAN multiplayer; only the login/lobby plane is dead.

## Current state (session 22, 2026-11-05)

| Area | Status |
|---|---|
| RelicLink login (`POST /game/login/platformlogin`) | **done** — served by our in-DLL TLS server on `127.0.0.1:443`, the client parses the reply |
| Profile selection (`accountInfo.profiles`, `selectProfile`) | **done** — client runs its whole post-login service sweep and PlayFab `/Client/LoginWithCustomID` returns 200 + SessionTicket |
| WebSocket `/wss/` notification plane | up, pings answered; push ladder off by default (`AOE2LAN_PUSH=1` re-enables) |
| Relay registration | **done** — client logs `Adding LAN relay server: <lan-ip>, GUID …` |
| **Multiplayer button** | **still disabled** — a disabled WPF button raises no click, so the gate is the button's enable/visibility state on the main menu, decided by game code from the platform (Xbox-Live) state. Only remaining platform error in the log: `PlatformSetPresenceAsync::Process: No user session.` |
| M2 (LAN lobby + relay) | not started; `/game/advertisement/*` shapes are mapped and the WS type set is known |

## Read this first

- `PLAN.md` — mission, evidence, architecture, milestones, component contracts (§6.1 is the login-shim contract)
- `notes/m1-session22.md` — current state, supersedes everything older
- `notes/m1-session21.md` — full login work: what the login reply must contain and why
- `notes/m0-findings.md` — M0: PE facts, strings, RTTI survey, relay protocol

## Repo layout

```
PLAN.md                      plan + evidence (start here)
notes/                       session notes, findings, analysis scripts (session notes are the state)
dev/lanhook/                 the shim: dbghelp.dll proxy -> in-DLL TLS/HTTP/WS server + IAT hooks
  loginsrv.c                 H1 login server: TLS 127.0.0.1:443, DNS redirect, login reply builder
  lanhook.c, iathook.c       IAT hook set, cert trust injection, wire logging
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

## Ground rules that keep this reproducible

- Never hook or patch encrypted-on-disk game code; hook ids 4/5 (LogHelper/LogHelper2) and 13 (LogWarn) only.
- Never raw-deref process memory from our own threads.
- `purge_aoe2lan_roots()` must run before every cert add — stale same-DN roots once crashed the client
  inside its cert-store build.
- Keep the 68/68 IAT slot set; keep `AoE2DE_s.exe` untouched; do not use ageLANServer in any form.
- Static analysis: `git`-ignored `gametext.bin` (decrypted `.text`, VA = `0x140001000 + offset`) is the
  disassembly source; `.rdata` strings are read from `AoE2DE_s.exe` directly.