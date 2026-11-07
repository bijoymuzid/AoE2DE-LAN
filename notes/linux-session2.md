# Linux session 2 — the new dbghelp.dll fixes the login; the game itself stops at "communications handler"

Supersedes `notes/linux-tls-framing-bug.md` for Linux state. Everything below is MEASURED on
2026-11-07 22:00–23:00 (+0600), Arch, prefix `~/Games/aoe/winepfx`, unless marked INFERRED.
No game file was modified; the only repo change is `linux/launch.sh` (+ this note).

DLL under test: `dbghelp.dll` 240,128 B, MD5 `42868034f7cb57276e7d3a6de3b203bc` (W1's session-34
build, i.e. the post-`EncryptMessage` TLS-framing fix).

## 2a. The TLS framing fix works — the login plane is done on Linux

The session-31 bug (`tls_encrypt_send` sending pre-`EncryptMessage` sizes) is fixed by this build.
`/game/login/platformlogin` is accepted and the game logs the **same event order as the healthy
Windows reference** (`logs/lanhook-9908.log`, `logs/lanhook-8528.log`):

```
Found %zd profiles for account %s   -> Found profile: AnkerGames
WorldwidePollingService::OnAccountEvent: Client is using WebSockets...
WorldwideAdvertisementService::InitiateRelayServerQoSTest(): QOS test started
HTTP REQ /game/Leaderboard/getAvailableLeaderboards   (matchTypes non-empty = the M1 unlock)
HTTP REQ /wss/  -> WS: 101 Switching Protocols -> WS TEXT {clientLibVersion,operation,sessionToken}
HTTP REQ /game/Leaderboard/getStatsForLeaderboardByProfileName  (x2)
```

`srv: H1 login server listening on 127.0.0.1:443 (TLS)` binds fine (`ip_unprivileged_port_start=0`
already set). No `LoginAsync - response was failure: 0xffffffd2` any more. **M1's Linux half is
closed.** The `LeaderboardStatsCache - response was not formatted correctly: [0,[]` warning is ours
and also present in the Windows reference logs — tolerated there, so it is not a blocker.

## 2b. Launch path: `proton run` was handing the game to the real Steam client

`proton run <exe>` goes through Proton's `c:\windows\system32\steam.exe` stub, which under
Proton-CachyOS delegated to the bundled client: `C:\Program Files (x86)\Steam\steam.exe
steam://run/813780` — and hung there (found as a 1 h 35 m old orphan, no wineserver left).
`linux/launch.sh` now uses `proton runinprefix`, which execs `wine AoE2DE_s.exe` directly: no Steam
client, no stub. The RUNE crack (`steam_api64.dll`, `steam_emu.ini`, `Steam/steamclient64.rne`) is
untouched and initialises correctly under it:

```
[S_API] SteamAPI_Init(): Loaded 'C:\Games\AoE2DE\Steam\steamclient64.rne' OK.
```

## 2c. Second, separate Linux-only bug found and fixed: a real 401 kills the login flow

On this machine `api.ageofempires.com` resolves to the **real** Azure endpoint (`52.238.248.160`),
the game's `ExtensionDoExternalCallEvent` gets a genuine **HTTP 401**, and the run ends there.
The Windows reference box resolves the same name to a LAN address (`192.168.0.103`), so it fails at
*transport* level instead — `ExtendedError -15`, `response was failure: -47` — which the game
tolerates and continues past. Same call, different failure class, different outcome: the game
survives "unreachable" and quits on "rejected".

Fix applied on the Linux host (this Wine build ignores the prefix's `drivers\etc\hosts` — verified
by string search across `files/lib/wine/x86_64-unix/*.so`, so it must be the real resolver):

    127.0.0.2 api.ageofempires.com cdn.ageofempires.com      # in /etc/hosts

`127.0.0.2` is loopback with nothing on :443 (our server binds `127.0.0.1` exactly,
`loginsrv.c:1882`), so the connect is refused instantly and the game sees
`SOCK connect 127.0.0.2:443` -> `response was failure: -47` — the Windows failure code, exactly.
Measured: this removed the 401. It did **not** remove the exit in 2d, which is a different wall.

## 2d. The actual Linux wall: the game stops in its own comms init, with or without our DLL

Every run exits **cleanly with code 0** (no crash, no dump, no unhandled exception, no error dialog)
and the game's own log stops at the same place:

`%USERPROFILE%\Games\Age of Empires 2 DE\logs\<stamp>\Main.txt` — **18 lines, identical in all 8
runs tonight**, last line:

```
[Main] :   ...success! About to setup communications handler...
```

The decisive control run: `AOE2LAN_DLL=/nonexistent ./linux/launch.sh` — **stock cracked game, no
proxy DLL, no hooks, no login server** — produces the same 18-line `Main.txt` and the same exit 0
(18 s wall). So `dbghelp.dll` is exonerated: this is game-vs-Wine, not the mod.

Matrix of runs, all ending at the same line:

| variable | values tried | outcome |
|---|---|---|
| Proton build | GE-Proton11-12, Proton-CachyOS `cachyos-11.0-20261015-slr` | same |
| sync backend | ntsync (default), `PROTON_NO_NTSYNC=1` (fsync) | ntsync: exits *or* wedges into a 100 %-CPU spin; fsync: clean exit 0 |
| proxy DLL | session-34 build, `AOE2LAN_HOOKS=0`, no DLL at all | same |
| network | normal, `api.ageofempires.com` blocked, loopback-only netns (`unshare -rn`) | same (netns run survived 60 s but never reached login — it stalls on the `title.mgt.xboxlive.com` call, so it is not a counter-example) |
| launch verb | `proton run` (Steam stub), `proton runinprefix` (direct wine) | `run` hangs in Steam; `runinprefix` reaches 2a–2d |

Ruled out with evidence, do not re-test:

- **Not a crash.** Exit code 0; no BugSplat dump; no `Unhandled exception` in wine's stderr.
- **Not the anti-tamper noise.** The run is full of `EXCEPTION_ILLEGAL_INSTRUCTION` at densely
  packed addresses (up to 3520 hits at one address, VEH at `0x142BFA4D8` returning
  CONTINUE_EXECUTION) and of `sigsys_handler SIGSYS, rax 0x2c/0x25/0x1e/0xf/0xb8, rip 0x170005a`
  (direct syscalls from a JIT page). Both are the packer/protector working normally — Wine emulates
  the syscalls and the game continues for seconds afterwards. INFERRED, but consistent with
  `PLAN.md` M0.3's Arxan note.
- **Not raw sockets.** Socket census from `WINEDEBUG=+ws2_32`: 13x TCP (`family 2, type 1`),
  2x UDP/17, 2x IPv6 UDP. Zero `SOCK_RAW`/ICMP, so no `CAP_NET_RAW` gap and no
  `ping_group_range` sysctl is needed.
- **Not `SIO_IDEAL_SEND_BACKLOG_QUERY`** (`WSAIoctl code=0x4004747b`, the game's only exotic
  ioctl): Wine implements it and answers 64k.
- **Not the prefix Windows version**: `Windows 10 Pro`, build 22000. The `"OSVersion":
  "Windows XP Professional(Build )"` string in our telemetry is the game's own broken version
  readout under Wine — cosmetic.
- **Not the 401 / telemetry** (2c): still exits after that is fixed.

Remaining suspects for the comms-handler step, none measured yet: the WinRT/COM surfaces the game
touches there (`err:combase:RoGetActivationFactory Failed to find library for
L"Windows.Internal.System.Profile.RegionPolicyEvaluator"` is the one hard error near the end), and
anything the LAN discovery path needs before it binds UDP 4341 (the Windows reference only resolves
`localhost:4341` at t=9.6 s, i.e. after the menu — we never get there).

## 2e. Consequence for the plan, and the next Linux experiment

Linux parity is blocked by the **game**, not by the shim, so it cannot be fixed by more work in
`dev/lanhook/**`. This is exactly what `PLAN.md` R9 ("Linux tested from M2.5, not at the end")
anticipated: M2 (Windows co-op) should be finished first, and M2.5 attempted as its own bounded
experiment.

Cheapest decisive next step, not done tonight: catch the exit itself. Launch as a child of the
debugger's shell (Yama `ptrace_scope=1` only allows descendants) and break on `ExitProcess` /
`NtTerminateProcess` with `winedbg` or `gdb -p`, then read the backtrace — that names the function
that decides to quit. Second best: `WINEDEBUG=+loaddll` and diff the last-loaded DLLs against a
Windows Process-Monitor trace of the same step.

## 2f. Launcher knobs that are now defaults in `linux/launch.sh`

- `AOE2LAN_PROTON` default -> `Proton-CachyOS Latest-x86_64_v3/proton` (GE still works via the env
  override; both hit the same wall).
- `proton runinprefix` instead of `proton run` (2b).
- `WINEDLLOVERRIDES="dbghelp,winmm=n,b"` unchanged.
- `PROTON_NO_NTSYNC=1` set, with a comment. Reason: with ntsync the failing exit can wedge into a
  spinning thread that survives the launcher (one was found at 100 % CPU, 1 h 16 m old, with a
  dead wineserver and a defunct lanhub). Revisit once the game actually reaches the menu.
- Housekeeping: `launch.sh` `exec`s proton, so its EXIT trap never runs and `lanhub` is orphaned on
  every launch. Kill it before relaunching (`pkill -f 'lanhub --ini'`) or the new one cannot bind
  47100/47101.
