# Session-17 (2026-11-04, M1) — LOGIN PARSE CLOSED: `Found 1 profiles for account AnkerGames`

## 17a. Headline
The M1 login reply is fully accepted by the client. Two supervised runs (lanhook-21416,
lanhook-2268) both log:

```
HIT LogHelper #95: "Found %zd profiles for account %s" r8=0x1 r9=<heap> s9="AnkerGames"
```

r8 = 1 profile, and the `%s` at r9 is now a readable "AnkerGames" string (previous runs
had r9 = an unreadable garbage pointer and no `s9=`) — so the AccountInfo object is
committed, not just the token. §16's open problem is closed.

## 17b. Root cause: `spamAllowed` is an INT field, not a bool
The only dedicated bool reader in this deserializer is `0x14039c730` (compares the
5-byte literal `false`, then `true`, then int 0/1). Per the field map it is used for
**one** field only: `shouldUseClientSync`. `spamAllowed` is read by `0x140611270`:

```
0x140611288 call 0x14039b8e0      ; "null" -> consume, accept
0x14061129c call 0x14039c900      ; strtoll   (NO "false"/"true" compare anywhere)
0x1406112a3 je  0x1406114e5       ; not a number -> return FALSE (hard abort)
0x1406112b5 cmp rax,0xff / ja     ; must fit int8
0x1406112cc js / cmp eax,3 / jle  ; valid range 0..3
```
`"spamAllowed":false` → strtoll fails → reader false → `AccountInfo` fails at
`0x140614a1b je 0x1406147f5` → LoginResult aborts at the accountInfo call. The token had
already been written (hence readSession worked) and `profiles` stayed empty. Served
value is now **2** (inside 0..3; 2 is also the library's own default and the value in
the public capture's accountInfo tuple).

Lesson (applies to every later struct): out-of-range *numbers* are logged and defaulted,
they do not abort (`0x1406115fa: mov dword [r14],2; ret al=1`). Only a token that fails
strtoll/string/array/object expectations aborts.

Also re-verified in 17: resultCode 0 ∈ [-1..11], ssoStatus 0 ∈ [-1..3], accountType 3 ∈
[0..13] in both readers (0x14061fe20), key order == wire order in LoginResult /
AccountInfo / ProfileInfo, `accountInfo.profiles:null` takes the null path at
0x140614bc6, relay endpoint types match, and `clientSettings` elements are positional
2-string arrays (`0x1406124e0`).

## 17c. Probe ladder answered (and is now retired)
`loginsrv.c` ProbeThread scanned for three raw LE int64 needles, one run:
```
PROBE done connectionID regions=209 hits=0     <- LoginResult+0x20 not in memory
PROBE hit profileID   va=0x27d80df1ed0         <- ProfileInfo.id
PROBE hit             va=0x27d80df2950         <- accountInfo.id (same 8 bytes)
PROBE hit statGroupID va=0x27d80df1f78         <- ProfileInfo.personalStatGroupID
```
`statGroupID` sits exactly +0xa8 after `profile.id` in the same private buffer, i.e. the
whole ProfileInfo element (field 8 of 18) is materialised. connectionID not being found
is just the needle never being stored anywhere private in that shape — not a problem.

Costs 3.5 s of process-wide ReadProcessMemory per login and adds load during boot; it
has done its job. Keep the code, but only arm it behind an env flag (`AOE2LAN_PROBE=1`)
for future struct work.

## 17d. What killed the run at t≈86 s: AppHang from a WebSocket retry storm
Windows telemetry (Application log, 18:26:49): `Application Hang 1002` +
`WER AppHangB1`, bucket 1857632049504807364, `IsFatal=1` — a **hang, not a crash**
(no Application Error, no exception).

Cause is visible in the log within 0.4 s of a successful login:
```
WebSocketConnection::Process: Creating a websocket connection; host=pb-live-release6-api.worldsedgelink.com port=443
HTTP REQ /wss/                      <- our fallback answers a normal HTTP "[0,[]"
WebSocketConnection::OnConnectFail; m_resumeState=0
```
Repeated 69x (run 21416) / 111x (run 2268) at ~78 ms intervals, forever. The client
wants an HTTP **101 Switching Protocols** upgrade on `/wss/`; we answer a body, the
upgrade fails, it immediately retries. Loop + UI thread = AppHang after ~50 s.

Next stage (M2 precondition, small and self-contained): implement the WS upgrade in
`loginsrv.c` — compute `Sec-WebSocket-Accept` = base64(SHA1(key + 258EAFA5-E914-47DA-
95CA-C5AB0DC85B11)) with CryptoAPI (already linked for certs), reply 101, then hold the
socket and answer frames (masked client frames in, unmasked out; ping→pong; ignore
payload). Serving relay/poll events over that socket is the follow-on.

## 17e. The three short logs are not crashes
lanhook-19452, -15572, -9908 (109/109/810 lines) all stop at ~1.2-1.3 s, right after
`cert: user-Root registered`. Our DLL is fine in them: `srv: H1 login server listening
on 127.0.0.1:443` is logged, no error, no `PROBE`, no HTTP request, and the Application
log has **no** WER event for them — the process exited by itself during boot (relaunch
while the previous hung instance was still being torn down). Nothing to fix on our side.

## 17f. Tree state / artifacts
- `dev/lanhook/loginsrv.c`: `"spamAllowed":2` (comment records reader 0x140611270),
  ladder probe (`g_ProbeId`/`g_ProbeStat`/`g_ProbeConn`, `mem_probe(label,...)`,
  first-hit dump only, `ProbeThread` runs the ladder).
- Builds: build.cmd clean (only pre-existing C4090 const warnings), hooktest 68/68,
  srvtest+srvclient PASS (json asserts incl. `profiles[0].id == accountInfo.id`).
- Staged `dbghelp.dll` = `aacab8ddbb7acbf7` (193024 B), rollback
  `dbghelp.dll.prev-s17-before`. `AoE2DE_s.exe` untouched `1e415af8…`.
- `fmap2.py` (new): prints key → dst offset → reader for any TypesStream reader function
  — the tool that made this session's audit cheap. Usage: `python fmap2.py 0x140620540`.
