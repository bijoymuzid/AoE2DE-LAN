# Session-18 (2026-11-04, M1) — WebSocket upgrade landed: no more AppHang

## 18a. Headline
One supervised run, `logs/lanhook-14604.log`, **212 s, ended with our logout at 212.4 s and no
WER/Application-Hang event** (the Application log's only 1002/AppHang entry is still the s17 one at
18:26:49). Session-17's blocker is gone:

```
[t=4.641s] HTTP REQ /wss/
[t=4.641s] WS: 101 Switching Protocols, accept=ICX+Yqv66kxgM0FcWaLWlFLwTAI=
[t=4.797s] HIT LogHelper #108: "WebSocketConnection::OnConnect; m_resumeState=%d" r8=0x0
[t=4.797s] HIT LogHelper #109: "WebSocketConnection::Process: Sending session token;
           clientLibVersion=%d sessionToken=%s" r8=0xc2 s9="1193815356"
[t=4.313s] HIT "Found %zd profiles for account %s" r8=1 s9="AnkerGames"
[t=4.313s] HIT "Found profile: %s" s8="AnkerGames"
[t=4.313s] HIT "WorldwidePollingService::OnAccountEvent: Client is using WebSockets to receive updates from the server"
[t=4.313s] HIT "WorldwideAdvertisementService::InitiateRelayServerQoSTest(): QOS test started"
```

`s17` had `OnConnectFail` 111x and no `OnConnect`; this run has 1 websocket connection and **0**
`OnConnectFail`. Pings (op=9, 4 B) arrive every ~10 s and are answered with pongs for the whole run.

## 18b. What changed in `dev/lanhook/loginsrv.c`
1. **WebSocket upgrade + frame loop** (`ws_accept`, `ws_send`, `ws_serve`, `log_ws_text`, `b64enc`,
   `sha1_b64`, `log_int`). `serve_conn` diverts any path containing `/wss` to `ws_serve` before
   `route()` and ends the HTTP loop after it. Accept = base64(SHA1(key + 258EAFA5-…-C5AB0DC85B11))
   through the same CAPI hash path the cert code uses (`CryptCreateHash(g_CspProv, CALG_SHA1…)`,
   base64 table by hand). Reply is one TLS record:
   `101 / Upgrade: websocket / Connection: Upgrade / Sec-WebSocket-Accept / Cache-Control: no-store`.
   Frames: masked client frames unmasked in place, unmasked server frames out, ping→pong,
   close→close, op 1/2 payloads logged (first 3, 280 chars) and otherwise ignored, >65535 B frame or
   buffer overflow closes. Idle socket: `tls_decrypt` returns -1 on SO_RCVTIMEO, so a ping is sent
   and the socket kept (3 strikes).
2. **`readSession` reply** `[1]` → `0,[null]` (reference shape `%d,%s` = `<ackNum>,[<chunks>]`).
   Not exercised yet: the poller never ran because the client chose WebSockets (18a).
3. **Memory probe is opt-in**: `probe_arm()` returns unless `AOE2LAN_PROBE=1`. Normal runs no longer
   pay the 3.5 s process-wide RPM ladder.
4. `srvclient.py` gained a WebSocket section: raw GET /wss/ upgrade, verifies the 101 + accept hash,
   sends a masked text frame + masked ping, asserts an unmasked pong with the echoed payload, then
   the close handshake and EOF. Offline: hooktest **68/68**, srvtest+srvclient **PASS**.

## 18c. New facts from the run (use these, don't re-derive)
- The client's first WS message is a **binary** frame (op=2, 66 B) — rlink sends JSON as binary, not
  text. `log_ws_text` now dumps op 1 and 2 payloads (the 18c build that ran only dumped op=1, so the
  token message body is known only from LogHelper #109: `sessionToken=1193815356`,
  `clientLibVersion=0xc2`(194)). Next run prints the raw JSON.
- WS keepalive is a client **ping** every ~10 s, not an application message.
- `/game/login/readSession` is **not** requested while a WS is up — the UI logs "Client is using
  WebSockets to receive updates". So readSession's shape is now a fallback, not the main path.
- `setLanguage` (t=23.4, body `callNum=6&connect_id=…&language=en&sessionID=…&title=age2`) accepted our
  `[0,[]]`; news polls every ~60 s die at 206 s — the menu stayed alive the whole time.
- `Adding LAN relay server: %s, GUID %s` fired at t=14.0 with `192.168.0.104` = this machine's LAN IP
  and GUID `6ef1d03a-af50-4e0a-8f35-147dedcc4622`, name "My Serv…". The UDP advert is received by the
  game's broadcast listener from **192.168.0.104:59719 every ~10 s**, frame starts `21 24 00 36` (`!$`,
  len `0x24`, GUID, `\t\0`, name). No process owns 59719 after the run, so whoever advertises lives
  only while the game runs (the game itself starting LAN hosting, or a helper it spawns). Identify it
  before M2 — a rogue LAN relay advert changes what `getLanAdvertisements` returns.
- PlayFab/XAL is the live escalation path: `WinHttp` POSTs to the **real** cloud
  (`20.51.14.110:443`) `/Client/LoginWithCustomID?sdk=XPlatCppSdk-3.171` and gets
  `{"code":400,"status":"BadRequest","error":"InvalidParams"…}` every ~16-32 s, forever. No
  `/game/advertisement/*` request ever arrives, i.e. the MP screen is still gated upstream of the
  advertisement service.
- A stale `ageLANServer Self-signed` cert is in the user Root store from older experiments (harmless;
  it is enumerated along with ours at boot).

## 18d. Where to go next (in order)
1. Read the WS payload of the next run (`WS TEXT {"operation":0,…}`) — that is the whole notification
   channel for M2: rlink pushes events as one JSON array `[0,"<Message>",<profileID>,[…]]`, same shape
   as one readSession event chunk (reference). No reply is expected to the login message.
2. `defaultProfileInfo` / `AET_Login`: `Found profile` ran, but nothing in the log shows a profile
   *selection* (`selectProfile` was never POSTed). If MP is still grey, the missing piece is the
   account-event push over WS (an account/profile update event) or `GetDefaultProfileInfo` on the
   login reply's `selectProfile`/`allProfileInfo` fields.
3. XAL suppression (PLAN §6.1): the PlayFab `/Client/LoginWithCustomID` 400 loop to the real cloud
   needs to be answered locally or suppressed (`"NON XBOX"` path) before the MP screen stops
   escalating; that also kills a repeated 16-32 s network round trip.
4. M2 start: relay advert identity (18c), then run `BattleServer.exe` and point the login reply's
   `relayServers` at it (raw 27012 / ws 27112 / oob 27212, token, region LAN).

## 18e. Tree state / artifacts
- `dev/lanhook/loginsrv.c`: WS server (18b), `0,[null]` readSession, opt-in probe.
- Builds: build.cmd clean (only the pre-existing C4090 const warnings), hooktest 68/68,
  srvtest+srvclient PASS including the WS assertions.
- Staged game-dir `dbghelp.dll` = crc `c1610785` (196,608 B) — this is the build with **binary** frame
  logging. Rollback `dev/lanhook/dbghelp.dll.prev-s18-before` (crc `7819a763`, 193,024 B = the s17
  build). `AoE2DE_s.exe` untouched (`4f533b6c`, 72,176,952 B).
- Launcher unchanged: `PLAY-stage8-LOGIN.cmd` (AOE2LAN_STAGE=8, telemetry muted).
- Validation ritual unchanged: `hooktest.exe` (68/68) → `srvtest.exe` + `python srvclient.py` (PASS) →
  confirm no LISTENING on 127.0.0.1:443 → launch.
