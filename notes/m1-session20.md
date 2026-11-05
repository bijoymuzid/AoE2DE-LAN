# Session-20 (2026-11-04, M1) — the rlink WS code is readable; the frame grammar, partly proven

## 20a. Headline
Four supervised runs. Three results that change the shape of the problem:

1. **The "dispatcher is inside Arxan / unhookable" conclusion was a bug in our xref tool, not a fact.**
   `dev/lanhook/aoe2re.py`'s `xrefs()` computed targets from *file offsets* instead of VAs. With
   `lea rip+rel32` resolved correctly (`VA = 0x140001000 + offset` for `gametext.bin`, `.rdata` VA =
   `imagebase + file offset`), the whole rlink WebSocket path resolves and disassembles cleanly.
2. **Every s19/s20 push was rejected by the client's own reader** — the client logs
   `WebSocketConnection - failed to parse notification messages [<frame>]`. That log goes through
   `0x1402BCC00`, which is **clean on disk** (prologue byte-identical to the proven-safe `LogHelper`)
   and had never been hooked, so we were blind to every verdict for two sessions. It is now hook
   **id 13 `LogWarn`**, and it is the fastest oracle we have.
3. **The wire grammar, measured in-game** (see 20d): `null,` parses · `null` fails · `0,` fails ·
   `{},` **parses** · `[],` fails · every object carrying keys fails. So: the frame is a
   **comma-terminated object**, and an object may only contain the three envelope keys plus one
   registered payload container at the end.

## 20b. Static map of the WS login/poll path (all readable, all in `gametext.bin`)
| VA | what it is |
|---|---|
| `0x1406d1170` | `WebSocketConnection::Process` — big frame (0x10160). One `recv` → **one message** (no internal splitting); appends each read to a list; then `{"operation":1,"ackCount":<frames read>}`; then parses each message. `SO_RCVTIMEO` gates the loop, i.e. the push pump only advances on socket events. |
| `0x1406d143a` | `LogHelper` echo `WebSocketConnection::ProcessMessages: message=%s` (fires for *every* frame, parse verdict irrelevant). |
| `0x1406d17d4` | `LogWarn` `failed to parse notification messages [%s]` after the parse returns false. |
| `0x1407a7620` | the frame reader (`ParseMessage`): accepts `null` or `[`…`]` or `{`…`}`; fields **positional or named**: `result` (int32, range-checked), `m_type` (string), `m_profileID` (int64). |
| `0x1407a7ace` | **mandatory** fallback: hands the cursor to the registered-payload registry; if no registered parser accepts the bytes → the whole frame parse fails. Runs after the third field, at the container end for `{}` it is never reached. |
| `0x1407a7070` | the registry walker: iterates the global list at `0x144c9e3e0`, calling each `fn(tmp, reader, &out->m_type)` until one returns non-null, then stores a `shared_ptr` in `out+0x30`. |
| `0x1407a7d30` | `[ … ]` of messages, each element re-entering `0x1407a7620` (used by the `"messages"` key). |
| `0x144116af0 + 0x10k` (56 nodes) | registered payload parsers, first qword = fn. None of the 56 references `resultCode`/`accountInfo`/`defaultProfileInfo` (re-scanned with correct bounds — the earlier scan broke at the first `ret`). Only #44/45/53 call into `0x140618xxx`/`0x14061axxx`. |
| reader helpers | `0x14039b8e0` = consume `null` **then require `,`** · `0x14039b860` = expect `,` · `0x14039b550` = advance n · `0x14039bb50` = peek char · `0x14039b7c0` = skip ws · `0x14039c900` = read number · `0x14039cc60` = read string · `0x14039a910` = open container (`[` else `{`) · `0x14039b340` = next member/end · `0x14039ac90` = skip value. |

## 20c. The rule the client itself proved
Every value in this stream must be **followed by a comma** (`0x14039b8e0` ends with `expect ','`,
`0x1407a7bfd` too). `null,` parses; `null` does not. That single byte invalidated all six s19
pushes (chunk wrappers) and all twelve s20-candidates from run 1 — none of which were ever wrong
about transport, frame, payload or name.

## 20d. Run-by-run verdicts (hook id 13 = ground truth)
Run 1 `logs/lanhook-24196.log` (s20 candidates, no comma): all 12 fail. Run 2 `logs/lanhook-7816.log`
(comma added): `null,` ok, `null` fail, `0,` fail, `[0,"AccountLoginEvent",<pid>,{Info}],` fail,
`{"result":0,"m_type":…,"m_profileID":…,{Info}},` fail, `{"messages":[…]}`, `1,[[[…]]]`, and all name
variants fail.
Run 4 `logs/lanhook-30612.log` (prefix ladder, 108 s, healthy):
```
[],            FAIL
{},            PARSE OK          <- object at top level is right, array is not
[0],           FAIL
[0,"…"],       FAIL      [0,"…",<pid>], FAIL      … rest of the ladder: FAIL
{"result":0},  FAIL      {"result":0,"m_type":…}, FAIL   +m_profileID FAIL   +resultCode FAIL   +accountInfo FAIL
```
Reading with `0x1407a7620`/`0x1407a7070` in hand: `{}` succeeds because the payload fallback is never
reached. Any object with keys reaches the fallback (`0x1407a7ace`) and fails because the payload
parser for that content is not registered. So the remaining candidate is the **bare payload
container** in object form:
`{"result":0,"m_type":"<EventName>","m_profileID":<pid>,{…payload…}},`

## 20e. Fixed this session
- **Stale-root leak (crash cause).** `mint_cert()` creates a fresh key container + fresh self-signed
  cert every launch and `RootRegThread` adds it to `CURRENT USER\Root`; nothing removed the old ones
  → **44 stale roots with the same DN, different keys** had accumulated, and runs 20:33/20:34 died
  at ~1.1 s inside the client's cert-store build (zero sockets opened — nothing to do with the push
  code). Purged by hand; `purge_aoe2lan_roots()` now deletes every root whose encoded `Subject`
  matches ours byte-for-byte before adding this run's (verified: `cert: purged stale roots=1`).
  Stale `aoe2lan-*` CSP key containers still leak (~130 on disk) — harmless, not yet swept.
- **Crash vs hang visibility.** `SetUnhandledExceptionFilter` → `CRASH code=… at=… game+0x… modBase=…
  +0x…` plus stack words that land inside the game image (pseudo-backtrace); a 5 s `hb alive sec=N`
  heartbeat so a truncated log is classifiable. Process-level APIs only, no game-code patching.
- **Pump cadence.** `SO_RCVTIMEO` 60 s → **1 s** in `ConnWorker` (the pump advances between reads, so
  a 4 s interval was silently becoming 10 s); keepalive ping now resets `quiet`. Verified 3 s.
- `srvclient.py` asserts the whole candidate ladder; `hooktest` 68/68; srvtest+srvclient PASS.

## 20f. Next (cheapest first)
1. **Bare-payload object**, 4 s apart, in one run:
   `{"result":0,"m_type":"AccountLoginEvent","m_profileID":<pid>,{Info}},` with `resultCode:99`
   (a dispatch is unmistakable: `Enum changed on the server AccountLoginEvent::Result` via hook 13).
   Then the same with `resultCode:0` and expect `Account info:` / `Default profile info:` /
   `AET_Login/R_Success profileID=`.
2. If the fallback rejects our Info, prove the registry path first with a payload a registered parser
   accepts (handler #0 wants a `"achievement"` member) and then walk the 56 parsers for the one that
   accepts `resultCode`/`accountInfo` (they are *not* among the 56 by string, so check their
   callees/type descriptors, or accept that the login event is delivered on a different stream).
3. **Fallback that bypasses the WS entirely**: answer the **long poll** `POST /game/login/readSession`
   with the same `"<ackNum>,[<chunks>]"` text (`1,[[[0,"AccountLoginEvent",<pid>,{Info}]]]`). The
   login stream is `WorldwideLoginService/WorldwideLoginStream` (enum log at `0x143691e28`, keys at
   `0x143692020`), and if the WS notification path cannot carry a login event, the poll reply is the
   supported channel. Gate: the client only falls back to polling if the WS doesn't answer
   `RL_USE_WEBSOCKET_PERCENT`… test with the env var, cheap.
4. Then M2: run `BattleServer\BattleServer.exe` (`-bsPort/-webSocketPort/-outOfBandPort/
   -relayBroadcastPort`) and aim the login reply's `relayServers[]` at it.

## 20g. Tree state
- staged game-dir `dbghelp.dll` = crc **598910b1** (202,240 B); rollback
  `dev/lanhook/dbghelp.dll.prev-s20-before` = crc `c6793b01` (s19 build). `AoE2DE_s.exe` untouched
  (crc 4f533b6c).
- `dev/lanhook/loginsrv.c`: `PUSHCAND {label,tpl,trail}` template table (`%p` profileID, `%r`
  resultCode, `%A` accountInfo, `%P` defaultProfileInfo, `%I` full Info), `emit_rc()`,
  `emit_info_body()`, `build_cand()`, `purge_aoe2lan_roots()`, `PUSH_INTERVAL_MS 3000`.
- `dev/lanhook/lanhook.c`: hook id 13 `LogWarn 0x1402BCC00` (grp 2), stage-8 filter now selects
  grp 2|3 by group instead of by index; `LanCrashFilter` + `HeartbeatThread`.
- New tools this session: `dz.py` (annotated disassembly with string/symbol resolution),
  `rr.py` (any rip-relative ref to a VA), `cx.py` (E8 call xrefs). Use these; the old `xrefs()` lies.
- Root store after cleanup: 0 stale AoE2LAN roots (the DLL keeps exactly one).