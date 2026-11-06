# Session-30 — the LAN switch is real and it is already offered

Supersedes `notes/m1-session29.md` for state. Everything below is MEASURED unless the line says
INFERRED. No game file, no `.text` byte, no XAML was changed. The only code change is a read-only
readout added to `dev/lanhook/lanhook.c` (`rules_probe`).

## 30a. Offline gates (re-run, pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS** (`leaderboards reply: object, 1 entry`).
- `AoE2DE_s.exe` crc **`4f533b6c`** — untouched.
- `dbghelp.dll` rebuilt from unchanged sources this session: crc **`579ed184`** (217,088 B). The
  bytes differ from s29's `06472804` only because a rebuild is not bit-reproducible; the source is
  the same plus the readout in 30c.

## 30b. MEASURED: the create-lobby Server dropdown already offers the LAN entry

Operator, in the live game (pid 17444), opened Multiplayer → Host Game → Create Game:

| control | contents |
|---|---|
| **Server** dropdown (`Background/Settings/RegionAnchor/RegionDropDown`) | `Default`, `LAN`, **`Use Local Lan Server`** |
| **Lobby Type** dropdown (`.../LobbyTypeAnchor/LobbyTypeDropDown`) | `Public`, `Private` |

So the LAN door is not hidden behind a flag we have to flip: the game offers it, on this install,
with our login shim in place. The s29 lead was right about the string and wrong about the widget —
the item is appended to the **Server/Region** dropdown, not the Lobby Type one.

## 30c. MEASURED: the code path, and the check that gates it

`0x1418eee60` (1032 B) is the function that fills that dropdown:

1. `0x140ac4090("Background/Settings/RegionAnchor/RegionDropDown")` → `0x140ab0660("DropDownListBox")`.
2. Loop over the item vector at `[0x1442dc4f0]+0x2628 .. +0x2630`, **stride 0x50**, one listbox item
   per record (`0x140acad40` builds the 0xc0-byte item, `0x140adbb30` appends it).
3. Then, at `0x1418ef107`: `rcx = [[0x1442dc4f0]+0x2e8]`, `call [[rcx]+0x418]`, and **only if the
   result is non-zero** it appends one more item, text key `IDS_LOBBY_CREATE_USE_LOCAL_LAN_DROPDOWN_ITEM`
   (`0x143322df0`, string id 300414 = `"Use Local Lan Server"`), at index `-1` (append).

The gate function is **`0x140f0f5c0`** (44 B):

```
mov rcx, [rcx+0x31e0]      ; null -> return false
call qword ptr [0x143197998]   ; (obj, 0)
cmp eax, 0x102
sete al
```

Read-only probe added to `rules_probe()` (same `AOE2LAN_RULES=1` flag, nothing written):

```
rules: svc slot+0x418 fn = game+0x0000000000f0f5c0
rules: svc slot+0x418 LAN item gate = 257        (low byte = 1 -> true)
rules: root dropdown item count (0x50) = 2
```

identical at t=25/40/70 s. `2` records + the appended LAN item = the three entries the operator saw.
The gate is **true on this install**, which is why the entry is there.

Note on the probe value: the function returns `char` in `al`; the readout prints the whole `eax`, so
`257` means `al = 1`. Read the low byte, not the number.

## 30d. What is still open

1. **Does selecting `Use Local Lan Server` change the host mode?** Host mode lives at
   `[advertSvc+0x1a8]`: 0 = online, 2 = offline, anything else = LAN (`0x140351343`, log lines
   `0x14367ee40/58/78`). s29 measured `starting online hosting` and then a silent failure. The test
   is one click: Server = `Use Local Lan Server`, then Create. The log must say **`starting LAN
   hosting`** instead of `starting online hosting`.
2. If it does, the next question is whether a lobby appears and whether the relay is addressed at
   the tailnet IP. The relay the game starts is `BattleServer\BattleServer.exe`; in this run the
   client logged `Adding LAN relay server: 192.168.0.104, GUID 134b56f5-…` at t=14.4 s, i.e. the
   relay is discovered on the machine's LAN address, not loopback.
3. The online host path (s29j) stays unexplained and is now the *fallback*, not the main road: no
   advertisement request is ever sent, and `WorldwideHostAsync`'s failure log never fires.

## 30e. Tooling notes

- `xr.py` was reliable this session for `.rdata` string xrefs; the one `<unconfirmed>` hit
  (`0x142f1a651`) is in a data blob, not code.
- `fn.py <addr>` gives pdata bounds; `fn.py <addr> --dump` disassembles the whole function from
  `gametext.bin`. Both were enough to read `0x1418eee60` and `0x140f0f5c0` without Ghidra.
- The `.rdata` string table is read from `AoE2DE_s.exe` directly (not `gametext.bin`, which is
  `.text` only). `widgetui/stringreference.json` maps key name → string id, and
  `resources/en/strings/key-value/key-value-strings-utf8.txt` maps id → text; that pair is how
  `300414` became `"Use Local Lan Server"`.

## 30f. MEASURED: the LAN host attempt (operator, pid 12192, Server = `Use Local Lan Server`)

The dropdown works: the log line changed from `starting online hosting` to **`starting LAN
hosting`** (`0x14035144a`, host mode `[advertSvc+0x1a8]` was NOT 0 and NOT 2). So the UI selection
reaches the hosting decision.

The create still fails, with the same operator-visible dialog (`Could not create game. Server
Error. Source: AdvertisementJoinEvent Error Code: 0x00000001`) and a new set of facts:

```
[t=136.671s] DNS resolve DESKTOP-64DAV0P -> 100.79.215.72 (tailnet) and 192.168.0.104 (LAN)
[t=136.687s] LogHelper: "starting LAN hosting"
[t=136.765s] TCP connect 127.0.0.1:443 (ours) -> TLS complete at 136.828
[t=136.875s] client sends 410B of TLS application data on that connection; our server logs no
             request and sends no reply
[t=137.890s] client closes that connection (close_notify)
[t=137.953s] LogHelper: "HostAsync - completed with HostResult = %d" -> 1
```

- **Still no advertisement HTTP request**: `/game/advertisement/` appears only at 35.9 s and
  81.3 s (browsing), never in the host window.
- **No connection to the relay's raw port 27012** at any point in the session; the 30 connections to
  27212 are the QoS probe (t=4…33 s). The relay itself was running (the QoS loop proves it).
- Both s29j mystery strings are referenced from **inside the same function that logs `starting LAN
  hosting`** (`0x1403503a0..0x1403526fc`): `"join failure - we don't have a slot reservation"`
  (`0x14367e950`, logged at `0x14035165e` through hooked `LogWarn`) and `"%s: This AsyncJob is not
  the active connect, waiting..."` (`0x14367e980`, logged at `0x140351606`). Neither fired in this
  run, so the host job did not take either of those two branches — it failed somewhere else.
- The host decision then calls `0x14034f240(rcx=advertSvc, edx, r8)` — with `edx = 9` on the
  normal path, and `0x16` (22) on the "no slot reservation" path. `0x14034f240` is the function that
  logs `HostAsync - completed with HostResult = %d`.
- `LANAdvertisementCache - response was not formatted correctly: [0,[]]` is logged twice (at 35.9 s
  and 81.3 s) — our catch-all reply to `/game/advertisement/getLanAdvertisements` is still malformed.

## 30g. New instrument: per-connection transcript in our own server

`serve_conn()` in `loginsrv.c` now logs, for every connection: `srv: blk#<conn> n=<bytes>` for each
decrypted block, `srv: req#<conn> n=<request bytes>` just before dispatch, `srv: too big#<conn>`
when the 8 KB request buffer guard trips, and `srv: closed pending#<conn> n=<unparsed bytes>`.
It is our own file; no game hook, no game memory. Purpose: settle whether the 410-byte block at
host time is a request we failed to parse (a shim bug we must fix) or a request the game never
finished (a game-side abort).

## 30h. FOUND AND FIXED: our server never answered "Expect: 100-continue"

The second run (pid 18384, same click) showed the request arriving:

```
[t=60.719s] client -> 127.0.0.1:443  3578B TLS record
[t=60.719s] srv: blk#14 n=3549          <- we decrypted the whole 3.5 KB request
[t=61.719s] srv: closed pending#14 n=3549   <- and sat on it for exactly 1.000 s
[t=61.797s] LogWarn "WorldwideHostAsync - failed with reason %d" r8=-1 r9=0x60
[t=61.797s] LogHelper "HostAsync - completed with HostResult = %d" -> 1
```

Every other request in the session is answered (`srv: req#N`); this is the only one that is not.
It is also the only request bigger than 1 KB. The game's HTTP client is **libcurl** (its own
warnings appear in the log: `curl_easy_setop failed; option=CURLOPT_SSL_CTX_FUNCTION`), and libcurl
adds **`Expect: 100-continue`** to POST bodies over 1024 bytes, then waits **exactly 1000 ms** for
the interim `HTTP/1.1 100 Continue` before it sends the body. Our server never implemented the
interim reply, so the body never came, and the client aborted at its 1 s deadline. That is the whole
hosting failure: the game tried to create the advertisement and we hung up on it.

Fix (ours, `dev/lanhook/loginsrv.c`):

- when the header block is complete and contains `Expect: 100-continue`, send
  `HTTP/1.1 100 Continue\r\n\r\n` once, then keep waiting for the body;
- the per-connection HTTP state is now per connection: the request buffer is a 64 KB heap block
  (was a `static char req[8192]` shared by every connection thread), `head[512]` moved from static
  to the stack, and the TLS send scratch buffer is `__declspec(thread)` instead of a plain static.
  Those were real data races between the ~35 connections the game keeps open, not cosmetic, and the
  old 8 KB request cap would have truncated larger advertisement bodies.

## 30i. Tests (offline, both new, both fail on the old code)

`dev/lanhook/srvclient.py` now also checks:

- `concurrent requests: 6/6 answered` — six overlapping POSTs, each must get its own 200.
- `expect-100: interim ok, body 3022B answered` — send headers with `Expect: 100-continue`, read the
  interim reply, then send the body. Removing the new block makes this one print
  `FAIL: no 100 Continue reply (b'')`, i.e. the test does catch the bug.

Gates after the fix: `hooktest.exe` 68/68, `srvtest.exe` + `srvclient.py` PASS, `AoE2DE_s.exe` crc
`4f533b6c` untouched, staged `dbghelp.dll` crc **`883a488f`** (234,496 B — grew by the extra
per-connection logging and the 64 KB request buffer).

Not yet measured: whether the create now succeeds. That is the next single click.

## 30j. MEASURED: the fix worked — hosting now sends its request, and fails on our reply

Third run (pid 3124, Server = `Use Local Lan Server`). The `Expect: 100-continue` fix is confirmed
in game:

```
[t=538.188s] LogHelper: "starting LAN hosting"
[t=538.406s] srv: blk#31 n=381
[t=538.406s] srv: 100-continue#31 n=1383      <- our interim reply, the body follows
[t=538.500s] srv: req#31 n=1764
[t=538.500s] HTTP REQ /game/advertisement/host
[t=538.500s] HTTP BODY advertisementid=-1&appbinarychecksum=188329&automatchPoll_id=-1&
             callNum=58&connect_id=1193958235&datachecksum=0&description=AnkerGames%27s%20Game&
             hostid=3842241165083521967&isObservable=0&joinable=1&mapname=my%20map&matchtype=-1&
             maxplayers=8&moddllchecksum=0&moddllfile=INVALID&modname=INVALID&mo…
[t=538.500s] HTTP RESP BODY [0,[]]            <- the catch-all, still an array
```

Downstream, with that reply:

```
[t=538.610s] "OnlineHostAsync success"
[t=538.610s] "Created Matchinfo for sessionID %llu"            -> -1
[t=538.610s] "OnJoinAdvertisementSuccess - joined online match, server leave notification required"
[t=538.610s] "starting local hosting"
[t=538.610s] "PeerRemoveAll - flushing local session peer data"
[t=538.610s] "Destroyed Matchinfo for sessionID %lld"          -> -1
[t=598.625s] "HostAsync - completed with HostResult = %d"       -> 0xfffffff4 (-12)
```

Operator dialog this time: **`Could not create game. Request was invalid. Source:
AdvertisementJoinEvent Error Code: 0xfffffff4 extended code: 0xffffffff`** — a different and later
error than session 29's `0x00000001`, which is what the fix bought.

⇒ The game does reach the advertisement-create call and the request *is* carried. What is missing is
the **reply**: with an array reply the host gets advertisement id `-1`, joins with that, and the
whole chain unwinds. `/game/advertisement/leave` is then retried every ~10 s for the rest of the
session with `advertisementid=-1` (9 times), i.e. the game is trying to clean up a lobby it never got.

Where the reply is read: `0x140309298` (the message that references `OnJoinAdvertisementSuccess`,
`0x14367d2d0`) receives the parsed DTO; `0x140351771` (`call 0x1402ff080`) then does
`rdi+0x358 = rdi+0x80` and passes `&[rdi+0x390]` on, with the success log `OnlineHostAsync success`
(`0x14367ee90`) at `0x14035171e` in the same function. That function (`0x1403503a0`) is the same one
that logs `starting LAN hosting`, so the whole host flow is one function.

## 30k. Change made, not yet measured: a real `/game/advertisement/host` reply

`loginsrv.c` now answers that path with an object instead of the catch-all:

```json
{"result":0,"advertisementid":1,"hostid":<echo of the request's hostid>,
 "sessionID":1,"maxplayers":8,"matchtype":-1,"slotinfo":null,"encodedSlots":""}
```

`slotinfo`/`encodedSlots` are a first guess — the real slot layout has to be copied from what the
create dialog produces (the request's own `slotinfo` field, which our log truncates at 300 chars;
raise the `log_body_head` cap when the slot error appears). Gates after the change: `hooktest.exe`
68/68, `srvtest` + `srvclient` PASS (3 checks incl. 100-continue and 6 concurrent), game exe crc
`4f533b6c` unchanged. Staged `dbghelp.dll` crc `159dcdab` (235,520 B).
