# Session 47 — SOLVED: the WS notification frame is a positional array, MatchStartMessage parses, AET_MatchStartNotify fires

Supersedes `notes/m1-session46.md`. All addresses are VAs unless written `RVA`.
One game run this session (`logs/lanhook-11640.log` = the run that cracked it; an
earlier run `logs/lanhook-10516.log` died at t=5 s, see §47e). Game exe untouched
(`affb19f03ca96965abf9e56775cab688`). DLL rebuilt twice → **`cc68c98ec43e6fcb38a0aa5c6906fb16`**.

## 47a. The answer, and the mistake that hid it for four sessions

**The server→client websocket notification frame is a POSITIONAL JSON ARRAY:**

```
[ <result:int>, "<m_type:string>", <m_profileID:int64>, { <body> } ]
```

Measured live in a real game process, `parsefail=0`, and the game then logged
**both** `WorldwideAutomatchService::OnStartComplete - detected successful game
start` and `[Network] OnAdvertisementEvent/AET_MatchStartNotify result=%d
date=%lu session=%ls` — the event §43 identified as "the only thing that builds
the roster the match loads from" and that had never fired in 43 sessions.

Winning frame (168 B, opcode 2 and opcode 1 both work):

```json
[0,"MatchStartMessage",3842241165083521967,{"ownedAppIDs":[],"profileRaces":[],"matchStartDate":0,"equippedItems":[],"matchAdvertisement":{},"inProgressChallenges":[]}]
```

**The mistake:** §45a's ENCRYPTED list means *cannot be hooked* — the on-disk
`.text` bytes differ from the runtime bytes. It does **not** mean *cannot be
read*. `dev/lanhook/gametext.bin` is a dump of the **decrypted** `.text`, so every
function on that list is fully disassemblable offline. Sessions 43–46 treated
"encrypted" as "opaque" and spent ~110 live payload guesses on a question that
was sitting in a file we already had. **Read the dump; only the hooking is
forbidden.**

## 47b. The whole parse chain, read out of gametext.bin

`WebSocketConnection::Process` is `0x1406d1160..0x1406d204f`. It logs
`WebSocketConnection::ProcessMessages: message=%s` (string @ `0x143699068`),
acks with `{"operation":%d,"ackCount":%d}` (@ `0x143699048`), then calls the
**envelope reader `0x1407a7620`** directly at `0x1406d16cc`. On false it logs
`WebSocketConnection - failed to parse notification messages [%s]`
(@ `0x143699000`) — that is the line hook 13 counts as `parsefail`.

The reader is a hand-rolled streaming JSON parser over these helpers (all in the
`0x14039xxxx` block, all readable in the dump):

| fn | role |
|---|---|
| `0x14039b7c0` | SkipWhitespace |
| `0x14039bb50` | PeekChar |
| `0x14039b860` | SkipComma (ws, optional `,`, ws) |
| `0x14039b8e0` | IsNull (literal `null` → consume + SkipComma) |
| `0x14039a910` | **BeginContainer — needs `[` or `{`, else false** |
| `0x14039b340` | NextKey (object mode: reads `"key":`; array mode: element counter) |
| `0x14039b5a0` | ScanToken (number/string), **ends in SkipComma** |
| `0x14039c900` | ReadInt64 (via ScanToken + strtoll) |
| `0x14039cc60` | ReadString, **ends in SkipComma** |

Envelope reader `0x1407a7620` → struct `{int32 result @+0; std::string m_type @+8;
int64 m_profileID @+0x28; shared_ptr @+0x30/+0x38}`. It checks `result`,
`m_type`, `m_profileID` **in that order**, and in array mode (`state[1]==0`)
reads them **positionally** with no keys at all. Then it calls
**dispatch `0x1407a7070`**, which walks the 46-node registry at RVA `0x4c9e3e0`
and **returns false if no factory returns an object**.

Node `0x24` is `MSThunk 0x1407b66f0` → **factory `0x1407cdf10`**, which:

1. `m_type.size() == 0x11` and `memcmp(m_type, "MatchStartMessage", 17) == 0`
   (exact, case-sensitive) — else return null;
2. allocates `0x2c8` bytes, vtable `0x143676890`;
3. `__RTDynamicCast` (ILT thunk `0x142d705a5`) of the reader to the JSON reader
   type → body parser **`0x1407b6710`**; if that cast fails, a second cast and
   body parser `0x1407b73f0` (the keyless/positional variant);
4. **if the body parser returns false, the factory returns null.**

**Why every object shape in §46e was doomed:** each value reader ends in
SkipComma, so after `m_profileID` the parser sits on the *next token*. In object
form that token is `}`. The body parser's first act is BeginContainer, which
needs `[` or `{` → false → factory null → dispatch false → parsefail. In array
form the fourth element supplies the `{`. It was never the members and never the
key names; it was the container.

**Body layout** (offsets in the `0x2c8` object; order is identical in reader
`0x1407b6710` and writer `0x1407b7220`):

| offset | key | reader |
|---|---|---|
| +0x08 | `ownedAppIDs` | `0x14057b600` |
| +0x20 | `profileRaces` | `0x1407d4300` |
| +0x38 | `matchStartDate` (int64) | `0x14039c900` |
| +0x40 | `equippedItems` | `0x1403e3dc0` |
| +0x58 | `matchAdvertisement` | `0x14056cce0` |
| +0x2b0 | `inProgressChallenges` | `0x1407d4490` |

All six are optional (no required-field bitmap); `{}` alone measures
`parsefail=0`. §46e only knew three of them: the bond string table beside
`WorldwideNotificationStream.cpp` (`0x14369eb40`, `MatchStartMessage` @
`0x14369ee08`) lists only `inProgressChallenges`/`matchAdvertisement`/
`profileRaces`, because the other three are declared in a different region
(`ownedAppIDs` `0x14368c608`, `matchStartDate` `0x14368c5f8`, `equippedItems`
`0x14368c5e8`). §45a had already found all six as "m-read" addresses; §46e's
bond-table reading dropped them.

**`matchAdvertisement`** — reader `0x14056cce0` and writer `0x14056dda0` agree on
27 keys in this order: `id, steamLobbyID, goodOldGamesLobbyID, psnPlayerSessionID,
psnMatchId, xboxSessionID, hostProfileID, matchState, description,
filteredDescription, visible, mapName, options, isPassworded, maxPlayerCount,
encodedSlots, matchTypeID, matchMembers, observerNum, observerMax, isobservable,
observerDelay, isObserverPassworded, service, matchStartTime, matchRegion,
matchRegionLocalized`. NextKey consumes `"key":` in object mode and skips a
member that did not match in turn, so **key order can silently drop fields**. We
emit 21 of the 27 (no `id`, no platform lobby ids) and they are now emitted in
reader order (§47f).

**The long-poll container is different:** `0x1407a7220` reads the key
`"messages"` (@ `0x143681eb8`) and hands the value to `0x1407a7d30`. Its failure
line is `ProcessLongPoll - failed to parse notification messages [%s]`
(@ `0x14369e108`). So `{"messages":[…]}` is the HTTP shape and **must not** be
used on the websocket — measured, it is rejected there. Route 1 of §46h is now
unnecessary and should not be pursued.

Also useful: `ProcessNotification - Notification not handled [%s]` @
`0x14369e2a8` is a *distinct* verdict from the parse failure — it means the frame
parsed but no stream claimed it.

## 47c. The live measurement (run 11640, t≈260 s, no lobby needed)

`livepush.py s47`, all on the live channel at the main menu — **a hosted lobby is
not required to test a payload shape**, `ping` reports `armed=1` as soon as the
game's rlink websocket is up (t≈4 s).

| payload | op | parsefail | thunkhits |
|---|---|---|---|
| `[0,"MatchStartMessage",pid,{six keys}]` | 2 | **0** | 1 |
| same | 1 (TEXT) | **0** | 1 |
| `[0,"MatchStartMessage",pid]` (no body) | 2 | 1 | 1 |
| `{"result":0,"m_type":"MatchStartMessage","m_profileID":pid}` | 2 | 1 | 1 |
| `[0,"SessionStatusMessage",pid,{…}]` | 2 | **0** | 0 |
| `{"messages":[<positional>]}` | 2 | 1 | 1 |
| `[[<positional>]]` | 2 | 1 | 0 |
| `[0,"MatchStartMessage",pid,[],[],0,[],{},[]]` (body inline) | 2 | 1 | 1 |

Every control failed exactly where §47b predicts. Note the last two columns:
`thunkhits=1` for the object envelope too, so **§46d's "thunk fires for any
top-level object" was an artefact of the s46 payloads** — with the array form,
`SessionStatusMessage` gives `thunkhits=0` (a different node matched first).
`parsefail` remains the only verdict that matters.

## 47d. Trap: `message=%s` echoes the raw frame — use it to check what you sent

The first `s47` batch failed with `parsefail=1` across the board, and the log
showed why immediately:

```
ProcessMessages: message=[0,"MatchStartMessage",3842241165083521967,[["ownedAppIDs",[]],["profil…
```

`_body()` returned a **list of `(key, value)` tuples**, and `json.dumps` renders
tuples as arrays — so the body went out as `[["ownedAppIDs",[]],…]` instead of
`{"ownedAppIDs":[]…}`. The object-form controls had the same bug. Fixed by
returning a real `dict` (insertion order preserved), and `livepush.py selftest`
now asserts the serialized frame contains `{"ownedAppIDs"` and **not**
`[["ownedAppIDs"`.

General rule: `WebSocketConnection::ProcessMessages: message=%s` prints the exact
bytes we pushed (hook 4 truncates it to 70 chars, enough to see the shape).
**Read that line before believing any payload verdict.**

## 47e. Trap: `srvtest.exe` holds port 443 and the game silently talks to it

Run 10516 booted perfectly — cert auto-clicked at t=0.188, `live: payload channel
listening`, `srv: H1 login server listening on 127.0.0.1:443` — and then made
**zero** TLS handshakes and vanished between t=5 s and t=10 s. No crash in the
Windows Application log.

Cause: `loginsrv.c` sets `SO_REUSEADDR` before `bind` (line ~2301). On Windows
that lets a second socket bind a port another socket is already listening on, so
the game "bound" 443 while the `srvtest.exe 90` from the gate run still owned it,
and the game's connections went to srvtest. **Never launch the game until
`tasklist | grep srvtest` is empty and `netstat -ano | grep 127.0.0.1:443` shows
no LISTENING.** Both gate runs this session were waited out before launching.

## 47f. What changed in the shim

- **`build_match_start()`** now emits the positional array. The s45 3-variant
  ladder is kept, because it is now a real fallback rather than a guess list:
  `0` = all six body members with the real advertisement; `1` = empty body `{}`
  (measured `parsefail=0`, so it still fires AET_MatchStartNotify if the
  advertisement body is what breaks); `2` = `matchAdvertisement` only. The
  stop-on-no-failure rule is unchanged, so in game the ladder pushes variant 0
  once and stops. §46i forbade touching the ladder "without a measurement that
  says to" — §47c is that measurement.
- **`emit_advertisement()`** keys reordered into reader `0x14056cce0`'s order
  (`matchState` moved 11th→2nd, `visible` before `mapName`, `encodedSlots` after
  `maxPlayerCount`, `matchMembers` moved last→18th, `isobservable`/`observerDelay`
  after `observerMax`, `service` after `isObserverPassworded`). Still 21 keys;
  `hostProfileID` must stay first because `adv_raw`/`adv_num` emit a leading comma.
- **`srvclient.py`** asserts the 4-element positional frame, the body key order,
  and the advertisement key order; the ladder expectations are now body key sets
  (`variant1 empty-body` = `{}`, `variant2 advert-only` = `{matchAdvertisement}`).
- **`work/livetest.py`** needle changed from `"m_type"` to `"MatchStartMessage"`
  + a `[0,` prefix check.
- **`work/livepush.py`** gains `s47` (the batch above) and `selftest`;
  `sweep`/`bisect`/`types` are marked CLOSED in the docstring — kept only as the
  §46e evidence trail, do not re-run them.
- **`work/keys.py`** (new): dumps the JSON key names any bond-generated reader or
  writer probes, in parse order, straight out of `gametext.bin`. This is the tool
  that produced §47b's tables — `python work/keys.py <va> [<va>…]`.

## 47g. Gates (current build — all re-runnable, all passed)

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged.
- `dbghelp.dll` MD5 **`cc68c98ec43e6fcb38a0aa5c6906fb16`**, identical in the game
  dir and `dev/lanhook/`. Backups taken BEFORE each build:
  `.prev-s47-before` = `21fb2d236ad342ac9647cd7bbdc97fef` (the s46 build),
  `.prev-s47b-before` = `1ed7df4d5cf19110e510fe77cd48d534` (intermediate, before
  the advertisement reorder).
- `hooktest.exe`: `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`,
  `swapped 68 of 68`.
- `AOE2LAN_LIVE=1 srvtest.exe` + `srvclient.py`: **PASS**, including
  `updateState reply: matchState=1`, `MatchStartMessage push: 758B`,
  `ladder variant1 empty-body: 46B`, `ladder variant2 advert-only: 650B`,
  `ladder terminated after variant2`; plus `work/livetest.py`: **PASS**
  (`GETVARIANT 1` 46 B, `GETVARIANT 0` 758 B).
- `work/verifydll.py`: **19** HOOKDEF entries; `MSThunk va=0x1407b66f0 … grp=0
  kind=0`; `GLog va=0x1407db520 … grp=0 kind=7`.
- `dumpbin -IMPORTS` → **KERNEL32.dll only**.
- Build warnings are the pre-existing C4090 five, now at loginsrv.c
  **690/692/694/1921/1952**.

## 47h. Next session

**Priority 1 is down to one measurement:** host a lobby with 3 AI, press Start,
and read the log. The shim pushes variant 0 on `updateState matchState=1`. Look
for, in order:

1. `MSLADDER pushing variant=0` then `MSLADDER PARSED - no failure logged,
   ladder stops` — the shim's own frame parsed in game (offline it is 758 B).
2. `OnAdvertisementEvent/AET_MatchStartNotify result=%d date=%lu session=%ls`.
3. Then either the scenario loads (`GAMEDATA`, `[Network]` lines) — Priority 1
   done — or one of these, each of which names the next fix:
   - `WorldwideNotifier::ProcessNotification: Failed to add profile information
     to slots.` → the advertisement body parsed but a nested member is wrong
     shape; `matchMembers` is the likely one (its element reader has not been
     dumped yet — do that with `work/keys.py` before guessing).
   - `A match discrepancy has been detected, can't start the match.` → the
     advertisement we echo back disagrees with the game's own lobby state.
   - `ProcessNotification - Notification not handled [%s]` → parsed, but no
     stream claimed it; the profileID or session is wrong.
   - `MSLADDER variant=0 parsefail=1` then variant 1 parsing → the real
     advertisement body is the problem, and `[0,"MatchStartMessage",pid,{}]`
     is the known-good floor to bisect upwards from.

If a nested member needs fixing, `work/keys.py <reader-va>` gives its key list and
order in one command; the readers are all reachable from §47b's table.

**Priority 2 (AI) is untouched and independent.** §46f stands: the game's own
`slotinfo` has 8 slots with slots 1–7 empty, so the AI never reach the
advertisement even though hooks 15/16 fire. Now that the notification parses,
re-check whether the AI arrive via `matchMembers` in the pushed advertisement
instead — `emit_advertisement` currently hardcodes a **single** member (the
host), which is very likely Priority 2's real blocker on the notification path.

**Priority 3** still needs `relayIP` to stop being `127.0.0.1` (PLAN §W1-c).

The `ageLANServer` question (§46h route 2) is **moot** — the wire format came out
of our own binary. No decision needed from the operator.

## 47i. Do NOT (new, on top of §46i / §45g / §44h / §43h which all still hold)

- Do NOT send the notification as a JSON **object**, and do NOT wrap it in
  `{"messages":[…]}` on the websocket. Both are measured rejects (§47c). The
  `messages` container belongs to the long-poll path only.
- Do NOT pursue §46h route 1 (forcing long polling). The WS format is known; long
  polling would only add a second transport to maintain.
- Do NOT re-run `livepush.py sweep`/`bisect`/`types`, and do NOT re-test any §46e
  shape. They are closed.
- Do NOT treat "on the §45a ENCRYPTED list" as "cannot be read". Those functions
  are fully disassemblable from `gametext.bin`; only **hooking** them is forbidden.
- Do NOT believe a payload verdict without reading the
  `ProcessMessages: message=%s` line for that push (§47d).
- Do NOT launch the game while `srvtest.exe` is alive, or without confirming
  127.0.0.1:443 has no LISTENING socket (§47e).
- Do NOT reorder `emit_advertisement`'s keys away from reader `0x14056cce0`'s
  order, and do not move `hostProfileID` off the front (the helpers emit a
  leading comma).
- Still in force: no hooking anything on the §45a list, no fixed-window cleanliness
  checks, no re-deriving the registry node layout, `BUF b = {0};`, `.prev-*`
  backups of both `dbghelp.dll` copies before any rebuild, and no deleting the
  `srvtest.c` 1 Hz `g_ParseFail` bump (the offline ladder still needs it to
  escalate through all three variants).

## 47j. Files added / changed this session

| file | what changed |
|---|---|
| `loginsrv.c` | `build_match_start` emits the positional array (s47 comment block replaces the s43/s45 one); `emit_advertisement` keys reordered into reader order |
| `srvclient.py` | push assertions rewritten for the 4-element positional frame + body order + advertisement order; ladder expectations are body key sets |
| `work/livepush.py` | new `s47` batch and `selftest`; `_body` returns an ordered dict (the tuple bug); docstring marks sweep/bisect/types CLOSED and records the answer |
| `work/livetest.py` | GETVARIANT needle → `"MatchStartMessage"` + `[0,` prefix |
| `work/keys.py` | **new** — dumps a bond reader/writer's JSON key names in parse order from `gametext.bin` |
| `dbghelp.dll` (both copies) | rebuilt → `cc68c98ec43e6fcb38a0aa5c6906fb16` |

Unchanged on purpose: the hook table (still 19 entries, ids 4/5/13/14/15/16/17/18
active), `registry_dump()`, `srvtest.c`, the ladder state machine, the cert
auto-clicker, the live channel protocol.
