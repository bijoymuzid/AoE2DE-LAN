# Session-29 — M1 DONE: the Multiplayer screen opens

Supersedes `notes/m1-session28.md` for state. Everything below is MEASURED unless the line says
INFERRED. **Read 29i for the result, 29c for the fix, 29f/29g for what was behind it.** No game file, no `.text` byte, no XAML was changed. The only code changes are in
`dev/lanhook/loginsrv.c` (ours) and a read-only readout added to `lanhook.c` (ours).

## 29a. Offline gates (re-run, pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS**, and the client now also checks the new
  `getAvailableLeaderboards` reply: object, `result` 0, non-empty `leaderboards` array, first entry
  `{leaderboardID:int, leaderboardName:str, isRanked:bool}` (`leaderboards reply: object, 1 entry`).
- `AoE2DE_s.exe` crc **`4f533b6c`** — untouched. `dev/AoE2DE_dec.exe` `487054ce`.
- `dev/lanhook/gametext.bin` crc `ca040d52`. XAML stock crc `8398949b` — untouched.
- game-dir `dbghelp.dll` = `dev/lanhook/dbghelp.dll` = crc **`06472804`** (217,088 B, final build of
  this session — the build that made the button live; earlier in-session builds were `bbfeec88`
  and `617d80f3`).

## 29b. MEASURED: the reply schema of `getAvailableLeaderboards`

Session 28 pointed at `0x14074b8b0` as "the item parser" — that is wrong. `0x14074b8b0` is the
**array** reader for the member named `leaderboards`; its element parser is **`0x1407365e0`**, and
the element is three named fields:

| member | type reader | field |
|---|---|---|
| `leaderboardID` | `0x14039c900` (int64, range-checked -0x80..0x7f) | int |
| `leaderboardName` | `0x14039cc60` (string) | str |
| `isRanked` | `0x14039c730` (bool) | bool |

Element size 0x40 (appended by `0x14074f450`). The whole reply is parsed by **`0x14073d890`**
(source path in the binary: `rlink\internal\core\TypesStream.cpp`), which reads these members:

`result` (int, `0x14073d500`), `mappings`, `leaderboards`, `matchTypes`, `races`, `factions`,
`leaderboardRegions`, `rankLevels`, `statDefinitions`, `selfAssessmentTiers`, `matchHistoryID`,
`creatorProfileID`.

Which reply belongs to which cache was settled from the log, not guessed: `LogWarn #8` in the s28
log returns to **game+0x6aebca** (game base `0x7ff780ee0000`), inside the generic cache-response
handler **`0x1406ae110`**, which calls `0x14073d890` at `0x1406ae5eb` and logs
`"%s - response was not formatted correctly: %s"` with the cache name at `cache+0x38+0x20`.
So `LeaderboardInfoCache` ↔ `0x14073d890`. (The format string in *this* handler is a second copy at
`0x143677510`, not the one at `0x143676110` — that is why `xr.py` found no xref for it.)

`0x1406ae110` also shows why "format ok" is not enough: on success it stores the body length at
`cache+0xc8`, stores a string at `cache+0x78`, destroys the parsed struct and returns 1. It does not
hand anything to the leaderboard-definition registry.

## 29c. The change (relay side, ours)

`dev/lanhook/loginsrv.c`, `route()`: one new branch, `else if (contains(path,
"/game/Leaderboard/getAvailableLeaderboards"))`, replying with a single constant JSON object:

```json
{"result":0,
 "leaderboards":[{"leaderboardID":1,"leaderboardName":"1v1","isRanked":true}],
 "mappings":[{"leaderboardID":1,"matchTypeID":1,"statType":0,"raceID":0}],
 "matchTypes":[{"matchTypeID":1,"name":"1v1","teamSize":1,"numTeams":2,"localizedName":"1v1"}],
 "races":[{"raceID":0,"name":"random","factionID":0,"localizedName":"Random"}],
 "factions":[{"factionID":0,"name":"random","localizedName":"Random"}],
 "leaderboardRegions":[{"leaderboardRegionID":2,"name":"LAN","localizedName":"LAN"}],
 "rankLevels":[],"statDefinitions":[],"selfAssessmentTiers":[]}
```

The second version (with the id lists filled in) is the one that works — see 29i.

Every other path is byte-for-byte what it was (the catch-all `[0,[]]` is untouched).

## 29d. MEASURED: the parse error is gone (two launches, pid 18176 and 12856)

- `[t=4.437s] HTTP REQ /game/Leaderboard/getAvailableLeaderboards` → our new body is sent.
- **`LeaderboardInfoCache` never appears in the LogWarn stream again** (`grep -c` = 0). In s28 the
  same run logged `LeaderboardInfoCache - response was not formatted correctly: [0,[]]`.
  ⇒ the reply is now well formed for the game's parser. The s28 diagnosis of *that link* is
  confirmed and closed.
- Still logged (a different, unfixed cache): `LeaderboardStatsCache - response was not formatted
  correctly: [0,[]]` from `/game/Leaderboard/getStatsForLeaderboardByProfileName` (11 times). That
  DTO is `0x14062cb20` = `{result, leaderboards:[{profileId, leaderboardStats:[…]}]}`, element
  parser `0x14062d090`. Not touched this session.

## 29e. MEASURED: rule 2 is still 0, and now we know exactly why

`rules_probe()` was extended (read-only, same `AOE2LAN_RULES=1` flag) to print the registry that
rule 2 counts — `0x1442e18b0` / `0x1442e18b8`, entry stride 0xc0:

```
lb registry begin [0x1442e18b0] = 0x0000000000000000
lb registry end   [0x1442e18b8] = 0x0000000000000000
lb registry map   [0x1442e18c8] = 0x000001cfc29ce9b0     (tree sentinel present, tree empty)
lb definition count = 0
```

identical at t=40 and t=70 s, in the run that no longer logs a parse error. All five rule inputs
unchanged from s28 (byte+0x698 = 0, slots 0x80 = -1976585471, 0x88 = 1, **0x90 = 0**, 0x308(2) = 0,
0x308(4) = 0), the two Multiplayer records still read **status=2**, every other record 0.

⇒ **parse success does not fill the registry.** The s28 chain has one link that does not hold:
"correct reply → registry non-empty". The button stays grey.

## 29f. What the registry is, and who can fill it (static, from the decrypted `.text`)

- count: `0x140e84100` = `(end-begin)/0xc0 != 0` over the vector at `0x1442e18b0`.
- insert: `0x140e81740` appends one 0xc0 entry and updates the maps at `0x1442e18c8` /
  `0x1442e18d8`. Two callers only: `0x140e83414` (inside `0x140e83240`) and `0x140e84322`
  (inside `0x140e84190`).
- `0x140e83240(out, id)` = **get-or-create by int64 id** — 60 call sites, nearly all screens
  (`0x141a…`, `0x141c…`, `0x140a69268`, …). So the registry is a lazy per-id definition cache.
- `0x140e84190(list)` = **bulk install**: `0x140e82860` clears the registry first, then inserts one
  entry per 0xb0-byte element of the vector it is given. Called from `0x140ee0090` and
  `0x140edde**` (the `TComm_Leaderboard_RL` handler family), which fetch that 0xb0 vector from an
  engine object reached through `0x1402ab8a0` (a very widely used singleton getter — identity NOT
  established).
- Nothing on the `LeaderboardInfoCache` response path calls either inserter.

⇒ The registry is filled either by a screen asking for a leaderboard by id, or by the bulk install
from the engine's own 0xb0 definition list. Our relay reply feeds neither.

## 29g. NOT known (next session starts here)

1. **What produces the 0xb0-byte definition vector** that `0x140e84190` installs. That is the
   shortest path to `rule 2 = 1`. Cheapest next step: a read-only probe that prints
   `[0x144c9e5f0]` (the `0x1402ab8a0` singleton), its vtable RVA, then the object returned by
   `[vtbl+0xc0]` and its vtable RVA — that names the class and therefore the data source.
2. Whether any *screen* would ask for a leaderboard id during a normal main-menu session (if one
   does, `get_or_create` alone makes the count 1).
3. Whether the real reliclink reply is expected to fill the registry through the nested members
   (`mappings` / `statDefinitions` / `matchTypes` / …) that we send empty. Their element schemas are
   not extracted. If (1) is a dead end, this is the fallback: element parsers are `0x14074b6b0`
   (mappings), `0x14074bb00` (matchTypes), `0x14074bfe0` (races), `0x14074c370` (factions),
   `0x14074c6f0` (leaderboardRegions); each of their element parsers names its own fields inline the
   same way `0x1407365e0` did, so the same trick works.

## 29h. Where the session stops

**Superseded by 29i — M1 is met.** For the record, the state before the second half of the fix: the
reply was well formed but every list in it was empty, so the game accepted it and installed no
definitions. The registry that rule 2 counts was fed by `0x140e84190`, driven from the `matchTypes`
vector, so an object with an empty `matchTypes` cannot work no matter how correct the rest is.
M2 is untouched.

Tooling notes: `cmd /c` from this shell needs `/c/WINDOWS/system32/cmd.exe //c` (plain `cmd` starts
an interactive shell and ignores the argument). Launching the game twice in a row still needs the
~45-50 s pause after a ~3 s death; the first launch this session died at 2.7 s.
## 29i. MEASURED, end to end: the Multiplayer button is LIVE and the screen opens

Same run, pid 1624, with the reply from 29c **plus non-empty `matchTypes` / `mappings` /
`races` / `factions` / `leaderboardRegions`** (this was the missing half):

| what | before | after |
|---|---|---|
| `LeaderboardInfoCache - response was not formatted correctly` | every run | **gone** |
| leaderboard definition count (`0x1442e18b0`, stride 0xc0) | 0 | **1** |
| rule 2 = `[svc][vtbl+0x90]` (`0x140f12e80` = `[vtbl+0x88]` && count!=0; vtable slot identity verified from the file) | 0 | **1** |
| both Multiplayer twin records (`ids 2,8,4,5,11,12,13` minus skip 12) | status=2 | **status=0** |

Operator, at the main menu: **the plate is no longer grey, the tooltip shows, and clicking
Multiplayer opens the Multiplayer screen and it stays open** (Host Game / Find Custom Game /
Ranked visible, no freeze, no crash, no bounce back).

⇒ M1's stated exit condition is met. The s28 chain was right about the *cause* and wrong about the
*sufficiency*: the reply has to be a well-formed object **and** carry at least one entry in
`matchTypes` (plus the id lists it resolves against), because the game-side installer
`0x140e84190` is driven from the `matchTypes` vector. An object with those lists empty parses
cleanly and installs nothing — that is the trap a future session must not fall into.

Evidence: `logs/lanhook-1624.log` (readouts at 25/40/70 s, record scan at 126 s).

## 29j. MEASURED: the first host attempt, and where it dies

Operator, still in the live session (pid 1624), clicked Host Game → Create Lobby in the working
Multiplayer screen. Result: dialog `Could not create game. Server Error. Source: AdvertisementJoinEvent
Error Code: 0x00000001`. No crash, no freeze.

What the log shows for that moment (`logs/lanhook-1624.log`):

```
[t=791.844s] LogHelper: "starting online hosting"
[t=791.953s] srv: connection accepted  -> TLS handshake complete -> NO HTTP REQUEST (and no bytes)
[t=793.125s] LogHelper: "HostAsync - completed with HostResult = %d"  -> 1
[t=793.125s] LogHelper: "WorldwideAutomatchService::OnHostComplete - automatcher is no longer active"
```

Facts, all measured:

- The game chose **online** hosting, not LAN: `[advertSvc+0x1a8]` host mode 0 → online, 2 → offline,
  anything else → LAN (`0x140351343`, log lines at `0x14367ee40/58/78`).
- **No advertisement HTTP request was ever sent.** `/game/advertisement/` appears exactly twice in the
  whole session, both before the click (`getLanAdvertisements` at 677.578 s, `findAdvertisements` at
  677.782 s). No connect, no DNS, no send to any address in the 791-794 s window.
- `WorldwideHostAsync`'s own failure log (`0x140335926`, "WorldwideHostAsync - failed with reason %d",
  through **hooked** LogWarn `0x1402bcc00`) did **not** fire ⇒ the rlink host call did not take its
  normal failure branch.
- "srv: connection accepted, TLS complete, then no request" is NOT special: 8 such connections occur
  across the session (4.0 s, 4.5 s, 28.1 s, 28.7 s, 38.1 s, 91.2 s, 154.3 s, 792.0 s), i.e. each
  HTTP request opens a fresh connection and some are preconnect/warm-up.
- About 30 connections went to the relay's out-of-band port 27212 (the QoS probe started at 4.172 s);
  **nothing ever connected to 27012 (raw) or 27112 (websockets)**, and the stock `BattleServer.exe`
  (pid 6160, started by the game) listens on 27012 + 27212 only.
- Two leads printed by the game's own code and not yet explained: `"HostAsync: This AsyncJob is not the
  active connect, waiting..."` (`0x14367e980`) and `"join failure - we don't have a slot reservation"`
  (`0x14367e950`). Both suggest the host is an AsyncJob queued behind "the active connect", so the
  question is whether the job ever runs.

### 29j.1 The LAN door the UI already has

`.rdata` proves the create-lobby screen carries a lobby-type selector:
`IDS_LOBBY_CREATE_USE_LOCAL_LAN_DROPDOWN_ITEM` at `0x143322df0`, immediately followed by the widget
path `Background/Settings/LobbyTypeAnchor/LobbyTypeDropDown/DropDownListBox`. So the UI itself can ask
for **local LAN hosting** — which is exactly the mod's target and skips the online advertisement
service that just failed. Next session tries that dropdown before reverse-engineering the online host
path any further.

### 29j.2 Tooling trap found this session

`xr.py` and my own disp32 scanners silently miss references in some cases (e.g. they report
`adc byte ptr [rip+...]`); the reliable check is: candidate disp32 → disassemble backwards with
capstone → keep only instructions whose end equals the disp end. Re-test any "no xref" conclusion
against a string known to be used in the same `.rdata` block before believing it.

Also: `0x140f19210` (the game's own `Network`-category logger, used by all `TComm_*` code) is
**encrypted on disk** (`disk` bytes differ from `gametext.bin`), so it can never be hooked under the
standing Arxan rule. Everything the game's comm layer says is therefore permanently invisible to the
log hooks; only the rlink SDK's loggers (`0x1402bcb30`, `0x1402abc80`, `0x1402bcc00`) are usable.
