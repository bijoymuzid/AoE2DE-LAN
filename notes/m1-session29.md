# Session-29 — the rubbish reply is fixed; the button stays grey for a second reason

Supersedes `notes/m1-session28.md` for state. Everything below is MEASURED unless the line says
INFERRED. No game file, no `.text` byte, no XAML was changed. The only code changes are in
`dev/lanhook/loginsrv.c` (ours) and a read-only readout added to `lanhook.c` (ours).

## 29a. Offline gates (re-run, pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS**, and the client now also checks the new
  `getAvailableLeaderboards` reply: object, `result` 0, non-empty `leaderboards` array, first entry
  `{leaderboardID:int, leaderboardName:str, isRanked:bool}` (`leaderboards reply: object, 1 entry`).
- `AoE2DE_s.exe` crc **`4f533b6c`** — untouched. `dev/AoE2DE_dec.exe` `487054ce`.
- `dev/lanhook/gametext.bin` crc `ca040d52`. XAML stock crc `8398949b` — untouched.
- game-dir `dbghelp.dll` = `dev/lanhook/dbghelp.dll` = crc **`bbfeec88`** (216,576 B, this session).

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
 "mappings":[],"matchTypes":[],"races":[],"factions":[],
 "leaderboardRegions":[],"rankLevels":[],"statDefinitions":[],"selfAssessmentTiers":[]}
```

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

The relay no longer lies about this request. The Multiplayer button is still grey, and the reason is
now a *different*, precisely measured one: the leaderboard-definition registry that rule 2 counts is
empty and nothing on this reply path fills it. M2 is untouched.

Tooling notes: `cmd /c` from this shell needs `/c/WINDOWS/system32/cmd.exe //c` (plain `cmd` starts
an interactive shell and ignores the argument). Launching the game twice in a row still needs the
~45-50 s pause after a ~3 s death; the first launch this session died at 2.7 s.