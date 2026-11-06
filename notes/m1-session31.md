# Session-31 — hosting works end to end; the lobby's settings panel does not

Supersedes `notes/m1-session30.md` for state. Everything below is MEASURED unless the line says
INFERRED or UNKNOWN. No game file, no `.text` byte, no XAML was changed. Every code change is in
`dev/lanhook/loginsrv.c` and `dev/lanhook/srvclient.py` (ours).

## 31a. Offline gates (re-run after every change, all pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS**, now six checks: TLS, wss upgrade + ws ping/pong/close,
  leaderboards object, 6 concurrent requests each answered, `Expect: 100-continue` interim + 3 KB
  body, and the three new advertisement checks in 31d–31f.
- `AoE2DE_s.exe` crc **`4f533b6c`** — untouched (MD5 `affb19f03ca96965abf9e56775cab688`).
- Staged `dbghelp.dll` at session end: 239,616 B, MD5 **`518eb09cfad12fb6cf338a1e1aded275`**.

## 31b. MEASURED: the whole body is now logged

`log_body_head` / `log_resp_head` no longer stop at 300 chars. They dump the full body in 340-char
lines, continuation lines marked with `+` after the tag (`HTTP BODY +…`). Join the chunk payloads and
you have the exact body. That is how the host request's `slotinfo`/`options` blobs became visible at
all — they sit past char 1200.

## 31c. MEASURED: hosting succeeds — the reply was the wrong DTO

Run `logs/lanhook-8528.log` (and `16448`): with the join-result reply (31d) the game logs

```
starting LAN hosting
HTTP REQ /game/advertisement/host          (body 5268 B, incl. slotinfo + options)
OnlineHostAsync success
Created Matchinfo for sessionID %llu       -> 1193966527  (a real id, not -1)
OnJoinAdvertisementSuccess - joined online match, server leave notification required
starting local hosting
hosting - Session is connected             (after SOCK connect 192.168.0.104:27012)
HostAsync - completed with HostResult = %d -> 0
Publishing Visible match
```

and the operator sees a lobby with slots. **M1/M2 entry: LAN hosting is functional.**

Run `7564` (the failed attempt before the fix) ended with `WorldwideHostAsync - failed with reason
%d -> -1` and `HostResult = 1`. That `-1` was the DTO's init value, never overwritten.

## 31d. The host reply shape (static, then confirmed in game)

- Caller/step function: `0x140334ae0` (builds `/game/advertisement/host` at `0x140334d88`, then
  parses the reply). It calls the generic response helper `0x14035b050`, which parses into the DTO
  built by `0x14032f5e0` using **`0x140572540`**.
- `0x140572540` member names, in parser order: `resultCode`, `gatheringID`, `relayAuthToken`,
  `relayIP`, `relayPortRaw`, `relayPortWebSockets`, `relayPortOutOfBandSocket`, `relayRegion`,
  `yourMatchMembers`, `steamLobbyID`, `goodOldGamesLobbyID`, `psnPlayerSessionID`, `psnMatchId`,
  `xboxSessionID`, `filteredDescription`.
- DTO offsets: `+0` resultCode (int, init -1), `+8` gatheringID (int64, init -1), `+0x10`
  relayAuthToken, `+0x30` relayIP, `+0x50/0x52/0x54` the three ports **as WORD**, `+0x58`
  relayRegion, `+0x78` yourMatchMembers vector (stride **0x48**), `+0x90` steamLobbyID, `+0xe0`
  xboxSessionID, `+0x100` filteredDescription.
- After a successful parse the caller requires `resultCode == 0` **and** a non-empty member vector
  (`DTO+0x78 != DTO+0x80`), then copies `gatheringID` into `[svc+0x80]`, which is what
  `0x14035172d` moves to `[svc+0x358]` and passes to the matchinfo constructor `0x1402ff080`
  (`[rdx+8]` -> `[matchinfo+0x198]`). So **advertisement/session id == gatheringID**.
- One member record (`yourMatchMembers[]`, parser **`0x14056eb40`**): `sessionID` -> `+0x24` (dword),
  `profileID` -> `+8` (int64), `ranking` -> `+0x10`, `statGroupID` -> `+0x18`, `raceID` -> `+0x20`
  (dword), `teamID`, `url` -> `+0x28` (string). Element size 0x48.

Our reply (`build_host_reply`) is exactly that, with `gatheringID` echoing the request's `sessionID`
and the relay endpoints the login reply already advertises (27012 / 27112 / 27212, region `LAN`).

## 31e. `/game/advertisement/update` (host calls it ~every second after hosting)

Parser **`0x140579020`**: `result` (int) + `updatedAvertisement` — the game's own misspelling, one
`d` — holding **one** advertisement object parsed by **`0x14056cce0`** (same member set as the
writer at `0x14056dda0`): `steamLobbyID`, `goodOldGamesLobbyID`, `psnPlayerSessionID`,
`psnMatchId`, `xboxSessionID`, `hostProfileID`, `matchState`, `description`,
`filteredDescription`, `visible`, `mapName`, `options`, `isPassworded`, `maxPlayerCount`,
`encodedSlots`, `matchTypeID`, `matchMembers`, `observerNum`, `observerMax`, `isobservable`,
`observerDelay`, `isObserverPassworded`, `service`, `matchStartTime`, `matchRegion`,
`matchRegionLocalized`.

The request sends the same data under *different* names (`hostid`, `mapname`, `maxplayers`,
`slotinfo`), so `emit_advertisement()` translates field by field. The option blob travels as
`encodedSlots`, byte for byte (PLAN §6.2). Verified in game: the
`WorldwideUpdateAdvertisementAsync - response was not formatted correctly: [0,[]]` warning is gone.

## 31f. Browse replies — one shape for four endpoints

`/game/advertisement/getLanAdvertisements`, `findAdvertisements`, `getAdvertisements`,
`findObservableAdvertisements` all parse with **`0x140571ae0`**: `result` (int), `advertisements`
(array, element parser **`0x14057b170`**), `playerRatings` (array). Our server keeps the last
host/update body (one lobby, locked copy) and returns it as one advertisement, or an empty array if
nothing is hosted. Verified in game: `LANAdvertisementCache - response was not formatted correctly`
is gone from the run that browsed.

## 31g. FOUND AND FIXED: intermittent `SEC_E_UNTRUSTED_ROOT` killed a whole launch

Run `logs/lanhook-12788.log` (14:18) never reached our server: SChannel rejected our own certificate
at 3.8 s with `SEC_E_UNTRUSTED_ROOT`, so login failed, no `/game/login/platformlogin` was sent, and
the rules readout 40 s later showed all zeros. From the operator's side that looked like "the mod
was turned off". The DLL was loaded and correct.

The only structural difference from two healthy runs: `RootRegThread` purged the stale root first
and added the new one **~0.7 s later** (`purged stale roots=1` at 0.83 s, `user-Root registered` at
1.58 s), while the game does its own crypt32 work in 1.0–1.5 s. Fixed by adding first and purging
after; `purge_aoe2lan_roots()` now skips the certificate whose **encoded bytes** equal ours, so the
purge can no longer delete what was just added (it used to match on Subject only).

New read-only instrument: every accepted connection logs `cert: root present=0|1` (9 = could not
query). The harness prints `root present=1` on all 15 connections it opens. INFERRED that this was
the mechanism; the next failing run's `root present` line will settle it.

## 31h. MEASURED: the game is in the HOST lobby

`widgetui/screenmultiplayerlobbyhost.json` contains `ButtonStart`, `GameDropDown`,
`MapSizeDropDown`, `DifficultyDropDown`, `ResourcesDropDown`, `PopulationDropDown`,
`GameSpeedDropDown`, `RevealMapDropDown`, `StartingAgeDropDown`, `EndingAgeDropDown`,
`TreatyLengthDropDown`, `VictoryDropDown`, `BattleRoyaleTimeDropDown`, `TimeDropDown`.
`screenmultiplayerlobbyclient.json` has `ButtonReadyStart` but **no** `ButtonStart` and none of those
dropdowns. The operator sees *both* Ready and Start Game (Start Game only enables after Ready),
which only the host screen offers. So hosting produces the host lobby.

## 31i. OPEN: the lobby's settings panel is locked (only the map is selectable)

UNKNOWN cause. No measurement points at a specific cache yet. The dropdown widget names are
referenced from a data blob, not from an instruction, so `xr.py` gives nothing — the enable code has
to be found another way. First discriminator (not yet answered): **which** dropdown is dead — if
`GameDropDown` itself is dead, everything hangs off it; if only the rest are, it is a different gate.

Candidates, all still unmeasured as the cause:
- host-side ready state (the operator clicks "I am ready" before Start Game — in DE a ready host locks
  the settings; test: click Ready again to un-ready, then try a dropdown),
- the party plane: `/game/party/peerAdd` and `/game/relationship/setPresence` still answer the
  catch-all `[0,[]]` (`WorldwideOnPartyPeerAddAsync`, `WorldWideSetPresenceAsync`,
  `WorldwideUpdateTagsAsync`, `SetDataAsync` all log `not formatted correctly` / `failure`),
- the rules readout (needs `PLAY-stage8-RULES.cmd` on a run that actually logs in).

## 31j. Relay / cross-machine state (unchanged, not yet this session's work)

The game picks the relay itself: it logged `Adding LAN relay server: 192.168.0.104, GUID
0f4b94ea-…` and connected to `192.168.0.104:27012` with no help from us. Our advertisement and login
reply still say `relayIP 127.0.0.1`, and no second machine has been tried. W1-c in PLAN §17.3 is
therefore untouched.

## 31k. Tool notes for the next session

- `fn.py <addr>` / `fn.py <addr> --dump` (pdata bounds + capstone) was enough to map every parser in
  this note. `xr.py` works for `.rdata` string xrefs, but **not** for the widget-name table (those
  names are indexed from a data blob): a range scan over `.text` for rip-relative operands into the
  string's address range is the fallback (see the snippet used in s31 for `0x140572540`).
- Windows `C:/Python314/python.exe` cannot read `/tmp` paths written by this shell; keep scratch
  files under `dev/lanhook/work/`.
- The assistant cannot launch the game: `cmd /c start` returns "Access is denied" (no interactive
  desktop) and a direct launch dies at ~5 s. The operator must double-click the `PLAY-stage*.cmd`.
