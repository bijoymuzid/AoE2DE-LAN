# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Read `notes/m1-session41.md` in full before touching anything; it
supersedes `notes/m1-session40.md`. Then read `PLAN.md` §0–§2, §6.1, §6.2 and §17.

Say everything in plain English: short sentences, no jargon, no code dumps, no leaps. If something is
unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo: `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first. At the end run
`cmd /c D:\aoe2lan-repo\sync.cmd "session 42 - <one line, no parentheses, no colon after NN>"`
(in this shell `cmd /c` must be written as `/c/WINDOWS/system32/cmd.exe //c`, and the `sync.cmd` path
must be in single quotes or bash eats the backslashes).

## THE JOB, in priority order. Nothing else outranks these.

1. **Make a hosted match actually load and run.** Pressing Start is already accepted; the game then
   sits in the lobby forever. The single known blocker is our fake server's reply to
   `/game/party/peerAdd` (and `/game/party/peerUpdate`) in `dev/lanhook/loginsrv.c`.
2. **Then confirm AI are in that match and actually play.** AI already appear in the lobby and are
   already carried in the session's slot data, so this may work with no further changes.
3. Only after that: a second human joining over the tailnet (PLAN §W1-c / M2).

## SOLVED IN SESSION 41 — do not redo any of it

- **AI in the MULTIPLAYER HOST LOBBY dropdown: DONE and verified on screen and in the log.** All seven
  empty slots offer Open / Closed / AI. Mechanism, fully measured: the populator `0x141a344f0..0x1a362aa`
  already ran block C (§40e's `ebx == 1` / block-B theory is **dead**). What blocked the AI item were
  two checks *inside* block C at `0x1a35db8` and `0x1a35dc5`, and both failed:
  `[screen+0x1cf8]` was `-1` and had to equal the sentinel `[0x14326b258]`, which is **0** (read-only
  `.rdata`, zero on disk, no `.reloc` entry — an `extern const` null); and the populator's own `r9b`
  copy at `[rbp-0xd0]` was `0`, which selects a name-list branch instead of the single "AI" item.
- **The fix that works** (`AOE2LAN_AIGATE=1`): hook id 16 `AISlotLabel` on CLEAN `0x140ac5480`
  (localize-by-id, 633 sites), caller-filtered to the populator, writes the sentinel into
  `screen+0x1cf8` and `1` into `[rbp-0xd0]`; plus `lobby_keepgate()` called from hook 14
  (`WidgetSetEn`) which re-asserts the sentinel from the cached screen pointer, because the lobby
  restores `-1` on every refresh (measured: 16 repairs in 125 ms). Do not remove either half.
- **`hooks.asm` now snapshots callee-saved registers** at `ctx[-8]=rbx, ctx[-7]=rsi, ctx[-6]=rdi,
  ctx[-5]=rbp`, with `sub rsp,0C0h` and ctx at `rsp+0x60`, so `ctx+0x98` is still the live
  return-address slot and `ctx[20..]` is still the caller's stack. **Every existing ctx index is
  unchanged and HK_WSET needed no edit.** `HK_MAX` is 20, `g_TailTable QWORD 20 DUP(?)`.
- **The Start button works.** No error message. `Match Started - …, slot = 0`,
  `OnStartComplete - detected successful game start`, `/game/advertisement/updateState state=1`,
  `hosting - Session is connected`, `BattleServer.exe` spawned, LAN relay added.
- **The two lobby errors are gone for good, not worked around.** The Start handler
  `0x141a3c700..0x141a3ce53` has three doors on the same field: `field == 0` skips every check and
  starts; `field != 0` counts **only slots with status 2** (status 0 = human, 1 = empty, 2 = AI) and
  rejects an odd count with `IDS_LOBBY_SCREEN_ERROR_UNEVEN_PLAYERS`, then rejects unbalanced teams with
  `IDS_LOBBY_SCREEN_ERROR_UNBALANCED_TEAMS` unless registry record `+0xb0 == 1`. "Even number of
  players" really meant "even number of AI", which is why 3 AI and 7 AI both failed.
- **MEASURED control run, no AI at all (`logs/lanhook-17168.log`): identical failure.** So the match
  not loading has nothing to do with AI. `WorldwideOnPartyPeerAddAsync` fires at lobby creation, before
  any AI exists.

## THE BLOCKER, precisely

`loginsrv.c` has explicit handlers only for login, `readSession`, `getAvailableLeaderboards`,
`advertisement/host`, `advertisement/update`, `advertisement/getLan*|find*|getAdvertisements`, and
`/game/news/`. **Everything else falls into the catch-all `[0,[]]` at `loginsrv.c:1649-1652`**, and
`/game/party/peerAdd` and `/game/party/peerUpdate` are not named anywhere in the file. The game logs
`"%s - response was not formatted correctly: %s"` with `s8="WorldwideOnPartyPeerAddAsync"`,
`s9="[0,[]]"`. 19 other caches log the same warning in one boot (`LeaderboardStatsCache`, `NewsCache`,
`ChatChannelCache`, `ItemCategoryCache`, `GetOfflineMessagesAsync`, `RelationshipCache`, …) — those are
PLAN §W1-d and are NOT blocking; peerAdd is.

## NEXT STEP, already planned as §41h N10 — follow it

**Shape the `/game/party/peerAdd` reply (then `peerUpdate`).**

- **Develop it offline, without the game.** `srvtest.exe` starts loginsrv on `127.0.0.1:443` and idles
  60 s; `C:/Python314/python.exe -X utf8 dev/lanhook/srvclient.py` (stdlib only) does the TLS handshake
  with SNI `pb-live-release6-api.worldsedgelink.com` and POSTs at it. That is how the login object-form
  reply was built in s12/s21. Add a peerAdd case to `srvclient.py`, iterate, and only spend a game run
  once the offline reply is shaped.
- **Find the expected shape the way s30 did for `/game/advertisement/host`** (parser `0x140579020`
  wants `result` + `updatedAvertisement`) and s12/s21 did for login (parser `0x140615b70`, named keys,
  not a positional array). Entry point: the `not formatted correctly` warning is logged through
  `0x1402BCC00` (hook id 13, already installed) and the cache name arrives in `s8`, so the *caller* of
  that log line is the peerAdd completion handler — xref it and read its parse. `ret=0x00007ff648…` in
  those lines is a heap address, not a code RVA: recover the caller from the frame the way HK_WSET does
  (`ctx[25]`), not from `ret`.
- Then re-test in game with `PLAY-stage8-AIGATE.cmd`, 3 AI, Start. Expect a loading screen.
- §41h also lists N11 (verify the AI play), N12 (whether the s38 bit-0x4 row suppression can now be
  retired — **unverified**, the suppression is still armed and may be masking the result) and N7 (M2).

## ALREADY SETTLED — do not re-open

- The host-lobby settings rows: fixed and verified in-game by the bit-0x4 suppression in HK_WSET (hook
  id 14) with four locker ranges. Correct and staged. Do not touch it unless a specific log line shows
  a new re-lock site.
- The lobby is healthy; its settings round-trip. `mapname="my map"` and `matchtype=-1` in our replies
  are dead fields for lobby health. (Note `screen+0x1cf8` holding `-1` is a *different* thing and is now
  handled client-side; §41e records that **who writes -1 is unresolved** and that outvoting it works.)
- AI in an online match is a real supported feature (`UNRANKED_VIA_AI`, string 13204).
- The AI table itself is fine: `kind=2, nAI=2` in both screens, so `AOE2LAN_AIKIND=n` cannot help.
- `0x141ab4bd0` is the SKIRMISH filler, not the host lobby's.

## METHOD RULES

- Never patch or hook code that is encrypted on disk. Read it from `dev/lanhook/gametext.bin` only.
  `gametext.bin` is code-only: no strings, no `IDS_` keys, so find string xrefs by scanning it for
  rip-relative `lea` (`work/xgrp.py`). Localized text lives in
  `resources/en/strings/key-value/key-value-strings-utf8.txt`; `IDS_` keys live in the exe's `.rdata`.
- A fix must be a caller-filtered hook on a CLEAN function (HK_WSET's bit-0x4 suppression and hook 16
  are the templates) or something server-side in `loginsrv.c`.
- Verify any rebuilt DLL by parsing it (`work/verifydll.py` — **its kind filter must include every
  `HK_*` kind or it silently drops the entry**) and with `dumpbin -DISASM`, never with a byte grep.
  MSVC folds constants into displacements and puts static arrays in `.rdata`. `dumpbin` is not on PATH:
  `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe`.
- `build.cmd` ends with `copy /y dbghelp.dll ..\..\dbghelp.dll` and makes **no backup**, and **Windows
  locks the file while the game runs** (the copy then fails silently and the two copies diverge). Close
  the game first, copy `dbghelp.dll` to a `.prev-*` name BEFORE building, and `md5sum` both copies after.
- Measure before patching. Prefer a read-only logging hook and one run per screen over guessing.
- Opt-in hook ids only via `AOE2LAN_HOOKS` in a `PLAY-stage8-*.cmd`. Default stage-8 hooks stay 4, 5, 13.
  No whole-memory sweeps, never `AOE2LAN_UIW=1` or `rules_scan()`. Do not edit `lanhub/**`, `linux/**`,
  `notes/linux-*.md`.
- Edit the game-dir tree (`D:\Age of Empires II Definitive Edition\dev\lanhook`), then sync with `sync.cmd`.
- Start disassembly from an `fn.py` bound, not a guessed address: `dz.py` silently emits garbage
  mid-instruction and prints nothing at all below the dump base. RVA vs VA: `VA = 0x140000000 + RVA`.
  Never name a helper script `grp.py` (shadows the stdlib module `pathlib` imports).
- `g_Hooks` lives in `.data`, not `.rdata`. The launcher returns the `cmd.exe` PID, not the game's —
  find the real PID from the newest `logs/lanhook-<pid>.log`.
- To reassemble a request/response body from a log: join the `HTTP BODY +` continuation lines FIRST
  (the plain `HTTP BODY` regex also matches them and will shred the body), then URL-decode,
  base64-decode, `zlib.decompress`. `slotinfo` decodes to `"<n>,[{profileInfo.id, stationID, teamID,
  factionID, raceID, rankLevel, rankMatchTypeID, timePerFrameMS, isReady, status, metaData}…]`, and
  `metaData` is base64-of-base64 of a binary blob whose strings are `ScenarioPlayerIndex` and `Team`.
- **A launch that dies under ~5 s with a clean boot log is a transient.** It happened once in s41 right
  after `cert: purged stale roots=1`; the identical DLL ran for minutes on relaunch. Relaunch before
  debugging it.

## GATES before any in-game run

`AoE2DE_s.exe` MD5 must be `affb19f03ca96965abf9e56775cab688` and untouched; `hooktest.exe` must pass
68/68 plus `post-hook ok (21, 210, 2100, 6)`; `srvtest.exe` must pass; staged `dbghelp.dll` MD5
**`a4ab2ba4c4e9d69db27195b4cad2fc6b`** (**247,296 B**) unless you rebuilt it, in which case record the
new MD5 and keep a `.prev-*` backup first. Existing backups: `.prev-s41-before` (the s40 build
`f499bbd13a4e838f4f6b8c37267d27f4`), `.prev-s41-readonly` (`09fd1423a94a514fed366ea5c2c29adc`,
read-only hook 16), `.prev-s41-aigate1` (`a4340466b10f3dcd9d2a7323ef584e8a`, one-shot write, no
keepgate).

## To launch for a test

```
powershell -NoProfile -ExecutionPolicy Bypass -File "dev\lanhook\work\launch-detached.ps1" -cmdFile PLAY-stage8-AIGATE.cmd
```

then wait ~16 s and tell me what to click; I will click and report back. `PLAY-stage8-AIGATE.cmd` is
the working fix (`AOE2LAN_HOOKS=4,5,13,14,15,16`, `AOE2LAN_AIGATE=1`). `PLAY-stage8-AISLOT.cmd` is the
same set with the writes OFF (pure logging) — use it to A/B any suspicion that a write caused a problem.
Log caps: `WidgetSetEn` skips the first 20 s and caps at 512 lines; `AISlotPick` skips 20 s, caps 256;
`AISlotLabel` skips 20 s, caps 256. Give me one run per screen if a log is filling.

## Useful existing tooling in `dev/lanhook`

`dz.py` (disassemble a VA range from `gametext.bin` with strings resolved), `fn.py` (pdata bounds +
whole-function dump), `cx.py` (E8 call sites), `rr.py` (rip-relative lea xrefs), `aoe2re.py` (PE + dump
helpers), `srvclient.py` (offline TLS client for `srvtest.exe`), and in `work/`: `aistr.py`,
`cleanfns.py`, `verifydll.py`, `xgrp.py`, `launch-detached.ps1`.
