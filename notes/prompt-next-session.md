# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Session 31 is finished. Read `notes/m1-session31.md` in full
before touching anything — it supersedes everything older. Then `PLAN.md` §0–§2, §6.1 and
**§17 (two-worker split)**.

Say everything to me in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo (keep current): `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first.

At the end of the session run: `cmd /c D:\aoe2lan-repo\sync.cmd "session 32 - <one line, no
parentheses, no colon after NN>"`. In this shell `cmd /c` must be written as
`/c/WINDOWS/system32/cmd.exe //c`.

**You cannot launch the game.** `cmd /c start` gives "Access is denied" and a direct launch dies at
~5 s (no interactive desktop). The operator double-clicks `PLAY-stage*.cmd`. Do not waste turns
trying; ask the operator instead. If a launch dies at ~3 s, wait ~45 s and ask for a relaunch.

## WHERE WE ARE (all measured in session 31, do not re-derive)

- Offline gates: `hooktest.exe` **68/68**; `srvtest.exe` + `srvclient.py` **PASS**, six checks (TLS,
  wss + ws ping/pong/close, leaderboards object, 6 concurrent requests, `Expect: 100-continue`, and
  the host/update/browse advertisement replies). `dev/lanhook/build.cmd` builds and stages
  `dbghelp.dll` into the game dir by itself. Game exe MD5 `affb19f03ca96965abf9e56775cab688`,
  untouched. Staged DLL at s31 end: 239,616 B, MD5 `518eb09cfad12fb6cf338a1e1aded275`.
- **LAN hosting works end to end.** With `AOE2LAN_STAGE=8`, Server = `Use Local Lan Server`, Create:
  the host request arrives, our reply is accepted, and the log shows
  `Created Matchinfo for sessionID %llu` with a real id, `HostAsync - completed with HostResult = 0`,
  `hosting - Session is connected`, and the operator gets a lobby with slots. Evidence:
  `notes/m1-session31.md` §31c.
- The three advertisement reply shapes are decoded from the game's own parsers and all three now
  parse clean in game (§31d–31f): `/game/advertisement/host` is a **join result** (`resultCode`,
  `gatheringID`, relay endpoints, non-empty `yourMatchMembers[]`), `/game/advertisement/update` is
  `result` + `updatedAvertisement` (the game's spelling) with one advertisement object, and the four
  browse endpoints share `result` + `advertisements[]` + `playerRatings[]`. The option blob is passed
  through as `encodedSlots`, byte for byte.
- **OPEN, and it is the live blocker: the host lobby's settings panel is locked.** Only the map can
  be selected; Game/Map Size/Population/Resources/… do not respond. It is definitely the *host*
  screen (both Ready and Start Game are present, which only the host XAML offers), so hosting is not
  the problem. Cause UNKNOWN. See §31i: first find out *which* dropdown is dead, then check whether
  the host simply has its Ready box ticked (in DE a ready host locks settings), then the party plane
  (`/game/party/peerAdd`, `/game/relationship/setPresence`, `updateTags` still answer `[0,[]]`).
- A fix landed for an intermittent `SEC_E_UNTRUSTED_ROOT` that killed a whole launch (§31g): the
  certificate is now added to the user Root store *before* the stale ones are purged, the purge skips
  our own certificate by exact bytes, and every connection logs `cert: root present=0|1`.
- Relay: the game finds and connects to `192.168.0.104:27012` by itself; our replies still say
  `relayIP 127.0.0.1`. Cross-machine play is untested (W1-c in PLAN §17.3).

## THIS SESSION, IN ORDER

1. `git pull`, run both gates, confirm the staged DLL hash.
2. Ask the operator which lobby dropdowns are dead (Game first, then Map Size, Population,
   Resources, Victory) and whether unticking "I am ready" frees them. Their answer picks the road.
3. Only after that, chase the enable code for those dropdowns. Static only, read-only instruments in
   our own DLL. No new detour, no `.text` or `.rdata` change without the operator's explicit go-ahead
   with exact bytes and a revert story.
4. Then, one at a time and each measured: `join`, `leave`, then the browse path from a second machine
   (the friend's Linux box), then the relay address pointed at the tailnet IP instead of loopback.

## RULES THAT STILL APPLY

Never patch or hook code encrypted on disk. Hook ids 4, 5 and 13 only. No blind patching. No
cosmetic fixes. Any new detour or game-file edit is the operator's call and needs exact bytes plus a
revert story. Use `dev/lanhook/gametext.bin` for code, never the encrypted exe. Do not edit
`lanhub/**`, `linux/**` or `notes/linux-*.md` — that is the Linux worker (PLAN §17.1). Hand him
`dbghelp.dll` as a file when he asks; it is git-ignored, so it travels outside the repo
(`D:\dbghelp-session31-latest.dll` is the s31 copy). Ask the operator what is on screen — you cannot
see screenshots.