# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Session 30 is finished. Read `notes/m1-session30.md` in full
before touching anything — it supersedes everything older. Then `PLAN.md` §0–§2, §6.1 and the new
**§17 (two-worker split)**.

Say everything to me in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo (keep current): `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN

At the end of the session run: `cmd /c D:\aoe2lan-repo\sync.cmd "session 31 - <one line, no
parentheses, no colon after NN>"`. In this shell `cmd /c` must be written as
`/c/WINDOWS/system32/cmd.exe //c`.

## WHERE WE ARE (all measured in session 30, do not re-derive)

- Login works with `AOE2LAN_STAGE=8` via `PLAY-stage8-LOGIN.cmd`. Offline gates: `hooktest.exe`
  68/68, `srvtest.exe` + `srvclient.py` PASS (the client now also proves 6 concurrent requests are
  answered and that an `Expect: 100-continue` request gets its interim reply).
  `dev/lanhook/build.cmd` builds and stages `dbghelp.dll` into the game dir by itself.
- M1 is met: the Multiplayer button is live and the Multiplayer screen opens.
- **The LAN door is real and already offered by the UI.** In the Create Game dialog the **Server**
  dropdown lists `Default`, `LAN`, **`Use Local Lan Server`**. That last entry is appended by
  `0x1418eee60` (fills `Background/Settings/RegionAnchor/RegionDropDown`) after the item vector at
  `[0x1442dc4f0]+0x2628` (stride 0x50), and only when `[svc+0x2e8] -> [[vtbl]+0x418]` (i.e.
  `0x140f0f5c0`) returns non-zero. It returns true on this install (probe prints `257`, read the low
  byte). Do not go looking for a hidden switch: pick the dropdown entry.
- With `Server = Use Local Lan Server` the log now says **`starting LAN hosting`** instead of
  `starting online hosting`. So the selection reaches the hosting decision.
- **The hosting failure was ours and is now fixed but NOT yet verified in game.** The game's HTTP
  client is libcurl; it adds `Expect: 100-continue` to bodies over 1 KB and waits exactly 1000 ms for
  the interim reply. Our server never sent it, so the 3.5 KB create-advertisement request never
  reached us and `WorldwideHostAsync` failed with reason -1 / `HostResult = 1`. `loginsrv.c` now
  sends `HTTP/1.1 100 Continue` (and the per-connection HTTP state is no longer shared between
  threads). Evidence and the exact log lines are in `notes/m1-session30.md` §30f–30i.
- Current staged DLL crc **`883a488f`** (234,496 B). `AoE2DE_s.exe` crc `4f533b6c` — unchanged.
  XAML stock crc `8398949b` — unchanged. No game file, no `.text` byte, no XAML was ever changed.
- About 60% of `.text` is encrypted at rest. Never reason about `.text` from `AoE2DE_s.exe`. Use
  `dev/lanhook/gametext.bin` (VA = `0x140001000 + offset`) or `dev/AoE2DE_dec.exe`.
- `LANAdvertisementCache - response was not formatted correctly: [0,[]]` still fires twice per
  session (our catch-all reply to `/game/advertisement/getLanAdvertisements`). That is W1-b below.

## THIS SESSION, in order

1. Offline gates (`build.cmd`, `hooktest.exe`, `srvtest.exe` + `srvclient.py`).
2. **One click test, first thing.** Operator: Multiplayer → Host Game → Create Game → Server =
   `Use Local Lan Server` → Create. In the log, look for `srv: 100-continue`, then a
   `POST /game/advertisement/...` request, then whether a lobby appears. Report what the screen says.
3. If the create request now arrives, give it a real reply. `getLanAdvertisements` /
   `findAdvertisements` / the create and join paths are still the catch-all `[0,[]]`. Crack each
   reply's schema from the game's own parser the same way `getAvailableLeaderboards` was cracked
   (element parser address, then the named-field readers). One at a time, each measured.
4. Then the relay: the advertisement must carry this machine's **tailnet IP**, not `192.168.0.x`.
   `Adding LAN relay server: <ip>` in the log shows what the game picked up.
5. Only after a lobby exists, think about the second machine. The success target is unchanged: two
   machines on one tailnet, one Windows and one Arch Linux via Proton, a `[LAN]` lobby with 2 human
   and 6 AI slots, a full skirmish to a victory screen with no desync.
6. Do not batch the other caches (news, community events, item bundles, item categories, challenges,
   chat channels, leaderboard stats, achievements, offline messages, cloud credentials). One at a
   time, own element schema, only when a measurement points at it.

## SECOND WORKER

An Arch Linux worker is now on the same repo, same game build, working the platform-neutral half:
the native `lanhub`, the Linux launcher and Wine prefix, and the relay regression harness. The split,
the file ownership table and both workstreams are in `PLAN.md` §17. **Do not edit `lanhub/**`,
`linux/**` or `notes/linux-*.md`.** Hand over the built `dbghelp.dll` when it is asked for; it is
git-ignored so it travels as a file. `git pull` at session start.

## RULES

Never patch or hook code that is encrypted on disk; hook ids 4+5 (LogHelper/LogHelper2) and 13
(LogWarn) only; no blind patching; no cosmetic fixes (making something look right without fixing the
behaviour is forbidden); any new detour, `.rdata` re-point or game-file edit is the OPERATOR's call
and needs exact bytes plus the revert story; if a game launch dies at ~3 s, wait ~45 s with nothing
running and relaunch.

## TOOLS

`C:/Python314/python.exe` (capstone + numpy). MSVC 14.44 + WinSDK 10.0.26100;
`dev/lanhook/build.cmd`. Static: `dz.py` (start end), `fn.py` (`<addr>` [--dump]), `xr.py`, `vt.py`,
`cx.py`, `aoe2re.py`. `xr.py` silently misses some references — verify any "no xref" conclusion
against a string known to be used in the same `.rdata` block, and re-derive with a backwards capstone
disassembly that keeps only instructions ending exactly at the disp. Ghidra:
`dev/ghidra-decomp.cmd` + `dev/ghidra-scripts/PdataDecomp.java` + `targets.txt` (~60–90 s per
batch). Live: `logs/lanhook-<pid>.log`; the game's `Main.txt` only carries the `[Main]` category and
is useless for network work; localization strings are in
`resources/en/strings/key-value/key-value-strings-utf8.txt` and the key→id map is
`widgetui/stringreference.json`. This model cannot view images, so ask the operator what is on
screen instead of screenshotting.