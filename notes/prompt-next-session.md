# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Session 32 is finished. Read `notes/m1-session32.md` in full
before touching anything — it supersedes everything older. Then `PLAN.md` §0–§2, §6.1 and **§17
(two-worker split)**.

Say everything to me in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo (keep current): `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first.

At the end of the session run: `cmd /c D:\aoe2lan-repo\sync.cmd "session 33 - <one line, no
parentheses, no colon after NN>"`. In this shell `cmd /c` must be written as
`/c/WINDOWS/system32/cmd.exe //c`.

**You cannot launch the game.** `cmd /c start` gives "Access is denied" and a direct launch dies at
~5 s (no interactive desktop). The operator double-clicks `PLAY-stage*.cmd`. Do not waste turns
trying; ask the operator instead. If a launch dies at ~3 s, wait ~45 s and ask for a relaunch. You
cannot see the screen either — ask what is on it.

**Two source trees.** The one that builds is the game-dir copy:
`D:\Age of Empires II Definitive Edition\dev\lanhook`. Its `build.cmd` stages `dbghelp.dll` into the
game dir and `hooktest.exe` finds the game next to it. `D:\aoe2lan-repo\dev\lanhook` is only a mirror,
refreshed by `sync.cmd` at the end. Edit the game-dir copy. A rebuild is not bit-reproducible: the PE
timestamp and the debug timestamp differ, so compare those two offsets instead of the whole MD5 when
the code is supposed to be unchanged.

## WHERE WE ARE (all measured in session 32, do not re-derive)

- Gates: `hooktest.exe` **68/68**; `srvtest.exe` + `srvclient.py` **PASS**, now seven checks (the s31
  six plus `updateTags`). Game exe MD5 `affb19f03ca96965abf9e56775cab688`, untouched. Staged DLL at
  s32 end: **240,128 B**, MD5 `d32910972f7d221842607cf37144174e`.
- **LAN hosting still works end to end** (s31c): host request, accepted reply, real advertisement id,
  `HostResult = 0`, a lobby with slots, both Ready and Start Game on screen.
- **The blocker is unchanged and now sharply measured.** In the host lobby only the map (Location)
  and Map Size work. Dead, and clicking opens no list at all: Difficulty, Resources, Population, Game
  Speed, Reveal Map, Starting Age, Ending Age, Treaty Length, Victory, every Team and Advanced
  checkbox, and the add-AI offer on empty slots. Values still display (Resources = Standard). Unticking
  "I am ready" changes nothing. Start Game cannot be pressed with one player.
- **Single-player Skirmish works.** Same rows, same install, everything opens and changes. So the
  widget code, the option tables and the data files are fine; the lock is specific to the host lobby.
- **Fixed this session, measured, and NOT the cause:** `updateTags` and `updateState` were matching
  the `update` branch by substring and were being answered with a junk advertisement (`hostProfileID`
  0, empty `options`/`encodedSlots`, `matchState -1`) every second. They now echo the stored lobby and
  never overwrite it; `srvclient.py` fails if that id ever reads 0 again. Confirmed live in
  `logs/lanhook-18928.log` — and the panel is still locked.
- **The switch is found.** `0x141aab4a0(screen, flag)` enables/disables the whole block: Resources,
  Population, Reveal Map, Starting Age, Ending Age, Treaty Length, Time, LockTeams,
  SharedExploration, PlayerAssist, SolidFarms and the Reset/Randomize/Lobby Settings buttons — the
  exact dead set. Map, Map Size and the Game-mode row are not in that list, which is why they live.
  `vtable+0x68` is SetEnabled (measured: `ButtonReadyStart` is set to 1 at `0x141a40a99`),
  `vtable+0x60` is SetVisible.
- It has exactly two callers: `0x141aacd03`, inside the 19 KB per-slot refresh `0x141aac3d0`, which
  passes **0**; and `0x141abe0e5`, inside `UpdateLobbySettings` `0x141abc6c0`, which passes
  `IsEventScenario(...)` (`0x1413d4210` → `0x140f69fe0`: the selected scenario name against a 4-entry
  event-scenario table at `0x1442eb050`). The second call is also **skipped entirely** when a lobby
  object (`rbx`) is null.
- **The open contradiction to settle first:** if `flag = 0` means *disabled*, the per-slot refresh
  disables the block every time and the host lobby could never be editable; if `0` means *enabled*,
  neither caller explains the lock. Only a live read of one widget's flag decides it.
- `xr.py` **does** work on the full widget paths (this corrects s31 §31k, which matched bare names and
  landed on other screens). `.rdata` VA = `0x140000000 + (fileoff - 0x3195c00 + 0x3197000)`;
  `aoe2re.off2va()` is off by 0x1400 there.
- The game's own UI log strings (`UIScreenMultiplayerLobbyHost::Wake`,
  `...::UpdateLobbySettings initial call`) **never fire**, so a quiet log says nothing about whether
  the screen refresh ran.
- Still open from s31: relay says `127.0.0.1` in our replies while the game uses `192.168.0.104:27012`;
  join / leave / browse from a second machine is untested; `matchTypeID` is still `-1` in our update
  reply (unmeasured); the party plane (`/game/party/peerAdd`, `/game/relationship/setPresence`) still
  gets `[0,[]]`.

## THIS SESSION, IN ORDER

1. `git pull`, run both gates, confirm the staged DLL size and MD5.
2. **Settle the flag polarity with a measurement, not more reading.** Build the read-only probe
   described in s32i: opt-in env var, no detour, no write, in our own DLL. Scan committed memory for
   the pointer to each widget's full path string; for a hit whose preceding qword is an `.rdata`
   vtable with a sane `+0x68` setter, dump the object's first `0x80` bytes. Run it repeatedly (the
   operator has to be sitting in the host lobby) and diff one known-enabled row
   (`Background/Data/GameSettings/Data/MapSizeDropDown`) against known-disabled ones
   (`.../ResourcesDropDown`, `.../AdvancedAndTeamSettings/LockTeams`). That gives the enable-flag
   offset. Add a `PLAY-stage8-*.cmd` that sets the flag, and ask the operator to double-click it.
3. Only after that, chase why the flag is wrong: either the refresh `0x141aac3d0` is never reached on
   this lobby (it has no direct callers — it is a vtable entry), or it is reached and its `0` really
   does disable, or the `rbx`-guarded call in `0x141abc6c0` is what normally does the enabling and it
   is being skipped. Each of those is a different road; the probe picks it.
4. Then, one at a time and each measured: join, leave, then the browse path from a second machine (the
   friend's Linux box), then the relay address pointed at the tailnet IP instead of loopback.

## RULES THAT STILL APPLY

Never patch or hook code encrypted on disk. Hook ids 4, 5 and 13 only. No blind patching. No cosmetic
fixes. Any new detour or game-file edit is the operator's call and needs exact bytes plus a revert
story. Use `dev/lanhook/gametext.bin` for code, never the encrypted exe. Do not edit `lanhub/**`,
`linux/**` or `notes/linux-*.md` — that is the Linux worker (PLAN §17.1). Hand him `dbghelp.dll` as a
file when he asks; it is git-ignored, so it travels outside the repo
(`D:\dbghelp-session31-latest.dll` is the s31 copy; make a fresh `D:\dbghelp-session32-latest.dll`).
Ask the operator what is on screen — you cannot see it.