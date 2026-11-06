# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Session 33 is finished. Read `notes/m1-session33.md` in full
before touching anything — it supersedes everything older. Then `PLAN.md` §0–§2, §6.1 and **§17
(two-worker split)**.

Say everything to me in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo (keep current): `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first.

At the end of the session run: `cmd /c D:\aoe2lan-repo\sync.cmd "session 34 - <one line, no
parentheses, no colon after NN>"`. In this shell `cmd /c` must be written as
`/c/WINDOWS/system32/cmd.exe //c`.

**You cannot launch the game.** The operator double-clicks `PLAY-stage*.cmd`. You cannot see the
screen either — ask what is on it. If a launch dies at ~3 s, wait ~45 s and ask for a relaunch.

**Two source trees.** The one that builds is the game-dir copy:
`D:\Age of Empires II Definitive Edition\dev\lanhook`. Its `build.cmd` stages `dbghelp.dll` into the
game dir. `D:\aoe2lan-repo\dev\lanhook` is only a mirror, refreshed by `sync.cmd` at the end. Edit the
game-dir copy. **A running game locks the staged `dbghelp.dll`**, so a rebuild can only be staged
after the operator closes the game — check the copy actually happened (`cp` fails with "Device or
resource busy"); s33 wasted two launches on exactly that.

## WHERE WE ARE (do not re-derive)

- Gates: `hooktest.exe` **68/68**; `srvtest.exe` + `srvclient.py` **PASS**. Game exe MD5
  `affb19f03ca96965abf9e56775cab688`, untouched. Staged DLL **240,128 B**, `0baf925b…`, which is the
  s32 build: it differs from `D:\dbghelp-session32-latest.dll` in only the two timestamps.
- **LAN hosting still works** (`HostAsync - completed with HostResult = 0`, real advertisement id, a
  lobby with slots, Ready and Start Game on screen).
- **The blocker is unchanged**: in the host lobby only Location (map) and Map Size work; Difficulty,
  Resources, Population, Game Speed, Reveal Map, Starting Age, Ending Age, Treaty Length, Victory,
  every Team and Advanced checkbox, and the add-AI offer are dead. Skirmish works, on the same
  install, same rows.
- **A whole-address-space memory sweep crashes this game.** s33 built four read-only probe variants
  that all walked committed memory; the last one killed the game during lobby creation (Windows Event
  1000, exception `0x40010006` in `KERNELBASE.dll`) and the heartbeat thread had already stopped 68 s
  earlier. Removing the probe made the same walk clean. **Do not sweep memory.** Read only addresses
  reached through a pointer you already trust.
- **Widget lookup is understood** (`GetWidget` `0x140ac4090` → comparator `0x140ab0780`): the screen's
  widget vector is at `[screen+0x58]`..`[screen+0x60]`; a widget's own name is a `std::string` inside
  the object at **`+0x3e8`** (size at `+0x3f8`, capacity at `+0x400`); the comparison uses the **last
  path component** only. Row paths confirmed live in Skirmish:
  `Background/Data/GameSettings/Data/{GameDropDown, MapSizeDropDown, ResourcesDropDown,
  PopulationDropDown}`, `Background/Data/AdvancedAndTeamSettings/{LockTeams, …, AllTechs}`.
- **s32f's "`vtable+0x68` = SetEnabled" is class-specific and does not carry over.** Vtable
  `0x1433fe100` has a **getter** there (`movzx eax,[rcx+0x45]`) with the setter one slot later at
  `+0x74` (`mov [rcx+0x46],dl`). Two enable setters that ARE clean on disk and therefore hookable:
  **`0x140a74cf0`** = `mov byte ptr [rcx+0xa5],dl; ret`, and **`0x140a74ca0`** = same plus a side
  effect. `0x141aab4a0`, `0x141abc6c0`, `0x140ac4090` are **encrypted on disk** — never hook those.
- **Polarity of the settings-block flag is still UNKNOWN.** The `0x2f/0x3f` words found in the row
  tables are widget-type flags (they differ row to row *while every row works* in Skirmish) — do not
  read them as on/off.
- `0x141aab4a0` also reads an 8-byte field of a settings struct and passes its **inverse** to the last
  two widgets, so the argument may be a preset selector rather than a plain bool. INFERRED.
- Still open from s32: relay answers `relayIP 127.0.0.1` while the game uses `192.168.0.104:27012`;
  cross-machine join untested; `matchTypeID` `-1`; party plane answers `[0,[]]`.

## THIS SESSION, IN ORDER

1. `git pull`, run both gates, confirm the staged DLL size and MD5 (expect 240,128 B / `0baf925b…` or
   a rebuild that differs only in the two timestamps).
2. Settle the polarity with the cheapest allowed measurement, not with more sweeping. Preferred: a
   read-only logging detour on the two **clean-on-disk** setters `0x140a74cf0` and `0x140a74ca0`,
   logging `rcx` (the object), the byte argument, and `ctx[19]` (the caller). Ask the operator first —
   it is a new detour, it needs exact bytes and a revert story (revert = rebuild without it; ids 4, 5
   and 13 remain the only ones installed, and keep it behind an env var so a normal launch is
   untouched, which is what made s33's isolation run possible).
3. In parallel, for free: finish the static trace of **who sets `rbx`** in `0x141abc6c0` before the
   `test rbx,rbx` at `0x141abe0d1`. If that object is missing because our shim never populates it,
   the enable call at `0x141abe0e5` is skipped and this becomes a shim gap rather than a patch. Report
   what the object is before proposing any patch.
4. Only after the flag is understood: join, leave, then the browse path from the friend's Linux box,
   then the relay address pointed at the tailnet IP instead of loopback.

## RULES THAT STILL APPLY

Never patch or hook code encrypted on disk (`0x141aab4a0`, `0x141abc6c0`, `0x140ac4090` and friends).
Hook ids 4, 5 and 13 only unless the operator approves a new one. No blind patching. No cosmetic
fixes. No whole-memory sweeps. Any new detour or game-file edit is the operator's call and needs exact
bytes plus a revert story. Use `dev/lanhook/gametext.bin` for code, never the encrypted exe. Do not
edit `lanhub/**`, `linux/**` or `notes/linux-*.md` — that is the Linux worker (PLAN §17.1). Hand him
`dbghelp.dll` as a file when he asks; it is git-ignored and travels outside the repo
(`D:\dbghelp-session32-latest.dll` is the s32 copy; make a fresh `D:\dbghelp-session33-latest.dll`).
Ask the operator what is on screen — you cannot see it.