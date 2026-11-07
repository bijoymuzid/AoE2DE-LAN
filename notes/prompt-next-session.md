# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Read `notes/m1-session36.md` in full before touching anything; it
supersedes `notes/m1-session35.md` and resolves the widget enable polarity contradiction from s32–s35.
Then read `PLAN.md` §0–§2, §6.1 and §17.

Say everything to me in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo: `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first. At the end run
`cmd /c D:\aoe2lan-repo\sync.cmd "session 37 - <one line, no parentheses, no colon after NN>"`
(in this shell `cmd /c` must be written as `/c/WINDOWS/system32/cmd.exe //c`).

## WHERE WE ARE (do not re-derive)

- **Gates:** `hooktest.exe` PASS (68/68), `srvtest.exe` + `srvclient.py` PASS. Game exe MD5
  `affb19f03ca96965abf9e56775cab688`, untouched. Staged `dbghelp.dll` = 241,664 B, MD5
  `5ca2dadf03b0f9951ed0a0dbb61592d6`.
- **The one blocker:** in the host lobby only Location (map) and Map Size work. Difficulty, Resources,
  Population, Game Speed, Reveal Map, Starting/Ending Age, Treaty Length, Victory, Teams, the Advanced
  checkboxes and the add-AI offer are all dead.
- **What Session 36 proved (measured in `logs/lanhook-2536.log` and `logs/lanhook-8660.log`):**
  1. **The main-menu twin-rule table (`AOE2LAN_RULES=1`) is NOT used by the host lobby.** Whole-`.text`
     xref of `0x141b126f0` / `0x141b12a00` found zero calls in `0x141aa0000..0x141ad0000`.
  2. **Session 35's `0x140a74ca0` (`+0xa5`) is NOT called by the UI widgets** (zero hits across an
     entire login + host lobby run).
  3. **The real widget enable/visibility flag is `[rcx+0x3d8]`, written by `0x140ab6300` (`[vt+0x78]`,
     CLEAN ON DISK, shared by 35 widget vtables).**
     - In `0x141aab4a0`, `GetWidget` results are `__RTDynamicCast`'d (`0x142d705a5`) to Checkbox/Button
       (vtable `0x143219728`, `[vt+0x68] = 0x140ab02a0`) or DropDown (vtable `0x14321a0a8`,
       `[vt+0x68] = 0x140acc950`).
     - Both `[vt+0x68](widget, dl, r8b)` functions do:
       - **`dl == 0` -> `and rdx, ~4` (CLEARS bit `0x4` = ENABLED / UNLOCKED)**
       - **`dl != 0` -> `or rdx, 4` (SETS bit `0x4` = DISABLED / LOCKED)**
       and then call `[vt+0x78]` = `0x140ab6300(rcx, rdx)`.
     - `[vt+0x60]` (`0x140ab6d20`, visibility) does the same for **bit `0x8` (HIDDEN)** (`dl != 0`
       clears `0x8` = visible; `dl == 0` sets `0x8` = hidden) and calls `0x140ab6300`.
     - Measured in `logs/lanhook-8660.log`: dropdowns and checkboxes start with `+0x3d8 = 0x4`
       (disabled), and enabling them transitions **`old=0x4 -> new=0x0`**.
     - **This resolves s32f's contradiction:** `0x141aab4a0(screen, 0)` at `0x141aacd03` is an
       **UNLOCK** call (`dl = 0`), and `0x141aab4a0(screen, IsEventScenario)` at `0x141abe0e5` locks
       (`dl = 1`) only when `IsEventScenario` is true!

## THIS SESSION, IN ORDER

1. `git pull`. Confirm staged `dbghelp.dll` is 241,664 B / `5ca2dadf03b0f9951ed0a0dbb61592d6`.
2. **Run the already-staged `PLAY-stage8-SETEN.cmd`:**
   - Hook id 14 (`WidgetSetEn` on `0x140ab6300`, `grp=0`, active only via `AOE2LAN_HOOKS=4,5,13,14`)
     is already updated to skip the first 20 s of boot (so Options/QueueButtons don't fill the log cap)
     and log all bit-`0x4` changes + `lobby_caller` RVAs up to 512 lines.
   - Launch `PLAY-stage8-SETEN.cmd` (WAIT at least 20 s after launch before entering the host lobby!),
     let the operator click Multiplayer -> Host Game, and inspect the new `logs/lanhook-<pid>.log` live.
3. **Read the `WidgetSetEn` lines from the host lobby:**
   - Check whether the dead rows (`ResourcesDropDown`, `DifficultyDropDown`, `PopulationDropDown`,
     `GameSpeedDropDown`, `LockTeams`, etc.) ever get `old=0x4 -> new=0x0` (unlocked) and then locked
     back (`new=0x4`), OR if they are never unlocked at all because `0x141aab4a0` / the caller skipped
     them, OR if `DropDownListBox` child widgets stay at `0x4`.
   - From that exact measurement, implement the cleanest fix to unlock the host lobby rows and add-AI.

## RULES THAT STILL APPLY

Never patch or hook code encrypted on disk (`0x141aab4a0`, `0x141abc6c0`, `0x140ac4090`, `0x140ab02a0`,
`0x140acc950`) — read those from `dev/lanhook/gametext.bin` only. (`0x140ab6300` IS clean on disk.)
**No whole-memory sweeps and never set `AOE2LAN_UIW=1` or `rules_scan()`.** Default stage-8 hooks stay
ids 4, 5 and 13 (`grp=0` for id 14). Do not edit `lanhub/**`, `linux/**` or `notes/linux-*.md`. Edit
the game-dir tree (`D:\Age of Empires II Definitive Edition\dev\lanhook`), then sync with `sync.cmd`.
