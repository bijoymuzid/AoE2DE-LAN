# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Read `notes/m1-session37.md` in full before touching anything; it
supersedes `notes/m1-session36.md`. Then read `PLAN.md` §0–§2, §6.1 and §17.

Say everything to me in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo: `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first. At the end run
`cmd /c D:\aoe2lan-repo\sync.cmd "session 38 - <one line, no parentheses, no colon after NN>"`
(in this shell `cmd /c` must be written as `/c/WINDOWS/system32/cmd.exe //c`).

## WHERE WE ARE (do not re-derive)

- **Gates:** `hooktest.exe` PASS (68/68), `srvtest.exe` + `srvclient.py` PASS. Game exe MD5
  `affb19f03ca96965abf9e56775cab688`, untouched. Staged `dbghelp.dll` = 241,664 B, MD5
  `5ca2dadf03b0f9951ed0a0dbb61592d6`, unchanged since session 36.
- **The one blocker:** in the host lobby only Location (map) and Map Size work. Difficulty, Resources,
  Population, Game Speed, Reveal Map, Starting/Ending Age, Treaty Length, Victory, Teams, the Advanced
  checkboxes and the add-AI offer are all dead.
- **What session 37 measured (`logs/lanhook-13752.log`) — this is the new, decisive fact:**
  - At **t=75.438s**, seconds after the host lobby is built, exactly **twelve** match-settings
    dropdowns get **bit `0x4` SET** (`old=0x8 -> new=0xc`) through the DropDown `[vt+0x68]` thunk
    `0x140acc950`, and that bit is **never cleared again**: `GameDropDown`, `DifficultyDropDown`,
    `ResourcesDropDown`, `PopulationDropDown`, `RevealMapDropDown`, `StartingAgeDropDown`,
    `EndingAgeDropDown`, `TreatyLengthDropDown`, `BattleRoyaleTimeDropDown`, `TimeDropDown`,
    `GameSpeedDropDown`, `VictoryDropDown`.
  - `MapSizeDropDown` and `ButtonLocation` are **never touched** after the 20 s boot window, so they
    keep bit `0x4` clear = enabled. That is exactly why those two rows work.
  - So the rows are not "never unlocked by us" — **the engine deliberately locks them**, once, in one
    pass, and `NameDropDown` (own seat) gets locked *and* unlocked in the same pass.
- **Not captured yet:** which function does the locking. `ret=` in those lines is the setter thunk,
  not the caller. Reason: `hooks.asm` makes entry `rsp = ctx + 0x98`, so the existing `ctx[20..31]`
  scan only reads the caller's shadow space; `lobby_caller` was empty on all 141 lines. Widening that
  scan is a 3-line change in `hookcore.c` `HK_WSET` (see 37d).
- **Launching the game from the agent:** a game started with `cmd /c PLAY-*.cmd` dies after ~1 s
  (job-object teardown). Use `dev/lanhook/work/launch-detached.ps1`
  (`powershell -NoProfile -ExecutionPolicy Bypass -File "dev\lanhook\work\launch-detached.ps1"`),
  which spawns through WMI. Wait ~10 s, then ask me to click Multiplayer -> Host Game.

## THIS SESSION, IN ORDER

1. `git pull`. Confirm staged `dbghelp.dll` is 241,664 B / `5ca2dadf03b0f9951ed0a0dbb61592d6`.
2. **Cheap route first — static, no game run, no DLL change.** Run the rip-relative xref scan on the
   thirteen multiplayer lobby widget-path strings listed in 37e, e.g.
   `python xr.py 0x14334c1b8 0x14334c1f0 0x14334c228 0x14334c260 0x14334c298 0x14334c2d0 0x14334c308 0x14334c340 0x14334c378 0x14334c3b0 0x14334c3f0 0x14334c428 0x14334c148`
   (from `dev/lanhook`). The function that looks up `MapSizeDropDown` **and** the twelve, and calls
   `[vt+0x68](w, 1)` on the twelve only, is the locker. Disassemble it from `gametext.bin`
   (`python fn.py <hexva> --dump`) and read its gate: a bool field, a call result, or a matchtype test.
3. **If step 2 does not produce the gate in one pass, go live:** widen the `HK_WSET` stack scan to
   ~1024 slots as described in 37d, rebuild + retest (`hooktest.exe`), re-stage `dbghelp.dll`, launch
   via `launch-detached.ps1`, and have me sit in the host lobby. Read `lobby_caller` off the twelve
   `0x8 -> 0xc` lines.
4. **Then fix at the source, not with a cosmetic unlock:** find what makes the lobby treat the match
   settings as fixed (the `IsEventScenario`-shaped flag from s36d is the prime suspect) and clear it for
   the LAN lobby. Only if the test lives in encrypted code that cannot be reached cleanly, fall back to
   suppressing the `bit 0x4` set inside the already-hooked CLEAN `0x140ab6300` — and then verify in-game
   that the rows actually respond, because a cleared flag may not be the only gate.

## RULES THAT STILL APPLY

Never patch or hook code encrypted on disk (`0x141aab4a0`, `0x141abc6c0`, `0x140ac4090`, `0x140ab02a0`,
`0x140acc950`) — read those from `dev/lanhook/gametext.bin` only. (`0x140ab6300` IS clean on disk.)
**No whole-memory sweeps and never set `AOE2LAN_UIW=1` or `rules_scan()`.** Default stage-8 hooks stay
ids 4, 5 and 13; id 14 (`WidgetSetEn`, `grp=0`) only via `AOE2LAN_HOOKS=4,5,13,14`. Do not edit
`lanhub/**`, `linux/**` or `notes/linux-*.md`. Edit the game-dir tree
(`D:\Age of Empires II Definitive Edition\dev\lanhook`), then sync with `sync.cmd`.