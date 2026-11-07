# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Read `notes/m1-session38.md` in full before touching anything; it
supersedes `notes/m1-session37.md`. Then read `PLAN.md` §0–§2, §6.1 and §17.

Say everything to me in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo: `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first. At the end run
`cmd /c D:\aoe2lan-repo\sync.cmd "session 39 - <one line, no parentheses, no colon after NN>"`
(in this shell `cmd /c` must be written as `/c/WINDOWS/system32/cmd.exe //c`).

## WHERE WE ARE (do not re-derive)

- **Gates:** `hooktest.exe` PASS (68/68), `srvtest.exe` PASS. Game exe MD5
  `affb19f03ca96965abf9e56775cab688`, untouched. Staged `dbghelp.dll` = 242,176 B, MD5
  `d313af6964b08e0ab4fe6d908a6f1a01`. The last-known-good s37 DLL is backed up at
  `dev/lanhook/dbghelp.dll.prev-s37-5ca2`.
- **The blocker is mostly FIXED.** In the host lobby, the match-settings rows were dead because the
  engine locks them (sets bit `0x4` on the widget) in a pass right after the lobby is built. Session
  38 found the lockers and now suppresses the lock at the clean `WidgetSetEn` hook (id 14).
- **Verified working in-game (operator):** Difficulty, Resources, Population, Game Speed, Reveal Map,
  Treaty Length, Teams, and the Advanced checkboxes all respond now. Location and Map Size still work.
- **NOT yet verified (code-complete, rebuilt, but the operator did not re-test):** Starting Age,
  Ending Age, Victory, and the add-AI button. These needed a 3rd and 4th locker range because a second
  pass re-locks them; that fix is in the staged DLL but unconfirmed in-game.

## THE MECHANISM (do not re-derive — it is proven)

- Hook id 14 = `WidgetSetEn` at the CLEAN `0x140ab6300`. `rdx` = new flags for `[widget+0x3d8]`;
  bit `0x4` = disabled/locked.
- `ctx[25]` (module-relative) = the return address of whoever called the `[vt+0x68]` DropDown thunk =
  **the locker**. (Frame math in 38b. The old s37 scan missed it only because it filtered to
  `0x1aa0000..0x1ad0000` and the lockers are below that.)
- `hooks.asm` restores `rdx` from `ctx[16]`, so writing `ctx[16]` in the logger changes what the
  original stores. The fix clears bit `0x4` in `ctx[16]` when `l25` is inside a known locker.
- Locker ranges already in the predicate (see 38e): `0x1a2ce20..0x1a2d2dd`, `0x1a31940..0x1a32e31`,
  `0x1a2e250..0x1a2f5e2`, `0x1a48820..0x1a48cc2`.
- The real source gate is `cmp [this+0x1cf8],[0x14326b258]; je skip-locking` at locker entry
  `0x141a2ce20` — but that code is **encrypted on disk**, so it cannot be hooked. Suppression at the
  clean `WidgetSetEn` is the authorized fallback.

## THIS SESSION, IN ORDER

1. `git pull`. Confirm staged `dbghelp.dll` = 242,176 B / `d313af6964b08e0ab4fe6d908a6f1a01`.
2. **Verify the last four rows.** Launch with
   `powershell -NoProfile -ExecutionPolicy Bypass -File "dev\lanhook\work\launch-detached.ps1"`
   (runs `PLAY-stage8-SETEN.cmd`, hooks `4,5,13,14`). Wait ~12 s, confirm `AoE2DE_s.exe` is alive and
   `logs/lanhook-<pid>.log` is growing. Ask me to click Multiplayer → Host Game and test **Starting
   Age, Ending Age, Victory, and the add-AI button**.
   - If a row still dead: `grep name="<Widget>" logs/lanhook-<pid>.log`, read the `l25` on its final
     `new=0x…4` line → that is the next re-lock site. Get its function bounds
     (`cd dev/lanhook && python fn.py 0x1<l25>`), add the range to the 38e predicate in
     `hookcore.c` `HK_WSET`, rebuild (`cmd /c build.cmd`), re-run `hooktest.exe` (must stay 68/68),
     relaunch, re-test. Repeat until all rows respond.
   - "AI" is assumed to be `ButtonCiv`. If the add-AI offer is a different widget, find its name in the
     log and handle its locker the same way.
3. **Then prove it is not cosmetic.** Once every row responds, start an actual LAN match (change a
   setting, start the game) and confirm the setting takes effect in the sim and there is no desync.
   A cleared bit `0x4` makes the row editable; it does not by itself prove the click handler commits
   the value. This is the gate to M2.
4. Only if suppression keeps whack-a-moling (a new re-lock pass every time), consider the harder source
   route: find what writes `this->field_0x1cf8` on the lobby screen and why it differs from the
   sentinel `[0x14326b258]` for LAN. The writer may also be encrypted — check disk-vs-`gametext.bin`
   before trying.

## HOW TO LAUNCH (do not use `cmd /c PLAY-*.cmd` directly — it dies in ~1 s)

`powershell -NoProfile -ExecutionPolicy Bypass -File "dev\lanhook\work\launch-detached.ps1"` spawns
through WMI (parented to `WmiPrvSE`, outside the agent's job object). Wait ~12 s, then ask me to click.
To stop: `taskkill /PID <gamepid> /F` (write it as `/c/WINDOWS/system32/taskkill.exe //PID <pid> //F`).

## RULES THAT STILL APPLY

Never patch or hook code encrypted on disk (`0x141aab4a0`, `0x141abc6c0`, `0x140ac4090`, `0x140ab02a0`,
`0x140acc950`, and the lockers `0x141a2ce20` / `0x141a31940` / `0x141a2e250` / `0x141a48820`) — read
those from `dev/lanhook/gametext.bin` only. `0x140ab6300` IS clean. No whole-memory sweeps; never set
`AOE2LAN_UIW=1` or `rules_scan()`. Default stage-8 hooks stay 4, 5, 13; id 14 only via
`AOE2LAN_HOOKS=4,5,13,14`. Do not edit `lanhub/**`, `linux/**`, `notes/linux-*.md`. Edit the game-dir
tree (`D:\Age of Empires II Definitive Edition\dev\lanhook`), then sync with `sync.cmd`.
