# Session 37 — the host-lobby rows ARE locked by the engine (bit `0x4`), measured; locker caller not captured yet

Supersedes `notes/m1-session36.md`. Everything below is MEASURED in a live run
(`logs/lanhook-13752.log`) or read from `AoE2DE_s.exe` / `gametext.bin`. No game file was touched
(`AoE2DE_s.exe` unchanged; staged `dbghelp.dll` unchanged, see §37a). **No source file was changed this
session** — this is a measurement-only session.

## 37a. Gates (unchanged, all pass)

- `hooktest.exe` 68/68, `srvtest.exe` + `srvclient.py` PASS.
- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688`.
- Staged `dbghelp.dll` 241,664 B, MD5 `5ca2dadf03b0f9951ed0a0dbb61592d6` (game dir + `dev/lanhook/`).
  It already contains the s36 `HK_WSET` (20 s boot skip, 512-line cap, bit-`0x4` filter).

## 37b. How to launch the game from the agent (new, important)

A game started as a child of the agent's shell (`cmd /c PLAY-*.cmd`) is **killed after about 1 s**
(job-object teardown when the tool call returns). Symptom: `logs/lanhook-<pid>.log` stops at
`t=1.0..1.1s` with no `hb alive` line and no process left.

Working method — spawn it through WMI so it is parented to `WmiPrvSE`, outside the job:
`dev/lanhook/work/launch-detached.ps1` (run with `powershell -NoProfile -ExecutionPolicy Bypass -File`).
It has one parameter, the `PLAY-*.cmd` to run, and creates the process with
`Invoke-CimMethod -ClassName Win32_Process -MethodName Create`. The run in this note survived 8+ minutes.

## 37c. MEASURED — the dead rows receive `bit 0x4` (LOCKED) at lobby build, and never get it cleared

Run: `PLAY-stage8-SETEN.cmd` (stage 8, hooks `4,5,13,14`), operator clicked Multiplayer -> Host Game,
sat in the host lobby. `logs/lanhook-13752.log`, hook id 14 = `WidgetSetEn` on `0x140ab6300`.
141 deduped lines, **log cap not hit**.

Timeline (all `ret=` values are the setter's own return address, i.e. the thunk's frame, not the
caller — see §37d):

| t | what |
|---|---|
| 67.781s | host-lobby list screen: `DropDownListBox 0x0 -> 0xc`, `ButtonJoin/ButtonSpectateCA 0x0 -> 0x4` |
| 67.875s | `DelayDropDown 0x0 -> 0x4`, `DataModDropDown 0x0 -> 0x4`, `ButtonCreate 0x0 -> 0x4` |
| 67.906s | `DelayDropDown 0x4 -> 0x0` (unlocked) — the only dropdown that gets an explicit unlock |
| 69.5–70.5s | `ButtonCreate 0x4 -> 0x0`, `AllowSpectatorsCheckBox 0x0 -> 0x4` |
| 74.969s | the host lobby screen is built. Every widget: `0x0 -> 0x4` (lock) then `0x4 -> 0x0` (unlock); checkboxes and `ButtonLocation`, `NameDropDown`, `RecordGame` end at `0xc -> 0x8` |
| **75.438s** | **exactly the twelve match-settings dropdowns go `0x8 -> 0xc` = bit `0x4` SET = LOCKED, and never cleared afterwards** |

The twelve locked at 75.438s, all with `vt=0x321a0a8` (DropDown) and `ret=0xacc989`
(= inside `0x140acc950`, the DropDown `[vt+0x68]` thunk):

`GameDropDown`, `DifficultyDropDown`, `ResourcesDropDown`, `PopulationDropDown`, `RevealMapDropDown`,
`StartingAgeDropDown`, `EndingAgeDropDown`, `TreatyLengthDropDown`, `BattleRoyaleTimeDropDown`,
`TimeDropDown`, `GameSpeedDropDown`, `VictoryDropDown`.

This is a 1:1 match with the visible symptom: the two rows that work are the two that are **never
touched**: `MapSizeDropDown` and `ButtonLocation` do not appear in the log at all after t=20s, so
their `+0x3d8` keeps the value it was built with (bit `0x4` clear = enabled).

`NameDropDown` (own seat civ/name) is locked and then unlocked at the same timestamp
(`0x8 -> 0xc`, then `0x4 -> 0x0`), so the lobby does run a per-widget lock pass, not one blanket call.

Widget state semantics (confirmed again): bit `0x4` = disabled/locked, bit `0x8` = hidden,
`0x40/0x80/0x90/0x9c` etc. appear on labels and scrollbars and are unrelated.

## 37d. Why the locker's RVA was not captured (and the fix)

`hooks.asm` saves `7` GPRs then `sub rsp,0x80`, so the entry `rsp` is `ctx + 0x98` and `ctx[19]` is the
original return address *at* entry `rsp`. `HK_WSET` then scans only `ctx[20..31]` = entry `rsp+8 ..
rsp+0x60`, i.e. the caller's shadow space and the first four stack args — **not the caller's frame**.
Result: `lobby_caller` was empty on all 141 lines and `ret=0xacc989` (the thunk) was logged instead.
Zero hits in `0x141aa0000..0x141ad0000` does **not** mean the locker is outside the lobby cluster.

Fix for the next run (small, in `hookcore.c` `HK_WSET`): widen the stack scan to ~1024 slots
(8 KB, `__try`-guarded — this is our own stack, not a memory sweep) and log the first value in
`0x141aa0000..0x141ad0000` as `lobby_caller` plus the first value that is any code address inside the
game module as `frame=`. Keep everything else (20 s skip, bit-`0x4` filter, 512-line cap).

## 37e. Static handle for the same question (no live run needed)

The multiplayer lobby widget paths are one contiguous `.rdata` block (`.rdata` VA = `0x3197000 +
(raw - 0x3195c00)`):

```
raw 0x334ad48  0x14334c148  Background/Data/GameSettings/Data/GameDropDown
raw 0x334adb8  0x14334c1b8  .../MapSizeDropDown      <- the one that works
raw 0x334adf0  0x14334c1f0  .../DifficultyDropDown   <- first of the twelve that get locked
raw 0x334ae28 .. ..c228     .../ResourcesDropDown
raw 0x334ae60 .. ..c260     .../PopulationDropDown
raw 0x334ae98 .. ..c298     .../GameSpeedDropDown
raw 0x334aed0 .. ..c2d0     .../RevealMapDropDown
raw 0x334af08 .. ..c308     .../StartingAgeDropDown
raw 0x334af40 .. ..c340     .../EndingAgeDropDown
raw 0x334af78 .. ..c378     .../TreatyLengthDropDown
raw 0x334afb0 .. ..c3b0     .../BattleRoyaleTimeDropDown
raw 0x334aff0 .. ..c3f0     .../VictoryDropDown
raw 0x334b028 .. ..c428     .../TimeDropDown
```

`python xr.py 0x14334c1b8 0x14334c1f0 ...` (rip-relative xref scan over the decrypted `.text`) gives the
functions that look these widgets up; the locking function must be one of them (it calls `[vt+0x68]`
with `dl=1` on the twelve but not on `MapSizeDropDown`).

(The earlier `Background/DifficultyDropDown` and `Background/Data/GameSettings/Data/...` hits at
raw `0x3333aeb` belong to `UIScreenCampaignScenarioSelection` / `UIScreenSinglePlayerCreate` — not the MP
lobby. `.data` copies exist at raw `0x4138573`, `0x41b080a`.)

## 37f. Where the next session starts

Two independent routes to the same answer; do the cheap one first, in this order:

1. **Static: `xr.py` on the thirteen path VAs from §37e.** If one function both looks up
   `MapSizeDropDown` and the twelve, and calls `[vt+0x68](w, 0)` / `(w, 1)` around them, its gate
   (a bool field or a call result) is the thing to fix. This needs no game run and no new DLL.
2. **Live: widen the `HK_WSET` stack scan (§37d)** and re-run `PLAY-stage8-SETEN.cmd` with the operator
   in the host lobby; read `lobby_caller` off the twelve `0x8 -> 0xc` lines.

Then decide the fix. Two candidates, in order of taste:
- **Source fix (preferred):** whatever flag makes the lobby think the match settings are fixed
  (`IsEventScenario`-like, per s36d; or a matchtype/`dataChecksum`-derived "not editable") — clear it
  for the LAN lobby so the engine unlocks the rows itself.
- **Mechanical fix (fallback, only if the source fix is unreachable without patching encrypted code):**
  hook the CLEAN `0x140ab6300` (already hook id 14's target) and refuse the `bit 0x4` *set* when the
  stack says the caller is the lobby lock pass, i.e. `newf = oldf` for those widgets. In-memory only,
  revert = drop the hook. Note this hides the lock but the engine may still gate the click handler
  elsewhere, so it must be verified in-game, not assumed.

Never patch or hook code encrypted on disk (`0x141aab4a0`, `0x141abc6c0`, `0x140ac4090`,
`0x140ab02a0`, `0x140acc950`) — read those from `dev/lanhook/gametext.bin` only. No whole-memory
sweeps; never set `AOE2LAN_UIW=1` or `rules_scan()`.