# Session 38 — locker FOUND and gated; bit-`0x4` suppression fix lands; most host-lobby rows now work

Supersedes `notes/m1-session37.md`. Everything below is MEASURED in a live run
(`logs/lanhook-1240.log` capture, `logs/lanhook-1780.log` fix-verify) or read from `gametext.bin`.
Game exe untouched. **The fix is in `dev/lanhook/hookcore.c` (`HK_WSET`), staged into `dbghelp.dll`.**

## 38a. Gates

- `hooktest.exe` 68/68 PASS. `srvtest.exe` PASS (loginsrv unchanged this session).
- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688`, untouched.
- Staged `dbghelp.dll` now **242,176 B, MD5 `d313af6964b08e0ab4fe6d908a6f1a01`** (game dir +
  `dev/lanhook/`). The s37 DLL (241,664 B, `5ca2dadf03b0f9951ed0a0dbb61592d6`) is backed up as
  `dev/lanhook/dbghelp.dll.prev-s37-5ca2`. Revert = restore that file or drop hook id 14.

## 38b. The decisive measurement — `ctx[25]` IS the locker's return address

The s37 stack scan came up empty because it filtered to `0x1aa0000..0x1ad0000`, but the lockers live
**below** that (RVA `0x1a2c…`–`0x1a48…`). The slot was already being read; the range filter threw it
away.

Proven frame math (read off `hooks.asm` + the thunk `0x140acc950` prologue):

- `hooks.asm`: entry `rsp = ctx + 0x98`; `ctx[19] = [entry_rsp]` = return address into the caller.
- Thunk `0x140acc950` prologue is `mov [rsp+10],rbx; mov [rsp+18],rbp; push rsi; sub rsp,0x20`, so at
  its `call r9` (→ WidgetSetEn) the thunk's entry `rsp = WSE_entry_rsp + 0x30`.
- Therefore **`[WSE_entry_rsp + 0x30] = ctx[25]` = the return address into whoever called
  `[vt+0x68]`** — the locker. Fixed slot, no scanning needed.

Fix to capture it (in `HK_WSET`): read `ctx[24]/ctx[25]/ctx[26]` directly, module-relative, no range
filter, and log them as `l24/l25/l26`. One live run (`PLAY-stage8-SETEN.cmd`, operator in the host
lobby) then printed the locker RVA on every lock line.

Setter semantics, confirmed from the thunk: `[vt+0x68](widget, dl, r8b)` → `dl=1` does
`or [w+0x3d8],4` (LOCK), `dl=0` does `and ~4` (UNLOCK); `r8b` is a secondary flag. So **bit `0x4` set
= disabled**, and the lock calls all pass `dl=1`.

## 38c. The lockers (module-relative RVAs; absolute = `0x140000000 + RVA`)

Grouping every `old→new` bit-`0x4` SET line by `l25` function bounds:

| locker func (RVA range) | widgets it locks | note |
|---|---|---|
| **`0x1a2ce20..0x1a2d2dd`** | GameDropDown, Difficulty, Resources, Population, RevealMap, StartingAge, EndingAge, TreatyLength, BattleRoyaleTime, Time, GameSpeed + TeamTogether, LockTeams, LockSpeed, AllowCheats, SharedExploration, AllTechs, EmpireWarsMode, SuddenDeathMode, PlayerAssist, TeamPosition, TurboMode (22) | **the main match-settings locker** |
| **`0x1a31940..0x1a32e31`** | Team, ButtonRandomize, ButtonReset, VictoryDropDown | Victory + seat Team |
| **`0x1a2e250..0x1a2f5e2`** | StartingAge, EndingAge, Victory, Resources (re-lock, `old=0x0→new=0x4`) | a SECOND pass that re-locks after the first |
| **`0x1a48820..0x1a48cc2`** | ButtonCiv (civ / add-AI button) | `Color` is at `0x1a48f04`, just outside — untouched |

Also seen but NOT part of the dead-row symptom (left alone): a wide pass at `l25=0x1a4687e`
(checkboxs/options) and `0x1a4675e` (all the lobby Buttons) — those widgets work, so their locks are
either undone later or not the effective gate.

## 38d. The gate (why it locks) — and why we can't fix it at the source

Main locker entry `0x141a2ce20`:

```
push rbx; sub rsp,0x30
mov rax, [0x14326b258]        ; global sentinel (referenced ~50 places engine-wide)
mov rbx, rcx                  ; this = lobby screen object
cmp [rcx+0x1cf8], rax         ; this->field_0x1cf8  vs  sentinel
je  0x141a2d2d7               ; EQUAL -> return immediately, lock NOTHING (editable)
                              ; NOT equal -> fall through, lock all 22 rows
```

So **`this->field_0x1cf8 == [0x14326b258]` means "settings editable"**. In our LAN host lobby the
field does NOT equal the sentinel, so everything locks. This is the `IsEventScenario`-shaped flag s36d
predicted.

**Blocker for the source fix:** I compared on-disk `AoE2DE_s.exe` bytes vs the decrypted
`gametext.bin` — the locker `0x141a2ce20`, the gate at `0x141a2ce30`, the Victory/Team locker, and the
re-lock pass are **all encrypted on disk** (`disk != run`, same as the known-encrypted controls
`0x140acc950` / `0x141aab4a0`). They cannot be hooked or patched. Only `WidgetSetEn 0x140ab6300` is
clean (`disk == run`) — and it is already hook id 14. That is exactly the "gate lives in encrypted
code" case where s37f authorizes the mechanical fallback.

## 38e. The fix (in `HK_WSET`, hook id 14, clean `0x140ab6300`)

`WidgetSetEn(widget=rcx, newflags=rdx)` stores `rdx` into `[widget+0x3d8]` (via `xchg`, skipped if
unchanged). `hooks.asm` restores `rdx` from `ctx[16]` (`pop rdx` reads `[rsp+0xA0] = ctx+0x80 =
ctx[16]`), so **writing `ctx[16]` in the logger changes the flags the original stores.**

```c
if ((newf & 4) &&
    ((l25 >= 0x1a2ce20 && l25 < 0x1a2d2dd) ||    // main match-settings locker
     (l25 >= 0x1a31940 && l25 < 0x1a32e31) ||    // Victory / Team locker
     (l25 >= 0x1a2e250 && l25 < 0x1a2f5e2) ||    // re-lock pass: Start/EndAge, Victory, Resources
     (l25 >= 0x1a48820 && l25 < 0x1a48cc2))) {   // ButtonCiv (civ / add-AI button)
    ((unsigned long long *)ctx)[16] = newf & ~4ULL;   // clear LOCK before the original stores it
    newf &= ~4ULL; suppressed = 1;
}
```

Suppression runs BEFORE the dedup/512-cap returns, so it always fires; a `SUPPRESSED` tag is added to
the log line. In-memory only, opt-in via `AOE2LAN_HOOKS=4,5,13,14` (`PLAY-stage8-SETEN.cmd`); revert =
drop hook 14 or restore the s37 DLL.

## 38f. Verified in-game (operator, `logs/lanhook-1780.log`)

With the **first two ranges only**, the operator confirmed: **all rows work EXCEPT StartingAge,
EndingAge, Victory and AI.** 36 `SUPPRESSED` lines logged. The log shows why the four stayed dead — a
**second lock pass** (`0x1a2e250` locker) re-locks StartingAge (`l25=0x1a2e8f4`), EndingAge
(`0x1a2ea18`), Victory (`0x1a2e671`) and Resources (`0x1a2eeb7`) with `old=0x0→new=0x4` AFTER the
first suppression, and ButtonCiv is locked from `0x1a48c63`.

The **third + ButtonCiv ranges were then added (38e) and rebuilt** — this is **code-complete but NOT
yet re-verified in-game.** First job next session: relaunch, host lobby, confirm StartingAge,
EndingAge, Victory and the add-AI button now respond.

## 38g. Where the next session starts

1. **Verify the last four.** `launch-detached.ps1` → `PLAY-stage8-SETEN.cmd`, operator hosts, tests
   StartingAge / EndingAge / Victory / add-AI. If a row is still dead, grep its name in the new
   `logs/lanhook-<pid>.log`, read the final `l25` on its `new=…4` line — that is the next re-lock
   site; add its function range to the 38e predicate. (Whack-a-mole risk is real: s37f warned "a
   cleared flag may not be the only gate.")
2. **Confirm "AI" == ButtonCiv.** No widget literally named AddAI appears; the civ/AI button in the
   log is `ButtonCiv` (+ `CivOptionAll/AoE2/Paphos` locked from `0x1a3ae40` and `0x1a4687e`). If the
   add-AI offer is a different widget, identify it from the log and add its locker range.
3. **Only after the rows respond:** try an actual LAN match (M2) — start a game, confirm the settings
   round-trip to the sim and nothing desyncs. The bit-`0x4` clear makes the UI editable; it does not
   by itself prove the click handlers commit the value.
4. **Optional real source fix (harder):** find what writes `this->field_0x1cf8` on the lobby screen
   and why it differs from `[0x14326b258]` for LAN. If a clean (non-encrypted) writer exists, setting
   the field to the sentinel makes the engine unlock the rows itself — cleaner than suppression, but
   the writer may also be encrypted. The global `0x14326b258` is referenced ~50 places; it is a
   shared sentinel/singleton, not lobby-specific.

## 38h. Rules that still apply

Never patch or hook code encrypted on disk (`0x141aab4a0`, `0x141abc6c0`, `0x140ac4090`, `0x140ab02a0`,
`0x140acc950`, and now confirmed the lockers `0x141a2ce20` / `0x141a31940` / `0x141a2e250` /
`0x141a48820`) — read those from `gametext.bin` only. `0x140ab6300` IS clean. No whole-memory sweeps;
never set `AOE2LAN_UIW=1` or `rules_scan()`. Default stage-8 hooks stay 4, 5, 13; id 14 only via
`AOE2LAN_HOOKS=4,5,13,14`. Do not edit `lanhub/**`, `linux/**`, `notes/linux-*.md`. Edit the game-dir
tree (`D:\Age of Empires II Definitive Edition\dev\lanhook`), then sync with `sync.cmd`.
