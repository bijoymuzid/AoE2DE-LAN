# Session 36 — real widget enable/visibility flag (`+0x3d8` via `0x140ab6300`) measured; polarity inverted from s32/s35

Supersedes `notes/m1-session35.md`. Everything below is MEASURED in live runs (`logs/lanhook-2536.log`,
`logs/lanhook-8660.log`) or read directly from `gametext.bin` / `AoE2DE_s.exe`. No game file on disk
was touched (`AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688`).

## 36a. Offline gates (all pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS** (all checks green).
- `AoE2DE_s.exe` MD5 **`affb19f03ca96965abf9e56775cab688`** — untouched.
- Staged `dbghelp.dll`: **241,664 B**, MD5 **`5ca2dadf03b0f9951ed0a0dbb61592d6`**, identical in the
  game dir and `dev/lanhook/dbghelp.dll`.

## 36b. Step 2 (`AOE2LAN_RULES=1`) settled without a memory sweep

Scanned the entire decrypted `.text` (`dev/lanhook/gametext.bin`) for `E8 rel32` call sites of the
twin-rule functions:
- `0x141b126f0` (register twin pair): 53 call sites, all in `0x141b87905`..`0x141c912c2` (main menu
  and dialogs).
- `0x141b12a00` (evaluate rules): 8 call sites, all in `0x141bd9cef`..`0x141c8fa8f`.
- `0x141b12d60` (fill statuses): 1 call site (`0x141b12a1f`).

**Zero** calls in the host lobby cluster (`0x141aa0000`..`0x141ad0000`). The host lobby settings rows
are not in the twin-rule table, and running `AOE2LAN_RULES=1` was skipped because `rules_scan()` is a
full-memory sweep like the one that crashed the game in s33.

## 36c. MEASURED (`logs/lanhook-2536.log`): `0x140a74ca0` is NOT called by the UI widgets

Installed hook id 14 on `0x140a74ca0` (s35's candidate `+0xa5` setter, clean on disk) and ran through
login -> Multiplayer -> Host Game -> host lobby (`logs/lanhook-2536.log`, `HostAsync - completed with
HostResult = 0` at `t=45.844s`).

Result: **zero hits** across the entire session. Why: `0x140a74ca0` sits at vtable offset `+0x38` on
only 2 base vtables (`0x1432141d8`, `0x14331e0f8`), while the lobby calls `[vtable+0x68]`.

## 36d. Static + MEASURED (`logs/lanhook-8660.log`): the real widget state setter is `0x140ab6300`

In `0x141aab4a0` (the lobby settings block switch), each `GetWidget` (`0x140ac4090`) result is passed
to `0x142d705a5` = `__RTDynamicCast` (via IAT `0x143198960`), casting from base widget
(`TypeDescriptor` `0x144179368`) to:
- **Checkbox / Button** (`TypeDescriptor` `0x144179618` -> vtable **`0x143219728`**):
  - `[vt+0x60]` = `0x140ab6d20` (encrypted on disk)
  - `[vt+0x68]` = `0x140ab02a0` (encrypted on disk)
  - `[vt+0x78]` = **`0x140ab6300` (CLEAN ON DISK)**
- **DropDown** (`TypeDescriptor` `0x144179788` -> vtable **`0x14321a0a8`**):
  - `[vt+0x68]` = `0x140acc950` (encrypted on disk)
  - `[vt+0x78]` = **`0x140ab6300` (CLEAN ON DISK, shared across 35 widget vtables)**

Disassembly of `[vt+0x68]` (`0x140ab02a0` and `0x140acc950`) and `[vt+0x60]` (`0x140ab6d20`):
- `[vt+0x68](widget, dl, r8b)`: loads `rdx = [rcx+0x3d8]`; if `dl != 0` does `or rdx, 4`; if `dl == 0`
  does `and rdx, ~4`; then calls `[vt+0x78]` = **`0x140ab6300(rcx, rdx)`**!
- `[vt+0x60](widget, dl, r8b)`: loads `rdx = [rcx+0x3d8]`; if `dl != 0` does `and rdx, ~8`; if
  `dl == 0` does `or rdx, 8`; then calls `[vt+0x78]` = **`0x140ab6300(rcx, rdx)`**!
- `0x140ab6300` itself (`48 8b 81 d8 03 00 00 90 48 3b d0 74 12 48 87 91 d8 03 00 00 ...`, 7-byte
  boundary, clean on disk): compares `rdx` with `[rcx+0x3d8]`, swaps it into `[rcx+0x3d8]`, and marks
  `[rcx+0x3e0] = 1` (dirty).

**Measured in `logs/lanhook-8660.log` with hook id 14 on `0x140ab6300`:**
1. Hidden QueueButtons (`ret=0xab6d63` inside `0x140ab6d20` and `ret=0xab02d9` inside `0x140ab02a0`):
   `old=0x1 -> new=0x9` (bit `0x8` set = hidden), then `old=0x9 -> new=0xd` (bit `0x4` set = disabled).
2. Live Options dropdowns and checkboxes (`GameSpeedDropdown`, `DisplayMode`, `Crossplay`, etc., via
   `ret=0xacc989` and `ret=0xab02d9`):
   **`old=0x4 -> new=0x0`**.

**What this settles (and why s32f's contradiction is now resolved):**
- In `[rcx+0x3d8]`, **bit `0x4` = DISABLED (locked)** and **bit `0x8` = HIDDEN**.
- Every dropdown (`vtable 0x14321a0a8`) and checkbox (`vtable 0x143219728`) is constructed with
  `+0x3d8 = 0x4` (**disabled by default**)!
- In `[vt+0x68](widget, dl, r8b)`:
  - **`dl = 0` CLEARS bit `0x4` -> ENABLED (unlocked)!**
  - **`dl = 1` SETS bit `0x4` -> DISABLED (locked)!**
- That resolves s32f's contradiction completely:
  - `0x141aacd03` (inside `0x141aac3d0`) calls `0x141aab4a0(screen, 0)` -> **`0` means UNLOCK the
    settings block** (for non-event-scenario games)!
  - `0x141abe0e5` (inside `UpdateLobbySettings` `0x141abc6c0`) calls
    `0x141aab4a0(screen, IsEventScenario)` -> passes `1` (LOCK) when it is a fixed event scenario, and
    `0` (UNLOCK) otherwise!

## 36e. Why our log in `lanhook-8660.log` stopped before t=45s, and what is staged now

In `lanhook-8660.log`, `QueueButton0..63` and the Options screen widgets fired at `t=7.75s..7.84s`
and filled the 256-line cap before the operator opened the host lobby.

Updated `HK_WSET` in `dev/lanhook/hookcore.c` (built, tested, staged in `dbghelp.dll` MD5
`5ca2dadf03b0f9951ed0a0dbb61592d6`):
- Ignores the first 20 seconds of process uptime (`GetTickCount() - g_t0 < 20000`) so startup screens
  cannot consume the log cap.
- Logs only named widgets where bit `0x4` changes (`((oldf ^ newf) & 4) != 0`) or where a stack frame
  in the lobby range (`0x141aa0000..0x141ad0000`) is on the call stack (`lobby_caller=0x...`).
- Raised the dedupe table and line cap to 512.
- Fixed `AOE2LAN_HOOKS` log printing in `lanhook.c` for 2-digit hook ids (`14:WidgetSetEn` instead of
  `>:WidgetSetEn`).

## 36f. Static finding from `0x141ab1310` / `0x141ab28a0` / `0x141abbc30` (dropdown population)

While inspecting the host lobby functions (`0x141ac7e00` -> `0x141ab28a0` MapSize, `0x141aab0f0`
Difficulty, `0x141abbc30` Resources, `0x141ab6dc0` Population, `0x141ab1310` GameSpeed):
- Each of those functions populates the dropdown's `DropDownListBox` items (`0x140adbb30`), sets the
  selected item (`0x140ace800`), and binds the change callback (`0x1415d5410`), **without calling
  `[vt+0x68]`**.
- So the widgets stay at their initial `+0x3d8` state unless `0x141aab4a0(screen, 0)` (or each widget's
  `[vt+0x68](w, 0, 0)`) runs and clears bit `0x4`, OR something else sets bit `0x4` back to `1`.
- One run with the updated `PLAY-stage8-SETEN.cmd` (after `t=20s`, entering the host lobby) will show
  immediately whether `0x141aab4a0` runs in the host lobby and what `old -> new` flags hit the rows.
