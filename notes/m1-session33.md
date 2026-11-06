# Session-33 — my memory scanner crashed the game; the flag is still unmeasured

Supersedes `notes/m1-session32.md` for state. Everything below is MEASURED unless the line says
INFERRED or UNKNOWN. No game file, no `.text` byte, no XAML was changed. **No shipped-code change
this session**: `dev/lanhook/lanhook.c` ends the session byte-for-byte as it started in s32, and
`loginsrv.c` / `srvclient.py` were not touched.

## 33a. Offline gates (re-run at session end, all pass)

- `hooktest.exe` **68/68** (`game-image iat walk: swapped 68 of 68`).
- `srvtest.exe` + `srvclient.py` **PASS** (seven checks).
- `AoE2DE_s.exe` MD5 **`affb19f03ca96965abf9e56775cab688`** — untouched.
- Staged `dbghelp.dll`: **240,128 B**, MD5 **`0baf925b3351fd56a94b8af8b38316cf`**. Compared against
  `D:\dbghelp-session32-latest.dll` it differs in **exactly 6 bytes** — `0x110..0x112` (PE
  TimeDateStamp) and `0x2def4..0x2def6` (debug timestamp). So the s32 code state is intact.

## 33b. MEASURED, and the reason to stop sweeping memory: it crashes the game

Four separate probe builds were tried this session (all read-only, all env-gated, all in
`lanhook.c`). The last one crashed the game.

`logs/lanhook-3132.log` — the operator was in a Skirmish lobby, then clicked create lobby:

| t | event |
|---|---|
| 280.781 | last probe tick that finished (`t=60 … matched=6`) |
| 305.781 | `hb alive sec=85` — **the last heartbeat line ever written** |
| 373.625 | `/game/advertisement/host` answered, `HostAsync - completed with HostResult = 0` |
| 373.781 | `Publishing Visible match`, hosting fully succeeded |
| 19:55:43 | log ends. Windows Event 1000 at 19:55:45. |

Windows' own record: *faulting application `AoE2DE_s.exe`*, **faulting module `KERNELBASE.dll`**,
**exception `0x40010006`** (= `DBG_PRINTEXCEPTION_C`, a debug-print/`OutputDebugString` exception,
not a memory fault), offset `0xc187a`.

Isolation: the operator relaunched with `PLAY-stage8-LOGIN.cmd` (no `AOE2LAN_WP`), created a lobby,
**no crash, panel exactly as before**. So the crash came from the probe, not from hosting.

The heartbeat dying ~68 s *before* the reported crash is the part that is still UNKNOWN: the sweep
runs on the heartbeat thread inside `wpo_scan`, and the tick-90 sweep (which starts around t=311)
never returned. An 8-byte-stride sweep of ~5.6 GB of committed memory with a guarded read per qword,
running while the game is loading a lobby, is the only new thing in the process.

**Rule for next session: do not walk the whole address space of this game again.** It is slow
(minutes, not seconds), and with the sweep in the process the game died during lobby creation. Only
read addresses you were given by a pointer you already trust.

The probe and `PLAY-stage8-WP.cmd` were deleted after the isolation run; a rebuild is byte-identical
to s32 in code (33a). Because the probe was gated on `AOE2LAN_WP`, a normal launch was never at risk —
that was confirmed by the isolation run itself.

## 33c. MEASURED (static, useful): how a widget is named and found

`GetWidget` **`0x140ac4090`** does, in order: strip a leading `//`; read the screen's widget vector at
`[screen+0x58]`..`[screen+0x60]`; for each 8-byte element `e`, call **`0x140ab0780(*e, path)`**. That
comparator builds a `std::string` from the path, takes the tail after the last `/`, and compares it
against a `std::string` **inside the widget object at `+0x3e8`** (MSVC layout: `{union{char buf[16];
char *p}; size_t size at +0x10; size_t cap at +0x18}`).

So: (1) the widget name is a *string inside the object*, not a pointer to `.rdata`, which is why
scanning for the `.rdata` path pointer found nothing in s32i; (2) matching is on the **last path
component**, so `GetWidget(..., "Background/Data/GameSettings/Data/ResourcesDropDown")` and a call
with a different prefix ending in `ResourcesDropDown` are the same lookup.

Widget path names in the live process are full paths, e.g. measured this session:
`Background/Data/GameSettings/Data/{GameDropDown, MapSizeDropDown, ResourcesDropDown,
PopulationDropDown}` and `Background/Data/AdvancedAndTeamSettings/{LockTeams, LockSpeed,
TeamTogether, AllowCheats, TeamPosition, TurboMode, SharedExploration, AllTechs}` — all confirmed
present in the Skirmish lobby.

## 33d. MEASURED (static): s32f's "vtable+0x68 = SetEnabled" is class-specific, not universal

This matters because the s32f argument leaned on it.

- Class at vtable **`0x1433fe100`** (the class with 24…62 instances on every screen measured):
  `[vtable+0x68]` = **`0x141f40420`** = `movzx eax, byte ptr [rcx+0x45]; ret` — a **getter**. The
  setter is the next function, `0x141f40430` = `mov byte ptr [rcx+0x46], dl; ret`. Both are
  byte-identical on disk and in the live dump.
- **`0x140a74cf0`** = `mov byte ptr [rcx+0xa5], dl; ret` and **`0x140a74ca0`** = same store plus a
  side effect when `dl != 0`. Both are **clean on disk** (`40 53 48 83 ec 20 88 91 a5 00 00 00 …`),
  i.e. hookable under the project rule.
- `0x141aab4a0`, `0x141abc6c0`, `0x140ac4090` are all **encrypted on disk** (disk bytes differ from
  the runtime dump at their prologues). They stay unhookable.

So "the flag handed to `[vtable+0x68]`" is a different function per class. The Ready-button
measurement in s32f (edx=1 at `0x141a40a99`, button pressable) does **not** transfer to the dropdown
and checkbox classes. **Polarity for the settings block is therefore still UNKNOWN**, and s32f's
contradiction is not resolved.

One more static observation from `0x141aab4a0`: at its end it takes an 8-byte field of a settings
struct (`0x140fa3cd0` keyed by the flag), then for the last two widgets passes
`(byte [rsp+0x30] == 0)` — the **inverse**. A function that both forwards a bool and inverts a
struct field for two of its targets is at least as likely to be "apply a settings preset" as
"enable/disable". INFERRED, not measured.

## 33e. What the row-definition tables look like (found, not usable for this question)

The sweeps did find, by exact path, arrays of 0x20-byte records of the form
`{q0 = 0x2f or 0x3f, q1 = pointer to the name text, q2 = 0, q3 = name length}` — one record per
settings row, e.g. `MapSizeDropDown 0x3f`, `GameDropDown 0x2f`, `ResourcesDropDown 0x2f`,
`PopulationDropDown 0x2f`, `LockTeams 0x3f`. Those words are **widget-type flags, not enable state**:
in the Skirmish lobby, where every one of those rows is live and editable, the values already differ
row to row. Do not read `0x2f/0x3f` as on/off.

## 33f. OPEN — the next measurement (needs the operator's approval)

Two clean-on-disk setters are available (`0x140a74cf0`, `0x140a74ca0`). A read-only logging detour on
both would answer, in one run:

1. which flag values actually reach a widget's enable field (the store offset is visible in the
   function itself: `+0xa5`);
2. which caller passed them (`ctx[19]` = the original return address, so `0x141aacd03` vs
   `0x141abe0e5` vs something else);
3. whether the host lobby ever receives an "enable" call at all.

That is a new detour, so it is the operator's call, and it needs exact bytes plus a revert story (the
revert is: rebuild with the hook removed; ids 4, 5, 13 stay the only installed ones). It replaces
memory sweeping entirely.

The static alternative, for free: finish tracing **who sets `rbx`** in `0x141abc6c0` before the
`test rbx,rbx` at `0x141abe0d1`. s32f flagged it UNKNOWN. If that object is a refcounted lobby /
settings object that our shim never populates, the guarded call at `0x141abe0e5` is skipped and the
panel keeps whatever state it was created with — which would make this a shim gap, not a patch.

## 33g. Unchanged / still open from s32

- LAN hosting works end to end; measured again this session (`HostAsync - completed with HostResult =
  0`, `Created Matchinfo for sessionID 1193990974`).
- The settings panel in the host lobby is still locked: only Location (map) and Map Size work.
- Relay still answers `relayIP 127.0.0.1`; cross-machine join untested (W1-c).
- `matchTypeID` still `-1` in our update reply; the party plane still answers `[0,[]]`.