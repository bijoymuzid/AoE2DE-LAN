# Session-27 (2026-11-05 19:1x–21:2x) — the grey-button overlay theory is dead; the widget really is disabled, and .text is encrypted at rest

Supersedes `notes/m1-session26.md` for state. Everything below is measured. Where
something is unknown it says so. No game file and no `.text` byte was changed this
session; the XAML was edited twice and is back to **stock (crc `8398949b`, 35,095 B)**.

## 27a. Offline gates + build

No `.c` had changed at session start, so the first checks used the s26 DLL
(crc `36a55633`). `hooktest.exe` **68/68**, `srvtest.exe` + `srvclient.py` **PASS**,
127.0.0.1:443 clear after an 11 s wait. After the session's rebuild the gates were
re-run: `hooktest.exe` **68/68**, `srvtest`+`srvclient` **PASS**, DLL crc
**`9b8aa96b`** (211,456 B). `AoE2DE_s.exe` crc **`4f533b6c`**, untouched.

`dev/lanhook/build.cmd` now **stages the built DLL into the game directory**
(`copy /y dbghelp.dll ..\..\dbghelp.dll`). This matters: the first instrumented run
of the session silently used the stale s26 DLL because nothing copied it.

New launcher: `PLAY-stage8-UIW.cmd` (stage 8 + `AOE2LAN_UIW=1`).

## 27b. Measured: ~60% of `.text` differs between the on-disk file and the t=70 s dump

`gametext.bin` (decrypted `.text`, VA = `0x140001000` + offset) was compared against
the same region of `AoE2DE_s.exe` (file offset = `va2off(va)`). **31,585,163 of
51,990,528 bytes differ (60.75%)**, uniformly across all of `.text`. The first
difference is at VA `0x140001030`.

⇒ Most of `.text` is **encrypted at rest** and decrypted only in memory. Consequences:

- A disassembler given the *file* is looking at ciphertext for most functions. This
  is why the Ghidra project started this session (import of `AoE2DE_s.exe`) was
  killed as worthless for `.text`. **If Ghidra is wanted, import a copy of the exe
  whose `.text` raw bytes are overwritten with `gametext.bin`** — same headers, same
  VAs, real code.
- Static analysis of the *shipped file* cannot find the Age2Button class, its vtable
  or its constructor. Everything in 27c–27f was read from the decrypted dump instead.
- The existing detour mechanism (`hc_match_now` in `hookcore.c`) installs against the
  **live decrypted** bytes, which is why the s26 LogHelper/LogWarn hooks work at all.

## 27c. `[widget_vtbl + 0x68](widget, bool)` — every call site in the exe, enumerated

Scan of the decrypted dump for the call shape `mov rX,[rY+0x68]; ...; call rX`
(6 ModRM variants, byte-pattern prefilter, each hit re-confirmed by disassembly):
**255 call sites in 101 functions**. For each enclosing function (`.pdata` bounds) all
rip-relative string operands were dumped (`dev/lanhook/unlock68.py`, output kept in
`/tmp/all68.txt` during the session; re-run the script to regenerate).

Findings:

- The **only** call site that touches `Background/ButtonMultiplayer` is `0x1419dfa30`,
  and it passes **1** (enable) for 17 buttons in a row. TestKey `0x14333af28` is
  referenced exactly once in the whole exe — from `0x1419dfa80` in that function.
- With `--arg0` filtering (a nearby `xor edx,edx` / `mov edx,0`), **34 functions**
  remain. All of them are in-game screens: map selection, load game, mod manager,
  lobby host, campaign lists. **None** is the main menu.
- Several of them are the `Age2ButtonPropertyManager::UpdatePrivilege*` family: they
  carry `IDS_PRIVILEGE_DENIED_GENERAL_WARNING` / `IDS_PRIVILEGE_DENIED_UGC_BLOCKED`
  and disable buttons through this slot — consistent with 26d, where the *main menu*
  never asks for a privilege.

⇒ **No code anywhere in the exe calls the widget setter with `0` for the Multiplayer
button.** The grey state is not a `SetEnabled(false)` push.

## 27d. The main-menu screen's own state block never says "disabled" either

The screen (`Age2ScreenSimpleMainMenu`) binds widgets by their **XAML names**, not by
TestKey: `0x141b91160(this, &field, L"ButtonMultiplayer")` at `0x141c900fd` and
`0x141b81c40(this, L"ButtonMultiplayerDisabled")` at `0x141c9010c`, both inside the
generated binder `0x141c8feb0..0x141c91302`. The UTF-16 name table lives at
`0x1433a9d30`–`0x1433a9e50` (plain text in `.rdata`).

The screen keeps a widget-state block at `this+0x2c8` (bytes `+0x2c8..+0x2f0`), built
by `0x141b83e60(state, enabled, group, ..., vector)` and applied by `0x141b33c80`.
Measured:

- `0x141c8bf40` fills it with `dl = 1` at `0x141c8c004` and stores it at
  `0x141c8c836`; **no instruction between ever overwrites byte `[rbp+0x10]`**.
- **All 31 call sites of `0x141b83e60` pass `dl = 1`.** There is no caller that
  passes 0.
- `0x141c8d370(mode)` toggles one byte of that block and is called from exactly one
  place (`0x141c8c8b7`, mode `2`).

⇒ The screen's own state machine always says "enabled". Unknown where the visible
disabled state comes from.

## 27e. The "cannot connect" path does not touch the button

`0x141c8f6a0` is the message builder behind a Multiplayer click when services are
unavailable. It reads:

- `state = 0x141027670(0x141027640())` — a getter pair returning a **global object**
  (`[0x144357640]`, read-only accessors `+0x60` = maintenance state 0..5, `+0x64`,
  `+0x68`, `+0x70`);
- `[0x1442dc4f0] + 0x2e8` = the online service object, `[vtbl + 0xa8]()` returning a
  pointer whose `+0` and `+4` fields are two flags.

It only chooses a string (`IDS_NO_CONNECTION`, `IDS_RELIC_NOT_LOGGED_IN`,
`IDS_MAINTENANCE_IN_PROGRESS`, `IDS_MAINTENANCE_DOWN_DEFAULT`) and shows a box. It
returns a bool; it never touches a widget. Unknown whether those two flag fields are
true in our login state — **not measured**.

## 27f. XAML experiments (both concluded, do not repeat)

1. `Visibility="Collapsed"` on `PaphosButtonMultiplayerDisabled` and
   `ButtonMultiplayerDisabled` ⇒ **the game exits ~3–5 s after start and writes no
   user log at all** (session dir empty, only `Age2SessionData.txt`). The loose XAML
   is therefore parsed **very early** and a rejected attribute is fatal. New fact:
   the parser is real and strict, and it is *not* limited to geometry.
2. Shrinking both grey twins to `Width="1" Height="1"` (attributes already used
   everywhere in the same file) ⇒ **no visible change**: Multiplayer still grey, no
   help line / no tooltip on hover, click still does nothing (operator observation).

⇒ The grey duplicates drawn on top of each enabled button are **not** the cause.
This reconfirms s25 (the enabled twin is the live one) and kills the last data-side
explanation. The enabled widget itself is in a disabled state.

## 27g. Read-only runtime probes added (`AOE2LAN_UIW=1`), and what they found

Two probes in `lanhook.c`, both read-only, SEH-guarded, run at t=60 s from the
heartbeat thread:

1. `ui_widget_probe()` — scans committed private writable memory (5,617 MB scanned in
   practice) for `.rdata` pointers whose `+0x68` slot is `.text` and whose first 32
   bytes contain a `mov [rcx+d], dl` store. **Result: exactly one candidate,
   vtable `+0x33fe100`, whose `+0x68` is `+0x1f40420` = `0f b6 41 45 c3` (a *getter*),
   i.e. a false positive.** The filter is too narrow: the real widget setter's store
   is not in the first 32 bytes.
2. `ui_widget_keyprobe()` — scans the same memory for a qword equal to the image
   address of `"Background/ButtonMultiplayer"` (`+0x333af28`). **Result: one hit, and
   it is not inside a widget object** (no readable vtable at `q-8/-16/-24`; the
   address printed negative because the hit was above the module, not in the heap).
   The widget stores its key as a `std::string` copy, not as a pointer to `.rdata`.

⇒ Neither probe produced the widget or its vtable. **Unknown: the Age2Button vtable,
its enabled-flag offset, and the code that sets it.**

## 27h. Launch reliability (new, unexplained)

Three launches in a row died at ~3 s (log stops right after
`cert: user-Root registered`, before the XAL request to `title.mgt.xboxlive.com`) and
wrote **no** user log; three later launches were clean (login, `Found profile`,
`Adding LAN relay server` at 14 s). The pattern correlated with launching again
immediately after killing the previous instance, but **that correlation is not
proven**; the cause of the early exits is **unknown**. Recovery that worked: wait
~45 s with no game running, then relaunch.

## 27i. Ghidra (installed this session, on the operator's instruction)

- `dev/tools/jdk-25.0.5+8` (Temurin, 141 MB zip) — `java -version` OK.
- `dev/tools/ghidra_12.2_PUBLIC` (569 MB zip, 8,823 files) — `support/analyzeHeadless.bat`
  answers usage; needs `JAVA_HOME` set to the JDK above.
- `dev/ghidra-import.cmd` imports `..\AoE2DE_s.exe` with
  `GHIDRA_HEADLESS_MAXMEM=10G`; project at `dev/ghidra-proj` (16 GB RAM, 6 cores on
  this machine). The import ran 40 min and was **killed on purpose**: it was
  analysing the on-disk ciphertext (27b), so its output would be junk.
- No env var was set for the REA MCP server, and it cannot see this install without a
  restart of the agent host. Do not plan on REA's Ghidra provider; drive
  `analyzeHeadless.bat` directly.

## 27j. Where the next session starts (no guessing)

Facts already excluded as the button's cause: the privilege chain (s26), TestKey
lookups (s26), any `SetEnabled(false)` call site (27c), the screen state block (27d),
the connect-warning path (27e), the grey twin buttons (27f).

The open question is only: **which code, or which state, puts the enabled widget into
the disabled look and blocks the click.** Two honest routes, in order of cost:

1. **A decrypted-binary Ghidra project** (27b): copy `AoE2DE_s.exe`, overwrite
   `.text` raw bytes with `gametext.bin`, import that copy, then decompile
   `0x141c8feb0` (binder), `0x141c8bf40`, `0x141a0xxxx` and the `Age2Button`
   constructor once found. No game file changes; it is a file under `dev/`.
2. **Find the widget at runtime, properly.** The two probes in 27g were too narrow.
   A next probe should scan for the *widget manager map* itself or dump the raw
   screen object; the screen holds the widget at `this+0x2c8`-adjacent fields, and
   the binder's `FindName` result is the widget pointer. Requires one instrumented
   run, i.e. the operator's approval (per the standing rule: any new detour,
   `.rdata` re-point or game-file edit is the operator's call).

Do not re-run: XAML `IsEnabled`/TestKey edits (s26), the privilege slot patch (s26),
the s23/s25 vtable `0x143669fc0` patch, the three XAML experiments of 27f.