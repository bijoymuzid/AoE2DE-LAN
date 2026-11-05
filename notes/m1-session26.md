# Session-26 (2026-11-05 17:2x–19:5x) — the privilege chain was never the button's problem

Supersedes `notes/m1-session25.md` for state. s25g/s25h (the UI is data) stand and were
confirmed again; s25c's target list is **wrong** and is superseded by 26c below.

Four launches this session, all clean stage 8. No game file, no XAML, no `.text` was
changed. Everything below is measured.

## 26a. Offline gates + rebuild

No `.c` had changed since the s25 build, so the first three runs used it unchanged
(game-dir `dbghelp.dll` crc `e3c0dbc6`). Afterwards the DLL was extended three times;
final build this session: crc **36a55633** (208,384 B). Each build: `hooktest.exe`
**68/68**, `srvtest.exe` + `srvclient.py` **PASS**, 127.0.0.1:443 clear, 11 s wait after
killing `srvtest.exe`. `AoE2DE_s.exe` crc **4f533b6c**, untouched. XAML back to stock
(crc `8398949b`, 35,095 B) — verified after the experiments.

## 26b. Both XAML enable experiments are no-ops (done, do not repeat)

Two clean runs (`mpunlock: off` confirmed from the log first — an earlier run was
accidentally `MPUNLOCK`, so its result was thrown away):

| # | change to `screensimplemainmenu.xaml` | result |
|---|---|---|
| a | `IsEnabled="True"` on `PaphosButtonMultiplayer` + `ButtonMultiplayer` | grey, no help line, click nothing |
| b | (a) + both `TestKey`s changed to unknown values (`Background/MPLanButton`, `Background/MPLanPaphos`) | identical, no crash |

⇒ the attribute is read but code overwrites it; and the disable is **not** a TestKey
lookup, so the manager holds the widget directly. The data seam is exhausted for
*enablement* (it is still good for geometry/help text, as s25 proved).

Also found: `.rdata` holds a hard-coded TestKey table `0x14333af10`–`0x14333b110`
(`Background/ButtonMultiplayer` at `0x14333af28`), consumed only by `0x1419dfa30`
(caller `0x1419e1130`, behind a settings read of `0x1443552b8`), which does
*key → widget → `[widget_vtbl+0x68](widget, 1)`* for ~15 buttons. That is a bulk
**enable**, not the disable, and is where the `+0x68` setter signature comes from.

RTTI names that exist in the exe (useful, unresolved to code): `Age2ButtonPropertyManager::
UpdatePrivilegeMultiplayer(TState&)` / `::UpdatePrivilegeMods`, `widgetuiscreen::
UIScreenMainMenu::CheckMultiPlayerPrivileges()` / `::MultiPlayerPrivilegeConfirmed()`,
`Age2ScreenSimpleMainMenu::ButtonMultiplayerPressed` (`0x1433aa0d8`). `Age2Button` has no
class-name RTTI, so its vtable is not findable by name.

## 26c. The s25 target was wrong — measured, not guessed

Read-only probe (`AOE2LAN_MPSPY=1`, added this session: prints the live object map, no
writes) at t=6/10/20/40 s, identical every time:

```
platform obj (heap)            vtable rva = 0x366b450     <- NOT 0x3669fc0
  slot+0x90..0x158             all member getters: mov rax,[rcx+0x1818] ...
  [plat+0x1818] svc  ptr=...   vtable rva = 0x366f848
     +0xb0 -> 0x5204f0   keyed readiness query (0 = present, 2 = not ready)
     +0xb8 -> 0x5214a0
     +0xc0 -> 0x5203d0
     +0xc8 -> 0x520620
  [plat+0x12f8] usr  ptr=...   vtable rva = 0x3670a10
     +0xb0 -> 0x552440
     +0xb8 -> 0x556d90   "who is signed in" name query (std::string&, bool)
     +0xc0 -> 0x552790
     +0xc8 -> 0x5527b0   HasPrivilege: stock writes {0,1,0} and returns 1
```

All six slot values match the shipped `.rdata` byte-for-byte. The s25 slots
(`0x14366A078/080/088` on vtable `0x143669FC0`) belong to a **different class**
(`XboxPlatform`-side, constructed at `0x1403b26fd`), are not on the privilege path, and
were dropped from the patch.

Chain, re-read from the decrypted dump and confirmed:

```
0x14051a390 HasPlatformPrivilege(priv, out):
   fa70 = platform_user_signed_in():
        svc = [plat]->vtbl[0x98] -> [plat+0x1818]
        if svc->vtbl[0xb0](svc, &key) != 0  -> not signed in      (key: [0x14327ce50], +0x10 = -1)
        usr = [plat]->vtbl[0x150] -> [plat+0x12f8]
        return usr->vtbl[0xb8](usr, &out)
   ; if fa70() -> jump straight to the privilege call
   fc80 = profile_is_ready(): same svc query, then state != 4
   a456: usr = [plat]->vtbl[0x150]; usr->vtbl[0xc8](usr, priv, &out)
         eax==0 -> allowed; else 2 -> "PlatformInterface::HasPrivilege failed."
```

## 26d. Three slots re-pointed on the real tables — and they were not asked the right question

Patch set (in-memory only, `VirtualProtect`, revert = relaunch), `AOE2LAN_MPUNLOCK=1`:

| slot (.rdata) | stock | stub answer |
|---|---|---|
| `0x14366F8F8` svc+0xb0 | `0x1405204F0` | `0` **only** for descriptor `[0x14327ce50, .., -1]`; every other key is forwarded to the saved stock function |
| `0x143670AC8` usr+0xb8 | `0x140556D90` | `1` + a valid empty `std::string` |
| `0x143670AD8` usr+0xc8 | `0x1405527B0` | `0` (allowed) + `{0,1,0}` |

Run (`logs/lanhook-2088.log`): all three patched OK at t=0.079 s, then

```
[t=4.344s] called usr_signed_in      <- usr+0xb8
[t=4.344s] called usr_has_priv       <- usr+0xc8
(never once: svc_query == svc+0xb0)
```

So privilege **was** answered "allowed" — and the button stayed grey, same as always.

Second run with a caller trace (`logs/lanhook-9008.log`, `_AddressOfReturnAddress` + 12
stack words, image VAs only) names the askers:

| stub | caller | identity |
|---|---|---|
| usr+0xb8 | `0x14044e6d5` in func `0x14044e607` | `Worldwide*Service` — the offline-items reader ("Failed to read offline items file") |
| usr+0xc8 | `0x140683e14` in func `0x140683db0` | **`WorldwideLoginAsync::DoUpdateCrossplaySetting`** — its own string: "Error requesting crossplay privilege." |

Decisive negative: `svc+0xb0` — the *first* call `platform_user_signed_in` makes — was
**never called in either run**. Therefore `WorldwideAccountService::HasPlatformPrivilege`
never ran at all, so the multiplayer button does not consult the multiplayer privilege in
this build. The privilege we faked went to the **crossplay** check and the items reader.

⇒ Stop treating privilege as the button's cause. The grey state is pushed onto the widget
by ordinary, unencrypted UI code, and the click handler
(`Age2ScreenSimpleMainMenu::ButtonMultiplayerPressed`) already exists.

## 26e. Named next step (no launch needed)

Make every enable/disable of an `Age2Button` visible. The setter is
`[widget_vtable + 0x68](widget, bool)`, proven by real code at `0x1419dfa30`. Plan:

1. Find the `Age2Button` vtable(s) in `.rdata` — no class-name RTTI, so resolve from code:
   the constructor(s) that store a `.rdata` vtable into a fresh object, plus the `+0x68`
   slot reading/writing an enabled flag. Verify each candidate slot against the shipped
   file (same method that worked in 26c).
2. Re-point `+0x68` with a logging wrapper that calls the stock setter and logs
   `self`, the bool, and 6 return addresses (reuse `spy_callers`).
3. One instrumented run: the log then names the exact moment, value and caller for the
   Multiplayer widget.
4. Only then propose the smallest honest change. If the disable is a state push, the
   answer is to answer that state correctly, not to force the widget.

Watch for: the Multiplayer **screen** may still re-check something and bounce a forced
button (s25d's caveat), so the button is necessary but may not be sufficient.

## 26f. Tooling notes

- `dev/lanhook/aoe2re.py` `xrefs()` is wrong (it indexes int32 slots, but x86
  instructions are not 4-byte aligned — it silently misses real refs). Use
  `dev/lanhook/xr.py` instead: it scans all four alignments (`eff = disp + off0 + 4*i +
  4 + base`), then confirms each candidate by disassembling backwards from the
  instruction end, longest form first (so a REX-prefixed `lea rdx,[rip+..]` is not
  misread as an 8-bit `lea dl,[rip+..]`). Sanity-checked against three known refs.
- RTTI for the interesting classes is **scrubbed**: COLs point into zero-filled `.data`
  and the type descriptors read back as junk ("82901458756096"). Names that survive are
  lambda/`_Func_impl` and plain string names such as
  `UIScreenMainMenu::MultiPlayerPrivilegeConfirmed` (unreferenced statically).
- New env vars: `AOE2LAN_MPSPY=1` (read-only object map), `AOE2LAN_MPUNLOCK=1` (the
  three slots above). Launchers: `PLAY-stage8-LOGIN.cmd` (clean stage 8),
  `PLAY-stage8-SPY.cmd` (stage 8 + map), `PLAY-stage8-MPUNLOCK.cmd` (stage 8 + slots).
- REA MCP is connected but has **no analysis provider configured** (Ghidra:
  `GHIDRA_INSTALL_DIR` unset, Java path unresolved; IDA absent), so its
  `open_binary`/decompile/xref tools are unavailable. Using them needs Ghidra 12.1.x +
  Java installed and the env var set — a machine change for the operator to approve.