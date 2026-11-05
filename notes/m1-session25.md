# Session-25 (2026-11-05 16:1x–16:3x) — the privilege chain IS consulted, once, at login, and dies one level deeper

Supersedes `notes/m1-session24.md` for state. §24a–24c (the measured negation of the vtable
re-point as *the* answer) stand; §24c's reading of `0x1433aa182` is corrected in 25e.

This session did instrument-only work, as planned: two additions to `dbghelp.dll`, one operator run,
no new detour, no new `.rdata` re-point, no game-file edit.

## 25a. Instrumentation added (all behind `AOE2LAN_MPUNLOCK`, stage 8 otherwise byte-identical)

`dev/lanhook/lanhook.c`:

1. one-shot `mpunlock: called pv_signed_in / pv_has_priv / pv_priv_state` in each stub
   (`InterlockedExchange`, first call only).
2. the three slot descriptors hoisted to `g_MpSlots[]`; `g_MpUnlocked` set only when all three took.
3. `mp_check_slots()` on the existing heartbeat thread — cadence 5 s → 1 s, re-reads the three
   `.rdata` slots under `__try`, logs `mpunlock: slot reverted <slot> now rva=0x…` once per slot.
   Liveness line still every 5 s.

Built + staged. Offline gates: `hooktest.exe` **68/68**, `srvtest.exe` + `srvclient.py` **PASS**,
`127.0.0.1:443` clear. Game-dir `dbghelp.dll` crc **e3c0dbc6**, 204,288 B; previous build kept at
`dev/lanhook/dbghelp.dll.prev-s25-before` (crc `c3df124a`). `AoE2DE_s.exe` untouched (`4f533b6c`).
The DLL also boots clean in a non-game host (`not AoE2DE_s.exe … idle`, no `mpunlock` activity).

## 25b. The run (`logs/lanhook-3316.log`, 157 s, one launch, no early death)

```
[t=0.078s] mpunlock: patched slot 0xb8 user-signed-in OK
[t=0.078s] mpunlock: patched slot 0xc0 HasPrivilege OK
[t=0.078s] mpunlock: patched slot 0xc8 privilege state OK
[t=4.125s] mpunlock: called pv_signed_in          <- exactly once, right after "Found profile: AnkerGames"
(no pv_has_priv, no pv_priv_state, no "slot reverted", for the next 153 s)
```

Operator observation is unchanged: Multiplayer grey, no bottom-right help line, click does nothing.
Telemetry agrees: the session's only three `ScreenChange` records are at menu load
(`ScreenSimpleMainMenu`, `widget:screenmainmenu`, `widget:dialogchallengenotification`), all with
`InputHistory: []`; nothing after. `Adding LAN relay server: 192.168.0.104 GUID 59588bb7-…` at
t=13.8 s. The two `PlatformSetPresenceAsync: No user session.` warnings at t=28.6 / 38.6 s — the
known periodic 10 s retry.

**Both open questions from 24e are now answered:**

| question | answer |
|---|---|
| do the stubs fire? | **yes, one of them.** `pv_signed_in` (vtable slot 0xb8) fires once, at login, at t=4.125 s |
| does anything revert the slots? | **no.** 1 Hz re-read for 157 s logged nothing; the three slots still hold our stubs at exit |

⇒ Not "never asked" and not "asked then reverted". It is **asked once, answered yes, then refused one
level deeper, and never asked again** — so `HasPrivilege`/privilege-state are never reached and the
widget never sees an allowed privilege.

## 25c. Why: the decrypted dump of `HasPlatformPrivilege` (0x14051a390) — s23a's map, corrected

`gametext.bin` at `0x14051a390` (disk bytes encrypted, read from the decrypted dump only):

```
call 0x14051fa70            ; platform_user_signed_in()
test al,al ; jne 0x14051a456
call 0x14051fc80            ; profile_is_ready()
test al,al ; je  0x14051a456
; else: "WorldwideAccountService::HasPlatformPrivilege: Not currently logged into the platform."
mov eax,2 ; (denied)
...
0x14051a456: rcx=[0x144c9e5f0] ; platform = [vtbl+0x150]
             out = {..}; call [platform.vtbl+0xc8](platform, priv, &out)
             eax==0 -> allowed; 1 -> ?; 2 -> "PlatformInterface::HasPrivilege failed."
```

Two corrections to §23a: the slot read **first** is 0xb8 only inside `0x14051fa70`, and the true
`HasPrivilege` call on the platform object is **slot 0xc8 alone** (0xc0 is not on this path).

Both helpers share one query, and that is the surviving gate:

```
svc = [[0x144c9e5f0] + vtbl[0x98]]          ; the rlink service object
fa70:  dst=&[rbp+0x90]; r8 = svc.vtbl[0xb0]; rcx=svc; rdx=&key(0x14327ce50)
       if eax != 0 -> false
       platform = [[0x144c9e5f0]+vtbl[0x150]]; al = platform.vtbl[0xb8](platform, &[rbp+0x90])
fc80:  same svc.vtbl[0xb0] call; if eax != 0 -> false; else compare the returned state field != 4
```

Measured consequence: our 0xb8 stub answered 1 **inside** `0x14051fa70`, and `fa70` still returned
false — because the `svc.vtable[0xb0]` query (the profile/account-readiness answer, keyed by a string)
reports "not ready". Both `fa70` and `fc80` fail on it, `HasPlatformPrivilege` returns 2, and slot
0xc8 is never called. That is why no privilege ever arrives and why the widget stays on the grey twin.

**Named next target (data-side, same proven pattern, not yet touched):** the object returned by
`[[0x144c9e5f0] + vtbl[0x98]]` and its **vtable slot 0xb0**, plus the state field `fc80` compares
against 4. Resolve the object's vtable from RTTI first, verify the stock slot value against the
shipped file, and only then propose a re-point — a `.text` detour is off the table, that whole region
(0x14051a390 / 0x14051fa70 / 0x14051fc80 / 0x1403b5c40 / 0x1403ba0f0) is **encrypted on disk**
(re-verified this session).

Second, and cheaper: because the chain is consulted **exactly once, at login (t≈4.1 s), before the
menu exists**, a correct privilege answer only helps if `Age2ButtonPropertyManager` consumes it at
that moment. The UI layer may well be reachable without any rlink answer at all — see 25d.

## 25d. The cheap decisive experiment on the UI layer (needs the operator's OK)

The screen is `resources\_common\wpfg\screen\screensimplemainmenu.xaml`, loose and readable. Neither
twin declares `Visibility` or `IsEnabled` there — code-behind sets `Visibility` — but the *help line*
is a pure XAML attribute that code-behind never rewrites:

| twin | line | `ToolTipService.ShowOnDisabled` | `HelpLocale` |
|---|---|---|---|
| `PaphosButtonMultiplayer` | 331 | `True` | `99203` |
| `PaphosButtonMultiplayerDisabled` | 339 | **absent** | `IDS_XBOX_SIGNIN_POPUP_MESSAGE` |
| `ButtonMultiplayer` | 394 | `True` | `99203` |
| `ButtonMultiplayerDisabled` | 405 | **absent** | `IDS_XBOX_SIGNIN_POPUP_MESSAGE` |

That asymmetry is exactly the observed symptom (focusable, blank help line), and it does not tell us
which of the two stacks is live (`IsPaphos` picks one at runtime).

Proposed one-attribute test, on **both** disabled multiplayer twins — insert
`ToolTipService.ShowOnDisabled="True"` (matching the enabled twins). Exact insertion points:
line 338/341 region for `PaphosButtonMultiplayerDisabled` (attribute list starts line 340), and the
`ButtonMultiplayerDisabled` attribute block at lines 402–412.

- If the bottom-right line then appears for Multiplayer → **loose XAML is live**: the whole UI layer
  is patchable as data, no code bytes, and the twin can be flipped (`Visibility`/`IsEnabled`) from
  XAML. Revert = delete the two inserted attributes.
- If nothing changes → XAML is baked/precompiled and the UI layer is not a seam; the rlink slot-0xb0
  hunt above is the only road.

Risk to state plainly: even with the button live, `ScreenMultiplayer` may re-check the privilege and
bounce straight back, so the XAML route is necessary-but-possibly-not-sufficient for M1's exit.

## 25e. Correction to §24c — the twin names ARE in the exe, as UTF-16

`ButtonMultiplayerDisabled` is not in the exe **as ASCII**; the helper-name block is UTF-16, which is
why the s24 ASCII scan found nothing. VAs (imagebase `0x140000000`):

| string (UTF-16) | VA |
|---|---|
| `ButtonMultiplayerDisabled` | `0x1433a9d58` |
| `PaphosButtonMultiplayer` | `0x1433a9d90` |
| `PaphosButtonMultiplayerDisabled` | `0x1433a9dc0` |
| `ButtonMultiplayer` | `0x14338a180` |

They sit in a contiguous helper-name block next to the ASCII class-name strings
`Age2ScreenSimpleMainMenu::ButtonMultiplayerPressed` / `::PaphosButtonMultiplayerPressed`
(`0x1433aa182` is the **class** name `PaphosButtonMultiplayerPressed`, not a twin slot — s24 read it
as the enable path). Any future scan for UI element names must test UTF-16 as well as ASCII.

## 25f. State of the binaries / next

- Game-dir `dbghelp.dll` crc **e3c0dbc6**, 204,288 B; revert = `dev/lanhook/dbghelp.dll.prev-s25-before`
  (crc `c3df124a`, the s23 build).
- `AoE2DE_s.exe` crc **4f533b6c**, unmodified. `resources\_common\wpfg\…` unmodified.
- Do **not** re-run the three-slot patch as if it were the answer, and do not extend it with a fourth
  slot without resolving the slot-0xb0 object's vtable from the shipped file first.