# Session-23 (2026-11-05) — first gate found, MP unlock implemented (operator run pending)

Supersedes `notes/m1-session22.md` for state; s22 remains the analysis of the click path.

## 23a. The first gate, named (all offline, this session)

The MP button's enable state is not the s22 click gate. It is the rlink **platform
privilege** chain, and the client's own RTTI/vtable tables name every step:

| Layer | Evidence |
|---|---|
| UI | `Age2ButtonPropertyManager::UpdatePrivilegeMultiplayer(TState&)` + `UpdatePrivilegeMods` (RTTI lambda names at `0x144147760/0x1441477d0`) — a button-property manager that renders a button from a privilege state enum |
| UI screen | `widgetuiscreen::UIScreenMainMenu::CheckMultiPlayerPrivileges()` → `MultiPlayerPrivilegeConfirmed()` (RTTI at `0x14413ecf0/0x14413ed60`) |
| Privilege manager | `UserPrivilegeManagerPC` code lives at `0x14175e…`–`0x14176c…`; at `0x14176c6a0` it asks the account service for the privilege, stores the int at `[this+0x28c]`, then calls `0x141772c30` (the change-notify that feeds the button property manager) |
| Account service | `WorldwideAccountService::HasPlatformPrivilege` = **`0x14051a390`** (vtable slot 0x2b8 of the object at `[0x144c9e5f0]`), sibling `HasPrivilege` = `0x14051a340` (slot 0x2b0) |
| Platform object | `[[0x144c9e5f0]+0x150]` → rlink `XboxPlatform`; `0x14051a390` reads **vtable slot 0xb8** ("user signed in") first and only then **slot 0xc8** ("HasPrivilege") |

`0x14051a390` disassembly (decrypted dump): `call 0x14051fa70` (that helper calls platform
`[vtable+0xb8]`) → if false, `call 0x14051fc80` (profile readiness) → then logs
`"WorldwideAccountService::HasPlatformPrivilege: Not currently logged into the platform."` and
returns **2** (denied). With a profile selected but no XAL user session we hit exactly that
branch — which is why run-2's only platform error was `PlatformSetPresenceAsync: No user session.`
and why no privilege ever reaches `UpdatePrivilegeMultiplayer`.

**XboxPlatform vtable = `0x143669FC0`** (found by scanning `.rdata` for the 107-slot run whose
entries all point into rlink's `XboxPlatform.cpp` code `0x1403b4–0x1403c2`; its own slots are
self-consistent, e.g. slot 0xb8 `0x1403ba0f0` calls slot 0xa8 and tests the result == 1).

| vtable slot | VA | function |
|---|---|---|
| 0xa8 | `0x14366a068` | `0x1403b5c40` — user-state int (`[self+0x158]`, 0 while no XAL user) |
| 0xb8 | `0x14366a078` | `0x1403ba0f0` — "user signed in" (state == 1) |
| 0xc0 | `0x14366a080` | `0x1403b7200` — `HasPrivilege` → bool |
| 0xc8 | `0x14366a088` | `0x1403b7270` — privilege state → 0 = allowed |

## 23b. Decision taken: (b), narrowed to a `.rdata` vtable re-point

Option (a) (fake XAL) and the naive form of (b) (patch the enable check in `.text`) were both
checked first, and both got cheaper/worse from it:

- **`0x14051a390` is ENCRYPTED on disk** (`disk 55 ad 12 d2 …` vs dump `48 89 5c 24 08 …`). Same
  class of function the repo already proved deadly: an E9 detour there is the Arxan tamper
  response (clean exit ~5.6 s, see `lanhook.c` hook-def comments). Patching the enable check in
  `.text` is therefore *not* the cheap move it looked like.
- XAL stays expensive: the client reaches `title.mgt.xboxlive.com/titles/default/endpoints?type=1`
  (t=3.45 s, our only XAL request) and XAL's own NSAL strings
  (`0x1433db9d0`…`0x1433dd1a8`: `title.mgt/device.auth/user.auth/xsts.auth/sisu`, "Endpoints
  conflict", `%s/titles/default/endpoints?type=1`, `/device/authenticate`, `/user/authenticate`,
  `/xsts/authorize`, `ProofOfPossession`, `RpsTicket`) show it will *allow-list* whatever hosts we
  serve — so it is tractable, but it is a multi-session protocol build with unknown JWT checks.

So the chosen move is the smallest thing that makes the privilege chain answer yes **without
touching a single byte of game code**: re-point three slots of `0x143669FC0` (plain `.rdata`, never
encrypted) at our own stubs in `dbghelp.dll`.

- in-memory only; nothing on disk changes, `AoE2DE_s.exe` crc stays `4f533b6c`
- restored by the next normal launch (no persistence, no uninstall step)
- opt-in per launch: `AOE2LAN_MPUNLOCK=1` (stage 8 otherwise unchanged)
- the three slots are verified against their stock values (`0x1403ba0f0/0x1403b7200/0x1403b7270`)
  before writing, and re-read + logged after; a mismatch skips that slot instead of writing
- `AOE2LAN_STAGE=8` alone still behaves exactly as in s22

What it can and cannot buy: it makes `HasPlatformPrivilege` return "allowed", i.e. the button and
the privilege dialogs. It does **not** create an XBL user, so `PlatformSetPresenceAsync` and any
Party/PlayFab identity still have no session — those only matter after the MP screen opens.

## 23c. Implemented this session

- `dev/lanhook/lanhook.c`: `mp_unlock()` + `pv_signed_in` / `pv_has_priv` / `pv_priv_state` stubs,
  `getenv_flag()`, call site after the install loop; logs `mpunlock: patched … OK` per slot.
- `PLAY-stage8-MPUNLOCK.cmd` (new): stage 8 + `AOE2LAN_MPUNLOCK=1`.
- Offline validation re-run after the change: `hooktest.exe` 68/68, `srvtest.exe` + `srvclient.py`
  PASS, no listener left on `127.0.0.1:443`.
- Game-dir `dbghelp.dll` = **crc `47c92917`, 203,776 B** (new). Rollback of the s22 binary:
  `dev/lanhook/dbghelp.dll.prev-s23-before` (crc `8fba5c87`). `AoE2DE_s.exe` untouched
  (`4f533b6c`).

## 23d. Open questions the operator's run answers (one run)

1. Does the button become live with the three platform slots re-pointed? (`mpunlock: patched … OK`
   ×3 in the log, then a clickable Multiplayer.)
2. Tooltip / Tab focus — which XAML twin was live before the patch. Report what the tooltip said
   and where the Tab ring went (that is the check s22 asked for; it is free in this run).
3. If the MP screen opens: the next gate is M2 (`/game/advertisement/getLanAdvertisements` +
   `getAdvertisements`, LAN region) — the client already registers our LAN relay.
4. If it stays grey: the enable decision is not the account-service privilege path, and the next
   targets are `Age2ButtonPropertyManager::UpdatePrivilegeMultiplayer` and `CanUseXboxLive`
   (getter `0x14084c260`, registered as a WPF-bindable property at `0x14084d95c`).

Run: double-click `PLAY-stage8-MPUNLOCK.cmd`, sit ~50 s, hover Multiplayer (read the tooltip), Tab
once, click Multiplayer once, wait ~10 s, quit.

## 23e. Operator run (2026-11-05 15:23–15:27, three launches) — the patch NEVER applied

| log | life | outcome |
|---|---|---|
| `lanhook-3956.log` | 2.6 s | died before the menu |
| `lanhook-17532.log` | 5.0 s | died before the menu |
| `lanhook-14624.log` | 195 s | **full run**: login ok, menu reached, click did nothing, clean quit (`Lifecycle FinishedViaExit`) |

All three logged exactly this at t≈0.08 s:

```
mpunlock: slot mismatch, skipped slot 0xb8 user-signed-in
mpunlock: slot mismatch, skipped slot 0xc0 HasPrivilege
mpunlock: slot mismatch, skipped slot 0xc8 privilege state
```

**Cause: the guard was right and my arithmetic was wrong.** `AoE2DE_s.exe` is DYNAMICBASE +
HIGHENTROPYVA and loads at `game base=0x00007ff65cf10000`, so every pointer inside its `.rdata`
is relocated with the image. I compared the slot against the *static* `0x1403ba0f0/0x1403b7200/
0x1403b7270` instead of `base + those RVAs`, so all three checks failed and nothing was written.
Fixed in `mp_unlock()`: compare `(*slot - g_Base)` against the RVA, and log `found rva=` on a
mismatch so this can never be silent again. Rebuilt, hooktest 68/68, srvtest PASS, installed
(game-dir `dbghelp.dll` crc **c3df124a**, 203,776 B). The 15:2x run therefore says **nothing**
about the privilege hypothesis — the experiment did not happen.

**The two early deaths are not the patch** (it wrote nothing). They are the pre-menu cert-store
path: each launch mints a fresh self-signed root and adds it to the user Root store (`purged
stale roots=1` then `user-Root registered`), which is the known-fragile step from s21 (44 stale
same-DN roots once killed the client inside its cert-store build). Third launch, same env, 195 s.

**What the run did settle (operator observations, worth keeping):**

- Tab cycles through every menu button, so the Multiplayer widget is *focusable*.
- Every focused button shows its help line bottom-right **except Multiplayer, which showed
  nothing**. In this UI the help line is the button's `HelpLocale` tooltip, and WPF suppresses a
  disabled control's tooltip unless `ToolTipService.ShowOnDisabled` is set. In this XAML only the
  *enabled* twin (`ButtonMultiplayer`, `HelpLocale=99203` "Play with or against human players.")
  has `ShowOnDisabled="True"`; the greyed twin (`ButtonMultiplayerDisabled`, `HelpLocale=IDS_XBOX_
  SIGNIN_POPUP_MESSAGE`) does not. ⇒ the widget that takes focus is **disabled** (a disabled
  widget raises no click, which is exactly the s22 symptom). It is not a hidden working button.
- `PlatformSetPresenceAsync::Process: No user session.` appears **twice** in the 195 s run, at
  t=28.6 s and t=38.6 s — i.e. the presence path retries around the time the operator interacts.
  The platform layer still has no XBL user, exactly as modelled in 23a.
- Nothing else regressed: `/game/login/platformlogin` at t=3.7 s, full service sweep, `/wss/` up,
  normal exit.

## 23f. Next (session 24)

1. Re-run `PLAY-stage8-MPUNLOCK.cmd` and require `mpunlock: patched … OK` ×3 in the log *before*
   interpreting anything. If a slot still mismatches, read the logged `found rva=` and re-derive
   the vtable (do not guess a second time).
2. If the button becomes live → gate settled as privilege; go to M2 (`getLanAdvertisements` +
   `getAdvertisements`, LAN region) and point `relayServers[]` at `BattleServer\BattleServer.exe`.
3. If it stays grey/disabled with the three slots patched, privilege is not the widget's input and
   the next named targets are `Age2ButtonPropertyManager::UpdatePrivilegeMultiplayer` and the
   `CanUseXboxLive` bindable property (getter `0x14084c260`, registered at `0x14084d95c`).
4. Cert flakiness: two launches in three died pre-menu in the root-store step. If that repeats,
   purge *all* same-DN roots before adding, and consider only registering the root once per boot
   instead of per launch.