# Session-24 (2026-11-05 16:0x) — the unlock ran, the button is still dead ⇒ privilege is not the widget's input

Supersedes `notes/m1-session23.md` for state. §23a–23d (the gate map, the vtable facts) stand;
§23e's "the patch never applied" is now **closed**: it applied, three times, and changed nothing.

## 24a. The experiment happened (three launches, all patched)

Operator ran `PLAY-stage8-MPUNLOCK.cmd` three times: two died pre-menu, the third ran to a clean
`FinishedViaExit` (Lifecycle `StageStr=FinishedViaExit`, `1Uv6KK61p…`, 355 s).

| log | life | mpunlock |
|---|---|---|
| `lanhook-2296.log` | died ~2.3 s (last line = our `cert: user-Root registered`) | **3/3 patched OK** |
| `lanhook-17404.log` | died ~2.2 s (same last line) | **3/3 patched OK** |
| `lanhook-15420.log` | 355 s, full run, clean exit | **3/3 patched OK** |

```
[t=0.063s] mpunlock: patched slot 0xb8 user-signed-in OK
[t=0.063s] mpunlock: patched slot 0xc0 HasPrivilege OK
[t=0.063s] mpunlock: patched slot 0xc8 privilege state OK
[t=0.063s] mpunlock: platform vtable re-pointed (in-memory only)
```

Pre-run check that this was going to work, done against the shipped file (not the dump):
`.rdata` slots `0x14366a078/0x14366a080/0x14366a088` = `0x1403ba0f0/0x1403b7200/0x1403b7270`,
rvA `0x3ba0f0/0x3b7200/0x3b7270` — MATCH. So no arithmetic excuse this time.

**Result in the live run:** hovered Multiplayer → **bottom-right help line still blank**, Tab → focus
reaches it, click → nothing. Telemetry agrees: the only `ScreenChange` records for that session are
the three at menu load (`widget:screenmainmenu` + a `dialogchallengenotification`), all with
`InputHistory: []`; no screen or dialog after them. Same symptom as s22/s23, now with the platform
privilege vtable provably re-pointed.

⇒ **Hypothesis (b) from 23a is falsified at the widget level**: `HasPlatformPrivilege` answering
"allowed" does not enable the Multiplayer widget. Either the widget's enable state never goes through
that vtable, or it does and something else overrides it. The instrumentation in 24e settles which.

Correction to 23e: the two `PlatformSetPresenceAsync::Process: No user session.` warnings are at
t=28.1 s and t=38.1 s — exactly 10 s apart, and the same 28/38 pattern appeared in the 195 s s23 run.
It is a **periodic 10 s retry**, not a reaction to the operator interacting. (Also
`GetXboxRelationshipsAsync::OnStart: No user session.` at t=4.06 s.)

## 24b. What "disabled" actually is, now nailed down (UI layer, all on disk)

The UI is not XAML-driven off `widgetui/*.json`; the JSON is only the dispatch/tab layer and the real
WPF files are **shipped loose and readable** in the game dir:

- `widgetui/screenmainmenu.json` — `Collection.Name = "ScreenMainMenu"`, `TabOrder` names
  `Background/ButtonMultiplayer`, and `Widgets` = exactly one `Base` (background). Nothing about
  enablement. ⇒ tab/focus routing comes from this JSON, which is why Tab still reaches the button.
- `resources\_common\wpfg\screen\screensimplemainmenu.xaml` — the actual screen. Every XboxLive-gated
  button exists **twice, at the same position, in the same `Grid`**:

| twin | HelpLocale | `ToolTipService.ShowOnDisabled` | Foreground |
|---|---|---|---|
| `ButtonMultiplayer` `TestKey=Background/ButtonMultiplayer` | `99203` ("Play with or against human players.") | **True** | normal |
| `ButtonMultiplayerDisabled` `TestKey=Background/ButtonMultiplayerDisabled` | `IDS_XBOX_SIGNIN_POPUP_MESSAGE` | absent | `button_player_icon_disable` |

  Same pattern for `ButtonSingleplayer{,Disabled}`, `ButtonLearnDialog{,Disabled}`,
  `ButtonCoop{,Disabled}`, and the `Paphos*` (variant) twins. So the operator's observation —
  focusable but **no** bottom-right help line — identifies the live widget as
  **`ButtonMultiplayerDisabled`**, and the code-behind picks the twin by setting Visibility.

This is exactly `Age2ButtonPropertyManager::UpdatePrivilegeMultiplayer`'s job name: render *one* of a
primitive's state twins. Our privilege patch fed the wrong input to it, or fed nothing.

## 24c. Fallback targets measured this session (both hostile — do not detour)

| target | on-disk bytes | verdict |
|---|---|---|
| `CanUseXboxLive` getter `0x14084c260` | `7e e2 65 c7 43 b5 95 a7 …` vs dump `48 89 5c 24 08 57 48 83 ec 20 …` | **encrypted** |
| its property registration `0x14084d95c` | `31 5e 30 52 44 92 47 13 …` vs dump `48 8d 15 bd e5 97 02 …` | **encrypted** |
| `Age2ButtonPropertyManager` RTTI lambdas `0x144147760/0x1441477d0` | type descriptors (`.?AV<lambda_1>/<lambda_2>@…UpdatePrivilegeMultiplayer…`), not code | n/a |

An E9 detour at either of the first two is the Arxan response, same as `0x14051a390`.

New static leads, both cheap:

- The string `PaphosButtonMultiplayer` **is** in the exe `.rdata` at `0x1433aa182` (also
  `0x144153373`, `0x1441d90da`), while `ButtonMultiplayerDisabled` is **not** in the exe at all — so
  the code-behind names the *enabled* twin only (`…Disabled` is XAML/`TestKey`-only). Whatever reads
  `0x1433aa182` is the code-behind twin switch. It is referenced through a `.rdata` pointer table, not
  a rip-relative immediate (`rr.py` finds no direct ref) — resolve that table next, then check the
  function for clean-on-disk bytes before proposing any detour.
- `CanUseXboxLive` literals at `0x1431cbf20`; `ButtonSignInOut` at `0x14333b36b`.

## 24d. Offline gates / binary state (unchanged, all green)

`hooktest.exe` 68/68 · `srvtest.exe` + `dev/lanhook/srvclient.py` PASS (TLS1.2, 14-key login JSON,
wss 101, keepalive, ping/pong, close) · no listener on `127.0.0.1:443` · game-dir `dbghelp.dll` crc
**c3df124a**, 203,776 B · `AoE2DE_s.exe` crc **4f533b6c**. No rebuild was needed or done.

## 24e. Next: instrument before patching anything else (one run, no new patch surface)

Three of the questions above are answered by logging we already have the code for:

1. **Do the stubs fire at all?** Add a one-shot `log_line("mpunlock: called <name>")` inside
   `pv_signed_in` / `pv_has_priv` / `pv_priv_state`. If they never fire, the privilege chain is not on
   the widget's path (and probably not on the click path either) — stop patching it.
2. **Does something revert the slots?** Re-read all three from the existing heartbeat thread
   (1 s) and log once per change. Distinguishes "never consulted" from "consulted then overwritten"
   (some engines re-init platform vtables; Arxan would also show here).
3. **Is the loose XAML even loaded?** XAML-only test, zero risk: change the disabled twin's
   `HelpLocale="IDS_XBOX_SIGNIN_POPUP_MESSAGE"` to `99203` in
   `resources\_common\wpfg\screen\screensimplemainmenu.xaml`. If the bottom-right line starts showing
   the multiplayer help text, loose XAML is live and the whole UI layer is patchable without touching
   encrypted code. Revert after.

Item 3 is a **game-file edit** (`resources\_common\wpfg\…`) — operator's call, one string, revert by
value. Items 1–2 are additions to `dbghelp.dll` and touch no game byte.

If stubs do fire and the button stays dead, the enable input is `Age2ButtonPropertyManager`'s state,
and the next move is the `.rdata` pointer table behind `0x1433aa182` — a vtable/table re-point in the
proven-safe style (verify stock RVA, log `OK`, in-memory only), never a `.text` detour.

## 24f. Cert flakiness: mechanism now visible, not fixed

The two early deaths end **immediately after our own `cert: user-Root registered`** (t≈2.2–2.3 s), and
the previous line in both is the game logging `WindowsCertificates: Adding certificate; subject=/CN=
pb-live-release6-api.worldsedgelink.com/O=AoE2LAN` at t≈1.0 s. In the 355 s run the same code appears
and it survives. Our `RootRegThread` purges the *previous* launch's same-DN root and adds the new one;
the game is enumerating that store at the same time in a fast retry loop. Leading hypothesis: **we
delete a cert out from under the game's cert-store build**. `purge_aoe2lan_roots()` already deletes all
same-DN roots (not just one), so "purge more thoroughly" is not the fix. Candidate fixes for later, in
order of size: (a) persist the cert/key across launches (`cert.der` is already on disk) so there is
nothing stale to purge, (b) move the purge+add before the game's first store read (DLL load, inline),
(c) leave it — an occasional relaunch is cheaper than either. Do not "fix" this blind.