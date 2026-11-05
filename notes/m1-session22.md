# Session-22 (2026-11-05) — the MP button is disabled at the *widget* level, not by the click handler

Supersedes `notes/m1-session21.md` (which remains the full state of the login work).

## 22a. The measurement that settled it (run 2, `logs/lanhook-16204.log`, 199 s)

The operator hovered and clicked Multiplayer on a *working* login. Result: **nothing at all**, and the
telemetry oracle recorded **no click event**.

- `telemetry/TelemetryEventsNormalPriority.json`, 2026.11.05 13:30:52–13:31:22:
  `RelicCloudFileRequested` ×2, `CloudUsageStatus`, then exactly three `ScreenChange` lines —
  `["widget:screenmainmenu"]` → `["widget:dialogchallengenotification","widget:screenmainmenu"]` →
  `["ScreenSimpleMainMenu","widget:dialogchallengenotification","widget:screenmainmenu"]` — all with
  `InputHistory: []`.
- The only telemetry record of `dialogconnectivityloss` + `WPFG:<EventButton[Reconnect to Multiplayer
  Services]>:(button):1` is from **2026.11.02 17:18**, i.e. *before* login worked. The s21 claim that
  the click was recorded in our run was wrong; it was that old line.
- Run-2 log is otherwise a clean repeat of s21: `/game/login/platformlogin` at t=3.7, 1 profile found,
  `/wss/` up, full service sweep (leaderboards ×4, achievements, items, challenges, chat, automatch,
  cloud, account/FindProfilesByPlatformID, relationship/setPresence+getPresenceData, news,
  CommunityEvent), `PlatformSetPresenceAsync::Process: No user session.` at t=10.4 (the *only* XBL
  error left), `Adding LAN relay server: 192.168.0.104, GUID …` at t=13.5, clean logout at t=198.

**Conclusion:** a disabled WPF button never raises a click, so the gate is the MP button's *enable /
visibility* state, decided when the main menu screen refreshes — **not** the click path. The function
buried in s21 (`HandleMultiplayerServiceUnavailable`) only runs *after* a click gets through, so it is
the second gate, not the first.

## 22b. Static facts found this session (all offline, `gametext.bin` + `.rdata`)

| Item | Where |
|---|---|
| `ButtonMultiplayerPressed` handler calls `HandleMultiplayerServiceUnavailable` | `0x141c8f6a0`–`0x141c8fa50` = the "unavailable?" function; two std::function invokers at `0x141c8e440`/`0x141c8e890` (`call f; test al,al; jne tail` → if "unavailable" the click is swallowed, else the MP screen opens) |
| Its inputs | `[[0x1442dc4f0]+0x2E8]->vtable[0xa8]()` returns `{int32 result; byte connected; byte loggedIn}`; plus `f(0x141027640/0x141027670)` = int compared against 2/3 (maintenance) |
| Message it picks | `!connected` → `IDS_NO_CONNECTION` ("Please check your internet connection"); `!loggedIn` → `IDS_RELIC_NOT_LOGGED_IN` ("Cannot connect to Multiplayer Services."); `result∈{2,3}` → `IDS_MAINTENANCE_IN_PROGRESS`/`_DOWN_DEFAULT`; text is set on `DialogConnectivityLoss/Background/Message`, whose buttons are `ButtonRetry` (text `IDS_MAINMENU_CANT_CONNECT` = "Reconnect to Multiplayer Services") and `ButtonCancel` |
| Grey button | `resources/_common/wpfg/screen/screensimplemainmenu.xaml` has `ButtonMultiplayer` and `ButtonMultiplayerDisabled` in the same Grid; the disabled twin's tooltip is `IDS_XBOX_SIGNIN_POPUP_MESSAGE` = "Please sign into Xbox Network to continue." (`IDS_PRIVILEGE_DENIED_MULTIPLAYER_BLOCKED` is the *other* blocked text) |
| UI reflection names | `IsXbox`, `IsSteam`, `CanUseXboxLive` are adjacent strings at `0x1431cbf00` — a UI-bindable property block, not a log string; `CanUseXboxLive` has **no** rip-relative xref (bound by name at runtime), so it cannot be traced statically |
| Command-line args (full table at `0x143284200`–`0x143284530`) | only `DISABLE_RL_UPDATE`, `SERVER_TIME_OFFSET`, `FORCE_TEST_SERVERS`, `FORCE_LIVE_SERVERS`, `FORCE_LAN_WINDOW`, `DEBUG_BAN`, `OVERRIDE_MP_VERSION`, `TEST_RL_ACCOUNT`, `IGNORE_MP_VERSION`, `PURGE_MOD_STATUS_FILE`, plus `EDGELINK_SERVER`/`EDGELINK_LOGLEVEL` at `0x14328ac00`. **No offline/LAN/skip-login switch exists.** |
| Account-type enum | `Enum changed on the server AccountType` (`0x14369269b`); `AOEAccountListener::OnAccountEvent` EXTENDED_ERROR branch prints `"xbox"` vs `"NON XBOX"` from `[event+0x340]==9`, so 9 = Xbox account type, we serve 3 (correct, non-Xbox) |
| Xbox platform object | rlink's own `XboxPlatform.cpp` (`0x1436900..`), `XblInitialize`, `XalInitialize`, `GetUserLicenseToken`, `/game/msstore/getStoreTokens`, `PlatformPresenceCache` — the XAL layer is statically linked and fully instrumented by our `libHttpClient`/`WinHttp` hooks |
| Offline dead ends | vtable[0xa8] candidate scan over all 2982 RTTI classes yields exactly one unrelated class (`Microsoft::Applications::Events::ContextFieldsProvider`) → the rlink classes carry no COL and `0x1442dc4f0` is written by Arxan-protected init (no static store site found), so the state pair cannot be named offline |

## 22c. Reading of the state

1. rlink login/profile/services/PlayFab/WS/relay-registration: **done** and reproducible twice.
2. The MP button stays disabled. The only platform-side error left in the whole log is
   `PlatformSetPresenceAsync::Process: No user session.` → **there is no Xbox-Live user session.**
   `xboxservices.config` exists (TitleId 2064168993), `XblInitialize` runs at t≈3.6 but no XSTS/XUser
   sign-in ever completes, so `CanUseXboxLive`/`HasPlatformPrivilege(MULTIPLAYER)` cannot be true and
   the XAML's grey twin stays up.
3. Therefore M1's last mile is *not* more rlink work. It is one of:
   - **(a) fake the XAL side** so `Xbl/Xal` produces a user: redirect `title.mgt.xboxlive.com`,
     `*.auth.xboxlive.com`, `*.xsts.auth.xboxlive.com`, `*.xboxlive.com` to our TLS server and answer
     the title-endpoint list, `XblDeviceToken`/SISU (`/device/auth`), `XSTS /xsts/auth` with a JWT
     carrying the needed `prv` privilege claims. Highest payoff (unlocks privilege *and* the Party/
     PlayFab identity), highest cost.
   - **(b) neuter the enable check**: the decision is game code (`Age2ScreenSimpleMainMenu` +
     `PrivilegeManagerPC`), so it needs a **runtime** detour/patch in decrypted-in-memory `.text`
     (never on-disk; `gametext.bin` proves the bytes at `0x141c8f6a0` are plain). Cheapest, but it is
     exactly the "hook game code" move the rules currently forbid — a decision the operator must make.

## 22d. Next (cheapest first)

1. **One more oracle run, zero code change**: the *tooltip* of the grey button distinguishes the two
   XAML twins and is visible on hover. If the operator hovers and reads the tooltip we learn which
   widget is live ("Please sign into Xbox Network to continue." = disabled twin). Combine with
   `INPUT` on `Background/ButtonMultiplayerDisabled` in `widgetui/screenmainmenu.json`'s TabOrder to
   confirm which twin takes focus.
2. Then pick (a) or (b) in 22c explicitly, with the operator's call on the game-code hook rule.
3. M2 is unchanged and independent of the gate: `/game/advertisement/getLanAdvertisements` +
   `getAdvertisements` with a `LAN` region lobby (shape already in `dev/lanhook/loginsrv.c` s18), and
   point the login reply's `relayServers[]` at `BattleServer\BattleServer.exe`. Note the run-2 log
   already shows the client registering our relay for LAN: `Adding LAN relay server: 192.168.0.104`.

## 22e. Tree state

- Game-dir `dbghelp.dll` = crc **8fba5c87** (202,752 B), unchanged this session. Rollback
  `dev/lanhook/dbghelp.dll.prev-s21-before` (crc `598910b1`). `AoE2DE_s.exe` untouched (`4f533b6c`).
- Offline validation re-run this session: `hooktest.exe` 68/68, `srvtest.exe` + `srvclient.py` PASS,
  stale `127.0.0.1:443` listener killed before the run.
- Logs: `logs/lanhook-16204.log` (run 2, 199 s) is the reference run for a *working login with a dead
  MP button*.