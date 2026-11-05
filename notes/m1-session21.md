# Session-21 (2026-11-05, M1) — the login event is NOT on the notification plane; the login reply is

## 21a. Headline
1. **The WS notification plane cannot carry a login event — proven statically, not guessed.**
   The registry the message reader walks (`0x1407a7070`, head `0x144c9e3e0`) is filled at static-init
   by **56** 16-byte node stubs of the shape
   `mov rax,[head]; mov [node+8],rax; lea rax,[node]; mov [head],rax; ret`
   (nodes `0x144116af0 + 0x10k`, 46 of them; a second stub family at `0x140298a20`/`0x140299070`
   fills a *different*, never-read head `0x144c849d8` — dead).
   Each of the 46 wrappers tail-calls a payload parser that first compares `m_type` by length + strcmp
   against **its own** message name:
   `AchievementGrantedMessage, PersonalChatMessage, ChannelChatMessage, ChannelJoinMessage,
   ChannelLeaveMessage, OfflineMessageMessage, MatchHostedMessage, PartyHostUpdatedMessage,
   PlatformSessionUpdateMessage, MatchStartMessage, MatchObserveMessage, MatchReceivedChatMessage,
   SessionStatusMessage, PresenceMessage, Extend/Cancel/ReplyInvitationMessage, Friend{Request,
   Accept,Clear,Reject}Message, IgnoreMessage, GameResultNotificationMessage, Avatar{Update,Deleted,
   StatsUpdated}Message, ItemLocation/ItemInstanceMessage, ExtensionMessage, Automatch{,2}{StartPolling,
   StopPolling,Game,LeaveMatch}Message, Clan{MembershipRequestUpdate,ChangeClan,Chat,MemberUpdate,
   Remove,Update,PermissionsUpdate}Message, OutdatedVersionMessage, ChallengeUpdatedMessage,
   CommunityEventChallengeUpdatedMessage`.
   There is **no standalone "AccountLoginEvent" string anywhere in the binary** (the only occurrence is
   the tail of the log text "Enum changed on the server AccountLoginEvent::Result"). So every s19/s20
   WS candidate was doomed twice over: the envelope grammar *and* the type set.
2. **The login event comes from the login response.** `LoginResult` (`0x140615b70`, all keys readable)
   carries `selectProfile` → `SelectProfileEvent {resultCode, profile}` (`0x140616ed0`; `profile` is a
   `ProfileInfo` via `0x140620540`) and `accountInfo.profiles` → vector of `ProfileInfo`
   (`0x140619210`, element size 0x1c0). Both were `null` through s20. Filled them.
3. **Effect measured in-game (`logs/lanhook-6668.log`, 200 s, clean logout):** the client now runs the
   *whole post-login service sweep* it never ran before — `/game/Leaderboard/getAvailableLeaderboards`,
   `getStatsForLeaderboardByProfileName` ×3, `/game/Achievement/getAvailableAchievements`+`getAchievements`,
   `/game/item/getInventoryByProfileIDs`, `/game/chat/getChatChannels`+`getOfflineMessages`,
   `/game/automatch2/getAutomatchMap`, `/game/account/FindProfilesByPlatformID`,
   `/game/relationship/setPresence`, `/game/CommunityEvent/getAvailableCommunityEvents`. And
   PlayFab `/Client/LoginWithCustomID` now returns **200 OK + SessionTicket** instead of 400
   InvalidParams. So rlink login + profile selection is now genuinely complete.
4. **MP is still grey, and the game's UI says why:** `IDS_MAINMENU_CANT_CONNECT` — the telemetry file
   records the operator's click on `EventButton[Reconnect to Multiplayer Services]`.

## 21b. New oracle: the game's own telemetry on disk (game-side verdicts, zero hooks)
`C:\Users\Bijoy\Games\Age of Empires 2 DE\telemetry\TelemetryEvents{Normal,High}Priority.json` is
**NDJSON, appended even with `RL_TELEMREPORTPCT=0`** (this is where the muted telemetry goes).
`TelemetryEventsNormalPriority.json` carries `ScreenChange` events with `ScreenHistory` (e.g.
`["ScreenSimpleMainMenu","widget:dialogchallengenotification","widget:screenmainmenu"]`) and the
`WPFG:<Widget[Text]>:(button):1` click lines. `HighPriority` carries `PlayerLogin`/`StatusUpdate`/
`PlayerSession*`/`Lifecycle`. This is the only *game-side* (as opposed to rlink-side) log we can read:
the game's own log calls go through `0x14101bb50`, **not** rlink's `LogHelper`, so hooks 4/5/13 cannot
see `AOE2LOG`/`AOEAccountListener` lines. Use telemetry + `logs/lanhook-*.log` together.

## 21c. Static map additions (all in `gametext.bin`, all readable)
| VA | what |
|---|---|
| `0x1407a7220` | top-level notification value: `null` \| container; object member `"messages"` → `0x1407a7d30` (array of messages) |
| `0x1407a7620` | one message: 3 optional slots in fixed order `result`(int32, range-checked via `0x140610780`), `m_type`(string), `m_profileID`(int64) — each may be `null`; then the **mandatory** registry payload; then next member |
| `0x140a7ace` | the registry call; a container with zero members returns before it (`{}` parses) |
| `0x140799300` | `ProcessNotificationMessage` — dispatches ~28 of the 46 types (chat/ad/party/clan/…) |
| `0x140798f30` | `ProcessLongPoll` — same envelope, logs "ProcessLongPoll - failed to parse notification messages" |
| `0x140615b70` | `LoginResult` reader (resultCode, connectionToken, connectionID, serverTime, accountInfo, profiles, banLevel/Seconds/Message, clientSettings, selectProfile, sslCertificates, shouldUseClientSync, relayServers) |
| `0x140616ed0` | `SelectProfileEvent` reader (`resultCode`, `profile`→ProfileInfo) |
| `0x140614060` | `AccountInfo` reader (id, accountName, accountType, ssoID, ssoStatus, country, currency, spamAllowed, metaData, profiles→`0x140619210`) |
| `0x140620540` | `ProfileInfo` reader |
| `0x140611620` | `AccountLoginEvent::Info` reader (result→log "Enum changed…", accountInfo, defaultProfileInfo) — **called from one place only**: the item service's offline UserData reader |
| `0x140593540` | item service "UserData" reader (platformAccountID, profileID, `m_loginEvent.m_info`, inventory/stats/achievements/partyStats/challengeProgress, m_rlinkLibVersion) + its writer at `0x1405944e3`. Persisted as `%lsitem-%s-%s.dat`; **never written in our runs** → the client has no offline login-event cache = it never saw an Info |
| `0x140683db0` | `WorldwideLoginAsync::DoUpdateCrossplaySetting` (privilege 5 via platform vtable `[+0xc8]`, then `[+0xb0]` = local profile; logs "Could not fetch local profile." and *continues*) |
| `0x140684130` | `WorldwideLoginAsync::Process` (logs "Found %zd profiles", "Found profile: %s"; profile vector at job+0x558) |
| `0x140f0f9xx` | **game side** `AOEAccountListener::OnAccountEvent`; switch on `[rsi+0x60]` (event id −3..11); R_Success branch at `0x140f0fcc4` logs `OnAccountEvent/AET_Login/R_Success profileID=%lld` and sets `word [rdi+3]=0x101`; EXTENDED_ERROR branch at `0x140f0fba5` computes `"NON XBOX"` vs `"xbox"` from `[rsi+0x340]==9` and logs `Account info: %s, type=%s` / `Default profile info: %s type=%s alias=%ls sanitised_alias=%ls` |

## 21d. Reading of the current state
rlink: logged in, profile selected, 46 service caches primed, PlayFab OK. UI: "Reconnect to
Multiplayer Services" (`IDS_MAINMENU_CANT_CONNECT`), MP button dead, and the game **never** asks for
`/game/advertisement/*` — so the MP screen is gated *upstream of* the advertisement service.
Two candidates left, both on the **platform/privilege** side, not on rlink login:
- `WorldwideAccountService::HasPlatformPrivilege` (strings `0x143689410`, `0x1436894c0` — no static
  xrefs, so that function is Arxan-encrypted) → `PlatformInterface::HasPrivilege(5)` needs an
  Xbox-Live/XAL user; the game's own PrivilegeManager (`PrivilegeManagerPC`, `0x1432f8xxx`) is what
  shows the "reconnect" button.
- The click-to-MP path may require `ScreenXBLSignIn`/`CanUseXboxLive` to be resolved to "NON XBOX"
  (PLAN §6.1) — telemetry `ScreenHistory` never shows `ScreenXBLSignIn`, so that screen is not what the
  operator sees; the "reconnect" button is.

## 21e. Next (cheapest first)
1. **Use the telemetry oracle** (21b) for every subsequent run: after a launch, diff
   `telemetry/TelemetryEvents*.json` for `ScreenChange`/`WPFG:` lines. Clicking MP must produce a
   `ScreenChange`; its absence localises the gate to the click handler, not the services.
2. **Hook-free check of the privilege answer**: the game asks `HasPlatformPrivilege` through the
   platform interface. Serve the XBL/XAL side locally (`title.mgt.xboxlive.com` endpoint list, XSTS
   token) so the privilege call returns true, or find where the button's enable state is computed from
   RLink (`CanUseXboxLive` string `0x1431cbf20`, widget `Background/ButtonAnchor/XBLSignIn`).
3. **`/game/advertisement/getLanAdvertisements` + `getAdvertisements`** are already implemented shapes
   (s18): once the MP screen opens, answer them and push the LAN lobby list. That is M2 entry.
4. Keep the WS ladder **off** (`AOE2LAN_PUSH=1` re-enables). For M2 the WS *is* the notification
   channel — now with 46 known-good `m_type` names to push (e.g. `SessionStatusMessage`,
   `PartyHostUpdatedMessage`) and the comma-terminated envelope from s20.

## 21f. Tree state
- `dev/lanhook/loginsrv.c`: `emit_accountinfo` emits `profiles:[ProfileInfo]`; `build_login_response`
  emits `selectProfile:{"resultCode":0,"profile":ProfileInfo}`; push ladder gated behind
  `AOE2LAN_PUSH=1` (`g_PushEnable`); `srvclient.py` asserts the two new fields + "no push by default".
- Builds: `hooktest.exe` 68/68, `srvtest.exe` + `python srvclient.py` PASS.
- game-dir `dbghelp.dll` = crc **8fba5c87** (202,752 B). Rollbacks:
  `dev/lanhook/dbghelp.dll.prev-s21-before` = s20 build (`598910b1`, 202,240 B).
  `AoE2DE_s.exe` untouched (`4f533b6c`).
- Last run: `logs/lanhook-6668.log` (200 s, 78 WS frames, 1 client data frame, clean logout, no hang).
