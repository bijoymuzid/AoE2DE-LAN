# Session-19 (2026-11-04/05, M1) — first AccountLoginEvent push: received, not dispatched

## 19a. Headline
One supervised run, `logs/lanhook-3292.log`, 105 s, clean logout at 97.3 s (`/game/login/logout`),
no WER/hang. New: the client's WS login frame is now known byte-for-byte, and **six server-pushed
AccountLoginEvent variants were all received and logged by the client** — but none reached the
AccountLoginEvent parser (no `Enum changed…`, no `Account info:`, no `AET_Login/R_Success`).
So the transport works, the *envelope or the name* is wrong. That is the whole open question now.

## 19b. What the client actually sends (fact, replaces the s18 guess)
```
[t=4.969s] WS: frame op=2 len=66 masked
[t=4.969s] WS TEXT {"clientLibVersion":194,"operation":0,"sessionToken":"1193817848"}
[t=5.047s] WS TEXT {"operation":1,"ackCount":1}                 <- 28 B ack, only twice in the run
```
Key order is alphabetical, binary frame, one JSON object per frame. `ackCount` stayed at 1 both
times (5.047 s after push #1, 15.172 s after push #2); pushes #3–#6 got no ack at all. `null` ack
semantics unknown.

## 19c. What we pushed and what came back
`dev/lanhook/loginsrv.c` now has a push pump: once a data frame containing `sessionToken` arrives,
it sends one candidate per 7 s (binary op=2), variants 0–3 with `resultCode:99` (probe) then
variants 0–1 with `resultCode:0`. Payload = `Info{resultCode, accountInfo, defaultProfileInfo}`,
one chunk per push, e.g. variant 0:
`[[0,"AccountLoginEvent",<pid>,{"resultCode":99,"accountInfo":{…},"defaultProfileInfo":{…}}]]`

Every push was accepted by the WS layer and echoed back to us by the client's own log:
```
#115 t=5.047  message="[[0,"AccountLoginEvent",3842241165083521967,{"resultCode":99,…
#117 t=15.172 message="0,"AccountLoginEvent",…                      (variant 1, bare — note leading quote)
#118 t=25.219 message="[[0,"AccountLoginEvent",…,[{"resultCode":99,…  (variant 2, payload list)
#119 t=35.266 message="[[0,"AccountLoginEvent",{"resultCode":99,…   (variant 3, no profileID slot)
#120 t=45.297 message="[[0,"AccountLoginEvent",…,{"resultCode":0,…
#121 t=55.344 message="0,"AccountLoginEvent",…,{"resultCode":0,…
```
`LogHelper` #115/#117–#121 are all the same format string
`WebSocketConnection::ProcessMessages: message=%s` — a *transport-level* echo, not dispatch.
No new format string appeared, i.e. nothing logged an unknown message, and nothing logged an
enum mismatch, so the handler never ran. Also of note: `ret=0x…78144d` is identical for #120/#121,
so the same parse/dispatch loop handled them.

## 19d. Static facts nailed this session (do not re-derive)
- **LoginResult (0x140615b70) has no `defaultProfileInfo`.** Full field set, in parse order:
  `resultCode, connectionToken, connectionID, serverTime, accountInfo, profiles, banLevel,
  banSeconds, banMessage, clientSettings, selectProfile, sslCertificates, shouldUseClientSync,
  relayServers`. (`selectProfile` → `[result+0x160]`, parser 0x140619860, takes a container of
  0x40-byte elements; `sslCertificates` → 0x14039 55c0; `shouldUseClientSync` → 0x14039c730 = the
  only bool reader; `relayServers` → 0x140616ed0.) Confirms M1 cannot be closed from the HTTP reply.
- **`defaultProfileInfo` lives only in `RLink::AccountLoginEvent::Info`**: parser region
  ~0x140611952 keys `resultCode`→`[Info+0x48]` (0x140610780), `accountInfo`→`[+0x50]`
  (0x140614060), `defaultProfileInfo`→`[+0x58]`. String pool for those keys:
  0x143691fe0–0x1436921f8 (`accountInfo, friends, defaultProfileInfo, accountName,
  privacySettings, ssoStatus, ssoID, chatBlockedProfiles, platformFriends, enableCrossplay, clanID,
  webSocketPort, rawSocketPort, connectionToken, outOfBandSocketPort, profiles, spamAllowed,
  publicIP, regionLocalized, clientSettings, banMessage, sslCertificates, selectProfile, serverTime,
  connectionID, banSeconds, banLevel, relationships, profile, relayServers, shouldUseClientSync`).
  No `lea` xref to any of these keys or to the AET_Login log strings exists in `gametext.bin`
  (checked with `re.finditer(rb'\x48\x8d[\x05\x0d…]')` + rel32 decode) → the dispatcher that calls
  this parser is inside the Arxan region: unhookable, unanalyzable. **Nothing in this area can be
  read statically any further; it must be proven at runtime.**
- **RLink wire message class set (47, from `_Ref_count@U…@RLink@@` RTTI)** — the complete list in
  this build: AchievementGranted, Automatch2Game/LeaveMatch/Polling/StopPolling, AutomatchGame,
  AutomatchStartPolling, AutomatchStopPolling, AvatarDeleted, AvatarStatsUpdated, AvatarUpdate,
  CancelInvitation, ChallengeUpdated, ChannelChat, ChannelJoin, ChannelLeave, ClanChangeClan,
  ClanChat, ClanMemberUpdate, ClanMembershipRequestUpdate, ClanPermissionsUpdate, ClanRemove,
  ClanUpdate, CommunityEventChallengeUpdated, ExtendInvitation, Extension, FriendAccept,
  FriendClear, FriendReject, FriendRequest, GameResultNotification, Ignore, ItemInstance,
  ItemLocation, MatchHosted, MatchObserve, MatchReceivedChat, MatchStart, OfflineMessage,
  OutdatedVersion, PartyHostUpdated, PersonalChat, PlatformSessionUpdate, Presence,
  ReplyInvitation, SessionStatus (+`Packet`). **No account/login Message class exists** → the login
  event really is an *event* on the stream, not a `*Message`, so its wire name is not in this set.
- `AET_Login` log strings sit at 0x143285e28–0x143286038 (`Account info: %s, type=%s`,
  `Default profile info: %s type=%s alias=%ls sanitised_alias=%ls`,
  `OnAccountEvent/AET_Login/R_Success profileID=%lld`, plus `xbox` / `NON XBOX`).

## 19e. Run timeline (what the MP click did, again)
`platformlogin` 4.4 s → WS 101 4.8 s → items/challenges/cloud/setLanguage/news 5.3–15.3 s →
PlayFab `/Client/LoginWithCustomID` **first attempt t=14.1 s, before any click** (so it is a
consequence of rlink login completing, i.e. PlayFab Party init), retries 16.6/20.6/28.6/44.6/76.6 s →
`/game/login/logout` 97.3 s. **Still zero `/game/advertisement/*` requests.** The click produced no
new rlink traffic, only another PlayFab attempt (76.6 s) — the MP gate is XAL/PlayFab, not rlink
advertisement.

## 19f. Next (cheapest first, all in ONE run)
The WS layer accepts our frames and logs them, so the remaining unknowns are (a) the server→client
WS *operation* envelope and (b) the event *name*. Prove which with a control:
1. **Control**: push `[[0,"ChallengeUpdatedMessage",<pid>,{}]]` (a name that definitely exists as a
   Message class). If it dispatches (any new log/eﬀect), the envelope is right and only the *name*
   is wrong → sweep names. If it is silent too, the envelope is wrong.
2. **Envelope candidates** (same body, `resultCode:99` probe): `1,[[[0,…]]]` (readSession's literal
   `"<ackNum>,[<chunks>]"` string — the WS may carry the same text), `{"operation":2,"messages":
   [[0,…]]}`, `{"messages":[[0,…]]}`, and a chunk whose 4th element is `[info]` (variant 2 shape)
   with an explicit `"ack":1`.
3. If nothing dispatches, the fallback is the **name sweep** with the proven-received chunk shape:
   `AccountLoginEvent`, `AccountLoginMessage`, `LoginResult`, `LoginEvent`,
   `AccountLoginResult`, `AccountUpdatedMessage`, `ProfileUpdatedMessage` — 12 pushes at 5 s fit in
   a 70 s sitting, and the probe `resultCode:99` makes a hit unmistakable
   (`Enum changed on the server <Name>::Result`).
4. Only after AET_Login fires: PlayFab/XAL suppression (owners of the remaining MP gate) and then
   M2 (relay advert = the game's own BattleServer spawn: `.rlink` string
   `\BattleServer\BattleServer.exe -simulationPeriod 125`, and `Adding LAN relay server` names this
   machine's LAN IP).

## 19g. Tree state / artifacts
- `dev/lanhook/loginsrv.c`: `mk_ids()` + `emit_accountinfo()` + `emit_profileinfo()` (shared by the
  login reply and the event builder), `build_account_event(b, alias, rc, variant)` with
  `N_EVENT_VARIANTS 4`, `strstr_n()` bounded search, `g_Alias` (set on platformlogin), and the push
  pump inside `ws_serve()` (`pushAt`/`pushed`, starts only on a frame containing `sessionToken`,
  one push per 7 s, 6 total).
- `dev/lanhook/srvclient.py`: sends the real binary login frame, asserts the first push is a
  well-formed `AccountLoginEvent` chunk with `resultCode:99` and matching ids, and skips op=2 pushes
  while waiting for pong/close.
- Builds: `build.cmd` clean (only the pre-existing C4090 warnings), `hooktest.exe` **68/68**,
  `srvtest.exe` + `srvclient.py` **PASS**.
- Staged game-dir `dbghelp.dll` = crc **c6793b01** (198,144 B). Rollback
  `dev/lanhook/dbghelp.dll.prev-s19-before` = crc `c1610785` (s18 build). `AoE2DE_s.exe` untouched.
- Launcher unchanged: `PLAY-stage8-LOGIN.cmd` (AOE2LAN_STAGE=8). Ritual unchanged: hooktest 68/68 →
  srvtest+srvclient PASS → no LISTEN on 127.0.0.1:443 → launch.