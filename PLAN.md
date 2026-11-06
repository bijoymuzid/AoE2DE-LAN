# PLAN.md — AoE2LAN: LAN/Tailscale multiplayer for a cracked AoE2:DE

**Status:** M0 ~done (M0.1 + M0.3 + M0.4 closed; M0.2 half-answered — remaining half
blocked on M1). Phase M1 (Identity / LoginShim) is mid-flight.
**How to use this file in a new chat:** read §0 → §1 → §2, then start at M1 below
(§9 milestone table + "M1 entry state"), then notes/m0-findings.md §10a–10e.
Everything a fresh assistant needs to continue without redoing the analysis
is here. **Start at notes/m1-session29.md (current state; supersedes everything older)**, then
notes/m1-session28.md (the twin-rule cause chain), then
notes/m1-session21.md (the login reply that made the client login), then §9 milestone table +
"M1 entry state" below, then notes/m0-findings.md §10a–10e.

---

## 0. Mission

Make **LAN-style multiplayer work in a cracked AoE2:DE** (RUNE `steam_emu`, AppID 813780) whose
Multiplayer button is greyed out, so that the operator and friends on the same **Tailscale tailnet**
can play **co-op vs AI** first, then PvP, on **Windows and Linux/Proton**.

Not a netcode project. The engine already has LAN multiplayer; only the login/lobby plane is dead.

**Success (v1):** two machines on one tailnet — one Windows, one Linux via Proton — launch from our
launcher, click Multiplayer, see a `[LAN]` lobby with 2 human + 6 AI slots, play a full skirmish to a
victory screen without a desync, over the tailnet's direct path, with the game's own files untouched.

**Non-goals for v1:** matchmaking, ranked, clans, cloud saves, achievements, mod subscription,
spectators, drop-in-rejoin, NAT traversal code (Tailscale owns that), anti-cheat.

---

## 1. Ground truth about this installation

Path: `D:\Age of Empires II Definitive Edition`

| Item | Value |
|---|---|
| Game exe | `AoE2DE_s.exe` — 72,176,952 B, PE32+ x64, MSVC, 8 sections, imagebase `0x140000000` |
| Packed? | **No.** Import table intact; `.text` entropy 7.68 (normal for a 52 MB MSVC blob) |
| Crack | RUNE `steam_emu`: `steam_api64.dll` + `winmm.dll` proxy; `steam_emu.ini` → `AppId=813780`, `LobbyEnabled=1`, `LobbyPort=31183`, `steamclient64.dll` in `Steam\` |
| Emulator data root | `%SystemDrive%\Users\Public\Documents\Steam\RUNE\813780` |
| Game data root | `<Documents>\Games\Age of Empires 2 DE\<userrelicid>\{profile, mods\{subscribed,preview}, savegame\multi, resources\_packages, logs, widgetui}` |
| Relay binary | `BattleServer\BattleServer.exe` — 3,216,696 B, OpenSSL + WinSock + websocketpp |
| Server-side schema present | `Schema\eCellCategory_services.bond` — **telemetry only**, NOT the rlink service schema |
| CA bundle on disk | `certificates\cacert.pem` |
| Symbol situation | No PDB, but **all** internal log strings, RTTI names and source paths survive (`F:\Agents\PhoenixBuilder-07\p4\portland_group\...`) — every subsystem is identifiable |
| Aux files | `xboxservices.config` (TitleId 2064168993, SCID `...7b08b821`, ClientId `0000000040225237`), `libHttpClient.Win32.dll`, `PartyWin.dll`, `webclient\winlive-webclient.exe`, `client.dat` |

**Imports of `AoE2DE_s.exe` (load-bearing ones):** `steam_api64.dll`, `PartyWin.dll` (PlayFab Party,
59 imports), `libHttpClient.Win32.dll` (72), `WS2_32`/`WSOCK32`, `WINHTTP`/`WININET`, `bcrypt`/`CRYPT32`,
`d3d11`/`dxgi`, `dbghelp`, `D3DCOMPILER_47`, `winmm`.

---

## 2. Evidence (why this plan looks like this)

All strings below were extracted from `AoE2DE_s.exe` / `BattleServer.exe` during analysis.

### 2.1 Why the Multiplayer button is grey

The button tracks RelicLink account state, not a "crack flag":

- `IDS_RELIC_NOT_LOGGED_IN "Cannot connect to Multiplayer Services."`
- `IDS_RELIC_LOGGING_IN "Signing into Multiplayer Services"`
- `OnAccountEvent/AET_Login/R_Success profileID=%lld`, `R_PlatformSignInError`, `R_ExtendedError/EE_RLinkServiceUnavailable`
- UI binding `CanUseXboxLive`; widget path `Background/ButtonAnchor/XBLSignIn`; screen `ScreenXBLSignIn`
- `IDS_PRIVILEGE_DENIED_MULTIPLAYER_BLOCKED`, `IDS_MAINMENU_CANT_CONNECT "Reconnect to Multiplayer Services"`

⇒ No successful RelicLink login ⇒ no `defaultProfileInfo` ⇒ no `profileID` ⇒ Multiplayer disabled.
Login is the **only** broken thing.

### 2.2 The engine already contains a LAN mode

- `WorldwideAdvertisementService`: `starting online hosting` / `starting offline hosting` / **`starting LAN hosting`** / `starting local hosting`
- `/game/advertisement/getLanAdvertisements` with `lanServerGuids`; `LANAdvertisementCache`
- `BroadcastListener`, `Adding LAN relay server: %s, GUID %s`, `Failed to find server %s for LAN advertisement`
- Client arg **`-relayBroadcastPort`**, help text: *"Port to broadcast server presence, must also pass same arg/value to client"*
- `AdvertisementCache::LobbyMatch REJECTED NOT LAN`
- UI strings: `IDS_REGION_LAN "LAN"`, `IDS_REGION_LAN_TAG "[LAN] %s"`, `IDS_LOBBY_CREATE_USE_LOCAL_LAN_DROPDOWN_ITEM`, `IDS_FIREWALL_BLOCK_LAN`, `IDS_RELIC_NAT_FAILURE "...joining a LAN game? see https://www.ageofempires.com/support/aoe2/#lan-issues"`

### 2.3 The relay is shipped and self-contained

`BattleServer.exe` banner: `Battleserver %d.%d.%d running on ports %u,%u,%u`
CLI (from its option table): `-name`, `-bsPort` (*"Override the port advertised for incoming
connections"*), `-publicPort`, `-lobbyPort`, `-replayPort`, `-webSocketPort`, `-outOfBandPort`,
`-relayBroadcastPort` (*"Port to broadcast server presence, must also pass same arg/value to
client"*), `-muninReportDelay`.

Protocol message types (strings): `LOBBYCONNECT{titleID, sessionID, secret}`, `LOBBYRELAY`,
`LOBBYPING`, `PROXY{sourcePeerID, destinationPeerIDs}`, `PEERHEADER{flagBits, ackBits, packetNumber,
startACKReliableNonSequential, lastReliableSequentialID}`, `REQUESTJOIN`, `REQUESTJOINDENIED`,
`ADDPEER{peerID, isHost, isLocal, globalID, addressList}`, `REMOVEPEER{peerID, reasonCode}`,
`GAMEDATA`, `DROPOUT`, `INTEGRITYCHECK{proposedHostID, peers, migrateState}`, `STARTOBSERVEREQUEST`,
`ACTIVATEOBSERVER`, `STOPOBSERVE`, `SETOBSERVABLEPARAMATERS`, `LEAVESIMULATION`, checksum channel,
`Session:PeerAccepted: New host for session; hostPeerID=%d`, silence timeouts, DOS guard.

### 2.4 Where the seams are

`TComm_Provider_RL` method names appear in logs, which means the **comm provider is a clean
interface** (this is the seam we use):

`InitProvider` / `CreateChannel(%d)` / `PlatformLogin` / `ReinitProvider` /
`SendP2PPacketRawMemCopy PKT=%d/%s (%u bytes)` / `SendSyncPacketRawMemCopy` /
`SendUnreliablePacketRawMemCopy` / `ReceiveNetworkData` / `ProcessPackets %d pkts` /
`UpdateConnectionState %d -> %d` / `connectToGame host=%lld` / `findOrInitiateP2PConnection` /
`onPacketSendingTicket` / `SetPlayerSlotInfo` / `UpdateSlotsOnProvider` / `SetEnableCrossplay` /
`UpdateBlockedlist` / `rlUpdateLoop` / `UpdateFrame`.

Above it sits the packet/channel model (`CommPacketPlayerCommand`, `CommPacketChat`,
`CommPacketVote`, `CommPacketPreGameNotify`, `CommPacketPreGameHostState`,
`CommPacketPlayfabPartyInfo`, `CommPacketResign`, `CommPacketDropPlayer`, …; channel
`CHECKSUM_CHANNEL_ID`, events `OnMessageEvent/MET_MessageReceived`, `SyncMessageToRelay`).
Below it sits the RelicLink SDK (`Worldwide*Service` over HTTPS + WSS, `BattleServerRelay`,
`PartyWin.dll`).

**Seam ranking**

| Seam | What is swapped | Cost | Notes |
|---|---|---|---|
| **S1** `TComm_Provider_RL` vtable | transport + peer/station model | medium | chosen — tolerates any lobby source |
| **S2** `Worldwide*Service` objects | login/advertisement/stats plane | medium | chosen — needs exact struct layouts (recoverable from RTTI + field-name strings) |
| S3 HTTPS/WSS redirect (`hosts` + CA in `certificates\cacert.pem`) | whole server | high — Bond serialization RE; the `.bond` in this install is telemetry-only | rejected for v1, kept as a fallback |
| S4 UI patch only | button enablement | trivial | insufficient alone |

### 2.5 Service endpoints and env knobs (for reference / fallback)

- Base: `https://www.reliclink.com/`; paths `/game/account/*`, `/game/advertisement/*`,
  `/game/party/*`, `/game/automatch*`, `/game/cloud/*`, `/game/chat/*`, `/game/relationship/*`
- Login response carries: `relayServers[{relayIP, relayPortRaw, relayPortWebSockets,
  relayPortOutOfBandSocket, relayAuthToken, region}]`, `connectionToken`, `rawSocketPort`,
  `webSocketPort`, `outOfBandSocketPort`, `profiles`, `defaultProfileInfo`, `sslCertificates`
- Advertisement fields: `advertisementid, hostid, maxplayers, slotinfo, encodedSlots, matchtype,
  modDllFile, modDLLChecksum, dataChecksum, appBinaryChecksum, passworded, observable, region,
  matchRegion, matchRegionLocalized, relayAuthToken, contract: start/count/desc`
- Args on `AoE2DE_s.exe`: `FORCE_LAN_WINDOW` (*"Force the battle server console to appear"*),
  `IGNORE_MP_VERSION`, `OVERRIDE_MP_VERSION`, `FORCE_TEST_SERVERS`/`FORCE_LIVE_SERVERS`,
  `TEST_RL_ACCOUNT`, `EDGELINK_SERVER`, `SERVER_TIME_OFFSET`, `DISABLE_RL_UPDATE`,
  `PURGE_MOD_STATUS_FILE`
- Env: `RL_TITLEID`, `RL_CLUSTERNAME`, `RL_TELEMSHOULDNTSEND`, `RL_TELEMREPORTPCT`,
  `RL_USE_WEBSOCKET_PERCENT`, `RL_BATTLESERVER_USE_RAW_SOCKETS`, `RL_SSLVERSION`, `RL_KEEPALIVE`

---

## 3. Transport reality: Tailscale (load-bearing)

Tailscale is an L3 WireGuard mesh. **It carries no broadcast or multicast** (open feature requests
tailscale#11134, #1013 — same reason mDNS, SSDP, KDE Connect and Steam discovery break on tailnets).
Consequences, baked into the design rather than discovered in testing:

1. **Never depend on `-relayBroadcastPort` / `SO_BROADCAST`** for anything that must work.
2. **Discovery = unicast gossip** between `lanhub` nodes at tailnet IPs.
3. **`relayServers[].relayIP` = the host machine's tailnet IP**, never `127.0.0.1`.
4. **MTU 1280** on `tailscale0` → clamp `[net] mtu = 1200`. Gameplay is TCP, so MSS/PMTUD copes;
   UDP is only the out-of-band ping.
5. **DERP fallback** (`path=derp`) adds 100–200 ms; acceptable for lockstep; must be *reported*.
6. **ACLs**: default tailnet policy (`*` → `*:*`) already permits it; restrictive policies need an
   explicit rule for 47101/tcp + 47110–47114.
7. **Peer enumeration**: `tailscale status --json` (run by the **native** hub, not inside Wine)
   gives `DNSName` + `TailscaleIPs`; ini seeds are the manual fallback.

---

## 4. Architecture

```
┌────────────────────── one machine ──────────────────────┐
│ aoe2lan-launcher        (native: .exe | .sh)            │
│  ├─ read aoe2lan.ini                                     │
│  ├─ start lanhub        (native on host OS)              │
│  ├─ host? start BattleServer.exe inside game env         │
│  ├─ copy/verify proxy DLL, set env + args                │
│  └─ launch AoE2DE_s.exe                                   │
│                                                          │
│ lanhook.dll  (in-process, injected as dbghelp proxy)     │
│  ├─ H1 LoginShim      account+profile, unblock MP UI     │
│  ├─ H2 LobbyShim      host/join/find/getLanAdvertisements │
│  ├─ H3 ProviderBridge TComm_Provider_RL → LanHub         │
│  └─ H4 TelemetryOff   silence cloud/stats/telemetry      │
│                                                          │
│ BattleServer.exe (stock, unmodified) — relay             │
│                                                          │
│ lanhub (native; loopback:47100 for the game,             │
│         tailnet:47101 for other nodes)                   │
│  ├─ Peers     tailscale status --json + ini seeds        │
│  ├─ Directory ANNOUNCE/ADVERT/WITHDRAW gossip, TTL 3     │
│  ├─ Identity  nickname → stable 64-bit profileID         │
│  └─ RelayCtl  spawn/monitor relay, issue tokens/ports    │
└──────────────────────────────────────────────────────────┘
```

### 4.1 Decisions (do not relitigate without a reason)

| # | Decision | Why |
|---|---|---|
| R1 | One injected DLL, **signature-based**, vtable swap (S1+S2) | fastest to first match; a game patch invalidates signatures, not the design |
| R2 | **Stock `BattleServer.exe`** as relay, unmodified | days saved; stays on the official implementation |
| R3 | Fake login, `profileID = FNV1a64("aoe2lan:" + nickname)` | stable saves/mods per person; no server |
| R4 | Lobby plane = LanHub unicast mesh, JSON/TCP | no broadcast, no HTTP/TLS/Bond RE |
| R5 | `lanhook.dll` loaded as a **`dbghelp.dll` proxy** | no injector, no AV noise, same PE under Proton |
| R6 | Hard checksum equality; `IGNORE_MP_VERSION` never auto-set | desyncs are the #1 way LAN mods die |
| R7 | **v1 = co-op vs AI**; PvP is a free consequence | AI is host-local, zero wire cost, exercises 100 % of the stack |
| R8 | **Transport = Tailscale**, unicast only (see §3) | works today; also on a physical LAN |
| R9 | **Linux tested from M2.5**, not at the end | same PE; only launcher/hub are platform-specific |
| R10 | Never modify `steam_api64.dll`, `winmm.dll`, `AoE2DE_s.exe` on disk | install/uninstall must be additive |

### 4.2 The three planes

- **Identity plane** (H1): everything that makes the game believe it is logged in. Fabricated
  `AccountInfo`, privileges, presence; XBL path forced onto the binary's `"NON XBOX"` branch.
- **Lobby plane** (H2 + lanhub): advertisements, slots, join/leave, party chat. Local only.
- **Transport plane** (H3 + relay): `TComm_Provider_RL` mapped onto the relay at the host's tailnet
  IP. The relay is the engine's own `BattleServer.exe`.

---

## 5. Interfaces

### 5.1 Game-side control protocol (shim ↔ local lanhub, `127.0.0.1:47100`, JSON over TCP)

```
HELLO   {ver, nick, appChecksum, dataChecksum}           → {profileID, sessionToken, ports{}}
HOST    {lobby{name,maxPlayers,map,slots[],passworded}}  → {advertisementID, relayAuthToken, relayIP}
UPDATE  {advertisementID, patch{}}                       → {ok}
FIND    {filters{}}                                      → {advertisements[]}
JOIN    {advertisementID, password?}                     → {slot, peers[], relayIP, relayAuthToken}
LEAVE   {advertisementID}                                → {ok}
PEERS   {advertisementID}                                → {peers[]}      (push subscription)
PING                                                     → {rttMs, nodeName, path}
```

### 5.2 Node gossip protocol (lanhub ↔ lanhub, tailnet IPs, TCP 47101)

```
ANNOUNCE {nodeGUID, nodeName, ver, appChecksum, dataChecksum, ports{}, ttlHops}
ADVERT   {advertisementID, originGUID, lobby{…}, relayIP, relayPorts, ttlHops}
WITHDRAW {advertisementID, originGUID}
PINGNODE → {rttMs, path: direct|derp}
```

Re-flood with `ttlHops-1` to peers that have not seen the id. `ttlHops = 3` covers any realistic
group; ≤8 nodes flood trivially. On `HELLO`, mismatched `dataChecksum` ⇒ that node's lobbies are
hidden and the reason is displayed (never silently ignored).

### 5.3 Ports (all overridable, all bound on `0.0.0.0` unless noted)

| port | proto | use |
|---|---|---|
| 47100 | tcp | lanhub control — **loopback only** |
| 47101 | tcp | lanhub node gossip (tailnet-facing) |
| 47103 | udp | optional L2 broadcast announce (physical LAN only) |
| 47110 | tcp | `BattleServer -bsPort` (raw relay) |
| 47111 | tcp | `-webSocketPort` |
| 47112 | udp | `-outOfBandPort` |
| 47113 | udp | `-relayBroadcastPort` (physical LAN only; unused on a tailnet) |
| 47114 | tcp | `-lobbyPort` |

### 5.4 Config (`aoe2lan.ini`)

```ini
[nickname]  name = Player1              ; → stable profileID
[hub]       mode = auto                 ; auto | host | join
            relayMode = match           ; match (host runs relay) | fixed
            relayHost =                 ; when relayMode = fixed (tailnet name/IP)
            basePort  = 47100
[tailscale] autodiscover = true         ; `tailscale status --json` from the native hub
            peers =                     ; manual seeds: names or 100.x IPs
            prefer  = direct            ; warn when a peer is on derp
[net]       iface =                     ; pin interface on multi-homed hosts
            mtu   = 1200                ; tailscale0 is 1280 — do not exceed
[game]      extraArgs =                 ; appended verbatim
            checksumGuard = strict      ; refuse mismatched peers
[debug]     logLevel = info             ; nothing | hook | proto | full
            sigFile = auto              ; auto = keyed by appBinaryChecksum
```

---

## 6. Component contracts

### 6.1 H1 LoginShim

| rlink call | LAN behaviour |
|---|---|
| `Login` | `R_Success` + synthetic `AccountInfo` (D3/R3), emit `AET_Login/R_Success profileID=…` |
| `SelectProfile` / `DeselectProfile` | synthetic success + `AET_SelectProfile` |
| `GetProfileName`, `SetLanguage`, `setInputDevice`, `setCrossplayEnabled` | synthetic success |
| `HasPlatformPrivilege(MULTIPLAYER)` | `true` (else `IDS_PRIVILEGE_DENIED_MULTIPLAYER_BLOCKED`) |
| XBL sign-in / `CanUseXboxLive` | suppressed; must land on `"NON XBOX"` (`0x3284abc` / `0x3284ac8`) |
| cloud, achievements, stats, leaderboards, relay QoS, chat channels | empty success |
| telemetry | muted (`RL_TELEMSHOULDNTSEND=1`, `RL_TELEMREPORTPCT=0`) |

Exit: Multiplayer enabled offline; `Games\Age of Empires 2 DE\<profileID>\` created once and reused;
no 30 s menu stalls.

### 6.2 H2 LobbyShim

| rlink call | LAN answer |
|---|---|
| `host` | register in lanhub, allocate `sessionID`, return `relayIP` (= this host's tailnet IP) + token |
| `update` / `updateState` / `updateTags` | mutate registry entry |
| `findAdvertisements`, `getAdvertisements`, `getLanAdvertisements`, `findObservableAdvertisements` | filtered registry snapshot, region `LAN` |
| `join`, `leave`, `startObserving`, `stopObserving` | slot reservation + peer list update |
| `party/*` (pregame chat, invites) | answered locally |
| notifications | replay as `AET_GetAdvertisements` / `AET_HostNotification` |

**AI slots:** pass `encodedSlots` / `SlotInfo` through **byte-for-byte**; never normalise them
away. Round-trip AI difficulty, `SlotCount`, `SlotsFilled`, victory settings.

### 6.3 H3 ProviderBridge

Map provider concepts onto the relay: `channel` → relay channel, `station` ↔ `peerID`,
`SendSyncPacketRawMemCopy` / `SendUnreliablePacketRawMemCopy` / `SendP2PPacketRawMemCopy` →
`GAMEDATA` frames, `connectToGame(host)` → relay connect with the issued token,
`SetPlayerSlotInfo` ← advertisement slots, `UpdateConnectionState` from relay events,
`onPacketSendingTicket` ← `ADDPEER`.

### 6.4 Relay

Use stock `BattleServer.exe`. If it turns out to validate `LOBBYCONNECT.secret` (unknown), pick from
the M0 decision tree (§10.2). Fallback `lanrelay` implements exactly the message set in §2.3:
accept N TCP peers, assign peerIDs, frame/forward, per-peer reliable-sequential + ack bitfield, host
election on `INTEGRITYCHECK`, checksum-channel forwarding. ~2–3k LOC, ground truth = a captured
stock session.

---

## 7. Flows

**Host:** launcher → lanhub `HELLO` → spawn `BattleServer.exe -name <nick> -bsPort 47110
-webSocketPort 47111 -outOfBandPort 47112 -lobbyPort 47114` → game launches → H1 login with
`relayServers[] = {relayIP = <this machine's tailnet IP>, ports, token, region "LAN"}` → Multiplayer
→ Create Game → H2 registers (`serviceType=LAN`) → lanhub `ADVERT` floods → pregame chat local →
Start → all peers connect to `<host tailnet IP>:47110` → lockstep over relay.

**Browse/Join:** client launcher → `HELLO` → lanhub already holds peer `ADVERT`s → Multiplayer →
browser region `LAN` → H2 `FIND` → join → slot reserved → provider connects to advertised tailnet IP
→ pregame → start. **No broadcast at any point.**

**Drop / migration:** relay silence timeout removes the peer → `INTEGRITYCHECK` elects a new host →
lanhub marks the lobby migrated. Save/restore uses the engine's own `Restore Multiplayer Game`.

**Mismatch:** `HELLO` compares `appChecksum`/`dataChecksum`; mismatch ⇒ lobbies hidden + reason shown.

---

## 8. Platform matrix

### Windows
- Injection: launcher copies `lanhook.dll` into the game dir **as `dbghelp.dll`** (1 import, crash
  reporting only) with a full forwarder `.def`. No remote-thread injection. Do **not** touch
  `winmm.dll` or `steam_api64.dll` (RUNE owns those).
- Firewall: allow the helper exes; `IDS_FIREWALL_BLOCK_LAN` is the in-game symptom of a block.
- Defender/EDR: proxy DLL + launcher only; no packer, no RWX stubs beyond the hook trampolines.

### Linux (Proton)
- Everything inside one Proton prefix (`STEAM_COMPAT_DATA_PATH` / `WINEPREFIX` shared) so
  `127.0.0.1` and the `Documents` mapping are shared between game, relay and launcher.
- Same PE DLL via `dbghelp` proxy; override Wine's builtin with `WINEDLLOVERRIDES="dbghelp=n"`.
- `lanhub-linux` runs **natively** (needs `tailscale status --json` and the real `tailscale0`); the
  shim inside the prefix reaches it at `127.0.0.1:47100` (Wine shares host loopback).
- ufw: 47101/tcp + 47110–47114. Multi-homed hosts: pin `[net] iface`.
- Paths: keep lowercase-safe; never change the case of `savegame\multi\`.

---

## 9. Milestones

### M0 — Proof (2–4 days, no product code)

| # | Task | Method | Exit | Status |
|---|---|---|---|---|
| M0.1 | Get stock `BattleServer` to relay a session we created ourselves | two script clients, hand-crafted `LOBBYCONNECT` + `REQUESTJOIN` over websocket | both peers relay `GAMEDATA` | **DONE locally 2026-11-02** (full-duplex GD via type-0x0A funnels; tailnet rerun is a repeat) |
| M0.2 | **Can LAN hosting start from login-provided `relayServers` alone, with NO broadcast-discovered relay?** | logging hook only; two tailnet machines | `starting LAN hosting` appears; lobby addressed at a tailnet IP; both peers relay | half-answered 2026-11-02: broadcast-discovered relay accepted pre-login (args captured, no login); rlink login yields 0 profiles → no relayServers; MP click escalates to XAL sisu browser sign-in → M1 precedes the two-machine run (logging build ready: stage 6 = 2 clean log-helper detours) |
| M0.3 | Are `TComm_Provider_RL` + `Worldwide*Service` singletons swappable at runtime? | RTTI scan → vtable dump → install a no-op vtable | game still boots and plays single-player | **DONE 2026-11-02**: runtime hit proof in the live game (log-helper detour chain executes + returns cleanly); supervised stage-4 skirmish stable; Arxan rule: only never-encrypted fns are E9-patchable (encrypted-region patch = clean exit ~5.6 s) |
| M0.4 | Capture a stock relay session as ground truth | packet capture of a single-player-turned-local session or a synthetic pair | `notes/relay-capture.txt` + pcap | **DONE 2026-11-02**: `notes/relay-capture.txt` (synthetic 2-peer session, frame-level annotated); pcap not needed (ws payloads bare) |

M0.1 detail (2026-11-01, session 3 — authoritative, supersedes earlier probes):
the JOIN path is REQUESTJOIN (0x02) nested in PEERHEADER (0x0F); first REQUESTJOIN
creates the session server-side, host admits with ADDPEER (0x06), then GAMEDATA (0x09)
relays. Integers are LITTLE-ENDIAN on the wire. Secrets are lookup keys, never
checked. Exact builders in `notes/bs_client.py` (`join`, `admit` subcommands),
call chain + decompiles in `notes/bs_peerjoin.c`, session log in `notes/m0-findings.md`
("Session-3 headline"). No secret/token, DB, or lobby service is needed — the decision
tree §10.2 branch A ("pre-seed token") is obsolete.

Deliverables: `notes/m0-findings.md` (done), `notes/relay-capture.txt` (**done** 2026-11-02),
`sigs/<appBinaryChecksum>.json` draft (needs game-side vtable addrs, still open).

### M1 — Identity (in progress — read notes/m1-session12.md for session-12 state first)

Status vs the entry text below: the session-11 "IAT hooks can't see it" mystery
is SOLVED (game imports WSOCK32 BY ORDINAL; all 6 slots now hook — offline walk
68/68), the trust seam is CONFIRMED (engine merges Windows Root store into its
OpenSSL pool; H1 injects our in-memory cert at enum end), and the hosts file
still redirects the rlink family to dead 192.168.0.103 (redirect to 127.0.0.1 + 
local TLS login server serving the ageLANServer-proven envelope). Remaining before
the first stage-8 game run: the two items in m1-session12.md §12f (SNI check + 
EncryptMessage secbuffer check), then srvtest+srvclient PASS offline.

Entry target (3-5 days): H1 + H4.
H1 + H4. Hook the account service and platform sign-in; synthetic `AccountInfo`; force `"NON XBOX"`;
privileges true; empty success for cloud/stats/achievements/leaderboards/QoS; telemetry muted.
**Exit:** MP button enabled offline, lobby screens open, profile dir stable across restarts, no stalls.

**M1 entry state (2026-11-02, read before designing).** The rlink login
sequence was captured end-to-end by the stage-6 logging build (log-helper
`0x1402BCB30` hooked, all hits with format string + r8/r9 deref + 2 stack
args in `logs/lanhook-<pid>.log`):
1. `WorldwideLoginService ctor` → cert-store load → `AutomatchInternal:
Instantiating` (t≈1.2 s).
2. `Requesting ticket` / `OnRequest app ticket returned 'N'` /
`SteamAuth received ticket` (t≈4 s) — the RUNE `steam_emu` ticket flow works.
3. `Found 0 profiles for account %s` (t≈6.7 s, retried every ~110 s) —
login reaches `www.reliclink.com` and parses; the account has ZERO
profiles → no `defaultProfileInfo`, no `relayServers[]`. THIS is where H1
must intervene: the response (or the getter `0x14039AAF0`) must present
≥1 profile with valid `defaultProfileInfo`.
4. Clicking MP with no profile → XAL sisu browser sign-in (`WebClient.exe
→ https://sisu.xboxlive.com/client/v68/0000000040225237/…`); on close:
`XalSignInAsync, sign in aborted`. This is the user-visible MP gate.
**Constraint (Arxan rule, hard):** the rlink/login/account `TComm_*` code
is encrypted on disk and integrity-checked post-decrypt — E9 head-patches
there kill the game (clean exit ~5.6 s, proven per-hook). M1 hook sites
must be clean-on-disk functions only (dump == disk bytes), or go
data-side (vtable/`g_Exp`/registry swaps, call-site E8 retargets from clean
callers). The login fns' retaddrs from the log pin their locations:
init = LogHelper ret offset +0x4f0062, profiles = +0x4f4542,
ticket = +0x3ff59a area, XalBrowser = +0x38c20c, sign-in-abort = +0x36e49f
(offsets from game base; match in `dev/lanhook/gametext.bin`, offsets =
VA−0x140001000). `gametext.bin` is the t=70 s decrypted .text dump;
re-dump via `dev/memcheck/dumptext.exe <pid>`. `notes/m02sites.py` +
`m02scan{2,3,4,5}.py` are the pdata/lea-scan tools; the RTTI survey is
`notes/rtti_game.py` + `notes/rtti_tables.json`.
Current hooks live in `dev/lanhook/` (`lanhook.c` + `hookcore.c/h` +
`hooks.asm`, built by `build.cmd` → staged as game-dir `dbghelp.dll`;
`hooktest.exe` is the detour self-test, `dev/fwdtest/` the proxy check).
Stage env: `AOE2LAN_STAGE` 1=safe-idle, 4=provider, 5=all-clean, 6=log
helpers; `AOE2LAN_HOOKS=<ids>` restricts (0–3 provider, 4 LogHelper,
9 LogHelper2, 5–8 encrypted → debug only, fatal). Launchers
`PLAY-stage1-SAFE/stage4-M03/stage6-M02.cmd` in the game dir.

### M2 — Co-op vs AI over Tailscale, 2 machines (5–8 days) ← first playable
H2 + H3 + lanhub node side (peer enumeration, gossip, `PINGNODE`) + launcher spawning the relay and
stamping the host's tailnet IP.
**Exit:** 2 tailnet machines, host + 1 client + 4–6 AI, full skirmish to victory, no desync, checksums
equal, `PINGNODE=direct`.

### M2.5 — Linux/Proton parity (2–3 days)
Native `lanhub-linux`, `dbghelp` override, ufw docs.
**Exit:** Windows↔Linux in one co-op lobby over the tailnet. From here on every milestone is
cross-OS.

### M3 — PvP + robustness (5–7 days)
Human slots everywhere, teams/diplomacy, chat, pregame vote/speed; drop → host election; save/restore.
**Exit:** 4 humans, 45 min, clean exit; one client force-quit at 20:00 leaves the others playable.

### M4 — Transport hardening (2–3 days)
DERP-only path playable and honestly reported; CGNAT pairs; 3-hop gossip; node join/leave; duplicate
nicknames; ACL recipe; Tailscale setup page.

### M5 — Packaging (3–4 days)
`aoe2lan-launcher.exe` / `.sh`, `aoe2lan.ini`, port-check utility (reports `direct|derp`), optional
`widgetui`/string data-mod for LAN labels (reuse `IDS_REGION_LAN`, don't invent strings), setup guide.

**Total to cross-OS co-op vs AI: M0+M1+M2+M2.5 ≈ 12–20 focused days.**

---

## 10. Decision trees

### 10.1 If M0.3 fails (singletons not swappable)
Fall back to function-level hooks on the same classes (still signature-based), or to S3
(HTTPS/WSS redirect + local rlink subset) at +2 weeks. Do not rewrite the netcode.

### 10.2 If M0.1 fails (relay rejects our token)

RESOLVED 2026-11-01: the relay never checks a token — the "secret" is a lookup key,
and the session row is created by the first peer's REQUESTJOIN. This branch stays
only for history; if the live two-machine test (session 4) still fails, the failure
is a wire-detail bug (PEERHEADER 15-byte header field values, ADDPEER layout, or
opcode assumptions) — debug from `notes/bs_server.log` + `notes/bs_peerjoin.c`, not
from this tree.

```
├── A. Pre-seed BattleServer with our token through its own config path   (obsolete — no token check exists)
├── B. Write `lanrelay` from the captured protocol                        (+7–10 d)
└── C. Reconsider S3 (local rlink HTTP server)                            (+2 weeks, last resort)
```

### 10.3 If M0.2 fails (engine demands a broadcast-discovered relay)

Synthesise the `BroadcastListener` hit inside the shim — feed the LAN relay list directly (GUID + IP
+ ports) — and keep the tailnet address from the login response. +2–3 d, still viable.
**Never reintroduce a broadcast dependency**: a tailnet will never carry it.

---

## 11. Test matrix (v1 acceptance)

| Case | Expected |
|---|---|
| 2 tailnet machines, Windows ×2 | co-op vs 6 AI, 60 min, no desync, `PINGNODE=direct` |
| 2 tailnet machines, Windows + Proton/native hub | same; lobby visible both ways |
| Direct path blocked → DERP only | playable; latency reported; no desync |
| Restrictive ACL (only 47100–47114 allowed) | works; a missing rule gives a clear error, not a hang |
| 3+ nodes, 3-hop gossip | lobby on node C visible on node A |
| Physical L2 switch, no Tailscale | works via 47103 broadcast and/or manual seeds |
| Mismatched `dataChecksum` | lobby hidden + reason; join refused |
| Client force-quit at 20:00 | others continue; lobby marked migrated |
| Nickname change | new profile dir (documented), old preserved |
| Restart chain ×5 | no duplicate profile dirs, no port conflicts |
| Defender/EDR enabled | no detection, no quarantine |

---

## 12. Repo layout (shipped as a zip overlay)

```
AoE2LAN\
  launcher\   aoe2lan-launcher.exe        (Win32/C++; also runs under Wine)
  linux\      aoe2lan-launcher.sh         lanhub-linux
  bin\        lanhook.dll                 lanhub.exe
  sigs\       <appBinaryChecksum>.json    (hook signatures per build)
  overlay\    aoe2lan.ini                 README.txt
  tools\      portcheck.exe               sigdump.exe (dev only)
  docs\       PLAN.md                     LAN_MOD_ARCHITECTURE.md
```

Install = unzip + run launcher + point at `AoE2DE_s.exe`. Uninstall = delete the folder plus the
four files copied into the game dir (`dbghelp.dll`, `lanhook.dll`, `aoe2lan.ini`, log dir).
Nothing is ever written into `resources\`, `widgetui\`, or next to `steam_api64.dll`.

---

## 13. Risks & open unknowns

**Risks**
1. A hidden engine check still demands a real Xbox token → mitigated by breadth in H1 (privileges,
   presence, strings verification all faked).
2. Game patch moves code → mitigated by signatures (R1); `sigs\` is data, not code.
3. Desktop/driver AV flags the proxy DLL → mitigated by using `dbghelp` and adding no packer.
4. Silent desync from data drift → mitigated by R6 (strict checksum equality, never auto
   `IGNORE_MP_VERSION`).
5. Tailscale DERP-only pairs feel laggy → surfaced by `PINGNODE`, not hidden.

**Open unknowns (must close in M0)**
1. Does `BattleServer` validate `LOBBYCONNECT.secret`? Against what?
2. Exact layouts of `AccountInfo` / `Advertisement` / `SlotInfo` as passed across S2.
3. Which object serves `getLanAdvertisements`, and is it reachable only from create-lobby or also
   from the browser?
4. Is the PlayFab Party plane (`PartyWin.dll`) on the critical path for pregame in LAN mode, or is
   `CommPacketPlayfabPartyInfo` skipped when no party exists?
5. Can LAN hosting start from `relayServers` alone (no broadcast hit)? ← make-or-break
   ANSWERED 2026-11-02: the premise inverted — the game accepts a
   broadcast-discovered relay with NO login (stock relay added at menu
   idle), while login yields 0 profiles and hence no relayServers at all.
   The open part is now: LAN hosting *initiated from the lobby UI* (needs
   M1's synthetic profile first), then relaying over a tailnet IP.
6. Does `getLanAdvertisements` require a `lanServerGuids` entry per advertisement, or is an invented
   GUID acceptable?

---

## 14. Appendix — how §2 was derived (reproducible)

Python 3 + `pefile` are available on this machine.

```python
# PE facts / imports / section entropy
import pefile, math
from collections import Counter
pe = pefile.PE('AoE2DE_s.exe', fast_load=True)
pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
print([(e.dll.decode(), len(e.imports)) for e in pe.DIRECTORY_ENTRY_IMPORT])
ent = lambda b: -sum(v/len(b)*math.log2(v/len(b)) for v in Counter(b).values())
print([(s.Name.rstrip(b'\0'), round(ent(s.get_data()), 2)) for s in pe.sections])
```

```python
# string mining (this is where every finding came from)
import re
d = open('AoE2DE_s.exe','rb').read()
for m in re.finditer(rb'[\x20-\x7e]{5,}', d):
    s = m.group().decode()
    if 'LAN' in s or 'Advertisement' in s or 'BattleServer' in s or 'TComm_Provider' in s:
        print(hex(m.start()), s)
```

Useful offsets from the analysis session: `0x31cab20 CanUseXboxLive`, `0x31f5f48`–`0x31f8690`
data-root path strings, `0x3282da0`–`0x3283100` command-line arg table, `0x3287988`
`AdvertisementCache::LobbyMatch REJECTED NOT LAN`, `0x32849a8 \BattleServer\BattleServer.exe`,
`0x367c018`–`0x3680a00` rlink service strings (endpoints, advertisement fields, LAN relay discovery),
`0x367e0f8 Adding LAN relay server`. In `BattleServer.exe`: `0x23fe88` banner, `0x240288` usage,
`0x240260 relayBroadcastPort`, `0x241490`–`0x241b20` relay message types.

Patch/verification tips: strings are ASCII in `.rdata` (no PDB needed); RTTI names give class/vtable
identity (`?AVPlayFabException@PlayFab@@`, `ModPackage`, `Age2Frame`, `RgeStream`, …); the binary is
not packed, so xrefs from log strings land directly on the relevant functions.

---

## 15. Definition of done (v1)

Two people on the same tailnet — one Windows, one Linux via Proton — launch from the launcher, click
Multiplayer, see a `[LAN]` lobby with 2 human + 6 AI slots, start, and play a full skirmish to a
victory screen without a desync, over the tailnet's direct path, with the game's own files untouched
and no broadcast/multicast dependency anywhere in the chain.

## 16. Playbook reuse — other AoE titles / other games

This project doubles as a reusable method for any AoE title (or any game) that
ships a match relay and a dead login plane. Everything learned is recorded so
it can be replayed against a new binary without redoing the discovery:

- `notes/m0-findings.md` — the running experiment log: wire formats, handshake
  order, server behavior, every failure mode with its cause (attach-before-
  session rule, GD-vs-LOBBYPING peer timeout, single-ADDPEER rule, etc.).
  **Rule: record every experiment, success and failure, with hex and timing.**
- `notes/relay-capture.txt` — frame-level ground truth of a full 2-peer session.
- `notes/bs_client.py`, `notes/bs_live_test.py` — protocol builders + the
  two-machine regression harness (host/joiner roles, stdlib only).
- `notes/bs_*.c` — Ghidra decompiles of the relay's packet/join/session code.
- `tools/ghidra_scripts/` — the analysis scripts (FindByString, Decompile,
  Vftable, XrefsTo) that work on any PE.

Method for a new title: confirm the game binary contains the same subsystem
strings (rlink / BattleServerRelay / TComm_Provider_RL / LAN advertisement),
find its shipped relay binary, repeat M0.1's two-script probe against it with
`-logLevel debug`, then diff the wire format against this file's notes. The
seams (S1 provider vtable, S2 service singletons) are expected to be the same
classes in sibling engines.

---

## 17. Two-worker split (session 30 onward)

From session 30 the project has **two workers on the same repo**:

- **W1 — Windows box** (operator + assistant). Owns everything that needs the live game process on
  this machine: the injected DLL, the login shim, hook ids, `.text` reverse engineering, and every
  measurement taken while the game is running.
- **W2 — Arch Linux** (friend). Owns everything platform-neutral or Linux-side: the native LAN hub,
  the Linux launcher and Wine prefix, the relay test harness, and Linux documentation.

Why this split: the two kinds of work need different machines and never need the same file. Nobody
has to wait for the other, and merge conflicts are avoided by file ownership rather than by
coordination.

### 17.1 File ownership (do not edit the other worker's files)

| Path | Owner |
|---|---|
| `dev/lanhook/**` (DLL, login server, hooks, tests) | W1 |
| `dev/memcheck/**`, `dev/fwdtest/**`, `dev/ghidra*` | W1 |
| `PLAY-stage*.cmd`, `logs/**` | W1 |
| `notes/m1-session*.md`, `notes/m0-*.md` | W1 |
| `lanhub/**` (new: the native hub) | **W2** |
| `linux/**` (new: launcher, Wine prefix, docs) | **W2** |
| `notes/linux-*.md` (new: W2 session notes) | **W2** |
| `PLAN.md`, `README.md` | shared — append only, never rewrite the other's section |
| `notes/bs_client.py`, `notes/relay-capture.txt`, `notes/m0-findings.md` | shared, read-mostly |

Both workers: `git pull` before you start, small commits, commit message starts with the area
(`linux: …` / `lanhook: …` / `hub: …`), push before you stop for the day.

### 17.2 W2 workstream, in priority order

| # | Task | Done when |
|---|---|---|
| L1 | **`lanhub` skeleton** (Go or C, W2's call): control server on `127.0.0.1:47100` plus node gossip on `:47101`, JSON over TCP, protocols exactly as §5.1 and §5.2. No game involvement at all. | Two `lanhub` instances on one host (different ports) exchange `ANNOUNCE` and one `ADVERT` shows up on the other; a `HELLO`/`HOST`/`FIND`/`JOIN` walk from a command-line client returns the expected JSON |
| L2 | **Peer enumeration**: `tailscale status --json` → `{nodeGUID, nodeName, tailnetIP, online}`; ini seeds as fallback; report `path=direct` vs `derp`. | `lanhub peers` prints the real tailnet peers on the friend's machine, and printing the route per peer |
| L3 | **Relay harness regression**: run `notes/bs_client.py` (stdlib only) against `BattleServer/BattleServer.exe` under the same Wine prefix, reproducing the session-3 two-peer `LOBBYCONNECT`/`REQUESTJOIN`/`GAMEDATA` relay, and turn it into `notes/bs_live_test.py`-style PASS/FAIL. | The harness prints PASS on Linux under Wine, and again from a second machine over the tailnet |
| L4 | **Linux launch path**: a launcher script that copies our `dbghelp.dll` into the game dir, sets `WINEDLLOVERRIDES="dbghelp=n"`, the telemetry env vars and `AOE2LAN_STAGE=8`, starts `lanhub`, starts the game. Plus the ufw/tailnet checklist. | The Multiplayer button is live inside Proton, `logs/lanhook-<pid>.log` is written inside the prefix, and the doc lists the exact commands |
| L5 | **Analysis W2 can do from Linux**: `.rdata` strings, RTTI, widget XAML/JSON, localization. Not `.text` — that needs a Windows-side decrypted dump. | Any finding recorded in `notes/linux-*.md` with addresses, so W1 can verify it on the dump |

W2 does **not** touch the DLL, the hook table, or the staged `dbghelp.dll`. The DLL is handed over as
a file (the repo git-ignores binaries): W2 drops it next to the game exe inside the prefix.

### 17.3 W1 workstream, in priority order

| # | Task | Done when |
|---|---|---|
| W1-a | **Hosting**: confirm the `Expect: 100-continue` fix (session 30h) makes Create Lobby succeed in LAN mode. | `starting LAN hosting` is followed by a *create advertisement* request, then a visible lobby |
| W1-b | **LAN advertisement reply**: replace the catch-all `[0,[]]` for `/game/advertisement/getLanAdvertisements` (and `findAdvertisements`) with a well-formed object, schema taken from the game's own parser the same way `getAvailableLeaderboards` was cracked. | `LANAdvertisementCache - response was not formatted correctly` disappears; the browser lists a `[LAN]` lobby |
| W1-c | **Relay wiring**: make the host's advertisement point at this machine's **tailnet IP**, not `192.168.0.x`, and prove the relay accepts both peers. | a second machine on the tailnet joins and both peers relay `GAMEDATA` |
| W1-d | **The other caches, one at a time**, each only when a measurement points at it: leaderboard stats, news, community events, item bundles, item categories, challenges, chat channels, achievements, offline messages, cloud credentials. | each cache's `response was not formatted correctly` line goes away and nothing else regresses |

Rules that still apply to both: never patch or hook code that is encrypted on disk; hook ids 4, 5
and 13 only; no blind patching; no cosmetic fixes; any new detour, `.rdata` re-point or game-file
edit is the operator's call and needs exact bytes plus a revert story; the game's own files are never
modified.
