# AoE2LAN — LAN Multiplayer Mod for a Cracked AoE2:DE (Windows + Linux/Proton)

Architecture and design document. No implementation code. Every claim below that is
marked **[evidence]** was read out of the installed binaries during this analysis; claims
marked **[unverified]** are load-bearing assumptions that must be proven in phase P0 before
any code is written.

---

## 1. What this installation actually is

| Item | Finding |
|---|---|
| Executable | `AoE2DE_s.exe`, 72,176,952 bytes, PE32+ x64, MSVC, 8 sections, **not packed** (import table intact: 274 imports from `MSVCP140`, 216 from `KERNEL32`, 59 from `PartyWin.dll`, 72 from `libHttpClient.Win32.dll`, 12 from `steam_api64.dll`) **[evidence]** |
| DRM/crack | RUNE `steam_emu` (`steam_api64.dll` + `winmm.dll` proxy, AppID `813780`, `LobbyEnabled=1`, `LobbyPort=31183`) **[evidence]** |
| Symbols left in binary | Full internal log strings, RTTI type names, and source paths (`F:\Agents\PhoenixBuilder-07\p4\portland_group\Aoc\Source\...)`. This is a gift: every subsystem is identifiable by its printf strings **[evidence]** |
| Server-side companion | `BattleServer\BattleServer.exe` (3.2 MB, OpenSSL + WinSock + websocketpp) — the **relay server** the game connects through **[evidence]** |
| Data root | `<Documents>\Games\Age of Empires 2 DE\<userrelicid>\{profile, mods\{subscribed,preview}, savegame\multi, resources\_packages, logs, widgetui}` **[evidence]** |
| Service endpoints in binary | `https://www.reliclink.com/`, `/game/account/*`, `/game/advertisement/*`, `/game/party/*`, `/game/automatch*`, `/game/cloud/*`, `/game/chat/*`, plus `EDGELINK_SERVER` arg to override the service host **[evidence]** |
| Identity stacks compiled in | Xbox XAL/XSAPI (`XalSignInAsync`, `XblMultiplayer*`, `https://sisu.xboxlive.com/...`) **and** Steam (`SteamPlatform`, `CreateSteamSessionAsync`) **and** PlayFab Party (`PartyWin.dll`: `PartyNetworkCreateEndpoint`, `PartySerializeNetworkDescriptor`) **[evidence]** |

---

## 2. Why the Multiplayer button is grey

The button state is driven by the account/login state, not by the crack flag itself:

* `IDS_RELIC_NOT_LOGGED_IN "Cannot connect to Multiplayer Services."`, `IDS_RELIC_LOGGING_IN "Signing into Multiplayer Services"` **[evidence]**
* `OnAccountEvent/AET_Login/R_Success profileID=%lld`, `R_PlatformSignInError`, `R_ExtendedError/EE_RLinkServiceUnavailable` **[evidence]**
* UI binding `CanUseXboxLive`, widget path `Background/ButtonAnchor/XBLSignIn`, screen `ScreenXBLSignIn` **[evidence]**
* Login drives `defaultProfileInfo` → which drives the save/profile directory `<userrelicid>` **[evidence]**

So: no successful RelicLink login ⇒ no profile ⇒ Multiplayer disabled. The crack breaks the
login, and the login is the *only* thing that is broken. Everything behind it (lobby, relay,
lockstep, checksums) is intact and is exercised by single-player skirmish too.

---

## 3. The good news: AoE2:DE *has* a LAN mode in this build

This is not a "write a new netcode" project. The engine already contains a LAN path:

* `WorldwideAdvertisementService`: `starting online hosting` / `starting offline hosting` / **`starting LAN hosting`** / `starting local hosting` **[evidence]**
* `/game/advertisement/getLanAdvertisements` with `lanServerGuids`; `LANAdvertisementCache` **[evidence]**
* `BroadcastListener`, `Adding LAN relay server: %s, GUID %s` **[evidence]**
* Client arg `-relayBroadcastPort` — documented in the binary as *"Port to broadcast server presence, must also pass same arg/value to client"* **[evidence]**
* `AdvertisementCache::LobbyMatch REJECTED NOT LAN` (LAN filtering inside the lobby cache) **[evidence]**
* UI strings: `IDS_REGION_LAN "LAN"`, `IDS_REGION_LAN_TAG "[LAN] %s"`, `IDS_LOBBY_CREATE_USE_LOCAL_LAN_DROPDOWN_ITEM`, `IDS_FIREWALL_BLOCK_LAN`, `IDS_RELIC_NAT_FAILURE "...joining a LAN game? see .../lan-issues"` **[evidence]**
* `BattleServer.exe` CLI: `-name -bsPort -publicPort -lobbyPort -replayPort -webSocketPort -outOfBandPort -relayBroadcastPort -muninReportDelay`; banner `Battleserver %d.%d.%d running on ports %u,%u,%u` **[evidence]**

Conclusion: the game can host and join LAN matches through a locally discovered
`BattleServer` relay. What it cannot do is get past login to reach that UI.

---

## 4. Network stack (where the seams are)

```
AoE2DE_s.exe
├── UI shell (native C++ menu + widgetui/*.json screens)      ← seam S4 (cosmetic only)
├── Simulation (lockstep, per-turn world/player checksums)
├── Comm abstraction: TComm_*  — packets: CommPacketPlayerCommand, CommPacketChat,
│      CommPacketVote, CommPacketPreGameNotify/HostState, CommPacketPlayfabPartyInfo, …
│      channels: sync / checksum (`CHECKSUM_CHANNEL_ID`) / party
├── TComm_Provider_RL                                          ← SEAM S1 (recommended)
│      InitProvider/CreateChannel/PlatformLogin, ReinitProvider,
│      SendP2PPacketRawMemCopy(pkt, station), SendSyncPacketRawMemCopy,
│      SendUnreliablePacketRawMemCopy, ReceiveNetworkData, ProcessPackets,
│      UpdateConnectionState, connectToGame(host), findOrInitiateP2PConnection,
│      onPacketSendingTicket, SetPlayerSlotInfo, SetEnableCrossplay, rlUpdateLoop
├── RelicLink SDK (rlink)                                      ← SEAM S2
│      ├── service plane: HTTPS POST /game/* + WebSocket push streams (Worldwide*Service)
│      ├── relay client: BattleServerRelay (raw TCP | WebSocket | out-of-band)
│      └── PartyWin.dll (PlayFab Party) — pregame/party channel only
├── BattleServer.exe (child process) — the relay
└── Platform SDKs: XAL/XSAPI (Xbox), Steam, MS Store
```

**Seam ranking (decided in §5):**

| Seam | What you swap | Cost | Fragility |
|---|---|---|---|
| **S1** `TComm_Provider_RL` vtable | transport + peer/station model | medium | tolerates any lobby source |
| **S2** `Worldwide*Service` objects | advertisement/login/stats plane | medium | needs the service struct layouts |
| S3 HTTP/WSS redirect (`hosts` + CA in `certificates/cacert.pem` + local TLS) | whole server | high (Bond serialization RE; `Schema/` in this install is **telemetry-only**, not rlink services) | very faithful, build-proof |
| S4 UI patch only | button enablement | trivial | useless alone |

---

## 5. Design

### 5.1 Component model

```
┌──────────────────────────── one machine ────────────────────────────┐
│                                                                      │
│  aoe2lan-launcher            (Windows .exe | Linux .sh)              │
│   ├─ reads aoe2lan.ini  (nickname, base port, relay host/autodetect) │
│   ├─ starts LanHub  (if this machine is the hub)                     │
│   ├─ ensures BattleServer.exe is running (spawns it, LAN profile)    │
│   ├─ sets env + args, injects lanhook (proxy DLL or remote thread)   │
│   └─ launches AoE2DE_s.exe  (-relayBroadcastPort N …)                │
│                                                                      │
│  lanhook.dll  (in-process, injected)                                 │
│   ├─ [H1] LoginShim      — synthesise account+profile, unblock UI    │
│   ├─ [H2] LobbyShim      — local advertisement/host/join service     │
│   ├─ [H3] ProviderBridge— route TComm_Provider_RL onto LanHub/LAN    │
│   └─ [H4] TelemetryOff   — silence cloud/stats calls that stall      │
│                                                                      │
│  BattleServer.exe  (stock, unmodified)  ← relay, discovered by       │
│                                          UDP broadcast               │
│                                                                      │
│  LanHub  (one per machine, native on the host OS)                    │
│   ├─ Peers       unicast peer list: tailscale status --json + ini    │
│   ├─ Directory   gossip/flood lobby registry with TTL (no central)   │
│   ├─ Identity    nickname → stable 64-bit profileID                  │
│   └─ RelayCtl    starts/stops BattleServer, hands out tokens/ports   │
│                  relay is advertised at the HOST's tailnet IP        │
└──────────────────────────────────────────────────────────────────────┘
```

### 5.2 Decisions

**D1 — Do not reimplement the relay unless forced.** `BattleServer.exe` is shipped, self
contained, has the full reliable-UDP-over-TCP-ish protocol (see §6.3) and speaks the exact
wire format the client expects. Target design: run it unmodified on the machine that hosts the
match, hand its address to the client **through the login response**
(`relayServers[].relayIP` = that machine's tailnet IP, not loopback), and inject only the
*login* and *advertisement* planes.

> `-relayBroadcastPort` discovery is **not usable over Tailscale** (no broadcast domain, see
> §8.3). It stays as an option for a real L2 LAN only. The login-provided `relayServers` path is
> the primary mechanism, and M0.2 must prove LAN hosting works from it alone. Fallback `lanrelay` is specified in §6.3 in case **[unverified]**
BattleServer turns out to validate the login-issued `relayAuthToken` on `LOBBYCONNECT`.

**D2 — Interpose at S2 (service objects), not S3 (HTTP).** The rlink service classes are
in-binary C++ objects with RTTI; the game reaches them through singletons and passes
structs like `Advertisement`, `SlotInfo`, `AccountInfo`. Swapping vtable pointers to our own
implementations avoids reverse-engineering Bond compact-binary encoding and TLS, and it
cannot break when the game rotates certificates. Cost: our structs must match the game's
layout exactly — recovered from RTTI + field-name strings (`advertisementid`, `slotinfo`,
`maxplayers`, `relayIP`, `relayAuthToken`, `relayPortRaw`, `profiles`, `defaultProfileInfo`, …).

**D3 — Login is faked, not bypassed.** Provide a complete `AccountInfo`:
`profileID = FNV1a64("aoe2lan:" + nickname)` (stable across sessions, so the
`Games\Age of Empires 2 DE\<userrelicid>` folder and campaign progress persist),
`relayServers[] = {relayIP=hub, relayPortRaw, relayPortWebSockets, relayPortOutOfBandSocket,
relayAuthToken, region="LAN"}`, empty stats/achievements/clan, `sslCertificates=[]`.
The same nickname therefore always maps to the same profile and save folder.

**D4 — Lobby plane is a unicast mesh, not a broadcast domain.** `findAdvertisements` /
`getLanAdvertisements` / `host` / `join` / `leave` are answered from LanHub, which gossips the
lobby registry to known peers over plain unicast TCP. No HTTP, no TLS, no broadcast, no
multicast, no internet. Each node's own game talks only to its local LanHub at
`127.0.0.1:47100`; inter-node traffic is LanHub↔LanHub at tailnet IPs.

**D5 — Keep the checksum contract.** In-game integrity is the engine's own lockstep
checksums; a mismatch causes a desync, not a security hole. All peers must run identical
`resources\` data. `IGNORE_MP_VERSION` (an existing arg: *"Allow builds with this command arg
to match with each other regardless of build version or configuration"*) is passed **only**
when the launcher verifies that `appBinaryChecksum`/`dataChecksum` match across peers; it is
never used to paper over differing data.

**D6 — One DLL, two OSes.** `lanhook.dll` is plain Win32 C++ with no MSVC runtime beyond
what the game already loads. Windows: loaded by the launcher. Linux: the *same* DLL under
Proton, loaded through a DLL-search-order proxy (see §8).

---

## 6. Component contracts

### 6.1 lanhook — H1 LoginShim

Hook the rlink account service singleton (`WorldwideAccountService` RTTI) and the
platform-login path (`XalTryAddDefaultUserSilentlyAsync` / `SteamPlatform` sign-in) and
short-circuit to a synthetic success:

| call | behaviour |
|---|---|
| `Login` | return `R_Success`, fill `AccountInfo` per D3, emit `AET_Login/R_Success profileID=…` |
| `SelectProfile` / `DeselectProfile` | synthetic success + `AET_SelectProfile` |
| `GetProfileName`, `SetLanguage`, `setInputDevice`, `setCrossplayEnabled` | synthetic success |
| `HasPlatformPrivilege(MULTIPLAYER)` | `true` (otherwise `IDS_PRIVILEGE_DENIED_MULTIPLAYER_BLOCKED`) |
| XBL sign-in | suppressed; the game's own `xbox` / `"NON XBOX"` branch (`0x3284abc/0x3284ac8`) must land on NON XBOX |
| cloud/achievements/stats/leaderboards/relay-QoS | empty success (H4) |

Exit criteria H1: Multiplayer button enabled, multiplayer screens open, profile folder
created and stable across restarts.

### 6.2 lanhook — H2 LobbyShim

| rlink call the game makes | LAN answer |
|---|---|
| `/game/advertisement/host` | register lobby in LanHub; allocate sessionID; return `url` + `relayAuthToken` |
| `updateState` / `update` / `updateTags` | mutate registry entry |
| `findAdvertisements`, `getAdvertisements`, `getLanAdvertisements`, `findObservableAdvertisements` | filtered registry snapshot, region = `LAN` |
| `join`, `leave`, `startObserving`, `stopObserving` | slot reservation in registry; peer list update |
| `party/*` (pregame chat, invites) | answered locally over LanHub (party channel is only used pre-game) |
| notifications | replay cached advertisements in `AET_GetAdvertisements`/`AET_HostNotification` form |

Exit criteria H2: host sees own lobby; second machine sees it in the browser; joining
populates slots and launches the match.

### 6.3 Relay (stock BattleServer, fallback lanrelay)

Wire facts recovered from `BattleServer.exe` strings **[evidence]**: peer/host model with
`LOBBYCONNECT{titleID, sessionID, secret}`, `LOBBYRELAY`, `LOBBYPING`, `PROXY`,
`PEERHEADER{flagBits, ackBits, packetNumber, startACKReliableNonSequential,
lastReliableSequentialID}`, `REQUESTJOIN`, `ADDPEER{peerID,isHost,isLocal,globalID,addressList}`,
`REMOVEPEER`, `GAMEDATA`, `DROPOUT`, `INTEGRITYCHECK{proposedHostID, peers, migrateState}`,
`STARTOBSERVEREQUEST{passwordHash}`, `ACTIVATEOBSERVER`, `SETOBSERVABLEPARAMATERS`,
`LEAVESIMULATION`, `STOPOBSERVE`, checksum channel, `Session:PeerAccepted: New host for session`,
silence timeouts, DOS guard.

`lanrelay` (fallback, only if D1 fails) implements exactly that: accept N TCP peers, assign
peerIDs, broadcast/proxy frames, maintain per-peer reliable-sequential + ack bitfield, run
host election on `INTEGRITYCHECK`, and forward checksum-channel messages. ~2–3k LOC +
packet capture from a stock session as ground truth.

### 6.4 Control protocol (launcher ↔ LanHub ↔ lanhook)

One small JSON-over-TCP protocol on the base port (`47100` by default):

Game-side commands (shim ↔ local LanHub, `127.0.0.1:47100`):

```
HELLO   {ver, nick, appChecksum, dataChecksum}          → {profileID, sessionToken, ports{}}
HOST    {lobby{name,maxPlayers,map,slots[],passworded}} → {advertisementID, relayAuthToken, relayIP}
UPDATE  {advertisementID, patch{}}                      → {ok}
FIND    {filters{}}                                     → {advertisements[]}
JOIN    {advertisementID, password?}                    → {slot, peers[], relayIP, relayAuthToken}
LEAVE   {advertisementID}                               → {ok}
PEERS   {advertisementID}                               → {peers[]}          (push subscription)
PING                                                    → {rttMs, nodeName, path}
```

Node-side commands (LanHub ↔ LanHub, at tailnet IPs — this replaces broadcast discovery):

```
ANNOUNCE {nodeGUID, nodeName, ver, appChecksum, dataChecksum, ports{}, ttlHops}
ADVERT   {advertisementID, originGUID, lobby{…}, relayIP, relayPorts, ttlHops}
WITHDRAW {advertisementID, originGUID}
PINGNODE → {rttMs, path: direct|derp}
```

Gossip rule: re-flood `ANNOUNCE`/`ADVERT` with `ttlHops-1` to peers that have not seen the id;
`ttlHops=3` is enough for any realistic tailnet group, and ≤8 nodes flood trivially.

Ports (all configurable; bound on `0.0.0.0` so the tailnet IP works):

| port | proto | use |
|---|---|---|
| 47100 | tcp | LanHub control, **loopback only** (game shim ↔ hub) |
| 47101 | tcp | LanHub node gossip, tailnet-facing |
| 47103 | udp | optional LAN broadcast announce (`AOE2LAN:<guid>:<name>`) — physical L2 only |
| 47110 | tcp | BattleServer raw relay (`-bsPort`) |
| 47111 | tcp | BattleServer websocket (`-webSocketPort`) |
| 47112 | udp | BattleServer out-of-band (`-outOfBandPort`) |
| 47113 | udp | `-relayBroadcastPort` (physical L2 only; unused on a tailnet) |
| 47114 | tcp | `-lobbyPort` |

---

## 7. Flows

**Host:** launcher → LanHub `HELLO` → spawn `BattleServer.exe -name <nick> -bsPort 47110 -webSocketPort 47111 -outOfBandPort 47112 -lobbyPort 47114` → game starts → H1 logs in, `relayServers[] = { relayIP = <this machine's tailnet IP>, relayPortRaw/WebSockets/OutOfBandSocket, relayAuthToken, region = "LAN" }` → player opens Multiplayer → Create Game → H2 registers lobby (`serviceType=LAN`) → LanHub `ADVERT` floods it to peers → pregame chat over the party channel (answered locally) → Start → every peer's session connects to the host's tailnet IP:47110 with the issued token → lockstep over the relay.

**Browse/Join:** client launcher → `HELLO` → LanHub has already received `ADVERT` from peers (and `ANNOUNCE` for node presence) → game Multiplayer → browser, region `LAN` → H2 `FIND` returns the host's advertisement **plus the host's `relayIP`** → Join → slot reserved → provider connects to that tailnet IP → pregame handshake → start. No broadcast involved at any point.

**Relay placement:** the relay always runs on the machine that hosts the match (peer-to-peer, no dedicated hub). A machine that only joins never starts `BattleServer.exe`. If the group prefers one fixed relay box, set `relayMode = fixed` and `relayHost = <tailnet name>`; then every login response points there instead.

**Drop / host migration:** relay's silence timeout removes the peer; `INTEGRITYCHECK` elects a
new host from remaining peers; LanHub marks the lobby as migrated. Engine handles save/restore
(`Restore Multiplayer Game`) unchanged.

**Version mismatch:** on `HELLO` mismatch of `dataChecksum`, the launcher refuses to list that
hub's lobbies and shows the diff instead of silently enabling `IGNORE_MP_VERSION`.

---

## 8. Platform matrix

### Windows
* Injection: launcher copies `lanhook.dll` into the game dir as a proxy of a **lightly used
  imported DLL** (`dbghelp.dll` — 1 import, or `d3d11.dll`/`dxgi.dll` via a forwarder `.def`).
  No remote-thread injection, no AV-flagged behaviour, works with any launcher.
  `winmm.dll` and `steam_api64.dll` are already taken by the RUNE emu — do not touch them.
* Firewall: one inbound rule per helper exe; `IDS_FIREWALL_BLOCK_LAN` is the in-game warning
  that appears when discovery is blocked.
* Store `%USERPROFILE%\Documents\Games\Age of Empires 2 DE\<profileID>\` unchanged.

### Tailscale (the actual transport — see §8.3)

Legal here, and it replaces the "later" internet-play story entirely. Constraints that are
baked into the design rather than discovered in testing:

* **No broadcast/multicast** — discovery is the unicast `ANNOUNCE`/`ADVERT` gossip above; the
  game's own `-relayBroadcastPort` listener simply hears nothing and is harmless.
* **Relay must be addressed by tailnet IP**, never loopback: `relayServers[].relayIP` is filled
  from the host node's own tailnet address (`tailscale ip -4` / `status --json`).
* **MTU 1280** on `tailscale0`; clamp `[net] mtu = 1200`. Gameplay is TCP (`-bsPort` /
  `-webSocketPort`), so MSS/PMTUD handles it; UDP is only the out-of-band ping.
* **DERP fallback**: if a pair cannot go direct (CGNAT, hostile firewall), traffic relays through
  Tailscale's DERP servers — add 100–200 ms. Acceptable for lockstep with the engine's buffer,
  but the launcher's port-test must report `path: direct|derp` so stutter is diagnosable.
* **ACLs**: the default tailnet policy (`*` → `*:*`) already permits this. A restrictive policy
  needs an explicit accept rule for the ports in §6.4 between members.
* **Peer enumeration**: `tailscale status --json` (run by the native LanHub, not inside the
  prefix) supplies DNSName + `100.x` addresses; `[tailscale] peers =` in the ini is the manual
  fallback when the CLI is unavailable.

### Linux (Proton)
* Run everything inside one Proton prefix: launcher starts `BattleServer.exe` and
  `AoE2DE_s.exe` with the *same* `STEAM_COMPAT_DATA_PATH`/`WINEPREFIX` so they share
  `127.0.0.1` and the `Documents` mapping.
* `lanhook.dll` loads identically (it is PE, executed by Wine). Use the same proxy-DLL trick —
  `WINEDLLOVERRIDES` is not needed and Proton's builtin d3d11 would shadow a proxy, so prefer
  `dbghelp` (Wine's builtin can be overridden per-app with
  `WINEDLLOVERRIDES="dbghelp=n,b"`).
* LanHub may run natively on the Linux host (`lanhub-linux`) with the in-prefix game talking to
  `host.docker`-style loopback — simplest, and it makes mixed Windows+Linux LANs trivial because
  the relay protocol is plain TCP/UDP.
* Sockets: Wine uses the host network stack directly (no separate netns), so tailnet `100.x`
  addresses and `127.0.0.1` both work from inside the prefix. Open ufw for 47101/tcp (gossip) and
  47110–47114 (relay); on multi-homed hosts pin the interface in `aoe2lan.ini`.
* Broadcast (`SO_BROADCAST`) is available in Wine but pointless over a tailnet — the design never
  relies on it.
* Case sensitivity: keep all paths lowercase-safe inside the prefix; the game already writes
  `savegame\multi\` — do not change case.
* `%SystemDrive%\Users\Public\Documents\Steam\RUNE\813780` (RUNE emu data root) maps into the
  prefix automatically; no change needed.

---

## 9. Failure modes and mitigations

| Symptom | Cause | Mitigation |
|---|---|---|
| Buttons still grey | H1 landed on the Xbox branch | force the `"NON XBOX"` path; verify `CanUseXboxLive=false` |
| Lobby list empty on second machine | gossip blocked by ACL/firewall, or peers unknown | `ANNOUNCE` never arrived: check `[tailscale] peers`, ACL, and `PINGNODE` |
| Lobbies visible but join hangs | advertisement carried a loopback/wrong `relayIP` | always stamp the host's tailnet IP into `relayServers` and `ADVERT` |
| Periodic 100–200 ms stutter | traffic on DERP instead of direct | `tailscale ping <peer>`; open the ports / enable direct path |
| "Unable to detect Battleserver" (`IDS_RELIC_NAT_FAILURE`) | OOB/raw ports blocked or token mismatch | verify D1 assumption; fall back to `lanrelay` |
| Desync at turn N | data/`appBinaryChecksum` mismatch | enforce checksum equality in `HELLO`; never auto-enable `IGNORE_MP_VERSION` |
| New profile folder each run | profileID derived from non-stable input | derive from nickname only |
| 30 s stalls entering menus | cloud/stats/telemetry calls timing out | H4: `RL_TELEMSHOULDNTSEND=1`, empty-success stats/cloud |
| Crack stops working after update | RUNE emu version vs new exe | keep the shim signature-based, not address-hardcoded |

---

## 10. Phases

**P0 — Prove the three assumptions (no product code).**
1. Stock `BattleServer.exe` accepts a session created with a locally issued token **[unverified]**.
2. The client's LAN path can be reached with only login + advertisement faked (no Xbox, no HTTP).
3. `TComm_Provider_RL` and the `Worldwide*Service` singletons are locatable and swappable at runtime.
Exit: a 2-machine loopback test where a hand-driven shim hosts and joins.

**P1 — LoginShim (H1 + H4).** Exit: MP UI unlocked offline, stable profile dir, no stalls.

**P2 — LobbyShim (H2) + relay attach.** Exit: two machines see and join each other; 1v1 + AI, in-game.

**P3 — Robustness.** 4–8 players, spectators, drop/rejoin, host migration, save/restore, mixed OS.

**P2.5 — Linux/Proton parity + Tailscale hardening.** Native `lanhub-linux`, DERP-only and
cross-OS testing. Pulled forward from P4 so no later milestone ships Windows-only.

**P4 — Packaging.** `aoe2lan-launcher.exe`, `aoe2lan-launcher.sh`, `aoe2lan.ini`, optional
`widgetui`/string data-mod for LAN labels, one-page setup guide, port test utility.

Milestone IDs above are intentionally loose; `LAN_MOD_PLAN.md` §2 is authoritative (M0–M5).

---

## 11. Open questions for RE (P0 detail)

1. Does `BattleServer` validate `LOBBYCONNECT.secret` against anything (it only logs
   `secret=%llu`)? If it validates, against what?
2. Exact layout of `AccountInfo` / `Advertisement` / `SlotInfo` as passed across the S2 boundary.
3. Which service object owns `getLanAdvertisements`, and is it reached with
   `serviceType=LAN` from the *create-lobby* UI only, or also from the browser?
4. Whether the party plane (`PartyWin.dll`) is on the critical path for pregame in LAN mode, or
   whether `CommPacketPlayfabPartyInfo` is simply skipped when no party exists.
5. **Can LAN hosting start from the login-provided `relayServers` list alone, with no
   broadcast-discovered relay present?** This is now make-or-break, because a tailnet has no
   broadcast domain. If the engine insists on a `BroadcastListener` hit before enabling
   `starting LAN hosting`, the shim must synthesise that discovery event (feed the LAN relay
   list directly) — that work belongs in M0, not M2.
6. Does `/game/advertisement/getLanAdvertisements` require a `lanServerGuids` entry (i.e. a
   discovered relay GUID) per advertisement, or is a GUID we invent acceptable?

---

## 12. Risks

* **Silent engine behaviour**: an in-binary check may still demand a real Xbox token; mitigation
  is H1 breadth (privileges + presence + strings verification all faked).
* **Maintenance**: patches/updates move functions; keep the shim signature-based and version-gated.
* **Anti-cheat/telemetry**: none that blocks LAN, but report/telemetry paths must be silenced or
  they cost 30 s per menu transition.
* **Checksums** are the only real integrity barrier; treat data equality as a hard prerequisite.
