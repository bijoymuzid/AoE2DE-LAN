# AoE2LAN — Execution Plan (recommended path)

Companion to `LAN_MOD_ARCHITECTURE.md`. This is the build plan for the option that is
fastest to a playable match **and** survives game patches. Read §0 first; it is the whole
argument in six lines.

---

## 0. The recommended architecture, in one page

| # | Decision | Now | Future |
|---|---|---|---|
| R1 | One injected DLL (`lanhook`), **signature-based**, vtable swap on `TComm_Provider_RL` + `Worldwide*Service` | fastest route to first match | patch = new signatures, not a rewrite |
| R2 | Stock `BattleServer.exe` as relay, unmodified, `-relayBroadcastPort` discovery | days of work saved | stays on the official relay implementation |
| R3 | Fake login with **stable nickname-derived** `profileID` | unblocks MP UI | saves/mods/campaign stay bound to a person |
| R4 | Lobby plane = LanHub unicast mesh (JSON/TCP gossip). **No broadcast, no HTTP/TLS/Bond RE** | no broadcast dependency at all | identical code on a tailnet, a ZeroTier net, or a real L2 LAN |
| R5 | DLL loaded as a **proxy of `dbghelp.dll`**, game launched by our launcher | no injector, no AV noise | same PE DLL under Proton, one code path |
| R6 | Hard-enforced checksum equality; `IGNORE_MP_VERSION` never auto-set | no surprise desyncs | trustworthy diagnostics when someone mods data |
| R7 | **v1 target = co-op vs AI** (2–4 humans + AI slots), PvP is a free consequence | playable in the shortest time | AI load is host-local, so the relay is never the bottleneck |
| R8 | **Transport = Tailscale.** Discovery is unicast gossip, relay is addressed by tailnet IP, broadcast is never used | works today across the tailnet | same code works on a physical LAN; "internet play" is solved gratis |
| R9 | **Linux tested from M2**, not at the end | same PE DLL, only the launcher differs | Wine/builtin-DLL issues surface early, not at ship time |

**North star:** the mod is an *adapter plane*, not a netcode. If AoE2:DE ever ships proper LAN
again, the shim shrinks to zero and nothing else in the design is wasted.

**Transport assumption (R8), load-bearing:** Tailscale is a **point-to-point L3 WireGuard mesh
with no broadcast or multicast** (that is why mDNS, SSDP and KDE Connect break on tailnets —
tailscale#11134, tailscale#1013). Therefore:

* never depend on `-relayBroadcastPort` / `SO_BROADCAST` for anything that must work for you;
* discovery = `ANNOUNCE`/`ADVERT` gossip between LanHub nodes at tailnet IPs;
* `relayServers[].relayIP` = the **host machine's tailnet IP**, never `127.0.0.1`;
* tailnet `tailscale0` MTU is 1280 → clamp `[net] mtu = 1200`;
* DERP fallback costs 100–200 ms; the tooling must report `direct|derp` so stutter is diagnosable;
* default tailnet ACL (`*`→`*:*`) already permits it; a locked-down policy needs an explicit rule.

**Explicit non-goals for v1:** matchmaking, ranked, clans, cloud saves, achievements, mod
subscription, spectators, drop-in-rejoin, NAT traversal code (Tailscale owns that).

---

## 1. Invariants (violating any of these = wrong build)

1. Never modify `steam_api64.dll`, `winmm.dll`, `AoE2DE_s.exe` on disk. Everything is runtime
   or an overlay folder.
2. No hardcoded RVAs. Every hook is resolved by signature, with the signature set versioned per
   game build (`sigs\<appBinaryChecksum>.json`).
3. No packet is invented between peers that the engine does not expect — the relay protocol is
   the engine's own.
4. Data equality is mandatory. The launcher compares `appBinaryChecksum` + `dataChecksum` before
   listing lobbies.
5. Everything must be uninstallable by deleting the overlay folder + `aoe2lan.ini`.

---

## 2. Milestones

### M0 — Proof (2–4 days, no product code)
Goal: retire the three load-bearing unknowns.

| # | Task | Method | Exit criterion |
|---|---|---|---|
| M0.1 | Does stock `BattleServer` accept a session whose token we invented? | two stock clients, hand-crafted `LOBBYCONNECT{secret}` | both peers relay `GAMEDATA` |
| M0.2 | **Does LAN hosting start from the login-provided `relayServers` alone, with no broadcast-discovered relay?** (make-or-break on a tailnet) | trace with a logging hook (no logic); two tailnet machines, broadcast unavailable | `AET_GetAdvertisements` returns a lobby addressed at a tailnet IP; `starting LAN hosting` appears; both peers relay `GAMEDATA` |
| M0.3 | Are `TComm_Provider_RL` and the service singletons swappable at runtime? | RTTI scan → vtable dump → swap a no-op | game still runs with our vtable installed |

Deliverables: `notes/m0-findings.md`, `sigs/<cheksum>.json` draft, packet capture of a stock
relay session (ground truth for the fallback relay).

### M1 — LoginShim + TelemetryOff + stable profile (3–5 days)
* Hook the account service + platform sign-in; return synthetic `AccountInfo` with
  `profileID = FNV1a64("aoe2lan:"+nickname)`, `relayServers=[…]`, empty stats/cloud.
* Force the `"NON XBOX"` branch; `HasPlatformPrivilege(MULTIPLAYER)=true`.
* Empty-success for cloud/stats/achievements/leaderboards/QoS; silence telemetry.
* Exit: **Multiplayer button enabled offline**, lobby screens open, `Games\Age of Empires 2 DE\<id>\`
  created once and reused across restarts, no 30 s menu stalls.

### M2 — Co-op vs AI over Tailscale, 2 machines (5–8 days) ← first playable
* `LobbyShim`: host / update / leave / find / join / getLanAdvertisements answered from LanHub.
* `ProviderBridge`: station↔peer mapping, sync/unreliable channels onto the relay.
* `LanHub` node side: peer enumeration (`tailscale status --json` + ini seeds), `ANNOUNCE` /
  `ADVERT` / `WITHDRAW` gossip with TTL, `PINGNODE` reporting `direct|derp`.
* Launcher spawns `BattleServer.exe` (host machine only) on 47110–47114 and stamps the host's
  tailnet IP into the login response. **No `-relayBroadcastPort` dependency.**
* **AI support:** preserve AI slots byte-for-byte in `encodedSlots` / `SlotInfo` (never normalise
  them away), keep AI difficulty and per-slot settings in the advertisement, let the host own all
  AI simulation. AI adds **no** traffic — it is deterministic host-side state inside lockstep.
* Exit: two tailnet machines, host + 1 client + 4–6 AI, full skirmish to a win condition, no
  desync, checksums equal, `PINGNODE` shows `direct`.

### M2.5 — Linux / Proton parity (2–3 days) ← moved early, deliberately
* Same `lanhook.dll` via `dbghelp` proxy inside one Proton prefix; `WINEDLLOVERRIDES="dbghelp=n"`.
* `lanhub-linux` **native** build (runs outside the prefix, owns Tailscale enumeration; the shim
  inside the prefix talks to it at `127.0.0.1:47100`, which Wine shares with the host).
* Exit: Windows↔Linux in the same co-op lobby over the tailnet, `PINGNODE` correct, ufw rules
  documented. From here on, **every** milestone is tested on both OSes.

### M3 — PvP + robustness (5–7 days)
* Human slots on all sides, team/diplomacy, chat, pregame vote/speed, observer-free.
* Drop handling: relay silence timeout → `INTEGRITYCHECK` host election path verified.
* Save/restore multipayer game through the LAN plane.
* Exit: 4 humans, no AI, 45-minute game, clean exit; one client force-quit mid-game leaves the
  others playable.

### M4 — Transport hardening (2–3 days)
* DERP-only path (block the direct ports deliberately) still playable; latency reported honestly.
* CGNAT/hostile-firewall pairs, 3-hop gossip chains, node join/leave, duplicate nicknames.
* ACL recipe + one-page Tailscale setup in the docs.

### M5 — Packaging + polish (3–4 days)
* `aoe2lan-launcher.exe` / `aoe2lan-launcher.sh`, `aoe2lan.ini`, port-test utility, one-page guide.
* Optional data-mod for LAN labels (`IDS_REGION_LAN` already exists — reuse, don't invent strings).
* Exit: a friend can install from a zip and be in a co-op game in under 10 minutes.

**Total to a v1 you can actually play with someone (over Tailscale, Windows+Linux):
M0+M1+M2+M2.5 ≈ 12–20 days of focused work.**

---

## 3. AI: what "playing against AI" requires (and what it doesn't)

* AI slots are just player slots with `SlotStatus = AI`; the advertisement carries them in
  `encodedSlots`, which `LobbyShim` must pass through untouched.
* AI is simulated identically on every peer as part of lockstep. **No packets, no relay cost.**
* Requirements: identical `resources\_common\ai\` on all peers (covered by `dataChecksum`), and the
  host's lobby options (`LobbyElo`, `SlotCount`, `SlotsFilled`, `victory`, difficulty) round-tripped
  through the advertisement.
* Therefore the cheapest useful product is **2 humans + N AI**. That is M2 and it ships first.

---

## 4. Why this survives the future

1. **Signature layer** — a new game patch = re-derive 6–12 signatures. `sigs\*.json` is data, not code.
2. **Relay is stock** — no protocol drift.
3. **Lobby contract is versioned JSON** (`HELLO/HOST/FIND/JOIN/LEAVE/PEERS`) — the transport behind it
   can later be replaced by a real rlink-compatible server (the S3 option in the architecture doc)
   without touching the game side.
4. **VPN-compatible by construction** — discovery is unicast gossip and the relay is a plain TCP
   endpoint at a routable address, so Tailscale/ZeroTier need no special support and no NAT
   traversal code. (Broadcast would have broken here — that is why it is not in the design.) This
   is the long-term answer to "multiplayer is greyed out".
6. **One shim, two OSes** — the game-side DLL is a PE loaded by Wine on Linux and by Windows
   natively; only the launcher and the native LanHub binary are platform-specific, and both are
   small.
5. **Degrades gracefully** — if a future build ships working LAN, the shim's hooks simply stop
   being installed.

---

## 5. Configuration surface (`aoe2lan.ini`)

```ini
[nickname]  name = Player1              ; → stable profileID
[hub]       mode = auto                 ; auto | host | join
            relayMode = match           ; match (host runs relay) | fixed
            relayHost =                 ; used when relayMode = fixed (tailnet name/IP)
            basePort  = 47100
[tailscale] autodiscover = true         ; run `tailscale status --json` in the native hub
            peers =                     ; manual seeds: names or 100.x IPs, comma separated
            prefer  = direct            ; warn if a peer is on derp
[net]       iface =                     ; pin interface on multi-homed hosts
            mtu   = 1200                ; tailscale0 is 1280 — do not exceed
[game]      extraArgs =                 ; appended verbatim
            checksumGuard = strict      ; refuse mismatched peers
[debug]     logLevel = info             ; nothing/hook/proto/full
            sigFile = auto              ; auto = keyed by appBinaryChecksum
```

Port map (all overridable): 47100/tcp control (loopback) · 47101/tcp node gossip · 47103/udp
optional L2 broadcast announce · 47110/tcp relay raw · 47111/tcp relay ws · 47112/udp OOB ·
47113/udp `-relayBroadcastPort` (physical LAN only) · 47114/tcp lobby.

---

## 6. Test matrix (v1 acceptance)

| Case | Expectation |
|---|---|
| 2 machines on the **tailnet**, Windows ×2 | co-op vs 6 AI, 60 min, no desync, `PINGNODE=direct` |
| 2 machines on the tailnet, Windows + Proton (native `lanhub-linux`) | same, mixed OS, lobby visible both ways |
| Tailnet with **direct blocked → DERP only** | playable, added latency reported, no desync |
| Restrictive tailnet ACL (allow only 47100–47114) | works; a missing rule produces a clear error, not a hang |
| 3+ nodes, 3-hop gossip | lobby hosted on node C visible on node A |
| Physical L2 switch, no Tailscale | works via 47103 broadcast and/or manual seeds |
| Mismatched `dataChecksum` | lobby hidden + reason shown; join refused |
| Client force-quit at 20:00 | others continue; lobby marked migrated |
| Nickname change | new profile dir (documented behaviour), old dir preserved |
| Restart chain ×5 | no duplicate profile dirs, no port conflicts |
| Windows Defender / EDR on | no detection, no quarantine (proxy DLL + launcher) |

---

## 7. Decision tree at M0

```
M0.1 relay accepts our token?
├── yes  → R2 holds. Build M1 → M2 → M2.5 → M3.
└── no   → choose at M0:
    ├── A. Pre-seed BattleServer with our token via its own config path (cheapest, 1–2 d)
    ├── B. Write `lanrelay` from the captured protocol (2–3k LOC, +7–10 d)
    └── C. Reconsider S3 (local rlink HTTP server) — only if A and B both fail
```

```
M0.2 can LAN hosting start with NO broadcast-discovered relay?
├── yes  → tailnet transport is viable as designed. Proceed.
└── no   → the engine demands a BroadcastListener hit before `starting LAN hosting`:
          synthesise that discovery event inside the shim (feed the LAN relay list directly)
          and keep the tailnet relay address from the login response. +2–3 d, still viable.
          Do NOT reintroduce a broadcast dependency — a tailnet will never carry it.
```

---

## 8. Repository layout (overlay, shipped as a zip)

```
AoE2LAN\
  launcher\        aoe2lan-launcher.exe        (C++/Win32; also runs under Wine)
  linux\           aoe2lan-launcher.sh         lanhub-linux
  bin\             lanhook.dll                 lanhub.exe
  sigs\            <appBinaryChecksum>.json    (hook signatures, per build)
  overlay\         aoe2lan.ini                 README.txt
  tools\           portcheck.exe               sigdump.exe (dev only)
  docs\            LAN_MOD_ARCHITECTURE.md     LAN_MOD_PLAN.md
```

Nothing is written into `resources\`, `widgetui\` or next to `steam_api64.dll`. Install = unzip,
run launcher, point at `AoE2DE_s.exe`. Uninstall = delete folder + the four files copied into the
game dir (`dbghelp.dll`, `aoe2lan.ini`, `lanhook.dll`, log dir).

**Host OS split:** `lanhook.dll` + `BattleServer.exe` run inside the game's environment (native
Windows, or the Proton prefix on Linux). `lanhub` runs **natively** on the host OS — Windows exe or
`lanhub-linux` — because it must call `tailscale status --json` and read the real tailnet interface.
It is reached from inside the prefix at `127.0.0.1:47100`, which Wine shares with the host.

---

## 9. Definition of done for v1

Two people on the same **tailnet** — one on Windows, one on Linux via Proton — launch from the
launcher, click Multiplayer, see a `[LAN]` lobby with 2 human + 6 AI slots, start, and play a full
skirmish to a victory screen without a desync, over the tailnet's direct path, with the game's own
files untouched and no broadcast/multicast dependency anywhere in the chain.
