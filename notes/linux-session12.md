# Linux session 12 (2026-11-13) — cross-machine lobby discovery wired (todo #8, M2 phase 1)

**Bottom line.** loginsrv.c now talks to the local lanhub (127.0.0.1:47100): lobbies you host are gossiped to peer machines, and lobbies peers host appear in your game's server browser. Both directions verified live on one machine with a second hub simulating the Windows box. A real join attempt against a real second machine is still untested — that is next session's work (see §12e). Committed as `2cf723f`, pushed to origin/main.

Decision record: the operator asked whether loginsrv should be rewritten in Rust (folded into lanhub). Answer: yes eventually (coupling is exactly two calls from lanhook.c:459-460; rustls kills ~600 lines of SChannel machinery; crash isolation), but NOT before #8 — the C increment was ~200 lines while a Rust port must replay all ~15 endpoints perfectly before adding anything. Rust rewrite = weekend project, and it gets *safer* after the join protocol is measured live.

## 12a. What was built

**lanhub (`lanhub/src/main.rs`):**
- `HOST` accepts an optional `relayIP` — loginsrv sends its `g_RelayIP` (the machine's LAN IP), so the gossiped advert carries the address remote games must dial. Falls back to the hub's own tailnet/loopback IP for bare-control clients.
- New control verb `FINDRAW` — deliberately NOT single-line JSON. Reply is `OK <n>\n` then n lines of `<relayIP>\t<formbody>`, one per REMOTE lobby (`local: false`; a node's own lobby is served by its in-process server, so no double-listing). The body is the host machine's raw advertisement request body, stored verbatim as `lobby: {"body": ...}` at HOST time — that is the format loginsrv's `emit_advertisement` already eats, so zero translation exists anywhere. Bodies are form-encoded (no raw `\n`/`\t`); hub sanitizes anyway.

**loginsrv.c hub client** (all in the "lanhub client (M2, #8)" block):
- One-shot TCP client: `hub_open` (127.0.0.1:47100, SO_RCVTIMEO 2000 ms), `hub_send`, `hub_line` (byte-at-a-time line read). An absent hub is an instant loopback refuse — single-machine play is byte-for-byte unchanged and needs no kill switch.
- host handler → `hub_leave()` (previous lobby must not linger in the mesh on re-host) then `hub_host(body)`; the hub's hex `advertisementID` reply is flat-scanned into `g_HubAdvId`.
- leave handler → `hub_leave()` → hub withdraws + floods WITHDRAW.
- browse handlers (getLanAdvertisements / findAdvertisements / etc.) → `hub_browse(resp, already)`: sends FINDRAW, replaces the remote-lobby table wholesale (`g_RemId/g_RemRelay/g_RemBody`, 8 slots, spinlock), appends each as an advertisement with the host's REAL sessionID as `id` — no fake-id mapping exists; the id the game sees IS the session the join must name.
- join handler → `remote_lookup(sid, relay)`: on a hit, `build_host_reply` gets `relayOverride = <hosting machine's IP>` and `useAdvId = 0`. **Two latent bugs were pre-empted here:** `build_host_reply` and `emit_advertisement` unconditionally overwrote the id with the local `g_AdvId`, which on a machine that both hosts and joins would have clobbered the join's gatheringID and every remote advert's id. Both now take an explicit `useAdvId` flag.

**launch.sh:** `AOE2LAN_RELAY_IP` auto-detects the egress LAN IP (`ip -4 route get 1.1.1.1 ... src`); empty when offline → loginsrv falls back to 127.0.0.1. Env var still wins if set.

## 12b. The one real bug found this session

`hub_send(s, "{\"type\":\"FINDRAW\"}\n", 18)` — the literal is 19 bytes, so the `\n` never went out, the hub waited forever for a complete line, and every browse ate the full 2000 ms timeout and merged nothing. Diagnosed from the log, not the code: `HTTP REQ getLanAdvertisements` at t=147.393, `HTTP RESP` at t=149.395 — exactly 2.000 s = the SO_RCVTIMEO signature. Fix: `strlen_f(req)` — never hand-count string literals.

## 12c. Verification evidence (all on one machine, hub B = simulated Windows)

- Hub plumbing (pre-game): `HOST` on B with `relayIP=192.168.1.250` → ADVERT gossip → `FINDRAW` on A returns `192.168.1.250\thostid=123456789&sessionID=777000111&...`.
- Browse merge through the REAL game process: `curl -k -X POST https://127.0.0.1/game/advertisement/getLanAdvertisements` returned the remote lobby as a full advertisement DTO (`"id":777000111,"description":"TestLobbyFromWin","mapName":"Arabia",...`), and the lanhook log shows `HUB browse: remote lobbies=1`.
- Host direction through the real game: curl'd `POST /game/advertisement/host` → `HUB host ok, advertisementID=949e935d...` → `FINDRAW` on B shows the Linux lobby.
- Leave direction: curl'd `/leave` → `HUB leave: lobby withdrawn` → both hubs `OK 0`. Mesh left clean.

Startup race seen twice and misdiagnosed once: a backgrounded lanhub prints its banner (after bind) but a python client 2 s later can still get ECONNREFUSED; the retry works. Don't trust the first connection attempt in test scripts.

## 12d. Open items for the real two-machine test

1. **Join request body keys are STILL unmeasured.** The join handler's fallbacks (`advertisementid` / `sessionID` / `connect_id`) are guesses; the first live join dumps the real body (`JOIN:` line + log_body_head). Highest-value artifact next session.
2. **Match-start notify to remote joiners is NOT wired.** `AET_MatchStartNotify` reaches only the local game's WS (loginsrv pushes on the updateState arm). A remote joiner will likely sit in the lobby when the host presses Start. Fix sketch when measured: host loginsrv → host hub control → gossip → joiner hub; joiner loginsrv polls its hub (e.g. on the ws_serve ping tick) and pushes MatchStartMessage locally. Not built yet on purpose.
3. **Friend-side kit:** prebuilt `dbghelp.dll` in repo root (md5 `50cd832b...` this session) + `lanhub.exe` (`cargo build --release` on Windows, or cross `x86_64-pc-windows-gnu`; main.rs already carries Windows fixes) + `aoe2lan.ini` `[tailscale] peers=<my ip>` + `AOE2LAN_RELAY_IP=<friend's LAN IP>` env. Firewall both sides: TCP 47101 (gossip), UDP 9999 (beacons), TCP 27012/27112/27212 (BattleServer relay).
4. **This machine is 192.168.1.9 now** (enp3s0, DHCP). The handover from s11 said the Windows box was .9 — stale. Verify both IPs on game day (`ip -4 -br addr`).
5. Windows-side SChannel/cert path is unexercised on real Windows (developed under Wine). Most likely first-boot surprise there.
6. ufw: operator owns the rules. TCP 47101 inbound from LAN still needs adding (only UDP 9999 was decided last session).

## 12e. Next session shape

Friend online, Tailscale up both ends (autodiscover seeds the hubs; plain-LAN ini peers are the fallback). Order: (1) he sees my lobby in his browser, (2) I see his, (3) he joins — read both logs, fix what the join body shows, repeat, (4) then measure the Start-press gap and wire the match-start relay. His log: newest `lanhook-*.log` next to `AoE2DE_s.exe`, collected after a NORMAL menu-quit (kill loses the tail).
