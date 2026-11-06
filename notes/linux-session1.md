# Linux session 1 — 2026-11-06 — L1 lanhub skeleton

## Environment measured

- Machine: Arch (kernel n/a), 16 cores, 15 GiB RAM.
- Game: RUNE release present, 52 GiB, `AoE2DE_s.exe` + `BattleServer/BattleServer.exe` (3,216,696 B —
  matches PLAN §1) now at `C:\Games\AoE2DE` **inside** the prefix.
- Prefix: `~/Games/aoe/winepfx/pfx`, created with the workspace-local **GE-Proton11-12**
  (`proton run wineboot -u`); wine-staging 11.0, ntsync active. No other Proton/Wine touched.
  `wine cmd /c dir` inside the prefix sees `C:\Games\AoE2DE\BattleServer\BattleServer.exe`.
- Toolchains: no Go; **rustc/cargo 1.99.1**, gcc 16.2.1, python 3.14.9, tailscale 1.104.5 (CLI
  installed; `tailscale ip -4` returned **no 100.x address — tailscaled not logged in yet**;
  needed for L2 and for the cross-tailnet L3 run).

## L1 — lanhub skeleton: DONE

Chose **Rust + serde_json** (brief offered Go/C/Rust; no Go on this box, Rust stdlib has no JSON).
Threads + std::net, no async runtime, no other deps. Binary 706 KiB (release, stripped).

- Control server `127.0.0.1:47100`: HELLO, HOST, UPDATE, FIND, JOIN, LEAVE, PEERS (push), PING.
- Node gossip on `0.0.0.0:47101`: ANNOUNCE / ADVERT / WITHDRAW / PINGNODE, flood with
  `ttlHops-1`, dedup on `ANNOUNCE:<guid>` / `ADVERT:<id>:<seq>` / `WITHDRAW:<id>`.
- New peers are caught up with our local ADVERTs on connect; seeds retry every 2 s.
- FIND hides lobbies whose origin node announced a different `dataChecksum`, with reason (§5.2).

### Spec gaps filled (also in lanhub/README.md)

Framing NDJSON; reply envelope `{reply, ok, error?, ...spec fields}`; ADVERT carries `seq` (so
UPDATE propagates past dedup) and `relayAuthToken` (relay secrets are unchecked lookup keys per
PLAN M0.1, so no token handshake is needed).

### Acceptance run (numbers)

`python3 lanhub/test_walk.py`: two instances (47100/47101 vs 47200/47201), seeded at each other.
**11/11 PASS in 2.3 s** wall: HELLO ×2, HOST, cross-instance FIND via gossip, JOIN remote, JOIN
local (slot 0), PEERS, UPDATE, PING, LEAVE, WITHDRAW propagation. Re-run: same result.

## ageServer (luskaner) review — for the shared pile

Read the repo (AGPL-3.0 — do not vendor code; shapes/semantics only). Useful to W1:
`server/internal/routes/game/login/platformlogin.go` (relayServers encoding),
`server/internal/routes/game/advertisement/getLanAdvertisements.go` (envelope `[0,{},[...]]`,
empty `lanServerGuids="[]"` → return nothing), `server/resources/config/age2/login.json` (RL_*
knobs). Conflicts with our rules: it appends its CA to the game's `certificates/cacert.pem` on
disk (rule 1) and its discovery is broadcast rebroadcast (rule 4). Reference only.

## L2 — peer enumeration: DONE (same session, after tailscaled came up)

Tailscale is up: self `cachyos-x8664-1` = `100.109.201.126`, tailnet `tail9ccab8`.
`lanhub peers` prints all 7 peers; **2 online: DESKTOP-64DAV0P (`100.79.215.72`) and
DESKTOP-HUFTPCO (`100.122.146.107`), both `path=derp` with WARN** (CurAddr empty,
Relay set: bom / sin). Which one is W1's box: **unknown — ask operator.**
Path rule: online + CurAddr → direct; online + Relay only → derp; offline → unknown
(Relay keeps the last-used region even when offline — measured, would have been a
false "derp" report). Ini fallback (`[tailscale] peers`) verified by hiding the CLI
via PATH: prints seeds as `unknown (ini seed)`.
Hub auto-seeds gossip connections to online tailnet peers (§5.4 autodiscover, default
on; `--no-autodiscover` flag; test_walk.py uses it to stay hermetic). L1 walk re-run
after the change: 11/11 PASS.

## L3 (local half) — relay regression harness: DONE

`linux/relay_test.py local`: spawns stock `BattleServer.exe` (in-prefix,
`C:\Games\AoE2DE\BattleServer\BattleServer.exe`) via the workspace GE-Proton with the
M0 port set (`-bsPort 47110 -webSocketPort 47111 -outOfBandPort 47112 -lobbyPort 47114
-relayBroadcastPort 47113 -logLevel debug`), runs both synthetic peers from one process
(builders imported read-only from `notes/bs_live_test.py`), asserts bidirectional
GAMEDATA inside type-0x0A funnels, prints PASS/FAIL, exit 0/1.
Session-5/6 rules baked in: B attaches before session creation, distinct secrets/pidents,
single ADDPEER on intro (5 s backstop), GAMEDATA keepalive every 2 s.

Runs: PASS 8.4 s, PASS 8.4 s (relay up 2.0 s after spawn). Funnel frame carries both
pings coalesced: `0afe02000900412d47442d50494e47020900422d47442d50494e47000000`.
Relay stdout: `linux/bs_relay_linux.log`.

Remaining for L3 full: cross-tailnet run — `relay_test.py relay` (relay only) + `host`
/ `joiner` modes in, windows widened for human coordination (host RJ at +30 s, joiner RJ
at +45 s). W1's box identified by operator: **DESKTOP-64DAV0P = 100.79.215.72**.

### Path measurement (2026-11-06, peer online)

`tailscale ping --c 15` total to 100.79.215.72: **all via DERP(bom), ~85 ms RTT**
(first 181 ms, then 84–90 ms), "direct connection not established" both runs.
NAT punching failing between these two networks (cause unknown — CGNAT either side is
the usual suspect, not measured). PLAN §3.5 says derp is acceptable for lockstep and
must be reported: lanhub reports it. 85 ms is at the GOOD end of the 100–200 ms derp
estimate — BOM relay is geographically close to both ends.

## L4 — launcher: written, acceptance blocked on DLL

`linux/launch.sh` (+ `linux/README.md` with the ufw/tailnet checklist): stages
`AoE2DE-LAN/dbghelp.dll` (gitignored, delivered by W1) into `C:\Games\AoE2DE`, starts
native lanhub, sets `WINEDLLOVERRIDES="dbghelp=n"` + `AOE2LAN_STAGE=8`, execs the game
under the workspace Proton. `bash -n` clean, paths verified. NOT run end-to-end:
launching the game without the DLL proves nothing (MP stays grey) and opens a GUI on
the operator's desktop. Telemetry env knobs deliberately unset — semantics unknown,
H4 owns that in-process.

**Ask W1 for: the current `dbghelp.dll` build, and which tailnet box is theirs.**

### L3 cross-tailnet run: PASS (2026-11-06 18:27)

Setup: relay (`relay_test.py relay`) + host side (`relay_test.py host 127.0.0.1 600`)
on this box; joiner (`relay_test.py joiner 100.109.201.126`) on W1's
**DESKTOP-64DAV0P / 100.79.215.72**. Relay's own connection table showed
`ESTAB 100.109.201.126:47111 <- 100.79.215.72:61981` before the session opened.

Numbers: A's RJ at 18:27:29 (session created), self-ADDPEER 18:27:30,
**B-GD-PING inside a type-0x0A funnel at 18:27:32** (=3 s), B intro relay seen
18:27:33, ADDPEER(B,2) 18:27:33, loop torn down 18:27:38 → **A_saw_B=True, 55
funnels, PASS**. Frame: `0afe01000900422d47442d50494e47000000`.
Path: all traffic via DERP(bom) at ~85 ms — no direct path (NAT punching failed,
cause unknown). The relay does not care; lockstep tolerates it (PLAN §3.5).

Race fixes made during the runs (both pushed): joiner retries RJ every 15 s until
admitted (start order now self-heals), LOBBYPING keepalive during both wait phases
(the 60 s silence timeout applies there too), host window 120 s default / joiner 900 s.
Earlier failures were ours, not the network: (a) relay not yet listening, (b) the
10-minute run's RJ fired 600 s in while the joiner had given up.

Remaining for L3: nothing. W1 should re-run `joiner` once against a live relay to
capture his side's PASS line for the record (his side was not read out).

## Open / next

- L2 done; PINGNODE still replies `path: "unknown"` — wiring it to the peer table is M2 polish.
- Remote JOIN returns `slot: null, peers: []` from the cached ADVERT — documented shortcut; real
  cross-node slot allocation is undefined in §5.2, flag for W1 discussion before M2.
- Node GUID is per-run (not persisted).
- L3 local done; cross-tailnet PASS pending W1 coordination.
