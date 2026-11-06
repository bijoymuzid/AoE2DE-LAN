# lanhub

Native lobby hub for AoE2LAN (PLAN.md §4, §5). One process, two plain-JSON-over-TCP
protocols, zero broadcast/multicast — discovery is unicast gossip between seeded peers,
because a Tailscale tailnet carries neither.

## Build & run

```sh
cargo build --release
./target/release/lanhub [--control-port 47100] [--node-port 47101] \
                        [--nick Player1] [--peer 100.x.y.z:47101 ...] [--ini aoe2lan.ini]
```

Reads `[hub] basePort`, `[tailscale] peers`, `[nickname] name` from `aoe2lan.ini`
(PLAN §5.4); CLI flags win over ini.

## Test

```sh
python3 test_walk.py
```

Spawns two seeded instances on one machine and runs the L1 acceptance walk
(HELLO → HOST → FIND → JOIN, plus UPDATE / PEERS / PING / LEAVE / WITHDRAW).

## Wire conventions (spec gaps we had to fill)

PLAN §5.1/§5.2 fix the verbs and fields; these are the choices we made where it is silent:

- **Framing:** newline-delimited JSON — one complete object per line, both protocols.
- **Envelope:** request has `"type": "<VERB>"`; replies carry `"reply": "<VERB>"`,
  `"ok": true|false`, `"error"` on failure, then the spec'd fields at top level.
- **profileID:** FNV-1a-64 of `"aoe2lan:" + nick` (PLAN R3), as a JSON number.
- **ADVERT additions:** `seq` (monotonic per lobby, so UPDATE re-floods past dedup) and
  `relayAuthToken` (BattleServer treats secrets as unchecked lookup keys — PLAN M0.1 —
  so no out-of-band token exchange is needed).
- **Gossip dedup keys:** `ANNOUNCE:<guid>`, `ADVERT:<id>:<seq>`, `WITHDRAW:<id>`.

## Known limits (skeleton, L1)

- Remote JOIN is answered from the cached ADVERT (`slot: null, peers: []`); real slot
  allocation across nodes needs a join round-trip §5.2 does not define. M2 work.
- `PINGNODE` replies `path: "unknown"` until L2 wires `tailscale status --json`.
- A node GUID is random per run (not persisted); duplicate seed pairs can hold two
  connections (one per direction) — harmless with dedup, cosmetic.
- No reconnect backoff cap, no auth on the node port (tailnet ACLs own that, §3.6).
