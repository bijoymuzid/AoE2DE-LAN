# Session 48 — SOLVED: a hosted match loads and runs. The missing key was `id`

Supersedes `notes/m1-session47.md`. All addresses are VAs unless written `RVA`.
Two game runs (`logs/lanhook-15416.log` = the run that cracked it,
`logs/lanhook-14620.log` = the clean end-to-end confirmation). Game exe
untouched (`affb19f03ca96965abf9e56775cab688`). DLL rebuilt once →
**`fa9330748b0fe297675f44e2828e738d`**.

## 48a. The answer

**`matchAdvertisement` must carry `id`.** That single key was the whole of
Priority 1.

Without it the frame still parses, `MSThunk` still fires, `AET_MatchStartNotify`
still logs — and the lobby simply never leaves. No sync packets, no scenario,
nothing but heartbeats. Every §47h diagnostic line stays silent, which is why
§47h's four outcomes did not include the real one: **a body that parses cleanly
and is then quietly acted on to no effect.**

With `id` present the same frame takes the game straight into the lockstep layer.
Measured A/B on one live lobby, 257 s apart, one key different:

| t | frame | result |
|---|---|---|
| 282.9 | shim variant 0, 1717 B, 21 adv keys | `parsefail=0 thunkHits=1`, `AET_MatchStartNotify`, then **nothing for 257 s** |
| 539.9 | identical + `"id":1194243939`, 1733 B, 22 keys | `parsefail=0 thunkHits=1`, `AET_MatchStartNotify`, `Sending final pregamehoststate packet.`, `SendSyncPacketRawMemCopy`, `AISlotPick nAI=0x2`, `ProcessPackets`, sync keep-alives — **map loaded, operator confirmed AI playing** |

The quiet window between the two pushes was verified empty (only `hb alive`,
`MessageCounts` and one `RLEVENT long update time`), so nothing but the added key
changed.

**Fix shipped:** `emit_advertisement()` now opens with `"id":<sessionID>`. The
game's own `advertisementid` equals the `gatheringID` we issue as host reply, and
we set that to the `sessionID`, so `sid` is the correct value with no new state.

## 48b. The clean end-to-end confirmation (run 14620, no livepush)

Rebuilt DLL, fresh launch, operator hosted + Start. The shim's own ladder did it
unaided, 63 ms end to end:

```
t=129.390  MSLADDER pushing variant=0
t=129.390  WS PUSH MatchStartMessage len=1741
t=129.453  OnAdvertisementEvent/AET_MatchStartNotify result=%d date=%lu session=%ls
t=129.453  Sending final pregamehoststate packet.
t=129.453  TComm_Provider_RL::SendSyncPacketRawMemCopy PKT=%d/%s (%u bytes; total now %llu)
t=129.468  HIT AISlotPick #148965 ... val=0x2 kind=2 nAI=0x2
t=132.453  MSLADDER variant=0 parsefail=0 thunkHits=1 / MSLADDER PARSED - ladder stops
```

Game process grew to 3.0 GB (from 2.1 GB in the lobby) and stayed alive with
`BattleServer.exe` up. **Priority 1 is DONE.**

## 48c. Correction to §47b/§47f/§47i: advertisement key ORDER does not matter

§47b asserted "NextKey skips a member that did not match in turn, so key order
can silently drop fields", and §47f reordered `emit_advertisement` accordingly.
That reading was wrong. Read out of `gametext.bin`:

Reader `0x14056cce0` (and the `matchMembers` element reader `0x14056eb40`, same
shape) is a **name cascade that restarts for every key**:

- one `NextKey` (`0x14039b340`) at the top, then a chain of per-field blocks in
  declaration order;
- each block is `IsNull` (`0x14039b8e0`, literal `null` → consume + SkipComma)
  → in object mode, compare the *current* key against this field's name char by
  char → on match consume `"key":` and read the value → fall into the next block;
- **on mismatch it falls into the next block without consuming anything**, so the
  same key is tried against the next expected name;
- the tail (`0x14056f64a` / `0x14056f68d`) calls `NextKey` and `jmp`s back to
  `0x14056eba9`, i.e. the cascade restarts at the first field for every key.

So any permutation parses, and unknown keys fall through the whole cascade and
are skipped. Confirmed live: the working s48 push had `id` first (reader order)
while the shim emits it first too — but a reordered frame would have worked.

The s47 reorder is harmless and stays. **Do not spend another session on key
order.** What is load-bearing is *which keys are present*.

`matchMembers` element keys, in the order reader `0x14056eb40` probes them
(`work/keys.py 0x14056eb40`): `sessionID, profileID, ranking, statGroupID,
raceID, teamID, url`. Element size `0x48`. Our `profileID`-first order is fine.
§47h's suspicion that `matchMembers` element shape was the next blocker is
**closed — it was never broken.**

## 48d. Method that won it: reuse a live lobby as a test bench

The game keeps its rlink websocket **armed after Start** (`livepush.py ping` →
`PONG armed=1` at t=539 s, 257 s into a stalled lobby). So a single run supports
unlimited A/B pushes of modified frames against real lobby state — no relaunch,
no re-hosting, ~4 s per hypothesis.

New tools:

- `work/s48.py` — pushes the shim's real variant-0 frame, a 4-member-roster
  variant, and the `{}`-body control, at the main menu.
- `work/s48b.py <label> '<json>'` — loads `work/v0-real.json` (the REAL frame
  captured from a live lobby via `livepush.py get 0`), applies overrides to
  `matchAdvertisement` (or `--body` for the six body members), re-emits in reader
  order and pushes. This is the tool that isolated `id`.
- `work/v0-real.json` — the captured 1717-byte real frame (real base64+zlib
  `encodedSlots`, real `sessionID`). Prefer it over `v0-s48.json`, which is
  srvtest's synthetic equivalent.

**Playbook for the next blocker:** host a lobby, press Start, let it stall, then
`livepush.py get 0 > work/v0-real.json` and A/B with `s48b.py`. Only relaunch
when the lobby state itself is the variable.

## 48e. Priority 2 (AI) — largely moot, one open number

§46f's premise was that the AI never reach the match because the game's own
`slotinfo` has slots 1–7 empty. Re-measured on the real lobby this session —
still true, the decoded `encodedSlots` is unchanged:

```
header '12', 8 slots
  slot 0: pid=3842241165083521967 station=1 team=0 faction=0 race=0 isReady=1
  slots 1-7: pid=-1 station=-1 team=1..7 faction=-1 race=-1 isReady=0
```

**And the AI work anyway.** The operator confirmed the map loaded with AI
playing, while the advertisement we pushed still carried that empty-slot blob and
a single `matchMembers` entry. So AI are host-local simulation, not network
peers, and they do not need to be in `slotinfo` or `matchMembers` for a
single-machine co-op match. `emit_advertisement()`'s hardcoded single member is
**not** the blocker §47h suspected — leave it alone for co-op.

Open, unknown: the operator set **3** AI but every `HIT AISlotPick` reports
`nAI=0x2 val=0x2 kind=2`, in both runs, before and after Start. Either the hook
reads a different counter than the lobby's AI count, or one AI is not being
counted. Needs an operator answer (how many AI are visibly in the match?) before
any code touches it. Priority 2 for M2 (a second human joining) is unaffected —
that path needs `matchMembers` to carry the joiner, which is Priority 3 work.

## 48f. Gates (current build — all re-run, all passed)

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged.
- `dbghelp.dll` MD5 **`fa9330748b0fe297675f44e2828e738d`**, identical in the game
  dir and `dev/lanhook/`. Backup taken BEFORE the build:
  `.prev-s48-before` = `cc68c98ec43e6fcb38a0aa5c6906fb16` (the s47 build).
- `hooktest.exe`: `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`,
  `swapped 68 of 68`.
- `AOE2LAN_LIVE=1 srvtest.exe` + `srvclient.py`: **PASS**, now
  `update reply: result=0, advertisement keys=22` (was 21),
  `MatchStartMessage push: 774B` (was 758B), `ladder variant1 empty-body: 46B`,
  `ladder variant2 advert-only: 666B` (was 650B), `ladder terminated after
  variant2`; plus `work/livetest.py`: **PASS**.
- `work/verifydll.py`: **19** HOOKDEF entries; `MSThunk va=0x1407b66f0 … kind=0`;
  `GLog va=0x1407db520 … kind=7`.
- `dumpbin -IMPORTS` → **KERNEL32.dll only**.
- Build warnings are the pre-existing C4090 five, now at loginsrv.c
  **690/692/694/1928/1959** (moved from 1921/1952; the new comment block shifted
  them).

## 48g. Next session

**Priority 1 is closed. Priority 3 is now the front of the queue** (PLAN §W1-c /
M2): a second human joining over the tailnet.

1. **`relayIP` is still `127.0.0.1`** in the host reply — measured again this
   session at t=74.4 of run 15416. A remote peer cannot connect. It must become
   this machine's tailnet IP. This is the known, named blocker.
2. Then `findAdvertisements`/`getLanAdvertisements` must show the lobby to the
   second machine, and `join` must reserve a slot and add a **second**
   `matchMembers` entry. That is the one place where §48e's "single member is
   fine" stops being true — a joiner is a network peer, not host-local AI.
3. `work/s48b.py` is the tool for step 2: host on machine A, and A/B the
   joiner's `matchMembers` shape against the live lobby before committing to it.

Cheapest first measurement for Priority 3: on the host, with a second machine on
the tailnet, change only `relayIP` and see whether the peer's relay connect
reaches `BattleServer.exe`. Do not bundle it with the `matchMembers` change.

Still open and untouched: the `nAI=0x2` vs 3-AI question (§48e), and the six
advertisement keys we still do not emit (`steamLobbyID`, `goodOldGamesLobbyID`,
`psnPlayerSessionID`, `psnMatchId`, `xboxSessionID` — all platform ids, all
irrelevant on LAN; `id` was the seventh and it was the one that mattered).

## 48h. Do NOT (new, on top of §47i / §46i / §45g / §44h / §43h which all still hold)

- Do NOT spend time on advertisement or `matchMembers` **key order**. §48c proves
  the readers are name cascades that restart per key. Presence matters, order
  does not.
- Do NOT remove `"id"` from `emit_advertisement`, and do not change its value
  away from the sessionID without a measurement. It is the only thing that makes
  the match load. `srvclient.py` asserts it.
- Do NOT add the AI to `slotinfo` or `matchMembers` to "fix" Priority 2. §48e
  measures that AI already work with both empty. Answer the `nAI=0x2` question
  first.
- Do NOT chase §47h's four diagnostic lines any more. None of them fires for a
  frame that parses and is silently under-specified — that failure mode is
  invisible to `parsefail`, and `SendSyncPacketRawMemCopy` is the line that says
  a match really started.
- Still in force: no JSON-object or `{"messages":[…]}` envelope on the websocket,
  no forcing long polling, no re-running `sweep`/`bisect`/`types`, no hooking
  anything on the §45a ENCRYPTED list, no fixed-window cleanliness checks,
  `BUF b = {0};`, `.prev-*` backups of both `dbghelp.dll` copies before any
  rebuild, never launch while `srvtest.exe` lives or 443 has a LISTENING socket,
  and read `ProcessMessages: message=%s` before believing any payload verdict.

## 48i. Files added / changed this session

| file | what changed |
|---|---|
| `loginsrv.c` | `emit_advertisement()` opens with `"id":<sessionID>`; the s47 key-order comment replaced with the s48 finding (cascade, order irrelevant, `id` load-bearing); reader key list in the header comment gained `id` |
| `srvclient.py` | asserts the pushed advertisement carries a numeric `id` |
| `work/s48.py` | **new** — pushes the real variant-0 frame + a 4-member roster + the `{}` control |
| `work/s48b.py` | **new** — A/B tool: override any advertisement or body key in the captured real frame and push it into a live lobby |
| `work/v0-real.json` | **new** — the real 1717-byte frame captured from live lobby 15416 |
| `work/v0-s48.json` | **new** — srvtest's synthetic equivalent (shape proxy only) |
| `work/f_matchmember_elem.txt` | **new** — disasm of the `matchMembers` element reader `0x14056eb40` |
| `dbghelp.dll` (both copies) | rebuilt → `fa9330748b0fe297675f44e2828e738d` |

Unchanged on purpose: the hook table (19 entries, ids 4/5/13/14/15/16/17/18
active), the s45 3-variant ladder and its stop-on-no-failure rule, `srvtest.c`,
`build_match_start()`'s positional array, the cert auto-clicker, the live channel
protocol, `registry_dump()`.

## 48j. Priority 3 groundwork, measured this session (do not re-derive)

Cheap checks run after the confirming run, so the next session starts from facts:

- **Tailscale is installed but NOT connected.** Service `RUNNING`, version
  `1.102.2`, `HaveNodeKey: true`, but `BackendState: NoState` and `tailscale ip`
  → `no current Tailscale IPs; state: NoState`. The Tailscale adapter has only a
  link-local IPv6, no `100.x` address. **Nothing in Priority 3 can be measured
  until the operator logs Tailscale back in.** This is an operator action, not code.
- **The relay layer is already proven cross-tailnet — by W2, not by us.** Repo
  commit `a890ab3`: "L3 cross-tailnet PASS — relay + host on Arch, joiner on
  DESKTOP-64DAV0P, B-GD-PING at RJ+3s (55 funnels), derp 85ms". `linux/relay_test.py`
  runs it; `notes/linux-session1.md` §L3 has the detail. Tailnet IPs seen there:
  `100.122.146.107`, `100.79.215.72`, path `derp` ~85 ms. So stock
  `BattleServer.exe` accepts two remote peers and funnels `GAMEDATA`. PLAN §6.4's
  "if it validates LOBBYCONNECT.secret (unknown)" is answered: it does not block us.
- **`lanhub` exists and passes its acceptance walk.** Rust, `lanhub/src/main.rs`,
  `lanhub/test_walk.py`: "11/11 PASS in 2.3 s — HELLO ×2, HOST, cross-instance FIND
  via gossip, JOIN remote". Control `127.0.0.1:47100`, gossip `:47101`. W1 has not
  wired the shim to it yet.
- **`relayIP` is one hardcoded literal**: `loginsrv.c:1551`,
  `bs(b, ",\"relayAuthToken\":\"lan\",\"relayIP\":\"127.0.0.1\"")` inside
  `build_host_reply()`. Ports beside it: raw 27012, ws 27112, oob 27212.
- **There is NO `/game/advertisement/join` handler.** The router
  (`loginsrv.c:1779..1895`) covers login/readSession/leaderboards, `host`,
  `update` (prefix-matches `updateTags`+`updateState`), the four browse endpoints,
  `party/peerAdd`+`peerUpdate`, `news`, then a catch-all empty success. `join` and
  `leave` currently fall into the catch-all.
- **Head start on the join reply:** the comment at `loginsrv.c:1531` records that
  the *host* call parses its answer with the **join-result DTO** (parser
  `0x140572540`, DTO built by `0x14032f5e0`), members in parser order:
  `resultCode, gatheringID, relayAuthToken, relayIP, relayPortRaw/WebSockets/
  OutOfBandSocket, relayRegion, yourMatchMembers[], steamLobbyID…,
  filteredDescription`. So `build_host_reply()` already emits the shape a join
  reply needs. Member element parser is `0x14056eb40` — the same reader §48c
  dumped (`sessionID, profileID, ranking, statGroupID, raceID, teamID, url`).
- **The browse list only ever returns this machine's own lobby.** `g_AdvBody` is
  filled by `host`/`update` on this shim, and `getLanAdvertisements`/
  `findAdvertisements`/`getAdvertisements`/`findObservableAdvertisements` all
  answer `{"result":0,"advertisements":[<g_AdvBody or nothing>],"playerRatings":[]}`.
  A second machine runs its own shim with its own empty `g_AdvBody`, so it will
  never see the host's lobby. **That is the discovery gap, and it is what `lanhub`
  is for.**
