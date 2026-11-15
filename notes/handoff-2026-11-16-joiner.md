# Handoff 2026-11-16 — joiner (Windows) side + what changed on the host

Read this top to bottom before touching anything. It is self-contained: state,
the exact build to run, the driller checklist, and how to read the next log.
Longer history: `AGENT_LOG.md` (repo root's parent on the host machine) and
`notes/m1-session*.md` / `notes/linux-session*.md`.

Host and joiner are two physical machines on a Tailscale tailnet:

| role | machine | tailnet IP | game |
|---|---|---|---|
| host (lobbies) | Linux + Proton | `100.109.201.126` | `AoE2DE_s.exe` |
| joiner | Windows | `100.79.215.72` | `D:\Age of Empires II Definitive Edition\` |

Re-check both IPs with `tailscale ip -4` before a session; they are not fixed.

---

## 1. Do this now (joiner machine)

1. **Fully quit the game** (and its launcher). A loaded DLL cannot be replaced on
   Windows — copying over a running game *silently fails*, which has already cost
   two sessions.
2. Copy the new `dbghelp.dll` into
   `D:\Age of Empires II Definitive Edition\dbghelp.dll`.
   Build identity:
   - md5 **`560d26387adc1fcebafd23e85065678a`**
   - size **272384 bytes**
   Verify, from PowerShell in that folder:
   ```powershell
   Get-FileHash .\dbghelp.dll -Algorithm MD5    # must print 560D26387ADC1FCEBAFD23E85065678A
   (Get-Item .\dbghelp.dll).Length              # must print 272384
   (Get-Item .\dbghelp.dll).LastWriteTime       # must be the time you just copied
   ```
   The DLL is **not in git** (`*.dll` is git-ignored) — it is ferried as a file.
3. **Leave your existing PLAY `.cmd` alone.** Your log line
   `relayIP: AOE2LAN_RELAY_IP 100.109.201.126` and
   `hook filter: only 4:LogHelper,5:LogHelper2,13:LogWarn,14:WidgetSetEn,...`
   show the two things that matter are already right. Only requirement on top:
   `AOE2LAN_NOKW=1` must be set (kernel watchpoints crash this machine's game
   ~1.8 s after arming; the DLL logs `KW: disabled by env` when it is honoured).
   If `100.109.201.126` is no longer the host's tailnet IP, fix
   `AOE2LAN_RELAY_IP` in the `.cmd` first.
4. Launch, go to Multiplayer, refresh the lobby list, join the host's lobby.
5. Send back the newest `logs\lanhook-*.log` (the same folder you have been
   sending from). Do not trim it.
6. **The first thing to check in that log: it must contain `REMOTEFIND:` lines.**
   If it does not, the new DLL did not load — back to step 1. This is the whole
   point of this build: no build before it ever logged that stage.

---

## 2. What was broken and what changed (this session)

### 2.1 The join never started (root cause, proven from the joiner's log)

Joining fails with *"lobby no longer exists"* / `R_MatchExpired`, `JoinResult=2`,
and the host sees **zero** `/game/advertisement/join` requests. Sequence in
`lanhook-14088-136099718.log` (joiner machine):

```
t=67.016s  HUB browse: remote lobbies=1                    <- lobby WAS served
t=71.735s  HTTP REQ /game/advertisement/getAdvertisements?match_ids=[1194768206]
t=71.938s  HTTP RESP BODY {"result":0,"advertisements":[],"playerRatings":[]}
t=71.938s  HUBFILTER: dropped 8 stale-relay entries        <- nothing left
```

The host-lobby list that the browser shows and the list the join-click re-reads
are the same route family, so the lobby flickered: present at one poll, gone at
the next. The join click does its own refresh, got an empty list, and the game
aborted before sending `/join`.

### 2.2 Fix 1 — `hub_remote_find` cache (`dev/lanhook/loginsrv.c`)

A joiner has no local lobby, so every browse pulls the live list straight from
the **hosting machine's** lanhub control port (`AOE2LAN_RELAY_IP:47100`,
`{"type":"FIND"}`). That fetch occasionally came back empty. Now:

- every stage of the fetch logs: `REMOTEFIND: connect failed | send failed |
  empty reply | reply bytes=N | entries=N`;
- successful entries are **merged** (never replaced) into a 60 s cache with a
  per-entry timestamp, oldest slot evicted;
- every browse serves the cache, so a fetch that fails, or that returns only
  a dead leftover, cannot empty the join refresh;
- cached entries still pass `HUBFILTER`, so they disappear as soon as their
  `relayRegion` GUID is no longer a live BattleServer.

Merge (not replace) matters: the host hub can legitimately return only stale
entries for a moment, and a replace-style cache would be poisoned by that.

### 2.3 Fix 2 — republish by `UPDATE`, not leave+host (`dev/lanhook/loginsrv.c`)

`AdvPushThread` re-published the hosted lobby every 5 s with `hub_leave()` +
`hub_host()`. The host log had **245** such pairs, each minting a **new
advertisementID**, so:

- the lobby was withdrawn and re-inserted 245 times (measured gap on the hub:
  7 ms — the join failure above was that gap *plus* a failed direct fetch);
- every cycle floods a new ad id at the peer's hub, which is one source of the
  ~8 zombie lobby entries the joiner's own hub accumulates (the hub mesh never
  expires entries).

`hub_republish()` now sends `{"type":"UPDATE","advertisementID":<same>,
"patch":{"body":<fresh form body>}}` and only falls back to leave+host when the
hub answers `ok:false` (i.e. the hub was restarted and lost the id).

Proven against a scratch hub (ports 48100/48101):

```
HOST   -> advertisementID 07699495a1f219a8dec575a26fc6d2ad
FIND   -> n=1, id_match=True, body=sessionid=111&x=1
UPDATE -> {"ok":true}
FIND   -> n=1, same_id=True, body=sessionid=111&x=2, relayIP preserved
UPDATE unknown id -> {"error":"unknown advertisementID","ok":false}   (fallback)
```

And live on the host after the restart: the same advertisementID across two
`FIND`s 6 s apart (`7e66dc56…`, `sessionID=1194769634`).

**Not changed on purpose:** the game's `/game/advertisement/update` route still
does leave+host, so a lobby-settings change can mint one extra ad id (same
`sessionID`, deduped by the joiner). Cosmetic; fix it only if it causes trouble.

---

## 3. Architecture in one page

- `dbghelp.dll` is a proxy next to `AoE2DE_s.exe`. It hooks the game's HTTP stack
  and DNS, redirects every relic host to a TLS server it runs **inside the game
  process** on `127.0.0.1:443`, and answers the whole relic API locally.
- Lobby discovery: `lanhub` (Rust, control `:47100`, node gossip `:47101`) is
  asked for lobbies and gossiped to the peer. The node mesh between the two
  machines is unreliable (the joiner's hub drops our floods), so the joiner's DLL
  ignores the mesh and pulls from the host hub directly: `FIND` on
  `AOE2LAN_RELAY_IP:47100`.
- The advertisement body's `relayRegion` must be the **live BattleServer GUID**
  the joiner hears on UDP 9999 beacons. The host's `AdvPushThread` injects it
  (`adv_patch`) when the game omits it. `beaconrelay.py` on the host forwards the
  game's 56-byte beacons to the joiner so it keeps that GUID. Do not kill it.
- `HUBFILTER` drops any lobby whose `relayRegion` GUID is not in the joiner's
  live `lanServerGuids` list (that list comes from its browse query). This is
  what removes the joiner hub's dead-host zombies.
- The join reply names the host's BattleServer address; the joiner connects to
  `relayIP:port` where `relayIP` is the host's `AOE2LAN_RELAY_IP` (its tailnet
  IP). That is why the host must run with its tailnet IP, not `127.0.0.1`.

---

## 4. Facts that are already settled — do not "improve" them

Verified over multiple clean sessions (details in `AGENT_LOG.md`):

1. `GET /game/relationship/getRelationships` must answer **8 elements**:
   `[0,[],[],[],[],[],[],[]]` — one error code plus **7** empty array slots, per
   ageLANServer's `relationshipResponse()`. 9 elements fails. Objects in slots
   fail. The game calls this repeatedly (`callNum=` rises); each answer logs
   `RELSHAPE n=1 cand=1 callNum=…` on the host.
2. `getPresenceData` is served **verbatim** from ageLANServer's captured
   `age2` asset (`PRESENCE n=3 body=age2 signed asset verbatim`).
3. Stats, `setPresence`, login, party peerAdd/peerUpdate, `getProfileName`,
   beacon forwarding: all fixed earlier; do not touch.
4. The kick is not a parse error. With every response shape clean, the host
   still kicks the joining peer ~**10.4 s** after the join, **4 ms** after the
   peer's PlayerReadyRequest: `KICKSEND 00`, then `6b` ×2, then
   `peerremove reasonID=1000 (0x3e8)`.
5. `ageLANServer`'s own `Relationships()` fills `lastConnection` with *other
   online users'* `profileInfo` for AoE2 — hence the content theory below.

### The kick theory being tested

`AOE2LAN_REL=<n>` on the **host** pins which relationship-response candidate is
served (no rebuild needed, one host restart each):

| `AOE2LAN_REL` | candidate |
|---|---|
| 1 | 8-slot envelope, all slots empty (proven parse-clean, still kicked) |
| 2 | same envelope + the joiner's `profileInfo` row in the `lastConnection` slot (slot 6) |
| 3 | joiner row in the friends slot (slot 2) |
| 4 | both slots filled |

The joiner's profileID is `2949963597078017023` (`mk_ids("AmiEktamc")` reproduces
it; it appears verbatim in her login body). **cand=2 has never actually been
tested** — every attempt since it was built died earlier in the flow (in the
lobby-list flicker above).

Next: get one join through, then watch the host log for `RELSHAPE … cand=2` and
`KICKSEND`. No kick for 2+ minutes = the content theory is right, then test
pressing **Start** (match-start relay is untested). Still kicked → host restart
with `AOE2LAN_REL=3`, then `=4`.

If all of 1–4 fail, the remaining work is game RE: the kick decision site is
upstream of the ready-processing. Chain already mapped (base `0x140000000`):
`0x40d0xx` peer-message processing (calls validators `0x643440`, `0x643670`,
`0x643a20`) → recursive peer-message dispatcher `0x1407976e0` (tail-call dispatch,
entered at `0x6434a7` and `0x6439e8`) → packet builder `0x63fca0` (IAT send at
`0x6402ca`, returns to `0x6402d0`). Type switch at `0x643fe1`: message types 6 and
7–10 route to the sender. Tools: `dev/re/disasm.py <dump> 140000000 <rva> …`,
`dev/re/scan_calls.py`. The dump is not in git: it is `/tmp/aoe_text_*.bin`
produced by `kill -USR1` on `supervise.py`.

---

## 5. Reading the next log (in this order)

| line | meaning / what to do |
|---|---|
| `lanhook v2 boot in …` | DLL loaded at all. No such line = it never loaded. |
| `relayIP: AOE2LAN_RELAY_IP <ip>` | must be the **host's** current tailnet IP. |
| `KW: disabled by env` | `AOE2LAN_NOKW=1` honoured (required on the Windows machine). |
| `REMOTEFIND: connect failed` | the joiner cannot open TCP to `host:47100`: tailnet down, host hub dead, or wrong `AOE2LAN_RELAY_IP`. |
| `REMOTEFIND: send failed` / `empty reply` | TCP opened but the hub said nothing: hub not listening, or host game/hub restarted mid-flight. Retry on next browse is automatic. |
| `REMOTEFIND: reply bytes=N` then `entries=N` | the fetch worked; `entries=0` means the *host hub* has no lobby (host is not hosting, or its AdvPushThread stopped). |
| `HUBFILTER: dropped N stale-relay entries` | expected (peer hub zombies). If the served list is empty *and* the live lobby was among the dropped, its `relayRegion` GUID is stale on the joiner side: beacons not arriving (check `beaconrelay.py` on the host). |
| `HUB browse: remote lobbies=N` | N lobbies actually served to the game this poll. |
| `RELSHAPE n=… cand=… callNum=…` (host side) | relationship candidate served; confirms which `AOE2LAN_REL` is active. |
| `KICKSEND`, `peerremove reasonID=1000` (host side) | the kick still happens — record the time delta after the join. |

Two things that always look broken but are not:

- the joiner's own lanhub showing ~8 stale lobby entries (zombies from dead host
  sessions; the mesh never expires them) — `HUBFILTER` hides them;
- the joiner's hub dropping our mesh gossip floods (direct `FIND` is used
  instead). Do not spend time on the mesh.

---

## 6. Host-side runbook (Linux machine, for reference)

```bash
# build (cross-compiles the Windows DLL with clang/mingw here)
cd AoE2DE-LAN/dev/lanhook && ./build.sh          # -> AoE2DE-LAN/dbghelp.dll, prints md5

# deploy: NEVER truncate a loaded DLL; move the old inode away, then copy
G=~/Games/aoe/winepfx/pfx/drive_c/Games/AoE2DE
mv -f "$G/dbghelp.dll" /tmp/dbghelp.old && cp -f AoE2DE-LAN/dbghelp.dll "$G/dbghelp.dll"

# hub (bind 0.0.0.0:47100 control, 0.0.0.0:47101 node; HUBCTL_LOOPBACK=1 = loopback only)
cd AoE2DE-LAN && nohup ./lanhub/target/release/lanhub --ini aoe2lan.ini >/tmp/lanhub.log 2>&1 &

# beacon forwarder: host UDP 9999 -> joiner UDP 9999 (needed for the relay GUID)
nohup python3 dev/re/beaconrelay.py 100.79.215.72 >/dev/null 2>&1 &

# game (restart): wineserver -k MUST target the prefix, bare -k hits ~/.wine and does nothing
WINEPREFIX=~/Games/aoe/winepfx/pfx \
  "$HOME/Games/aoe/Proton-CachyOS Latest-x86_64_v3/files/bin/wineserver" -k
cd AoE2DE-LAN/dev/re && AOE2LAN_REL=2 nohup python3 supervise.py >/tmp/supervise.log 2>&1 &
```

Notes: `supervise.py` stays as the game's ancestor so `/proc/<pid>/mem` stays
readable, and dumps `.text` on `SIGUSR1`. Every host game restart changes the
BattleServer GUID, so the joiner must restart **after** a host restart (its
beacon-derived GUID list has to match, or `HUBFILTER` drops everything).

Watch the host log:

```bash
grep -E "RELSHAPE|RelationshipCache|KICKSEND|peerremove|NEWPEER|HUB |REMOTEFIND" logs/lanhook-*.log
```

---

## 7. Open items

1. One clean join to get the `cand=2` verdict (blocked only on the joiner loading
   this DLL and a lobby existing on the host).
2. If kicked: `AOE2LAN_REL=3`, then `=4` (host restart each, no DLL change).
3. If all candidates fail: the kick-decision RE from §4.
4. Untested: pressing **Start** (match-start relay) and actual gameplay.
5. Cosmetic, unfixed: `/game/advertisement/update` still does leave+host (§2.3).
6. Known-unfixed elsewhere: `supervise.py` warm-up is a 1 s sleep; an earlier
   "5255B early exit" regression wants ~8 s before the BattleServer starts.
7. Two-game-on-one-machine harness is **not** set up. Blockers: the DLL hardcodes
   `127.0.0.1:443` (`loginsrv.c:3132`) and the DNS redirect hardcodes
   `127.0.0.1` (`iathook.c:825`) — it needs an `AOE2LAN_BIND` knob in both
   places, plus a second WINEPREFIX (a second instance in the same prefix shares
   the alias ⇒ same profileID ⇒ the hub cannot tell the two peers apart).
   `127.0.0.2:443` does bind on the host, so it is feasible, not proven.