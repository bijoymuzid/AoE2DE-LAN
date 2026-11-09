# Prompt for the next chat (paste this whole file into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). This is the **session 50 brief**. It supersedes the
session 49 brief. Read `notes/m1-session49.md` first (current state), then
`notes/m1-session48.md` in full, then `PLAN.md` §0–§3, §6.1, §6.2, §6.4 and §17.

Say everything in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

WORKING RULE — obey it every turn: **MEASURE FIRST.** Do not burn time or tokens on long
static reverse-engineering when one instrumented run answers the question. Make each game
run capture the maximum information so runs stay few. Before proposing ANY new hook, check
the target is CLEAN on disk (on-disk `.text` bytes == `gametext.bin`, compared over the
**pdata function bounds**, not a fixed window). "Encrypted" means cannot-HOOK, NOT
cannot-read: `dev/lanhook/gametext.bin` is a dump of the **DECRYPTED** `.text`, so every
function on the §45a ENCRYPTED list is fully disassemblable offline. If the hard way
genuinely raises the chance of the thing working, take the hard way.

Working dir: `D:\Age of Empires II Definitive Edition`. Repo: `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first. At the end run
`/c/WINDOWS/system32/cmd.exe //c 'D:\aoe2lan-repo\sync.cmd' "session 50 - <one line, no parentheses, no colon after NN>"`
(in this shell `cmd /c` must be written as `/c/WINDOWS/system32/cmd.exe //c`, and the
`sync.cmd` path must be in single quotes or bash eats the backslashes). Two "The system
cannot find the path specified" lines from `sync.cmd` are pre-existing noise; it still
commits and pushes.

---

## FIRST ACTION IN THE NEW CHAT: ask me which job I want, A or B

Do not start either job on your own. Your first reply must be a short question:

> Which one do you want to do now — **A** (fix Tailscale) or **B** (the one game run:
> 7 AI plus the 2-member roster test)?

Then wait for my answer and do only that one. Both are described in full below. If I say
"both", do A first, because B's relay measurement is more useful once a tailnet IP exists.

---

## STATE RIGHT NOW (session 49, all committed and pushed)

Priority 1 (a hosted match loads and runs) and Priority 2 (AI in that match) are **DONE —
measured, shipped, gated. Do not reopen them.** The front of the queue is **Priority 3: a
second human joining over the tailnet** (PLAN §W1-c / M2).

Session 49 shipped two of the four Priority 3 steps plus one Proton fix. Commits `533993f`
and later. Full detail in `notes/m1-session49.md`.

- **Step 1, `relayIP` — DONE.** `loginsrv.c` now has `g_RelayIP` plus `relay_ip_init()`,
  called from `loginsrv_start()`. It reads `AOE2LAN_RELAY_IP` once, logs
  `relayIP: AOE2LAN_RELAY_IP <value>`, and falls back to `127.0.0.1` when unset, oversize,
  or containing any character outside `[0-9A-Za-z.:-]` (it is spliced into a JSON string, so
  that check is a trust boundary). `build_host_reply()` emits `g_RelayIP` instead of the
  old literal. `PLAY-stage8-VERBOSE.cmd` sets it to `127.0.0.1`.
  Measured offline three ways: unset → `127.0.0.1`; set to `100.99.88.77` → that value in
  the host reply **and** the join reply; set to `1.2.3.4","evil":1` → rejected, logged,
  fallback. **Not yet measured against a real tailnet IP** — that needs job A first.
- **Step 2, `/game/advertisement/join` — DONE.** There was no handler; the call fell into
  the catch-all `[0,[]]`, an array, which the join-result DTO reader (`0x140572540`) cannot
  parse. The new branch reuses `build_host_reply()` (no second builder, per §48j) by
  handing it a synthetic form body: `hostid=` this machine's own profileID
  (`mk_ids(g_Alias)`), `sessionID=` the lobby being joined, `description=` empty. It logs
  `JOIN: hostid=…&sessionID=…`. Session id is taken from `advertisementid` unless that is
  `-1`, then `sessionID`, then `connect_id`, then `1`.
  `shortcut:` comment in the code names the limit — the member id comes from the last
  login's alias because the join request's own key names are **unmeasured**. No join has
  ever been attempted. The whole body is logged, so the first live join shows the truth.
- **Step 3, `matchMembers` must carry the joiner — NOT DONE.** `emit_advertisement()` still
  hardcodes ONE member. That is correct for co-op-vs-AI (§48e) and wrong the moment a human
  joins. Test the 2-member shape with `work/s48b.py` against a live lobby **before**
  committing to it. That is job B, and it is the only part of job B still open.
- **Also shipped in s49: dead `ncrypt` dependency removed.** Seven NCrypt pointers plus
  `CertCreateCertificateContext`/`CertSetCertificateContextProperty` were resolved at boot,
  never called, and sat in the hard resolve check — one missing Wine `ncrypt` export would
  have killed the shim with `srv: proc resolve failed`. `ncrypt.dll` is no longer loaded.
  No Windows behaviour change (`dbg: cert ok`, `dbg: cred ok`).
- **Step 4, discovery — NOT STARTED, one blocker cleared, one new.** The four browse
  endpoints answer only from this shim's own `g_AdvBody`, so a second machine never sees the
  host's lobby. Rust is now installed on this box (`cargo 1.99.1` at
  `C:\Users\Bijoy\.cargo\bin`, not on the bash PATH yet), `cargo build --release` in
  `D:\aoe2lan-repo\lanhub` works (6 s), and `lanhub/.gitignore` covers `/target`.
  **But `test_walk.py` gives 9/11 here, twice, deterministic**: the two failures are exactly
  the cross-instance gossip pair (`B: FIND sees A's lobby via gossip`,
  `B: JOIN remote lobby`). Everything local passes. So the shim↔lanhub wiring can be built
  and tested on one machine (control port only), but cross-machine discovery is blocked until
  W2's gossip works on Windows — or until we use the file/env shortcut (first two-machine
  proof only, named as a shortcut, not shipped as the design). `lanhub/**` is W2's: report,
  do not edit. Details in §49f.
- **Step 5, the relay needs no work.** Stock `BattleServer.exe` is already proven
  cross-tailnet by W2 (repo commit `a890ab3`, `GAMEDATA` funnelled, derp ~85 ms).
  Do NOT build `lanrelay`.

### Gates, all re-run and passed at the end of session 49

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` (untouched)
- `dbghelp.dll` MD5 **`d5cee0abac99629c36f13407f84985ef`**, identical in the game dir AND
  `dev/lanhook/`. **This build has not been in the game yet — offline gates only.** Backups:
  `.prev-s49b-before` = `bb31158c4dd13ba2706f1334aaf4e5e3` (relayIP + join; the build the
  7-AI run used), `.prev-s49-before` = `fa9330748b0fe297675f44e2828e738d` (s48).
- `hooktest.exe`: `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`, `swapped 68 of 68`
- `AOE2LAN_LIVE=1 srvtest.exe 90` + `C:/Python314/python.exe -X utf8 srvclient.py` → **PASS**
  (run srvclient FIRST, then `work/livetest.py` → **PASS**; livetest needs the advertisement
  srvclient stored, and both need the SAME srvtest instance)
- `srvclient.py` now also asserts the join reply and the `AOE2LAN_RELAY_IP` value; it
  re-logs in as `TestPlayer` before the join test because the expect-100 test posts a login
  body with no `alias=`, which clears the shim's stored alias
- `work/verifydll.py` → **19** HOOKDEF entries, `MSThunk va=0x1407b66f0 … kind=0`,
  `GLog va=0x1407db520 … kind=7`; `dumpbin -IMPORTS` → **KERNEL32.dll only**
- Build warnings are the pre-existing C4090 five, now at loginsrv.c **675/677/679/1986/2017**
- Never launch the game while `srvtest.exe` lives or `127.0.0.1:443` has a **LISTENING**
  socket (`TIME_WAIT` is harmless). Two srvtest instances at once produce
  `ConnectionResetError` in srvclient — that is the trap, not a code bug.

### The session-49 game is closed

The 7-AI run happened in `logs/lanhook-15940.log` and the game is no longer running, so job
B starts from a fresh launch (B1). That run used build `bb31158…`; the current build
`d5cee0ab…` has only passed offline gates.

---

## JOB A — fix Tailscale (operator action; you cannot do it, this shell is not admin)

Tailscale has been down since session 48. Measured facts, do not re-derive:

- Service `tailscale` RUNNING, version `1.102.2`. Two `tailscaled.exe` processes — that is
  **normal**, PID 5392's parent is the service PID 4128.
- `tailscale status --json`: `BackendState: NoState`, `Self.Online: false`,
  `TailscaleIPs: null`, `AuthURL: ""`, `HostName: DESKTOP-64DAV0P`.
- Health: "Unable to connect to the Tailscale coordination server" + "Tailscale is starting.
  Please wait." — and it stays like that for hours.
- The network itself is fine: `tailscale netcheck` completes (UDP true, IPv4
  `118.179.44.73`, UPnP, no captive portal) and `curl https://controlplane.tailscale.com/`
  returns 302. But netcheck printed "No DERP map from tailscaled", i.e. the **daemon** never
  fetched one. So the daemon is stuck, not the network.
- `tailscale up` and `tailscale login` both hang and print nothing.
- `C:\ProgramData\Tailscale\` is not readable without admin, so the daemon logs are unseen.

What to do: give me these commands to run in an **admin** terminal, then wait for my answer.

```
net stop tailscale
net start tailscale
tailscale up
```

If that does not work, reboot and log in from the tray icon. Success looks like
`tailscale ip` printing a `100.x` address. When I give you the address:

1. Put it in `PLAY-stage8-VERBOSE.cmd` as `set AOE2LAN_RELAY_IP=100.x.y.z`.
2. Re-run the offline gate with it (`AOE2LAN_RELAY_IP=100.x.y.z srvtest.exe 40` plus the
   same env on `srvclient.py`) to confirm it reaches the host and join replies.
3. Then a live run: host a lobby and read the `HTTP RESP BODY` for
   `/game/advertisement/host`, confirm the `100.x` address, and confirm the local game still
   connects to its own relay through it (the match must still load — `SendSyncPacketRawMemCopy`).
   Do NOT bundle this with any `matchMembers` change.

Do not write code against an IP you cannot see.

---

## JOB B — the 2-member roster test (7 AI and `nAI` are already CLOSED)

**Closed in session 49, do not redo:** 7 AI works (operator confirmed in the match), and
`nAI` stays `0x2` with 7 AI just as it was with 3 AI — and the same `val=0x2 kind=2 nAI=0x2`
fires at the main menu with no lobby at all. So `nAI` is not the lobby's AI count; it is a
constant field the hook reads. Nothing to fix, and do NOT touch the AISlotPick hook or add AI
to the advertisement (§49c).

What is left is the roster shape, and it needs one live lobby. It does NOT need Tailscale.

**B1. Launch (only if the game is not already up).** Confirm `srvtest.exe` is not running
(`tasklist | grep -i srvtest`) and that `127.0.0.1:443` has no LISTENING socket
(`netstat -ano | grep "127.0.0.1:443" | grep LISTENING`). Kill any leftover `AoE2DE_s.exe`
and `BattleServer.exe`. Then:

```
powershell -NoProfile -ExecutionPolicy Bypass -File "dev\lanhook\work\launch-detached.ps1" -cmdFile PLAY-stage8-VERBOSE.cmd
```

Wait ~45 s, take the newest `logs/lanhook-<pid>.log` (the launcher returns the cmd.exe PID,
not the game's). Nothing needs clicking — the cert consent dialog is auto-clicked in under
100 ms. Healthy boot = `relayIP: AOE2LAN_RELAY_IP 127.0.0.1`, repeated
`TLS: handshake complete (server side)`, `OnAccountEvent: Client is using WebSockets`,
`cert: user-Root registered via API (consent dialog auto-clicked)`,
`VERBOSE: log level byte [0x144356c66] 0 -> 2`. Then `work/livepush.py ping` → `PONG armed=1`.

**B2. Ask me to host.** Multiplayer → Host Game → **7 AI** → sit in the lobby and
**do NOT press Start**. Wait for my "ready".

**B3. While the lobby is idle, A/B the roster shape** (this is step 3, and the channel is
armed before Start — measured in session 49). Capture the real frame first, because the
committed `work/v0-real.json` holds run 15416's sessionID:

```
cd dev/lanhook
C:/Python314/python.exe -X utf8 work/livepush.py get 0 > work/v0-real.json
```

Then push, in this order, and record every verdict (`sent=1 parsefail=N thunkhits=M`):

1. baseline, unchanged: `work/s48b.py base '{}'`
2. two members — build the override from the captured member so the sessionID and the host
   profileID are the real ones:

```
C:/Python314/python.exe -c "import json;m=json.load(open('work/v0-real.json'))[3]['matchAdvertisement']['matchMembers'][0];j=dict(m);j['profileID']=m['profileID']+1;j['teamID']=1;print(json.dumps({'matchMembers':[m,j]}))" > work/ov2.json
C:/Python314/python.exe -X utf8 work/s48b.py members2 "$(cat work/ov2.json)"
```

3. four members (same code path, cheap): repeat with three clones instead of one.
4. control, empty body, to prove the channel still works:
   `work/livepush.py push '[0,"MatchStartMessage",<realPID>,{}]' 2` → must be `parsefail=0`.

`parsefail=0` means the shape parses. It does NOT mean the match started. A push before
Start may or may not load the map; if the lobby leaves, that is a finding, not a failure —
say so and move to B4 with a fresh lobby.

**B4. Then ask me to press Start.** Wait ~2 minutes. Expected within ~70 ms of
`WS PUSH MatchStartMessage`: `AET_MatchStartNotify`, `Sending final pregamehoststate packet.`,
`TComm_Provider_RL::SendSyncPacketRawMemCopy`, `HIT AISlotPick … nAI=0x…`, then
`MSLADDER PARSED - no failure logged, ladder stops`. The process grows to ~3 GB when the map
loads.

**B5. Also confirm the new build boots.** This is the first live run of `d5cee0ab…`. In the
log check `relayIP: AOE2LAN_RELAY_IP 127.0.0.1`, `dbg: cert ok`, `dbg: cred ok`,
`TLS: handshake complete (server side)`, `VERBOSE: log level byte … 0 -> 2`, and that the
match still loads (`SendSyncPacketRawMemCopy`). If `srv: proc resolve failed` appears, the
s49 deletion broke something — restore `.prev-s49b-before` and say so. With 7 AI placed, if `nAI`
tracks the count the s48 reading was a stale or different counter and there is nothing to
fix. Nothing we emit depends on the AI count: AI are host-local simulation, they never enter
`slotinfo` (slots 1–7 stay empty even with 3 AI) and never enter `matchMembers`.

**B6. Only then change code.** If the 2-member shape parses, make `emit_advertisement()`
carry a second member. There is no producer for a joiner yet (that is step 4 / discovery), so
keep it minimal and do not invent a member table with nothing to fill it — say what you
skipped. Test the new shape offline in `srvclient.py` before any live run.

---

## THE TOOLS

`AOE2LAN_LIVE=1` (already in `PLAY-stage8-VERBOSE.cmd`) opens a plain-TCP control channel on
`127.0.0.1:47199` inside the game process.

    livepush.py ping                     -> "PONG armed=1" means a game websocket is live
    livepush.py get [n]                  -> the shim's own built payload n (needs a hosted lobby)
    livepush.py push '<json>' [opcode]   -> push one payload, returns "sent=1 parsefail=N thunkhits=M"
    livepush.py selftest                 -> offline check of the payload shapes
    s48.py                               -> real variant-0 frame + 4-member roster + {} control
    s48b.py <label> '<json>'             -> THE A/B TOOL: override any matchAdvertisement key
    s48b.py <label> --body '<json>'        in the captured real frame and push it live
    keys.py <va> [<va>...]               -> JSON key names a bond reader/writer probes, in order
    livepush.py sweep / bisect / types   -> CLOSED, §46e evidence only, do NOT re-run

**Playbook for the next blocker:** host a lobby, press Start, let it stall or reach the state
you want, then `livepush.py get 0 > work/v0-real.json` and A/B with `s48b.py`. Only relaunch
when the lobby state itself is the variable.

## THE PARSE CHAIN (all readable in gametext.bin; §47b has the full version)

`WebSocketConnection::Process` `0x1406d1160..0x1406d204f` → envelope reader `0x1407a7620` →
dispatch `0x1407a7070` over the 46-node registry at RVA `0x4c9e3e0` → node `0x24` = MSThunk
`0x1407b66f0` → factory `0x1407cdf10` (memcmp's the exact 17 chars `"MatchStartMessage"`,
allocates `0x2c8`, vtable `0x143676890`) → body parser `0x1407b6710`, returns NULL if the body
parse fails. Fallback body parser `0x1407b73f0`. Body writer `0x1407b7220`.

**The WS notification frame is a POSITIONAL ARRAY**, never an object, never `{"messages":[…]}`:

    [ <result:int>, "<m_type:string>", <m_profileID:int64>, { <body> } ]

Body, six optional members in reader/writer order: `ownedAppIDs` +0x08 (`0x14057b600`),
`profileRaces` +0x20 (`0x1407d4300`), `matchStartDate` +0x38 int64 (`0x14039c900`),
`equippedItems` +0x40 (`0x1403e3dc0`), `matchAdvertisement` +0x58 (`0x14056cce0`),
`inProgressChallenges` +0x2b0 (`0x1407d4490`). `{}` alone measures `parsefail=0`.

Advertisement reader `0x14056cce0` / writer `0x14056dda0`, 27 keys in order: `id, steamLobbyID,
goodOldGamesLobbyID, psnPlayerSessionID, psnMatchId, xboxSessionID, hostProfileID, matchState,
description, filteredDescription, visible, mapName, options, isPassworded, maxPlayerCount,
encodedSlots, matchTypeID, matchMembers, observerNum, observerMax, isobservable, observerDelay,
isObserverPassworded, service, matchStartTime, matchRegion, matchRegionLocalized`. We emit 22
(`id` + 21); the five we skip are all foreign-platform lobby ids.

Host/join result DTO: parser `0x140572540`, builder `0x14032f5e0`, members in parser order
`resultCode, gatheringID, relayAuthToken, relayIP, relayPortRaw/WebSockets/OutOfBandSocket
(WORD), relayRegion, yourMatchMembers[], steamLobbyID…, filteredDescription`. Member element
parser `0x14056eb40`, keys `sessionID, profileID, ranking, statGroupID, raceID, teamID, url`,
element size `0x48`. The caller requires `resultCode == 0` AND a non-empty member vector
(DTO+0x78/+0x80), then copies `gatheringID` (DTO+8) into the service as the session id.

Tokenizer helpers: `0x14039b7c0` SkipWhitespace, `0x14039bb50` PeekChar, `0x14039b860`
SkipComma, `0x14039b8e0` IsNull, `0x14039a910` BeginContainer, `0x14039b340` NextKey,
`0x14039b5a0` ScanToken, `0x14039b550` consume-N, `0x14039c900` ReadInt64, `0x14039cc60`
ReadString. Browse-list reply parser `0x140571ae0` (`result`, `advertisements`, `playerRatings`).

## TRAPS (each of these cost a run or a session)

- **`srvtest.exe` also binds `127.0.0.1:443`** and `loginsrv.c` sets `SO_REUSEADDR` before
  bind, so the game can "bind" 443 while srvtest still owns it and the game's log shows ZERO
  handshakes. Always wait srvtest out. Two srvtest instances at once reset connections.
- **`WebSocketConnection::ProcessMessages: message=%s` prints the exact bytes we pushed**
  (hook 4 truncates to 70 chars). READ THAT LINE before believing any payload verdict.
- **`parsefail=0` does not mean success.** It means the frame parsed. `id` was missing for a
  whole session while every verdict read clean. Look for `SendSyncPacketRawMemCopy`.
- **Hook 17 dedupes by format string**, so a running match logs each network line once and
  then goes quiet. Silence after a successful start is normal, not a stall.

## Do NOT

- Do NOT reopen Priority 1 or 2. A hosted match loads and runs with AI; it is gated.
- Do NOT start job A or job B without asking me which one I want.
- Do NOT send the notification as a JSON object, and do NOT wrap it in `{"messages":[…]}`.
  Both are measured rejects. `messages` is long-poll only. Do NOT pursue forcing long polling.
- Do NOT spend time on advertisement or `matchMembers` **key order** (§48c). Presence
  matters, order does not.
- Do NOT remove `"id"` from `emit_advertisement`, and do not change its value away from the
  sessionID without a measurement. `srvclient.py` asserts it.
- Do NOT add AI to `slotinfo` or `matchMembers` to "fix" Priority 2 (§48e and §49c measure
  they already work), and do NOT touch the AISlotPick hook because of `nAI` (§49c closed it).
- Do NOT build `lanrelay`. Stock `BattleServer.exe` is proven cross-tailnet (§48j).
- Do NOT edit W2's files (`lanhub/**`, `linux/**`, `notes/linux-*.md`) — §17.1. `PLAN.md` and
  `README.md` are shared: append only, never rewrite the other worker's section.
- Do NOT re-run `livepush.py sweep`/`bisect`/`types`, and do NOT re-test any §46e shape.
- Do NOT treat "on the §45a ENCRYPTED list" as "cannot be read", and do NOT hook anything on
  it (dispatch `0x1407a7070`, envelope reader `0x1407a7620`, factory `0x1407cdf10`, body
  parser `0x1407b6710`, all six member readers, the `0x14039xxxx` helpers, polling fn
  `0x1406d1160`). `MSThunk 0x1407b66f0` and `GLog 0x1407db520` are CLEAN and stay hooked
  (ids 18 and 17).
- Do NOT change the s45 ladder's stop-on-no-failure rule or add a 4th variant.
- Do NOT re-run a cleanliness check with a fixed byte window — use the pdata bounds (§45a).
- Do NOT re-derive the registry node layout (`r14=[0x144c9e3e0]`, `fn=[r14]`, `next=[r14+8]`).
- Do NOT delete the `srvtest.c` 1 Hz `g_ParseFail` bump, and do NOT let `root_add_silent()`
  skip its `root_present()` re-check.
- Do NOT initialise a `BUF` partially — it is `{char *p; size_t len, cap; int oom;}` and a
  wild `p` crashes the shim thread and takes the whole process with it. Always `BUF b = {0};`
- Do NOT rebuild without a `.prev-*` backup of both `dbghelp.dll` copies first. Verify a
  rebuilt DLL with `verifydll.py` + `dumpbin -DISASM`, never a byte grep. dumpbin lives at
  `"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"`.
  Build with `dev/lanhook/build.cmd` (it stages the DLL into the game dir itself).
- Do NOT re-open the certificate dialog problem, `root_add_silent()`'s blob format, §45e, the
  t=1.2 s exit (§46a), or anything in §45g / §44h / §43h.

Method rules, traps, the encrypted-address list, fast tricks and tooling (`dz.py`, `fn.py`,
`cx.py`, `xr.py`, `work/keys.py`, `work/rrx.py`, `work/clean_s45.py`, `work/s48.py`,
`work/s48b.py`, `srvclient.py`, `livepush.py`, `livetest.py`, `dlgprobe.c`) are in §48, §47,
§46, §45, §44 and `notes/m1-session43.md` — all still in force.
