# Session 42 — peerAdd/peerUpdate FIXED; the relay plane is proven good; the remaining blocker is above rlink and we are blind there

Supersedes `notes/m1-session41.md` for everything below. All addresses are VAs unless written `RVA`.
Everything marked MEASURED came from run 5, `logs/lanhook-15584.log` (`PLAY-stage8-AIGATE.cmd`, 3 AI,
Start pressed), plus live localhost probes of the running `BattleServer.exe` with `work/bsprobe.py`,
`work/bsprobe2.py` and `work/bslc.py`; everything else was read from `dev/lanhook/gametext.bin`
(decrypted `.text`) and `AoE2DE_s.exe` `.rdata`. Game exe untouched.

**Code changes this session: one new branch in `loginsrv.c route()`, two new cases in `srvclient.py`,
four new read-only analysis tools in `work/`, no hook changes, no `hooks.asm` changes.**

## 42a. Result, up front

- **§41h N10 DONE and MEASURED.** `/game/party/peerAdd` and `/game/party/peerUpdate` now get
  `{"result":0}`. In run 5 both `WorldwideOnPartyPeerAddAsync - response was not formatted
  correctly` and `WorldwideOnPartyPeerUpdateAsync - …` are **gone from the log**. First time either
  has ever been absent.
- **Priority 1 NOT reached: the match still does not load.** The game sits in the lobby after
  `Match Started`, exactly as before. So peerAdd was a real gap and is now closed, but it was **not**
  the blocker. §41g2's conclusion ("peerAdd is the sole blocker") is **wrong**.
- **Priority 2 not reached** (the match never starts, so the AI never play). The AI dropdown fix from
  §41f is still working: 24 `AISlotLabel` hits and 17 `keepgate` repairs in run 5.
- **The relay plane is proven good.** This retires two long-standing unknowns: M0's "RAW TCP PORT DOES
  TLS, handshake unsolved" and PLAN §6.4's `lanrelay` fallback. Stock `BattleServer.exe` 2.58.0
  speaks **plaintext** on 27012 and **accepts the game's own captured packets**, creating the session
  and the host peer. See §42d.
- **The blocker is above rlink, in the game layer, and we have no instrument for it.** The game-layer
  log function and its writers are encrypted on disk, so they cannot be hooked; our hooks 4/5/13 only
  ever see rlink + schannel + steam. §42e. **§42f has a concrete, cheap fix for that blindness** — it
  is the next thing to do.

## 42b. Gates

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged (re-verified at end of session).
- `hooktest.exe` PASS: `game-image iat walk: swapped 68 of 68`, `post-hook ok (21, 210, 2100, 6)`.
- `srvtest.exe` + `srvclient.py` **PASS**, including the two new lines
  `/game/party/peerAdd reply: {'result': 0}` and `/game/party/peerUpdate reply: {'result': 0}`.
- Staged `dbghelp.dll` MD5 **`475c2ff7a37a382bf5336ac94da70597`**, **247,808 B**, identical in the game
  dir and `dev/lanhook/`. Backup taken BEFORE the build: `dbghelp.dll.prev-s42-before` (both dirs)
  = `a4ab2ba4c4e9d69db27195b4cad2fc6b` (the s41 build). Older backups unchanged.
- `work/verifydll.py`: 17 HOOKDEF entries, kinds 0–6 all present. Unchanged from s41.
- `dumpbin -DISASM` (not a byte grep) confirms the new branch really is in the DLL:
  `0x180012C23 lea rdx,[0x180029100]` = `"/game/party/peerAdd"`, `0x180012C36 lea rdx,[0x180029118]`
  = `"/game/party/peerUpdate"`, then at `0x180012C8A lea rdi,[0x180027B48]` = `{"result":0}` into an
  inline strlen, `call log_resp_head`, `jmp` to `http_respond`.
- No stray processes left: game and all `BattleServer.exe` instances killed at end of session.

## 42c. The peerAdd/peerUpdate reply shape — how it was found, and what it is

**§41h's claim that `ret=0x00007ff648…` in the LogWarn lines is a heap address is WRONG.** It is a
real code address. `VA = 0x140000000 + (ret − game base)`, and the game base is line 3 of every log
(`game base=0x00007ff648750000` in run 5). Applying it:

| warning | ret | → VA | lands in |
|---|---|---|---|
| peerAdd | `0x7ff648a642ca` | `0x1403142ca` | `0x140313810..0x1403149f1` |
| peerUpdate | `0x7ff648a630da` | `0x1403130da` | `0x140312620..0x140313801` |

Both are the instruction right after the `call 0x1402bcb30` that logs
`"%s - response was not formatted correctly: %s"` (`lea rdx,[0x143677510]` at `0x1403142b7` /
`0x1403130c7`). That is the *fastest* route from any warning in the log to its caller and it needs no
new hook — use it first, always.

Those two functions are the generic `WorldwideAsyncJob<T>` completion handler (source path in the
binary: `rlink\internal\service\worldwide\WorldwideAsyncJob.h`; there is a family of ~4577-byte
instances at `0x14030db70`, `0x14030edb0`, `0x140312620`, `0x140313810`, `0x140314a00`, …). Each calls
its own DTO parser:

- peerAdd handler `0x140313810` → `call 0x1404d01b0` at `0x140313ceb`; `test al,al; je` → the warning.
- peerUpdate handler `0x140312620` → `call 0x1404d05a0` at `0x140312afb`.

**Parser `0x1404d01b0..0x1404d059c` (1005 B) reads exactly one member: `"result"`** (string
`0x143677370`). Any other member is skipped (`0x1404d03fb` → next), so a bare `{}` also parses. The
value goes to **DTO+0x30** via the enum reader `0x1404cb930`:

```
1404cb930  call 0x14039b8e0            ; at end of structure? -> keep the existing value
1404cb95f  call 0x14039c900(r8d=1)     ; read a number into [rsp+0x78]
1404cb971  lea rax,[rcx+0x80]; cmp rax,0xff; ja fail    ; must be in [-128,127]
1404cb987  mov [r14], eax              ; store into DTO+0x30
1404cb98a  cmp eax,-1; jl warn         ; valid range is -1..4
1404cb995  cmp eax,4;  jle ok
           warn: "Enum changed on the server PartyPeerAddEvent::Result" (0x143686188) then [r14]=4
```

`0x1404d05a0` is the same 1005-byte shape with `PartyPeerUpdateEvent::Result` (`0x1436861c0`,
reader `0x1404cbcc0`). RTTI confirms the DTOs: `.?AUInfo@PartyPeerAddEvent@RLink@@` at `0x14423ad60`,
`.?AUInfo@PartyPeerUpdateEvent@RLink@@` at `0x14423acf0`.

`0` is the success value: every other rlink reply we already serve uses `"result":0` and parses
(leaderboards `0x14073d890`, advertisement update `0x140579020`, browse `0x140571ae0`), and §31d
established `resultCode == 0` is what the caller of the host reply requires.

**The shipped reply for both endpoints is `{"result":0}`.** The old catch-all `[0,[]]` is a JSON
*array*; the reader wanted an object, which is the whole bug. `loginsrv.c route()`: one new
`else if` for both paths, immediately before the `/game/news/` branch. Nothing else touched; the
catch-all still serves the other 19 caches.

Request side, for the record (all names are `.rdata` strings, xref'd with `work/rrx.py`):
`/game/party/peerAdd` `0x14367bac0`, builder `0x1402e6df0..0x1402e78e0`, op-name ctor `0x1402e6a60`
(`"WorldwideOnPartyPeerAddAsync"` `0x14367baa0`), request keys `match_id`, `profile_ids`,
`statGroup_ids`, `race_ids`, `teamIDs`. `/game/party/peerUpdate` `0x14367bb18`, builder
`0x1402e7e10..0x1402e88d0`, extra key `isNonParticipants`. Neither builder has an `E8` caller — both
are reached through a table (`0x1402e6df0` is stored at `0x143667bd8`, `0x1402e7e10` at `0x143667be8`).
Real bodies from run 5:

```
peerAdd    callNum=35&connect_id=1194088482&match_id=1194088482&profile_ids=[3842241165083521967]
           &race_ids=[-1]&sessionID=1194088482&statGroup_ids=[0]&teamIDs=[-1]
peerUpdate callNum=47&connect_id=…&isNonParticipants=[0]&match_id=…&profile_ids=[…]
           &race_ids=[43]&sessionID=…&teamIDs=[5]
```

`/game/party/*` appears in the logs with only these two paths, so the branch is exactly the scope.

## 42d. MEASURED — the relay plane works, and M0's TLS conclusion is wrong

The game spawns `BattleServer.exe -simulationPeriod 125` (that is the **entire** command line). It
listens on **TCP 27012** and **TCP 27212** only. **Nothing listens on 27112** — `-webSocketPort`
defaults to 0 = disabled — so the `relayPortWebSockets: 27112` our login and host replies advertise is
dead. The session uses `relayIP`/`relayPortRaw` = the LAN-broadcast relay `192.168.0.101:27012`
(this machine's own LAN address; the host request carries `relayRegion=d6238e97-2556-4295-b9db-258a8d6f9f55`,
the GUID from the UDP broadcast).

**27012 is PLAINTEXT.** Probed live (`work/bsprobe2.py`, `work/bslc.py`) against the running relay:

| sent to 27012 | result |
|---|---|
| the game's 194-byte TLS ClientHello, replayed verbatim | nothing (timeout) |
| a 31-byte malformed LOBBYCONNECT | nothing — **this is what fooled the first probe** |
| `u16be(32)` + a well-formed 32-byte LOBBYCONNECT | **the same 34 bytes echoed back** |
| `u16be(36)` + marker=2 (reconnect) | silent; relay logs `Attempt to reconnect to a non-existent sessionID` and disconnects |
| `u16be(24)` + version 4 (no secret) | echoed |
| `u16be(3)` + LOBBYPING `0x14` | silent |

27212 is the opposite: a bare SessionMessage gets **RST**, and a TLS ClientHello gets a fatal alert
`02 28` = handshake_failure(40). The game retries that handshake once per second for 30 s (t=4..33) and
gives up. **Identical in all four runs (8264, 17168, 15584 and the s41 run 3), so it is pre-existing
and not the regression.** The session never uses 27212 for data.

**Framing, proven from the game's own four sends** (`work/bs_pkt1.bin`, `work/bs_pkt2.bin` are the
exact captured bytes): a **u16 BIG-endian length prefix, then the bare SessionMessage**, several per
`send`. All four check out: `0020`+32 and `00b8`+184 = 220 B; `00b3`+179 = 181 B; `02f3`+755 = 757 B;
`0361`+865 = 867 B. Message bodies are little-endian (the prefix is not).

**The game's LOBBYCONNECT, decoded:**

```
15 | 725f2c4700001800 | 1bb61a0193809669 | 00 | 0500 | 00000000 | afb32f8afb615235
     titleID=0x18 (24)  (not the sessionID;  marker ver=5  dataRecvCnt  secret = the profileID
     session48=1194090354  the relay echoes     0            =0           0x355261FB8A2FB3AF
                          regardless of it)
```

**The rest of the sequence, decoded (zlib):** `LOBBYRELAY (0x13) = 13 | fromPeerID | toPeerID | inner`;
inner = `PEERHEADER (0x0f)` with **flagBits = 0x04, which means the subpacket is zlib-compressed**
(`PeerMessage::UncompressSubpacket`, `0x143684560`). Decompressed:

- pkt1 inner = **REQUESTJOIN (0x02)**, addrLen 0, customLen **0x022b = 555** — matches the log's
  `ValidateCustomData: called with 555 bytes of custom data`. The custom data holds the profileID as
  UTF-16LE text, the profileID as u64 LE, and `"AnkerGames"` UTF-16LE.
- pkt2 inner = **ADDPEER (0x06)**, `peerID=1 isHost=1 isLocal=1`.

So the host sends **LC → REQUESTJOIN → ADDPEER(self,host)**, exactly the sequence in
`notes/relay-capture.txt`.

**Replaying those exact captured packets at a debug relay works.** With
`BattleServer.exe -name AoE2LANdbg -simulationPeriod 125 -bsPort 47110 -webSocketPort 47111
-outOfBandPort 47112 -relayBroadcastPort 47113 -logLevel debug`:

```
Server::ProcessPacket: fromPeerID=0 LOBBYCONNECT titleID=24 sessionID=195948557 …
Server::ProcessPacket: fromPeerID=0 LOBBYRELAY fromPeerID=1 toPeerID=1
Server::ProcessPacket: fromPeerID=0 PEERHEADER flagBits=4 ackBits=0 packetNumber=0 …
Server::ProcessPeerMessage: fromPeerID=0 ADDPEER peerID=1 isHost=1 isLocal=1 globalID=9664183880830948884 addressList=[]
***** Title 24 Session 1194090354 STATUS UPDATE *****
Peer: #1, PIDENT:861e1409:5cfc1614
Session:PeerAccepted: New host for session; hostPeerID=1
Socks::PacketSend: socket 9/492 Buffering 179 bytes for later send
```

(the probe's LOBBYCONNECT carried a bogus sessionID but the compressed REQUESTJOIN inside still carried
the game's real one, hence `Session 1194090354`). Client side saw 217 B then 181 B back.

**Conclusion: no `lanrelay` is needed. PLAN §6.4's "use stock BattleServer.exe" holds.**

Corroborating from the game's own log at host time (t=156.969–156.985): `OnlineHostAsync success`,
`Created Matchinfo for sessionID 1194090354`, `starting local hosting`,
`WorldwideAdvertisementService::Process - EVENT_NEWPEER` (r8=1), `hosting - Session is connected`,
`HostAsync - got operation info 0:SessionOperationInfo::SUCCESS`, `HostAsync - completed with
HostResult = 0`, `Publishing Visible match`, `Accepted PlayerReadyRequest; profileID=… isReady=1`.
`EVENT_NEWPEER` can only come from relay traffic, so **the game does receive the relay's replies.**

**Therefore: our recv hook is blind on the relay socket, and "0 recv from 192.168.0.101" in our log
means nothing.** Run 5 has 0 `SOCK WSARecv`, 0 `SOCK iov` and 0 `recv from 192.168.0.101` lines.
`Hook_WSARecv` logs only immediate completions; the overlapped path is logged by
`Hook_WSAGetOverlappedResult` as `SOCK iov`, and an I/O-completion-port reader would be invisible
entirely. `Hook_send`/`Hook_recv` are symmetric otherwise (`iathook.c:704`/`748`), and recvs on 443 and
27212 are logged, so the hook itself works.

## 42e. MEASURED — run 5 timeline, and why the match does not load

- t=13.641 `Adding LAN relay server: 192.168.0.101, GUID d6238e97-…` (UDP broadcast from
  `192.168.0.101:65469`, 56 B: `21 24 00 <36-byte GUID> 09 00 "My Serv…"`, every 10 s until t=144).
- t=156.5–156.99 hosting succeeds (all the lines quoted in §42d). `MessageCounts: … join=1/0, ichk=0/0 …`
- t=156.969/156.985/157.110 the four relay sends. **After t=157.110 the game never sends another byte
  to 27012 for the remaining 90 s.**
- t=157.047 `AISlotPick kind=2 nAI=2`; 24 `AISlotLabel` hits; `keepgate: field -1 -> 0, fix #1…#16`,
  then `17 fixes`. The §41f fix is intact.
- t=157.141 `/game/party/peerAdd` → `{"result":0}` — **no warning**.
- t=187.735 last `WidgetSetEn` of the run: `ButtonStart old=0x10 new=0x14`.
- t=192.750 `SetMatchState - state 1 - updating server`; t=193.328 `/game/party/peerUpdate` →
  `{"result":0}` — **no warning**; t=194.453 `/game/advertisement/updateState state=1`;
  t=194.563 `Sending matchinfo change #181`, `OnStartComplete - detected successful game start`,
  `Match Started - [3842241165083521967 AnkerGames], slot = 0, ranking = 0`.
- **Then nothing.** Zero `WidgetSetEn` after t=187.7 (159 lines total, cap 512 — not capped). Zero
  relay traffic. Zero `TComm_Provider_RL` lines. t=217.407 `MessageCounts: … join=0/2, ichk=0/0 …`,
  then only `hb alive` heartbeats. Operator: "it still sits in lobby".
- `ichk=0/0` in every report — no `INTEGRITYCHECK` ever. `MessageCounts` is built by
  `0x140429270..0x1404296e4` (`SessionMessage.cpp`): 35 message types, name from `0x140429030(type)`,
  counters `[0x144c9e350+4t]` / `[0x144c9e2c0+4t]`, format `%s=%u/%u`. The 4-char names live at
  `0x143684304` (`nudg rchk Peer Thdr ping PPrx rely Pfrg lb_c lb_p cdat cast sorq2 sorq1 endg sorp
  spob acto actr setp rlbc lsim rlbc2 …`). Our hook truncates the line at `deny=`, so the rest is lost.
- `Match Started` is logged once, by `WorldwidePartyService` (`0x1403002c0..0x140301835`), which loops
  the member vector at `[r14+0x310..0x318]` stride **0x210** and logs one line per member. One line ⇒
  one member ⇒ the party holds only the host. That is expected: AI are host-side simulation slots, not
  party members.
- `OnStartComplete` (`0x140543350..0x14054392d`) ends with
  `cmp byte [r15+0x50],0; je <return>` — when the automatcher is not active it returns **without**
  calling `0x140544140` and without logging `"forcing pollcomplete event"`. We did not see that line,
  and `OnHostComplete - automatcher is no longer active` confirms `[0x50]==0`. **This is normal for a
  manual host, not the bug** — do not chase it.
- 26 `not formatted correctly` warnings remain, all other caches: `LeaderboardStatsCache` ×8,
  `CommunityEventsCache` ×4, `NewsCache` ×2, `GetOfflineMessagesAsync` ×2,
  `WorldwideCloudGetTempCredentialsAsync` ×2, plus `SetDataAsync - response was failure: 401` and
  `ExtensionDoExternalCallEvent - response was failure: -47` (those go to the real
  `20.51.14.110`, not to us). PLAN §W1-d. None of them changed between runs.

**So: rlink is fully happy — login, host, session connected, peer added, ready, peerAdd, Start,
Match Started — and the game layer above it does nothing at all.** That is where the blocker is.

## 42f. We are blind above rlink, and here is the cheap way to see

The game layer logs through **`0x140f19210`** with `(rcx = category string, dl = level, r8 = format,
r9… = args)` — e.g. at `0x140eebb6a`:

```
140eebb6a  lea r8, [0x1432813f0]  "Got Advertisement Host event (profileID=%llu, hostResult=%d: %s)"
140eebb73  lea rcx, [0x143264280] "Network"
140eebb7a  call 0x140f19210
```

**`0x140f19210` is ENCRYPTED on disk** (exe bytes `ad ee 58 bb …` vs dump `4c 89 44 24 18 …`), so it
cannot be hooked. Its callees: `0x142d6e2b0` (`_alloca_probe`, clean), `0x142d6e390` (clean CRT),
`0x1402ab8a0` (clean thunk), **`0x1407db520` (CLEAN, 93 B)**, and the two real writers `0x14101b4b0`
(295 B) and `0x14101bb50` (4497 B) — **both encrypted**. That is why not one game-layer string
(`OnMatchEvent/MET_*`, `Got Advertisement Host event`, any `TComm_Provider_RL` line) has ever appeared
in our log, in 42 sessions.

**N13 — the fix: hook the CLEAN `0x1407db520`, caller-filtered to the two sites inside the log
function.** It is a vsnprintf helper (`0x1407db520(buf, size, fmt, …)` → `_vsnprintf` at
`0x1431991d0`), 60 call sites in the whole image, and **exactly two of them are inside the log
function: `0x140f19275` and `0x140f19347`** (measured with `aoe2re.find_calls`). Both pass
`fmt = "[%s] "` (`0x14328534c`), `rdx = 0x1000`, `r9 = the category`.

Why that yields the message: `0x140f19210` does `mov rsi, r8` (the caller's format string) at
`0x140f1924b` and again at `0x140f1931d`, **before** the call. Our `hooks.asm` snapshot (§41f) stores
callee-saved registers at the hooked function's entry, before it pushes anything, so
**`ctx[-7]` = `rsi` = the game-layer format string** and `r9` = the category. That is the §41i rule
working for us: `0x1407db520`'s first instruction is `mov [rsp+0x18],r8`, not a push of rsi, so the
captured `rsi` is the caller's.

- Target `0x1407db520`: clean, 16-aligned, 93 B, prologue
  `4c 89 44 24 18 4c 89 4c 24 20 55 56 57` = `mov [rsp+0x18],r8; mov [rsp+0x20],r9; push rbp; push
  rsi; push rdi`. **`hook_len` 10** (two 5-byte instructions), no rip-relative in them.
- Caller filter: `caller == 0x140f19275 || caller == 0x140f19347` (or the range
  `0x140f19210..0x140f196b0`; the function is split into many small pdata entries —
  `0x140f19210..0x140f1925a`, `0x140f192a0..0x140f192f0`, `0x140f1932c..0x140f19372`, … — so do not
  use `fn.py` bounds for the filter, use the two exact sites).
- Log `category` (r9) + `fmt` (ctx[-7]), deduped on the pair, capped, first-20 s skipped — same
  shape as hooks 15/16. Read-only: it writes nothing.
- We get the format string, not the substituted values. That is still enough to see exactly how far
  the game layer gets (`OnMatchEvent/MET_AddPlayer/R_Success`, `Got Advertisement Host event`,
  `InitProvider`, `connectToGame host=%lld`, `UpdateConnectionState %d -> %d`, …).

**N13b — the alternative, the game's OWN verbose log, is not cracked yet.** The exe has a full logging
system: settings `LOGSYSTEMS` ("The systems that will be logged", registered at `0x140198e10` into
`0x144356d90`), `VERBOSELOGGING` ("Log at verbose depth", `0x140199070` → `0x144356e80`),
`CONSTANTLOGGING` (`0x140198cf0`), `UNIQUE_LOG_FOLDER`, `BUFFEREDLOGGING`, `PROCMONLOGGING`; file base
`aoelog`, patterns `logs\%s.txt`, `logs\%s%.2d.txt`, `%s%s%s.txt`, `%s%s%s%.2d.txt`; runtime strings
`"Verbose Logging is ON/OFF"`, `"Constant Logging is ON/OFF"`, `"%s is being logged"`,
`"Log file %s is opened"`. Category names at `0x143299c68`: CommandLine, ScenarioEditor, AIScript,
**GameFlow**, **UserInterface**, Particle, ObjectRendering, Pathfinding, UserInput, **Networking**,
DirectX, Modding, Locale, UnitGroup, UnitAction, UnitPathing, UnitAI, RandomMapGeneration,
Achievements, SyncMandatory, SyncAI, SyncAction, SyncCommand, SyncGroup, **SyncMatchStart**,
**SyncNetwork**, SyncObject, SyncObstruction, SyncPlayer, SyncRandom, SyncRandomMap, SyncRandomMapVis,
**SyncServer**, SyncTime, SyncUnitAI, SyncVisibility, SyncXS, SyncOther, Telemetry, AllSync.
All are registered in the **"General"** settings group built by `0x1408f9f80`, exactly like the rlink
command args (`FORCE_LAN_WINDOW` at `0x1401733c0`, `FORCE_TEST_SERVERS`, `OVERRIDE_MP_VERSION`, …).
The command-line parser is `0x1408fc0b0..0x1408fc46f`: `GetCommandLineW` → `CommandLineToArgvW`
(IAT `0x1431985d8`) → per argv[1..] wide→narrow (`0x140a89230`) → append the whole string
(`0x140a1b9f0`) to a list, stride 0x18. **No prefix stripping and no name/value split happens there**,
so the split is at lookup time — and I did not find it. `0x1408fc0b0`, `0x140a89230` and `0x140a1b9f0`
are all **encrypted on disk**, so none can be hooked to log argv either.

**TWO ARG SYNTAXES TRIED, BOTH FAILED** (no `aoelog*` anywhere, `Main.txt` unchanged at 46 lines /
1882 B, no `Networking` line in it):

1. `-VERBOSELOGGING -CONSTANTLOGGING -LOGSYSTEMS Networking,GameFlow,CommandLine,UserInterface,SyncMatchStart,SyncNetwork,SyncServer`
   → booted normally (PID 8112), no effect.
2. `-VERBOSELOGGING=1 -CONSTANTLOGGING=1 -LOGSYSTEMS=Networking,GameFlow,CommandLine,UserInterface,SyncMatchStart,SyncNetwork`
   → **exited at t=4.19 s** with a clean boot log (`logs/lanhook-16692.log`, 113 lines, last line
   `cert: user-Root registered`). That is §41i's transient pattern, but it was not relaunched, so
   "the `=` form kills the boot" is **not excluded**. `PLAY-stage8-LOG.cmd` was deleted after this.

The game's own logs are useless as shipped: `C:\Users\Bijoy\Games\Age of Empires 2 DE\logs\<ts>\Main.txt`
is boot-only (46 lines, ends at `endMovieFunction complete`, identical ~1994 B in every run),
`Age2SessionData.txt` is 4 lines, `SlowLog_*` is 19 B. Note the real game-data root is
`C:\Users\Bijoy\Games\Age of Empires 2 DE` — **not** `<Documents>\Games\…` as PLAN §1 says.

## 42g. Next session, in order

1. **N13 — build the read-only hook on `0x1407db520`** exactly as specified in §42f (new hook id 17,
   caller-filtered to `0x140f19275`/`0x140f19347`, logs category + format string, writes nothing,
   opt-in via `AOE2LAN_HOOKS`). Remember §41b: **add any new `HK_*` kind to `work/verifydll.py`'s
   filter or it silently drops the entry.** Then run `PLAY-stage8-AIGATE.cmd` with the new id, host,
   3 AI, Start, and read what the game layer says at `Match Started`. Everything below rlink is now
   known-good, so the answer is in that log.
2. **N13b (only if N13 is not enough)** — find the settings lookup that matches `"LOGSYSTEMS"` against
   the argv list built by `0x1408fc0b0`, to learn the real switch syntax and turn on the game's own
   Networking/GameFlow log. Static reading only; the functions involved are encrypted so they cannot
   be hooked.
3. **N11** — once a match loads, verify the AI actually play (§41h item 2). `session+0xee0` already
   holds the AI list (§40d).
4. **N12** — retire the s38 bit-0x4 suppression? Still unverified; run 5 shows it still firing
   (`ButtonStart old=0x10 new=0x14`, `Team … SUPPRESSED`, `RegicideMode`/`AntiquityMode … SUPPRESSED`).
   Do not remove it until a run shows the rows unlocked without it.
5. **N7** — M2 with a second human, still below the AI work by operator request. Note §42d: the
   tailnet peer must reach **27012/TCP** on the host, and `relayIP` must become the tailnet IP
   (PLAN §W1-c). 27112 is dead unless we make the relay listen there.

**Do NOT:**
- re-open peerAdd/peerUpdate — fixed and measured;
- build `lanrelay` (PLAN §6.4 fallback) — the stock relay accepts the game's own packets (§42d);
- believe "0 recv from the relay" in our log — that socket's read path is not instrumented (§42d);
- chase the 27212 TLS handshake_failure or its 30 retries — identical in all four runs, pre-existing,
  and the session does not use that port;
- chase `OnStartComplete`'s missing "forcing pollcomplete event" — normal for a manual host (§42e);
- hook `0x140f19210`, `0x14101b4b0`, `0x14101bb50`, `0x1408fc0b0`, `0x140a89230`, `0x140a1b9f0`,
  `0x1404d01b0` or `0x140313810` — all encrypted on disk;
- chase who writes -1 into `screen+0x1cf8` (§41e — outvoting it works, 17 repairs measured again in
  run 5); re-open the four-row fix; force `AOE2LAN_AIKIND`.

## 42h. Traps recorded so nobody pays for them twice

- **`aoe2re.xrefs()` is BROKEN and returns `[]` for every string.** It builds its numpy index from a
  strided int32 view (offsets 0,4,8,…) but adds the *element index* instead of the *byte offset*:
  `arr = frombuffer(d, '<i4'); arr += arange(len(arr))`. Use **`work/rrx.py`** instead. It reads
  `xref_i32.npy` correctly: that file is 415,924,328 B = 51,990,525 int64 = one entry per byte offset
  (`len(dump) − 3`), and its value is **`uint32_at(o)`, unsigned, with no offset folded in** — so a
  rip-relative target is `0x140001000 + 4 + signed(IDX[o]) + o`. Verified: rrx.py finds the single
  known xref to `IDS_LOBBY_SCREEN_ERROR_UNEVEN_PLAYERS` (`0x143341be8`) at `0x141a3ca10`, and 167
  sites for `"%s - response was not formatted correctly: %s"` (`0x143677510` — note the `%s - ` prefix
  is part of the same string, 5 bytes before the offset `find_string` reports).
- `work/xgrp.py` scans the 52 MB dump twice per target in pure Python (~2 min each). `work/xgrp2.py`
  and `work/fnstr.py` use rrx/pdata instead. `rrx.py` loads the 416 MB index once, ~2 s.
- `rrx.py`'s instruction back-off can land mid-instruction and print a nonsense mnemonic
  (`adc byte ptr [rip+…], al`) for what is really a `lea`. **The address is still correct** and the
  `fn.py` bounds derived from it are what matter — don't "fix" the mnemonic.
- **The LogWarn/LogHelper `ret` field IS a code address** (§42c). `VA = 0x140000000 + (ret − base)`.
  §41h said it was a heap address; that cost a session.
- A malformed probe packet proves nothing: LOBBYCONNECT must be exactly 24/28/32/36 bytes
  (`notes/bs_client.py` header). The first probe built 31 and concluded "the relay ignores plaintext".
- **`BattleServer.exe` accepts `SO_REUSEADDR`: a second instance binds the same ports with no error
  and stays alive**, so pre-spawning a debug relay does NOT stop the game's own instance — both listen
  and connections are distributed between them. To get only yours, kill by command line (the one
  *without* `-logLevel`). `-help` lists only 4 flags but `-logLevel debug`, `-bsPort`,
  `-webSocketPort`, `-outOfBandPort`, `-relayBroadcastPort`, `-name` all work. BattleServer writes no
  log file; debug goes to **stdout** — redirect it.
- `pktmon` needs admin and this shell is not admin: no packet capture. Everything in §42d came from
  application-level probes plus the relay's own debug log.
- The launcher returns the **cmd.exe** PID, not the game's (§41i). Run 5's launcher said `Pid=7268`,
  the game was 15584; the `=`-args launch said `Pid=176`, the game was 16692. Always take the newest
  `logs/lanhook-<pid>.log`.
- `find -newermt` lists `AoE2DE_s.exe` as recently modified even when its MD5 is untouched — the
  timestamp is from an earlier session's copy. Trust `md5sum`, not mtime.

## 42i. Files added this session (all read-only analysis, nothing in the DLL)

| file | what it is |
|---|---|
| `work/rrx.py` | correct rip-relative xref finder over `xref_i32.npy`; `--ctx=N` disassembles around a site |
| `work/fnstr.py` | list pdata functions in a VA range with clean/encrypted status and their string refs |
| `work/xgrp2.py` | `xgrp.py` rewritten on rrx (fast); groups xrefs by containing function |
| `work/bsprobe.py` | port probe: does a BattleServer port speak TLS or plaintext (first version — its LOBBYCONNECT was malformed, kept only for the TLS/ClientHello part) |
| `work/bsprobe2.py` | the corrected probe: u16-BE framing, well-formed LC, the game's exact ClientHello |
| `work/bslc.py` | field-by-field LOBBYCONNECT variants against a live relay, bogus sessionID so it cannot touch a real one |
| `work/bs_pkt1.bin`, `work/bs_pkt2.bin` | the game's exact captured 220 B and 181 B relay sends |
| `work/f_0x1402e6a60.txt` … `work/f_0x1408fc0b0.txt` | the disassembly dumps this session's findings came from |

Changed: `loginsrv.c` (one branch), `srvclient.py` (two offline cases). Deleted: `PLAY-stage8-LOG.cmd`
(the arg syntaxes it tried are recorded in §42f and neither worked).
