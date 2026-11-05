# M0 state save — 2026-11-01, end of session 3 (JOIN handshake DECODED — see bottom)

## Session-3 headline (read this first tomorrow)
- REQUESTJOIN solved end-to-end: `02 | u16LE addrLen+addrList | u16LE custLen+customData |
  u64LE (titleID<<48|sessionID48) | u64LE PIdent`, sent NESTED in a PEERHEADER
  `0F | 15 raw bytes | <inner msg>` (flagBits bit 0x04 must stay clear).
- ALL multi-byte fields are LITTLE-ENDIAN, not BE — see corrections below.
- Session-row creator FOUND: `SessionManager::OnPeerRequestJoin` (FUN_1400ea680) news
  the WWBS::Session(0x938) keyed (titleID u16, sessionID u64) when the FIRST peer
  sends REQUESTJOIN. No lobby/mysql/DB involved. Both A and B just:
  ws-connect → LOBBYCONNECT(marker=0,v5) → PEERHEADER+REQUESTJOIN → (host: ADDPEER) → GAMEDATA.
- `notes/bs_client.py` now has `join [pident]` and `admit <peerID> <gid>` subcommands
  plus exact builders. Full decompiles in `notes/bs_peerjoin.c`.
- GAMEDATA relay (FUN_1400e2e00) walks the session+0x890 peer vector, which is filled
  by ADDPEER (type 6) from the host — REQUESTJOIN alone does NOT put you on the relay
  list. So the full p2p sequence needs the host to admit the joiner with ADDPEER.

## What M0 is
M0 = the "Proof" phase from PLAN.md §9. Four experiments, all analysis, no product code:
- M0.1: does stock `BattleServer.exe` accept a session whose token we invented?
- M0.2: can LAN hosting start from login-provided relayServers alone, no broadcast?
- M0.3: are `TComm_Provider_RL` + `Worldwide*Service` singletons swappable at runtime?
- M0.4: capture a stock relay session (pcap + notes/relay-capture.txt).

## Status per task
- M0.1: ~85%. Session creator narrowed to one candidate (lobby CONNECT path +
  TLS listener); blocked on TLS handshake mechanics, but a PROVEN cleartext path
  exists (websocket). See session-2 notes below. **PAUSED here — resumes in next
  chat with the two-machine tailnet test (friend's machine expected).**
- M0.2: 0% code, but the engine-side question advanced: `-lobbyPort` is NOT a
  listener, and no broadcast/lobby traffic is needed (see below).
- M0.3: 0% + one BIG structural finding (see "game-side navigation" below).
- M0.4: 0% (websocket gives us the capture path now).

## Next session (friend's machine online tomorrow)
0. Read "Session-3 headline" above, then:
1. `tailscale status` — confirm the peer is online; note direct vs DERP path.
2. Start relay on M0 ports on this machine (binds 0.0.0.0 → peer reaches it at
   100.79.215.72:47111). Keep it in the foreground with log to notes/bs_server.log.
3. Two-machine join test with the NEW `join` subcommand:
   - A (host, this machine): `python notes/bs_client.py join`
   - B (friend): `python bs_client.py join bbccddeeff0002` (any distinct pident)
     with HOST edited to 100.79.215.72, SAME sessionID (default 0x1122334455667788).
   - Watch server log for `ProcessPeerMessage: fromPeerID=... REQUESTJOIN` (join
     accepted) and `PEERHEADER ...` lines. Attach was never actually proven (see
     corrections) — a real parse shows as these log lines, silence = parse fail.
   - If B's join registers but GAMEDATA doesn't relay: A sends
     `python notes/bs_client.py admit 2 bbccddeeff0002` (ADDPEER for B), then
     re-send GAMEDATA (`join` already sends one; or rerun join on A).
   - Cross-check: does B receive A's `M0JOIN-ping-...` frame? That's the p2p relay.
4. If the 15-byte PEERHEADER header needs real values (packetNumber/ackBits),
   capture the real game's join via loopback relay + ws proxy (M0.4) or adjust
   from live behavior (server logs `PEERHEADER flagBits=%x ackBits=%x ...`).
5. Only after two-script relay works: think about real-game calling (M1+).
   Do NOT jump to the hook DLL before the wire path is proven.

## Environment facts learned
- Python is `C:\Python314\python.exe` (no `python3` on PATH). pefile + capstone 5.0.7 installed.
- Compiler: MSVC 14.44 at `C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/bin/Hostx64/x64/cl.exe`
  (also a second toolchain copy at `/c/msvcbin` — cl.exe, link.exe, dumpbin.exe, undname.exe).
- REA MCP providers unavailable (no Ghidra/kuna/IDA/Hopper on this box) →
  installed our own: `tools/ghidra/ghidra_11.3.2_PUBLIC` (11.3.2) + `tools/jdk-21.0.13+9`
  (Temurin 21). Ghidra headless works; decompiler works on BattleServer.exe.
- Tailscale: was `BackendState: Starting / NoState` at session 1 (root cause found
  session 2: node was LOGGED OUT, no stored profile). **Operator logged in during
  session 2 — tailnet is UP.** Self: `100.79.215.72 desktop-64dav0p`
  (bulbulmuzid16@, windows). Tailnet roster 2026-11-01 (all peers offline at
  last check except where noted):
  `100.109.201.126 cachyos-x8664-1` (linux, offline 2d), `100.114.135.101
  cachyos-x8664` (linux, offline 106d), `100.108.57.55 desktop-ghv74pp`
  (windows, offline 94d), `100.122.146.107 desktop-huftpco` (windows, offline 2h),
  `100.66.161.35 desktop-nqtaq9s` (windows, offline 48d), `100.96.12.26 gunbeat`
  (windows, offline 88d), `100.92.42.99 laptop-l2rltq37` (windows, active via
  DERP relay "sin", last seen 9h). Two-machine test needs one peer online;
  this machine's relay binds 0.0.0.0 so it is reachable at 100.79.215.72:47111
  with zero config change.
- /tmp = C:\Users\Bijoy\AppData\Local\Temp (may be wiped on reboot).

## Ghidra projects (redo cheaply if /tmp is wiped)
- BattleServer, FULL analysis: /tmp/ghproj, project TestProj, program `BattleServer.exe`
  (sha256 941a6d084e55521477b967afe0077bc176d7b4b4e02cee4619fa5f5040e61b89).
  Import+analyze took ~98 s. Redo: `analyzeHeadless /tmp/ghproj TestProj -import BattleServer/BattleServer.exe`
- AoE2DE_s.exe (72 MB), PARTIAL analysis: /tmp/ghproj7, project AoEProj, program `AoE2DE_s.exe`.
  Full auto-analysis does not finish in 20 min; imported with DISABLED heavy analyzers via
  `-preScript DisableHeavy.java` + `-analysisTimeoutPerFile 1200`, saved with strings+refs done
  (395 MB). Redo: same command as session used (see notes below). Program address space:
  image base 0x140000000, .text 0x140001000-0x143196000, sections are .text/.rodata/.rdata/.data/.pdata/_RDATA/.rsrc/.reloc.
- Scripts (all in tools/ghidra_scripts/): FindByString.java `<substr> [refsOnly]`,
  Decompile.java `<addr...>`, Disasm.java `<addr>`, Inspect.java `<symbol-substr>`,
  Vftable.java `<addr> [count]`, XrefsTo.java `<addr>`, DisableHeavy.java (prescript).
- Ghidra quirk: `(GhidraScript)` lines pollute output; filter with grep. `launch.properties`
  JAVA_HOME_OVERRIDE is set to a /d/... path that Ghidra's launcher warns about but headless runs fine.
- NOTE: FindByString relies on auto-analysis defined-data (strings). It works on BattleServer;
  on AoE2DE_s.exe it should work for strings (String analyzer runs early) even in the partial DB.

## M0.1 findings: BattleServer wire (Ghidra decompiles in notes/bs_*.c)
- Banner ports = (rawTCP -bsPort, webSocket -webSocketPort, outOfBandUDP -outOfBandPort).
  Default run printed `27012,0,27212`. Websocket port answers `Server: WebSocket++/0.8.2`.
- RAW TCP PORT DOES TLS. Accept thread (FUN_1400d8c80 "raw SockBind port %u failed") creates an
  SSL socket; ReadSome/DoHandshake stage (FUN_14008cb80 "Shutting down lobby socket") runs before
  any packet parse. Plain-TCP LOBBYCONNECT probes are swallowed silently (verified: no log lines).
  Certs: "LoadEmbeddedSSLCertificates" (embedded blob) with `-sslKey` override; "Error loading SSL Certificate".
- Once TLS yields bytes, packets parse in Server::ProcessPacket (FUN_1400de050, notes/bs_ProcessPacket.c):
  cursor uses available()=vftable+0x20 / dataAt()=vftable+0x10 / consume(n).
- Message types observed in switch: 9 GAMEDATA, 0x0F PEERHEADER, 0x10 PROXY, 0x13 LOBBYRELAY,
  0x14 LOBBYPING, 0x15 LOBBYCONNECT, 0x17/0x18/0x1A/0x1B/0x1C/0x1D/0x1F, else "!!!Unknown message type %d received!!!".
- LOBBYCONNECT layout (LobbyConnectMessage::unpack FUN_1400efe50):
    u8 0x15; u64 BE (titleID<<48 | profileID_low48); u64 BE sessionID; u8 0x02;
    u32 BE timeoutOverride; u16 BE clientMessageVersion;
    if version>4: u32 BE dataReceivedCount, u64 BE secret. Total len must be exactly 24 or 36.
  PEERHEADER (FUN_1400f1160): u8 0x0F + 15 raw bytes + reliable-range sub-parse, must consume ALL bytes.
  GAMEDATA (case 9): u8 flag must be 0xFE, u16 BE len, that many bytes, must end exactly.
  Python client draft: notes/bs_client.py (`probe` subcommand sends 4 LOBBYCONNECT variants).
- Session admission (FUN_1400eb5f0, notes/bs_OnPacket.c): lookup by (titleID, sessionID);
  NO comparison of secret against a registered value anywhere (secret is a lookup/replacement key,
  "OnReplacePeerSocket ... secret="; marker==0 + existing session = full socket replacement;
  marker==2 + no session = ignored reconnect, no creation). So an invented token is structurally
  FINE — the only question is who creates the session row.
- Open: session-row creator. Candidates: lobbyPort service (note: -lobbyPort 47114 REFUSED TCP
  connections in our test — maybe UDP, or binds only when a game hosts, or needs -lobbyPort plus
  something else), OOB UDP 47112, or the login plane. Next: decompile around the "Session ended"
  function FUN_1400e2050 callers / SessionManager FUN_1400e9e90 + 0x1400eae60, or capture live traffic.
- Game-side client module confirmed in AoE2DE_s.exe strings:
  rlink\internal\relay\battleserverrelay\battleserverrelay.cpp
  ("BattleServerRelay::Start ... m_maxSilenceUntilReconnectMS", "-sslKey",
  "Unable to write [%i] bytes to the socket for the battle server", "Sending connection test message").
  Login-response connect spec fields (one struct block): webSocketPort, rawSocketPort,
  connectionToken, outOfBandSocketPort; advertisement block: relayAuthToken, relayPortRaw,
  relayPortWebSockets, relayPortOutOfBandSocket, relayIP. Client log line shared both directions:
  "type%u=%u/%u ... SrcP#:%u DstP#:%u Size%u nowMS:%llu sessionID:%s secret:%s reconnectState:%u
  clientMessageVersion: %u timeoutOverride:%u". 29 SessionMessage subclasses in RTTI.

## Session-2 findings (2026-11-01, second half)

### BattleServer startup/config map (FUN_1400d1310 parse → 0x1400d2f40 factory → 0x1400d6790 Server ctor)
- Banner = raw,websocket,outofband ports only; usage text lists 4 CLI flags
  (-name/-simulationPeriod/-bsPort/-relayBroadcastPort) but the parser accepts MANY
  more key=value options: lobbyHost, lobbyPort, clusterName, observerUpdateIntervalMS,
  publicIP, publicPort, bsPort, uploadVia, lobby|mysql|odbc, muninLog, muninReportDelay,
  serverLog(deprecated), logFileCount/Size(deprecated), simulationPeriod, plus from the
  config-name table: region, allowTimeoutOverride, webSocketPort, outOfBandPort,
  sslCert, sslKey, name, help (file 0x240200-0x240260 area).
- lobbyPort is a CONNECT target, not a listener: `-lobbyPort 47114` binds NOTHING
  (TCP refused, UDP = ICMP unreachable). Live test with a fake lobby listener on
  127.0.0.1:47114 + `-lobbyHost 127.0.0.1 -lobbyPort 47114` → NO outbound connection.
  Config-struct copy chain: [rsi+6]=relayBroadcastPort (used as broadcast port on
  255.255.255.255), [rsi+0xf0]/[rsi+0x118]→[rdi+0x230/0x232] ports; lobbyHost string
  is stored at Server+[0x178] but NO runtime reader of [server+0x178] was found in
  .text (only the dtor frees it, FUN_1400d72f0). So in this build `lobbyHost`/`lobbyPort`
  are parsed-and-stored-but-unused: the relay does not phone home by default.
- Raw listener init = FUN_1400d8b70 (called from Server ctor 0x1400d6b74/0x1400d6c61):
  SockCreate → SockBind(port=[cfg+0]) → SockListen. Web listener similar (init fn
  0x1400d724f region, `-webSocketPort 0` disables websocket; log 'web SockBind port
  %u failed'). SockAccept (0x1400dd450) is PLAIN accept (no TLS inline): new
  client object + vtable call 0x1400d61e0; TLS is a layer above (TlsConnection).
- Nobody listens on UDP (47112/47113/27212 all ICMP-unreachable) and nothing
  listens on the lobby port — so this build's relay = TCP raw + websocket only.
  `uploadVia` select: lobby(2)=not wired, mysql(1)→MySqlUpload, odbc(3)→replay
  upload disabled path. Replay upload needs DB creds → stays disabled (good).

### TLS on bsPort: shape known, handshake unsolved
- Per-listener TLS setup = FUN_1400d3f60: if sslKey empty →
  LoadEmbeddedSSLCertificates (0x14009bf30, creates SockLib object vtable 0x14023b360 →
  TLS vtable 0x14023b860) else LoadSSLCertificate (sslCert/sslKey files).
- Accept side = SSLAcceptThread@SockLib@@ / TlsConnection::Accept (0x14009dcb0 →
  OpenSSL `SSL_new`(0x1401eb810) + step fn 0x14009e000 → internal 0x1401ec590).
  CTX = TLS_method + SSL_CTX_new, min/max = 0x303/0x303 (TLS 1.2) both ways
  (0x14009e33a: 0x7b=min, 0x7c=max → 0x1401eac90).
- Empirics: bsPort accepts TCP, sends nothing first, and NEVER answers a Python
  ClientHello (TLS 1.2/1.3, default or ALL-ciphers/SECLEVEL=0, with/without SNI) —
  not even an alert; server log stays silent; socket kept open. So either the TLS
  accept loop is event-gated and never fires in our runs, or it wants a different
  ClientHello shape. NOT YET solved. Next: correct-version ClientHello per the
  0x303 bounds, or run the REAL game client against loopback relay and pcap it
  (game speaks whatever the server wants — fastest ground truth for M0.4).
- `-sslKey` override exists (file path option) but useless without the embedded
  cert's key — and NO plaintext/DER cert or key material found in the binary
  (only MS Authenticode certs in .rsrc + OpenSSL's own s3_lib.c strings).
  OpenSSL is statically linked; no libssl imports.

### THE WORKING PATH: websocket binary frames (bsPort bypass)
- ws://127.0.0.1:<webSocketPort>/chat + RFC6455 handshake → 101 (WebSocket++/0.8.2).
- Binary frame carrying a bare 36-byte LOBBYCONNECT (type 0x15, marker 0x02, ver=5,
  synthesized title/session/secret): server answers CLOSE 0x8800 then drops.
- Binary frame with 24-byte legacy LOBBYCONNECT (ver=4, NO secret) → **silently
  accepted, socket kept open, no log line** = treated as attach/reconnect-pending.
- Binary frame with 36-byte marker=0 + ver=5 → ALSO silently accepted, kept open.
  Marker=2 + no session → CLOSE (matches admission code: 'Attempt to reconnect to
  a non-existent sessionID'). So the admission gate behaves EXACTLY as the
  decompiled FUN_1400eb5f0 says: no secret check, marker decides.
- Follow-ups sent on the attached socket (LOBBYPING 0x14, PEERHEADER 0x0F,
  GAMEDATA 0xFE..., second peer same session) got NO replies and NO cross-peer
  ADDPEER/forwarding — attach ≠ join. Missing step is the JOIN (REQUESTJOIN from
  the host), whose wire layout is still unknown.
- Same-port control: plain HTTP GET on 47110 (raw) → timeout; same GET on 47111 →
  `400 + Server: WebSocket++/0.8.2`. Raw port speaks ONLY the (uncooperative) TLS.
- notes/bs_client.py gained a `ws` subcommand (handshake + masked binary frame +
  drain helpers + LOBBYRELAY guess-builder). The `[u32 LE len]` framing assumption
  in its header comment is now flagged UNCONFIRMED — relay accepts bare payloads
  over websocket.

### Session-row creator: narrowed, not closed
- SessionManager::ctor (0x1400e9dc0) allocates exactly ONE Session (0x5a4) via
  0x1400ecd80 — the heartbeat/session template (all 26 call sites pass edx=0x5a4,
  i.e. Session::Session size, not a type tag).
- No allocation of a Session object anywhere in the REQUESTJOIN handler
  (FUN_1400ea680: callees = map/copy/log helpers only) nor inside ProcessPacket's
  LOBBYCONNECT case. The map insert seen at 0x1400de26e (malloc 0x28) is a
  ServerClient-by-socket node, not a session.
- `Session ended` (FUN_1400e2050) has exactly 2 callers (refcounted session
  teardown + error path) — bookkeeping, not creation.
- Remaining candidates: (a) LOBBYRELAY (0x13) — server-to-server relay, whose
  branch at 0x1400de947 UNCONDITIONALLY allocates a Session (0x1400dea62:
  `new 0x28; createSession(0x5a4)`) BEFORE dispatching; (b) the game client sends
  something after LOBBYCONNECT that we haven't (REQUESTJOIN first? its layout
  unknown). `ws` probe of a LOBBYRELAY-encapsulated LOBBYCONNECT got silence
  (layout guess likely wrong — ids/lengths unconfirmed). Next: decode
  LobbyRelayMessage::unpack (server) + the client's RequestJoinMessage pack
  (game RTTI at file ~0x4240d50) to build a correct JOIN.

## M0.3 notes (started this session: game-side navigation problem)
- TComm_Provider_RL methods located in .text 0x140f19xxx–0x140f1cxxx (e.g.
  OnAppSuspending 0x140f19680 → log-helper 0x140f19210; server/client log strings
  like 'battleserver' host default resolved at 0x140dfedb1 — that fn is a
  Windows-Firewall INetFwPolicy2 check, NOT relay config).
- KEY STRUCTURAL FINDING: ~2 MB of .rdata strings (rva 0x3280000–0x349FFFF:
  TComm_Provider_RL::*, Worldwide*Service, connectToGame, 'starting LAN hosting',
  'Adding LAN relay server', modDllFile, OnlineHostAsync, getLanAdvertisements…)
  have ZERO rip-relative lea refs and ZERO imm64 refs anywhere in .text.
  Reference density resumes at rva 0x34a0000+. Single-copy strings, so they are
  not duplicates — the referencing code is either dead-stripped (but then the
  lambdas/RTTI like rlUpdateLoop wouldn't exist — they DO) or takes them via a
  computed/offset-table path. PRACTICAL CONSEQUENCE: string→xref navigation does
  NOT work in this range; navigate via pdata bounds + vtables + absolute qword
  scans instead. (Vendored Ghidra FindByString agrees: 0 refs for these.)
- BattleServerRelay vtable found at VA 0x143675790 (14 slots): dtor 0x140771520,
  stop-ish 0x140772fb0, state predicates, tiny field accessors. Direct callers /
  vtable-install sites are scarce (dtor only) — Start path likely via relay
  manager object; still open.
- 29 client SessionMessage subclasses confirmed in RTTI (file ~0x4240xxx).
- NOTE: one vtable slot (0x140772ff0, 22-byte thunk) decodes as garbage at rest
  (unwind says prolog-12 real fn) while all neighbors decode cleanly. Single-
  thunk corruption or runtime-patched guard — DO NOT hook/trust that slot until
  verified in a live process. All other BattleServerRelay slots decode as normal
  leaf accessors / real functions.
- Next for M0.3: vtable addrs → draft sigs/<appBinaryChecksum>.json (hook
  targets = provider vtable slots + Worldwide*Service singletons, located via
  absolute-pointer scans + pdata, not via log strings).
- notes/xref.py is the fixed section-aware REX-lea scanner (earlier miss was wrong VA math —
  .text is raw 0x400/rva 0x1000, .rdata raw 0x3195c00/rva 0x3197000; imagebase 0x140000000).
- RTTI names for SessionMessage subclasses live at file ~0x42405e2 (e.g. `.?AV?$_Ref_count@VLobbyConnectMessage@SessionMessage@RLink@@`).
- Next: in AoEProj DB, FindByString "TComm_Provider_RL" → vtable addrs → Vftable.java each →
  draft sigs/<appBinaryChecksum>.json.

## Session-3 findings (2026-11-01 late — JOIN handshake decode, M0.1 ~95%)

### Corrected protocol (overrides session-2 where they conflict)
- ENDIANNESS: LE, not BE. RequestJoin unpack (FUN_1400f3370)/pack (FUN_1400f4b80)
  load/store wire qwords/units with native casts and no bswap (titleID =
  (native_u64)>>48; pack writes count() bytes the size fn computed). All
  bs_client.py integer fields were flipped BE→LE this session.
- LOBBYCONNECT: u32 timeoutOverride exists ONLY when marker==2; u32
  dataReceivedCount is ALWAYS present (unconditional). Correct attach is marker 0 +
  v5 = 32 bytes, not 36. Valid totals: 24/32 (marker 0) and 28/36 (marker 2).
  Session-2's "36-byte marker=0 attach accepted" and "24-byte v4 legacy accepted"
  both failed to parse (wrong offsets/size → silent drop, socket kept open). The only
  session-2 probe that actually parsed was marker=2/36B — and the server correctly
  CLOSEd it (reconnect to nonexistent session). NOTHING has attached yet.
- LOBBYRELAY: `13 | from:u8 | to:u8 | nested message` (u8 ids — supersedes the u16
  guess). Case 0x13 recurses ProcessPacket on the nested bytes and creates a
  Session(0x5a4) unconditionally — server-to-server/cluster path (from!=0 or warning).
- New files: notes/bs_peerjoin.c (all JOIN-path decompiles), bs_client.py gained
  build_requestjoin / build_peerheader / build_addpeer / build_gamedata /
  corrected build_lobbyconnect / build_lobbyrelay + `join` / `admit` flows.

### REQUESTJOIN decode (server authoritative: unpack FUN_1400f3370, pack FUN_1400f4b80,
    size FUN_1400f4200; vtable 0x140243c30 located via RTTI COL→vtable scan)
- Message type 0x02, nested inside PEERHEADER (0x0F):
  `0F | 15 raw hdr | 02 | u16 addrLen+addr | u16 custLen+custom | u64 Ident | u64 PIdent`
- header: flagBits u8@0, ackBits u32@1, packetNumber u16@5, startACK u32@7,
  lastReliable u16@11, flag u8@14 (split provisional; use zeros, keep bit 0x04 clear).
- route: ProcessPacket case 0x0F → ProcessPeerMessage (FUN_1400daaf0) case 2 →
  OnPeerRequestJoin (FUN_1400ea680): map-lookup (titleID@msg+0x68 u16,
  sessionID@msg+0x70 u64); miss → new 0x938 WWBS::Session, client+0x28=session,
  FUN_1400e5b00 registers PIdent (msg+0x78) in session+0x820; hit must match or reject.

### ADDPEER / GAMEDATA relay
- ADDPEER (type 6) from host → OnAddPeerMessage (FUN_1400eae60) → FUN_1400e5670
  fills session+0x890 — the peer vector FUN_1400e2e00 (GAMEDATA relay) walks.
  Test sequence: both peers REQUESTJOIN, host ADDPEERs the joiner, then GAMEDATA.
- AoE2DE_s.exe cross-check: RTTI _Ref_count@VRequestJoinMessage at file 0x4240d50
  present; debug fmt at file 0x3679e98 = five fields
  (Addrs/TIdent/SIdent/PIdent/CustomSize); join-receive semantics strings at
  file 0x36792e0+. Game rlink code sits in unreferenced-strings region (M0.3 note),
  so no direct game pack fn — server pair is authoritative and self-consistent.
  (Partial game DB for this decode at /tmp/ghproj7, import saved, analysis timed
  out at 1500s same as before.)

## Session-3.5 (2026-11-02 ~05:30) — LOCAL dry-run: M0.1 core PROVEN, one hop left

Ran the whole join flow against a local relay with `-logLevel debug` (logLevel is a
valid CLI flag — config strings at file 0x237dc0; debug makes ProcessPacket lines
visible; session-2's "silence" diagnostics were blind without it).

PROVEN (see notes/bs_server.log patterns + /d/dryrun3.py):
- 32-byte LOBBYCONNECT parses: `LOBBYCONNECT titleID=-18399 sessionID=56368583571336
  secret=... dataReceivedCount=-1` (values are our LE ints, printed signed). Server
  ECHOES the LOBBYCONNECT back (32-byte frame) = attach ACK.
- PEERHEADER+REQUESTJOIN parses; `ProcessPeerMessage: ... REQUESTJOIN`; session
  CREATED; `STATUS UPDATE ... PendingPeer: PIDENT:aabbccdd:eeff0001`.
- A receives B's PEERHEADER+REQUESTJOIN relayed to the host (cross-peer intro
  relay WORKS); B gets its own echo. Ws frames split across TCP segments —
  ws_drain was fixed to reassemble (32+37B arrived as one 69B read).
- ADDPEER CORRECTED: TWO strings (two std::string members in the object, 0x30/0x48),
  then peerID/isHost/isLocal u8s, then globalID u64. Server parsed our fixed builder
  exactly: `ADDPEER peerID=2 isHost=0 isLocal=0 globalID=0x00bbccddeeff0002` and
  B left PendingPeer, appeared as `Peer: #2, PIDENT:00bbccdd:eeff0002` (admitted!).
- 60s peer silence timeout: `Peer silent timeout expired, disconnecting peer` then
  `Session: Session ended` — keep peers alive (LOBBYPING 0x14 or traffic) or the
  session dies after ~60s idle.

EMPIRICAL DISPATCH RULE (websocket path):
- Attach all clients BEFORE the session exists (both connect + LOBBYCONNECT, THEN
  the REQUESTJOINs) → everything dispatches normally (dryrun3 works this way).
- A client whose LOBBYCONNECT is processed while the session already exists gets
  its SUBSEQUENT messages swallowed after SockPacketReceive logs them (no
  ProcessPacket) — true even for back-to-back LC+RJ in one TCP segment; a 2nd
  message from a session-era connection never dispatches. Cause not yet traced
  (suspect the admission/store-creds path in FUN_1400eb5f0 mutating the client's
  stream state, or a session-queue takeover). The real game attaches peers AFTER
  the host created the session, so there must be a correct sequence we haven't
  replicated (maybe: wait for the LC echo, or the session must be in state 1 —
  FUN_1400e9e90 gate `session+0x91c == 1`).

REMAINING FOR M0.1: SOLVED 2026-11-02 ~06:10 — GAMEDATA RELAY PROVEN, two findings.

FINDING 1 (the +8 assignment): FUN_1400e5670 (ADDPEER fill) writes the admitted
peer record's client slots directly: node[5] (client ptr from the pending map)
gets *(u64*)(client+0x0) = globalID and *(u8*)(client+0x8) = peerID. So ADDPEER
IS what assigns a socket's fromPeerID (client+8). Theory 3a confirmed: the sender
must be ADDPEER-admitted; our ADDPEER(0,isHost=1) triggered
'Session:PeerAccepted: New host ... hostPeerID=0' (FUN_1400dfe60 sets
session+0x840) and delivery started. Decompiles of FUN_1400e2e00 + FUN_1400e5670
+ FUN_1400e5cb0 in /tmp GhProj notes; FUN_1400e5b00 registers pending
(node[5] = client ptr). FUN_1400e34f0 builds the funnel, FUN_1400e2590 is the
per-session flush tick (broadcasts via FUN_1400d49a0 to every peer slot).

FINDING 2 (the funnel, this session's real discovery): FUN_1400e2e00 does NOT
send to sockets. It appends the GAMEDATA payload into the SENDER's queue entry
(the +0x890 vector entry whose entry+0x20 == fromPeerID; entry = 5 qwords:
+0x0 msg-vector, +0x18 tail-ptr?, +0x20 peerID). Delivery = separate tick that
builds type 0x0A messages and BROADCASTS to every peer socket. Tick fires while
socket traffic is flowing (~8 Hz observed, NOT the 1.3s animate loop).

TYPE 0x0A = MultiGameDataMessage (flag 0xFE). Delivery frames:
  `0a | fe | u16 frameStart | u16 frameEnd | <nested 09 frames...>`
Observed: `0a fe 0200 0900 09 00 412d47442d50494e47 09 00 422d47442d50494e47
00 00 00` (30B: A-GD-PING + B-GD-PING to BOTH peers, full-duplex per-sender
queues). Plus continuous `0a fe 0002 0002 0000` (8B) frame-range heartbeats.
Top-level 09: log-silent by design (bs_ProcessPacket.c); inner 09 logs
'ProcessPeerMessage: fromPeerID=%d GAMEDATA'. FIXED inner header: type 0x0a
msg = 0a | fe | u16/u16 frame range | nested gamedata | 3B pad.
Working sequence = bs_two_peer_test flow + self-ADDPEER(host) before B's
ADDPEER. M0.4 = relay-capture.txt (full session capture, this file's sibling).
- bs_client.py: `join [pident] [selfpeerID]` (self-admit fixes the slot gate),
  fixed %08x formatting crash on long pidents.
- bs_client.py now has: fixed build_addpeer (two strings), frame-reassembling
  ws_drain, `livejoin [pident]` (long-lived listener for operator-driven tests).

TEST SEQUENCE THAT WORKS (both attach BEFORE any REQUESTJOIN):
  1. relay up with -logLevel debug
  2. both clients: ws connect + LOBBYCONNECT
  3. A: PEERHEADER+REQUESTJOIN (creates session, host) 
  4. B: PEERHEADER+REQUESTJOIN (pending peer; A receives B's intro)
  5. A: PEERHEADER+ADDPEER (admits B: two strings + ids + globalID)
  6. A: GAMEDATA / LOBBYPING — verify B receives (this is the remaining hop)
- `BattleServer/BattleServer.exe -bsPort 47110 -webSocketPort 47111 -outOfBandPort 47112 -lobbyPort 47114 -relayBroadcastPort 47113 -logLevel debug` (debug ALWAYS — session-2 diagnostics were blind)
- ORDER MATTERS (see TEST SEQUENCE THAT WORKS above): both peers attach (ws +
  LOBBYCONNECT) BEFORE the first REQUESTJOIN. `join`/`admit` subcommands send LC
  per-connection so for the two-machine test: B connects and sends LC FIRST, then
  A runs `python notes/bs_client.py join` (creates session), then B sends its RJ —
  use `livejoin` + a second shell, or extend /d/dryrun3.py (correct ordering, in
  /tmp — copy it into notes/ if it survives reboot).
- Watch log: `ProcessPeerMessage: ... REQUESTJOIN` / `ADDPEER peerID=2 ...` /
  `Peer: #2, PIDENT:...` = join+admit OK (all three proven locally 2026-11-02).
- Then A: `python notes/bs_client.py admit 2 <B-pident>` and re-send GAMEDATA.
- Success = B's drain shows A's `M0JOIN-ping` payload (host→joiner relay works).
- Peers idle >60s get dropped (`Peer silent timeout`) — keep LOBBYPING/traffic flowing.

## Resume commands (run from D:\Age of Empires II Definitive Edition)
- `export JAVA_HOME="/d/Age of Empires II Definitive Edition/tools/jdk-21.0.13+9"`
- `cd tools/ghidra/ghidra_11.3.2_PUBLIC/support`
- BattleServer string search: `./analyzeHeadless /tmp/ghproj TestProj -process BattleServer.exe -noanalysis -scriptPath "/d/Age of Empires II Definitive Edition/tools/ghidra_scripts" -postScript FindByString.java "<substr>" refsOnly`
- Same against the game: replace `/tmp/ghproj TestProj -process BattleServer.exe` with `/tmp/ghproj7 AoEProj -process AoE2DE_s.exe`
- Decompile: `-postScript Decompile.java <addr...>`
- Restart relay on M0 ports: `BattleServer/BattleServer.exe -bsPort 47110 -webSocketPort 47111 -outOfBandPort 47112 -lobbyPort 47114 -relayBroadcastPort 47113`
- NOTE: stop launching the relay with `timeout`+`&` from Git Bash — it survives the shell; use taskkill.

## PLAN cross-check (no conflicts found this session)
- §2.2 LAN strings all confirmed present (offsets: CanUseXboxLive 0x31cab20, NON XBOX 0x3284ac8, broadcast 0x368a9f8, LAN relay 0x367e0f8, REJECTED NOT LAN 0x3287988, arg table 0x3282da0).
- §2.4 seam ranking stands; S1+S2 still the plan. §2.3 schema note stands (.bond is telemetry-only).
- One PLAN gap found: M0.1 must speak TLS on bsPort (stock relay is not plain-TCP). Fastest paths:
  (a) extract embedded cert+key from BattleServer.exe, (b) capture a real game↔relay loopback session
  and replay/extend it.

## Deliverables status
- notes/m0-findings.md: THIS FILE (wire format + session-2 server-side results).
- sigs/<appBinaryChecksum>.json: NOT YET (needs M0.3 vtable addrs). Draft started as sigs/draft-note below.
- notes/relay-capture.txt + pcap: NOT YET (websocket gives the capture path: attach
  + JOIN with correct REQUESTJOIN/LOBBYRELAY layout, then dump GAMEDATA relay).
- notes/bs_client.py: `ws` probe + `join [pident]` (attach+REQUESTJOIN+GAMEDATA) +
  `admit <peerID> <gid>` (host ADDPEER) with exact builders (LE, corrected layouts).
  NOTE: 'ws attach' from session 2 was never a successful parse � see corrections.

## Session-6 (2026-11-02 ~06:35) — tailnet repeat, LIVE (in progress)

Setup: relay #4692 on M0 ports with -logLevel debug (appended to notes/bs_server.log).
Tailnet: cachyos-x8664-1 (100.109.201.126, friend's Arch box) ONLINE at test start;
this box 100.79.215.72. Pre-flight: existing inbound firewall rules for BattleServer
(`ageLANServer BattleServer` + `battleserver`, Private+Public) found — no change needed.
New self-contained two-role client `notes/bs_live_test.py` (stdlib only, same proven
builders as bs_client.py; per-role LC secrets A=0x0BADF00DCAFEF00D / B=0x0BADC0DE5AFEBABE,
pidents aabbccddeeff0001 / bbccddeeff0002; host auto-ADDPeer(B,2) on B-intro relay;
GD ping every 5s, LOBBYPING every 15s; PASS printed on seeing the other's ping in a
0x0A/fe funnel). Served to friend via http://100.79.215.72:47115/bs_live_test.py
(port 47115, reachable from the tailnet — verified 200 from this box).
Host A launched 06:35:16: LC echo OK (32B 0x15), RJ parsed (`ProcessPeerMessage:
fromPeerID=0 REQUESTJOIN`, `PendingPeer: PIDENT:aabbccdd:eeff0001`),
self-ADDPEER(0,host) -> `Peer: #0 ...` + `New host ... hostPeerID=0`. A pings
A-GD-PING every 5s and is waiting for B's intro (funnels flowing, hb rising).
Next: friend runs joiner; success = both sides print SUCCESS with funnel hex.

## Session-6 (2026-11-02) — tailnet repeat: FULL-DUPLEX RELAY PROVEN over tailnet

Setup: stock BattleServer 2.58.0, relay #18084, M0 ports + -logLevel debug (log
appended to notes/bs_server.log). A = this box (100.79.215.72, host,
pid aabbccddeeff0001, secret 0x0BADF00DCAFEF00D). B = friend's Arch Linux box
(cachyos-x8664-1, 100.109.201.126, pid 00bbccddeeff0002, secret
0x0BADC0DE5AFEBABE). Same sessionID 0x1122334455667788. Client:
notes/bs_live_test.py (self-contained, stdlib only; A role: LC, delayed RJ,
self-ADDPEER(0,host), single ADDPEER(B,2) 5 s post-RJ, GD every 5 s,
LOBBYPING/15 s; B role: LC, delayed RJ, GD every 5 s ungated, LOBBYPING/15 s).

RUN ORDER THAT WORKS (after 4 live failures): A LC -> B LC (both pre-session,
each gets the 32 B 0x15 echo) -> B RJ -> A RJ -> A self-ADDPEER(0,host) -> A
single ADDPEER(2,B). Note either RJ order works as long as both LCs land
pre-session; in the final run B's RJ created the session and A's RJ joined it.

Hard failures diagnosed live this session (all in server log):
1. Session-era LC attach = swallowed, regardless of secret. B LC after session
   exists: SockPacketReceive logs the 32 B LC but no ProcessPacket/echo, and
   ALL its later messages (RJ, LOBBYPING) are logged at SockPacketReceive but
   never dispatch. Secret difference does NOT save it; the session-5 theory
   ("same secret triggers the swallow") is WRONG — same or different, a
   session-era marker-0 LC is dead. B had to Ctrl-C and re-attach pre-session.
2. Same for the A side: A's LC after B created the session swallowed (echo=0).
3. Unbound (pre-RJ) sockets are killed by the ~60 s idle timer: A's first host
   run sat silent 180 s and its socket was aborted before its RJ fired. Fix:
   LOBBYPING heartbeat during the wait phase (works for attach-phase sockets).
4. Admitted peers that send ONLY LOBBYPING are dropped at ~60 s by the 'Peer
   silent timeout' (peer timer counts GAMEDATA, not pings). Fix: both sides
   send GAMEDATA every 5 s; that is what resets the timer, not LOBBYPING.
5. Repeated ADDPEER for an already-admitted peer KILLS its funnel delivery:
   periodic re-ADDPeer(B,2) every 30 s stopped B's server->client writes dead
   (B's SockPacketSend went from 7-9/tick to zero after the 2nd ADDPEER).
   Fix: admit EXACTLY ONCE per peer. (Suspect: re-fill corrupts the +0x890
   vector entry's client slot or duplicates it out of the broadcast walk.)
6. Minor: script countdown had a sleep(0) busy-spin bug at the 0 s mark; fixed.

SUCCESS (both directions, hex from live runs):
- A side: `SUCCESS(A): B-GD-PING inside 0x0A funnel:
  0afe01000900422d47442d50494e47000000` (18 B: 0a fe frameStart=0001 frameEnd
  then nested `09 00 <len9> 422d47442d50494e47` = "B-GD-PING" + 3 B pad).
- B side: `SUCCESS(B): A-GD-PING inside 0x0A funnel:
  0afe01000900412d47442d50494e47000000` (same shape, "A-GD-PING").
- B's run: admitted=True after first funnel, funnels 56 -> 1020+ over 4 min,
  GD flowing both ways at 5 s cadence, LOBBYPING alive. No desync/drop once
  both sides sent GAMEDATA. Server status: `Peer: #0 PIDENT:aabbccdd:eeff0001`
  + `Peer: #2 PIDENT:00bbccdd:eeff0002`, `New host ... hostPeerID=0`.

What M0.1 still owes PLAN: nothing on the relay path — M0.1 exit criterion
("both peers relay GAMEDATA") is now met over the tailnet, not just loopback.
Remaining M0 items unchanged: M0.3 vtable addrs -> sigs/<checksum>.json draft.
Deliverable bs_live_test.py doubles as the two-machine regression harness.

## Session-7 (2026-11-02) — M0.3 game-side vtable hunt (solo, no friend needed)

Goal: locate TComm_Provider_RL + Worldwide*Service vtables in AoE2DE_s.exe,
draft sigs/<appBinaryChecksum>.json (hook targets S1+S2).

Deliverables: `sigs/1e415af8b7fbbe6aeb4e1eebf888f43e9d9b8b9129df2bd010d0a7a60dc3ca16.json`
(draft v2, valid JSON), `notes/rtti_game.py` (pure-python RTTI/vtable survey,
no Ghidra needed), `notes/rtti_tables.json` (2982 classes w/ vtable VA + slot counts).
Ghidra-side: `tools/ghidra_scripts/{StrRefs,XrefsRaw,SigDump,DisRange,VtableScan,FuncsInRange,NoAuto}.java`
new this session; partial AoE2DE_s.exe DB at /tmp/ghproj7 (import saved, analysis incomplete).

STRUCTURAL RESULTS (all verified against raw bytes + .pdata):
1. Provider method cluster .text 0x140f19037-0x140f1d006: 84 pdata functions.
   Dead-zone log strings verified reachable: only 2 .text bodies use lea into
   rva 0x3280000-0x349FFFF: OnAppSuspending 0x140f19680 (lea "TComm_Provider_RL::
   OnAppSuspending" + "Network" tag) and OnAppResumed 0x140f196f0. Log helper =
   0x140f19210 (11 E8 callers game-wide). No lea anywhere in .text targets the
   dead zone except those two — confirms the PLAN §2 string table observation.
2. BattleServerRelay vtable CONFIRMED at 0x143675790, 14 slots
   (dtor 0x140771520 ... slot6 = 0x140772ff0 22B thunk), COL 0x1438234a8,
   TypeDescriptor at rva 0x4253ac8. BUT the class name bytes are a decimal
   number, not an RTTI name: this class identity was SANITIZED. Same for ~190
   other classes (decimal "names" like `83481279349066`, in .data not .rdata).
   Six 13-slot vtables at 0x1435100c8-0x1435102f8 + 7-slot 0x143520578 are
   RTTI-ful, COL-valid, and share entries (0x1425fc7f0/900, 0x1426051e0/b50/ea0
   0x1426035e0/710/720, 0x141863610) but point at sanitized-class COLs — family
   members, identity TBD by M-code decompile, NOT assumed to be the provider.
3. RTTI survey (notes/rtti_game.py, the durable tool): 5324 TypeDescriptors,
   3054 COLs, 2982 classes with vtables. KEY GOTCHA: RTTI names live in BOTH
   .rdata AND .data raw ranges — the TComm_/RLink:: names are in .data
   (file ~0x411f000-0x4170000); a .rdata-only scan finds just ~1900 std names.
   Anchor: TypeDescriptor[0] = 0x14365d5f8 (type_info vftable). COL = PE32+
   form (sig=1, pTypeDescriptor/pSelf as u32 RVAs). Scan cost ~minutes, stdlib only.
4. TComm_Provider_RL / Worldwide*Service / BattleServerRelay as NAMED classes
   have NO vtable in the survey: only std::function/lambda RTTI mentioning
   their methods survives (rlUpdateLoop 0x143286838/870, IsMutedUser
   0x143288ea8/ee0, ShouldPlayerStartMuted(FromUserData) 0x143288f18/f50/f88/fc0,
   DidPlayerStartMuted 0x14328ff8/ff8-030, matchmaking/party/invitation
   lambdas 0x1432819a8-0x143284160). 29 RLink::SessionMessage event RTTI intact
   (RequestJoinMessage etc. at 0x14366c028 area) for the M1 S2 layout work.
5. TComm_Stats_RL callback table at 0x143286938: 10 fn slots
   (0x140f1c900 deb0 c9d0 da70 cae0 cab0 d400 cb40 + c8f0 cb50) referenced by
   exactly one lea each from 0x140f1c906/0x140f1c918; zero E8/JMP/FF-indirect
   refs — reached via vtable or registration, same as the provider methods.
   70 of 84 provider bodies have no E8/E9/lea-ref anywhere: they are
   vtable/register/dispatch invoked, i.e. the provider interface IS the
   indirection layer (consistent with S1 seam ranking).
6. Spend cap hit: DO NOT re-run blind full-.text xref scans (each ~10+ min);
   use notes/rtti_game.py + targeted capstone on pdata ranges instead.
   Next for M0.3 completion: (a) decompile 0x140f19xxx bodies via Ghidra
   DisRange/Vftable on the confirmed VAs, (b) recover Worldwide* singleton
   addrs from Login-response connect-spec parsing (webSocketPort/
   rawSocketPort/connectionToken block) rather than RTTI, (c) M0.2 logging-hook
   experiment (below) can start in parallel — it does not need the vtables.

## M0.2 logging-hook experiment design (for next session, needs 2 machines)

Question (PLAN §10.3): can LAN hosting start from login-provided relayServers
alone, with no broadcast-discovered relay?
Method: logging hook only, no behavior change. Run stock BattleServer on M0
ports on host; on both machines set env RL_TELEMSHOULDNTSEND=1 and add a
dbghelp-proxy log shim that (1) prints every BattleServerRelay::Start
relayIP/relayPort args, (2) prints on `starting LAN hosting` vs `starting
online hosting` (WorldwideAdvertisementService strings at rva 0x367xxxx),
(3) dumps the login-response relayServers[] the game WOULD use
(relayIP/relayPortRaw/relayPortWebSockets/relayPortOutOfBandSocket/
relayAuthToken/region). Two tailnet machines, host creates LAN lobby via
-FORCE_LAN_WINDOW or the LAN browser path, client joins by tailnet IP.
Success = `starting LAN hosting` + both peers relay GAMEDATA over the
host's tailnet IP with zero broadcast traffic. Fallback if the engine
demands a broadcast hit: synthesize the BroadcastListener entry inside the
shim (GUID + tailnet IP + ports) per PLAN §10.3 — still no broadcast.

## Session-8 (2026-11-02, solo) — M0.3 runtime exit TEST: lanhook.dll dbghelp proxy

Goal: build the first real lanhook.dll (dbghelp proxy + logging detour on one
confirmed provider method), prove injection for M1. Full build log in
`dev/lanhook/` (lanhook.c, build.cmd, genstubs.py, dbghelp.def, stubs.asm).

### 8a. On-disk "garbage" code = runtime-decrypted (Arxan-style), proven
- 0x140F19210 (log helper) on disk: `ad ee 58 bb ...` (entropy 5.76, lodsd/out
  garbage disasm), but valid pdata bounds (140F19210-140F1925A), 11 E8 callers.
- memcheck probe (dev/memcheck/memcheck.c: CreateProcess+ReadProcessMemory at
  T0 suspended vs T1 +40 s): T0 == disk bytes; T1 == real x64 code
  (`4c89442418...` = mov [rsp+18],r8; ...; call 0x142D6E2B0 stack-probe).
  Decryption happens after start (thread-init/TLS). Same verified for random
  .text regions (0x1404C00, 0x2053000). Clean regions: entry, TLS cbs, CRT,
  OnAppSuspending/Resumed, parts of the provider cluster — selective function
  encryption, pdata intact throughout.
- CONSEQUENCE (PLAN §10.1 route, hardened): hook placement MUST be
  runtime-verify — poll-and-compare against known-clean prologue bytes, then
  patch. On-disk bytes are untrustworthy. Points back to the TASK's function-
  level prescription (0x140F19210/0x140F19680), which this session validated.

### 8b. Same-name PE linker forwarders FAIL on this OS
- Test: testfwd.dll (single export `SymFromAddr=dbghelp.SymFromAddr`) as
  iso/dbghelp.dll + test exe importing SymFromAddr: child exits 0xC000007B
  (STATUS_INVALID_IMAGE_FORMAT) before main. Same-name forwarder target
  resolves to the forwarding module itself -> loader refuses.
- DESIGN (locked): RUNE-pattern jmp-stub proxy — 268 `jmp qword [rip+off]`
  stubs + explicit LoadLibraryExW(GetSystemDirectoryW()+dbghelp.dll) in
  DllMain, exactly like the RUNE winmm.dll proxy on this install.
  Verified: fwdtest through OUR built proxy -> SymFromAddr forwards correctly.

### 8c. The game spawns BsSndRpt64.exe (BugSplat) on EVERY launch here
- Every AoE2DE_s.exe launch in this session produced a BsSndRpt64.exe child
  (cmdline `BsSndRpt64.exe -i %TEMP%\BsSndRpt_*.ini`); per-PID logs
  (logs/lanhook-<pid>.log) were ESSENTIAL to separate game vs reporter.
  In-game evidence `Documents\...\Age of Empires 2 DE\logs\<date>\Main.txt`
  stops at `setup communications handler...` on the 5-10 s runs, then proceeds
  to `Game::setup() after hotkeys` -> `endMovieFunction complete` (main menu)
  on longer runs. STOCK game also exits 0 after 5-10 s in unattended runs;
  with user session active it stays up (stage1 game window visible 120 s+).

### 8d. Guarded .text pages: reads fault, writes... also fault
- Live ReadProcessMemory of 0x140F19680 in a RUNNING game: err 299
  (PARTIAL_COPY), page state MEM_COMMIT protect 0x1 (PAGE_NOACCESS).
  Contiguous readable .text from outside: only 0x1000-0x74000 (~460 KB).
- In-process probe of the same address: sometimes readable (0x40...), but
  copying (read) OR writing (slot) via install_hook raised AV caught by SEH.
  Split-phase logging proved: target read OK, slot write FAULT ->
  g_NearPage was never allocated (bug: assignment lived in a dropped drift
  of lanhook.c) -> write to NULL+offset, caught by SEH, no crash.
- FIXED: VirtualAlloc hint-walk near .text ((probe-0x20000000)&~0xFFFF,
  64 MB steps) for the 4 KB RWX trampoline page, before touching targets.
  After fix: both 5-byte E9 detours install cleanly (VP ok, patched E9,
  trampolines flushed), game process CONTINUES (no crash at install time).

### 8e. E9-patched game exits 0 quickly; unpatched proxy game stays up
- stage1 (proxy + idle thread, NO patches): game ALIVE 45 s, window 120 s+.
- stage4 (both OnAppSuspending/Resumed E9-installed at t~3 s): process gone
  by ~20-45 s, exit 0, no BsSndRpt, no hook-hit lines. Stock game in the same
  unattended harness ALSO exits 0 after 5-10 s (window shown then gone), so
  the 5-10 s quit is environmental, but the stage1-vs-4 DELTA (45 s+/120 s+
  vs <45 s) points at an integrity/re-check reacting to the .text patch.
- SHIPPED DEFAULT: stage defaults to 1 (idle-safe) unless AOE2LAN_STAGE=4 is
  set in the environment. Game with proxy boots to menu, window visible,
  `logs/lanhook-<pid>.log` shows clean boot (base, real dbghelp, near page).
  AoE2DE_s.exe sha256 unchanged (1e415af8...16); only ADDED files: dbghelp.dll
  (proxy, 128 KB), logs/. R10 holds.
- NEXT (M1): re-arm patching ONLY around a user-present session, or move the
  hook site to a hot path that is provably executed (log-helper 0x140F19210
  AFTER its runtime decryption, or BattleServerRelay::Start), with a menu-idle
  soak first. Also: stage1 game + minimize/restore produced no hits because
  NO hooks are installed by default — hits require AOE2LAN_STAGE=4.

Build: `cd dev/lanhook && build.cmd` (MSVC 14.44 + WinSDK 26100, /MT, kernel32
only). Stage: copy dev/lanhook/dbghelp.dll -> game dir as dbghelp.dll.

### 8f. Session-8 Task 2 prep: M0.2 logging-hook sites LOCATED (static, verified)
Method: runtime .text dump (dev/memcheck/dumptext.exe on a live 70 s-old game
-> 51,990,528 B) + lea rip-rel re-scan. On-disk xref scan finds NOTHING for
these (the referencing fns are in the encrypted set); the DECRYPTED dump
reveals 373 exact-VA lea hits. (Earlier 0-hit scan was a python bug: `tgt in
targets` tested dict KEYS, not values — fixed to a by-value set.)
- `starting LAN hosting` (0x14367EE78): 1 lea at 0x14035143B, inside a fn that
  also refs `starting online hosting` (0x14367EE40 at 0x140351399, same fn,
  branchy: cmp eax,2 / cmp [rax+10],4 / cmp [rax+18] paths -> log helper
  0x1402BCB30). HOOK CANDIDATE (function-level detour on the two lea sites'
  enclosing fn, or on call 0x1402BCB30's game-side caller).
- `Adding LAN relay server` (0x14367F4F8): 1 lea at 0x140359844 (same log
  helper 0x1402BCB30).
- `relayServers` (0x1436921D0): 1 lea at 0x14061694A as r8 key to call
  0x14039AAF0 (login-response field getter — the M0.2 relayServers[] dump
  point: hook this getter or the 0x14061694A site).
- `BattleServerRelay::Start - m_nextConnectRetryTimeMS...` (0x14369C0A0):
  1 lea at 0x140771D64 (in a teardown/epilogue path: restores rsp, pops,
  ret; log call 0x1402ABC80). NOT Start's entry — the Start-args hook needs
  the enclosing fn's head (recover via pdata bounds around 0x140771xxx).
- `getLanAdvertisements` (0x14367E4F0): NO lea anywhere even decrypted ->
  reached via table/offset (absolute-qword scan also empty on disk). Still
  open; next: scan the decrypted DUMP for qword refs (not done this session).
- Network-category (0x143264280): 367 leas (the log-helper's category arg is
  ubiquitous — confirms the provider cluster's logging shape).
- M0.2 experiment is now placeable without the friend: hook the 0x140351399
  fn + relayServers getter + Start-enclosing fn, log args, run LAN hosting
  path on one machine (FORCE_LAN_WINDOW). Needs a user-present session.

### 8g. Session-8 Task 1 exit status
- lanhook.dll BUILT and STAGED as game-dir dbghelp.dll (128 KB, MSVC 14.44
  /MT, kernel32-only imports, 268 forwarded exports, RVA-based detours).
- Game cold-boots WITH the proxy to the main menu (window visible 120 s+,
  Main.txt reaches `endMovieFunction complete`), Main.txt identical shape to
  stock, AoE2DE_s.exe sha256 unchanged, only added files dbghelp.dll + logs/.
- SymFromAddr C-hook proven end-to-end (fwdtest: hit logged + correct forward,
  err=183). Game-code E9 detours proven mechanically (both install, VP ok).
- DEFAULT IS SAFE (stage1, no game-code patches): AOE2LAN_STAGE=4 re-arms the
  two provider detours for a supervised run. Hook-hit proof in a real
  skirmish is the OPERATOR's step (game left running at end of session, proxy
  staged). If menu-idle shows SymFromAddr/menu hits, M0.3 runtime exit closes.
- REMAINING RISK (recorded, not blocking): patch-then-exit-0 correlation for
  E9 detours needs the operator's supervised AOE2LAN_STAGE=4 run to confirm
  or deny (could equally be unattended-session quit).
- Tools added: dev/memcheck/{memcheck,dumptext}.c, dev/lanhook/* (full source
  + build.cmd), dev/fwdtest/* (forwarder negative control).
- Next session: (1) supervised skirmish with log check, (2) AOE2LAN_STAGE=4
  supervised run, (3) M0.2 hooks (sites above) when the friend is online.

## Session-9 (2026-11-02, solo) — v2 hook machinery + M0.2 static completion

Goal: fix v1's latent hit-time crashes (found by code review, PROVEN by
self-test), finish the M0.2 hook site table, stage a trustworthy build for the
supervised M0.3/M0.2 run. New files: dev/lanhook/{hookcore.c,hookcore.h,
hooks.asm,hooktest.c} (build.cmd now builds all + hooktest.exe).

### 9a. v1 was broken at HIT time (never exercised: no hits ever logged)
Three bugs, all found before any new game run:
1. TORN TRAMPOLINE: install_hook copied a FIXED 5 bytes, but the stage-4
   prologues have their first instruction boundary at 6 (40 53 48 83 EC 20 =
   push rbx; sub rsp,0x20) or 8 (89 54 24 10 48 83 EC 38). The trampoline
   would execute `48 83 EC E9` (sub rsp,0xE9!!) + the rel32 bytes as code on
   the first hit -> guaranteed crash.
2. rel32 4th byte written from `rel>>32` instead of `rel>>24` (v1 line:
   `target[4]=(BYTE)(rel>>32)`): the E9 displacement's top byte was always
   0x00 -> every E9 jumped to a wrong address (works only if |rel|<0x10000
   AND positive). Both v1 patch AND v1 back-jmp had it.
3. Arg-count guess: v1 wrappers re-CALLED the trampoline with declared
   (this)/(this,int) args -> any real signature with 5+ args or different
   register usage would read garbage from the wrapper's frame.
=> v1's stage-4 would have crashed the game at the FIRST OnAppSuspending hit.
   The unattended stage-4 exit-0 runs never hit a hook (no HIT lines), so
   none of this ever fired. Session-8's "all 4 install cleanly" remains true
   (install-time logic was fine); only hit-time was broken.

### 9b. v2 machinery (hookcore.c + hooks.asm), all self-tested
- hook_len(): mini-LDE (push/pop r64, 81/83 group1 imm, 89/8A/8B/8D r/m,
  mov r,imm; REFUSES rip-rel or anything unpinnable) -> trampoline copies an
  instruction-aligned N in [5,11]. N per target: 0x140F19680/6F0/C900 = 6,
  0x140F1CAB0 = 8, 0x1403503A0 = 7, others 5.
- hooks.asm lanhook_thunk: stub sets r10=hook id; thunk saves ALL volatile
  GPRs + XMM0-5 (shadow space kept clear of the ctx block), calls
  lanhook_log_hit(id, ctx) (ctx: [0x00..5F]=xmm0-5, [0x60..0x90]=r11,r10,r9,
  r8,rdx,rcx,rax, [0x98]=ORIGINAL RETURN ADDRESS), restores everything, then
  tail-jmps [g_TailTable+r10*8] -> trampoline -> original body -> ret to the
  original caller. ANY signature (incl. 5th+ stack args, FP args) survives.
- Patch = ONE aligned 8-byte CAS write (E9 rel32 + original bytes 5..7),
  target required 16-aligned (all 9 are). No torn-patch window.
- hooktest.exe PASS (exit 0): synthetic fns with the exact 6-byte-boundary
  prologue AND a 5-byte leaf, 6 int args (2 on stack): pre-hook 21/21,
  post-hook 21/210/2100/6, HIT lines with correct rcx/rdx/r8/r9 + retaddr.
  Initial failure was a test bug (reading 32-bit stack args as qwords) and
  exposed bug #2 above; after the >>24 fix all green.
- fwdtest re-run through the v2 proxy: SymFromAddr forwards (err=183, same
  as session-8), exe-name gate idles BsSndRpt-like processes correctly.
- Staged: game-dir dbghelp.dll = v2 (sha256 55c0b52b...). AoE2DE_s.exe
  untouched (1e415af8...). Stages: AOE2LAN_STAGE 1=safe default (no game-code
  patches), 4=4 provider detours (M0.3), 6=5 M0.2 logging detours, 5=both.
  M0.2 wait window 600 s (operator may take minutes to reach hosting paths).

### 9c. M0.2 hook table COMPLETE (fn heads via .pdata, prologues via the
decrypted dump gametext.bin, file_off = VA-0x140001000, holes=0xCC):
| hook | VA | prologue (decrypted) | on-disk | N |
|---|---|---|---|---|
| HostDecision (both 'starting online/LAN hosting' leas 0x140351399/43B, log helper 0x1402BCB30) | 0x1403503A0 | 48 8B C4 48 89 58 10 | ENCRYPTED | 7 |
| AddLANRelay ('Adding LAN relay server') | 0x1403593C0 | 48 89 5C 24 18 | ENCRYPTED | 5 |
| RelayGetter (rcx=obj, rdx=out, r8=key, -> al; call site 0x14061694A-0x140616958: lea r8,[relayServers]; lea rdx,[rbp-20]; mov rcx,rbx; call 0x14039AAF0; test al,al) | 0x14039AAF0 | 40 56 57 41 55 | ENCRYPTED | 5 |
| StartAdjacent (BattleServerRelay::Start log site 0x140771D64's fn, helper 0x1402ABC80) | 0x140771600 | 48 89 5C 24 10 | ENCRYPTED | 5 |
| LogHelper (rdx=fmt string, keyword-filtered) | 0x1402BCB30 | 48 89 54 24 10 | CLEAN | 5 |
- RelayGetter hook kind=HK_R8STR: logs the key string whenever it contains
  "relay" (relayServers, relayAuthToken, relayIP...). LogHelper kind=HK_RDSTR:
  logs the format string when it contains hosting/relay/battleserver/login/
  advertis/account/profile/multiplayer/socket. Hits capped 64 raw / 512 str.
- The 5 fns above were all DECRYPTED by t=70s in the dump session WITHOUT any
  hosting attempt (game at main menu) => decrypt is not strictly on-demand;
  the 600 s poll window is comfortable.
- NOTE: 0x1402BCB30/0x1402ABC80 are NEVER ENCRYPTED ON DISK (dump==disk) —
  they install immediately; 0x1402ABE60 (mode enum getter called before both
  hosting leas) IS encrypted (decrypted in dump). Not hooked (redundant: the
  log-helper lines answer the LAN-vs-online question directly).
- RELAY GETTER SIGNATURE RECOVERED (from the decrypted call site):
  bool fn(obj* rcx, out* rdx, const char* key r8) — logs key strings.

### 9d. getLanAdvertisements: STILL unreferenced, now with negative result
- 0x14367E4F0 IS the full path "/game/advertisement/getLanAdvertisements"
  (file 0x367D0F0; the earlier 'bare suffix' read was wrong — the path starts
  exactly there). Sibling endpoints (host/join/update/updateState/
  findAdvertisements/getAdvertisements), field names (lanServerGuids,
  avatarAliases): NO lea in the decrypted dump, NO qword/dword pointer on
  disk (scans: whole-exe qword scan into pool 0x14367C000-0x143682000 =
  105 hits, all pointing at OTHER strings — name/type/description/password/
  id/count JSON field names). Endpoint URL strings are therefore ASSEMBLED at
  runtime (or reached via dead-zone tables, rva 0x3280000-0x349FFFF, which
  no code leas into — session-7's dead-zone result). Directly hooking the
  getLanAdvertisements call is NOT possible via string xref. For M0.2 the
  LogHelper + HostDecision hooks cover the question; for M2 (H2) the LAN
  browser seam should be attacked from the service-object side (S2), not
  the endpoint-string side. OPEN for M2, closed as a dead end for M0.

### 9e. Supervised run protocol (operator at keyboard — Task 1 + M0.2 data)
RUN 1 (M0.3 close): kill leftovers; AOE2LAN_STAGE=4 launch; wait 30 s at
menu (installs at t~3 s, all 4 clean-on-disk targets); MINIMIZE+RESTORE once
(OnAppSuspending/Resumed hits); short skirmish vs AI (Stats1/Stats2 hits);
quit; read logs/lanhook-<pid>.log. Hits + stable game = M0.3 DONE.
If it exits early under supervision too -> integrity re-check confirmed ->
PLAN §10.1 fallback (stage 6 / call-site detours / longer decrypt waits).
RUN 2 (M0.2 data, solo): AOE2LAN_STAGE=6 + RL_TELEMSHOULDNTSEND=1 +
RL_TELEMREPORTPCT=0, optionally -FORCE_LAN_WINDOW; walk to Multiplayer /
hosting UI; LogHelper/HostDecision/RelayGetter/StartAdjacent capture what
fires (expected without login: nothing on the rlink plane — that itself is
the data point confirming M1 must precede the full M0.2 two-machine run).

## Session-10 (2026-11-02, solo+operator) — M0.3 PROVEN + Arxan integrity rule + M0.2 half-answered

### 10a. M0.3 exit: injection proven, detours execute in the live game
- Final drive: LogHelper (0x1402BCB30) HIT in the real game:
  `HIT LogHelper #1: "WorldwideLoginService::WorldwideLoginService -
  initializing"` (ret=game+offset) — the full E9->stub->thunk->logger->
  trampoline->body->return chain executes correctly under Arxan.
  Combined with Run-1's supervised stage-4 skirmish (game stayed up, full
  skirmish played, 4 provider detours installed) and the unchanged
  AoE2DE_s.exe sha256: **M0.3 DONE — injection is proven for M1.**
- Session-9's hooktest PASS + fwdtest-verified proxy forwarding stand as
  the mechanism regression tests (dev/lanhook/{hooktest.exe,../fwdtest}).
- v2 fixes that paid off: LDE-aligned trampolines (N=6/6/6/8 on the four
  provider heads), `>>24` rel32 high byte (v1 wrote `>>32`: every v1 E9
  jumped to a wrong address), arg-safe generic thunk, atomic 8-byte CAS
  patch, exe-name gate for BsSndRpt64.exe (it inherits the env vars).

### 10b. Arxan integrity rule (decisive, found by bisect)
Single-hook isolation tests (AOE2LAN_HOOKS env, new this session):
  hook 4 LogHelper(0x1402BCB30, clean on disk) alone: ALIVE, 74 hits.
  hook 5 HostDecision/6 AddLANRelay/7 RelayGetter/8 StartAdjacent
  (ALL encrypted-on-disk, runtime-decrypted): EACH ALONE => deterministic
  clean exit at ~5.6s, exit code 0x0, no crash dump, no BsSndRpt.
  Stage table now: 1=safe idle; 4=provider detours (clean fns, tolerated);
  5=all-clean (4 provider + 2 log helpers); 6=2 log helpers (M0.2).
  RULE: only E9-patch functions whose bytes are identical on disk and in
  the live dump ("clean"); anything Arxan decrypts at runtime is watched
  post-decrypt. CONSEQUENCE FOR M1: LoginShim/AccountService/LoginService
  live in the encrypted set — M1 must NOT head-patch them; options are the
  clean-on-disk hot sites only, vtable swaps in .rdata/.data (data, not
  code), or call-site E8 retargets from clean callers.
- M0.2 hook table REBUILT around the rule: LogHelper + new LogHelper2
  (0x1402ABC80, the BattleServerRelay logger, also clean on disk, same
  prologue shape `48 89 54 24 10 4C 89 44`). HostDecision/AddLANRelay/
  RelayGetter/StartAdjacent stay in the table as grp=0 (AOE2LAN_HOOKS-only
  experiments; never enabled for real runs). HK_RDSTR now logs EVERY line
  (cap 512) with r8/r9 raw + dereferenced strings + 5th/6th stack args
  (ctx[20]/ctx[21]).
- Side discovery: the DIP authors' assumptions hold — the trampoline/vm
  pages live at 0x7ff6/7ff7xxxxxxxx (never page under the game's own
  mappings), near-page hint-walk covers the +/-512MB rel32 window.

### 10c. M0.2 core question HALF-ANSWERED by observation (2026-11-02)
Run (stage 6 v3, menu idle 30 s, NO login, NO operator hosting action):
  [t=6.890s] "Found %zd profiles for account %s" r8=0 a5=2
    => the game's rlink login attempt runs at boot, parses a response,
       finds ZERO profiles for this account (cracked box, no valid Xbox/
       RelicLink profile). NO relayServers are delivered — the M0.2 premise
       (login-provided relayServers) cannot be satisfied this way; H1
       (synthetic profile) must come first, as projected.
  [t=14.390s] "Adding LAN relay server: %s, GUID %s"
    s8="192.168.0.104" s9="17ed65ee-b95e-44ee-8ea7-6db4f52da976"
    => the game's BroadcastListener path is ACTIVE at the idle main menu
       and ADDED a stock unmodified BattleServer.exe that was still running
       on the box from the 14:44 M0-port test (47113 UDP broadcast). A
       broadcast-discovered relay is accepted with NO login, pre-menu,
       in seconds. 192.168.0.104 = a physical-LAN adapter address (NOT a
       Tailscale IP — the 47110-47112 listeners bind 0.0.0.0, the broadcast
       goes to 255.255.255.255). This disproves the design's standing worry
       that Tailscale is needed for discovery: the in-engine path works on
       raw L2 broadcast; on a tailnet it will need the GUID/IP fed through
       the LAN browser path (the §10.3 fallback) — or simply running the
       relay ON the host machine and binding clients to the tailnet IP.
Remaining for M0.2 (needs operator + optionally the friend): with a stock
relay up on the M0 ports, operator walks Multiplayer/hosting while the
2-clean-helper build logs BattleServerRelay::Start connection args
(relayIP/relayPort) and the LAN-vs-online hosting lines. If the greyed MP
button blocks reaching the lobby plane, that is itself the H1 dependency
(ordering: M1 before the two-machine M0.2 run).
- Config sensitivity confirmed irrelevant: stage-6 dies identically with
  and without RL_TELEMSHOULDNTSEND/RL_TELEMREPORTPCT and with/without
  -FORCE_LAN_WINDOW (all runs exit-0 at ~5.6s when any encrypted-region
  patch was present; all ALIVE with clean-only patches).
- The leftover relay was killed (its broadcast was the discovered source);
  a stale-hosted `ageLANServer` CA cert appeared in the game's cert-store
  log lines (the box has prior ageLANServer activity — operator context).

### 10d. Session-10 resume commands
Build+stage: `cd dev/lanhook && build.cmd` (builds dbghelp.dll + hooktest.exe),
verify `./hooktest.exe` prints PASS, `copy dbghelp.dll ..\..\dbghelp.dll`.
Per-hook debug: `AOE2LAN_STAGE=6 AOE2LAN_HOOKS=<ids> AoE2DE_s.exe`
(ids: 0-3 provider, 4 LogHelper, 9 LogHelper2, 5-8 ENCRYPTED, fatal, debug
only). Unattended stability check: stage 1/4/5 = alive 30 s+, stage with any
of 5-8 = exit 0 ~5.6 s. Fresh `.cmd` launchers live in the game dir
(PLAY-stage1-SAFE/stage4-M03/stage6-M02).

### 10e. Operator supervised M0.2 walk (2 runs, stage 6 v3) — the login chain captured
Full sequence from logs/lanhook-19340.log (menu idle, then MP click):
  t=1.2s   WorldwideLoginService ctor
  t=4.0s   "Requesting ticket" / "OnRequest app ticket returned %c"(r8='N') /
           "SteamAuth received ticket at t=%I64u"  <- RUNE emu's ticket flow WORKS
  t=6.7s   "Found %zd profiles for account %s" r8=0  <- rlink login reaches
           reliclink.com, parses, account has ZERO profiles
  t=14.0s  "Adding LAN relay server: %s, GUID %s" s8=192.168.0.104 (my
           freshly-started stock relay, new GUID per run) <- broadcast
           discovery live, pre-login, at menu idle
  t=115.8s "Found 0 profiles" again (login retry cycle ~110 s)
  t=117.9s "XalBrowserHandles: commandLine: %s" s8="\"WebClient.exe\"
           \"https://sisu.xboxlive.com/client/v68/0000000040225237/..."  <- MP
           CLICK: game escalates to XBL browser sign-in (XAL, sisu endpoint,
           ClientId 0000000040225237 = xboxservices.config TitleId family)
  t=133.7s "Browser returned an error: User manually closed web view" /
           "Response was cancelled." / "XalSignInAsync, sign in aborted"
  LogHelper2 (0x1402ABC80): ZERO hits — no BattleServerRelay::Start ever ran;
  the game never CONNECTS to the discovered relay, hosting is gated on login.
CONCLUSIONS (M0.2 final for this session):
  - SteamAuth ticket: works (RUNE).
  - rlink login: network + parse works; 0 profiles => no defaultProfileInfo,
    no relayServers[] in the response the game would use.
  - Broadcast-discovered relay: accepted pre-login (M0.2's premise inverted:
    login provides NOTHING, broadcast provides the relay).
  - MP UI gate: profile acquisition, escalating to XAL sisu browser sign-in
    when clicked. H1 (M1) must synthesize the profile/login state at or
    above the rlink layer; the XAL web flow is the visible symptom, not the
    seam (the seam is the rlink login response + profile selection).
  - => ORDERING: M1 (LoginShim) BEFORE the two-machine M0.2 run. M0.2's
    remaining question ("starting LAN hosting" + both peers relay over a
    tailnet IP) is fully instrumented and waiting on H1.
M1 targeting notes from this run (for next session):
  - "Found %zd profiles for account %s" caller ret=0x...+0x4f4542 (LogHelper
    ret offsets: init=+0x4f0062, profiles=+0x4f4542, XalBrowser=+0x38c20c,
    sign-in-abort=+0x36e49f, ticket=+0x3ff59a area) — these retaddrs pin the
    login-state-machine fns for H1 work (compute VA = ret - gamebase, then
    match in the decrypted dump; remember the Arxan rule: hook only
    clean-on-disk fns or go vtable/data-side).
  - "Found 0 profiles" r9 = account-name string ptr (SEH-deref failed in
    logger: not plain ASCII at that address — likely std::string/wchar or
    the ptr is a temp; next iteration could log r9->ptr deref).
  - Login retry cycle is ~110 s — H1 must answer the retry too, not just
    boot.
  - Optional probe (operator's call): letting the sisu webview complete with
    a real MS account once would prove the entire downstream (lobby, hosting,
    relay connect) unmodified — but it binds a real identity to a cracked
    client; the PLAN's R3 (synthetic profile) avoids needing this.
