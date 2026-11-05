# Session-14 (2026-11-03, M1) — filter bug fixed, full H1 chain live to TLS, cert-trust is the last blocker

## 14a. Headline
Stage 8 now RUNS: the game boots, swaps 68 IAT slots, starts our TLS login server,
redirects the rlink DNS, and the game's own client CONNECTS to 127.0.0.1:443 and sends
a real ClientHello. The handshake then dies at the certificate-trust check. Everything
before the cert check is proven; the login envelope is proven offline. ONE problem
remains: making the game's rlink TLS client trust our served cert.

## 14b. THE bug that killed the first supervised runs (do not rediscover)
Session 13's stage-8 filter was `g_Only[4]=1; g_Only[9]=1`, believing id 9 =
LogHelper2. Actual g_Hooks order (decoded from the staged DLL's own table bytes,
nameptr at va-off−8): 0-3 provider, **4=LogHelper(0x1402BCB30), 5=LogHelper2
(0x1402ABC80)**, 6-8 encrypted fns, **9=StartAdjacent(0x140771600)** — encrypted,
Arxan-fatal. So the filter installed an Arxan-watched function at t≈0.3s and the
game silently exited ~1-4s later. FIXED: stage 8 forces ids 4,5 now. The filter line
prints "hook filter: only 4:LogHelper,5:LogHelper2". Also hardened the
AOE2LAN_HOOKS parser: out-of-range ids are logged+skipped instead of silently
setting an empty filter.

## 14c. Verified live chain (logs/lanhook-*.log, e.g. 13760/9464/3036)
- 68/68 IAT slots, login server "listening on 127.0.0.1:443 (TLS)", LogHelpers
  installed, game alive 25s+ unattended (kills are the 5-15s environmental band —
  stage-1 control shows the same; NOT a crash, no WER events, no BsSndRpt).
- t≈3.5s "Requesting ticket" → "SteamAuth received ticket" (RUNE emu OK).
- t≈3.6s "DNS REDIRECT pb-live-release6-api.worldsedgelink.com -> 127.0.0.1 svc=443"
- t≈3.7s "SOCK connect 127.0.0.1:443" → "srv: connection accepted"
- ClientHello (204B, parsed fully in notes below): TLS1.2, 18 suites (c02c...002f),
  SNI=pb-live-release6-api.worldsedgelink.com, extensions: SNI, status_request(v1),
  supported_groups(001d/0017/0018), ec_point_formats, sig_algs, session_ticket,
  ext_master_secret, renegotiation_info. NO ALPN offered. Classic OpenSSL 1.1.x shape.
- Our ServerHello+Cert+... is sent; client replies with a bare close_notify
  (15 03 03 00 02 01 00) — no fatal alert — and our server logs
  "TLS: handshake failed st=0x00090317" (=SEC_I_CONTEXT_EXPIRED; server-side
  symptom of the client's close). The REAL failure is client-side and silent.
- After the failure the game itself opens WinHttp (through its own IAT, agent
  "WinHttp request to force windows trusted root certificate program to downloa...",
  caller game+0x5E70F4, encrypted region) and GETs /statistics on the rlink host —
  the game's own "maybe my roots are stale" retry heuristic. It then retries the
  login every ~5s. NO "Found N profiles" line ever appears (parse never happens).

## 14d. Cert work done (all shapes tested against the game; ALL still fail)
1. SAN-only (session-13 fix): CryptEncodeObjectEx(X509_ALTERNATE_NAME) → CERT_EXTENSION
   Value blob → CSSC. Embeds correctly (openssl shows DNS:host). Learned: CSSC expects
   the Value blob to be the ENCODED inner value; a decoded struct pointer or my
   hand-rolled [2]OID+[0]string guess reads as garbage (certext.c cases A/B/C —
   the ground-truth harness for this).
2. Full ageLANServer shape (certext.c case F, ported to loginsrv.c): KU critical
   DS+KE+KC (DER 03 02 02 A4), EKU serverAuth+clientAuth, BC critical CA:TRUE
   pathlen:0 (30 06 01 01 FF 02 01 00), SAN 3 entries (exact host + *.worldsedgelink.com
   + aoe-api.reliclink.com), SHA256 (szOID_RSA_SHA256RSA in CSSC's sigAlg param).
   openssl verify -CAfile cert.der cert.der = OK. STILL fails with the same code.
   (ageLANServer's own anchor ALSO has SKI; ours does not — only remaining shape delta,
   considered unlikely to matter.)
3. Windows Root store add (ageLANServer's actual mechanism): **CertAddCertificateContextToStore
   to CurrentUser\Root HANGS INDEFINITELY on this machine** — no UI, no completion,
   reproducible in a 20-line standalone (mkprobe.c). DEAD END for the auto-install
   path. The RootRegThread in loginsrv.c is inert/deferred — first connection never
   triggers it (code path deferred-to-first-connection exists but the serve path never
   calls it; harmless).
4. GetChain additional-store injection (Hook_CertGetCertificateChain builds a Memory
   collection store with our cert as hAdditionalStore): NEVER FIRES — the game never
   calls CertGetCertificateChain through its IAT on this path. Inert code, left in.

## 14e. THE key discovery: what the game's rlink TLS client actually is
- Static **OpenSSL 1.1.1g** (string "OpenSSL 1.1.1g  21 Apr 2020" at file 0x35a26d0)
  + **gRPC v1.51.1** (build path strings
  "F:\Agents\PhoenixBuilder-07\...\_vcpkg\grpc\src\v1.51.1-..." at 0x3521b98 etc.).
- gRPC-TLS client strings present: "tsi_ssl_frame_protector", "ssl_alpn_selected_protocol",
  "Cannot check peer: missing selected ALPN property.", "call host does not match SSL
  server name", "grpc_ssl_credentials_create(pem_root_certs=%s, ...)", "Certificate
  verify failed with code %d", "Cannot load server root certificates.",
  "Invalid server name indication %s.", "No match found for server name: %s.",
  default cipher list "TLS_AES_128...:ECDHE-RSA-AES256-GCM-SHA384" + "Falling back to
  TLS 1.2." and "/usr/share/grpc/roots.pem".
- The game EMBEDS its own RelicLink CA (extracted: dev/lanhook/reliclink-ca.der,
  1433B): self-signed, CN=battleserver.reliclink.com, O=Relic Entertainment,
  OU=RelicLink, RSA **4096**, sha256, 2018→2068, serial
  7254328DEF8B9610D045E45D362DA7FA2DEF5503, **NO extensions at all** (not even
  basicConstraints — file 0x3676E40, length from 30 82 05 95). So bare self-signed
  anchors ARE acceptable to this engine's TLS stack — extension shape is NOT the issue.
- The engine ALSO merges the Windows Root store into a pool at boot (SystemCertsWin,
  66 certs incl. our injected one — the count r8=0x42 includes it; the
  "WindowsCertificates: Adding certificate" line for /CN=pb-live.../O=AoE2LAN proves
  the enum injection lands in the engine's pool) and then adds the RelicLink CA
  (the "CN=RelicLin..." line, different reg signature a5=...0005, comes from CAPI
  memory not the store enum). Whether the rlink channel's SSL_CTX actually VERIFIES
  against that pool is the open question — evidence says NO (our cert is in the pool
  and the handshake still fails).
- Working hypothesis: the rlink channel is a gRPC secure channel whose
  pem_root_certs = the embedded RelicLink CA (and/or sslCertificates from a previous
  real login, cached in the RUNE/emu data dir), NOT the SystemCertsWin pool. That
  pool merge is for the WinHttp/webclient plane.

## 14f. Open leads for the next session (in order of promise)
1. **Recover the exact verify error.** The game's 1.1.1g error-string table is on
   disk (e.g. "unable to get local issuer certificate" at 0x35d3f70). The verify
   call site is in the encrypted set but DECRYPTED in dev/lanhook/gametext.bin.
   Route: from the known good LogHelper retaddrs / the gRPC strings region, find
   the channel-setup + verify code in the decrypted dump, decompile, read which
   store it loads and what X509_V_ERR code path aborts. This turns the mystery into
   a fact.
2. **Check for cached trust state**: `%SystemDrive%\Users\Public\Documents\Steam\
   RUNE\813780` and the game data root for any cached sslCertificates / login state
   the engine merges (the response field 'sslCertificates' is what the real server
   uses to update trust — see field-name block at file 0x3690d58).
3. **Serve a CA-signed chain**: mint a persistent CA (fixed CSP container, not
   per-launch) + a leaf signed by it; serve the leaf, enum-inject the CA. If the
   channel builds chains (rather than requiring the leaf itself in the store),
   this shape is closer to the real pb-live setup than a self-served anchor.
   (This is also the ageLANServer architecture: persistent CA + per-run leaf.)
4. **The /statistics WinHttp probe is a separate plane** (schannel via WinHttp) —
   if trust is beaten for it too it should return our fake data; not load-bearing
   for login but a useful second signal.
5. Wire-level fallbacks if data-side trust can't be beaten: hook the game's
   SSL_do_handshake inputs (BIO pair) — the game's TLS runs over OUR hooked
   send/recv already; the certificate message we serve could be REPLACED with the
   embedded RelicLink CA itself (we have the DER, 1433B) while keeping OUR key —
   no: signature check would fail. Real variant: serve the embedded CA as the
   anchor in the handshake (it's a CA, it IS self-signed) — we can't sign with it.
   So the realistic wire fallback is #1's outcome: find where the reject happens
   and what it compares, then feed it the exact bytes it wants.

## 14g. Tools and files added/changed this session
- dev/lanhook/certext.c + mkce.cmd — 3-way CSSC-extension ground truth harness
  (cases: raw-der-blob BAD, struct-pointer BAD, EncodeObjectEx-DER GOOD; case F =
  full ageLANServer shape) + dump mode (`certext2.exe d` prints SAN inner DER).
  NOTE: file was destroyed once by a bad scripted edit and rewritten; mkprobe.c is
  the Root-store-add hang reproducer (also dead-ends silently — use with timeout).
- loginsrv.c: SAN via EncodeObjectEx, full ageLANServer extension set, SHA256 sig,
  per-id-cert mint unchanged (unique CSP container per launch), RootRegThread
  (inert), GetChain hAdditionalStore injection (inert). srvtest+srvclient PASS.
- iathook.c: full ClientHello hex logging ("SOCK CH full <N>B ..."), WinHttpOpen/
  WinHttpConnect caller addresses (from=0x... via _ReturnAddress), AddCtx logging
  (never fires), g_Map index #defines (IDX_ADDCTX 55 etc. — VERIFY after any table
  edit: read nameptr at va-off−8 like session 14 did).
- lanhook.c: filter fix (ids 4,5), parser hardening, hook filter prints names.
- Stage-8 build in game dir: dbghelp.dll sha256 cc29e9e9... (188,416 B).
  Rollbacks: dev/lanhook/dbghelp.dll.prev-{stage8-broken,certbare,sanonly,chainenum}.
- Unattended test harness (inline python): launch with env, poll 22-26s, read
  newest logs/lanhook-<pid>.log. Deaths at 5-15s = environmental band (stage-1
  control shows it too); the runs that matter log past t=3.5s.
- AoE2DE_s.exe untouched (sha 1e415af8...). AgeLANServer CA still in both Root
  stores (harmless, never used by us; exported copy at C:\Users\Bijoy\temp-agelan.cer
  for shape reference only — operator rule: ageLANServer is reference-only).

## 14h. Expected log line order for the NEXT supervised run (when trust is fixed)
"iathook: swapped 68 IAT slots" → "srv: H1 login server listening" →
"hook filter: only 4:LogHelper,5:LogHelper2" → CRYPT32 INJECT (pool) →
"Requesting ticket"/"SteamAuth received ticket" → "DNS REDIRECT ... -> 127.0.0.1" →
"SOCK connect 127.0.0.1:443" → "TLS: handshake complete (server side)" →
"HTTP REQ /game/login/..." → "LOGIN: serving synthetic profile, alias=..." →
LogHelper "Found N profiles" (want 1). Triage: bind FAILED = port busy;
no DNS REDIRECT = hook timing; TLS ALERT/close = trust (the current frontier);
HTTP REQ but no progress = envelope tuning.
