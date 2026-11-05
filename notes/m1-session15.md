# Session-15 (2026-11-03 evening, M1) — TRUST CRACKED: live TLS+HTTP with the game's verifying client; cert trust is SOLVED

## 15a. Headline
The session-14 wall — "the game's rlink client silently closes after our
Certificate" — is broken. In the supervised run (logs/lanhook-5656.log) the
game's own OpenSSL TLS client **completed a full TLS 1.2 handshake against our
in-process SChannel server with our self-signed cert** (CKE+CCS+Finished at
t=30.328s, "TLS: handshake complete (server side)"), then sent an encrypted
HTTP POST (`/game/news/getNews`) and accepted our 193B response. The trust
chain works. M1's remaining work is now ENVELOPE/SERVE-side, not trust.

## 15b. The full live sequence (lanhook-5656.log — read this, not the theory)
- t=0.078: 68/68 IAT slots, login server listening, cert minted (der=958,
  ONE mint, CACPK ok), TLS set hooks installed (CTXSetVerify/CTXSetStore/
  StoreAddCert — clean-on-disk OpenSSL fns, added this session).
- t=1.266: SystemCertsWin pool build: 513 X509_STORE_add_cert hits (the game
  builds SEVEN+ stores, each re-fed the Windows Root certs + our injected one
  — CRYPT32 INJECT fired; our cert is in the pools).
- t=4.219: attempt 1 — ClientHello (SNI pb-live-release6-api.worldsedgelink.com)
  → we send ServerHello+Cert+CKE-flight (1427B, same bytes both attempts —
  earlier "two serials" was MY bad regex: the log hex is column-truncated;
  full-hex reassembly proved identical certs) → client sends bare close_notify,
  NO alert, NO CKE. **No CTXSetVerify had fired for this ctx** (mode never set
  → SSL_VERIFY_NONE by default) — an unverified early ctx that still closed:
  NOT a trust failure; a game-side artifact (early-boot HTTP object, likely
  torn down by its own retry logic before finishing).
- t=15.141: **cert: user-Root registered (schannel trust path live)** — the
  operator's "YES" click. RootRegThread's CertAddCertificateContextToStore to
  CurrentUser\Root COMPLETED (it had hung in session-14's mkprobe; on this
  interactive launch it prompted and the operator approved it).
- t=29.500: **HIT CTXSetVerify #1: ctx=…46fb0 mode=3 (SSL_VERIFY_PEER|
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT) cb=NULL ret=game+0x5E06D1** — the game built
  a NEW SSL_CTX with default OpenSSL verification ON.
- t=30.281: attempt 2 — ClientHello → our 1427B → client sends
  ClientKeyExchange(102B)+CCS+Finished(40B) = 158B → **handshake complete** →
  our 51B CCS+Finished → client sends 396B encrypted POST
  `/game/news/getNews` → our 193B encrypted JSON response. FULL SUCCESS.
- t=90.641: attempt 3 — ClientHello sent but **never accepted**: our server
  was single-connection (ServerThread parks in serve_conn's keep-alive recv
  on conn 2). Client waited 30s, close_notify at t=120.7. FIXED this session
  (per-connection worker threads, 60s recv timeout).
- No "Found N profiles" yet: the login POST itself never arrived on the live
  run (only getNews). The game's login request ordering/what triggers the
  POST is the next unknown — instrumented answer: watch the next run.

## 15c. Why trust works (mechanism, verified live + statically)
1. The client stack = static OpenSSL 1.1.1g + gRPC 1.51.1 (vcpkg, paths in
   the log strings), called via tsi_create_ssl_client_handshaker_factory_
   with_options (0x14278fee0, mapped 1:1 to ssl_transport_security.cc:
   verify_cb=0x142791090 "Certificate verify failed", root-load path,
   PARTIAL_CHAIN|TRUSTED_FIRST flags, line numbers 2119/2124/2128/2150/2156
   all match).
2. No-ALPN ClientHello ⇒ httpcli-style options (no ALPN) — the rlink login
   uses gRPC's httpcli/ssl_utils path (httpcli_security_connector.cc,
   HttpRequestSSLCredentials).
3. gRPC's DefaultSslRootStore is DEAD on Windows 1.51.1 (verified in dump:
   LoadSystemRootCerts = empty-slice stub 0x1427917b0; env config
   grpc_default_ssl_roots_file_path reads GetEnvironmentVariableA (IAT
   0x143197560) and is unset; installed_roots_path = "/usr/share/grpc/
   roots.pem" (slot 0x1440d99a8) — nonexistent; ssl_roots_override_cb
   global 0x144827058 never written anywhere in .text). So the LIVE verify
   path is the game's own: SystemCertsWin pools (513 add-certs at t=1.266)
   + our Windows-Root registration (t=15.141) + the enum injection.
4. Mode 3 + cb=NULL (t=29.5) ⇒ default OpenSSL verify against the ctx's
   store — and it ACCEPTED our self-served cert. Trust = our cert in the
   store(s). DONE. (The t=4.2 failure predates the user-Root registration at
   t=15.1 — timing is consistent with the registration being required for
   the FIRST ctx too, though that ctx had no set_verify call at all.)
5. Hookable-clean-OpenSSL-fns inventory (E9-safe, all clean-on-disk):
   SSL_CTX_set_verify 0x14292BC30 (mov [rcx+0x158],edx; mov [rcx+0x188],r8),
   SSL_CTX_set_cert_store 0x14292BA40, X509_STORE_add_cert 0x14297D450,
   CTX_get_cert_store 0x14292B4F0, STORE_set_flags 0x142972DD0,
   STORE_get0_param 0x142972C30, STORE_up_ref 0x142972E20, tsi verify_cb
   0x142791090, populate_ssl_context 0x14278F0B0. ENCRYPTED-at-rest:
   SSL_CTX_new 0x14292B530, tsi factory 0x14278FEE0, ssl_utils init
   0x1426CCAA0, httpcli connector 0x1428B3A70?? (clean! but its caller
   0x142666460 encrypted), DefaultSslRootStore getters 0x1426CDC20/70 (clean).

## 15d. What did NOT change (don't rediscover)
- The hosts file still maps api.ageofempires.com/cdn → dead 192.168.0.103
  (SOCK connect 192.168.0.103:443 spam in the log). Harmless for login;
  optionally clean the hosts file later.
- The 62ms-delay theory for attempt 1 is DEAD: attempts 1/2/3 all show the
  same ClientHello/ServerHello bytes; attempt 1's client closed without
  CKE while having NO set_verify (mode 0). It's a client-side early-boot
  artifact, not trust, not our server timing.
- "Two different certs served" — FALSE (log hex truncation artifact; both
  1427B flights byte-identical after full reassembly).

## 15e. Fixes shipped this session
- loginsrv.c: ServerThread now spawns a ConnWorker thread per accepted
  socket (60s SO_RCVTIMEO) — the t=90 retry starvation is gone.
- loginsrv.c: log_resp_head — every route response body head is logged
  (HTTP RESP BODY) so the serve side is no longer dark.
- lanhook.c/hookcore.c: TLS inspection hooks ids 10-12 (CTXSetVerify/
  CTXSetStore/StoreAddCert, kind HK_TLS, cap 512 lines, game+offset
  printing via hc_set_modbase) — installed by stage 8 alongside
  LogHelpers 4+5 ("hook filter: only 4:LogHelper,5:LogHelper2 + TLS set").
  Data-side logging only; original fns run via trampolines.
- game-dir dbghelp.dll = 231ce99d… (189,440 B). Build: hooktest PASS
  (68/68), srvtest+srvclient PASS (TLS OK, JSON 14 elements, resp-body
  logging live). AoE2DE_s.exe untouched (sha 1e415af8…).

## 15f. Next session (M1, in order)
1. One more supervised run with the new build (per-conn workers + response
   logging). Expect: every login cycle accepted, HTTP REQ lines for the
   actual login POST (`/game/login/platformlogin` with alias=), HTTP RESP
   BODY visible. If the POST arrives: the envelope is proven live and the
   only remaining question is the game's parse ("Found N profiles" via
   LogHelper #4 — want 1).
2. If getNews parses but the login POST never fires: look at request
   ordering (the game may want /game/login/login FIRST or a session read
   before platformlogin — check the captured sequence; add routes as
   observed).
3. XAL escalation check: with a served profile, MP click should NOT pop
   the sisu browser sign-in. If it still does: the "NON XBOX" branch work
   (PLAN §6.1) is next (H1 remaining scope), sites from session-11 notes.
4. RootRegThread prompt: interactive launches will show the Root consent
   once per NEW cert (per-launch container). Options: keep (operator clicks
   once), or move to enum-injection only. DO NOT re-run mkprobe-style dead
   ends. NOTE: the registration is currently part of the live trust path —
   treat it as load-bearing until a run proves otherwise.
5. Remaining noise: 192.168.0.103 connects (hosts file) — clean up when
   convenient.

## 15g. Session artifacts
- logs/lanhook-5656.log — THE run: complete trust-success evidence.
- dev/lanhook/: build.cmd unchanged; loginsrv.c (ConnWorker + resp logging);
  lanhook.c (TLS hook defs); hookcore.{c,h} (HK_TLS kind, g_ModBase).
- staged game-dir dbghelp.dll 231ce99d…, .prev copies in dev/lanhook/.

## 15h. RUN 2 (lanhook-14908.log, AFTER the envelope fix) — session ALIVE, still 0 profiles
- The object-form envelope WAS served ("HTTP RESP BODY {"resultCode":0,...}").
- Game answered: read the response, then **"Found %zd profiles" STILL r8=0** at
  t=4.047 (110ms after the platformlogin response) — the profiles element
  parse is still failing somewhere INSIDE the profile object (candidates:
  banInfo:null, metaData:{}, presencePropertyInfo:{} — the element parser
  0x140620540's value readers may reject null/nested-object shapes — or the
  big raw-JSON-number id).
- **HUGE progress though**: the game now treats our session as REAL — it
  long-polls `/game/login/readSession` with `ack=0&pollNum=N&sessionID=
  1193733145` (206 polls over ~2min, ~0.5s cadence, keep-alive connection
  working, per-connection server workers OK). Our `[1]` array answer is
  almost certainly the wrong shape for readSession too (object form?).
- First launch aborted (lanhook-10892): died right after user-Root
  registration (t=1.312) before first login — environmental early-exit band
  or the Root-prompt click raced process startup; second launch ran fine.
  The Root consent prompt appears once per launch (new per-launch container
  = new cert = new prompt each run).
- MP still grey (no profile → no defaultProfileInfo → button dead).

## 15i. Next steps for session 16 (in order)
1. Disassemble the profiles-ELEMENT parser 0x140620540 value readers
   (banInfo / metaData / presencePropertyInfo / id / linkedPlatformAccounts)
   — find which value shape kills the parse; fix the envelope accordingly.
   Cheap experiment first: swap banInfo:null→{} , metaData:{}→"{}"?? no —
   read the code; also test id as STRING.
2. readSession: find its parser (search "ack"/"pollNum"/"readSession" log
   strings + the response reader — likely fn near 0x140615b70 family) and
   serve the right object shape (probably carries profile/event updates).
3. THEN check: "Found N profiles" want ≥1 → MP un-grey → AET_Login events.
4. The 2131B first-attempt close_notify mystery from run 1 did NOT recur
   in run 2 (single attempt, straight to success) — the t=4.2 failure was
   a one-off; don't chase it unless it returns.
