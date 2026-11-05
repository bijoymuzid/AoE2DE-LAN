# Session-13 (2026-11-02 late, M1) — H1 login server FIXED end-to-end offline; first stage-8 run next

## 13a. Headline
Session 12's two "remaining bugs" (§12f) are dead: srvtest.exe + srvclient.py
now PASS offline end-to-end (TLS 1.2 handshake, HTTP, 14-element JSON
envelope, FNV1a64 profileID, stability, distinct aliases) and hooktest is
68/68 PASS. The new dbghelp.dll (185,344 B, 23:26) is staged in the game
dir; AoE2DE_s.exe untouched (sha 1e415af8...). Next: first supervised
PLAY-stage8-LOGIN.cmd run.

## 13b. THE bug list (what actually killed session 12 — do not rediscover)
1. **SP_PROT flag wrong**: `grbitEnabledProtocols = 0x00000800` is
   SP_PROT_TLS1_2_CLIENT; an INBOUND (server) credential needs **0x00000400**
   (SP_PROT_TLS1_2_SERVER). Symptom: AcquireCredentials → SEC_E_NO_CREDENTIALS
   (0x80090331). (Session 12 mislabeled the constant in its comment.)
2. **The §12f "EncryptMessage emits garbage" root cause: wrong PfnEM/PfnDM
   typedefs.** Both are 4-arg SEC_ENTRY/__stdcall:
     EncryptMessage(ctx, fQOP, pMessage, MessageSeqNo)
     DecryptMessage(ctx, pMessage, MessageSeqNo, pfQOP)
   The old 3-arg (ctx, pMsg, flags) call shifted the stack: the SecBufferDesc
   ptr landed in fQOP and NULL in pMessage → AV inside pEM. DecryptMessage
   happened to survive (its arg order shifted less fatally). This is THE fix
   session 12 was hunting in the SecBuffer layout — the buffers were fine.
3. **Cert minting: the NCrypt ephemeral + hand-DER + property approach is
   ABANDONED.** Even with a perfect DER (fixed a missing BIT STRING wrapper
   in my SPKI — openssl flagged "Unable to load Public Key"), the
   CERT_KEY_CONTEXT_PROP_ID/prop-78 key association never satisfied
   CryptAcquireCertificatePrivateKey (CRYPT_E_NO_MATCH) or SChannel
   (SEC_E_UNKNOWN_CREDENTIALS / SEC_E_NO_PRIVATE_KEY). Root cause not fully
   pinned (CSP-vs-CNG key matching); replaced wholesale.
4. **Working cert path: silent CSP self-sign.** Unique per-launch container
   ("aoe2lan-<tick-hex>"), CryptAcquireContextA(PROV_RSA_AES,
   CRYPT_NEWKEYSET|CRYPT_SILENT), CryptGenKey(AT_SIGNATURE, 2048<<16|
   CRYPT_EXPORTABLE), CertStrToNameW + CertCreateSelfSignCertificate
   (subject = CN=pb-live-release6-api.worldsedgelink.com, O=AoE2LAN, 9-year
   validity). NO consent UI appears on this path (the session-12 UI pop was
   the default-container path; the unique container avoids it). Cert is
   re-acquired (no NEWKEYSET) after self-sign so CACPK resolves.
5. **CryptAcquireContextW vs A**: loginsrv resolved ...W but passed a char*
   container name (ANSI) → UTF-16 mojibake container → NTE_BAD_KEYSET
   (0x80090016) at CACPK. Fixed: resolve **CryptAcquireContextA**.
6. **Record assembly (canonical SChannel stream pattern)**: ONE contiguous
   block [STREAM_HEADER|DATA|STREAM_TRAILER], plaintext memcpy'd at
   rec+cbHeader, EncryptMessage in place, send the whole block as one record.
   Session 12 used three separate stack buffers + 3 send() calls with
   pre-encrypt sizes (and an offset bug: plaintext at rec+0, not the DATA
   slot). Stream sizes from QueryContextAttributes are cbHeader=13,
   cbTrailer=16 (AES-GCM), and cbBuffer sizes do NOT change after the call.
7. serve_conn: tls_decrypt now blocks on recv when inLen==0 (was -2
   busy-loop); http_respond uses a 512-byte static head + 16KB static big[]
   (session 12's 160-byte stack head overflowed); platformUser terminates.
8. **JSON envelope bracket bugs**: after the second profileInfo, `"],[],["`
   closed allProfileInfo early (its contents spliced into the top array);
   correct emit is `",[],["` (element 2 is [], element 3 = extraProfileInfo
   array). Net envelope = 14 top-level elements, [9]=allProfileInfo (11
   elements), [10]=loginData, [13]=relayServers — verified by json.loads.
9. srvclient.py: recv loops stop at Content-Length (server is keep-alive;
   waiting for EOF hangs); assertions corrected (accountInfo[1]=="steam",
   extraPI is data[9][3] directly, 19 fields).

## 13c. Current verified behavior (offline)
- TLS 1.2, ECDHE-RSA-AES256-GCM-SHA384, self-signed cert served, cert DER
  dumped to dev/lanhook/cert.der (788 B) each run for inspection.
- POST /game/login/platformlogin with alias= → full envelope; profileID =
  FNV1a64("aoe2lan:"+alias); stable across logins; distinct per alias.
- keep-alive works (three sequential requests per run in the test).
- DNS REDIRECT logic unchanged (iathook getaddrinfo, stage 8): any
  *-api.worldsedgelink.com or aoe-api.reliclink.com → 127.0.0.1. The hosts
  file's stale ageLANServer block (→192.168.0.103) is bypassed because our
  hook rewrites the node BEFORE the real resolver runs.
- Trust injection unchanged (CertEnumCertificatesInStore app-end one-shot).
- Stage 8 in lanhook.c: IAT patch → loginsrv_start() → g_LoginInjectCert →
  LogHelper detours 4+9 (clean-on-disk only, Arxan rule honored).

## 13d. Ready for the first supervised run
PLAY-stage8-LOGIN.cmd (unchanged): AOE2LAN_STAGE=8 + telemetry env, start
AoE2DE_s.exe. Operator: sit at menu ~1 min, click Multiplayer once, quit.
Then read logs/lanhook-<pid>.log for, in order:
  "iathook: swapped 68 IAT slots" (hook layer up)
  "srv: H1 login server listening on 127.0.0.1:443 (TLS)" (H1 live)
  "DNS REDIRECT ...-api.worldsedgelink.com -> 127.0.0.1" (redirect fired)
  "SOCK connect 127.0.0.1:443" (TLS transport connected)
  "TLS: handshake complete (server side)" + "HTTP REQ /game/login/..."
  "LOGIN: serving synthetic profile, alias=..." (H1 answered)
  "CRYPT32 INJECT: own cert appended to store enum" (trust injection fired)
  LogHelper lines: "Found N profiles" (N should now be 1), any TLS ALERT
  (= validation issue), "Adding LAN relay server", XAL escalation (bad).
Failure triage: bind FAILED = port busy; no DNS REDIRECT = hook timing;
TLS ALERT after ServerHello = trust injection missed the enum window;
HTTP REQ but login fails = response shape (iterate envelope).
Login retry cycle ~110 s — if the first attempt raced DLL init, the retry
should catch it.

## 13e. Tree state
- dev/lanhook/loginsrv.c: rewritten as above (cert = CSP self-sign; dead
  hand-DER/NCrypt typedefs remain at top, unused, harmless).
- dbghelp.dll staged in game dir at 23:26 (185,344 B), .prev-stage7 copy
  kept in dev/lanhook/. hooktest.exe PASS, srvtest.exe+srvclient.py PASS.
- certtest*.c scratch files deleted.
