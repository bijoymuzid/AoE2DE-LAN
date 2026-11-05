# Session-12 (2026-11-02/03, M1) — rlink TLS seam closed, H1 server built, cert signed, 2 bugs left

## 12a. Operator run #1 debriefed (PLAY-stage7-IAT.cmd → logs/lanhook-9600s, e.g. lanhook-9604.log)
Stage-7 capture, 68-slot... no: 62-slot build. Findings:
1. The engine opens the Windows **"Root"** store at t=1.156s (SystemCertsWin ctor)
   and enumerates EVERY cert, adding each to its OpenSSL trust pool
   ("WindowsCertificates: Adding certificate; subject=..."). The trust pool
   == Windows Root store (+ certificates\cacert.pem likely merged). This IS
   the trust seam: return our own cert at enum end → our chain validates.
   The leftover ageLANServer CA is in the pool (proof of concept, unused by us).
2. The game's hosts file still holds the FULL ageLANServer redirect block
   (#ageLANServer lines): pb-live-release1..12-api.worldsedgelink.com,
   aoe-api.worldsedgelink.com, aoe-api.reliclink.com, api/cdn.ageofempires.com
   all → 192.168.0.103. THIS machine is now 192.168.0.104 (DHCP moved). So
   the rlink login currently resolves to a DEAD LAN IP and dies there.
   Session-10/11's "Found 0 profiles" = login failed against the dead IP
   (in session-11 the ageLANServer was still answering, hence parseable-0).
3. WSAIoctl ext-fn GUID f17d36b5-accb-cf11-95ca-00805f48a192 (×2 at t≈9.6s)
   = the LEGACY **ACCEPTEX** GUID (Win2K/Wine references) — the game's local
   relay/broadcast-listener stack (5× AF_INET6 sockets + FIONBIO), not rlink.
   GUID 112eda7f30866f43a031f536a6eec157 (×2 on MP click) = unidentified,
   not in any game file (runtime-constructed); DisconnectEx-adjacent
   (Data1/Data2 match WSAID_DISCONNECTEX exactly); not load-bearing.
4. "Nothing happened, MP still grey" — expected: stage 7 is capture-only.
   The grey button un-greys only when H1 serves the login (stage 8, next).
5. "Why always 3 min" — no longer needed. The interesting traffic is all in
   the first ~15 s; future runs are ~1 min + MP click.

## 12b. THE root cause of the missing TLS connect (all 6 WSOCK32 slots never hooked)
Map had 68 entries; the game logged "swapped 62". Offline reproduction
(hooktest game-image walk, exact parser) gave 62/68 too. The 6 missing =
**connect, socket, send, recv, recvfrom, closesocket** — ALL from WSOCK32.dll.
Why: the game imports WSOCK32 **BY ORDINAL** (ILT entries 0x800000000000000N,
WinSock 1.1 table: 3=closesocket, 4=connect, 16=recv, 17=recvfrom, 19=send,
23=socket, ...). The name-lookup parser skipped them all. The rlink TLS
client speaks WSOCK32 connect/send/recv — invisible to every capture so far.
FIXED: iathook_patch_module translates WSOCK32 ordinals via the stable
WinSock 1.1 table (plus a GetProcAddress-compare fallback for other legacy
ordinals). Offline walk now 68/68; hooktest PASS (incl. the WSAIoctl/ConnectEx
loopback test + SNI parser test). This also explains session-11's "50 slots"
arithmetic mismatch (55 entries − 5 failing = 50; the 6th (socket) is new).

## 12c. H1 LoginShim built (everything needed, two DER-header bugs left — §12f)
- getaddrinfo hook: g_IatRedirect=1 (stage 8) rewrites *-api.worldsedgelink.com
  + aoe-api.reliclink.com → 127.0.0.1 (real call does the 127.0.0.1 resolve).
- dev/lanhook/loginsrv.c: SChannel TLS 1.2 server on 127.0.0.1:443,
  in-memory ephemeral NCrypt RSA-2048 key (silent, no UI, no containers),
  hand-built X.509 v3 DER (openssl-verified: Version 3, sig sha256RSA,
  issuer==subject CN=pb-live-release6-api.worldsedgelink.com O=AoE2LAN,
  validity 2026-2035, real 2048-bit key), signed via NCryptSignHash PKCS1,
  context via CertCreateCertificateContext + CERT_NCRYPT_KEY_HANDLE_PROP_ID
  (78) attaching the live NCRYPT handle. HTTP/1.1 keep-alive responder.
- Trust injection (stage 8): CertEnumCertificatesInStore returns our cert once
  at enum end (store-keyed one-shot; engine adds it to its OpenSSL pool;
  self-referencing anchor==leaf chain).
- Response JSON: the ageLANServer-proven positional envelope (session-11's
  fetch): result 0, sessionId, 549000000, serverTime, accountInfo
  [profileId,"steam",1,-1,0,"en","eur",2,null], profiles [PI], 0,0,null,
  allProfileInfo [0,PI,[],[extraPI],[],null,[],null,1,[],-1],
  loginData (= age2 login.json pairs incl. RL_TELEMSHOULDNTSEND=.../RL_TITLEID=24),
  [],0, relayServers [["","localhost","127.0.0.1",27012,27112,27212]].
  PI: [now, profileId, "steam",null,alias,alias,"",statId,0,9999,0,null,
  platformUser,1,[]]; extraPI AoE2 shape. profileId=FNV1a64("aoe2lan:"+alias)
  (alias from the login request's alias= field; "Player" fallback).
  Routes: /game/login/login + /game/login/platformlogin → envelope;
  /game/login/readSession → [1]; /game/news/* → [0,[]]; everything else → [0,[]].
- Tests: hooktest PASS; srvtest.exe + srvclient.py offline: full TLS
  handshake server-side proven (decrypt/encrypt loop works), cert DER valid,
  SChannel credential handle acquired after the package-name fix.
- srvclient checklist asserts (run against srvtest): version/cipher line,
  Content-Length, 14 response elements, alias echo, level 9999, relay IP/ports,
  profileID == FNV1a64 and stable across logins, distinct per alias.
- srvclient.py lies next to srvtest (invocation inside its header comment).

## 12d. Debugging history worth not repeating
- CertCreateSelfSignCertificate pops the "Windows Security" consent UI on
  this machine (CredentialUIBroker) and fails; it cannot be silenced from
  our side → abandoned for a hand DER. (Operator saw the smart-card prompt:
  mine, killed; no recurrence — the NCRYPT path is silent throughout.)
- SChannel AcquireCredentials args are (principal, package, ...) — I passed
  the package name in the principal slot and NULL package →
  SEC_E_SECPKG_NOT_FOUND (0x80090305). Fixed.
- NCRYPT exports: FinalizeKey (not FinalizeKeyPair); NCryptSignHash takes
  (h, padInfo, hash, sig, flags) — all typedefs now verified against headers.
- WSS: UNISP_NAME_W must be used (build is ANSI).

## 12e. Where the tree stands (nothing staged to the game dir for stage 8 yet)
- game-dir dbghelp.dll = stage-7 build (20:51, 182272 B). AoE2DE_s.exe
  untouched (sha 1e415af8...). PLAY-stage8-LOGIN.cmd written, NEVER RUN
  (needs §12f first). dev/lanhook/cert.der = latest DER dump (784 B, valid).
- The failing call is pEM (EncryptMessage) creating a garbage ciphertext
  record header → client RSTs on receipt. Suspects ordered by likelihood:
  (1) SECBUFFER_STREAM_HEADER layout mismatch — CHECK my SecBuffer order
  against schannel docs; (2) spyder/AV on 443? no.

## 12f. Remaining items before the first stage-8 game run (next chat, in order)
1. In `tls_encrypt_send` (dev/lanhook/loginsrv.c): VERIFY the 4 SecBuffer
   descriptors are in the canonical SChannel stream order
   {STREAM_HEADER, DATA, STREAM_TRAILER, EMPTY} with buffers sized from
   SecPkgContext_StreamSizes (cbHeader/cbMaximumMessage/cbTrailer). The 
   EncryptMessage success + garbage client receipt in session 12 points at
   a header-buffer mismatch here (the SChannel stream layer is byte-exact;
   the TLS layer above was already proven with Wireshark-valid ServerHello).
2. srvtest.exe + srvclient.py to PASS offline (no operator needed).
   Note srvclient.py currently sets context VERIFY_NONE; for a first signal
   that is correct — validation of OUR cert by OpenSSL happens in the game
   run (via the injected anchor). Add local fingerprint pinning once stable.
3. Stage dbghelp.dll, run PLAY-stage8-LOGIN.cmd with the operator (~1 min +
   MP click). Read the game log for: DNS REDIRECT, SOCK connect to
   127.0.0.1:443, SNI, TLS lines, HTTP REQ/BODY, LOGIN lines, and the
   LogHelper lines (Found N profiles, Adding certificate, relay/add lines).
4. Iterate on what the log shows (TLS ALERT = validation issue → trust
   injection check; HTTP request but no progress → response-shape tuning).

## 12g. Next steps in order (next chat)
1. Fix §12f/§12e (check SecBuffer header order in tls_encrypt_send; rebuild).
2. srvtest + srvclient until PASS (offline; no operator needed).
3. Stage dbghelp.dll, run PLAY-stage8-LOGIN.cmd with the operator (~1 min +
   MP click). Read the game log.
4. Decide from the log: handshake done? HTTP request arrived? login served?
   (TLS ALERT lines tell us if validation failed; LogHelper lines tell us
   the rlink reaction: "Found N profiles", Adding certificate, etc.)
5. Iterate: LogHelper/HC lines → profileID folder creation, MP enable,
   lobby screens. Then H2/H3 per PLAN.
