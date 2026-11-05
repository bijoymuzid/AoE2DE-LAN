# Session-11 (2026-11-02 evening, M1) — IAT interception layer + login-plane mapping

## 11a. Entry state recap
M0 closed except the M0.2 two-machine run (blocked on M1). Login chain known
from stage-6 logs: SteamAuth ticket OK -> rlink login reaches server, parses,
0 profiles -> no defaultProfileInfo/relayServers -> MP grey; MP click
escalates to XAL sisu browser sign-in. Arxan rule (10b) hard: only E9-patch
fns whose disk bytes == decrypted dump; the login chain is all encrypted.

## 11b. Login-chain E9 sites: CLOSED (negative result, corrected math)
The PLAN's M1 entry offsets were miscomputed (wrong base subtraction).
Correct ret VAs from runtime base 0x7ff654570000 (logs/lanhook-19340.log):
  profiles call ret = 0x140674542   (call 0x14067453D)
  init     ret = 0x140670062
  XalBrowser call = 0x14061C207
  abort    call = 0x1405FE49A
  ticket   = 0x14076F595 / 0x14076F18A area (matches lea fns)
- profiles site: ENCRYPTED on disk AND shows DIFFERENT bytes in the t=70s
  dump than executed at t=6.7s -> Arxan re-encrypts/transforms after run.
- XalBrowser/abort: decrypted in dump, encrypted on disk.
=> No E9 site anywhere in the login chain. H1 must be data-side or below.
- "NON XBOX" selector: fn 0x140F0F990-0x140F10514 (encrypted), lea 0x140F0FBA5
  `lea rax,"XBOX-ish"; lea r15,"NON XBOX"; cmp [rsi+0x340],9; cmove r15,rax`.

## 11c. New machinery: iathook.c/h (game IAT pointer swap, data-only)
lanhook.dll (staged as game-dir dbghelp.dll) now swaps the game's OWN IAT
slots (import directory parsed at runtime from the in-memory PE headers,
VirtualProtect on the IAT page, one slot each, originals saved). ZERO game
code is touched -> outside the Arxan code-integrity rule entirely. Stage 7
(AOE2LAN_STAGE=7) = IAT-only build; no E9 detours.
- hooktest.exe extended: fake-PE unit test (parser swaps exactly the known
  slots, leaves unknown fns, stubs resolve). PASS.
- 50 slots live: WINHTTP(13) + WININET(11) + libHttpClient(16) + WS2_32/
  WSOCK32(11) + CRYPT32(4).
- All libHttpClient signatures verified against MS docs after three crash
  iterations (see 11e) — HCHttpCallResponseGetResponseBodyBytes is
  (call,size_t,uint8_t*,size_t*), RequestSetHeader has a 4th bool
  allowTracing, RequestSetRequestBodyReadFunction is
  (call,fn,bodySize,ctx). Post-call string reads are SEH-guarded.

## 11d. Login plane mapping (supervised runs, logs/lanhook-{3100,19352,5260,5672}.log)
- Run 1 (24 slots WinHttp+WinInet): ZERO traffic at login time. The game's
  own WINHTTP imports are not the rlink path.
- Run 2/3 (added libHttpClient): XAL + OneDS telemetry captured
  (title.mgt.xboxlive.com, self.events.data.microsoft.com) — but NO rlink
  login traffic. The HC plane = XAL/Xbox + Microsoft telemetry only.
- Run 4 (added sockets + CRYPT32): THE ANSWER —
    [t=4.484s] DNS resolve pb-live-release6-api.worldsedgelink.com svc=443
    (retried t=10.969s; also api.ageofempires.com, cdn.ageofempires.com,
    and DNS "localhost svc=4341" at t=10.188s — 4341 = game's local port?)
  => The rlink host for THIS build is pb-live-release6-api.worldsedgelink.com
  (the "-api.worldsedgelink.com" host-template string 0x143689260 area
  matches; ageLANServer wiki documents pb-live-release* per release).
  No connect()/send() lines => the rlink layer resolves DNS via
  getaddrinfo (hooked, logged) but the actual socket connect happens
  through WSASocketA/WSAConnect on a path where our connect hooks saw
  nothing yet OR connect is called via WSOCK32 ordinal thunk that resolved
  differently — TODO: verify which connect path fires (hook WSASocketA too,
  and log getaddrinfo RESULTS). CRYPT32 hooks: zero hits => rlink cert
  validation does NOT route through the game's CRYPT32 IAT (custom
  validator in encrypted code, or Schannel-by-DLL).
  Note: no SOCK connect/send/recv lines at all — the rlink TLS connection
  never got as far as connect, OR uses WSAConnect on a socket created by
  WSASocketA (we hook WSAConnect — also nothing). So either the connection
  happens through a socket API variant we don't cover (e.g. ConnectEx via
  WSAIoctl! — WSAIoctl IS imported and hooked? No — WSAIoctl is imported but
  NOT in our hook map; ConnectEx is obtained via WSAIoctl(SIO_GET_EXTENSION
  FUNCTION POINTER) and then called as a fn POINTER — invisible to IAT
  hooks!). ConnectEx is the likely transport for the rlink TLS client.

## 11e. Operator constraints + crash post-mortem
- Operator forbids using ageLANServer (told me once; reconfirmed today —
  "make your own mod"). The D:\AoE2LAN folder (ageLANServer v1.14 full
  install WITH cert+key+userData) was on disk during the session and the
  operator deleted it mid-session. DO NOT depend on it. Its one allowed
  use: public knowledge of the login-response JSON shape (protocol facts
  from its public source; same facts are observable from the real server).
  The ageLANServer CA remains in the Windows root stores (both) — unused
  by us; our plan mints its own cert and forces validation in-process.
- Three game crashes were MY misdeclared libHttpClient stubs (fixed; all
  signatures now doc-verified; post-call reads SEH-guarded). Game binary
  untouched throughout (sha 1e415af8...). Crash-free runs after fixes.

## 11f. M1 architecture decision (v3 — fully in-process, no external server)
The rlink plane = custom TLS client over raw sockets (ConnectEx likely).
Since the response JSON only exists post-TLS inside encrypted code, the
practical H1 seam is:
  1. getaddrinfo hook: when node == *-api.worldsedgelink.com (rlink family,
     pb-live-release6 current), return 127.0.0.1 (our in-DLL listener).
  2. In-DLL TLS server on 127.0.0.1:443 (SChannel server side, in-memory
     self-signed cert minted at boot; no files, no cert store installs).
  3. Cert validation: game's validator is custom/encrypted — defeat by
     hooking the CRYPTO/SSL layer the validator uses. CRYPT32 IAT shows
     zero hits, so the TLS stack is likely static OpenSSL (bcrypt imports
     hash/sign only = for SteamAuth, not TLS; TLS may be BoringSSL/OpenSSL
     static with its own X509 verify — NOT hookable via IAT).
     FALLBACK PLAN: hook the TLS at the SOCKET layer instead — no cert
     needed if the game's TLS client accepts a connection we terminate
     badly... (needs the ClientHello path first — see 11d ConnectEx TODO).
     SECOND FALLBACK: mint the cert with the SAME subject/issuer as a cert
     the game already trusts from its cacert.pem bundle (system root store
     certs are loaded into the game's trust list at boot: "WindowsCertificates:
     Adding certificate" lines) and sign... impossible without the CA key.
     THIRD: RL_SSLVERSION / RL_SSL_BACKEND env knobs — unexplored; may
     downgrade or disable TLS on the rlink client (test cheaply next).
  4. Login response: synthetic profile JSON (shape from the captured real
     request/response — still to be captured — or from public protocol
     knowledge of /game/login/login's fields: result, sessionId, profile,
     profileList, allProfileInfo, loginData, battleServers...).
  5. All other /game/* endpoints: empty-success. Telemetry already muted
     via RL_TELEMSHOULDNTSEND=1/RL_TELEMREPORTPCT=0 (H4 substantially done).

## 11g. Next steps (session 12, in order)
1. Socket-path closure: hook WSAIoctl (log SIO_GET_EXTENSION_FUNCTION_
   POINTER requests), WSASocketA, and wrap ConnectEx by replacing the fn
   pointer the game obtains (WSAIoctl output buffer — we can overwrite the
   returned ConnectEx pointer with our wrapper BEFORE the game reads it:
   clean data-side swap!). Same for any GetAcceptExSockaddrs etc.
   One supervised run then shows: connect target, ClientHello (SNI), the
   full login HTTP-over-TLS request + response byte stream.
2. Test RL_SSLVERSION/RL_SSL_BACKEND values (e.g. 0/off/none/ssl3) for a
   plaintext downgrade — if the rlink client accepts plain HTTP on 443,
   no TLS server needed at all; just redirect DNS and serve HTTP.
3. If TLS mandatory: in-DLL SChannel TLS server + ConnectEx-level redirect
   + find the validator seam (the login response carries sslCertificates
   the engine ADDS to its store — evidence the validator merges server-
   provided anchors; exploit: server hello chain that self-references).
4. Then the login-response synthesis (H1) + empty-success for noise (H4).
5. Update PLAN.md M1 entry state with corrected offsets + this seam map.

Files: dev/lanhook/iathook.{c,h} (new), lanhook.c (stage 7), hooktest.c
(fake-PE IAT test), build.cmd (builds all), PLAY-stage7-IAT.cmd (capture
launcher, stage 7 + telemetry env). Logs: lanhook-{3100,19352,5260,5672}.
