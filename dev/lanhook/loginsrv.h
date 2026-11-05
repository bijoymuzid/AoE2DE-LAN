// loginsrv.h — M1 H1 LoginShim: in-DLL HTTPS server for the fake rlink login.
//
// The rlink client connects to *-api.worldsedgelink.com:443 through raw
// WSOCK32 sockets with its own TLS. We never touch its code (Arxan rule):
//   - getaddrinfo hook redirects the rlink host family to 127.0.0.1
//   - this server terminates TLS 1.2 (SChannel, in-memory self-signed cert)
//   - the same cert is injected into the engine's trust pool through the
//     CertEnumCertificatesInStore hook (the engine adds every cert it
//     enumerates from the Windows Root store to its OpenSSL trust list)
//   - /game/login/login + /game/login/platformlogin get a synthetic 1-profile
//     response (profileID = FNV1a64("aoe2lan:" + nickname), stable across
//     restarts); everything else under /game/ gets an empty success.
#ifndef LOGINSRV_H
#define LOGINSRV_H

// Start the TLS server thread on 127.0.0.1:443. Returns 1 on success
// (listener bound). The cert is minted here; loginsrv_inject_cert() exposes
// it for the trust-pool injection.
int  loginsrv_start(void);

// The self-signed server cert (PCCERT_CONTEXT) — injected at the end of the
// Windows Root store enumeration so the engine trusts the exact cert we serve
// (self-referencing chain: the leaf IS the anchor).
void *loginsrv_inject_cert(void);

#endif
