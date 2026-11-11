// iathook.h — WinHTTP/WININET IAT interception for lanhook.dll (M1, session 11).
//
// The rlink login/audio state machine lives in Arxan-encrypted code: E9 head
// patches there are fatal (exit ~5.6 s, session 10 rule 10b). So H1/H4 go one
// layer down: the game reaches www.reliclink.com through WINHTTP.dll (13
// imports, incl. WinHttpSetStatusCallback) and WININET.dll (11 imports), and
// the rlink wire is plaintext JSON (nlohmann json_abi RTTI in the binary).
// Swapping the game's own IAT slots (data write in .rdata, no game-code
// patch) gives a fully transparent observer at the decrypted-data layer:
//
//   stage 7 (this iteration): LOG ONLY. Every request URL/method/body-chunk
//     and every response status/byte-chunk is logged, everything forwarded.
//     Goal: capture the live /game/login/login request+response schema.
//   stage 8 (next): SYNTHESIZE. Feed a synthetic login response (profiles[1]
//     + defaultProfileInfo + relayServers) at ReceiveResponse/ReadData so no
//     packet ever leaves; empty-success for telemetry/cloud/etc.
//
// The iathook_patch_module() entry is shared with hooktest.exe, which unit-
// tests the PE parser + swap logic on a synthetic in-memory PE image.
#ifndef IATHOOK_H
#define IATHOOK_H
#include <windows.h>

// Patch the game's WINHTTP/WININET/libHC/WS2_32/WSOCK32/CRYPT32/KERNEL32 IAT
// slots to our stubs (50 + 13 session-12 additions on this build). Data-only.
int iathook_patch_module(HMODULE mod);
void iathook_reset(void);

// stage 8 (set before iathook_patch_module runs):
extern int  g_IatRedirect;      // redirect the rlink host family to 127.0.0.1
extern void *g_LoginInjectCert; // PCCERT_CONTEXT appended to Root-store enums

// hooktest: inject a real fn pointer by import name (no IAT to patch there).
void iathook_set_real(const char *name, void *fn);

// the real ConnectEx captured from WSAIoctl's output buffer
extern void *g_RealConnectEx;

// parse+log a TLS ClientHello (SNI/version/suite count) from send bytes;
// returns 1 if a ClientHello was recognized.
int iathook_log_clienthello(const char *tag, const unsigned char *p, DWORD n);

// How many request/response log lines are left before the caps.
extern volatile LONG g_IatReqCap;
extern volatile LONG g_IatRespCap;

// stub entry points (also unit-tested by hooktest.exe)
void *WINAPI Hook_WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
void *WINAPI Hook_WinHttpConnect(void*, LPCWSTR, DWORD, DWORD);
void *WINAPI Hook_WinHttpOpenRequest(void*, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
BOOL WINAPI Hook_WinHttpAddRequestHeaders(void*, LPCWSTR, DWORD, DWORD);
BOOL WINAPI Hook_WinHttpSendRequest(void*, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
BOOL WINAPI Hook_WinHttpReceiveResponse(void*, LPVOID);
BOOL WINAPI Hook_WinHttpQueryHeaders(void*, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
BOOL WINAPI Hook_WinHttpQueryDataAvailable(void*, LPDWORD);
BOOL WINAPI Hook_WinHttpReadData(void*, LPVOID, DWORD, LPDWORD);
BOOL WINAPI Hook_WinHttpCrackUrl(LPCWSTR, DWORD, DWORD, LPVOID);
BOOL WINAPI Hook_WinHttpCloseHandle(void*);
void *WINAPI Hook_WinHttpSetStatusCallback(void*, void*, DWORD, DWORD_PTR);
BOOL WINAPI Hook_WinHttpSetOption(void*, DWORD, LPVOID, DWORD);
void *WINAPI Hook_InternetOpenW(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
void *WINAPI Hook_InternetConnectA(void*, LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
void *WINAPI Hook_HttpOpenRequestA(void*, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
BOOL WINAPI Hook_HttpAddRequestHeadersA(void*, LPCSTR, DWORD, DWORD);
BOOL WINAPI Hook_HttpSendRequestW(void*, LPCWSTR, DWORD, LPVOID, DWORD);
BOOL WINAPI Hook_HttpQueryInfoA(void*, DWORD, LPVOID, LPDWORD, LPDWORD);
BOOL WINAPI Hook_InternetReadFile(void*, LPVOID, DWORD, LPDWORD);
BOOL WINAPI Hook_InternetQueryOptionW(void*, DWORD, LPVOID, LPDWORD);
void *WINAPI Hook_InternetSetStatusCallbackW(void*, void*);
BOOL WINAPI Hook_InternetCrackUrlA(LPCSTR, DWORD, DWORD, LPVOID);
BOOL WINAPI Hook_InternetCloseHandle(void*);
int WINAPI Hook_HCCallSetUrl(void*, const char*, const char*);
int WINAPI Hook_HCCallSetBodyStr(void*, const char*);
int WINAPI Hook_HCCallSetBodyBytes(void*, const unsigned char*, DWORD);
int WINAPI Hook_HCCallPerform(void*, void*);
int WINAPI Hook_HCCallGetStatus(void*, DWORD*);
int WINAPI Hook_HCCallGetRespStr(void*, const char**, DWORD*);
int WINAPI Hook_HCCallGetNetErr(void*, DWORD*, DWORD*);
int WINAPI Hook_HCCallSetReadFn(void*, void*, SIZE_T, void*);
int WINAPI Hook_HCCallGetBodySize(void*, SIZE_T*);
int WINAPI Hook_HCCallGetBodyBytes(void*, SIZE_T, void*, SIZE_T*);
int WINAPI Hook_HCCallGetHeader(void*, const char*, const char**);
int WINAPI Hook_HCCallGetNumHeaders(void*, DWORD*);
int WINAPI Hook_HCCallGetHeaderAt(void*, DWORD, const char**, const char**);
int WINAPI Hook_HCCallSetHeader(void*, const char*, const char*, int);
int WINAPI Hook_HCWsConnect(void*, const char*, const char*, void*);
int WINAPI Hook_HCWsSend(void*, const char*, void*);

// ws2_32 / wsock32 transport + crypt32 cert path (shared with hooktest.exe)
typedef struct { unsigned long long len; char *buf; } WSABUF64;
int WINAPI Hook_getaddrinfo(const char*, const char*, const void*, void**);
int WINAPI Hook_WSAConnect(unsigned long long, const void*, int, void*, void*, void*, void*);
int WINAPI Hook_connect(unsigned long long, const void*, int);
int WINAPI Hook_send(unsigned long long, const char*, int, int);
int WINAPI Hook_WSASend(unsigned long long, WSABUF64*, unsigned long, unsigned long*, unsigned long, void*, void*);
int WINAPI Hook_recv(unsigned long long, char*, int, int);
int WINAPI Hook_WSARecv(unsigned long long, WSABUF64*, unsigned long, unsigned long*, unsigned long*, void*, void*);
int WINAPI Hook_recvfrom(unsigned long long, char*, int, int, void*, int*);
int WINAPI Hook_WSARecvFrom(unsigned long long, WSABUF64*, unsigned long, unsigned long*, unsigned long*, void*, int*, void*, void*);
BOOL WINAPI Hook_WSAGetOverlappedResult(unsigned long long, void*, unsigned long*, BOOL, unsigned long*);
int WINAPI Hook_closesocket(unsigned long long);
BOOL WINAPI Hook_CertGetCertificateChain(void*, void*, void*, void*, void*, unsigned long, void*, void**);
BOOL WINAPI Hook_CertVerifyChainPolicy(const char*, void*, void*, void*);
void *WINAPI Hook_CertCreateChainEngine(void*);
void *WINAPI Hook_CertFindCertificateInStore(void*, unsigned long, unsigned long, unsigned long, const void*, void*);
int WINAPI Hook_WSAIoctl(unsigned long long, DWORD, void*, DWORD, void*, DWORD, DWORD*, void*, void*);
unsigned long long WINAPI Hook_WSASocketA(int, int, int, void*, unsigned int, DWORD);
unsigned long long WINAPI Hook_socket(int, int, int);
BOOL WINAPI Hook_ConnectEx(unsigned long long, const void*, int, void*, DWORD, DWORD*, void*);
BOOL WINAPI Hook_GQCS(void*, DWORD*, unsigned long long*, void**, DWORD);
void *WINAPI Hook_CertOpenStore(const char*, DWORD, unsigned long long, DWORD, const void*);
void *WINAPI Hook_CertEnumCertificatesInStore(void*, void*);
BOOL WINAPI Hook_CertAddCtxToStore(void*, void*, DWORD, void**);
BOOL WINAPI Hook_CryptStringToBinaryA(const char*, DWORD, DWORD, unsigned char*, DWORD*, DWORD*, DWORD*);
BOOL WINAPI Hook_CertCloseStore(void*, DWORD);
BOOL WINAPI Hook_CertFreeCtx(void*);
BOOL WINAPI Hook_CryptQueryObject(DWORD, const void*, DWORD, DWORD, DWORD, DWORD*, DWORD*, DWORD*, void**, const void**);
DWORD WINAPI Hook_CertGetNameStringW(void*, DWORD, DWORD, void*, wchar_t*, DWORD);
DWORD WINAPI Hook_CertGetNameStringA(void*, DWORD, DWORD, void*, char*, DWORD);

#endif
