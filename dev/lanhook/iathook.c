// iathook.c — IAT interception for lanhook.dll (M1, session 11).
//
// Why the IAT: the login state machine is Arxan-encrypted (E9 = fatal), but
// the game's import tables are .rdata DATA — patched before any game code
// runs. Session-11 run 1 proved the game's own WINHTTP/WININET imports see
// NOTHING at login time: the rlink/XAL plane flows through
// libHttpClient.Win32.dll (the game imports the full HCHttpCall* surface:
// 72 fns), and libHttpClient then calls WinHttp* through ITS OWN IAT. So we
// hook the game's libHttpClient imports instead — and there the traffic is
// PLAIN STRINGS: HCHttpCallRequestSetUrl(call, method, url),
// HCHttpCallRequestSetRequestBodyString(call, body),
// HCHttpCallResponseGetResponseString(call, str, len)...
//
//   stage 7 (capture): log every HC request (url/method/body) and response
//     (status/headers/body) + WinHTTP/WININET as backup cover. Forward
//     everything. Goal: the live /game/login/login request+response schema.
//   stage 8 (synthesis): answer login with profiles[1]+defaultProfileInfo,
//     empty-success everything else. Same seam, zero game-code patches.
//
// No CRT: kernel32 only, own string builders, spinlocks.

#include <windows.h>
#include <stdint.h>
#include "hookcore.h"
#include "iathook.h"

typedef void *HIN;
int strcmp_f(const char *a, const char *b);   // defined below; used by realfn()

// ---------------------------------------------------------------- patch table
// flat name->stub map; names are unique across the three DLLs.
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

static struct { const char *fn; void *stub; void *real; } g_Map[] = {
    // WINHTTP.dll
    {"WinHttpOpen",                 (void*)&Hook_WinHttpOpen,                0},
    {"WinHttpConnect",              (void*)&Hook_WinHttpConnect,             0},
    {"WinHttpOpenRequest",          (void*)&Hook_WinHttpOpenRequest,         0},
    {"WinHttpAddRequestHeaders",    (void*)&Hook_WinHttpAddRequestHeaders,   0},
    {"WinHttpSendRequest",          (void*)&Hook_WinHttpSendRequest,         0},
    {"WinHttpReceiveResponse",      (void*)&Hook_WinHttpReceiveResponse,     0},
    {"WinHttpQueryHeaders",         (void*)&Hook_WinHttpQueryHeaders,        0},
    {"WinHttpQueryDataAvailable",   (void*)&Hook_WinHttpQueryDataAvailable,  0},
    {"WinHttpReadData",             (void*)&Hook_WinHttpReadData,            0},
    {"WinHttpCrackUrl",             (void*)&Hook_WinHttpCrackUrl,            0},
    {"WinHttpCloseHandle",          (void*)&Hook_WinHttpCloseHandle,         0},
    {"WinHttpSetStatusCallback",    (void*)&Hook_WinHttpSetStatusCallback,   0},
    {"WinHttpSetOption",            (void*)&Hook_WinHttpSetOption,           0},
    // WININET.dll
    {"InternetOpenW",               (void*)&Hook_InternetOpenW,              0},
    {"InternetConnectA",            (void*)&Hook_InternetConnectA,           0},
    {"HttpOpenRequestA",            (void*)&Hook_HttpOpenRequestA,           0},
    {"HttpAddRequestHeadersA",      (void*)&Hook_HttpAddRequestHeadersA,     0},
    {"HttpSendRequestW",            (void*)&Hook_HttpSendRequestW,           0},
    {"HttpQueryInfoA",              (void*)&Hook_HttpQueryInfoA,             0},
    {"InternetReadFile",            (void*)&Hook_InternetReadFile,           0},
    {"InternetQueryOptionW",        (void*)&Hook_InternetQueryOptionW,       0},
    {"InternetSetStatusCallbackW",  (void*)&Hook_InternetSetStatusCallbackW, 0},
    {"InternetCrackUrlA",           (void*)&Hook_InternetCrackUrlA,          0},
    {"InternetCloseHandle",         (void*)&Hook_InternetCloseHandle,        0},
    // libHttpClient.Win32.dll — the rlink/XAL HTTP plane, string level
    {"HCHttpCallRequestSetUrl",             (void*)&Hook_HCCallSetUrl,        0},
    {"HCHttpCallRequestSetRequestBodyString",(void*)&Hook_HCCallSetBodyStr,   0},
    {"HCHttpCallRequestSetRequestBodyBytes",(void*)&Hook_HCCallSetBodyBytes,  0},
    {"HCHttpCallPerformAsync",              (void*)&Hook_HCCallPerform,       0},
    {"HCHttpCallResponseGetStatusCode",     (void*)&Hook_HCCallGetStatus,     0},
    {"HCHttpCallResponseGetResponseString", (void*)&Hook_HCCallGetRespStr,    0},
    {"HCHttpCallResponseGetNetworkErrorCode",(void*)&Hook_HCCallGetNetErr,    0},
    {"HCHttpCallRequestSetRequestBodyReadFunction",(void*)&Hook_HCCallSetReadFn, 0},
    {"HCHttpCallResponseGetResponseBodyBytesSize",(void*)&Hook_HCCallGetBodySize, 0},
    {"HCHttpCallResponseGetResponseBodyBytes",(void*)&Hook_HCCallGetBodyBytes, 0},
    {"HCHttpCallResponseGetHeader",        (void*)&Hook_HCCallGetHeader,     0},
    {"HCHttpCallResponseGetNumHeaders",    (void*)&Hook_HCCallGetNumHeaders, 0},
    {"HCHttpCallResponseGetHeaderAtIndex", (void*)&Hook_HCCallGetHeaderAt,   0},
    {"HCHttpCallRequestSetHeader",         (void*)&Hook_HCCallSetHeader,     0},
    {"HCWebSocketConnectAsync",             (void*)&Hook_HCWsConnect,         0},
    {"HCWebSocketSendMessageAsync",         (void*)&Hook_HCWsSend,            0},
    // WS2_32.dll / WSOCK32.dll — the rlink raw-socket plane (own TLS above it)
    {"getaddrinfo",                 (void*)&Hook_getaddrinfo,          0},
    {"WSAConnect",                  (void*)&Hook_WSAConnect,           0},
    {"connect",                     (void*)&Hook_connect,              0},
    {"send",                        (void*)&Hook_send,                 0},
    {"WSASend",                     (void*)&Hook_WSASend,              0},
    {"recv",                        (void*)&Hook_recv,                 0},
    {"WSARecv",                     (void*)&Hook_WSARecv,              0},
    {"recvfrom",                    (void*)&Hook_recvfrom,             0},
    {"WSARecvFrom",                 (void*)&Hook_WSARecvFrom,          0},
    {"WSAGetOverlappedResult",      (void*)&Hook_WSAGetOverlappedResult,0},
    {"closesocket",                 (void*)&Hook_closesocket,          0},
    // CRYPT32.dll — certificate store load/validation path (session 12: all 15
    // imports tapped, incl. the STORE-LOADING fns — "zero hits" in session 11
    // was because only the 4 chain-verify fns were hooked)
    {"CertGetCertificateChain",     (void*)&Hook_CertGetCertificateChain, 0},
    {"CertVerifyCertificateChainPolicy",(void*)&Hook_CertVerifyChainPolicy, 0},
    {"CertCreateCertificateChainEngine",(void*)&Hook_CertCreateChainEngine, 0},
    {"CertFindCertificateInStore",  (void*)&Hook_CertFindCertificateInStore, 0},
    {"CertOpenStore",               (void*)&Hook_CertOpenStore,           0},
    {"CertEnumCertificatesInStore", (void*)&Hook_CertEnumCertificatesInStore, 0},
    {"CertAddCertificateContextToStore",(void*)&Hook_CertAddCtxToStore,   0},
    {"CryptStringToBinaryA",        (void*)&Hook_CryptStringToBinaryA,    0},
    {"CertCloseStore",              (void*)&Hook_CertCloseStore,          0},
    {"CertFreeCertificateContext",  (void*)&Hook_CertFreeCtx,             0},
    {"CryptQueryObject",            (void*)&Hook_CryptQueryObject,        0},
    {"CertGetNameStringW",          (void*)&Hook_CertGetNameStringW,      0},
    {"CertGetNameStringA",          (void*)&Hook_CertGetNameStringA,      0},
    // WS2_32 runtime-resolved transport (session 12): WSAIoctl hands the game
    // ConnectEx as a fn POINTER — we swap that pointer in the game's own
    // output buffer, then wrap every ConnectEx call.
    {"WSAIoctl",                    (void*)&Hook_WSAIoctl,               0},
    {"WSASocketA",                  (void*)&Hook_WSASocketA,             0},
    // WSOCK32 legacy
    {"socket",                      (void*)&Hook_socket,                 0},
    // KERNEL32 — IOCP completion port (overlapped recv delivery path)
    {"GetQueuedCompletionStatus",   (void*)&Hook_GQCS,                   0},
};
#define NMAP (int)(sizeof(g_Map)/sizeof(g_Map[0]))
// certified g_Map indices (layout sensitive — edits above must update these):
#define IDX_ADDCTX   55  // CertAddCertificateContextToStore
#define IDX_CLOSE    57  // CertCloseStore
#define IDX_FREECTX  58  // CertFreeCertificateContext
#define IDX_ENUM     54  // CertEnumCertificatesInStore

// ---------------------------------------------------------------- handle map
// HINTERNET keys: session->connect->request tree. We need host/verb/path per
// REQUEST handle. Linear scan, 512 slots.
typedef struct {
    HIN   h;
    char  host[80];
    char  verb[12];
    char  path[168];
    DWORD bodyBytes;
    DWORD respBytes;
    DWORD respTotal;
} REQ;
static REQ g_Req[512];
static volatile LONG g_ReqLock = 0;
static volatile LONG g_ReqN = 0;

volatile LONG g_IatReqCap = 900;   // request-side log lines
volatile LONG g_IatRespCap = 1400; // response-side log lines

// session 12 (stage 8): rlink DNS redirect + trust-pool injection
int  g_IatRedirect;        // set by lanhook before patching (stage 8)
void *g_LoginInjectCert;   // PCCERT_CONTEXT to append to the Root enum

static void req_lock(void) { while (InterlockedCompareExchange(&g_ReqLock, 1, 0) != 0) Sleep(0); }
static void req_unlock(void) { InterlockedExchange(&g_ReqLock, 0); }

static REQ *req_find(HIN h) {
    for (int i = 0; i < g_ReqN; i++) if (g_Req[i].h == h) return &g_Req[i];
    return 0;
}
static REQ *req_add(HIN h, const char *host, const char *verb, const char *path) {
    REQ *r = 0;
    req_lock();
    if (g_ReqN < 512) { r = &g_Req[g_ReqN++]; }
    req_unlock();
    if (!r) return 0;
    r->h = h;
    { int i = 0; while (i < 79 && host && host[i]) { r->host[i] = host[i]; i++; } r->host[i] = 0; }
    { int i = 0; while (i < 11 && verb && verb[i]) { r->verb[i] = verb[i]; i++; } r->verb[i] = 0; }
    { int i = 0; while (i < 167 && path && path[i]) { r->path[i] = path[i]; i++; } r->path[i] = 0; }
    r->bodyBytes = 0; r->respBytes = 0; r->respTotal = 0;
    return r;
}
static void req_del(HIN h) {
    req_lock();
    for (int i = 0; i < g_ReqN; i++) {
        if (g_Req[i].h == h) {
            for (int j = i; j < g_ReqN-1; j++) g_Req[j] = g_Req[j+1];
            g_ReqN--;
            break;
        }
    }
    req_unlock();
}

// ---------------------------------------------------------------- text utils
static int wlen(const wchar_t *w) { int n = 0; if (!w) return 0; while (w[n]) n++; return n; }

static int wascii(const wchar_t *w, char *out, int cap) {
    int i = 0;
    if (!w) { out[0] = 0; return 0; }
    while (w[i] && i < cap-1) { wchar_t c = w[i]; out[i] = (char)(c < 128 ? c : '?'); i++; }
    out[i] = 0;
    return i;
}

static void log_str2(const char *tag, const char *s) {
    char b[384]; int i = 0;
    while (*tag && i < 380) b[i++] = *tag++;
    b[i++] = ':'; b[i++] = ' ';
    int j = 0;
    while (s && s[j] && i < 380) { b[i++] = s[j++]; }
    b[i] = 0;
    log_line(b);
}

static void log_bytes(const char *tag, const void *p, DWORD n, DWORD shown) {
    char b[640]; int i = 0;
    while (*tag && i < 600) b[i++] = *tag++;
    b[i++] = ' ';
    { char t[12]; int tl = 0; DWORD v = n;
      do { t[tl++] = (char)('0' + (v%10)); v /= 10; } while (v);
      while (tl) b[i++] = t[--tl]; }
    b[i++] = 'B';
    b[i++] = ' ';
    const unsigned char *q = (const unsigned char*)p;
    DWORD kmax = shown; if (kmax > 128) kmax = 128; if (kmax > n) kmax = n;
    if (q) {
        for (DWORD k = 0; k < kmax && i < 590; k++) {
            int hi = q[k] >> 4, lo = q[k] & 15;
            b[i++] = (char)(hi < 10 ? '0'+hi : 'a'+hi-10);
            b[i++] = (char)(lo < 10 ? '0'+lo : 'a'+lo-10);
            if ((k & 15) == 15 && k+1 < kmax) b[i++] = ' ';
        }
        b[i++] = ' '; b[i++] = '|';
        for (DWORD k = 0; k < kmax && i < 600; k++) {
            unsigned char c = q[k];
            b[i++] = (char)((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        b[i++] = '|';
    }
    b[i] = 0;
    log_line(b);
}

static int take_req(void) { return InterlockedDecrement(&g_IatReqCap) > 0; }
static int take_resp(void) { return InterlockedDecrement(&g_IatRespCap) > 0; }

// SEH-guarded string length (never crashes on a bad ptr)
static int safe_len(const char *s, int cap) {
    int i = 0;
    if (!s) return 0;
    HC_TRY
        while (i < cap && s[i]) i++;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return i;
}

// small printers so a log line can carry the HCCall pointer + both error codes
static int bsput_i(char *b, int i, const char *s) { while (*s) b[i++] = *s++; b[i] = 0; return i; }
static int hput(char *b, int i, DWORD64 v) {
    static const char hx[] = "0123456789abcdef"; char t[20]; int n = 0;
    b[i++] = '0'; b[i++] = 'x';
    if (!v) t[n++] = '0';
    while (v) { t[n++] = hx[v & 15]; v >>= 4; }
    while (n) b[i++] = t[--n];
    b[i] = 0;
    return i;
}
static int dput(char *b, int i, DWORD v) {
    char t[12]; int n = 0;
    if (!v) t[n++] = '0';
    while (v) { t[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n) b[i++] = t[--n];
    b[i] = 0;
    return i;
}

// ---------------------------------------------------------------- libHttpClient
// HRESULT (int) return for all HC calls. Plain char* strings.

// NOTE (wine): XAL's 1DS telemetry POST to self.events.data.microsoft.com fails
// here every ~19 s with HC E_FAIL / provider pe=0x80072f78
// (ERROR_HTTP_INVALID_SERVER_RESPONSE). It is NOT fatal - three 100 s runs each
// took 5 of those failures and held the menu throughout. An earlier run did log
// out + exit 0.7 s after its 2nd failure, but that has not reproduced in 3/3
// runs since (including with AOE2LAN_DUMPTEXT=1, the other suspect). Rewriting
// the URL to our own TLS server was tried and removed: libHttpClient.Win32.dll
// resolves and connects through its OWN IAT, so the rewrite never moved the
// socket - the server saw zero /OneCollector requests with it enabled.
// Evidence: notes/linux-session4.md §4c, /tmp/exp-{telem1,telem0,dumptext2}.shim.log.

typedef int (WINAPI *PfnHCSetUrl)(void*, const char*, const char*);
typedef int (WINAPI *PfnHCSetBodyStr)(void*, const char*);
typedef int (WINAPI *PfnHCSetBodyBytes)(void*, const unsigned char*, DWORD);
typedef int (WINAPI *PfnHCPerform)(void*, void*);
typedef int (WINAPI *PfnHCGetStatus)(void*, DWORD*);
typedef int (WINAPI *PfnHCGetRespStr)(void*, const char**, DWORD*);
typedef int (WINAPI *PfnHCGetNetErr)(void*, DWORD*, DWORD*);
typedef int (WINAPI *PfnHCWsConnect)(void*, const char*, const char*, void*);
typedef int (WINAPI *PfnHCWsSend)(void*, const char*, void*);

int WINAPI Hook_HCCallSetUrl(void *call, const char *method, const char *url) {
    PfnHCSetUrl real = (PfnHCSetUrl)g_Map[24].real;
    if (take_req() && url) {
        char b[384]; int i=0; const char *m="HC SET ";
        while (*m) b[i++]=*m++;
        for (int j=0; method && method[j] && i<330; j++) b[i++]=method[j];
        b[i++]=' ';
        for (int j=0; url && url[j] && i<330; j++) b[i++]=url[j];
        i = bsput_i(b, i, " call="); i = hput(b, i, (DWORD64)call);
        b[i]=0; log_line(b);
    }
    return real(call, method, url);
}

int WINAPI Hook_HCCallSetBodyStr(void *call, const char *body) {
    PfnHCSetBodyStr real = (PfnHCSetBodyStr)g_Map[25].real;
    if (take_req() && body) {
        char b[384]; int i=0; const char *m="HC REQBODY ";
        while (*m) b[i++]=*m++;
        for (int j=0; body[j] && i<360; j++) b[i++]=body[j];
        b[i]=0; log_line(b);
    }
    return real(call, body);
}

int WINAPI Hook_HCCallSetBodyBytes(void *call, const unsigned char *bytes, DWORD n) {
    PfnHCSetBodyBytes real = (PfnHCSetBodyBytes)g_Map[26].real;
    if (n && take_req()) log_bytes("HC REQBODYbytes", bytes, n, n);
    return real(call, bytes, n);
}

int WINAPI Hook_HCCallPerform(void *call, void *async) {
    PfnHCPerform real = (PfnHCPerform)g_Map[27].real;
    if (take_req()) {
        char b[64]; int i=0; const char *m="HC PERFORM call=";
        while (*m) b[i++]=*m++;
        i = hput(b, i, (DWORD64)call); b[i]=0; log_line(b);
    }
    return real(call, async);
}

int WINAPI Hook_HCCallGetStatus(void *call, DWORD *code) {
    PfnHCGetStatus real = (PfnHCGetStatus)g_Map[28].real;
    int hr = real(call, code);
    if (take_resp() && code) {
        char b[80]; int i=0; const char *m="HC STATUS ";
        while (*m) b[i++]=*m++;
        { char t[12]; int tl=0; DWORD v=*code;
          do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
          while (tl) b[i++]=t[--tl]; }
        b[i]=0; log_line(b);
    }
    return hr;
}

int WINAPI Hook_HCCallGetRespStr(void *call, const char **str, DWORD *len) {
    PfnHCGetRespStr real = (PfnHCGetRespStr)g_Map[29].real;
    int hr = real(call, str, len);
    if (hr == 0 && str && *str && take_resp()) {
        // full JSON first line(s): log in 300-char slices, SEH-guarded
        DWORD total = 0;
        HC_TRY
            if (len) total = *len;
            if (!total) { const char *q = *str; while (q[total] && total < 100000) total++; }
        } __except (EXCEPTION_EXECUTE_HANDLER) { total = 0; }
        if (total > 60000) total = 60000;
        DWORD off = 0;
        while (off < total && off < 2400) {
            DWORD chunk = total - off; if (chunk > 300) chunk = 300;
            char b[384]; int i=0; const char *m = (off==0) ? "HC RESP " : "HC resp+";
            while (*m) b[i++]=*m++;
            HC_TRY
                for (DWORD j=0; j<chunk; j++) {
                    char c = (*str)[off+j];
                    b[i++] = (char)((c=='\n'||c=='\r') ? ' ' : c);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            b[i]=0; log_line(b);
            off += chunk;
        }
        if (total > 2400) {
            char b[80]; int i=0; const char *m="HC RESP total=";
            while (*m) b[i++]=*m++;
            { char t[12]; int tl=0; DWORD v=total;
              do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
              while (tl) b[i++]=t[--tl]; }
            b[i]=0; log_line(b);
        }
    }
    return hr;
}

int WINAPI Hook_HCCallGetNetErr(void *call, DWORD *e, DWORD *pe) {
    PfnHCGetNetErr real = (PfnHCGetNetErr)g_Map[30].real;
    int hr = real(call, e, pe);
    if (take_resp() && e && *e) {
        // pe is the provider's own code (CURLE_* / WinHTTP), the only thing that
        // says WHY a call failed - E_FAIL alone is the same for every failure.
        char b[160]; int i=0; const char *m="HC NETERR ";
        while (*m) b[i++]=*m++;
        i = dput(b, i, *e); i = hput(b, i, *e);
        i = bsput_i(b, i, " pe="); i = dput(b, i, pe ? *pe : 0);
        i = hput(b, i, pe ? *pe : 0);
        i = bsput_i(b, i, " call="); i = hput(b, i, (DWORD64)call);
        b[i]=0; log_line(b);
    }
    return hr;
}

// response bodies that arrive via GetResponseBodyBytes(Size)
typedef int (WINAPI *PfnHCGetBodySize)(void*, SIZE_T*);
typedef int (WINAPI *PfnHCGetBodyBytes)(void*, SIZE_T, void*, SIZE_T*);
typedef int (WINAPI *PfnHCGetHeader)(void*, const char*, const char**);
typedef int (WINAPI *PfnHCGetNumHeaders)(void*, DWORD*);
typedef int (WINAPI *PfnHCGetHeaderAt)(void*, DWORD, const char**, const char**);
typedef int (WINAPI *PfnHCSetHeader)(void*, const char*, const char*, int);
typedef int (WINAPI *PfnHCSetReadFn)(void*, void*, SIZE_T, void*);

int WINAPI Hook_HCCallGetBodySize(void *call, SIZE_T *n) {
    PfnHCGetBodySize real = (PfnHCGetBodySize)g_Map[32].real;
    int hr = real(call, n);
    if (take_resp() && n && *n) {
        char b[80]; int i=0; const char *m="HC BODYBYTES size=";
        while (*m) b[i++]=*m++;
        { char t[12]; int tl=0; DWORD v=(DWORD)*n;
          do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
          while (tl) b[i++]=t[--tl]; }
        b[i]=0; log_line(b);
    }
    return hr;
}

int WINAPI Hook_HCCallGetBodyBytes(void *call, SIZE_T avail, void *buf, SIZE_T *nRead) {
    PfnHCGetBodyBytes real = (PfnHCGetBodyBytes)g_Map[33].real;
    int hr = real(call, avail, buf, nRead);
    if (hr == 0 && nRead && *nRead && take_resp()) {
        DWORD total = (DWORD)*nRead;
        DWORD off = 0;
        while (off < total && off < 12000) {
            DWORD chunk = total - off; if (chunk > 300) chunk = 300;
            char b[384]; int i=0; const char *m = (off==0) ? "HC BODY " : "HC body+";
            while (*m) b[i++]=*m++;
            for (DWORD j=0; j<chunk; j++) {
                char c = ((const char*)buf)[off+j];
                b[i++] = (char)((c=='\n'||c=='\r') ? ' ' : c);
            }
            b[i]=0; log_line(b);
            off += chunk;
        }
        if (off < total) {
            char b[80]; int i=0; const char *m="HC BODY total=";
            while (*m) b[i++]=*m++;
            { char t[12]; int tl=0; DWORD v=total;
              do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
              while (tl) b[i++]=t[--tl]; }
            b[i]=0; log_line(b);
        }
    }
    return hr;
}

int WINAPI Hook_HCCallGetHeader(void *call, const char *name, const char **val) {
    PfnHCGetHeader real = (PfnHCGetHeader)g_Map[34].real;
    int hr = real(call, name, val);
    if (hr == 0 && take_resp() && name) {
        char b[300]; int i=0; const char *m="HC RSPHDR ";
        while (*m) b[i++]=*m++;
        { int n = safe_len(name, 200); for (int j=0; j<n && i<280; j++) b[i++]=name[j]; }
        b[i++]='=';
        HC_TRY
            if (val && *val) { int n = safe_len(*val, 200); for (int j=0; j<n && i<280; j++) b[i++]=(*val)[j]; }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        b[i]=0; log_line(b);
    }
    return hr;
}

int WINAPI Hook_HCCallGetNumHeaders(void *call, DWORD *n) {
    PfnHCGetNumHeaders real = (PfnHCGetNumHeaders)g_Map[35].real;
    return real(call, n);
}

int WINAPI Hook_HCCallGetHeaderAt(void *call, DWORD idx, const char **name, const char **val) {
    PfnHCGetHeaderAt real = (PfnHCGetHeaderAt)g_Map[36].real;
    int hr = real(call, idx, name, val);
    if (hr == 0 && take_resp()) {
        char b[300]; int i=0;
        HC_TRY
            if (name && *name) { int n = safe_len(*name, 200); for (int j=0; j<n && i<280; j++) b[i++]=(*name)[j]; }
            b[i++]='=';
            if (val && *val) { int n = safe_len(*val, 200); for (int j=0; j<n && i<280; j++) b[i++]=(*val)[j]; }
            b[i]=0;
            log_str2((idx==0)?"HC HDRS":"HC hdrs+", b);
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    return hr;
}

int WINAPI Hook_HCCallSetHeader(void *call, const char *name, const char *val, int allowTracing) {
    PfnHCSetHeader real = (PfnHCSetHeader)g_Map[37].real;
    if (take_req() && name) {
        char b[380]; int i=0; const char *m="HC REQHDR ";
        while (*m) b[i++]=*m++;
        for (int j=0; name[j] && i<340; j++) b[i++]=name[j];
        b[i++]='=';
        if (val) for (int j=0; val[j] && i<340; j++) b[i++]=val[j];
        b[i]=0; log_line(b);
    }
    return real(call, name, val, allowTracing);
}

int WINAPI Hook_HCCallSetReadFn(void *call, void *fn, SIZE_T bodySize, void *ctx) {
    PfnHCSetReadFn real = (PfnHCSetReadFn)g_Map[31].real;
    if (take_req()) log_line("HC REQBODY-via-readfunction (streamed upload)");
    return real(call, fn, bodySize, ctx);
}

int WINAPI Hook_HCWsConnect(void *ws, const char *uri, const char *sub, void *ctx) {
    PfnHCWsConnect real = (PfnHCWsConnect)g_Map[38].real;
    if (take_req() && uri) {
        char b[384]; int i=0; const char *m="HC WS-CONNECT ";
        while (*m) b[i++]=*m++;
        for (int j=0; uri[j] && i<360; j++) b[i++]=uri[j];
        b[i]=0; log_line(b);
    }
    return real(ws, uri, sub, ctx);
}

int WINAPI Hook_HCWsSend(void *ws, const char *msg, void *ctx) {
    PfnHCWsSend real = (PfnHCWsSend)g_Map[39].real;
    if (take_req() && msg) {
        char b[384]; int i=0; const char *m="HC WS-SEND ";
        while (*m) b[i++]=*m++;
        for (int j=0; msg[j] && i<360; j++) b[i++]=msg[j];
        b[i]=0; log_line(b);
    }
    return real(ws, msg, ctx);
}

// ---------------------------------------------------------------- sockets
// The rlink plane runs its own TLS over raw sockets (WSOCK32 connect/send/recv
// + WS2_32 overlapped). Capture: DNS names, connect targets, handshake bytes
// (TLS ClientHello SNI is plaintext), response record heads, and whether cert
// validation routes through the CRYPT32 imports.

static void *realfn(const char *name) {
    for (int k = 0; k < NMAP; k++)
        if (!strcmp_f(name, g_Map[k].fn)) return g_Map[k].real;
    return 0;
}

typedef unsigned long long SOCKT;
typedef struct {
    SOCKT s;
    char  peer[28];        // "1.2.3.4:443"
    void *lastRecvBuf;     // WSARecv buffer for post-overlapped dump
    DWORD lastRecvCap;
} SKENT;
static SKENT g_Sock[512];
static volatile LONG g_SockLock = 0;
static volatile LONG g_SockN = 0;

static void sock_lock(void) { while (InterlockedCompareExchange(&g_SockLock, 1, 0) != 0) Sleep(0); }
static void sock_unlock(void) { InterlockedExchange(&g_SockLock, 0); }

static SKENT *sock_find(SOCKT s) {
    for (int i = 0; i < g_SockN; i++) if (g_Sock[i].s == s) return &g_Sock[i];
    return 0;
}
static SKENT *sock_add(SOCKT s, const char *peer) {
    SKENT *e = 0;
    sock_lock();
    if (g_SockN < 512) e = &g_Sock[g_SockN++];
    sock_unlock();
    if (!e) return 0;
    e->s = s; e->lastRecvBuf = 0; e->lastRecvCap = 0;
    { int i = 0; while (i < 27 && peer && peer[i]) { e->peer[i] = peer[i]; i++; } e->peer[i] = 0; }
    return e;
}
static void sock_del(SOCKT s) {
    sock_lock();
    for (int i = 0; i < g_SockN; i++) {
        if (g_Sock[i].s == s) {
            for (int j = i; j < g_SockN-1; j++) g_Sock[j] = g_Sock[j+1];
            g_SockN--;
            break;
        }
    }
    sock_unlock();
}

// session-12 forward decls (definitions in the WSAIoctl/ConnectEx section below)
typedef struct { void *ov; SOCKT s; void *buf; DWORD cap; } OVENT;
static OVENT *ov_find(void *ov);
static void ov_add(void *ov, SOCKT s, void *buf, DWORD cap);
static void ov_del(void *ov);
static void tls_note_recv(const unsigned char *p, DWORD n);

static void fmt_peer(const void *name, int fam_req, char *out, int cap) {
    const unsigned char *p = (const unsigned char*)name;
    out[0] = 0;
    if (!p) return;
    HC_TRY
        int fam = *(const short*)p;
        if (fam == 2) { // AF_INET: port BE at +2, addr at +4
            unsigned a = p[4], b = p[5], c = p[6], d = p[7];
            unsigned port = ((unsigned)p[2] << 8) | p[3];
            { char *w = out; int used = 0;
              unsigned parts[4] = {a,b,c,d};
              for (int q = 0; q < 4; q++) {
                if (used) { *w++='.'; used++; }
                char t[4]; int tl = 0; unsigned v = parts[q];
                if (!v) t[tl++]='0';
                while (v && tl < 4) { t[tl++]=(char)('0'+(v%10)); v/=10; }
                while (tl) { *w++ = t[--tl]; used++; }
                if (used > cap-8) break;
              }
              *w++ = ':';
              { char t[6]; int tl = 0; unsigned v = port;
                if (!v) t[tl++]='0';
                while (v && tl < 5) { t[tl++]=(char)('0'+(v%10)); v/=10; }
                while (tl) *w++ = t[--tl]; }
              *w = 0;
            }
        } else if (fam == 23) { // AF_INET6
            unsigned port = ((unsigned)p[2] << 8) | p[3];
            char *w = out; char t[6]; int tl = 0; unsigned v = port;
            *w++='['; *w++='v'; *w++='6'; *w++=']'; *w++=':';
            if (!v) t[tl++]='0';
            while (v && tl < 5) { t[tl++]=(char)('0'+(v%10)); v/=10; }
            while (tl) *w++ = t[--tl];
            *w = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { out[0] = 0; }
}

// suffix match, no CRT
static int ends_with(const char *s, const char *suf) {
    int ls = 0, lf = 0;
    while (s[ls]) ls++;
    while (suf[lf]) lf++;
    if (lf > ls) return 0;
    for (int i = 0; i < lf; i++) if (s[ls-lf+i] != suf[i]) return 0;
    return 1;
}

int WINAPI Hook_getaddrinfo(const char *node, const char *service, const void *hints, void **result) {
    typedef int (WINAPI *Pfn)(const char*, const char*, const void*, void**);
    Pfn real = (Pfn)realfn("getaddrinfo");
    const char *nodeUsed = node;
    int redirected = 0;
    if (g_IatRedirect && node &&
        (ends_with(node, "worldsedgelink.com") ||
         !strcmp_f(node, "aoe-api.reliclink.com"))) {
        nodeUsed = "127.0.0.1";
        redirected = 1;
    }
    if (take_req() && node) {
        char b[220]; int i=0; const char *m= redirected ? "DNS REDIRECT " : "DNS resolve ";
        while (*m) b[i++]=*m++;
        for (int j=0; node[j] && i<170; j++) b[i++]=node[j];
        if (redirected) { const char *t=" -> 127.0.0.1"; while (*t) b[i++]=*t++; }
        if (service && service[0] && i<180) { const char *t=" svc="; while (*t) b[i++]=*t++;
            for (int j=0; service[j] && i<190; j++) b[i++]=service[j]; }
        b[i]=0; log_line(b);
    }
    { int r = real(nodeUsed, service, hints, result);
      if (r == 0 && result && *result && take_req() && !redirected) {
          // log the resolved addresses (first 4 entries)
          void *ai = *result; int cnt = 0;
          HC_TRY
              while (ai && cnt < 4) {
                  const char *ad = *(const char**)((char*)ai + 32);   // ai_addr
                  char peer[28]; fmt_peer(ad, 0, peer, 28);
                  if (peer[0]) {
                      char b[96]; int i=0; const char *m="DNS   -> ";
                      while (*m) b[i++]=*m++;
                      for (int j=0; peer[j] && i<80; j++) b[i++]=peer[j];
                      b[i]=0; log_line(b);
                  }
                  ai = *(void**)((char*)ai + 40); cnt++;              // ai_next
              }
          } __except (EXCEPTION_EXECUTE_HANDLER) { }
      }
      return r; }
}

int WINAPI Hook_connect(SOCKT s, const void *name, int namelen) {
    typedef int (WINAPI *Pfn)(SOCKT, const void*, int);
    Pfn real = (Pfn)realfn("connect");
    char peer[28]; fmt_peer(name, namelen, peer, 28);
    if (peer[0]) sock_add(s, peer);
    if (take_req()) {
        char b[96]; int i=0; const char *m="SOCK connect ";
        while (*m) b[i++]=*m++;
        for (int j=0; peer[j] && i<80; j++) b[i++]=peer[j];
        b[i]=0; log_line(b);
    }
    return real(s, name, namelen);
}

int WINAPI Hook_WSAConnect(SOCKT s, const void *name, int namelen, void *cd, void *le, void *sq, void *gq) {
    typedef int (WINAPI *Pfn)(SOCKT, const void*, int, void*, void*, void*, void*);
    Pfn real = (Pfn)realfn("WSAConnect");
    char peer[28]; fmt_peer(name, namelen, peer, 28);
    if (peer[0]) sock_add(s, peer);
    if (take_req()) {
        char b[96]; int i=0; const char *m="SOCK WSAConnect ";
        while (*m) b[i++]=*m++;
        for (int j=0; peer[j] && i<80; j++) b[i++]=peer[j];
        b[i]=0; log_line(b);
    }
    return real(s, name, namelen, cd, le, sq, gq);
}

int WINAPI Hook_send(SOCKT s, const char *buf, int len, int flags) {
    typedef int (WINAPI *Pfn)(SOCKT, const char*, int, int);
    Pfn real = (Pfn)realfn("send");
    if (len > 0 && take_req()) {
        SKENT *e = sock_find(s);
        char tag[64]; int i=0; const char *m="SOCK send";
        while (*m) tag[i++]=*m++;
        if (e && e->peer[0]) { const char *t=" to "; while (*t) tag[i++]=*t++;
            for (int j=0; e->peer[j] && i<50; j++) tag[i++]=e->peer[j]; }
        tag[i]=0;
        log_bytes(tag, buf, (DWORD)len, 128);
        iathook_log_clienthello(tag, (const unsigned char*)buf, (DWORD)len);
        if (len < 512) { char tx[1024]; int ti=0;
            const char *m="SOCK CH full "; while (*m) tx[ti++]=*m++;
            { DWORD dd=(DWORD)len; char t2[8]; int tl=0; do { t2[tl++]=(char)('0'+(dd%10)); dd/=10; } while (dd);
              while (tl) tx[ti++]=t2[--tl]; }
            tx[ti++]='B'; tx[ti++]=' ';
            for (DWORD j=0; j<(DWORD)len && ti<980; j++) {
                unsigned c = ((const unsigned char*)buf)[j];
                tx[ti++]="0123456789abcdef"[c>>4]; tx[ti++]="0123456789abcdef"[c&15];
                if ((j&15)==15) tx[ti++]=' '; }
            tx[ti]=0; log_line(tx); }
    }
    return real(s, buf, len, flags);
}

int WINAPI Hook_WSASend(SOCKT s, WSABUF64 *bufs, DWORD cnt, DWORD *sent, DWORD flags, void *ov, void *cb) {
    typedef int (WINAPI *Pfn)(SOCKT, WSABUF64*, DWORD, DWORD*, DWORD, void*, void*);
    Pfn real = (Pfn)realfn("WSASend");
    if (bufs && cnt && take_req()) {
        SKENT *e = sock_find(s);
        char tag[64]; int i=0; const char *m="SOCK WSASend";
        while (*m) tag[i++]=*m++;
        if (e && e->peer[0]) { const char *t=" to "; while (*t) tag[i++]=*t++;
            for (int j=0; e->peer[j] && i<50; j++) tag[i++]=e->peer[j]; }
        tag[i]=0;
        log_bytes(tag, bufs[0].buf, (DWORD)(bufs[0].len > 4096 ? 4096 : bufs[0].len), 128);
        iathook_log_clienthello(tag, (const unsigned char*)bufs[0].buf, (DWORD)(bufs[0].len > 4096 ? 4096 : bufs[0].len));
    }
    return real(s, bufs, cnt, sent, flags, ov, cb);
}

int WINAPI Hook_recv(SOCKT s, char *buf, int len, int flags) {
    typedef int (WINAPI *Pfn)(SOCKT, char*, int, int);
    Pfn real = (Pfn)realfn("recv");
    int r = real(s, buf, len, flags);
    if (r > 0 && take_resp()) {
        SKENT *e = sock_find(s);
        char tag[64]; int i=0; const char *m="SOCK recv";
        while (*m) tag[i++]=*m++;
        if (e && e->peer[0]) { const char *t=" from "; while (*t) tag[i++]=*t++;
            for (int j=0; e->peer[j] && i<50; j++) tag[i++]=e->peer[j]; }
        tag[i]=0;
        log_bytes(tag, buf, (DWORD)r, 128);
        tls_note_recv((const unsigned char*)buf, (DWORD)r);
    }
    return r;
}

int WINAPI Hook_WSARecv(SOCKT s, WSABUF64 *bufs, DWORD cnt, DWORD *recvd, DWORD *flags, void *ov, void *cb) {
    typedef int (WINAPI *Pfn)(SOCKT, WSABUF64*, DWORD, DWORD*, DWORD*, void*, void*);
    Pfn real = (Pfn)realfn("WSARecv");
    int r = real(s, bufs, cnt, recvd, flags, ov, cb);
    if (r == 0 && recvd && *recvd && take_resp()) {
        // immediate completion (non-overlapped or already-done)
        SKENT *e = sock_find(s);
        char tag[64]; int i=0; const char *m="SOCK WSARecv";
        while (*m) tag[i++]=*m++;
        if (e && e->peer[0]) { const char *t=" from "; while (*t) tag[i++]=*t++;
            for (int j=0; e->peer[j] && i<50; j++) tag[i++]=e->peer[j]; }
        tag[i]=0;
        if (bufs && cnt) log_bytes(tag, bufs[0].buf, *recvd, 88);
    } else if (r == -1 && bufs && cnt) {
        // overlapped pending: remember buffer for the completion path
        SKENT *e = sock_find(s);
        if (e) { e->lastRecvBuf = bufs[0].buf; e->lastRecvCap = (DWORD)(bufs[0].len > 65536 ? 65536 : bufs[0].len); }
        ov_add(ov, s, bufs[0].buf, (DWORD)(bufs[0].len > 65536 ? 65536 : bufs[0].len));
    }
    return r;
}

int WINAPI Hook_recvfrom(SOCKT s, char *buf, int len, int flags, void *from, int *fromlen) {
    typedef int (WINAPI *Pfn)(SOCKT, char*, int, int, void*, int*);
    Pfn real = (Pfn)realfn("recvfrom");
    int r = real(s, buf, len, flags, from, fromlen);
    if (r > 0 && take_resp()) {
        char peer[28]; fmt_peer(from, fromlen ? *fromlen : 0, peer, 28);
        char tag[64]; int i=0; const char *m="SOCK recvfrom";
        while (*m) tag[i++]=*m++;
        if (peer[0]) { const char *t=" "; while (*t) tag[i++]=*t++;
            for (int j=0; peer[j] && i<50; j++) tag[i++]=peer[j]; }
        tag[i]=0;
        log_bytes(tag, buf, (DWORD)r, 48);
    }
    return r;
}

int WINAPI Hook_WSARecvFrom(SOCKT s, WSABUF64 *bufs, DWORD cnt, DWORD *recvd, DWORD *flags, void *from, int *fromlen, void *ov, void *cb) {
    typedef int (WINAPI *Pfn)(SOCKT, WSABUF64*, DWORD, DWORD*, DWORD*, void*, int*, void*, void*);
    Pfn real = (Pfn)realfn("WSARecvFrom");
    return real(s, bufs, cnt, recvd, flags, from, fromlen, ov, cb);
}

BOOL WINAPI Hook_WSAGetOverlappedResult(SOCKT s, void *ov, DWORD *xfer, BOOL wait, DWORD *flags) {
    typedef BOOL (WINAPI *Pfn)(SOCKT, void*, DWORD*, BOOL, DWORD*);
    Pfn real = (Pfn)realfn("WSAGetOverlappedResult");
    BOOL ok = real(s, ov, xfer, wait, flags);
    if (ok && xfer && *xfer && take_resp()) {
        SKENT *e = sock_find(s);
        OVENT *oe = ov_find(ov);
        void *dumpBuf = 0; DWORD dumpCap = 0;
        if (oe && oe->buf) { dumpBuf = oe->buf; dumpCap = oe->cap; ov_del(ov); }
        else if (e && e->lastRecvBuf) { dumpBuf = e->lastRecvBuf; dumpCap = e->lastRecvCap; e->lastRecvBuf = 0; }
        if (dumpBuf) {
            char tag[64]; int i=0; const char *m="SOCK iov ";
            while (*m) tag[i++]=*m++;
            if (e && e->peer[0]) { for (int j=0; e->peer[j] && i<50; j++) tag[i++]=e->peer[j]; }
            tag[i]=0;
            DWORD n = *xfer; if (n > dumpCap) n = dumpCap;
            log_bytes(tag, dumpBuf, n, n);
            tls_note_recv((const unsigned char*)dumpBuf, n);
        }
    }
    return ok;
}

int WINAPI Hook_closesocket(SOCKT s) {
    typedef int (WINAPI *Pfn)(SOCKT);
    Pfn real = (Pfn)realfn("closesocket");
    sock_del(s);
    return real(s);
}

// ---------------------------------------------------------------- WSAIoctl/ConnectEx (session 12)
// The rlink TLS client resolves ConnectEx at runtime via
// WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER) and then calls it as a fn
// POINTER — invisible to IAT hooks. Seam: WSAIoctl itself IS an IAT import,
// so we swap the fn pointer in the game's own output buffer (data-only)
// before the game ever reads it, then wrap every ConnectEx call.

static const unsigned char GUID_CONNECTEX[16] = {
    0xB9,0x07,0xA2,0x25,0xF3,0xDD,0x60,0x46,
    0x8E,0xE9,0x76,0xE5,0x8C,0x74,0x06,0x3E };
#define SIO_GET_EXT_FN 0xC8000006u

void *g_RealConnectEx;   // the real ConnectEx captured from WSAIoctl output

static int guid_eq(const void *a, const unsigned char *g) {
    const unsigned char *p = (const unsigned char*)a;
    int i;
    HC_TRY
        for (i = 0; i < 16; i++) if (p[i] != g[i]) return 0;
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

// WSAGetLastError without linking ws2_32 (lazy resolve)
static int wsa_err(void) {
    static int (WINAPI *pfn)(void);
    if (!pfn) {
        HMODULE h = GetModuleHandleA("WS2_32.dll");
        if (h) pfn = (int (WINAPI*)(void))GetProcAddress(h, "WSAGetLastError");
    }
    return pfn ? pfn() : 0;
}

// overlapped recv map: IOCP delivers buffers we only see filled at
// GetQueuedCompletionStatus / WSAGetOverlappedResult time
static OVENT g_Ov[256];
static volatile LONG g_OvLock;
static volatile LONG g_OvN;

static void ov_lock(void) { while (InterlockedCompareExchange(&g_OvLock,1,0)!=0) Sleep(0); }
static void ov_unlock(void) { InterlockedExchange(&g_OvLock, 0); }

static OVENT *ov_find(void *ov) {
    for (int i = 0; i < g_OvN; i++) if (g_Ov[i].ov == ov) return &g_Ov[i];
    return 0;
}
static void ov_add(void *ov, SOCKT s, void *buf, DWORD cap) {
    if (!ov) return;
    ov_lock();
    if (ov_find(ov)) { ov_unlock(); return; }
    if (g_OvN < 256) { g_Ov[g_OvN].ov=ov; g_Ov[g_OvN].s=s; g_Ov[g_OvN].buf=buf;
                       g_Ov[g_OvN].cap=(cap>65536?65536:cap); g_OvN++; }
    ov_unlock();
}
static void ov_del(void *ov) {
    ov_lock();
    for (int i = 0; i < g_OvN; i++) if (g_Ov[i].ov==ov) {
        for (int j=i;j<g_OvN-1;j++) g_Ov[j]=g_Ov[j+1];
        g_OvN--; break;
    }
    ov_unlock();
}

// ---------------------------------------------------------------- TLS records
// ClientHello SNI is PLAINTEXT in the first send on the socket; ServerHello
// version and TLS alerts tell us whether our (future) local server is
// accepted. Parse the record structure directly, SEH-guarded.

// returns 2 = ClientHello with SNI logged, 1 = ClientHello without SNI,
// 0 = not a ClientHello.
int iathook_log_clienthello(const char *tag, const unsigned char *p, DWORD n) {
    DWORD off;
    char b[384]; int i;
    unsigned vmaj, vmin;
    DWORD cslen;
    if (n < 44) return 0;
    HC_TRY
        if (p[0] != 0x16) return 0;
        vmaj = p[1]; vmin = p[2];
        if (vmaj != 3) return 0;
        if (p[5] != 0x01) return 0;              // ClientHello handshake
        off = 5 + 4 + 2 + 32;                    // rec+hs hdr, ver, random
        { DWORD sid = p[off]; off += 1 + sid; }  // session id
        if (off + 2 > n) return 0;
        cslen = ((DWORD)p[off]<<8)|p[off+1]; off += 2 + cslen;
        if (off >= n) return 0;
        { DWORD cmlen = p[off]; off += 1 + cmlen; }
        if (off + 2 > n) return 0;
        { DWORD extlen = ((DWORD)p[off]<<8)|p[off+1]; off += 2;
          DWORD extend = off + extlen; if (extend > n) extend = n;
          while (off + 4 <= extend) {
              DWORD etype = ((DWORD)p[off]<<8)|p[off+1];
              DWORD elen = ((DWORD)p[off+2]<<8)|p[off+3];
              off += 4;
              if (etype == 0 && off + 5 <= extend) {   // SNI
                  DWORD ntype = p[off+2];
                  DWORD nlen = ((DWORD)p[off+3]<<8)|p[off+4];
                  if (ntype == 0 && nlen > 0 && off+5+nlen <= extend) {
                      i = 0;
                      while (*tag && i < 360) b[i++] = *tag++;
                      { const char *m=" SNI="; while (*m) b[i++]=*m++; }
                      for (DWORD k = 0; k < nlen && k < 200 && i < 370; k++)
                          b[i++] = (char)((p[off+5+k]>=0x20 && p[off+5+k]<0x7f) ? p[off+5+k] : '.');
                      { const char *m=" ver="; while (*m) b[i++]=*m++; }
                      b[i++]=(char)('0'+vmaj);
                      b[i++]='.';
                      { int lo = vmin; char t[4]; int tl=0;
                        if (lo<10) t[tl++]=(char)('0'+lo); else { t[tl++]=(char)('0'+lo/10); t[tl++]=(char)('0'+lo%10); }
                        for (int q=0;q<tl;q++) b[i++]=t[q]; }
                      { const char *m=" suites="; while (*m) b[i++]=*m++;
                        { char t[6]; int tl=0; DWORD v=cslen/2;
                          if (!v) t[tl++]='0';
                          while (v && tl<5) { t[tl++]=(char)('0'+(v%10)); v/=10; }
                          while (tl) b[i++]=t[--tl]; } }
                      b[i]=0; log_line(b);
                      return 2;   // SNI found + logged
                  }
              }
              off += elen;
          } }
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

static void tls_note_recv(const unsigned char *p, DWORD n) {
    char b[96]; int i;
    if (n < 2) return;
    HC_TRY
        if (p[0] == 0x15 && n >= 3) {        // alert: level, description
            i = 0;
            { const char *m="TLS ALERT level="; while (*m) b[i++]=*m++; }
            b[i++]=(char)('0'+p[1]);
            { const char *m=" desc="; while (*m) b[i++]=*m++; }
            { char t[6]; int tl=0; DWORD v=p[2];
              if (!v) t[tl++]='0';
              while (v && tl<5) { t[tl++]=(char)('0'+(v%10)); v/=10; }
              while (tl) b[i++]=t[--tl]; }
            b[i]=0; log_line(b);
        } else if (p[0] == 0x16 && n >= 6 && p[5] == 0x02) {   // ServerHello
            i = 0;
            { const char *m="TLS ServerHello ver="; while (*m) b[i++]=*m++; }
            b[i++]=(char)('0'+p[1]); b[i++]='.';
            b[i++]=(char)('0'+(p[2]/10)); b[i++]=(char)('0'+(p[2]%10));
            b[i]=0; log_line(b);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { }
}

int WINAPI Hook_WSAIoctl(SOCKT s, DWORD code, void *in, DWORD inLen, void *out, DWORD outLen, DWORD *nret, void *ov, void *cr) {
    typedef int (WINAPI *Pfn)(SOCKT, DWORD, void*, DWORD, void*, DWORD, DWORD*, void*, void*);
    Pfn real = (Pfn)realfn("WSAIoctl");
    int r = real(s, code, in, inLen, out, outLen, nret, ov, cr);
    if (code == SIO_GET_EXT_FN && r == 0 && out) {
        if (in && inLen >= 16 && guid_eq(in, GUID_CONNECTEX)) {
            void *fn = *(void**)out;
            if (fn) {
                if (!g_RealConnectEx) g_RealConnectEx = fn;
                *(void**)out = (void*)&Hook_ConnectEx;
                { char b[96]; int i=0; const char *m="WSAIoctl: ConnectEx WRAPPED, real=0x";
                  while (*m) b[i++]=*m++;
                  for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)fn>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); }
                  b[i]=0; log_line(b); }
            }
        } else if (in && inLen >= 16 && take_req()) {
            char b[96]; int i=0; const char *m="WSAIoctl: ext-fn GUID ";
            while (*m) b[i++]=*m++;
            HC_TRY
                const unsigned char *g=(const unsigned char*)in;
                for (int k=0;k<16 && i<90;k++) {
                    int hi=g[k]>>4, lo=g[k]&15;
                    b[i++]=(char)(hi<10?'0'+hi:'a'+hi-10);
                    b[i++]=(char)(lo<10?'0'+lo:'a'+lo-10);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
            b[i]=0; log_line(b);
        }
    } else if (take_req()) {
        char b[80]; int i=0; const char *m="WSAIoctl code=0x";
        while (*m) b[i++]=*m++;
        for (int k=7;k>=0;k--) { int d=(int)((code>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); }
        b[i]=0; log_line(b);
    }
    return r;
}

unsigned long long WINAPI Hook_WSASocketA(int af, int type, int proto, void *info, unsigned int g, DWORD flags) {
    typedef unsigned long long (WINAPI *Pfn)(int, int, int, void*, unsigned int, DWORD);
    Pfn real = (Pfn)realfn("WSASocketA");
    SOCKT s = real(af, type, proto, info, g, flags);
    if (take_req()) {
        char b[96]; int i=0; const char *m="SOCK WSASocketA af=";
        while (*m) b[i++]=*m++;
        { char t[6]; int tl=0; DWORD v=(DWORD)af; if(!v)t[tl++]='0';
          while (v && tl<5) { t[tl++]=(char)('0'+(v%10)); v/=10; }
          while (tl) b[i++]=t[--tl]; }
        { const char *m2=" type="; while (*m2) b[i++]=*m2++; }
        { char t[6]; int tl=0; DWORD v=(DWORD)type; if(!v)t[tl++]='0';
          while (v && tl<5) { t[tl++]=(char)('0'+(v%10)); v/=10; }
          while (tl) b[i++]=t[--tl]; }
        if (flags) { const char *m2=" flags=0x"; while (*m2) b[i++]=*m2++;
          for (int k=7;k>=0;k--) { int d=(int)((flags>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        b[i]=0; log_line(b);
    }
    return s;
}

unsigned long long WINAPI Hook_socket(int af, int type, int proto) {
    typedef unsigned long long (WINAPI *Pfn)(int, int, int);
    Pfn real = (Pfn)realfn("socket");
    return real(af, type, proto);
}

BOOL WINAPI Hook_ConnectEx(SOCKT s, const void *name, int namelen, void *sendbuf, DWORD sendlen, DWORD *sent, void *ov) {
    typedef BOOL (WINAPI *Pfn)(SOCKT, const void*, int, void*, DWORD, DWORD*, void*);
    Pfn real = (Pfn)g_RealConnectEx;
    BOOL ok;
    char peer[28];
    fmt_peer(name, namelen, peer, 28);
    if (peer[0]) sock_add(s, peer);
    if (take_req()) {
        char b[96]; int i=0; const char *m="SOCK ConnectEx ";
        while (*m) b[i++]=*m++;
        for (int j=0; peer[j] && i<80; j++) b[i++]=peer[j];
        if (ov) { const char *t=" (overlapped)"; while (*t) b[i++]=*t++; }
        b[i]=0; log_line(b);
    }
    if (sendlen && sendbuf && take_req()) log_bytes("SOCK connectEx-data", sendbuf, sendlen, sendlen);
    if (!real) { log_line("ConnectEx: no real fn captured"); SetLastError(10038); return FALSE; }
    ok = real(s, name, namelen, sendbuf, sendlen, sent, ov);
    if (!ok && wsa_err() != 997 /* WSA_IO_PENDING */ && take_req()) {
        char b[96]; int i=0; const char *m="ConnectEx err=";
        while (*m) b[i++]=*m++;
        { char t[6]; int tl=0; DWORD v=(DWORD)wsa_err(); if(!v)t[tl++]='0';
          while (v && tl<5) { t[tl++]=(char)('0'+(v%10)); v/=10; }
          while (tl) b[i++]=t[--tl]; }
        b[i]=0; log_line(b);
    }
    return ok;
}

BOOL WINAPI Hook_GQCS(void *port, DWORD *xfer, unsigned long long *key, void **pov, DWORD ms) {
    typedef BOOL (WINAPI *Pfn)(void*, DWORD*, unsigned long long*, void**, DWORD);
    Pfn real = (Pfn)realfn("GetQueuedCompletionStatus");
    BOOL ok = real(port, xfer, key, pov, ms);
    if (ok && pov && *pov) {
        OVENT *e = ov_find(*pov);
        if (e && e->buf && xfer && *xfer && take_resp()) {
            SKENT *sk = sock_find(e->s);
            char tag[64]; int i=0; const char *m="SOCK iocp-recv ";
            while (*m) tag[i++]=*m++;
            if (sk && sk->peer[0]) { for (int j=0; sk->peer[j] && i<50; j++) tag[i++]=sk->peer[j]; }
            tag[i]=0;
            DWORD n2 = *xfer; if (n2 > e->cap) n2 = e->cap;
            log_bytes(tag, e->buf, n2, n2);
            tls_note_recv((const unsigned char*)e->buf, n2);
        }
        ov_del(*pov);
    }
    return ok;
}

// ---- CRYPT32 store loading (session 12: where does the trust pool come from?)

// trust-injection state: one shot per store handle
static void *g_InjStore[8];
static signed char g_InjDone[8];
static void cert_inj_reset_store(void *store) {
    for (int i = 0; i < 8; i++) if (g_InjStore[i] == store) { g_InjDone[i] = 0; return; }
    for (int i = 0; i < 8; i++) if (!g_InjStore[i]) { g_InjStore[i] = store; g_InjDone[i] = 0; return; }
}
static int cert_inj_done(void *store) {
    for (int i = 0; i < 8; i++) if (g_InjStore[i] == store) return g_InjDone[i];
    return 1;
}
static void cert_inj_mark(void *store) {
    for (int i = 0; i < 8; i++) if (g_InjStore[i] == store) { g_InjDone[i] = 1; return; }
}

typedef struct { void *store; LONG n; } STENT;
static STENT g_St[32];
static volatile LONG g_StN;

static LONG st_bump(void *store) {
    for (int i = 0; i < g_StN; i++) if (g_St[i].store == store)
        return InterlockedIncrement(&g_St[i].n);
    { LONG idx;
      do { idx = g_StN; if (idx >= 32) return 0; } while (InterlockedCompareExchange(&g_StN, idx+1, idx) != idx);
      g_St[idx].store = store; g_St[idx].n = 0;
      return InterlockedIncrement(&g_St[idx].n); }
}

void *WINAPI Hook_CertOpenStore(const char *prov, DWORD enc, unsigned long long cryptProv, DWORD flags, const void *para) {
    typedef void * (WINAPI *Pfn)(const char*, DWORD, unsigned long long, DWORD, const void*);
    Pfn real = (Pfn)realfn("CertOpenStore");
    void *h = real(prov, enc, cryptProv, flags, para);
    if (take_resp()) {
        char b[200]; int i=0; const char *m="CRYPT32 OpenStore prov=";
        while (*m) b[i++]=*m++;
        if (HC_IS_PTR(prov)) {
            HC_TRY for (int j=0; prov[j] && i<120; j++) b[i++]=prov[j]; } __except (EXCEPTION_EXECUTE_HANDLER) { }
        } else if (prov) {
            DWORD v = (DWORD)(ULONG_PTR)prov; char t[12]; int tl=0;
            b[i++]='#'; while (v && tl<10) { t[tl++]=(char)('0'+(v%10)); v/=10; }
            while (tl) b[i++]=t[--tl];
        }
        if (HC_IS_PTR(para)) {
            HC_TRY
                const char *pn = (const char*)para;
                if (pn[0] > 0x20 && pn[0] < 0x7f) {
                    b[i++]=' ';
                    for (int j=0; pn[j]>0x20 && pn[j]<0x7f && j<40 && i<180; j++) b[i++]=pn[j];
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
        }
        b[i]=0; log_line(b);
    }
    return h;
}

void *WINAPI Hook_CertEnumCertificatesInStore(void *store, void *prev) {
    typedef void * (WINAPI *Pfn)(void*, void*);
    Pfn real = (Pfn)realfn("CertEnumCertificatesInStore");
    void *ctx;
    // trust-pool injection (stage 8): when the Root-store enumeration is
    // about to end, hand the engine OUR cert once — the engine adds every
    // enumerated cert to its OpenSSL trust list, so our served self-signed
    // cert becomes a trusted anchor (self-referencing chain).
    if (prev == g_LoginInjectCert) return 0;   // our injected ctx as prev: enum done
    if (!prev && store) cert_inj_reset_store(store);
    ctx = real(store, prev);
    if (!ctx && prev && g_LoginInjectCert && store && !cert_inj_done(store)) {
        cert_inj_mark(store);
        { char b[96]; int i=0; const char *m="CRYPT32 INJECT: own cert appended to store enum";
          while (*m) b[i++]=*m++; b[i]=0; log_line(b); }
        return g_LoginInjectCert;
    }
    if (ctx) {
        LONG n = st_bump(store);
        if ((n & 255) == 1 && take_resp()) {
            // first cert of each 256-batch: encoded size + first 4 bytes
            char b[96]; int i=0; const char *m="CRYPT32 enum cert #";
            while (*m) b[i++]=*m++;
            { char t[8]; int tl=0; DWORD v=(DWORD)n; if(!v)t[tl++]='0';
              while (v && tl<7) { t[tl++]=(char)('0'+(v%10)); v/=10; }
              while (tl) b[i++]=t[--tl]; }
            HC_TRY
                DWORD cb = *(DWORD*)ctx;
                const unsigned char *pb = *(const unsigned char**)((char*)ctx+8);
                { const char *t=" enc="; while (*t) b[i++]=*t++;
                  { char t2[8]; int tl=0; DWORD v=cb; if(!v)t2[tl++]='0';
                    while (v && tl<7) { t2[tl++]=(char)('0'+(v%10)); v/=10; }
                    while (tl) b[i++]=t2[--tl]; } }
                if (pb) { const char *t=" head="; while (*t) b[i++]=*t++;
                    for (int k=0;k<4 && i<90;k++) { int hi=pb[k]>>4, lo=pb[k]&15;
                        b[i++]=(char)(hi<10?'0'+hi:'a'+hi-10);
                        b[i++]=(char)(lo<10?'0'+lo:'a'+lo-10); } }
            } __except (EXCEPTION_EXECUTE_HANDLER) { }
            b[i]=0; log_line(b);
        }
    } else if (prev && take_resp()) {
        char b[96]; int i=0; const char *m="CRYPT32 store enum END store=0x";
        while (*m) b[i++]=*m++;
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)store>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        b[i]=0; log_line(b);
    }
    return ctx;
}

BOOL WINAPI Hook_CertAddCtxToStore(void *store, void *ctx, DWORD flags, void **out) {
    typedef BOOL (WINAPI *Pfn)(void*, void*, DWORD, void**);
    Pfn real = (Pfn)realfn("CertAddCertificateContextToStore");
    BOOL ok = real(store, ctx, flags, out);
    if (take_resp() && ctx) {
        char b[240]; int i=0; const char *m="CRYPT32 AddCtx store=0x";
        while (*m) b[i++]=*m++;
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)(uintptr_t)store>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        { const char *t=" ctx=0x"; while (*t) b[i++]=*t++;
          for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)(uintptr_t)ctx>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        { const char *t=" flags=0x"; while (*t) b[i++]=*t++;
          for (int k=7;k>=0;k--) { int d=(int)((flags>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        HC_TRY
            DWORD cb = *(DWORD*)ctx;
            const unsigned char *pb = *(const unsigned char**)((char*)ctx+8);
            { const char *t=" enc="; while (*t) b[i++]=*t++;
              { char t2[8]; int tl=0; DWORD v=cb; if(!v)t2[tl++]='0';
                while (v && tl<7) { t2[tl++]=(char)('0'+(v%10)); v/=10; }
                while (tl) b[i++]=t2[--tl]; } }
            if (pb) { const char *t=" head="; while (*t) b[i++]=*t++;
                for (int k=0;k<4 && i<90;k++) { int hi=pb[k]>>4, lo=pb[k]&15;
                    b[i++]=(char)(hi<10?'0'+hi:'a'+hi-10);
                    b[i++]=(char)(lo<10?'0'+lo:'a'+lo-10); } }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        b[i]=0; log_line(b);
    }
    return ok;
}

BOOL WINAPI Hook_CryptStringToBinaryA(const char *in, DWORD inLen, DWORD flags, unsigned char *out, DWORD *outLen, DWORD *skip, DWORD *used) {
    typedef BOOL (WINAPI *Pfn)(const char*, DWORD, DWORD, unsigned char*, DWORD*, DWORD*, DWORD*);
    Pfn real = (Pfn)realfn("CryptStringToBinaryA");
    BOOL ok = real(in, inLen, flags, out, outLen, skip, used);
    if (take_resp() && in) {
        char b[160]; int i=0; const char *m="CRYPT32 StrToBin ";
        while (*m) b[i++]=*m++;
        HC_TRY for (int j=0; in[j] && j<56 && i<150; j++) b[i++]=in[j]; } __except (EXCEPTION_EXECUTE_HANDLER) { }
        b[i]=0; log_line(b);
    }
    return ok;
}

BOOL WINAPI Hook_CertCloseStore(void *store, DWORD flags) {
    typedef BOOL (WINAPI *Pfn)(void*, DWORD);
    Pfn real = (Pfn)realfn("CertCloseStore");
    return real(store, flags);
}

BOOL WINAPI Hook_CertFreeCtx(void *ctx) {
    typedef BOOL (WINAPI *Pfn)(void*);
    Pfn real = (Pfn)realfn("CertFreeCertificateContext");
    return real(ctx);
}

BOOL WINAPI Hook_CryptQueryObject(DWORD objType, const void *pvObject, DWORD expContent, DWORD expFormat, DWORD flags,
                                  DWORD *pEnc, DWORD *pContent, DWORD *pFormat, void **phStore, const void **ppvCtx) {
    typedef BOOL (WINAPI *Pfn)(DWORD, const void*, DWORD, DWORD, DWORD, DWORD*, DWORD*, DWORD*, void**, const void**);
    Pfn real = (Pfn)realfn("CryptQueryObject");
    if (take_resp() && HC_IS_PTR(pvObject)) {
        char b[200]; int i=0; const char *m="CRYPT32 QueryObject ";
        while (*m) b[i++]=*m++;
        HC_TRY for (int j=0; ((const char*)pvObject)[j] && j<100 && i<180; j++) b[i++]=((const char*)pvObject)[j]; } __except (EXCEPTION_EXECUTE_HANDLER) { }
        b[i]=0; log_line(b);
    }
    return real(objType, pvObject, expContent, expFormat, flags, pEnc, pContent, pFormat, phStore, ppvCtx);
}

DWORD WINAPI Hook_CertGetNameStringW(void *ctx, DWORD type, DWORD flags, void *para, wchar_t *out, DWORD cch) {
    typedef DWORD (WINAPI *Pfn)(void*, DWORD, DWORD, void*, wchar_t*, DWORD);
    Pfn real = (Pfn)realfn("CertGetNameStringW");
    DWORD r = real(ctx, type, flags, para, out, cch);
    if (r && out && out[0] && take_resp()) {
        char b[160]; int i=0; const char *m="CRYPT32 cert name=";
        while (*m) b[i++]=*m++;
        HC_TRY for (int j=0; out[j] && j<60 && i<150; j++) b[i++]=(char)(out[j]<128?out[j]:'?'); } __except (EXCEPTION_EXECUTE_HANDLER) { }
        b[i]=0; log_line(b);
    }
    return r;
}

DWORD WINAPI Hook_CertGetNameStringA(void *ctx, DWORD type, DWORD flags, void *para, char *out, DWORD cch) {
    typedef DWORD (WINAPI *Pfn)(void*, DWORD, DWORD, void*, char*, DWORD);
    Pfn real = (Pfn)realfn("CertGetNameStringA");
    return real(ctx, type, flags, para, out, cch);
}

// ---------------------------------------------------------------- CRYPT32
typedef struct { DWORD cbSize; DWORD dwErrorStatus; DWORD dwInfoStatus; } TRUSTSTATUS_HDR;

BOOL WINAPI Hook_CertGetCertificateChain(void *engine, void *certCtx, void *pTime, void *addStore,
                                          void *para, DWORD fl, void *resv, void **ppChain) {
    typedef BOOL (WINAPI *Pfn)(void*, void*, void*, void*, void*, DWORD, void*, void**);
    Pfn real = (Pfn)realfn("CertGetCertificateChain");
    // session 14: OWN collection store as hAdditionalStore — the chain engine
    // re-opens the system stores fresh at validation time, so the cert we
    // appended to an enum during setup is already gone by now. A Memory
    // collection store holding our served cert is merged into every chain
    // build (and kept alive until that store is closed).
    void *hAdd = addStore;
    if (g_LoginInjectCert && g_Map[IDX_ADDCTX].real && g_Map[IDX_CLOSE].real) {
        void *col = ((void* (WINAPI*)(const char*,DWORD,unsigned long long,DWORD,const void*))
            realfn("CertOpenStore"))("Memory", 0x10001 /*X509_ASN|PKCS_7*/, 0,
            0x2000 /*CERT_STORE_CREATE_NEW_FLAG*/, NULL);
        if (col) {
            typedef BOOL (WINAPI *Padd)(void*, void*, int, void**);
            if (((Padd)g_Map[IDX_ADDCTX].real)(col, g_LoginInjectCert, 4 /*ADD_REPLACE_EXISTING*/, NULL)) {
                hAdd = col;
                if (take_resp()) log_line("CRYPT32 INJECT: collection store merged into chain build");
            } else {
                typedef BOOL (WINAPI *Pclo)(void*, DWORD);
                ((Pclo)g_Map[IDX_CLOSE].real)(col, 0);
            }
        }
    }
    BOOL ok = real(engine, certCtx, pTime, hAdd, para, fl, resv, ppChain);
    if (hAdd != addStore) {
        // close the injected collection store: the chain engine addref'd it;
        // ours is released here, theirs by CertFreeCertificateChain.
        typedef BOOL (WINAPI *Pclo)(void*, DWORD);
        ((Pclo)g_Map[IDX_CLOSE].real)(hAdd, 0);
    }
    if (take_resp()) {
        char b[160]; int i=0; const char *m="CRYPT32 GetChain ctx=0x";
        while (*m) b[i++]=*m++;
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)certCtx>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        b[i++]=ok?' ':'!';
        HC_TRY
            if (ok && ppChain && *ppChain) {
                TRUSTSTATUS_HDR *ts = (TRUSTSTATUS_HDR*)((char*)*ppChain + 4);
                const char *t=" err=0x"; while (*t) b[i++]=*t++;
                { for (int k=7;k>=0;k--) { int d=(int)((ts->dwErrorStatus>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
                const char *t2=" info=0x"; while (*t2) b[i++]=*t2++;
                { for (int k=7;k>=0;k--) { int d=(int)((ts->dwInfoStatus>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        b[i]=0; log_line(b);
    }
    return ok;
}

BOOL WINAPI Hook_CertVerifyChainPolicy(const char *oid, void *chain, void *para, void *status) {
    typedef BOOL (WINAPI *Pfn)(const char*, void*, void*, void*);
    Pfn real = (Pfn)realfn("CertVerifyCertificateChainPolicy");
    BOOL ok = real(oid, chain, para, status);
    if (take_resp()) {
        char b[200]; int i=0; const char *m="CRYPT32 VerifyPolicy oid=";
        while (*m) b[i++]=*m++;
        for (int j=0; oid && oid[j] && i<180; j++) b[i++]=oid[j];
        b[i++]=ok?' ':'!';
        HC_TRY
            if (status) {
                DWORD dwErr = *(DWORD*)((char*)status + 4); // PCERT_CHAIN_POLICY_STATUS: cbSize; dwError
                const char *t=" dwError="; while (*t) b[i++]=*t++;
                { char t2[12]; int tl=0; DWORD v=dwErr;
                  if (!v) t2[tl++]='0';
                  while (v && tl<10) { t2[tl++]=(char)('0'+(v%10)); v/=10; }
                  while (tl) b[i++]=t2[--tl]; }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
        b[i]=0; log_line(b);
    }
    return ok;
}

void *WINAPI Hook_CertCreateChainEngine(void *config) {
    typedef void * (WINAPI *Pfn)(void*);
    Pfn real = (Pfn)realfn("CertCreateCertificateChainEngine");
    void *h = real(config);
    if (take_req()) log_line("CRYPT32 CreateChainEngine (custom trust engine built)");
    return h;
}

void *WINAPI Hook_CertFindCertificateInStore(void *store, DWORD enc, DWORD ff, DWORD ft, const void *para, void *prev) {
    typedef void * (WINAPI *Pfn)(void*, DWORD, DWORD, DWORD, const void*, void*);
    Pfn real = (Pfn)realfn("CertFindCertificateInStore");
    return real(store, enc, ff, ft, para, prev);
}

// ---------------------------------------------------------------- WINHTTP
typedef HIN (WINAPI *PfnOpen)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HIN (WINAPI *PfnConnect)(HIN, LPCWSTR, DWORD, DWORD);
typedef HIN (WINAPI *PfnOpenRequest)(HIN, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *PfnAddHdr)(HIN, LPCWSTR, DWORD, DWORD);
typedef BOOL (WINAPI *PfnSend)(HIN, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *PfnRecv)(HIN, LPVOID);
typedef BOOL (WINAPI *PfnQueryHdr)(HIN, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *PfnQueryAvail)(HIN, LPDWORD);
typedef BOOL (WINAPI *PfnRead)(HIN, LPVOID, DWORD, LPDWORD);
typedef BOOL (WINAPI *PfnClose)(HIN);
typedef void * (WINAPI *PfnSetCb)(HIN, void*, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *PfnSetOpt)(HIN, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *PfnCrack)(LPCWSTR, DWORD, DWORD, LPVOID);

HIN WINAPI Hook_WinHttpOpen(LPCWSTR agent, DWORD access, LPCWSTR proxy, LPCWSTR bypass, DWORD flags) {
    PfnOpen real = (PfnOpen)g_Map[0].real;
    HIN h;
    char a[80]; wascii(agent, a, 80);
    if (take_req()) {
        char b[160]; int i=0; const char *m="IAT WinHttpOpen agent=\"";
        while (*m) b[i++]=*m++;
        for (int j=0; a[j] && i<110; j++) b[i++]=a[j];
        b[i++]='"';
        { void *ra = _ReturnAddress();
          const char *t=" from=0x"; while (*t) b[i++]=*t++;
          for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)(uintptr_t)ra>>((unsigned)k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        b[i]=0; log_line(b);
    }
    h = real(agent, access, proxy, bypass, flags);
    if (take_req()) { logf1("IAT WinHttpOpen -> handle=0x", (DWORD64)h); }
    return h;
}

HIN WINAPI Hook_WinHttpConnect(HIN session, LPCWSTR server, DWORD port, DWORD resv) {
    PfnConnect real = (PfnConnect)g_Map[1].real;
    HIN h = real(session, server, port, resv);
    char s[80]; wascii(server, s, 80);
    if (h) { req_add(h, s, "", ""); }
    if (take_req()) {
        char b[180]; int i=0; const char *m="IAT WinHttpConnect host=\"";
        while (*m) b[i++]=*m++;
        for (int j=0; s[j] && i<170; j++) b[i++]=s[j];
        b[i++]='"';
        { const char *t=" port="; while (*t) b[i++]=*t++; }
        { char t[12]; int tl=0; DWORD v=port;
          do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
          while (tl) b[i++]=t[--tl]; }
        { const char *t=" h=0x"; while (*t) b[i++]=*t++; }
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)h>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        { const char *t=" from=0x"; while (*t && i<170) b[i++]=*t++;
          void *ra = _ReturnAddress();
          for (int k=15;k>=0;k--){ int d=(int)(((DWORD64)(uintptr_t)ra>>(k*4))&15); if(i<176)b[i++]=(char)(d<10?'0'+d:'a'+d-10);} }
        { const char *t=" ses=0x"; while (*t && i<182) b[i++]=*t++;
          for (int k=15;k>=0;k--){ int d=(int)(((DWORD64)(uintptr_t)session>>(k*4))&15); if(i<198)b[i++]=(char)(d<10?'0'+d:'a'+d-10);} }
        b[i]=0; log_line(b);
    }
    return h;
}

HIN WINAPI Hook_WinHttpOpenRequest(HIN connect, LPCWSTR verb, LPCWSTR objectName,
                                   LPCWSTR version, LPCWSTR referrer, LPCWSTR *accept, DWORD flags) {
    PfnOpenRequest real = (PfnOpenRequest)g_Map[2].real;
    HIN h = real(connect, verb, objectName, version, referrer, accept, flags);
    char v[12]; wascii(verb, v, 12);
    if (!v[0]) { v[0]='G'; v[1]='E'; v[2]='T'; v[3]=0; }
    char p[168]; wascii(objectName, p, 168);
    if (h) { REQ *c = req_find(connect); req_add(h, c ? c->host : "", v, p); }
    if (take_req()) {
        char b[320]; int i=0; const char *m="IAT WinHttpOpenRequest ";
        while (*m) b[i++]=*m++;
        for (int j=0; v[j] && i<300; j++) b[i++]=v[j];
        b[i++]=' ';
        for (int j=0; p[j] && i<300; j++) b[i++]=p[j];
        { const char *t=" h=0x"; while (*t) b[i++]=*t++; }
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)h>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        b[i]=0; log_line(b);
    }
    return h;
}

BOOL WINAPI Hook_WinHttpAddRequestHeaders(HIN req, LPCWSTR headers, DWORD len, DWORD modifiers) {
    PfnAddHdr real = (PfnAddHdr)g_Map[3].real;
    if (take_req()) {
        char h[300]; wascii(headers, h, 300);
        log_str2("IAT WinHttpAddRequestHeaders", h);
    }
    return real(req, headers, len, modifiers);
}

BOOL WINAPI Hook_WinHttpSendRequest(HIN req, LPCWSTR headers, DWORD headersLen,
                                    LPVOID optional, DWORD optionalLen, DWORD totalLen, DWORD_PTR ctx) {
    PfnSend real = (PfnSend)g_Map[4].real;
    BOOL ok;
    REQ *r = req_find(req);
    if (take_req()) {
        char b[320]; int i=0; const char *m="IAT WinHttpSendRequest ";
        while (*m) b[i++]=*m++;
        if (r) { for (int j=0; r->verb[j] && i<300; j++) b[i++]=r->verb[j];
                 b[i++]=' ';
                 for (int j=0; r->host[j] && i<300; j++) b[i++]=r->host[j];
                 for (int j=0; r->path[j] && i<300; j++) b[i++]=r->path[j]; }
        b[i]=0; log_line(b);
    }
    if (take_req() && headers) {
        char h[300]; wascii(headers, h, 300);
        log_str2("IAT   reqhdrs", h);
    }
    if (optionalLen && take_req()) {
        log_bytes("IAT   reqbody", optional, optionalLen, optionalLen);
    }
    if (r) r->bodyBytes = optionalLen;
    ok = real(req, headers, headersLen, optional, optionalLen, totalLen, ctx);
    if (!ok && take_req()) log_line("IAT   WinHttpSendRequest FAILED");
    return ok;
}

BOOL WINAPI Hook_WinHttpReceiveResponse(HIN req, LPVOID resv) {
    PfnRecv real = (PfnRecv)g_Map[5].real;
    BOOL ok = real(req, resv);
    if (take_req()) {
        REQ *r = req_find(req);
        char b[200]; int i=0; const char *m="IAT WinHttpReceiveResponse h=0x";
        while (*m) b[i++]=*m++;
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)req>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        if (r && r->path[0]) { const char *t=" path="; while (*t) b[i++]=*t++;
            for (int j=0; r->path[j] && i<190; j++) b[i++]=r->path[j]; }
        b[i++] = ok ? ' ' : '!';
        b[i++] = 0; log_line(b);
    }
    return ok;
}

BOOL WINAPI Hook_WinHttpQueryHeaders(HIN req, DWORD level, LPCWSTR name, LPVOID buf, LPDWORD buflen, LPDWORD idx) {
    PfnQueryHdr real = (PfnQueryHdr)g_Map[6].real;
    BOOL ok = real(req, level, name, buf, buflen, idx);
    if (ok && take_resp() && buf && buflen && *buflen && *buflen <= 2048) {
        char s[300]; wascii((const wchar_t*)buf, s, 300);
        log_str2("IAT   respheader", s);
    }
    return ok;
}

BOOL WINAPI Hook_WinHttpQueryDataAvailable(HIN req, LPDWORD avail) {
    PfnQueryAvail real = (PfnQueryAvail)g_Map[7].real;
    BOOL ok = real(req, avail);
    if (ok && avail && take_resp()) {
        REQ *r = req_find(req);
        char b[200]; int i=0; const char *m="IAT   available=";
        while (*m) b[i++]=*m++;
        { char t[12]; int tl=0; DWORD v=*avail;
          do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
          while (tl) b[i++]=t[--tl]; }
        if (r && r->path[0]) { const char *t=" path="; while (*t) b[i++]=*t++;
            for (int j=0; r->path[j] && i<190; j++) b[i++]=r->path[j]; }
        b[i]=0; log_line(b);
    }
    return ok;
}

BOOL WINAPI Hook_WinHttpReadData(HIN req, LPVOID buf, DWORD toRead, LPDWORD nRead) {
    PfnRead real = (PfnRead)g_Map[8].real;
    BOOL ok = real(req, buf, toRead, nRead);
    if (ok && nRead && *nRead && take_resp()) {
        REQ *r = req_find(req);
        char tag[80]; int i = 0;
        const char *m = "IAT   respdata";
        while (*m) tag[i++] = *m++;
        if (r && r->path[0]) {
            const char *t = " ";
            while (*t) tag[i++] = *t++;
            for (int j = 0; r->path[j] && i < 62; j++) tag[i++] = r->path[j];
        }
        tag[i] = 0;
        log_bytes(tag, buf, *nRead, *nRead);
        if (r) r->respBytes += *nRead;
    }
    return ok;
}

BOOL WINAPI Hook_WinHttpCrackUrl(LPCWSTR url, DWORD len, DWORD flags, LPVOID comps) {
    PfnCrack real = (PfnCrack)g_Map[9].real;
    if (take_req()) {
        char s[300];
        int n = (len && len != (DWORD)-1) ? (int)len : wlen(url);
        if (n > 299) n = 299;
        for (int i = 0; i < n; i++) s[i] = (char)(url[i] < 128 ? url[i] : '?');
        s[n] = 0;
        log_str2("IAT WinHttpCrackUrl", s);
    }
    return real(url, len, flags, comps);
}

BOOL WINAPI Hook_WinHttpCloseHandle(HIN h) {
    PfnClose real = (PfnClose)g_Map[10].real;
    req_del(h);
    return real(h);
}

void *WINAPI Hook_WinHttpSetStatusCallback(HIN h, void *cb, DWORD flags, DWORD_PTR resv) {
    PfnSetCb real = (PfnSetCb)g_Map[11].real;
    if (take_req()) {
        char b[160]; int i=0; const char *m="IAT WinHttpSetStatusCallback h=0x";
        while (*m) b[i++]=*m++;
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)h>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        const char *t=" cb=0x"; while (*t) b[i++]=*t++;
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)cb>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        b[i]=0; log_line(b);
    }
    return real(h, cb, flags, resv);
}

BOOL WINAPI Hook_WinHttpSetOption(HIN h, DWORD opt, LPVOID buf, DWORD buflen) {
    PfnSetOpt real = (PfnSetOpt)g_Map[12].real;
    if (take_req() && (opt == 84 /* SECURITY_FLAGS */ || opt == 79 || opt == 68)) {
        char b[120]; int i=0; const char *m="IAT WinHttpSetOption h=0x opt=";
        while (*m) b[i++]=*m++;
        { char t[12]; int tl=0; DWORD v=opt;
          do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
          while (tl) b[i++]=t[--tl]; }
        b[i]=0; log_line(b);
    }
    return real(h, opt, buf, buflen);
}

// ---------------------------------------------------------------- WININET
typedef HIN (WINAPI *PfnIOpenW)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HIN (WINAPI *PfnIConnA)(HIN, LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR);
typedef HIN (WINAPI *PfnHOpenA)(HIN, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR*, DWORD, DWORD_PTR);
typedef BOOL (WINAPI *PfnHSendW)(HIN, LPCWSTR, DWORD, LPVOID, DWORD);
typedef BOOL (WINAPI *PfnIRF)(HIN, LPVOID, DWORD, LPDWORD);

HIN WINAPI Hook_InternetOpenW(LPCWSTR agent, DWORD access, LPCWSTR proxy, LPCWSTR bypass, DWORD flags) {
    PfnIOpenW real = (PfnIOpenW)g_Map[13].real;
    char a[80]; wascii(agent, a, 80);
    if (take_req()) log_str2("IAT InternetOpenW agent", a);
    return real(agent, access, proxy, bypass, flags);
}

HIN WINAPI Hook_InternetConnectA(HIN ses, LPCSTR server, DWORD port, LPCSTR user, LPCSTR pw, DWORD svc, DWORD flags, DWORD_PTR ctx) {
    PfnIConnA real = (PfnIConnA)g_Map[14].real;
    HIN h = real(ses, server, port, user, pw, svc, flags, ctx);
    if (h) { char s[80]; int i=0; while (server && server[i] && i<79) { s[i]=server[i]; i++; } s[i]=0;
             req_add(h, s, "", ""); }
    if (take_req()) {
        char b[180]; int i=0; const char *m="IAT InternetConnectA host=";
        while (*m) b[i++]=*m++;
        for (int j=0; server && server[j] && j<70; j++) b[i++]=server[j];
        b[i]=0; log_line(b);
    }
    return h;
}

HIN WINAPI Hook_HttpOpenRequestA(HIN connect, LPCSTR verb, LPCSTR objectName, LPCSTR version,
                                 LPCSTR referrer, LPCSTR *accept, DWORD flags, DWORD_PTR ctx) {
    PfnHOpenA real = (PfnHOpenA)g_Map[15].real;
    HIN h = real(connect, verb, objectName, version, referrer, accept, flags, ctx);
    char v[12]; { int i=0; while (verb && verb[i] && i<11) { v[i]=verb[i]; i++; } v[i]=0; }
    if (!v[0]) { v[0]='G'; v[1]='E'; v[2]='T'; v[3]=0; }
    char p[168]; { int i=0; while (objectName && objectName[i] && i<167) { p[i]=objectName[i]; i++; } p[i]=0; }
    if (h) { REQ *c = req_find(connect); req_add(h, c ? c->host : "", v, p); }
    if (take_req()) {
        char b[300]; int i=0; const char *m="IAT HttpOpenRequestA ";
        while (*m) b[i++]=*m++;
        for (int j=0; v[j] && i<280; j++) b[i++]=v[j];
        b[i++]=' ';
        for (int j=0; p[j] && i<280; j++) b[i++]=p[j];
        b[i]=0; log_line(b);
    }
    return h;
}

BOOL WINAPI Hook_HttpAddRequestHeadersA(HIN req, LPCSTR headers, DWORD len, DWORD modifiers) {
    typedef BOOL (WINAPI *Pfn)(HIN, LPCSTR, DWORD, DWORD);
    Pfn real = (Pfn)g_Map[16].real;
    if (take_req() && headers) {
        char h[300]; int i=0;
        while (headers[i] && i < 299) { h[i] = headers[i]; i++; }
        h[i] = 0;
        log_str2("IAT HttpAddRequestHeadersA", h);
    }
    return real(req, headers, len, modifiers);
}

BOOL WINAPI Hook_HttpSendRequestW(HIN req, LPCWSTR headers, DWORD len, LPVOID optional, DWORD optionalLen) {
    PfnHSendW real = (PfnHSendW)g_Map[17].real;
    REQ *r = req_find(req);
    if (take_req()) {
        char b[320]; int i=0; const char *m="IAT HttpSendRequestW ";
        while (*m) b[i++]=*m++;
        if (r) { for (int j=0; r->verb[j] && i<300; j++) b[i++]=r->verb[j];
                 b[i++]=' ';
                 for (int j=0; r->host[j] && i<300; j++) b[i++]=r->host[j];
                 for (int j=0; r->path[j] && i<300; j++) b[i++]=r->path[j]; }
        b[i]=0; log_line(b);
    }
    if (optionalLen && take_req()) {
        log_bytes("IAT   reqbody", optional, optionalLen, optionalLen);
    }
    if (r) r->bodyBytes = optionalLen;
    return real(req, headers, len, optional, optionalLen);
}

BOOL WINAPI Hook_HttpQueryInfoA(HIN req, DWORD level, LPVOID buf, LPDWORD buflen, LPDWORD idx) {
    typedef BOOL (WINAPI *Pfn)(HIN, DWORD, LPVOID, LPDWORD, LPDWORD);
    Pfn real = (Pfn)g_Map[18].real;
    BOOL ok = real(req, level, buf, buflen, idx);
    if (ok && take_resp() && buf && buflen && *buflen && *buflen <= 512) {
        log_bytes("IAT   HttpQueryInfo", buf, *buflen, *buflen);
    }
    return ok;
}

BOOL WINAPI Hook_InternetReadFile(HIN f, LPVOID buf, DWORD toRead, LPDWORD nRead) {
    PfnIRF real = (PfnIRF)g_Map[19].real;
    BOOL ok = real(f, buf, toRead, nRead);
    if (ok && nRead && *nRead && take_resp()) {
        REQ *r = req_find(f);
        char tag[80]; int i=0; const char *m="IAT   inetdata";
        while (*m) tag[i++]=*m++;
        if (r && r->path[0]) { const char *t=" "; while (*t) tag[i++]=*t++;
            for (int j=0; r->path[j] && i<62; j++) tag[i++]=r->path[j]; }
        tag[i]=0;
        log_bytes(tag, buf, *nRead, *nRead);
        if (r) r->respBytes += *nRead;
    }
    return ok;
}

BOOL WINAPI Hook_InternetQueryOptionW(HIN h, DWORD opt, LPVOID buf, LPDWORD buflen) {
    typedef BOOL (WINAPI *Pfn)(HIN, DWORD, LPVOID, LPDWORD);
    Pfn real = (Pfn)g_Map[20].real;
    return real(h, opt, buf, buflen);
}

void *WINAPI Hook_InternetSetStatusCallbackW(HIN h, void *cb) {
    typedef void * (WINAPI *Pfn)(HIN, void*);
    Pfn real = (Pfn)g_Map[21].real;
    if (take_req()) {
        char b[160]; int i=0; const char *m="IAT InternetSetStatusCallbackW h=0x cb=0x";
        while (*m) b[i++]=*m++;
        { for (int k=15;k>=0;k--) { int d=(int)(((DWORD64)h>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); } }
        b[i]=0; log_line(b);
    }
    return real(h, cb);
}

BOOL WINAPI Hook_InternetCrackUrlA(LPCSTR url, DWORD len, DWORD flags, LPVOID comps) {
    typedef BOOL (WINAPI *Pfn)(LPCSTR, DWORD, DWORD, LPVOID);
    Pfn real = (Pfn)g_Map[22].real;
    if (take_req() && url) {
        char s[300]; int i=0;
        DWORD n = (len && len != (DWORD)-1) ? len : 0;
        if (!n) { while (url[i] && i < 299) { s[i]=url[i]; i++; } }
        else { while (i < (int)n && i < 299) { s[i]=url[i]; i++; } }
        s[i]=0;
        log_str2("IAT InternetCrackUrlA", s);
    }
    return real(url, len, flags, comps);
}

BOOL WINAPI Hook_InternetCloseHandle(HIN h) {
    PfnClose real = (PfnClose)g_Map[23].real;
    req_del(h);
    return real(h);
}

// ---------------------------------------------------------------- IAT patch
static int ascii_ieq(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        char x = a[i], y = b[i];
        if (x >= 'A' && x <= 'Z') x = (char)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (char)(y + 32);
        if (x != y) return 0;
        if (!x) return 1;
    }
    return 1;
}

// strcmp without CRT
int strcmp_f(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (int)(unsigned char)*a - (int)(unsigned char)*b;
}

// Reset the map (hooktest fake PE runs before/after real modules).
void iathook_reset(void) {
    for (int k = 0; k < NMAP; k++) g_Map[k].real = 0;
    g_ReqN = 0;
    g_SockN = 0;
    g_OvN = 0;
    g_RealConnectEx = 0;
    for (int i = 0; i < 8; i++) { g_InjStore[i] = 0; g_InjDone[i] = 0; }
}

// hooktest: inject real fn pointers directly (no IAT to patch in the test)
void iathook_set_real(const char *name, void *fn) {
    for (int k = 0; k < NMAP; k++)
        if (!strcmp_f(name, g_Map[k].fn)) { g_Map[k].real = fn; return; }
}

int iathook_patch_module(HMODULE mod) {
    unsigned char *base = (unsigned char*)mod;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_IMPORT_DESCRIPTOR *imp;
    int swapped = 0;
    if (!mod) return 0;
    HC_TRY
        dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != 0x5A4D) return 0;
        nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
        if (nt->Signature != 0x4550) return 0;
        imp = (IMAGE_IMPORT_DESCRIPTOR*)(base + nt->OptionalHeader.DataDirectory[1].VirtualAddress);
        if (!nt->OptionalHeader.DataDirectory[1].VirtualAddress) return 0;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    for (; imp->Name; imp++) {
        const char *dllName;
        HC_TRY dllName = (const char*)(base + imp->Name); }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (!ascii_ieq(dllName, "WINHTTP.dll", 12) &&
            !ascii_ieq(dllName, "WININET.dll", 11) &&
            !ascii_ieq(dllName, "libHttpClient.Win32.dll", 24) &&
            !ascii_ieq(dllName, "WSOCK32.dll", 11) &&
            !ascii_ieq(dllName, "WS2_32.dll", 10) &&
            !ascii_ieq(dllName, "CRYPT32.dll", 11) &&
            !ascii_ieq(dllName, "KERNEL32.dll", 12))
            continue;
        { // patch every thunk whose name matches our table
          DWORD64 *thunk = (DWORD64*)(base + (imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk));
          DWORD64 *iat   = (DWORD64*)(base + imp->FirstThunk);
          int i = 0;
          for (; thunk[i]; i++) {
              const char *fnName = 0;
              if (!(thunk[i] & IMAGE_ORDINAL_FLAG64)) {
                  IMAGE_IMPORT_BY_NAME *ibn = (IMAGE_IMPORT_BY_NAME*)(base + (DWORD)(thunk[i] & 0xFFFFFFFF));
                  HC_TRY fnName = (const char*)ibn->Name; }
                  __except (EXCEPTION_EXECUTE_HANDLER) { fnName = 0; }
              }
              if (!fnName) {
                  // ordinal import (WSOCK32 legacy: ordinal-flagged ILT): the
                  // WinSock 1.1 ordinal table is stable — translate to a name.
                  if (thunk[i] & IMAGE_ORDINAL_FLAG64) {
                      static const struct { WORD ord; const char *nm; } WSO[] = {
                          {1,"accept"}, {2,"bind"}, {3,"closesocket"}, {4,"connect"},
                          {5,"getpeername"}, {6,"getsockname"}, {7,"getsockopt"},
                          {8,"htonl"}, {9,"htons"}, {10,"inet_addr"}, {11,"inet_ntoa"},
                          {12,"ioctlsocket"}, {13,"listen"}, {14,"ntohl"}, {15,"ntohs"},
                          {16,"recv"}, {17,"recvfrom"}, {18,"select"}, {19,"send"},
                          {20,"sendto"}, {21,"setsockopt"}, {22,"shutdown"}, {23,"socket"},
                      };
                      WORD o = (WORD)(thunk[i] & 0xFFFF);
                      for (unsigned w = 0; w < sizeof(WSO)/sizeof(WSO[0]); w++)
                          if (WSO[w].ord == o) { fnName = WSO[w].nm; break; }
                  }
              }
              if (!fnName) {
                  // legacy/bound slot (name unreadable): identify by resolved
                  // address via GetProcAddress on the owning DLL
                  HC_TRY
                      HMODULE hm = GetModuleHandleA(dllName);
                      if (hm) {
                          for (int k = 0; k < NMAP; k++) {
                              FARPROC pa;
                              if (g_Map[k].real) continue;
                              pa = GetProcAddress(hm, g_Map[k].fn);
                              if (pa && (DWORD64)(uintptr_t)pa == iat[i]) {
                                  DWORD old = 0;
                                  if (VirtualProtect(&iat[i], 8, PAGE_READWRITE, &old)) {
                                      g_Map[k].real = (void*)iat[i];
                                      iat[i] = (DWORD64)(uintptr_t)g_Map[k].stub;
                                      VirtualProtect(&iat[i], 8, old, &old);
                                      swapped++;
                                      { char b[160]; int bi=0; const char *m="IAT+ ";
                                        while (*m) b[bi++]=*m++;
                                        for (int j=0; dllName[j] && bi<120; j++) b[bi++]=dllName[j];
                                        b[bi++]='!';
                                        { const char *n = g_Map[k].fn; for (int j=0; n[j] && bi<150; j++) b[bi++]=n[j]; }
                                        b[bi++]= ' '; b[bi++]='('; b[bi++]='b'; b[bi++]='y';
                                        b[bi++]=' '; b[bi++]='a'; b[bi++]='d'; b[bi++]='d';
                                        b[bi++]='r'; b[bi++]=')'; b[bi]=0; log_line(b); }
                                      break;
                                  }
                              }
                          }
                      }
                  } __except (EXCEPTION_EXECUTE_HANDLER) { }
                  continue;
              }
              for (int k = 0; k < NMAP; k++) {
                  if (g_Map[k].real) continue;
                  if (!strcmp_f(fnName, g_Map[k].fn)) {
                      DWORD old = 0;
                      if (VirtualProtect(&iat[i], 8, PAGE_READWRITE, &old)) {
                          g_Map[k].real = (void*)iat[i];
                          iat[i] = (DWORD64)(uintptr_t)g_Map[k].stub;
                          VirtualProtect(&iat[i], 8, old, &old);
                          swapped++;
                          { char b[160]; int bi=0; const char *m="IAT+ ";
                            while (*m) b[bi++]=*m++;
                            for (int j=0; dllName[j] && bi<120; j++) b[bi++]=dllName[j];
                            b[bi++]='!';
                            { const char *n = g_Map[k].fn; for (int j=0; n[j] && bi<150; j++) b[bi++]=n[j]; }
                            b[bi]=0; log_line(b); }
                      } else {
                          { char b[160]; int bi=0; const char *m="IAT! VP failed ";
                            while (*m) b[bi++]=*m++;
                            for (int j=0; dllName[j] && bi<120; j++) b[bi++]=dllName[j];
                            b[bi++]='!';
                            { const char *n = g_Map[k].fn; for (int j=0; n[j] && bi<150; j++) b[bi++]=n[j]; }
                            b[bi]=0; log_line(b); }
                      }
                      break;
                  }
              }
          } }
    }
    return swapped;
}
