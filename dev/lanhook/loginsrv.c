// loginsrv.c — M1 H1 LoginShim server (session 12).
//
// SChannel TLS 1.2 server + minimal HTTP/1.1 + positional-array JSON that
// matches the rlink wire format (field order proven by the ageLANServer
// public source; envelope: result, sessionId, statId, serverTime, accountInfo,
// profiles, 0, 0, null, allProfileInfo, loginData, [], 0, relayServers).
//
// No CRT: kernel32 only; ws2_32/secur32/crypt32/advapi32 are loaded
// dynamically so the dbghelp proxy's import table stays minimal.
//
// Offline validation: srvtest.exe starts this server; a Python ssl client
// proves the handshake + HTTP + JSON before the DLL ever touches the game.

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <security.h>
#include <schannel.h>
#include <stdint.h>
#include "hookcore.h"
#include "loginsrv.h"

// forward decls (no CRT, definitions below)
static size_t strlen_f(const char *s);
static char *strstr_f(const char *h, const char *n);
static void memmove_f(char *d, const char *s, size_t n);
static int  memcmp_f(const void *a, const void *b, size_t n);
static int atoi_f(const char *s);

// ---------------------------------------------------------------- dyn loads
static HMODULE g_hSecur, g_hCrypt, g_hAdv, g_hWs2, g_hNc;

typedef SECURITY_STATUS (WINAPI *PfnACH)(PCWSTR, PCWSTR, ULONG, PVOID, PVOID, PVOID, PVOID, PCredHandle, PTimeStamp);
typedef SECURITY_STATUS (WINAPI *PfnFCH)(PCredHandle);
typedef SECURITY_STATUS (WINAPI *PfnASC)(PCredHandle, PCtxtHandle, PSecBufferDesc, ULONG, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp);
typedef SECURITY_STATUS (WINAPI *PfnDSC)(PCtxtHandle);
typedef SECURITY_STATUS (WINAPI *PfnQCA)(PCtxtHandle, ULONG, PVOID);
typedef SECURITY_STATUS (WINAPI *PfnEM)(PCtxtHandle, unsigned long, PSecBufferDesc, unsigned long);
typedef SECURITY_STATUS (WINAPI *PfnDM)(PCtxtHandle, PSecBufferDesc, unsigned long, unsigned long*);
typedef SECURITY_STATUS (WINAPI *PfnACT)(PCtxtHandle, PSecBufferDesc);

static PfnACH  pACH;   // AcquireCredentialsHandleA
static PfnFCH  pFCH;
static PfnASC  pASC;
static PfnDSC  pDSC;
static PfnQCA  pQCA;
static PfnEM   pEM;
static PfnDM   pDM;
static PfnACT  pACT;

typedef void *(WINAPI *PfnCertCSSC)(ULONG_PTR, CERT_NAME_BLOB*, DWORD, CRYPT_KEY_PROV_INFO*, void*, SYSTEMTIME*, SYSTEMTIME*, void*);
typedef BOOL (WINAPI *PfnCertCTNW)(DWORD, LPCWSTR, DWORD, void*, BYTE*, DWORD*, LPCWSTR*);
typedef BOOL (WINAPI *PfnCertFCC)(PCCERT_CONTEXT);
typedef BOOL (WINAPI *PfnCEOE)(DWORD, LPCSTR, const void*, DWORD, void*, BYTE**, DWORD*);

static PfnCertCSSC pCertCSSC;
static PfnCertCTNW pCertCTNW;
static PfnCertFCC  pCertFCC;
static PfnCEOE   pCEOE;

typedef BOOL (WINAPI *PfnCAC)(HCRYPTPROV*, LPCSTR, LPCSTR, DWORD, DWORD);
typedef BOOL (WINAPI *PfnCGK)(HCRYPTPROV, DWORD, DWORD, HCRYPTKEY*);
typedef BOOL (WINAPI *PfnCRC)(HCRYPTPROV);

static PfnCAC pCAC;
static PfnCGK pCGK;
static PfnCRC pCRC;

// ws2_32 fns used directly (CRT-free sockets)
static int   (WINAPI *p_socket)(int,int,int);
static int   (WINAPI *p_bind)(SOCKET, const struct sockaddr*, int);
static int   (WINAPI *p_listen)(SOCKET,int);
static SOCKET (WINAPI *p_accept)(SOCKET, struct sockaddr*, int*);
static int   (WINAPI *p_closesocket)(SOCKET);
static int   (WINAPI *p_recv)(SOCKET, char*, int,int);
static int   (WINAPI *p_send)(SOCKET, const char*, int,int);
static int   (WINAPI *p_setsockopt)(SOCKET,int,int,const char*,int);
static u_short (WINAPI *p_htons)(u_short);
static int   (WINAPI *p_WSAStartup)(WORD, void*);
static int   (WINAPI *p_WSAGetLastError)(void);

static void logn(const char *s) { log_line(s); }
static char g_LastToken[24];   /* connectionToken of the last login we served */
static char g_Alias[64];       /* account alias of the last login (WS event pump) */
// The WS notification plane cannot carry a login event: every registered payload
// parser (46 of them, 0x144116af0+0x10k) locks m_type to its own message name and
// none is a login/account event (s21 static result). The ladder stays for M2,
// where the pushed types *are* registered ones. AOE2LAN_PUSH=1 re-enables it.
static int g_PushEnable = -1;
/* probe needles: each is a raw LE int64 the reply carries, so a hit in game
   memory localises how far the client's deserializer got (see ProbeThread) */
static unsigned char g_ProbeId[8];     /* profileID   (accountInfo.id / profile.id) */
static unsigned char g_ProbeStat[8];   /* personalStatGroupID (ProfileInfo field 8) */
static unsigned char g_ProbeConn[8];   /* connectionID (LoginResult+0x20) */

/* CRT-free byte search helpers (used by the memory probe) */
static unsigned char *memchr_p(const unsigned char *p, unsigned char c, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i] == c) return (unsigned char *)(p + i);
    return 0;
}
static int mem_eq(const unsigned char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) if (a[i] != (unsigned char)b[i]) return 0;
    return 1;
}

// ---------------------------------------------------------------- helpers
static DWORD64 unix_now(void) {
    FILETIME ft; ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime; u.HighPart = ft.dwHighDateTime;
    return (DWORD64)((u.QuadPart - 116444736000000000ULL) / 10000000ULL);
}

static DWORD64 fnv1a64(const char *s) {
    DWORD64 h = 0xcbf29ce484222325ULL;
    while (*s) { h ^= (unsigned char)*s++; h *= 0x100000001b3ULL; }
    return h;
}

// small append-only buffer (heap)
typedef struct { char *p; size_t len, cap; int oom; } BUF;
static void bput(BUF *b, const char *s, size_t n) {
    if (b->oom || !n) return;
    if (b->len + n + 1 > b->cap) {
        size_t nc = b->cap ? b->cap * 2 : 512;
        while (nc < b->len + n + 1) nc *= 2;
        char *np = (char*)HeapAlloc(GetProcessHeap(), 0, nc);
        if (!np) { b->oom = 1; return; }
        if (b->len) memcpy(np, b->p, b->len);
        if (b->p) HeapFree(GetProcessHeap(), 0, b->p);
        b->p = np; b->cap = nc;
    }
    memcpy(b->p + b->len, s, n);
    b->len += n;
    b->p[b->len] = 0;
}
static void bs(BUF *b, const char *s) { bput(b, s, strlen_f(s)); }
static void bnum(BUF *b, DWORD64 v) {
    char t[24]; int tl = 0;
    if (!v) t[tl++] = '0';
    while (v && tl < 22) { t[tl++] = (char)('0' + (int)(v % 10)); v /= 10; }
    char out[24]; int ol = 0;
    while (tl) out[ol++] = t[--tl];
    bput(b, out, (size_t)ol);
}

// strlen without CRT
static size_t strlen_f(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

static int starts(const char *s, const char *pre) {
    while (*pre) { if (*s++ != *pre++) return 0; }
    return 1;
}
static int contains(const char *s, const char *sub) {
    size_t ls = strlen_f(s), lb = strlen_f(sub);
    if (lb > ls) return 0;
    for (size_t i = 0; i + lb <= ls; i++) {
        size_t j = 0;
        while (j < lb && s[i+j] == sub[j]) j++;
        if (j == lb) return 1;
    }
    return 0;
}

// ---------------------------------------------------------------- identity
// profileID = FNV1a64("aoe2lan:" + nickname) — stable across restarts (R3).
// The nickname comes from the login request's alias field (Steam emu persona);
// "Player" if absent. Request bodies are urlencoded: alias=NAME&...
static void extract_alias(const char *body, char *out, int cap) {
    const char *a = body ? strstr_f(body, "alias=") : 0;
    int i = 0;
    out[0] = 0;
    if (!a) return;
    a += 6;
    while (a[i] && a[i] != '&' && i < cap-1) { out[i] = a[i]; i++; }
    out[i] = 0;
    // trim leading/trailing spaces and +
    while (out[0] == ' ' || out[0] == '+') memmove_f(out, out+1, (size_t)i--);
    while (i > 0 && (out[i-1] == ' ' || out[i-1] == '+')) out[--i] = 0;
    if (!out[0]) { out[0] = 'P'; out[1] = 'l'; out[2] = 'a'; out[3] = 'y'; out[4] = 'e'; out[5] = 'r'; out[6] = 0; }
}

static char *strstr_f(const char *h, const char *n) {
    size_t ln = strlen_f(n);    if (!ln) return (char*)h;
    for (const char *p = h; *p; p++) {
        size_t j = 0;
        while (j < ln && p[j] == n[j]) j++;
        if (j == ln) return (char*)p;
    }
    return 0;
}
// bounded substring search over a WS frame payload (not NUL-terminated)
static int strstr_n(const char *h, int n, const char *needle) {
    int ln = (int)strlen_f(needle);
    if (ln <= 0) return 0;
    for (int i = 0; i + ln <= n; i++) {
        int j = 0;
        while (j < ln && h[i + j] == needle[j]) j++;
        if (j == ln) return 1;
    }
    return 0;
}
static int memcmp_f(const void *a, const void *b, size_t n) {
    const unsigned char *x = (const unsigned char*)a, *y = (const unsigned char*)b;
    for (size_t i = 0; i < n; i++) if (x[i] != y[i]) return 1;
    return 0;
}
static void memmove_f(char *d, const char *s, size_t n) {
    if (d < s) { for (size_t i = 0; i < n; i++) d[i] = s[i]; }
    else { for (size_t i = n; i > 0; i--) d[i-1] = s[i-1]; }
}

// ---------------------------------------------------------------- login JSON
// Envelope (positional, ageLANServer-proven for AoE2):
//  [0]=result 0
//  [1]=sessionId
//  [2]=549000000
//  [3]=serverTime
//  [4]=accountInfo [profileId, platformPath, platformId, -1, 0, "en", "eur", 2, null]
//  [5]=[profileInfo]
//  [6]=0 [7]=0 [8]=null
//  [9]=allProfileInfo [0, profileInfo, [], [extraProfileInfo], [], null, [], null, 1, [], -1]
//  [10]=loginData [[key,value]...]
//  [11]=[]
//  [12]=0
//  [13]=relayServers [[region, name, ip, bsPort, wsPort, oobPort]]
// profileInfo: [time, profileId, "steam", null, alias, alias, "", statId,
//               xp, level, platformRelated, null, platformUserId, platformId, []]
// extraProfileInfo (AoE2): [statId,0,0,1,-1,0,0,-1,-1,-1,-1,-1,1000,
//                           1713372625,0,0,0,0,0]
static const char *LOGIN_DATA_JSON =
"[\"RL_AUTOMATCH2_FAILSAFE_SEC\",\"180\"],[\"PHX_LOG_SYNCPLAYER\",\"1\"],"
"[\"PHX_LOG_SYNCAI\",\"1\"],[\"PHX_LOG_SYNCRANDOM\",\"1\"],"
"[\"RL_TELEMSHOULDNTSEND\",\"ZoomChange,rlink_HttpRequest,RadialMenu,SpecialAction,SelectionEvent\"],"
"[\"RL_USE_WEBSOCKET_PERCENT\",\"100\"],[\"RL_KEEPALIVE\",\"20\"],[\"RL_DISCONNECT\",\"30\"],"
"[\"RL_MISSPOLL\",\"3\"],[\"RL_TELEMSERVICE\",\"0\"],[\"RL_TELEMSERVICE2\",\"5\"],"
"[\"RL_TELEMREPORTPCT\",\"1.0\"],[\"RL_MATCHTELEMPERIOD\",\"600\"],"
"[\"RL_TELEMCELLHOST\",\"phoenix.maelstrom.gameservices.xboxlive.com\"],"
"[\"RL_TELEMCELLPATH\",\"/tenants/phoenix/routes/steam/\"],"
"[\"RL_TELEMELFHOST\",\"elfphoenix-eventhub.servicebus.windows.net\"],"
"[\"RL_TELEMELFPATH\",\"/telemetry/messages\"],[\"RL_TELEMELFCS\",\"\"],"
"[\"RL_TELEMELFSKN\",\"SendTelemetry\"],[\"RL_TELEMELFKEYEXPIRYMIN\",\"5\"],"
"[\"RL_TELEMELFMAXBODYSIZEKB\",\"32\"],[\"RL_FORCE_CROSS_NETWORK_PLAY_ON\",\"[]\"],"
"[\"RL_FORCE_CROSS_NETWORK_PLAY_OFF\",\"[]\"],[\"RL_CLUSTERNAME\",\"aoelive_\"],"
"[\"RL_TITLEID\",\"24\"],[\"RL_OBSERVERCUSTOMDELAY\",\"180\"],[\"RL_OBSERVERMAX\",\"0\"],"
"[\"RL_USE_AUTOMATCH2\",\"1\"],[\"RL_AUTOMATCH2_TEAM_FACTION_TYPE\",\"1\"],"
"[\"RL_UPLOAD_TIMEOUT\",\"300000\"],[\"RL_CLOUDCACHETIME\",\"21600\"],"
"[\"RL_CLOUD_CREDENTIAL_PROVIDER\",\"AZURE\"],[\"RL_ITEM_LOADOUTS_MAX\",\"50\"],"
"[\"RL_CLAN_INVITE_EXPIRE_TIME_SEC\",\"43200\"],[\"RL_NUMBER_OF_GAMES_TO_RANK\",\"10\"],"
"[\"RL_NUMBER_OF_EVENT_GAMES_TO_RANK\",\"5\"],"
"[\"RL_WEB_ASSETS_ICONS_ROOT\",\"https://test-build-data.reliclink.com/\"],"
"[\"RL_GLOBAL_REWARD_CURRENCY\",\"\"],"
"[\"RL_SSO_URL\",\"https://sso.relic.com/en/steam?title=age2&?\"]";

// JSON-escape a name into b
static void jesc(BUF *b, const char *s) {
    for (const char *p = s; *p; p++) {
        char c = *p;
        if (c == '"' || c == '\\') { char q[2] = {'\\', c}; bput(b, q, 2); }
        else if ((unsigned char)c < 0x20) bs(b, " ");
        else bput(b, &c, 1);
    }
}

// ids are FNV1a64("aoe2lan:" + alias); the profile id is read with a SIGNED
// int64 reader (strtoll), so keep the top bit clear
typedef struct { DWORD64 profileId, statId; char platformUser[32]; } IDS;
static void mk_ids(const char *alias, IDS *o) {
    DWORD64 profileId = fnv1a64("aoe2lan:");
    { const char *p = alias; while (*p) { profileId ^= (unsigned char)*p++; profileId *= 0x100000001b3ULL; } }
    o->profileId = profileId & 0x7FFFFFFFFFFFFFFFULL;
    o->statId = 1000000 + (o->profileId % 900000000ULL);
    { DWORD64 pu = o->profileId % 76561198000000000ULL;
      char t[24]; int tl=0; if(!pu) t[tl++]='0';
      while (pu && tl<20) { t[tl++]=(char)('0'+(int)(pu%10)); pu/=10; }
      int ol=0; while (tl) o->platformUser[ol++]=t[--tl]; o->platformUser[ol]=0; }
}

static void emit_profileinfo(BUF *b, const char *alias, const IDS *s);

// accountInfo object (readers: LoginResult 0x140615b70 -> AccountInfo 0x140614060)
static void emit_accountinfo(BUF *b, const char *alias, const IDS *s) {
    bs(b, "{\"id\":");
    bnum(b, s->profileId);
    bs(b, ",\"accountName\":\"");
    jesc(b, alias); bs(b, "\",\"accountType\":3");
    bs(b, ",\"ssoID\":-1,\"ssoStatus\":0,\"country\":\"US\"");
    // spamAllowed is read by an INT reader (0x140611270: strtoll, valid 0..3,
    // out-of-range is logged and defaulted to 2). It is NOT the dedicated bool
    // reader (that one is 0x14039c730, used only for shouldUseClientSync), so
    // sending `false` here fails strtoll and aborts the whole AccountInfo parse.
    bs(b, ",\"currency\":\"eur\",\"spamAllowed\":2");
    // accountInfo.profiles is read as a vector of ProfileInfo (0x140619210).
    // It carried null through s20; the login service's "local profile" lookup
    // is the one thing the client still complains about, so fill it.
    bs(b, ",\"metaData\":\"{}\",\"profiles\":[");
    emit_profileinfo(b, alias, s);
    bs(b, "]}");
}

// one ProfileInfo object (reader 0x140620540)
static void emit_profileinfo(BUF *b, const char *alias, const IDS *s) {
    bs(b, "{\"entityVersion\":1,\"id\":");
    bnum(b, s->profileId);
    bs(b, ",\"name\":\"");
    jesc(b, alias); bs(b, "\",\"metaData\":\"{}\"");
    bs(b, ",\"alias\":\"");
    jesc(b, alias); bs(b, "\",\"sanitizedAlias\":\"");
    jesc(b, alias); bs(b, "\",\"clanName\":\"\"");
    bs(b, ",\"personalStatGroupID\":");
    bnum(b, s->statId);
    bs(b, ",\"xp\":0,\"level\":1,\"leaderboardRegionID\":2");
    bs(b, ",\"banInfo\":null,\"platformUserID\":\"");
    bs(b, s->platformUser); bs(b, "\",\"accountType\":3");
    bs(b, ",\"linkedPlatformAccounts\":[],\"presenceID\":0");
    bs(b, ",\"presenceLocalized\":\"\",\"presencePropertyInfo\":[]}");
}

static void build_login_response(BUF *b, const char *alias) {
    IDS ids; mk_ids(alias, &ids);
    DWORD64 profileId = ids.profileId, statId = ids.statId;
    const char *platformUser = ids.platformUser;
    for (int _i = 0; _i < 8; _i++) g_ProbeId[_i] = (unsigned char)((profileId >> (_i * 8)) & 0xFF);
    for (int _i = 0; _i < 8; _i++) g_ProbeStat[_i] = (unsigned char)((statId >> (_i * 8)) & 0xFF);
    { DWORD64 cid = 549000000ULL;
      for (int _i = 0; _i < 8; _i++) g_ProbeConn[_i] = (unsigned char)((cid >> (_i * 8)) & 0xFF); }
    DWORD64 now = unix_now();
    DWORD64 sess = 400000000 + (now % 1000000000ULL);

    bs(b, "{\"resultCode\":0,\"connectionToken\":\"");
    { // connectionToken: hex session token (opaque to the game)
      char t[24]; int tl=0; DWORD64 v=sess;
      if(!v)t[tl++]='0'; while (v && tl<20) { t[tl++]=(char)('0'+(int)(v%10)); v/=10; }
      int ol=0; while (tl && ol<23) g_LastToken[ol++] = t[--tl]; g_LastToken[ol]=0;
      { const char *q = g_LastToken; while (*q) { bput(b, q, 1); q++; } } }
    bs(b, "\",\"connectionID\":");
    bnum(b, 549000000ULL);
    bs(b, ",\"serverTime\":");
    bnum(b, now);
    // Types decoded from the client's own deserializer (LoginResult, 0x140615b70;
    // AccountInfo 0x140614060; ProfileInfo 0x140620540; relay endpoint 0x140615000):
    //   accountType is an ENUM READ AS INT64 (valid range 0..13, Steam = 3), not a string
    //   metaData is a std::string carrying JSON, not an object
    //   profile.presenceID is int64 (not a string)
    //   profile.presencePropertyInfo is an ARRAY (not an object)
    //   accountInfo.profiles is an array of {profileInfo,...} wrappers; null is accepted
    //   relayServer fields: region/regionLocalized/publicIP strings + 3 int32 ports
    //   accountInfo.ssoID is an INT64 too (writer 0x140614d50: `mov rdx,[rdi+0x40]`
    //   -> int writer; the live capture carried -1 there), not a string
    bs(b, ",\"accountInfo\":");
    emit_accountinfo(b, alias, &ids);
    bs(b, ",\"profiles\":[");
    emit_profileinfo(b, alias, &ids);
    bs(b, "]");
    bs(b, ",\"banLevel\":0,\"banSeconds\":0,\"banMessage\":\"\"");
    bs(b, ",\"clientSettings\":[");
    bs(b, LOGIN_DATA_JSON);
    bs(b, "],\"selectProfile\":{\"resultCode\":0,\"profile\":");
    // selectProfile (LoginResult+0x178, parser 0x140616ed0) = {resultCode, profile}.
    // The login service never POSTs /game/login/selectProfile and never raised a
    // usable default profile; this is the server-side way to say "this session
    // is on profile X" (the same field a real server uses on resume).
    emit_profileinfo(b, alias, &ids);
    bs(b, "},\"sslCertificates\":[]");
    bs(b, ",\"shouldUseClientSync\":false,\"relayServers\":[{");
    bs(b, "\"region\":\"LAN\",\"regionLocalized\":\"LAN\"");
    bs(b, ",\"publicIP\":\"127.0.0.1\"");
    bs(b, ",\"rawSocketPort\":27012,\"webSocketPort\":27112");
    bs(b, ",\"outOfBandSocketPort\":27212}]}");
}

// One WS frame = ONE rlink notification *value*. Two facts are proven in-game
// (s20 run 2, hook id 13 = the client's warn sink):
//   "null,"            parses   -> every value must be followed by a comma
//   "null" (no comma)  fails    -> that comma is mandatory, not optional
//   "0," / "[..]," / "{..}," fail -> so the value cannot be a bare number and
//                                    the container body is still wrong
// The client's reader (0x1407a7620) consumes result / m_type / m_profileID and
// then hands the cursor to a registered-payload parser (0x1407a7070). Rather
// than guess again, the pump walks templates and every accepted value shows up
// as the *absence* of "failed to parse notification messages [..]" — so one
// sitting maps the grammar by prefix. %p=profileID %r=resultCode
// %A=accountInfo %P=defaultProfileInfo %I={resultCode,accountInfo,defaultProfileInfo}
// shortcut: prefix sweep; collapse to the confirmed template once dispatch hits.
typedef struct { const char *label; const char *tpl; int trail; } PUSHCAND;
#define RC_PROBE 99
static const PUSHCAND g_Cands[] = {
    {"empty-arr",   "[]",                                                    1},
    {"empty-obj",   "{}",                                                    1},
    {"arr-r",       "[0]",                                                   1},
    {"arr-rt",      "[0,\"AccountLoginEvent\"]",                             1},
    {"arr-rtp",     "[0,\"AccountLoginEvent\",%p]",                          1},
    {"obj-r",       "{\"result\":0}",                                        1},
    {"obj-rt",      "{\"result\":0,\"m_type\":\"AccountLoginEvent\"}",      1},
    {"obj-rtp",     "{\"result\":0,\"m_type\":\"AccountLoginEvent\",\"m_profileID\":%p}", 1},
    {"arr-emptyobj","[0,\"AccountLoginEvent\",%p,{}]",                       1},
    {"arr-list1",   "[0,\"AccountLoginEvent\",%p,[{}]]",                     1},
    {"obj-rc",      "{\"result\":0,\"m_type\":\"AccountLoginEvent\",\"m_profileID\":%p,\"resultCode\":%r}", 1},
    {"arr-rc",      "[0,\"AccountLoginEvent\",%p,{\"resultCode\":%r}]",      1},
    {"obj-acct",    "{\"result\":0,\"m_type\":\"AccountLoginEvent\",\"m_profileID\":%p,\"accountInfo\":%A}", 1},
    {"arr-prof",    "[0,\"AccountLoginEvent\",%p,{\"defaultProfileInfo\":%P}]", 1},
    {"arr-info",    "[0,\"AccountLoginEvent\",%p,%I]",                       1},
    {"nested-obj",  "[{\"result\":0,\"m_type\":\"AccountLoginEvent\",\"m_profileID\":%p}]", 1},
};
#define N_CANDS ((int)(sizeof(g_Cands)/sizeof(g_Cands[0])))
#define PUSH_INTERVAL_MS 3000

static void emit_rc(char *rcb, int rc) {
    int rl = 0, v = rc;
    if (!v) rcb[rl++] = '0';
    while (v) { rcb[rl++] = (char)('0' + v % 10); v /= 10; }
    for (int i = 0; i < rl / 2; i++) { char t = rcb[i]; rcb[i] = rcb[rl-1-i]; rcb[rl-1-i] = t; }
    rcb[rl] = 0;
}

// Info members without the enclosing braces (shared with the login reply).
static void emit_info_body(BUF *b, const char *alias, const IDS *ids, const char *rcb) {
    bs(b, "\"resultCode\":"); bs(b, rcb);
    bs(b, ",\"accountInfo\":");    emit_accountinfo(b, alias, ids);
    bs(b, ",\"defaultProfileInfo\":"); emit_profileinfo(b, alias, ids);
}

static void build_cand(BUF *b, const char *alias, const PUSHCAND *c) {
    IDS ids; mk_ids(alias, &ids);
    char rcb[6]; emit_rc(rcb, RC_PROBE);
    for (const char *t = c->tpl; *t; t++) {
        if (*t != '%') { char ch[2]; ch[0] = *t; ch[1] = 0; bs(b, ch); continue; }
        switch (*++t) {
        case 'p': bnum(b, ids.profileId); break;
        case 'r': bs(b, rcb); break;
        case 'A': emit_accountinfo(b, alias, &ids); break;
        case 'P': emit_profileinfo(b, alias, &ids); break;
        case 'I': bs(b, "{"); emit_info_body(b, alias, &ids, rcb); bs(b, "}"); break;
        default:  bs(b, "%"); break;
        }
    }
    if (c->trail) bs(b, ",");
}

// ---------------------------------------------------------------- TLS server
#define TLS_MAX_PLAIN 16384
#define REQ_MAX (64*1024)   // per-connection request buffer (heap)

typedef struct {
    SOCKET s;
    CredHandle hCred;
    CtxtHandle hCtx;
    SecPkgContext_StreamSizes sizes;
    int handshook;
    unsigned char in[TLS_MAX_PLAIN * 2];
    int inLen;
} TLSSES;

static PCCERT_CONTEXT g_ServerCert;
static CredHandle g_hCred;
static int g_CredOk;

// ---------------------------------------------------------------- cert minting
// Silent CSP-backed self-sign (session 13): CRYPT_NEWKEYSET in a unique
// container + CryptGenKey(AT_SIGNATURE) + CertCreateSelfSignCertificate.
// The CSP path (not CNG) is what CertCreateSelfSignCertificate + SChannel
// consume without friction: CACPK resolves, ACH succeeds, and no consent UI
// appears (CRYPT_SILENT throughout; the session-12 UI pop came from the
// default-container path, avoided here via a unique per-launch container).
// The public key comes from the CSP, so no hand-built DER is needed.

typedef LONG (WINAPI *PfnNOSP)(void**, LPCWSTR, DWORD);
typedef LONG (WINAPI *PfnNCPK)(void*, void**, LPCWSTR, LPCWSTR, DWORD, DWORD);
typedef LONG (WINAPI *PfnNSP)(void*, LPCWSTR, void*, DWORD, DWORD);
typedef LONG (WINAPI *PfnNFK)(void*, DWORD);
typedef LONG (WINAPI *PfnNDFK)(void*, DWORD);
typedef LONG (WINAPI *PfnNEK)(void*, void*, LPCWSTR, void*, BYTE*, DWORD, DWORD*, DWORD);
typedef LONG (WINAPI *PfnNSH)(void*, void*, const BYTE*, DWORD, BYTE*, DWORD, DWORD*, DWORD);
typedef void *(WINAPI *PfnCCC)(DWORD, const BYTE*, DWORD);
typedef BOOL (WINAPI *PfnCSCP)(void*, DWORD, DWORD, const void*);
typedef BOOL (WINAPI *PfnCACPK)(void*, DWORD, void*, void**, DWORD*, DWORD*);
typedef BOOL (WINAPI *PfnCCH)(unsigned long long, DWORD, unsigned long long, DWORD, unsigned long long*);
typedef BOOL (WINAPI *PfnCHD)(unsigned long long, const BYTE*, DWORD, DWORD);
typedef BOOL (WINAPI *PfnCGHP)(unsigned long long, DWORD, BYTE*, DWORD*, DWORD);
typedef BOOL (WINAPI *PfnCDH)(unsigned long long);
static PfnNOSP pNOSP;   // NCryptOpenStorageProvider
static PfnNCPK pNCPK;   // NCryptCreatePersistedKey (no persist flag = ephemeral)
static PfnNSP  pNSP;    // NCryptSetProperty
static PfnNFK  pNFK;    // NCryptFinalizeKey
static PfnNDFK pNDFK;   // NCryptDeleteKey
static PfnNEK  pNEK;    // NCryptExportKey
static PfnNSH  pNSH;    // NCryptSignHash
static PfnCCC  pCCC;    // CertCreateCertificateContext
static PfnCSCP pCSCP;   // CertSetCertificateContextProperty
static PfnCACPK pCACPK; // CryptAcquireCertificatePrivateKey
static PfnCCH  pCCH;    // CryptCreateHash
static PfnCHD  pCHD;    // CryptHashData
static PfnCGHP pCGHP;   // CryptGetHashParam
static PfnCDH  pCDH;    // CryptDestroyHash
static void *g_NcProv;  // MS_KEY_STORAGE_PROVIDER handle
static void *g_NcKey;   // ephemeral RSA key handle

// ---- tiny DER builder (append-only, fixed buffers) ----
typedef struct { unsigned char *p; size_t n; } DER;
static void dput(DER *d, unsigned char b) { d->p[d->n++] = b; }
static void dbytes(DER *d, const void *b, size_t n) { memcpy(d->p + d->n, b, n); d->n += n; }
static void dhdr(DER *d, unsigned char tag, size_t len) {
    if (len < 128) { dput(d, tag); dput(d, (unsigned char)len); }
    else if (len < 256) { dput(d, tag); dput(d, 0x81); dput(d, (unsigned char)len); }
    else { dput(d, tag); dput(d, 0x82); dput(d, (unsigned char)(len>>8)); dput(d, (unsigned char)len); }
}
static void dint(DER *d, const unsigned char *v, size_t n) {
    while (n > 1 && v[0] == 0) { v++; n--; }
    size_t lead = (v[0] & 0x80) ? 1 : 0;
    dhdr(d, 0x02, n + lead);
    if (lead) dput(d, 0);
    dbytes(d, v, n);
}
// wrap: tag hdr + copy of a fully built body
static void dwrap(DER *d, unsigned char tag, const unsigned char *body, size_t n) {
    dhdr(d, tag, n);
    dbytes(d, body, n);
}
// AlgorithmIdentifier: SEQ { OID, NULL }
static void dalg(DER *d, const unsigned char *oid, size_t on) {
    unsigned char t[32]; DER x = {t, 0};
    dhdr(&x, 0x06, on); dbytes(&x, oid, on);
    dput(&x, 0x05); dput(&x, 0x00);
    dwrap(d, 0x30, t, x.n);
}
static void dtime(DER *d, const SYSTEMTIME *st) {
    char b[13];
    int y = st->wYear % 100;
    b[0]=(char)('0'+y/10); b[1]=(char)('0'+y%10);
    b[2]=(char)('0'+st->wMonth/10); b[3]=(char)('0'+st->wMonth%10);
    b[4]=(char)('0'+st->wDay/10); b[5]=(char)('0'+st->wDay%10);
    b[6]=(char)('0'+st->wHour/10); b[7]=(char)('0'+st->wHour%10);
    b[8]=(char)('0'+st->wMinute/10); b[9]=(char)('0'+st->wMinute%10);
    b[10]=(char)('0'+st->wSecond/10); b[11]=(char)('0'+st->wSecond%10);
    b[12]='Z';
    dhdr(d, 0x17, 13); dbytes(d, b, 13);
}
// RDN: SET { SEQ { OID, UTF8String } }
static void drdn(DER *d, const unsigned char *oid, size_t on, const char *val) {
    unsigned char atv[300]; DER a = {atv, 0};
    size_t vn = strlen_f(val);
    dhdr(&a, 0x06, on); dbytes(&a, oid, on);
    dhdr(&a, 0x0c, vn); dbytes(&a, val, vn);
    unsigned char seq[320]; DER s = {seq, 0};
    dwrap(&s, 0x30, atv, a.n);
    dwrap(d, 0x31, seq, s.n);
}
static void dname(DER *d, const char *cn, const char *o) {
    unsigned char rdns[640]; DER r = {rdns, 0};
    static const unsigned char OID_CN[] = {0x55,0x04,0x03};
    static const unsigned char OID_O[]  = {0x55,0x04,0x0a};
    drdn(&r, OID_CN, 3, cn);
    drdn(&r, OID_O, 3, o);
    d->n = 0;   // reusable: reset before writing
    dwrap(d, 0x30, rdns, r.n);
}

// SHA-256 via the legacy CAPI hash (verify-context + silent: no container,
// no key, no UI)
static int sha256(unsigned long long hProv, const unsigned char *data, size_t n,
                  unsigned char out[32]) {
    unsigned long long hHash = 0;
    DWORD hl = 32;
    if (!pCCH(hProv, 0x800c /*CALG_SHA_256*/, 0, 0, &hHash)) return 0;
    if (!pCHD(hHash, data, (DWORD)n, 0)) { pCDH(hHash); return 0; }
    if (!pCGHP(hHash, 2 /*HP_HASHVAL*/, out, &hl, 0)) { pCDH(hHash); return 0; }
    pCDH(hHash);
    return 1;
}

typedef struct {
    unsigned long Magic;        // BCRYPT_RSAKEY_MAGIC "RSA1"
    unsigned long BitLength;
    unsigned long cbPublicExp;
    unsigned long cbModulus;
    unsigned long cbPrime1;
    unsigned long cbPrime2;
} RSAKEYBLOB_HDR;   // 24 bytes exactly (BCRYPT_RSAKEY_BLOB)

static HCRYPTPROV g_CspProv;   // CSP handle for the self-signed key (kept open)
static HCRYPTKEY  g_CspKey;
static char       g_CspCont[48];
static void      *g_hRootStore;  // CURRENT USER Root store with our cert (kept open)

// ---- X.509 v3 extensions, ageLANServer shape (session 14: the exact
// anchor this game build accepts — KU critical DS+KE+KC, EKU server+client
// auth, BC critical CA:TRUE pathlen:0, 3-entry SAN, SHA256). The DER for
// SAN comes from CryptEncodeObjectEx; the small ones are hand-encoded.
// The served cert is byte-for-byte comparable to the ageLANServer anchor
// in the local Root stores (certext.exe -F-fullshape proved the rendering).
static const WCHAR g_HostW[] = L"pb-live-release6-api.worldsedgelink.com";
static const WCHAR g_HostW2[] = L"*.worldsedgelink.com";
static const WCHAR g_HostW3[] = L"aoe-api.reliclink.com";

static int mint_cert(void) {
    static const char contPre[] = "aoe2lan-";
    CERT_NAME_BLOB subj = {0};
    static char dnStr[] = "CN=pb-live-release6-api.worldsedgelink.com, O=AoE2LAN";
    DWORD dnsz = 0;
    unsigned char *dnb = 0;
    CRYPT_KEY_PROV_INFO kpi;
    SYSTEMTIME et;
    static wchar_t wcont[48];
    (void)dnb;

    if (!pCAC || !pCGK || !pCertCSSC || !pCertCTNW || !pCACPK || !pCCC || !pCEOE) { logn("cert: fns missing"); return 0; }
    logn("cert: fns ok");
    // unique per-launch container so no existing key/UI is ever touched
    { DWORD t = GetTickCount(); int i;
      for (i = 0; contPre[i]; i++) g_CspCont[i] = contPre[i];
      { int n = i;
        for (i = 0; i < 8; i++) { g_CspCont[n+i] = (char)('a' + (t & 15)); t >>= 4; }
        g_CspCont[n+8] = 0; } }
    if (!pCAC(&g_CspProv, g_CspCont, NULL, PROV_RSA_AES, CRYPT_NEWKEYSET | CRYPT_SILENT)) {
        // container may pre-exist from a crashed run: acquire + destroy key, retry
        if (!pCAC(&g_CspProv, g_CspCont, NULL, PROV_RSA_AES, CRYPT_SILENT)) {
            logn("cert: csp acquire failed"); return 0; }
    }
    if (!pCGK(g_CspProv, 2 /*AT_SIGNATURE*/, 2048 << 16 | CRYPT_EXPORTABLE, &g_CspKey)) {
        logn("cert: CryptGenKey failed"); return 0; }
    logn("cert: CSP RSA 2048 key ready (silent)");
    if (!pCertCTNW(X509_ASN_ENCODING, L"CN=pb-live-release6-api.worldsedgelink.com, O=AoE2LAN",
                   CERT_X500_NAME_STR, NULL, NULL, &dnsz, NULL) || !dnsz) {
        logn("cert: name size failed"); return 0; }
    dnb = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, dnsz);
    if (!dnb) return 0;
    if (!pCertCTNW(X509_ASN_ENCODING, L"CN=pb-live-release6-api.worldsedgelink.com, O=AoE2LAN",
                   CERT_X500_NAME_STR, NULL, dnb, &dnsz, NULL)) {
        logn("cert: name encode failed"); return 0; }
    subj.cbData = dnsz; subj.pbData = dnb;
    { int i; for (i = 0; g_CspCont[i]; i++) wcont[i] = g_CspCont[i]; wcont[i] = 0; }
    memset(&kpi, 0, sizeof(kpi));
    kpi.pwszContainerName = wcont;
    kpi.dwProvType = PROV_RSA_AES;
    kpi.dwKeySpec = 2; /*AT_SIGNATURE*/
    GetSystemTime(&et); et.wYear += 9;
    // SAN extension: pre-encoded via CryptEncodeObjectEx, SHA256 signature
    // (CSSC defaults to SHA1). Blob freed after CSSC copies it in.
    { CRYPT_DATA_BLOB sanDer = {0, 0};
      CERT_ALT_NAME_ENTRY ane[3]; CERT_ALT_NAME_INFO ani2;
      CERT_EXTENSION ext[4]; CERT_EXTENSIONS exts;
      CRYPT_ALGORITHM_IDENTIFIER said;
      static const unsigned char KU_DER[] = {0x03,0x02,0x02,0xA4};
      static const unsigned char EKU_DER[] = {0x30,0x14,
          0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01,
          0x06,0x08,0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x02};
      static const unsigned char BC_DER[] = {0x30,0x06,0x01,0x01,0xFF,0x02,0x01,0x00};
      if (!pCEOE) { logn("cert: SAN encoder missing"); return 0; }
      memset(&ane, 0, sizeof(ane));
      memset(ane, 0, sizeof(ane));
      ane[0].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
      ane[0].pwszDNSName = (LPWSTR)g_HostW;
      ane[1].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
      ane[1].pwszDNSName = (LPWSTR)g_HostW2;
      ane[2].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
      ane[2].pwszDNSName = (LPWSTR)g_HostW3;
      ani2.cAltEntry = 3; ani2.rgAltEntry = ane;
      if (!pCEOE(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &ani2,
                 CRYPT_ENCODE_ALLOC_FLAG, NULL, &sanDer.pbData, &sanDer.cbData)) {
          logn("cert: SAN encode failed"); return 0; }
      memset(ext, 0, sizeof(ext));
      ext[0].pszObjId = szOID_KEY_USAGE;           ext[0].fCritical = TRUE;
      ext[0].Value.cbData = sizeof(KU_DER);  ext[0].Value.pbData = KU_DER;
      ext[1].pszObjId = szOID_ENHANCED_KEY_USAGE; ext[1].fCritical = FALSE;
      ext[1].Value.cbData = sizeof(EKU_DER); ext[1].Value.pbData = EKU_DER;
      ext[2].pszObjId = szOID_BASIC_CONSTRAINTS2; ext[2].fCritical = TRUE;
      ext[2].Value.cbData = sizeof(BC_DER);  ext[2].Value.pbData = BC_DER;
      ext[3].pszObjId = szOID_SUBJECT_ALT_NAME2; ext[3].fCritical = FALSE;
      ext[3].Value = sanDer;
      exts.cExtension = 4; exts.rgExtension = ext;
      memset(&said, 0, sizeof(said));
      said.pszObjId = szOID_RSA_SHA256RSA;
      g_ServerCert = pCertCSSC((ULONG_PTR)g_CspProv, &subj, 0, &kpi,
                               &said, NULL, &et, &exts);
      LocalFree(sanDer.pbData); }
    HeapFree(GetProcessHeap(), 0, dnb);
    if (!g_ServerCert) { char e2[24]; int k=0; unsigned ugle=(unsigned)GetLastError();
        { int s; for (s=7;s>=0;s--) { unsigned d=(ugle>>((unsigned)s*4u))&15u;
          e2[k++]=(char)(d<10?('0'+d):('a'+d-10)); } }
        e2[k]=0; { char b[96]; int i=0; const char *m="cert: selfsign failed gle=0x";
        while(*m) b[i++]=*m++; for (int j=0;e2[j]&&i<90;j++) b[i++]=e2[j]; b[i]=0; log_line(b); } return 0; }
    // re-acquire the provider WITHOUT NEWKEYSET so the key link resolves
    // (the CREATE handle is a write session; CACPK/SChannel read from it)
    pCRC(g_CspProv); g_CspProv = 0;
    if (!pCAC(&g_CspProv, g_CspCont, NULL, PROV_RSA_AES, CRYPT_SILENT)) {
        logn("cert: csp re-acquire failed"); return 0; }
    { // CACPK check + DER dump + done (self-sign path)
      void *retKey = 0; DWORD ks = 0; DWORD spec = 0;
      BOOL okp = pCACPK((void*)g_ServerCert, 0x40 /*CRYPT_ACQUIRE_SILENT_FLAG*/, 0, &retKey, &ks, &spec);
      { char b[64]; int i=0; const char *m="cert: CACPK ";
        DWORD le = okp ? 0 : GetLastError();
        while (*m) b[i++]=*m++; b[i++]= okp ? 'o' : 'k';
        b[i++]=' '; b[i++]='k'; b[i++]='s'; b[i++]='=';
        { char t[8]; int tl=0; DWORD v=ks; if(!v)t[tl++]='0';
          while (v && tl<7) { t[tl++]=(char)('0'+(v%10)); v/=10; }
          while (tl) b[i++]=t[--tl]; }
        b[i++]=' '; b[i++]='l'; b[i++]='e'; b[i++]='='; b[i++]='0'; b[i++]='x';
        for (int k=7;k>=0;k--) { int d2=(int)((le>>(k*4))&15); b[i++]=(char)(d2<10?'0'+d2:'a'+d2-10); }
        b[i]=0; logn(b); }
      if (!okp) { logn("cert: key not retrievable"); return 0; }
      { HANDLE hf = CreateFileW(L"cert.der", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            DWORD w = 0; WriteFile(hf, g_ServerCert->pbCertEncoded, g_ServerCert->cbCertEncoded, &w, NULL); CloseHandle(hf); } }
      { char b[64]; int i=0; const char *m="cert: selfsigned der=";
        while (*m) b[i++]=*m++;
        { char t[8]; int tl=0; DWORD v=g_ServerCert->cbCertEncoded; if(!v)t[tl++]='0';
          while (v && tl<7) { t[tl++]=(char)('0'+(v%10)); v/=10; }
          while (tl) b[i++]=t[--tl]; }
        b[i]=0; logn(b); }
      { // ageLANServer-equivalent trust registration: add our cert to the
        // CURRENT USER Root store (schannel's chain engine re-opens the
        // real Windows stores at validation time; the enum injection alone
        // never reaches it). Deferred to first use: the registry add can
        // block on consent UI on some machines, so it runs OUTSIDE the
        // boot path — see srv_first_handshake().
        logn("cert: user-Root deferred to first connection"); }
      return 1;
    }
}

void *loginsrv_inject_cert(void) { return (void*)g_ServerCert; }

static int acquire_cred(void) {
    SCHANNEL_CRED sc;
    SECURITY_STATUS st;
    PCCERT_CONTEXT certs[1];
    memset(&sc, 0, sizeof(sc));
    { // probe: anonymous acquire to isolate package vs cert
      SCHANNEL_CRED p0;
      memset(&p0, 0, sizeof(p0));
      p0.dwVersion = SCHANNEL_CRED_VERSION;
      p0.grbitEnabledProtocols = 0x00000400;  /* SP_PROT_TLS1_2_SERVER */
      st = pACH(NULL, UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &p0, NULL, NULL, &g_hCred, NULL);
      { char b[96]; int i=0; const char *m="probe anon cred st=0x";
        while (*m) b[i++]=*m++;
        for (int k=7;k>=0;k--) { int d=(int)((st>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); }
        b[i]=0; logn(b); }
      if (st == SEC_E_OK) pDSC(&g_hCred);
      logn(UNISP_NAME_W[0] == 'M' ? "probe pkg name starts M (wide ok)" : "probe pkg name NOT wide");
    }
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = 0x00000400;  /* SP_PROT_TLS1_2_SERVER */
    certs[0] = g_ServerCert;
    sc.cCreds = 1;
    sc.paCred = certs;
    sc.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
    st = pACH(NULL, UNISP_NAME_W, SECPKG_CRED_INBOUND, NULL, &sc, NULL, NULL, &g_hCred, NULL);
    if (st != SEC_E_OK) {
        char b[96]; int i=0; const char *m="schannel: AcquireCredentials failed st=0x";
        while (*m) b[i++]=*m++;
        for (int k=7;k>=0;k--) { int d=(int)((st>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); }
        b[i]=0; logn(b);
        return 0;
    }
    g_CredOk = 1;
    return 1;
}

static int tls_recv_more(TLSSES *t) {
    int n = p_recv(t->s, (char*)(t->in + t->inLen), (int)(sizeof(t->in) - t->inLen), 0);
    if (n <= 0) return 0;
    t->inLen += n;
    return 1;
}

static int tls_send_all(SOCKET s, const char *p, int n) {
    int off = 0;
    while (off < n) {
        int w = p_send(s, p + off, n - off, 0);
        if (w <= 0) return 0;
        off += w;
    }
    return 1;
}

static int tls_handshake(TLSSES *t) {
    SecBuffer inB[2], outB[2];
    SecBufferDesc inD, outD;
    SECURITY_STATUS st;
    int first = 1;
    ULONG attr = 0; TimeStamp ts; ts.QuadPart = 0;
    ULONG ctxReq = ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                   ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                   ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM;
    for (;;) {
        if (t->inLen == 0 && !tls_recv_more(t)) return 0;
        inB[0].BufferType = SECBUFFER_TOKEN; inB[0].cbBuffer = (ULONG)t->inLen; inB[0].pvBuffer = t->in;
        inB[1].BufferType = SECBUFFER_EMPTY;  inB[1].cbBuffer = 0;               inB[1].pvBuffer = NULL;
        inD.ulVersion = SECBUFFER_VERSION; inD.cBuffers = 2; inD.pBuffers = inB;
        outB[0].BufferType = SECBUFFER_TOKEN; outB[0].cbBuffer = 0; outB[0].pvBuffer = NULL;
        outB[1].BufferType = SECBUFFER_ALERT; outB[1].cbBuffer = 0; outB[1].pvBuffer = NULL;
        outD.ulVersion = SECBUFFER_VERSION; outD.cBuffers = 2; outD.pBuffers = outB;
        st = pASC(&g_hCred, first ? NULL : &t->hCtx, &inD, ctxReq, SECURITY_NETWORK_DREP,
                  &t->hCtx, &outD, &attr, &ts);
        first = 0;
        if (st == SEC_E_OK || st == SEC_I_CONTINUE_NEEDED) {
            if (outB[0].cbBuffer && outB[0].pvBuffer) {
                if (!tls_send_all(t->s, (char*)outB[0].pvBuffer, (int)outB[0].cbBuffer)) return 0;
                LocalFree(outB[0].pvBuffer);
            }
            // consume what the provider consumed; keep EXTRA
            if (inB[1].BufferType == SECBUFFER_EXTRA && inB[1].cbBuffer) {
                memmove_f((char*)t->in, (char*)t->in + (t->inLen - (int)inB[1].cbBuffer), inB[1].cbBuffer);
                t->inLen = (int)inB[1].cbBuffer;
            } else {
                t->inLen = 0;
            }
            if (st == SEC_E_OK) {
                t->handshook = 1;
                pQCA(&t->hCtx, SECPKG_ATTR_STREAM_SIZES, &t->sizes);
                logn("TLS: handshake complete (server side)");
                return 1;
            }
            continue;
        }
        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            if (!tls_recv_more(t)) return 0;
            continue;
        }
        { char b[96]; int i=0; const char *m="TLS: handshake failed st=0x";
          while (*m) b[i++]=*m++;
          for (int k=7;k>=0;k--) { int d=(int)((st>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); }
          b[i]=0; logn(b); }
        return 0;
    }
}

// decrypt one record batch into out; returns plaintext length, -1 = closed, -2 = need more
static int tls_decrypt(TLSSES *t, unsigned char *out, int outCap) {
    SecBuffer bufs[4];
    SecBufferDesc d;
    SECURITY_STATUS st;
    if (t->inLen == 0) {
        int r = p_recv(t->s, (char*)t->in, (int)sizeof(t->in), 0);
        if (r <= 0) return -1;
        t->inLen = r;
    }
    bufs[0].BufferType = SECBUFFER_DATA; bufs[0].cbBuffer = (ULONG)t->inLen; bufs[0].pvBuffer = t->in;
    bufs[1].BufferType = SECBUFFER_EMPTY; bufs[1].cbBuffer = 0; bufs[1].pvBuffer = NULL;
    bufs[2].BufferType = SECBUFFER_EMPTY; bufs[2].cbBuffer = 0; bufs[2].pvBuffer = NULL;
    bufs[3].BufferType = SECBUFFER_EMPTY; bufs[3].cbBuffer = 0; bufs[3].pvBuffer = NULL;
    d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 4; d.pBuffers = bufs;
    st = pDM(&t->hCtx, &d, 0, NULL);   // (ctx, msg, seqNo, pfQOP)
    if (st == SEC_E_OK) {
        int plen = 0;
        if (bufs[1].BufferType == SECBUFFER_DATA && bufs[1].cbBuffer) {
            int n = (int)bufs[1].cbBuffer;
            if (n > outCap) n = outCap;
            memcpy(out, bufs[1].pvBuffer, (size_t)n);
            plen = n;
        }
        // consume; keep EXTRA for the next call
        if (bufs[3].BufferType == SECBUFFER_EXTRA && bufs[3].cbBuffer) {
            memmove_f((char*)t->in, (char*)t->in + (t->inLen - (int)bufs[3].cbBuffer), bufs[3].cbBuffer);
            t->inLen = (int)bufs[3].cbBuffer;
        } else {
            t->inLen = 0;
        }
        return plen;
    }
    if (st == SEC_E_INCOMPLETE_MESSAGE) {
        int r = p_recv(t->s, (char*)(t->in + t->inLen), (int)(sizeof(t->in) - t->inLen), 0);
        if (r <= 0) return -1;
        t->inLen += r;
        return -2;
    }
    if (st == SEC_E_CONTEXT_EXPIRED || st == SEC_E_OK + 1 /*never*/) return -1;
    { char b[96]; int i=0; const char *m="TLS: decrypt st=0x";
      while (*m) b[i++]=*m++;
      for (int k=7;k>=0;k--) { int d=(int)((st>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); }
      b[i]=0; logn(b); }
    return -1;
}

static int tls_encrypt_send(TLSSES *t, const char *msg, int len) {
    // canonical SChannel stream pattern (MSDN sample): ONE contiguous block
    // [STREAM_HEADER | DATA | STREAM_TRAILER], encrypt in place, send whole.
    __declspec(thread) static unsigned char rec[TLS_MAX_PLAIN + 256];  // one thread per connection
    SecBuffer bufs[4];
    SecBufferDesc d;
    SECURITY_STATUS st;
    int n0, n1, n2;
    if (len > TLS_MAX_PLAIN) len = TLS_MAX_PLAIN;
    if (len <= 0) return 1;
    n0 = (int)t->sizes.cbHeader;
    n1 = len;
    n2 = (int)t->sizes.cbTrailer;
    if (n0 + n1 + n2 > (int)sizeof(rec)) { logn("TLS: record too big"); return 0; }
    memcpy(rec + n0, msg, (size_t)n1);              // plaintext into DATA slot
    bufs[0].BufferType = SECBUFFER_STREAM_HEADER; bufs[0].cbBuffer = (ULONG)n0; bufs[0].pvBuffer = rec;
    bufs[1].BufferType = SECBUFFER_DATA;          bufs[1].cbBuffer = (ULONG)n1; bufs[1].pvBuffer = rec + n0;
    bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;bufs[2].cbBuffer = (ULONG)n2; bufs[2].pvBuffer = rec + n0 + n1;
    bufs[3].BufferType = SECBUFFER_EMPTY;         bufs[3].cbBuffer = 0; bufs[3].pvBuffer = NULL;
    d.ulVersion = SECBUFFER_VERSION; d.cBuffers = 4; d.pBuffers = bufs;
    __try {
        st = pEM(&t->hCtx, 0, &d, 0);   // (ctx, fQOP, msg, seqNo)
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        logn("TLS ENC: pEM faulted (AV)");
        return 0;
    }
    if (st != SEC_E_OK) {
        { char b[64]; int i=0; const char *m="TLS: encrypt failed st=0x";
          while (*m) b[i++]=*m++;
          for (int k=7;k>=0;k--) { int d2=(int)((st>>(k*4))&15); b[i++]=(char)(d2<10?'0'+d2:'a'+d2-10); }
          b[i]=0; logn(b); }
        return 0;
    }
    // after the call the DATA slot holds the ciphertext; sizes unchanged for
    // stream buffers � send the whole contiguous record
    if (!tls_send_all(t->s, (char*)rec, n0 + n1 + n2)) return 0;
    return 1;
}

// ---------------------------------------------------------------- HTTP
static void http_respond(TLSSES *t, const char *body) {
    char head[512];   // per call: one thread per connection (session 30: was static)
    int blen = (int)strlen_f(body);
    int hl = 0;
    logn("HTTP RESP: building head");
    const char *m =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ";
    while (*m) head[hl++] = *m++;
    { char c[12]; int cl=0; DWORD v=(DWORD)blen; if(!v)c[cl++]='0';
      while (v && cl<10) { c[cl++]=(char)('0'+(v%10)); v/=10; }
      while (cl) head[hl++]=c[--cl]; }
    m = "\r\nSet-Cookie: reliclink=7355608; Path=/\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n";
    while (*m) head[hl++] = *m++;
    if (hl + blen > TLS_MAX_PLAIN - 256) {
        // large body: send head, then body in TLS-sized chunks
        tls_encrypt_send(t, head, hl);
        int off = 0;
        while (off < blen) {
            int n = blen - off;
            if (n > TLS_MAX_PLAIN - 256) n = TLS_MAX_PLAIN - 256;
            tls_encrypt_send(t, body + off, n);
            off += n;
        }
        return;
    }
    if (hl + blen < (int)sizeof(head)) {
        memcpy(head + hl, body, (size_t)blen);
        tls_encrypt_send(t, head, hl + blen);
    } else {
        tls_encrypt_send(t, head, hl);
        { int off = 0;
          while (off < blen) {
              int n = blen - off;
              if (n > TLS_MAX_PLAIN - 256) n = TLS_MAX_PLAIN - 256;
              tls_encrypt_send(t, body + off, n);
              off += n;
          } }
    }
    logn("HTTP RESP: sent");
}

static void log_req(const char *line) {
    char b[384]; int i = 0;
    const char *m = "HTTP REQ ";
    while (*m && i < 360) b[i++] = *m++;
    while (*line && i < 370) b[i++] = *line++;
    b[i] = 0;
    logn(b);
}

static void log_body_head(const char *body, int len) {
    char b[384]; int i = 0;
    const char *m = "HTTP BODY ";
    while (*m && i < 20) b[i++] = *m++;
    for (int k = 0; k < len && k < 300 && i < 370; k++) {
        char c = body[k];
        b[i++] = (c == '\n' || c == '\r') ? ' ' : c;
    }
    b[i] = 0;
    logn(b);
}

static void log_resp_head(const char *body, int len) {
    // response side: what the game actually received (session 15 — the
    // request side was fully visible, the answer side was dark)
    char b[384]; int i = 0;
    const char *m = "HTTP RESP BODY ";
    while (*m && i < 20) b[i++] = *m++;
    for (int k = 0; k < len && k < 300 && i < 370; k++) {
        char c = body[k];
        b[i++] = (c == '\n' || c == '\r') ? ' ' : c;
    }
    b[i] = 0;
    logn(b);
}

// ---------------------------------------------------------------- mem probe
// The login deserializer is encrypted on disk (Arxan) so it cannot be hooked.
// Instead: after we serve a login response, walk the game's private memory for
// the connectionToken we just minted. The client stores it as a std::string at
// LoginResult+0 (SSO buffer, inline), so a hit IS the parse target. Dumping a
// window around it shows exactly how far the parse got and which fields landed.
static char g_LastToken2[24];
static volatile LONG g_ProbeArmed;

static void log_hexdump(const char *tag, const unsigned char *base, int n) {
    char line[160];
    for (int off = 0; off < n; off += 32) {
        int i = 0;
        const char *m = tag;
        while (*m && i < 24) line[i++] = *m++;
        {   /* offset */
            char t[8]; int tl = 0; unsigned v = (unsigned)off;
            if (!v) t[tl++] = '0';
            while (v) { t[tl++] = (char)('0' + (v & 15)); v >>= 4; }
            while (tl) { unsigned d = (unsigned)(t[--tl] - '0'); line[i++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); }
        }
        line[i++] = ':';
        line[i++] = ' ';
        for (int k = 0; k < 32 && off + k < n; k++) {
            unsigned b = base[off + k];
            line[i++] = "0123456789abcdef"[(b >> 4) & 15];
            line[i++] = "0123456789abcdef"[b & 15];
            line[i++] = ' ';
        }
        line[i++] = '|';
        for (int k = 0; k < 32 && off + k < n; k++) {
            unsigned char c = base[off + k];
            line[i++] = (c >= 32 && c < 127) ? (char)c : '.';
        }
        line[i++] = '|'; line[i] = 0;
        logn(line);
    }
}

static int rpm(void *dst, const void *src, size_t n) {
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), src, dst, n, &got)) return 0;
    return got == n;
}

/* Scan our own private committed memory for a byte needle.
   ReadProcessMemory is used for every access: pages can be freed between the
   VirtualQuery and the read, and a raw deref there would kill the game. */
static int mem_probe(const char *label, const unsigned char *needle, size_t nl) {
    if (nl < 4) return 0;
    SYSTEM_INFO si; GetSystemInfo(&si);
    unsigned char *p = (unsigned char *)si.lpMinimumApplicationAddress;
    unsigned char *end = (unsigned char *)si.lpMaximumApplicationAddress;
    unsigned long long scanned = 0;
    int hits = 0, regions = 0;
    static unsigned char chunk[256 * 1024];
    while (p < end && hits < 1) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(p, &mbi, sizeof mbi) != sizeof mbi) { p += 0x10000; continue; }
        unsigned char *base = (unsigned char *)mbi.BaseAddress;
        size_t sz = mbi.RegionSize;
        int ok = (mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE) &&
                 !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) &&
                 (mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE));
        if (ok && sz > 0 && sz <= (size_t)1024 * 1024 * 1024) {
            regions++;
            for (size_t off = 0; off < sz && hits < 1; off += sizeof chunk) {
                size_t n = sz - off; if (n > sizeof chunk) n = sizeof chunk;
                if (!rpm(chunk, base + off, n)) continue;
                scanned += n;
                for (size_t i = 0; i + nl <= n; i += 8) {
                    if (chunk[i] != needle[0]) continue;
                    if (!mem_eq(chunk + i, (const char *)needle, nl)) continue;
                    {   char tag[56]; int ti = 0;
                        const char *m = "PROBE hit ";
                        while (*m) tag[ti++] = *m++;
                        while (*label && ti < 22) tag[ti++] = *label++;
                        m = " va=";
                        while (*m) tag[ti++] = *m++;                        
                        unsigned long long v = (unsigned long long)(size_t)(base + off + i);
                        char t[16]; int tl = 0;
                        if (!v) t[tl++] = '0';
                        while (v) { t[tl++] = (char)(v & 15); v >>= 4; }
                        while (tl) { unsigned d = (unsigned)t[--tl]; tag[ti++] = (char)(d < 10 ? '0' + d : 'a' + d - 10); }
                        tag[ti++] = ' '; tag[ti] = 0; logn(tag); }
                    {   size_t abs_off = off + i;
                        size_t from = abs_off > 0x100 ? abs_off - 0x100 : 0;
                        size_t to = abs_off + 0x600; if (to > sz) to = sz;
                        size_t wn = to - from; if (wn > 0x740) wn = 0x740;
                        if (rpm(chunk, base + from, wn))
                            log_hexdump(label, chunk, (int)wn);
                    }
                    hits++;
                }
            }
        }
        p = base + sz;
        if (scanned > (unsigned long long)1024 * 1024 * 1024) break;
    }
    {   char b[96]; int i = 0;
        const char *m = "PROBE done ";
        while (*m) b[i++] = *m++;
        while (*label && i < 24) b[i++] = *label++;
        m = " regions=";
        while (*m) b[i++] = *m++;
        { char t[12]; int tl = 0; int v = regions; if (!v) t[tl++] = '0';
          while (v) { t[tl++] = (char)('0' + v % 10); v /= 10; }
          while (tl) b[i++] = t[--tl]; }
        b[i++] = ' '; b[i++] = 'h'; b[i++] = 'i'; b[i++] = 't'; b[i++] = 's'; b[i++] = '=';
        b[i++] = (char)('0' + (hits > 9 ? 9 : hits)); b[i] = 0; logn(b);
    }
    return hits;
}

static DWORD WINAPI ProbeThread(void *p) {
    (void)p;
    Sleep(60);
    // One run answers the whole ladder: each needle is written at a different
    // depth of the deserialize, so the highest hit = how far the client got.
    //   connectionID (LoginResult+0x20)  -> login record written at all
    //   profileID    (accountInfo.id, profile.id)
    //   statGroupID  (ProfileInfo+personalStatGroupID, field 8 of 18)
    // The dump at a connectionID hit - 0x100 IS the LoginResult (token at +0,
    // accountInfo at +0x38, profiles vector at +0x120), so it shows which
    // AccountInfo fields landed too.
    logn("PROBE ladder=connectionID,profileID,statGroupID");
    mem_probe("connectionID", g_ProbeConn, 8);
    mem_probe("profileID", g_ProbeId, 8);
    mem_probe("statGroupID", g_ProbeStat, 8);
    InterlockedExchange(&g_ProbeArmed, 0);
    return 0;
}

static void probe_arm(void) {
    // Off by default: the ladder probe costs ~3.5 s of process-wide RPM during
    // boot. Opt in with AOE2LAN_PROBE=1 only while doing struct analysis.
    char v[8];
    if (!GetEnvironmentVariableA("AOE2LAN_PROBE", v, sizeof v) || v[0] != '1') return;
    if (InterlockedExchange(&g_ProbeArmed, 1)) return;
    CreateThread(NULL, 0, ProbeThread, NULL, 0, NULL);
}

// ---------------------------------------------------------------- log helper
// "<pre><n>" — the dec-digit loop every other log site here hand-rolls.
static void log_int(const char *pre, int v)
{
    char b[96]; int i = 0;
    while (*pre && i < 60) b[i++] = *pre++;
    { char t[12]; int tl = 0;
      if (!v) t[tl++] = '0';
      while (v > 0) { t[tl++] = (char)('0' + v % 10); v /= 10; }
      while (tl) b[i++] = t[--tl]; }
    b[i] = 0;
    logn(b);
}

// ---------------------------------------------------------------- websocket
// 0.4 s after a successful login the client opens a WebSocket:
//   WebSocketConnection::Process: Creating a websocket connection;
//   host=pb-live-release6-api.worldsedgelink.com port=443 -> HTTP REQ /wss/
// Answering plain HTTP made OnConnectFail fire every ~78 ms until Windows
// killed the process for hanging (session 17). RFC 6455: client->server
// frames are always masked, server->client frames never are.
#define WS_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

static const char B64C[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static int b64enc(const unsigned char *in, int n, char *out)
{
    int o = 0;
    for (int i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= (unsigned)in[i + 2];
        out[o++] = B64C[(v >> 18) & 63];
        out[o++] = B64C[(v >> 12) & 63];
        out[o++] = (i + 1 < n) ? B64C[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < n) ? B64C[v & 63] : '=';
    }
    out[o] = 0;
    return o;
}

// SHA1 through the same CAPI hash path the cert code uses (sha256() above)
static int sha1_b64(const unsigned char *data, size_t n, char out[32])
{
    unsigned long long hHash = 0;
    unsigned char dg[20];
    DWORD hl = 20;
    if (!pCCH(g_CspProv, 0x8004 /*CALG_SHA1*/, 0, 0, &hHash)) return 0;
    if (!pCHD(hHash, data, (DWORD)n, 0)) { pCDH(hHash); return 0; }
    if (!pCGHP(hHash, 2 /*HP_HASHVAL*/, dg, &hl, 0)) { pCDH(hHash); return 0; }
    pCDH(hHash);
    if (hl != 20) return 0;
    b64enc(dg, 20, out);
    return 1;
}

// Sec-WebSocket-Accept = base64(SHA1(key + WS_MAGIC))
static int ws_accept(const char *req, char out[32])
{
    unsigned char cat[128];
    int n = 0, k = 0;
    const char *p = 0;
    char key[64];
    static const char *const hdr[2] = { "Sec-WebSocket-Key:", "sec-websocket-key:" };
    for (int i = 0; i < 2 && !p; i++) p = strstr_f(req, hdr[i]);
    if (!p) return 0;
    p += 18;
    while (*p == ' ') p++;
    while (p[k] && p[k] != '\r' && p[k] != '\n' && k < 60) { key[k] = p[k]; k++; }
    key[k] = 0;
    if (k < 8) return 0;
    for (int i = 0; i < k && n < 100; i++) cat[n++] = (unsigned char)key[i];
    { const char *m = WS_MAGIC; while (*m && n < 120) cat[n++] = (unsigned char)*m++; }
    return sha1_b64(cat, (size_t)n, out);
}

// one unmasked server frame; ping/pong payloads and relay events are small
static int ws_send(TLSSES *t, int op, const unsigned char *pl, int n)
{
    unsigned char out[4 + 4096];
    int hl;
    if (n > 4096) n = 4096;
    out[0] = (unsigned char)(0x80 | op);
    if (n < 126) { out[1] = (unsigned char)n; hl = 2; }
    else { out[1] = 126; out[2] = (unsigned char)((n >> 8) & 0xff); out[3] = (unsigned char)(n & 0xff); hl = 4; }
    for (int i = 0; i < n; i++) out[hl + i] = pl[i];
    return tls_encrypt_send(t, (const char*)out, hl + n);
}

// text frame payload, truncated and newline-flattened (the client's first WS
// message carries {"operation":0,"sessionToken":...})
static void log_ws_text(const unsigned char *p, int n)
{
    char b[300]; int i = 0;
    const char *m = "WS TEXT ";
    while (*m) b[i++] = *m++;
    for (int k = 0; k < n && k < 280; k++) {
        char c = (char)p[k];
        b[i++] = (c == '\n' || c == '\r') ? ' ' : c;
    }
    b[i] = 0;
    logn(b);
}

// Upgrade the connection and then sit on it: pings get pongs, closes get
// closes, everything else is counted and dropped (serving the rlink relay/
// poll events over this socket is the follow-on). Returns when the client
// goes away — the caller must not touch the socket after this.
static void ws_serve(TLSSES *t, const char *req)
{
    char acc[32];
    char head[320]; int hl = 0;
    unsigned char *plain = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, TLS_MAX_PLAIN);
    unsigned char *fb = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, TLS_MAX_PLAIN * 2);
    int fcap = TLS_MAX_PLAIN * 2, fl = 0, frames = 0, ignored = 0, quiet = 0;
    // event pump: after the client's session-token frame, walk the frame-shape /
    // event-name candidate table (g_Cands), 4 s apart. The client's warn sink
    // (hook id 13) logs any rejected frame, and resultCode 99 makes a parsed
    // AccountLoginEvent unmistakable at the deserializer.
    DWORD64 pushAt = 0; int pushed = 0; BUF ev = {0};
    if (g_PushEnable < 0) { char v[8]; g_PushEnable = 0;
        if (GetEnvironmentVariableA("AOE2LAN_PUSH", v, sizeof v)) g_PushEnable = (v[0] == '1'); }
    if (!plain || !fb) goto out;
    if (!ws_accept(req, acc)) {
        logn("WS: no usable Sec-WebSocket-Key in the upgrade request");
        goto out;
    }
    { const char *m =
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";
      while (*m) head[hl++] = *m++;
      for (int i = 0; acc[i]; i++) head[hl++] = acc[i];
      m = "\r\nCache-Control: no-store\r\n\r\n";
      while (*m) head[hl++] = *m++; }
    if (!tls_encrypt_send(t, head, hl)) { logn("WS: sending 101 failed"); goto out; }
    { char b[96]; int i = 0; const char *m = "WS: 101 Switching Protocols, accept=";
      while (*m) b[i++] = *m++;
      for (int k = 0; acc[k] && i < 90; k++) b[i++] = acc[k];
      b[i] = 0; logn(b); }
    for (;;) {
        if (pushAt && GetTickCount64() >= pushAt && pushed < N_CANDS) {
            const PUSHCAND *c = &g_Cands[pushed];
            ev.len = 0; ev.oom = 0;
            build_cand(&ev, g_Alias[0] ? g_Alias : "AnkerGames", c);
            if (ev.p && ws_send(t, 0x2, (const unsigned char*)ev.p, (int)ev.len)) {
                char b[112]; int i = 0; const char *m = "WS PUSH ";
                while (*m) b[i++] = *m++;
                { const char *r = c->label; while (*r && i < 60) b[i++] = *r++; }
                m = " len="; while (*m) b[i++] = *m++;
                { char ts[8]; int tl = 0; size_t v = ev.len;
                  if (!v) ts[tl++] = '0';
                  while (v) { ts[tl++] = (char)('0' + (int)(v % 10)); v /= 10; }
                  while (tl) b[i++] = ts[--tl]; }
                b[i] = 0; logn(b);
            } else { logn("WS PUSH send failed"); }
            pushed++; pushAt = GetTickCount64() + PUSH_INTERVAL_MS;
        }
        int n = tls_decrypt(t, plain, TLS_MAX_PLAIN);
        if (n == -1) {
            // SO_RCVTIMEO also lands here: keep the socket with a ping before
            // giving up, so an idle client is not churned into a reconnect.
            // quiet resets so a silent client sees one ping per ~3 ticks.
            if (++quiet > 2) { if (!ws_send(t, 0x9, 0, 0)) break; quiet = 0; }
            continue;
        }
        if (n <= 0) continue;                       // -2 = need more, 0 = empty record
        quiet = 0;
        if (fl + n > fcap) { logn("WS: frame buffer overflow, dropping"); fl = 0; }
        memcpy(fb + fl, plain, (size_t)n);
        fl += n;
        { int off = 0;
          while (fl - off >= 2) {
            int opc = fb[off] & 0x0f;
            int masked = (fb[off + 1] & 0x80) != 0;
            unsigned long long plen = fb[off + 1] & 0x7f;
            int hdr = 2;
            int tot;
            unsigned char *pl;
            if (plen == 126) {
                if (fl - off < 4) break;
                plen = ((unsigned long long)fb[off + 2] << 8) | fb[off + 3];
                hdr = 4;
            } else if (plen == 127) {
                if (fl - off < 10) break;
                plen = 0;
                for (int k = 0; k < 8; k++) plen = (plen << 8) | fb[off + 2 + k];
                hdr = 10;
            }
            if (plen > 65535) { logn("WS: frame too big, closing"); goto out; }
            if (masked) hdr += 4;
            if (fl - off < hdr + (int)plen) break;  // frame not fully here yet
            pl = fb + off + hdr - (masked ? 4 : 0);
            if (masked) {
                unsigned char mk[4];
                for (int k = 0; k < 4; k++) mk[k] = pl[k];
                pl += 4;
                for (unsigned long long k = 0; k < plen; k++) pl[k] ^= mk[k & 3];
            }
            frames++;
            if (frames <= 6) {
                char b[64]; int i = 0; const char *m = "WS: frame op=";
                while (*m) b[i++] = *m++;
                b[i++] = (char)('0' + (opc > 9 ? 9 : opc));
                m = " len="; while (*m) b[i++] = *m++;
                { char ts[12]; int tl = 0; unsigned long long v = plen;
                  if (!v) ts[tl++] = '0';
                  while (v) { ts[tl++] = (char)('0' + (int)(v % 10)); v /= 10; }
                  while (tl) b[i++] = ts[--tl]; }
                m = masked ? " masked" : " UNMASKED";
                while (*m) b[i++] = *m++;
                b[i] = 0; logn(b);
            }
            if (opc == 0x8) { ws_send(t, 0x8, pl, (int)plen); goto out; }
            if (opc == 0x9) ws_send(t, 0xA, pl, (int)plen);   // ping -> pong
            else if (opc == 0x1 || opc == 0x2) {              // rlink sends JSON as binary frames
                if (ignored < 3) log_ws_text(pl, (int)plen);
                ignored++;
                // the client's session-token frame: start the AccountLoginEvent pump
                if (g_PushEnable && !pushAt && strstr_n((const char*)pl, (int)plen, "sessionToken"))
                    pushAt = GetTickCount64();
            }
            off += hdr + (int)plen;
          }
          if (off) { fl -= off; memmove_f((char*)fb, (char*)fb + off, (size_t)fl); }
        }
    }
out:
    log_int("WS: closed, frames=", frames);
    if (ignored) log_int("WS: data frames ignored=", ignored);
    if (ev.p) HeapFree(GetProcessHeap(), 0, ev.p);
    if (plain) HeapFree(GetProcessHeap(), 0, plain);
    if (fb) HeapFree(GetProcessHeap(), 0, fb);
}

// ---------------------------------------------------------------- route
static void route(TLSSES *t, const char *method, const char *path,
                  const char *body, int bodyLen) {
    char alias[64];
    BUF resp = {0};
    log_req(path);
    if (body && bodyLen) log_body_head(body, bodyLen);
    (void)method;
    extract_alias(body, alias, 64);
    if (contains(path, "/game/login/login") || contains(path, "/game/login/platformlogin")) {
        g_LastToken[0] = 0;
        { int k = 0; while (alias[k] && k < 63) { g_Alias[k] = alias[k]; k++; } g_Alias[k] = 0; }
        build_login_response(&resp, alias);
        { char b[128]; int i=0; const char *m="LOGIN: serving synthetic profile, alias=";
          while (*m) b[i++]=*m++;
          for (int k=0; alias[k] && i<120; k++) b[i++]=alias[k];
          b[i]=0; logn(b); }
        { const char *rb = resp.p ? resp.p : "[0]";
          log_resp_head(rb, (int)strlen_f(rb));
          http_respond(t, rb); }
        probe_arm();
    } else if (contains(path, "/game/login/readSession")) {
        // Long poll reply is "<ackNum>,[<chunk>]", one chunk = list of events
        // (capture: "23,[[[0,\"ChallengeUpdatedMessage\",...]]]"). No events to
        // deliver yet, and ackNum stays put while nothing is acknowledged.
        log_resp_head("0,[null]", 8);
        http_respond(t, "0,[null]");
    } else if (contains(path, "/game/Leaderboard/getAvailableLeaderboards")) {
        // The game parses this into its LeaderboardInfoCache with an object
        // reader; the catch-all "[0,[]]" is a JSON *array*, so it logged
        // "response was not formatted correctly" and cached nothing.
        // Shape = the game's own DTO reader (0x14073d890): result int plus the
        // definition arrays; a leaderboard entry is {leaderboardID int,
        // leaderboardName str, isRanked bool} (0x1407365e0). One dummy entry so
        // the list is never empty.
        // shortcut: this reply alone does NOT fill the leaderboard-definition
        // registry that rule 2 counts, see notes/m1-session29.md 29f.
        // The game-side consumer (TComm_Leaderboard_RL::OnGetLeaderboardInfo,
        // 0x140edd4f0) installs its definitions from the `matchTypes` vector
        // and reads `mappings`/`races`/`factions`/`leaderboardRegions` to
        // resolve ids, so every one of those carries one entry.
        static const char LB[] =
            "{\"result\":0,"
            "\"leaderboards\":[{\"leaderboardID\":1,\"leaderboardName\":\"1v1\",\"isRanked\":true}],"
            "\"mappings\":[{\"leaderboardID\":1,\"matchTypeID\":1,\"statType\":0,\"raceID\":0}],"
            "\"matchTypes\":[{\"matchTypeID\":1,\"name\":\"1v1\",\"teamSize\":1,\"numTeams\":2,"
            "\"localizedName\":\"1v1\"}],"
            "\"races\":[{\"raceID\":0,\"name\":\"random\",\"factionID\":0,\"localizedName\":\"Random\"}],"
            "\"factions\":[{\"factionID\":0,\"name\":\"random\",\"localizedName\":\"Random\"}],"
            "\"leaderboardRegions\":[{\"leaderboardRegionID\":2,\"name\":\"LAN\","
            "\"localizedName\":\"LAN\"}],"
            "\"rankLevels\":[],\"statDefinitions\":[],\"selfAssessmentTiers\":[]}";
        log_resp_head(LB, (int)strlen_f(LB));
        http_respond(t, LB);
    } else if (contains(path, "/game/advertisement/host")) {
        // LAN hosting: the create request arrives only now that the server answers
        // libcurl's "Expect: 100-continue" (session 30h). The game reads the reply as
        // a DTO with named members (0x140309298 parses it, 0x140351771 passes the
        // address on). With the catch-all array it logged "OnlineHostAsync success"
        // but then "Created Matchinfo for sessionID -1", "starting local hosting",
        // "PeerRemoveAll" and finally HostResult 0xfffffff4 ("Request was invalid"),
        // i.e. the host joined with no advertisement id.
        // Replied shape = result + the advertisement we were asked to create, echoing
        // the request's own hostid and connect_id. shortcut: `slotinfo` is passed as
        // null and the slot layout is not built yet; when the lobby screen reports a
        // slot error, copy the encodedSlots the create dialog shows instead.
        static char hr[1024];
        const char *hid = body ? strstr_f(body, "hostid=") : 0;
        char hostid[32]; int hi2 = 0;
        hostid[0] = 0;
        if (hid) { hid += 7; while (hid[hi2] && hid[hi2] != '&' && hi2 < 31) { hostid[hi2] = hid[hi2]; hi2++; } }
        hostid[hi2] = 0;
        { const char *a = "{\"result\":0,\"advertisementid\":1,\"hostid\":";
          int i = 0; while (*a && i < 1000) hr[i++] = *a++;
          if (hostid[0]) { for (int k = 0; hostid[k] && i < 1000; k++) hr[i++] = hostid[k]; }
          else { hr[i++] = '0'; }
          a = ",\"sessionID\":"; while (*a) hr[i++] = *a++;
          a = "1"; while (*a) hr[i++] = *a++;
          a = ",\"maxplayers\":8,\"matchtype\":-1,\"slotinfo\":null,\"encodedSlots\":\"\"}";
          while (*a) hr[i++] = *a++;
          hr[i] = 0; }
        log_resp_head(hr, (int)strlen_f(hr));
        http_respond(t, hr);
    } else if (contains(path, "/game/news/")) {
        log_resp_head("[0,[]]", 5);
        http_respond(t, "[0,[]]");
    } else {
        // empty success for cloud/stats/achievements/leaderboards/QoS/chat/...
        log_resp_head("[0,[]]", 5);
        http_respond(t, "[0,[]]");
    }
    if (resp.p) HeapFree(GetProcessHeap(), 0, resp.p);
}

// Every launch mints a fresh key + fresh self-signed cert and adds it to the
// CURRENT USER Root store, so stale AoE2LAN roots pile up (s20: 44 of them in
// one afternoon). They share the exact DN bytes with ours (only the key and
// serial differ), so match on the encoded Subject and delete before adding.
static int purge_aoe2lan_roots(void *hStore) {
    typedef void * (WINAPI *Penum)(void*, void*);
    typedef int    (WINAPI *Pdel)(void*);
    typedef void * (WINAPI *Pfree)(void*);
    Penum pEnum = (Penum)GetProcAddress(g_hCrypt, "CertEnumCertificatesInStore");
    Pdel  pDel  = (Pdel) GetProcAddress(g_hCrypt, "CertDeleteCertificateFromStore");
    Pfree pFree = (Pfree)GetProcAddress(g_hCrypt, "CertFreeCertificateContext");
    int n = 0;
    if (!pEnum || !pDel || !pFree || !g_ServerCert) return 0;
    CERT_CONTEXT *pc = NULL;
    while ((pc = (CERT_CONTEXT*)pEnum(hStore, pc)) != NULL) {
        int same = 0;
        { CERT_NAME_BLOB *a = &pc->pCertInfo->Subject;
          CERT_NAME_BLOB *b = &g_ServerCert->pCertInfo->Subject;
          if (a->cbData == b->cbData && a->pbData && b->pbData &&
              !memcmp_f(a->pbData, b->pbData, a->cbData)) same = 1; }
        if (same) {
            if (pDel(pc)) n++;      // deletion frees this context
            pc = NULL;              // restart the enumeration
        }
    }
    return n;
}

// ageLANServer-equivalent trust registration, on its own thread:
// the CURRENT USER Root store add can stall (authroot CTL sync), so it
// must not sit on the boot or handshake path. The game's fast retry
// cycle (~5s while failing) picks it up once registered.
static DWORD WINAPI RootRegThread(void *p) {
    (void)p;
    if (g_ServerCert && g_hCrypt) {
        typedef void * (WINAPI *PopenSys)(void*, const wchar_t*);
        typedef int  (WINAPI *PaddCtx2)(void*, void*, int, void**);
        PopenSys pOpenSys = (PopenSys)GetProcAddress(g_hCrypt, "CertOpenSystemStoreW");
        PaddCtx2 pAddCtx  = (PaddCtx2)GetProcAddress(g_hCrypt, "CertAddCertificateContextToStore");
        if (pOpenSys && pAddCtx) {
            void *hRoot = pOpenSys(NULL, L"Root");
            if (hRoot) {
                int old = purge_aoe2lan_roots(hRoot);
                if (old) { char b[56]; int i = 0; const char *m = "cert: purged stale roots=";
                           while (*m) b[i++] = *m++;
                           { char t[8]; int tl = 0; int v = old;
                             if (!v) t[tl++] = '0';
                             while (v) { t[tl++] = (char)('0' + v % 10); v /= 10; }
                             while (tl) b[i++] = t[--tl]; }
                           b[i] = 0; logn(b); }
                if (pAddCtx(hRoot, (void*)g_ServerCert, 1, (void**)0))
                    logn("cert: user-Root registered (schannel trust path live)");
                else
                    logn("cert: user-Root add returned 0 (already present or denied)");
                g_hRootStore = hRoot;
            } else logn("cert: user-Root open failed");
        } else logn("cert: user-Root fns missing");
    }
    return 0;
}

// per-connection transcript: session 30 — the host attempt sends app data that
// never becomes a logged request, so each block and each close must be visible.
static volatile LONG g_connSeq;
static void log_conn(const char *tag, int id, int n) {
    char b[112]; int i = 0;
    while (*tag && i < 70) b[i++] = *tag++;
    { char t[12]; int tl = 0, v = id;
      if (v < 0) { b[i++] = '-'; v = -v; }
      if (!v) t[tl++] = '0';
      while (v) { t[tl++] = (char)('0' + v % 10); v /= 10; }
      b[i++] = '#'; while (tl) b[i++] = t[--tl]; }
    { const char *m = " n="; while (*m) b[i++] = *m++; }
    { char t[12]; int tl = 0, v = n;
      if (v < 0) { b[i++] = '-'; v = -v; }
      if (!v) t[tl++] = '0';
      while (v) { t[tl++] = (char)('0' + v % 10); v /= 10; }
      while (tl) b[i++] = t[--tl]; }
    b[i] = 0; logn(b);
}

// one connection: handshake → request loop → close
static void serve_conn(SOCKET s) {
    int cid = (int)InterlockedIncrement(&g_connSeq);
    TLSSES *t = (TLSSES*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(TLSSES));
    unsigned char *plain = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, TLS_MAX_PLAIN);
    char *req = (char*)HeapAlloc(GetProcessHeap(), 0, REQ_MAX);  // per connection
    int reqLen = 0;
    int contSent = 0;
    if (!t || !plain || !req) goto done;
    t->s = s;
    if (!tls_handshake(t)) goto done;
    for (;;) {
        int n = tls_decrypt(t, plain, TLS_MAX_PLAIN);
        if (n == -1) break;
        if (n == -2) continue;
        if (n > 0) {
            log_conn("srv: blk", cid, n);
            if (reqLen + n > REQ_MAX - 1) { reqLen = 0; log_conn("srv: too big", cid, n); }  // overflow guard
            memcpy(req + reqLen, plain, (size_t)n);
            reqLen += n;
            req[reqLen] = 0;
            // complete request? head must end with \r\n\r\n; body by Content-Length
            char *hdrEnd = strstr_f(req, "\r\n\r\n");
            if (hdrEnd) {
                int headLen = (int)(hdrEnd - req) + 4;
                int contentLen = 0;
                char *cl = strstr_f(req, "Content-Length:");
                if (!cl) cl = strstr_f(req, "content-length:");
                if (cl) contentLen = atoi_f(cl + 15);
                // libcurl (the game's HTTP client) adds "Expect: 100-continue" to
                // bodies over 1 KB, then waits exactly 1 s for the interim reply
                // before sending the body. Without it the host request never
                // arrives and the host job fails (session 30).
                if (!contSent && (strstr_f(req, "Expect: 100-continue") ||
                                  strstr_f(req, "expect: 100-continue"))) {
                    tls_encrypt_send(t, "HTTP/1.1 100 Continue\r\n\r\n", 25);
                    contSent = 1;
                    log_conn("srv: 100-continue", cid, contentLen);
                }
                if (reqLen >= headLen + contentLen) {
                    contSent = 0;
                    char method[12] = {0};
                    char path[256] = {0};
                    { int i = 0; while (req[i] != ' ' && i < 11) { method[i] = req[i]; i++; }
                      int j = 0; while (req[i+j+1] != ' ' && req[i+j+1] != '?' && j < 250) { path[j] = req[i+j+1]; j++; } }
                    if (contains(path, "/wss")) {
                        // the socket stops being HTTP here; ws_serve owns it
                        log_req(path);
                        ws_serve(t, req);
                        break;
                    }
                    log_conn("srv: req", cid, headLen + contentLen);
                    route(t, method, path, req + headLen, contentLen);
                    // keep-alive: reset for the next request on this connection
                    int leftover = reqLen - headLen - contentLen;
                    if (leftover > 0) memmove_f(req, req + headLen + contentLen, (size_t)leftover);
                    reqLen = leftover > 0 ? leftover : 0;
                    req[reqLen] = 0;
                }
            }
        }
    }
done:
    log_conn("srv: closed pending", cid, reqLen);
    if (t && t->handshook) pDSC(&t->hCtx);
    if (t) HeapFree(GetProcessHeap(), 0, t);
    if (plain) HeapFree(GetProcessHeap(), 0, plain);
    if (req) HeapFree(GetProcessHeap(), 0, req);
    p_closesocket(s);
}

static int atoi_f(const char *s) {
    int v = 0;
    while (*s == ' ') s++;
    while (*s >= '0' && *s <= '9') { v = v * 10 + (*s - '0'); s++; }
    return v;
}

// ---------------------------------------------------------------- listener
static volatile LONG g_Run = 1;

// one accepted socket per worker: the game opens a fresh TCP connection
// per login cycle (parallel web fetches + rlink retry). The old loop parked
// in serve_conn's keep-alive recv and never accepted again (session 15:
// the t=90s retry starved while conn 2 idled). Workers die on recv timeout.
static DWORD WINAPI ConnWorker(LPVOID p) {
    SOCKET c = (SOCKET)(DWORD_PTR)p;
    // Short timeout: the WS pump advances between reads, so a 60 s recv
    // timeout made every scheduled push wait for it (s20: 4 s interval became
    // 10 s). 1 s keeps pushes on schedule and still costs nothing (pings).
    { int to = 1000;
      if (p_setsockopt) p_setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, (const char*)&to, sizeof(to)); }
    serve_conn(c);
    return 0;
}

static DWORD WINAPI ServerThread(LPVOID p) {
    SOCKET srv;
    struct sockaddr_in la;
    int on = 1;
    (void)p;
    { WSADATA wd; p_WSAStartup(0x0202, &wd); }
    srv = p_socket(AF_INET, SOCK_STREAM, 0);
    if (srv == INVALID_SOCKET) { logn("srv: socket failed"); return 0; }
    p_setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on));
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = 0x0100007f;   // 127.0.0.1 as LE u32 (no htonl import)
    la.sin_port = 0xBB01;              // 443 network byte order
    if (p_bind(srv, (struct sockaddr*)&la, sizeof(la))) {
        logn("srv: bind 127.0.0.1:443 FAILED (port busy?)");
        p_closesocket(srv);
        return 0;
    }
    if (p_listen(srv, 8)) { logn("srv: listen failed"); p_closesocket(srv); return 0; }
    logn("srv: H1 login server listening on 127.0.0.1:443 (TLS)");
    while (g_Run) {
        SOCKET c = p_accept(srv, NULL, NULL);
        if (c == INVALID_SOCKET) continue;
        { char b[80]; int i=0; const char *m="srv: connection accepted";
          while (*m) b[i++]=*m++; b[i]=0; logn(b); }
        { HANDLE h = CreateThread(NULL, 0, ConnWorker, (LPVOID)(DWORD_PTR)c, 0, NULL);
          if (h) CloseHandle(h);
          else serve_conn(c);   // thread failed: serve inline (old behavior)
        }
    }
    p_closesocket(srv);
    return 0;
}

int loginsrv_start(void) {
    g_hWs2  = LoadLibraryExW(L"WS2_32.dll", NULL, 0);
    logn("dbg: ws2 loaded");
    // SSPI lives in SSPICLI.dll; Secur32.dll only forwards (GetProcAddress
    // through the forwarder returns the stub, which fails)
    g_hSecur = LoadLibraryExW(L"SSPICLI.dll", NULL, 0);
    logn("dbg: ssp loaded");
    g_hCrypt = LoadLibraryExW(L"CRYPT32.dll", NULL, 0);
    logn("dbg: crypt loaded");
    g_hAdv  = LoadLibraryExW(L"ADVAPI32.dll", NULL, 0);
    logn("dbg: adv loaded");
    g_hNc   = LoadLibraryExW(L"ncrypt.dll", NULL, 0);
    if (!g_hWs2 || !g_hSecur || !g_hCrypt || !g_hAdv || !g_hNc) { logn("srv: dyn load failed"); return 0; }
#define GPA(h, n) ((void*)GetProcAddress(h, n))
    p_socket = (int (WINAPI*)(int,int,int))GPA(g_hWs2, "socket");
    p_bind = (int (WINAPI*)(SOCKET, const struct sockaddr*, int))GPA(g_hWs2, "bind");
    p_listen = (int (WINAPI*)(SOCKET,int))GPA(g_hWs2, "listen");
    p_accept = (SOCKET (WINAPI*)(SOCKET, struct sockaddr*, int*))GPA(g_hWs2, "accept");
    p_closesocket = (int (WINAPI*)(SOCKET))GPA(g_hWs2, "closesocket");
    p_recv = (int (WINAPI*)(SOCKET, char*, int,int))GPA(g_hWs2, "recv");
    p_send = (int (WINAPI*)(SOCKET, const char*, int,int))GPA(g_hWs2, "send");
    p_setsockopt = (int (WINAPI*)(SOCKET,int,int,const char*,int))GPA(g_hWs2, "setsockopt");
    p_htons = (u_short (WINAPI*)(u_short))GPA(g_hWs2, "htons");
    p_WSAStartup = (int (WINAPI*)(WORD, void*))GPA(g_hWs2, "WSAStartup");
    p_WSAGetLastError = (int (WINAPI*)(void))GPA(g_hWs2, "WSAGetLastError");
    pACH = (PfnACH)GPA(g_hSecur, "AcquireCredentialsHandleW");
    pFCH = (PfnFCH)GPA(g_hSecur, "FreeCredentialsHandle");
    pASC = (PfnASC)GPA(g_hSecur, "AcceptSecurityContext");
    pDSC = (PfnDSC)GPA(g_hSecur, "DeleteSecurityContext");
    pQCA = (PfnQCA)GPA(g_hSecur, "QueryContextAttributesW");
    pEM  = (PfnEM)GPA(g_hSecur, "EncryptMessage");
    pDM  = (PfnDM)GPA(g_hSecur, "DecryptMessage");
    pACT = (PfnACT)GPA(g_hSecur, "ApplyControlToken");
    pCertCSSC = (PfnCertCSSC)GPA(g_hCrypt, "CertCreateSelfSignCertificate");
    pCCC  = (PfnCCC)GPA(g_hCrypt, "CertCreateCertificateContext");
    pCSCP = (PfnCSCP)GPA(g_hCrypt, "CertSetCertificateContextProperty");
    pCACPK = (PfnCACPK)GPA(g_hCrypt, "CryptAcquireCertificatePrivateKey");
    pNEK  = (PfnNEK)GPA(g_hNc, "NCryptExportKey");
    pNSH  = (PfnNSH)GPA(g_hNc, "NCryptSignHash");
    pCCH  = (PfnCCH)GPA(g_hAdv, "CryptCreateHash");
    pCHD  = (PfnCHD)GPA(g_hAdv, "CryptHashData");
    pCGHP = (PfnCGHP)GPA(g_hAdv, "CryptGetHashParam");
    pCDH  = (PfnCDH)GPA(g_hAdv, "CryptDestroyHash");
    pCertCTNW = (PfnCertCTNW)GPA(g_hCrypt, "CertStrToNameW");
    pCertFCC  = (PfnCertFCC)GPA(g_hCrypt, "CertFreeCertificateContext");
    pCEOE     = (PfnCEOE)GPA(g_hCrypt, "CryptEncodeObjectEx");
    pCAC = (PfnCAC)GPA(g_hAdv, "CryptAcquireContextA");
    pCGK = (PfnCGK)GPA(g_hAdv, "CryptGenKey");
    pCRC = (PfnCRC)GPA(g_hAdv, "CryptReleaseContext");
    pNOSP = (PfnNOSP)GPA(g_hNc, "NCryptOpenStorageProvider");
    pNCPK = (PfnNCPK)GPA(g_hNc, "NCryptCreatePersistedKey");
    pNSP  = (PfnNSP)GPA(g_hNc, "NCryptSetProperty");
    pNFK  = (PfnNFK)GPA(g_hNc, "NCryptFinalizeKey");
    pNDFK = (PfnNDFK)GPA(g_hNc, "NCryptDeleteKey");
#undef GPA
    if (!p_socket || !p_bind || !p_listen || !p_accept || !p_recv || !p_send ||
        !pACH || !pASC || !pDSC || !pQCA || !pEM || !pDM ||
        !pCCC || !pCSCP || !pCACPK || !pNEK || !pNSH || !pCCH || !pCHD || !pCGHP || !pCDH ||
        !pNOSP || !pNCPK || !pNSP || !pNFK || !pCAC) {
        logn("srv: proc resolve failed");
        return 0;
    }
    if (!mint_cert()) return 0;
    logn("dbg: cert ok");
    if (!acquire_cred()) return 0;
    logn("dbg: cred ok");
    { HANDLE h = CreateThread(NULL, 0, RootRegThread, NULL, 0, NULL);
      if (h) CloseHandle(h); }
    { HANDLE h = CreateThread(NULL, 0, ServerThread, NULL, 0, NULL);
      if (!h) return 0;
      CloseHandle(h); }
    return 1;
}
