// hookcore.h — shared detour machinery (used by lanhook.dll and hooktest.exe)
#ifndef HOOKCORE_H
#define HOOKCORE_H
#include <windows.h>

#define HK_MAX 20
#define HK_RAW   0   // log raw arg registers
#define HK_RDSTR 1   // rdx = char* log/format string, keyword-filtered
#define HK_R8STR 2   // r8  = char* field key, "relay"-filtered
#define HK_TLS   3   // OpenSSL TLS fns: log rcx/rdx/r8/r9 + ret, cap 256
#define HK_WSET  4   // widget SetEnabled (0x140a74ca0): rcx=widget, dl=en, deduped
#define HK_AISLOT 5  // 0x140d62260 AI-slot picker: rcx=setup obj, picks table[kind]
#define HK_LOCID 6   // 0x140ac5480 localize-by-id, filtered to the host lobby populator
#define HK_GLOG  7   // 0x1407db520 vsnprintf helper, filtered to the game-layer log fn

// s45: cross-TU signals for the MatchStartMessage parse experiment. The shim and
// the hooks share a process, so loginsrv.c reads these from the WS pump and can
// grade a pushed payload variant - and escalate to the next one - inside a
// single game run instead of spending a run per variant.
extern volatile LONG g_ParseFail;   // hook 13 logged "failed to parse notification messages"
extern volatile LONG g_MSReached;   // hook 18 ran = the MatchStartMessage factory was reached

typedef struct {
    const char *name;
    DWORD64     va;       // VA at imagebase 0x140000000
    const BYTE *exp;      // 8 expected runtime prologue bytes
    DWORD       waitMs;   // poll deadline from worker start
    int         grp;      // 1 = provider set (stage 4), 2 = M0.2 set (stage 6)
    int         kind;
} HOOKDEF;

extern HOOKDEF g_Hooks[];
extern const int g_NHooks;

extern unsigned long long g_TailTable[HK_MAX];   // hooks.asm
extern void lanhook_thunk(void);                 // hooks.asm
// ctx layout passed to lanhook_log_hit: ctx[-8..-5] = the caller's rbx/rsi/rdi/rbp
// snapshot, ctx[0..18] as below, ctx[19] = live return address, ctx[20..] = the
// caller's stack.

// exe base VA of the hooked process (set by lanhook.dll at boot; hooktest
// sets it to its own module). Used by HK_TLS to print fn offsets.
DWORD64 g_ModBase(void);
void hc_set_modbase(DWORD64 base);

void  hc_set_log(HANDLE hLog, DWORD t0);
void  log_line(const char *s);
void  logf1(const char *pre, DWORD64 a);
int   hc_match_now(const BYTE *t, const BYTE *exp);
int   hc_install_hook(BYTE *target, int id);
void  hc_alloc_near(BYTE *probe);
BYTE *hc_near_page(void);
#endif
