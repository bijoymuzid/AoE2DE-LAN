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
extern void lanhook_wset_vt(void);               // hooks.asm
int hc_install_wset_vtables(DWORD64 base);       // hookcore.c
// ctx layout passed to lanhook_log_hit: ctx[-8..-5] = the caller's rbx/rsi/rdi/rbp
// snapshot, ctx[0..18] as below, ctx[19] = live return address, ctx[20..] = the
// caller's stack.

// exe base VA of the hooked process (set by lanhook.dll at boot; hooktest
// sets it to its own module). Used by HK_TLS to print fn offsets.
DWORD64 g_ModBase(void);
void hc_set_modbase(DWORD64 base);

void  hc_set_log(HANDLE hLog, DWORD t0);
void  log_line(const char *s);

// HC_TRY — use instead of a bare `__try {`, and reach memory ONLY through the
// HC_RD*/HC_WR* accessors below. Two separate clang-mingw defects make a plain
// `__try { v = *p; } __except(...)` useless on the Linux build (measured in
// dev/lanhook/sehprobe.c, 4 cases x -O0/-O1 on wine 11; MSVC has neither):
//  1. a __try body with no call gets NO handler at all (unwind Flags: 0) —
//     hc_seh_anchor() keeps one alive;
//  2. clang emits an SEH scope record ONLY around call instructions, so an
//     access written inline in the body is covered by no region. The handler
//     exists, __C_specific_handler is called for that very frame, it finds no
//     matching record and returns ExceptionContinueSearch, and the process dies.
// So the anchor alone is not enough: the faulting instruction has to be inside
// a callee, which unwinds to the caller's guarded call site.
// Verified: notes/linux-session4.md §4b.
#ifdef __clang__
__attribute__((noinline)) void hc_seh_anchor(void);
#define HC_TRY __try { hc_seh_anchor();

// sz = 1/2/4/8; defined in hcaccess.inc. A fault raises out of the callee's
// frame, so the caller's __except catches it.
__attribute__((noinline)) void hc_rd(DWORD64 addr, void *out, int sz);
__attribute__((noinline)) void hc_wr(DWORD64 addr, DWORD64 val, int sz);
#define HC_RD64(a)     ({ DWORD64 hc_v = 0; hc_rd((DWORD64)(a), &hc_v, 8); hc_v; })
#define HC_RD32(a)     ({ DWORD   hc_v = 0; hc_rd((DWORD64)(a), &hc_v, 4); hc_v; })
#define HC_RD16(a)     ({ WORD    hc_v = 0; hc_rd((DWORD64)(a), &hc_v, 2); hc_v; })
#define HC_RD8(a)      ({ BYTE    hc_v = 0; hc_rd((DWORD64)(a), &hc_v, 1); hc_v; })
#define HC_WR64(a, v)  hc_wr((DWORD64)(a), (DWORD64)(v), 8)
#define HC_WR32(a, v)  hc_wr((DWORD64)(a), (DWORD)(v), 4)
#define HC_WR8(a, v)   hc_wr((DWORD64)(a), (BYTE)(v), 1)
#else
#define HC_TRY __try {
// MSVC covers every statement of a __try body with its scope table, so the
// direct access is correct (and free) there.
#define HC_RD64(a)     (*(const volatile DWORD64 *)(DWORD64)(a))
#define HC_RD32(a)     (*(const volatile DWORD   *)(DWORD64)(a))
#define HC_RD16(a)     (*(const volatile WORD    *)(DWORD64)(a))
#define HC_RD8(a)      (*(const volatile BYTE    *)(DWORD64)(a))
#define HC_WR64(a, v)  (*(volatile DWORD64 *)(DWORD64)(a) = (DWORD64)(v))
#define HC_WR32(a, v)  (*(volatile DWORD   *)(DWORD64)(a) = (DWORD)(v))
#define HC_WR8(a, v)   (*(volatile BYTE    *)(DWORD64)(a) = (BYTE)(v))
#endif

// Win32 APIs that take an LPCSTR sometimes take a small integer constant
// instead (CERT_STORE_PROV_* = 1..11, LPSTR_INTRESOURCE, ...). Dereferencing
// those faults, so every probe of a caller-supplied "string" checks this first.
#define HC_IS_PTR(p) ((ULONG_PTR)(p) >= 0x10000UL)
void  logf1(const char *pre, DWORD64 a);
int   hc_match_now(const BYTE *t, const BYTE *exp);
int   hc_install_hook(BYTE *target, int id);
void  hc_alloc_near(BYTE *probe);
BYTE *hc_near_page(void);
#endif
