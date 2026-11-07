// hookcore.h — shared detour machinery (used by lanhook.dll and hooktest.exe)
#ifndef HOOKCORE_H
#define HOOKCORE_H
#include <windows.h>

#define HK_MAX 16
#define HK_RAW   0   // log raw arg registers
#define HK_RDSTR 1   // rdx = char* log/format string, keyword-filtered
#define HK_R8STR 2   // r8  = char* field key, "relay"-filtered
#define HK_TLS   3   // OpenSSL TLS fns: log rcx/rdx/r8/r9 + ret, cap 256
#define HK_WSET  4   // widget SetEnabled (0x140a74ca0): rcx=widget, dl=en, deduped
#define HK_AISLOT 5  // 0x140d62260 AI-slot picker: rcx=setup obj, picks table[kind]

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
