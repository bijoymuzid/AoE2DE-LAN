// lanhook.c — AoE2LAN dbghelp.dll proxy + game detour hooks (v2, session 9).
//
// Design (PLAN.md R1/R5/R10, Arxan-style runtime-decrypted .text):
//  - Installed AS dbghelp.dll in the game dir; forwards all 268 exports to the
//    real System32 dbghelp via jmp [rip+disp32] stubs (same-name linker
//    forwarders FAIL 0xC000007B on this OS — dev/fwdtest/).
//  - Detours: 5-byte E9 with instruction-aligned trampolines in one near page,
//    arg-safe generic thunk (hooks.asm), atomic 8-byte CAS patch — see
//    hookcore.c. Every target is poll-and-compare verified against expected
//    runtime-decrypted prologue bytes before patching (on-disk bytes are
//    untrustworthy; ~half of .text is encrypted at rest).
//  - Stages (AOE2LAN_STAGE env): 1 = default, safe idle, no game-code patches.
//    4 = the four provider-cluster detours (M0.3). 6 = the five M0.2 logging
//    detours. 5 = both sets.
//  - M0.2 sites (session-8 §8f, verified in the decrypted dump this session):
//      0x1403503A0  fn containing both 'starting online hosting'/'starting LAN
//                   hosting' leas (0x140351399/0x14035143B) — hosting decision
//      0x1403593C0  'Adding LAN relay server: %s, GUID %s' fn
//      0x14039AAF0  login-response field getter (rcx=obj, rdx=out, r8=key) —
//                   logs every key containing "relay"
//      0x140771600  fn containing BattleServerRelay::Start's log site
//      0x1402BCB30  rlink log helper (rdx = format string, keyword-filtered) —
//                   never encrypted on disk, installs immediately
//  - Log: logs/lanhook-<pid>.log. Hooks in BsSndRpt64.exe are suppressed
//    (excluded by exe-name gate).
//
// Build: build.cmd (MSVC 14.44 + WinSDK 26100, /MT, kernel32 only).

#include <windows.h>
#include <tlhelp32.h>
#include <stdint.h>
#include "hookcore.h"
#include "iathook.h"
#include "loginsrv.h"

// ---------------------------------------------------------------- stages:
// 7 = IAT intercept only (no E9 game-code patches): log all WinHTTP/WININET
//     traffic at the decrypted-data layer. Capture run for M1 synthesis.
// 8 = H1 LoginShim: IAT + rlink DNS redirect + in-DLL TLS login server +
//     trust injection + LogHelper detours (proven clean fns 0x1402BCB30 +
//     0x1402ABC80) for the rlink log view.

// ---------------------------------------------------------------- proxy
#define MAX_EXPORTS 300
__declspec(dllexport) FARPROC g_Real[MAX_EXPORTS];
static int g_nReal = 0;

static DWORD64 g_Base = 0;

#include "stubs.inc"   // g_Exp[] table, DBG_TOTAL

// ---------------------------------------------------------------- hook defs
// expected prologue bytes = runtime-decrypted bytes verified in
// dev/lanhook/gametext.bin (dumped from a live game, t=70s) this session.
static const BYTE EXP_SUSP[8] = {0x40,0x53,0x48,0x83,0xEC,0x20,0x48,0x8B}; // OnAppSuspending
static const BYTE EXP_RESM[8] = {0x40,0x53,0x48,0x83,0xEC,0x30,0x48,0x8B}; // OnAppResumed
static const BYTE EXP_ST1[8]  = {0x40,0x57,0x48,0x83,0xEC,0x20,0x48,0x8D}; // TComm_Stats_RL cb1
static const BYTE EXP_ST2[8]  = {0x89,0x54,0x24,0x10,0x48,0x83,0xEC,0x38}; // TComm_Stats_RL cb2
static const BYTE EXP_HOST[8] = {0x48,0x8B,0xC4,0x48,0x89,0x58,0x10,0x48}; // hosting decision fn
static const BYTE EXP_ADDL[8] = {0x48,0x89,0x5C,0x24,0x18,0x55,0x56,0x57}; // add LAN relay fn
static const BYTE EXP_GETT[8] = {0x40,0x56,0x57,0x41,0x55,0x48,0x83,0xEC}; // field getter
static const BYTE EXP_STRT[8] = {0x48,0x89,0x5C,0x24,0x10,0x48,0x89,0x74}; // Start-adjacent fn
static const BYTE EXP_LOGH[8] = {0x48,0x89,0x54,0x24,0x10,0x4C,0x89,0x44}; // rlink log helper
// TLS inspection set (session 15): statically linked OpenSSL 1.1.1g /
// tsi fns, decrypted-at-runtime == on-disk bytes (verified in gametext.bin
// vs the exe this session), poll-and-compare installed like the LogHelpers.
//  - CTXSetVerify: SSL_CTX_set_verify(ctx, mode, cb) — which ctx verifies
//    how (mode) and with what callback. cb==NULL + mode==1 (SSL_VERIFY_PEER)
//    = default OpenSSL verify; a nonzero cb is the game's own verifier.
//  - CTXSetStore:  SSL_CTX_set_cert_store(ctx, store) — the actual trust
//    store pointer per ctx. Compare vs the SystemCertsWin pool store.
//  - StoreAddCert:  X509_STORE_add_cert(store, cert) — every cert entering
//    every store (pool build + login channel), with the store pointer.
static const BYTE EXP_SETVERIFY[8] = {0x89,0x91,0x58,0x01,0x00,0x00,0x4C,0x89};
static const BYTE EXP_SETSTORE[8]   = {0x48,0x89,0x5C,0x24,0x08,0x57,0xB8,0x20};
static const BYTE EXP_ADDCERT[8]    = {0xB8,0x28,0x00,0x00,0x00,0xE8,0x56,0x0E};

HOOKDEF g_Hooks[] = {
    // ids 0-3: provider cluster, CLEAN ON DISK (stage 4). Tolerated by the
    // integrity system (full supervised skirmish survived, 2026-11-02).
    {"OnAppSuspending", 0x140F19680, EXP_SUSP,   60000,  1, HK_RAW   },
    {"OnAppResumed",    0x140F196F0, EXP_RESM,   60000,  1, HK_RAW   },
    {"Stats1",          0x140F1C900, EXP_ST1,    60000,  1, HK_RAW   },
    {"Stats2",          0x140F1CAB0, EXP_ST2,    60000,  1, HK_RAW   },
    // ids 4,5: the two rlink/BattleServerRelay log helpers, CLEAN ON DISK,
    // proven SAFE + productive (stage 6 / M0.2 logging set).
    {"LogHelper",       0x1402BCB30, EXP_LOGH,  600000,  2, HK_RDSTR },
    {"LogHelper2",      0x1402ABC80, EXP_LOGH,  600000,  2, HK_RDSTR },
    // ids 5-8: ENCRYPTED-ON-DISK fns. Single-hook tests 2026-11-02: patching
    // any of them => deterministic clean exit ~5.6s (Arxan tamper response).
    // grp=0 => no stage selects them; reachable only via AOE2LAN_HOOKS for
    // experiments. Do NOT enable for real runs.
    {"HostDecision",    0x1403503A0, EXP_HOST,  600000,  0, HK_RAW   },
    {"AddLANRelay",     0x1403593C0, EXP_ADDL,  600000,  0, HK_RAW   },
    {"RelayGetter",     0x14039AAF0, EXP_GETT,  600000,  0, HK_R8STR },
    {"StartAdjacent",   0x140771600, EXP_STRT,  600000,  0, HK_RAW   },
    // ids 10-12: TLS inspection set (session 15, CLEAN ON DISK — same rule
    // as LogHelpers: E9 detours install and survive; install set = data-side
    // logging only, trampoline runs the original fns untouched).
    {"CTXSetVerify",   0x14292BC30, EXP_SETVERIFY, 600000, 3, HK_TLS   },
    {"CTXSetStore",    0x14292BA40, EXP_SETSTORE,  600000,  3, HK_TLS   },
    {"StoreAddCert",   0x14297D450, EXP_ADDCERT,   600000,  3, HK_TLS   },
    // id 13: the rlink WARN/ERROR log sink — CLEAN ON DISK, byte-identical
    // prologue to LogHelper (same function family). It carries the two signals
    // the H1 event-push work is blind without:
    //   "WebSocketConnection - failed to parse notification messages [%s]"
    //   "Enum changed on the server <Event>::Result" (the resultCode probe)
    {"LogWarn",         0x1402BCC00, EXP_LOGH,  600000,  2, HK_RDSTR },
};
const int g_NHooks = (int)(sizeof(g_Hooks)/sizeof(g_Hooks[0]));

// ---------------------------------------------------------------- SymFromAddr hook
static LONG g_nSym = 0;

typedef struct { ULONG SizeOfStruct; ULONG TypeIndex; unsigned long long Reserved[2]; ULONG Index; ULONG Size; unsigned long long ModBase; ULONG Flags; unsigned long long Value; unsigned long long Address; ULONG Register; ULONG Scope; ULONG Tag; ULONG NameLen; ULONG MaxNameLen; char Name[1]; } MY_SYMBOL_INFO;
BOOL WINAPI Hook_SymFromAddr(HANDLE hProcess, DWORD64 Address,
                             DWORD64 *Displacement, MY_SYMBOL_INFO *Symbol) {
    typedef BOOL (WINAPI *PFN)(HANDLE, DWORD64, DWORD64*, MY_SYMBOL_INFO*);
    static PFN real = NULL;
    LONG n;
    if (!real) {
        for (int i = 0; i < DBG_TOTAL; i++)
            if (g_Exp[i].ord == 1219) { real = (PFN)g_Real[i]; break; }
    }
    n = InterlockedIncrement(&g_nSym);
    if (n <= 64) logf1("SymFromAddr hit addr=", Address);
    if (n == 65) log_line("SymFromAddr hits capped at 64 log lines");
    if (!real) { SetLastError(ERROR_PROC_NOT_FOUND); return FALSE; }
    return real(hProcess, Address, Displacement, Symbol);
}

// ---------------------------------------------------------------- probes
static void probe_exec(void) {
    BYTE p = 0;
    __try {
        p = *(volatile BYTE*)(g_Base + (0x140F19680 - 0x140000000));
        logf1("probe: OnAppSuspending byte readable =", (DWORD64)p);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        log_line("probe: OnAppSuspending byte NOT readable (guarded page)");
    }
}

static void probe_self(void) {
    DWORD pid = GetCurrentProcessId();
    DWORD ppid = 0;
    { HANDLE snap = CreateToolhelp32Snapshot(2, 0);
      if (snap != INVALID_HANDLE_VALUE) {
          PROCESSENTRY32W e; e.dwSize = sizeof(e);
          if (Process32FirstW(snap, &e)) do {
              if (e.th32ProcessID == pid) { ppid = e.th32ParentProcessID; break; }
          } while (Process32NextW(snap, &e));
          CloseHandle(snap);
      } }
    logf1("self pid=", (DWORD64)pid);
    logf1("self ppid=", (DWORD64)ppid);
    { WCHAR cmdcp[256]; WCHAR *c0 = GetCommandLineW(); int q=0;
      while (q<255 && c0[q]) { cmdcp[q]=c0[q]; q++; } cmdcp[q]=0;
      { WCHAR *cmd = cmdcp; char b[320]; int i=0;
        const char *m="cmdline="; while(*m) b[i++]=*m++;
        for (int k=0;k<200 && cmd[k];k++) b[i++]=(cmd[k]<128)?(char)cmd[k]:'?';
        b[i]=0; log_line(b); } }
    { WCHAR mod[260]; DWORD n = GetModuleFileNameW(NULL, mod, 260);
      char b[320]; int i=0; const char *m="exepath="; while(*m) b[i++]=*m++;
      for (DWORD k=0;k<n && i<300;k++) b[i++]=(mod[k]<128)?(char)mod[k]:'?';
      b[i]=0; log_line(b); }
}

static int is_game_exe(void) {
    const WCHAR *suf = L"aoe2de_s.exe";
    int sl = 0; while (suf[sl]) sl++;
    WCHAR m[300]; DWORD n = GetModuleFileNameW(NULL, m, 300);
    if (n == 0 || n >= 300 || n < (DWORD)sl) return 0;
    for (int i = 0; i < sl; i++) {
        WCHAR a = m[n-sl+i], b = suf[i];
        if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
        if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
        if (a != b) return 0;
    }
    return 1;
}

// ---------------------------------------------------------------- worker
static signed char g_HState[HK_MAX];
static DWORD g_Stage = 1;
static signed char g_Only[HK_MAX];   // set when AOE2LAN_HOOKS restricts installs

// ---------------------------------------------------------------- MP unlock
// Session 23. The Multiplayer button is disabled because rlink's
// WorldwideAccountService::HasPlatformPrivilege (0x14051a390, ENCRYPTED on
// disk) needs a live platform user: it calls the platform object's vtable
// slot 0xb8 ("user signed in"), and only then slot 0xc8 (HasPrivilege).
// Both answer no without an XAL user, so no privilege ever arrives.
//
// We do not touch .text. We re-point three slots of rlink's XboxPlatform
// vtable (0x143669fc0, plain .rdata, never encrypted) at these stubs.
// In-memory only, nothing on disk changes, restored by relaunch. Opt-in:
// AOE2LAN_MPUNLOCK=1.
typedef int (*PfnPlatBool)(void *self);
typedef int (*PfnPlatPriv)(void *self, int priv, void *out, unsigned char b);
typedef int (*PfnPlatState)(void *self, int priv, unsigned char b);

static int pv_signed_in(void *self) { (void)self; return 1; }
static int pv_has_priv(void *self, int priv, void *out, unsigned char b) {
    (void)self; (void)priv; (void)out; (void)b; return 1;
}
static int pv_priv_state(void *self, int priv, unsigned char b) {
    (void)self; (void)priv; (void)b; return 0;   // 0 = allowed
}

static int getenv_flag(const WCHAR *name) {
    WCHAR v[8]; DWORD n = GetEnvironmentVariableW(name, v, 8);
    return n > 0 && v[0] != L'0';
}

static void mp_unlock(void) {
    static const struct { DWORD64 va; DWORD64 orig; void *repl; const char *what; } P[] = {
        { 0x14366A078, 0x1403BA0F0, (void*)&pv_signed_in,  "slot 0xb8 user-signed-in" },
        { 0x14366A080, 0x1403B7200, (void*)&pv_has_priv,   "slot 0xc0 HasPrivilege"    },
        { 0x14366A088, 0x1403B7270, (void*)&pv_priv_state, "slot 0xc8 privilege state" },
    };
    for (unsigned k = 0; k < sizeof(P)/sizeof(P[0]); k++) {
        DWORD64 *slot = (DWORD64*)(g_Base + (P[k].va - (DWORD64)0x140000000));
        // the loader relocates every pointer in .rdata with the image, so the
        // stock slot value is imagebase-relative, not the static 0x140000000 one.
        if ((*slot - g_Base) != (P[k].orig - (DWORD64)0x140000000)) {
            char b[160]; int i = 0; const char *m = "mpunlock: slot mismatch, skipped ";
            while (*m) b[i++]=*m++;
            for (int j=0; P[k].what[j] && i<90; j++) b[i++]=P[k].what[j];
            { const char *t="; found rva="; while (*t) b[i++]=*t++;
              DWORD64 v = *slot - g_Base;
              for (int s=11;s>=0;s--) b[i++]="0123456789abcdef"[(v>>(s*4))&15]; }
            b[i]=0; log_line(b); continue;
        }
        { DWORD old;
          if (!VirtualProtect(slot, 8, PAGE_READWRITE, &old)) {
              log_line("mpunlock: VirtualProtect failed"); continue; }
          *slot = (DWORD64)P[k].repl;
          VirtualProtect(slot, 8, old, &old); }
        { char c[128]; int j=0; const char *t="mpunlock: patched ";
          while (*t) c[j++]=*t++;
          for (int q=0; P[k].what[q]; q++) c[j++]=P[k].what[q];
          c[j++]=' ';
          { const char *o = (*slot == (DWORD64)P[k].repl) ? "OK" : "VERIFY FAILED";
            while (*o) c[j++]=*o++; }
          c[j]=0; log_line(c); }
    }
    log_line("mpunlock: platform vtable re-pointed (in-memory only)");
}

static DWORD WINAPI MainThread(LPVOID p) {
    (void)p;
    { WCHAR v[16]; DWORD sz = 16; v[0]=0;
      GetEnvironmentVariableW(L"AOE2LAN_STAGE", v, 16);
      if (v[0]==L'4') g_Stage=4;
      else if (v[0]==L'5') g_Stage=5;
      else if (v[0]==L'6') g_Stage=6;
      else if (v[0]==L'7') g_Stage=7;
      else if (v[0]==L'8') g_Stage=8;
      else g_Stage=1; }
    { char b[64]; const char *m="LanHookThread stage="; int i=0; while(*m) b[i++]=*m++;
      b[i++]=(char)('0'+(int)g_Stage); b[i]=0; log_line(b); }
    // AOE2LAN_HOOKS: comma-separated 0-based hook ids, install ONLY those
    { WCHAR v[64]; v[0]=0;
      if (GetEnvironmentVariableW(L"AOE2LAN_HOOKS", v, 64) && v[0]) {
          int id = -1; int any = 0;
          for (int i = 0; ; i++) {
              WCHAR c = v[i];
              if (c >= L'0' && c <= L'9') {
                  if (id < 0) id = 0;
                  id = id * 10 + (int)(c - L'0');
              } else {
                  if (id >= 0 && id < g_NHooks) { g_Only[id] = 1; any = 1; }
                  else if (id >= g_NHooks) {
                      // Never accept an id with no hook def: it would set
                      // onlyAny and silently suppress every real install.
                      char b[64]; int i=0; const char *m="hook filter: id out of range, skipped: ";
                      while(*m) b[i++]=*m++;
                      { char t[12]; int tl=0; int v=id;
                        do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
                        while(tl) b[i++]=t[--tl]; }
                      b[i]=0; log_line(b); }
                  id = -1;
              }
              if (!c) break;
          }
          if (any) {
              // print indices WITH names: index mistakes (session 13: 9 vs 5)
              // must be visible in the log, never silent.
              char b[192]; int i=0; const char *m="hook filter: only ";
              while(*m) b[i++]=*m++;
              for (int k=0;k<g_NHooks && i<180;k++) if (g_Only[k]) {
                  b[i++]=(char)('0'+k); b[i++]=':';
                  { const char *nm = g_Hooks[k].name; int j=0;
                    while (nm[j] && i<186) b[i++]=nm[j++]; }
                  b[i++]=','; }
              if (i>0) i--;
              b[i]=0; log_line(b);
          }
      } }
    if (!g_Base) g_Base = (DWORD64)GetModuleHandleW(NULL);
    hc_set_modbase(g_Base);
    if (!is_game_exe()) { log_line("not AoE2DE_s.exe (reporter/other): idle"); return 0; }
    if (g_Stage == 7) {
        // M1 capture: IAT intercept, no game-code patches at all.
        int n = iathook_patch_module((HMODULE)g_Base);
        { char b[80]; int i=0; const char *m="iathook: swapped ";
          while(*m) b[i++]=*m++;
          { char t[12]; int tl=0; int v=n;
            do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
            while(tl) b[i++]=t[--tl]; }
          { const char *t=" IAT slots (winhttp+wininet+libHC+ws2+wsock+crypt32+k32)"; while(*t) b[i++]=*t++; }
          b[i]=0; log_line(b); }
        return 0;
    }
    if (g_Stage == 8) {
        // M1 H1: IAT intercept + rlink redirect + login server, plus the two
        // proven-clean log-helper detours (group 2) for the rlink log view.
        g_IatRedirect = 1;
        { int n = iathook_patch_module((HMODULE)g_Base);
          { char b[80]; int i=0; const char *m="iathook: swapped ";
            while(*m) b[i++]=*m++;
            { char t[12]; int tl=0; int v=n;
              do { t[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
              while(tl) b[i++]=t[--tl]; }
            { const char *t=" IAT slots (winhttp+wininet+libHC+ws2+wsock+crypt32+k32)"; while(*t) b[i++]=*t++; }
            b[i]=0; log_line(b); } }
        if (!loginsrv_start()) log_line("loginsrv: START FAILED");
        g_LoginInjectCert = loginsrv_inject_cert();
        log_line("LanHookThread stage=8 (H1): redirect+server live, installing LogHelpers");
        // stage 8: force the AOE2LAN_HOOKS filter to the proven-clean
        // log-sink detours (group 2: LogHelper, LogHelper2, LogWarn) plus the
        // TLS set (group 3) unless the operator overrode it. Group-based on
        // purpose: encrypted-on-disk targets all sit in grp 0 and must never
        // be reachable from a stage.
        { int any = 0;
          for (int k=0;k<HK_MAX;k++) if (g_Only[k]) any = 1;
          if (!any) { for (int k=0;k<g_NHooks;k++)
                  if (g_Hooks[k].grp == 2 || g_Hooks[k].grp == 3) g_Only[k] = 1;
              log_line("hook filter: log sinks (grp2) + TLS set (grp3)"); } }
        goto install_loop;
    }
install_loop:
    if (g_Stage <= 1) { log_line("stage1: safe idle, no game-code patches"); return 0; }
    log_line("LanHookThread: enter");
    probe_self();
    { BYTE *probe = (BYTE*)(g_Base + (0x140F19680 - 0x140000000));
      hc_alloc_near(probe); }
    logf1("near page=", (DWORD64)hc_near_page());
    probe_exec();
    { int grpMask = (g_Stage==4) ? 1 : (g_Stage==6) ? 2 : 7;   // 5/7/8: groups 2|3 = LogHelpers + TLS set
      int onlyAny = 0;
      for (int k=0;k<HK_MAX;k++) if (g_Only[k]) onlyAny = 1;
      DWORD t0 = GetTickCount();
      for (;;) {
          int pending = 0;
          for (int k=0;k<g_NHooks;k++) {
              if (g_HState[k]) continue;
              if (onlyAny) { if (!g_Only[k]) { g_HState[k] = -2; continue; } }
              else if (!(grpMask & g_Hooks[k].grp)) { g_HState[k] = -2; continue; }
              if (GetTickCount()-t0 > g_Hooks[k].waitMs) {
                  g_HState[k] = -3;
                  { char b[96]; int i=0; const char *m="timeout, never decrypted: ";
                    while(*m) b[i++]=*m++;
                    { const char *nm = g_Hooks[k].name; int j=0;
                      while (nm[j] && i < 90) b[i++]=nm[j++]; }
                    b[i]=0; log_line(b); }
                  continue;
              }
              { BYTE *t = (BYTE*)(g_Base + (g_Hooks[k].va - (DWORD64)0x140000000));
                if (hc_match_now(t, g_Hooks[k].exp)) {
                    logf1("target clean, installing ", g_Hooks[k].va);
                    g_HState[k] = hc_install_hook(t, k) ? 1 : -1;
                } else pending++; }
          }
          if (!pending) break;
          Sleep(200);
      } }
    if (getenv_flag(L"AOE2LAN_MPUNLOCK")) mp_unlock();
    else log_line("mpunlock: off (AOE2LAN_MPUNLOCK unset)");
    log_line("LanHookThread: install loop done");
    return 0;
}

// ---------------------------------------------------------------- real dbghelp
static BOOL resolve_real(void) {
    WCHAR sysdir[MAX_PATH];
    UINT sl = GetSystemDirectoryW(sysdir, MAX_PATH);
    if (!sl || sl > MAX_PATH - 20) return FALSE;
    { WCHAR *p = sysdir + sl; *p++=L'\\'; *p++=L'd'; *p++=L'b'; *p++=L'g';
      *p++=L'h'; *p++=L'e'; *p++=L'l'; *p++=L'p'; *p++=L'.'; *p++=L'd';
      *p++=L'l'; *p++=L'l'; *p++=0; }
    { HMODULE h = LoadLibraryExW(sysdir, NULL, LOAD_WITH_ALTERED_SEARCH_PATH);
      if (!h) return FALSE;
      for (int i = 0; i < DBG_TOTAL; i++) {
          FARPROC a = g_Exp[i].name ? GetProcAddress(h, g_Exp[i].name)
                                    : GetProcAddress(h, (LPCSTR)(DWORD_PTR)(WORD)g_Exp[i].ord);
          g_Real[i] = a;
      }
      g_nReal = DBG_TOTAL;
      return TRUE; }
}

// ---------------------------------------------------------------- crash / hang view
// Two in-process deaths look identical in the log: a crash truncates it
// mid-sequence, a hang truncates it while the process is still alive. This
// filter names the faulting address and the module that owns it, and dumps the
// stack words that land inside the game image (pseudo-backtrace); the
// heartbeat thread proves liveness so a truncation means hang vs crash.
// Process-level APIs only: nothing here patches game code.
static int cput(char *b, int i, const char *s) { while (*s) b[i++] = *s++; return i; }
static int chx(char *b, int i, DWORD64 v) {
    const char *hx = "0123456789abcdef";
    for (int sh = 60; sh >= 0; sh -= 4) b[i++] = hx[(v >> sh) & 0xF];
    return i;
}
static int cpct(char *b, int i, unsigned long long v) {
    char t[24]; int tl = 0;
    if (!v) t[tl++] = '0';
    while (v && tl < 22) { t[tl++] = (char)('0' + (int)(v % 10)); v /= 10; }
    while (tl) b[i++] = t[--tl];
    return i;
}
// owning module of an address: walk back to a PE header that is actually mapped
static int mod_of(DWORD64 a, DWORD64 *base, DWORD64 *size) {
    DWORD64 p = a & ~(DWORD64)0xFFFF;
    MEMORY_BASIC_INFORMATION mbi;
    for (int k = 0; k < 512 && p > 0x10000; k++, p -= 0x10000) {
        if (!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))) break;
        if (mbi.State != MEM_COMMIT || (mbi.Protect & PAGE_NOACCESS)) continue;
        __try {
            if (*(WORD*)p == 0x5A4D) {
                DWORD lf = *(DWORD*)(p + 0x3C);
                DWORD64 nt = p + lf;
                if (lf < 0x1000 && *(DWORD*)nt == 0x00004550) {
                    *base = (DWORD64)mbi.AllocationBase;
                    *size = ((DWORD*)(nt + 0x18))[1];   // SizeOfImage
                    return 1;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) { }
    }
    *base = 0; *size = 0;
    return 0;
}
static LONG WINAPI LanCrashFilter(EXCEPTION_POINTERS *ep) {
    EXCEPTION_RECORD *er = ep->ExceptionRecord;
    DWORD64 a = (DWORD64)er->ExceptionAddress, b = 0, sz = 0;
    char buf[512]; int i = 0;
    i = cput(buf, i, "CRASH code=0x");
    { char t[16]; int tl = 0; DWORD v = (DWORD)er->ExceptionCode;
      if (!v) t[tl++] = '0';
      while (v && tl < 15) { t[tl++] = (char)('0' + (v & 0xF) + ((v & 0xF) > 9 ? 39 : 0)); v >>= 4; }
      while (tl) buf[i++] = t[--tl]; }
    i = cput(buf, i, " at=0x");  i = chx(buf, i, a);
    if (a >= g_Base && a < g_Base + 0x5000000) {
        i = cput(buf, i, " game+0x"); i = chx(buf, i, a - g_Base); }
    if (mod_of(a, &b, &sz) && b) {
        i = cput(buf, i, " modBase=0x"); i = chx(buf, i, b);
        i = cput(buf, i, " +0x"); i = chx(buf, i, a - b);
        i = cput(buf, i, " size=0x"); i = chx(buf, i, sz); }
    if (er->NumberParameters > 1) {
        i = cput(buf, i, " p1=0x"); i = chx(buf, i, er->ExceptionInformation[1]); }
    buf[i] = 0; log_line(buf);
    if (ep->ContextRecord) {                      // stack words inside the game image
        DWORD64 *sp = (DWORD64*)ep->ContextRecord->Rsp;
        int n = 0;
        for (int k = 0; k < 96 && sp; k++) {
            MEMORY_BASIC_INFORMATION mbi;
            if (!VirtualQuery((LPCVOID)(sp + k), &mbi, sizeof(mbi))) break;
            if (mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) break;
            DWORD64 v = 0;
            __try { v = sp[k]; } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
            if (v >= g_Base && v < g_Base + 0x5000000) {
                char l[128]; int j = 0;
                j = cput(l, j, "CRASH stack["); j = cpct(l, j, (unsigned long long)k);
                j = cput(l, j, "] game+0x"); j = chx(l, j, v - g_Base);
                l[j] = 0; log_line(l);
                if (++n >= 10) break;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;             // let the game's own handler run
}
static DWORD WINAPI HeartbeatThread(LPVOID p) {
    (void)p;
    for (int k = 1;; k++) {
        Sleep(5000);
        char b[64]; int i = 0;
        i = cput(b, i, "hb alive sec="); i = cpct(b, i, (unsigned long long)k * 5);
        b[i] = 0; log_line(b);
        if (k > 4000) break;
    }
    return 0;
}

// ---------------------------------------------------------------- dllmain
BOOL WINAPI DllMain(HINSTANCE hMod, DWORD reason, LPVOID pvRes) {
    (void)pvRes;
    if (reason == DLL_PROCESS_ATTACH) {
        DWORD t0 = GetTickCount();
        g_Base = (DWORD64)GetModuleHandleW(NULL);
        DisableThreadLibraryCalls(hMod);
        CreateDirectoryW(L"logs", NULL);
        { WCHAR fn[64]; WCHAR *w = fn; const WCHAR *pre = L"logs\\lanhook-";
          DWORD pid = GetCurrentProcessId(); WCHAR tmp[12]; int tl=0;
          while (*pre) *w++ = *pre++;
          if (!pid) tmp[tl++] = L'0';
          { WCHAR rev[12]; int rl=0; DWORD v=pid;
            while (v) { rev[rl++]=(WCHAR)(L'0'+(v%10)); v/=10; }
            while (rl--) tmp[tl++]=rev[rl]; }
          for (int i=0;i<tl;i++) *w++ = tmp[i];
          *w++=L'.'; *w++=L'l'; *w++=L'o'; *w++=L'g'; *w++=0;
          { HANDLE h = CreateFileW(fn, GENERIC_WRITE, FILE_SHARE_READ,
                                NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            hc_set_log(h, t0); } }
        { WCHAR me[260]; DWORD nl = GetModuleFileNameW(hMod, me, 260);
          char b[320]; int i=0; const char *m="lanhook v2 boot in ";
          while(*m) b[i++]=*m++;
          for (DWORD k=0;k<nl && i<300;k++) b[i++]=(me[k]<128)?(char)me[k]:'?';
          b[i]=0; log_line(b); }
        log_line("lanhook boot: dbghelp proxy attached");
        logf1("game base=", g_Base);
        if (!resolve_real()) {
            log_line("FATAL: could not load real dbghelp from System32");
            return TRUE;
        }
        log_line("real dbghelp resolved");
        { LPTOP_LEVEL_EXCEPTION_FILTER prev = SetUnhandledExceptionFilter(LanCrashFilter);
          logf1("crash filter installed, prev=", (DWORD64)prev); }
        { HANDLE h = CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);
          if (h) CloseHandle(h); else log_line("heartbeat thread failed"); }
        { HANDLE h = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
          if (h) CloseHandle(h); else { log_line("CreateThread failed"); return FALSE; } }
    }
    return TRUE;
}
