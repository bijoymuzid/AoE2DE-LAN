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
static const BYTE EXP_WSET[8]       = {0x48,0x8B,0x81,0xD8,0x03,0x00,0x00,0x90}; // 0x140ab6300 widget SetStateFlags
static const BYTE EXP_AISLOT[8]     = {0x48,0x83,0xEC,0x28,0x48,0x81,0xC1,0x80}; // 0x140d62260 sub rsp,0x28; add rcx,0x680
static const BYTE EXP_LOCID[8]      = {0x40,0x53,0x48,0x83,0xEC,0x20,0x8B,0xD9}; // 0x140ac5480 push rbx; sub rsp,0x20; mov ebx,ecx
static const BYTE EXP_GLG[8]        = {0x4C,0x89,0x44,0x24,0x18,0x4C,0x89,0x4C}; // 0x1407db520 mov [rsp+0x18],r8; mov [rsp+0x20],r9

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
    // id 14: widget SetStateFlags (0x140ab6300), CLEAN ON DISK, grp=0 (opt-in via
    // AOE2LAN_HOOKS=4,5,13,14 only). Logs (name, oldf, newf, caller) deduped.
    {"WidgetSetEn",     0x140AB6300, EXP_WSET,  600000,  0, HK_WSET  },
    // id 15: the AI-slot picker 0x140d62260, CLEAN ON DISK, grp=0 (opt-in via
    // AOE2LAN_HOOKS). The multiplayer host lobby's NameDropDown builder
    // (0x1ab4bd0) fills its AI items from table[kind].vec, so this logs the kind
    // the lobby asks for and how many AIs that slot holds. Read-only unless
    // AOE2LAN_AIKIND=n is set.
    {"AISlotPick",      0x140D62260, EXP_AISLOT, 600000, 0, HK_AISLOT },
    // id 16: localize-string-by-id 0x140ac5480, CLEAN ON DISK, grp=0 (opt-in via
    // AOE2LAN_HOOKS). Filtered to the host lobby's slot-dropdown populator
    // 0x1a344f0..0x1a362aa: the (call site, string id) pair names the exact
    // dropdown item being built, so one run shows which of the three item blocks
    // ran. Also reads screen+0x1cf8 (rsi) against the sentinel at [0x14326b258] -
    // the single field that gates BOTH the "AI" item and the settings-row locks.
    // Read-only unless AOE2LAN_AIGATE=1, which writes the sentinel into the field.
    {"AISlotLabel",     0x140AC5480, EXP_LOCID, 600000, 0, HK_LOCID  },
    // id 17 (s43 N13): the CLEAN vsnprintf helper 0x1407db520, grp=0 (opt-in via
    // AOE2LAN_HOOKS). Caller-filtered to the two sites inside the game-layer log
    // fn 0x140f19210 / 0x140f192f0, which is ENCRYPTED on disk and so unhookable.
    // Logs (category, format string) deduped - the only view we have ever had
    // above rlink. READ ONLY. See hookcore.c HK_GLOG for the register proof.
    {"GLog",            0x1407DB520, EXP_GLG,   600000, 0, HK_GLOG   },
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
// Session 26: the s23/s25 target was wrong. The read-only map proved the live
// platform object carries vtable 0x14366b450 (plain member getters), NOT
// 0x143669fc0 -- so those three slots were never on the privilege path. The
// real chain, measured at runtime and verified against the shipped .rdata:
//   svc = [platform+0x1818]  vtable 0x14366f848
//     +0xb0  keyed readiness query (0 = present, 2 = not ready)
//   usr = [platform+0x12f8]  vtable 0x143670a10
//     +0xb8  signed-in user name (bool)
//     +0xc8  HasPrivilege (0 allowed, 1 ?, 2 unsupported)
// HasPlatformPrivilege (0x14051a390) fails at the first of these for the key
// 0x14327ce50 + "state == -1" descriptor, and never reaches the other two.
// Re-point those three slots; the query stub answers only that one key and
// calls the stock implementation for anything else.
// In-memory only, nothing on disk changes, reverted by relaunch. Opt-in:
// AOE2LAN_MPUNLOCK=1.
//
// Session 23 note (superseded but kept for history). The Multiplayer button is disabled because rlink's
// WorldwideAccountService::HasPlatformPrivilege (0x14051a390, ENCRYPTED on
// disk) needs a live platform user: it calls the platform object's vtable
// slot 0xb8 ("user signed in"), and only then slot 0xc8 (HasPrivilege).
// Both answer no without an XAL user, so no privilege ever arrives.
//
// We do not touch .text. We re-point three slots of rlink's XboxPlatform
// vtable (0x143669fc0, plain .rdata, never encrypted) at these stubs.
// In-memory only, nothing on disk changes, restored by relaunch. Opt-in:
// AOE2LAN_MPUNLOCK=1.
typedef int (*PfnQuery)(void *self, void *key);
typedef int (*PfnName)(void *self, void *out);
typedef int (*PfnPriv)(void *self, int priv, void *out, unsigned char b);

// session 26: which path asks? 4 stack words per call, image VAs only, compact.
static void spy_callers(const char *tag, void *self) {
    char b[256]; int i = 0;
    DWORD64 *sp = 0;
    __try { sp = (DWORD64*)_AddressOfReturnAddress(); }   // caller's rsp after the call
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    i = cput(b, i, "callers "); 
    for (const char *t = tag; t && *t && i < 30; t++) b[i++] = *t;
    i = cput(b, i, " self=rva=0x");
    if ((DWORD64)self >= g_Base && (DWORD64)self < g_Base + 0x5000000) i = chx(b, i, (DWORD64)self - g_Base);
    else i = cput(b, i, "heap");
    b[i] = 0; log_line(b);
    if (!sp) return;
    for (int k = 0; k < 12; k++) {
        DWORD64 v = 0;
        __try { v = sp[k]; } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        if (v >= g_Base && v < g_Base + 0x5000000) {
            char l[96]; int j = 0;
            j = cput(l, j, "  ret["); j = cpct(l, j, (unsigned long long)k);
            j = cput(l, j, "] game+0x"); j = chx(l, j, v - g_Base);
            l[j] = 0; log_line(l);
        }
    }
}

static PfnQuery g_OrigSvcQuery = 0;      // stock 0x1405204f0, for the fallthrough
#define MP_KEY_DESC 0x327ce50            // descriptor fa70 builds: [0x14327ce50, .., -1]

// one-shot "called" lines separate "never asked" from "asked" (s25 pattern).
// Answers 0 ("ready") only for the descriptor platform_user_signed_in uses;
// every other key goes to the stock implementation untouched.
static int svc_query(void *self, void *key) {
    static LONG once = 0;
    if (key && (DWORD64)*(volatile DWORD64*)key == g_Base + (MP_KEY_DESC - 0x140000000)
             && *(volatile DWORD64*)((char*)key + 0x10) == (DWORD64)-1) {
        if (!InterlockedExchange(&once, 1)) { log_line("mpunlock: called svc_query (ready key)"); spy_callers("svc0xb0", self); }
        return 0;
    }
    return g_OrigSvcQuery ? g_OrigSvcQuery(self, key) : 2;
}
// "who is signed in" -> bool. The stock fills a std::string; fa70 only reads al,
// but leave a valid empty string behind so nothing downstream sees garbage.
static int usr_signed_in(void *self, void *out) {
    static LONG once = 0; (void)self;
    if (!InterlockedExchange(&once, 1)) { log_line("mpunlock: called usr_signed_in"); spy_callers("usr0xb8", self); }
    if (out) { volatile DWORD64 *q = (volatile DWORD64*)out;   // MSVC std::string, SSO
               q[0] = (DWORD64)out + 0x10; q[1] = 0; q[2] = 7; q[3] = 0; }
    return 1;
}
// HasPrivilege -> 0 = allowed, and the same out struct the stock writes.
static int usr_has_priv(void *self, int priv, void *out, unsigned char b) {
    static LONG once = 0; (void)self; (void)priv; (void)b;
    if (!InterlockedExchange(&once, 1)) { log_line("mpunlock: called usr_has_priv"); spy_callers("usr0xc8", self); }
    if (out) { volatile DWORD32 *d = (volatile DWORD32*)out;
               d[0] = 0; d[1] = 1; d[2] = 0; }
    return 0;
}

// the three slots (plain .rdata, never encrypted), shared with the 1 Hz re-read
static const struct { DWORD64 va; DWORD64 orig; void *repl; const char *what; } g_MpSlots[] = {
    { 0x14366F8F8, 0x1405204F0, (void*)&svc_query,     "svc vtable+0xb0 keyed readiness" },
    { 0x143670AC8, 0x140556D90, (void*)&usr_signed_in, "usr vtable+0xb8 signed-in name"  },
    { 0x143670AD8, 0x1405527B0, (void*)&usr_has_priv,  "usr vtable+0xc8 HasPrivilege"    },
};
static volatile LONG g_MpUnlocked = 0;   // set only when all three slots took
static int g_MpSpy = 0;                   // AOE2LAN_MPSPY: read-only object map
static signed char g_MpReverted[3];

static int getenv_flag(const WCHAR *name) {
    WCHAR v[8]; DWORD n = GetEnvironmentVariableW(name, v, 8);
    return n > 0 && v[0] != L'0';
}

static void mp_unlock(void) {
    int patched = 0;
    for (unsigned k = 0; k < sizeof(g_MpSlots)/sizeof(g_MpSlots[0]); k++) {
        DWORD64 *slot = (DWORD64*)(g_Base + (g_MpSlots[k].va - (DWORD64)0x140000000));
        // the loader relocates every pointer in .rdata with the image, so the
        // stock slot value is imagebase-relative, not the static 0x140000000 one.
        if ((*slot - g_Base) != (g_MpSlots[k].orig - (DWORD64)0x140000000)) {
            char b[160]; int i = 0; const char *m = "mpunlock: slot mismatch, skipped ";
            while (*m) b[i++]=*m++;
            for (int j=0; g_MpSlots[k].what[j] && i<90; j++) b[i++]=g_MpSlots[k].what[j];
            { const char *t="; found rva="; while (*t) b[i++]=*t++;
              DWORD64 v = *slot - g_Base;
              for (int s=11;s>=0;s--) b[i++]="0123456789abcdef"[(v>>(s*4))&15]; }
            b[i]=0; log_line(b); continue;
        }
        { DWORD old;
          if (!VirtualProtect(slot, 8, PAGE_READWRITE, &old)) {
              log_line("mpunlock: VirtualProtect failed"); continue; }
          if (g_MpSlots[k].repl == (void*)&svc_query)
              g_OrigSvcQuery = (PfnQuery)(g_Base + (g_MpSlots[k].orig - (DWORD64)0x140000000));
          *slot = (DWORD64)g_MpSlots[k].repl;
          VirtualProtect(slot, 8, old, &old); }
        { char c[128]; int j=0; const char *t="mpunlock: patched ";
          while (*t) c[j++]=*t++;
          for (int q=0; g_MpSlots[k].what[q]; q++) c[j++]=g_MpSlots[k].what[q];
          c[j++]=' ';
          { const char *o = (*slot == (DWORD64)g_MpSlots[k].repl) ? "OK" : "VERIFY FAILED";
            while (*o) c[j++]=*o++; }
          c[j]=0; log_line(c);
          if (*slot == (DWORD64)g_MpSlots[k].repl) patched++; }
    }
    log_line("mpunlock: privilege-path vtable slots re-pointed (in-memory only)");
    if (patched == (int)(sizeof(g_MpSlots)/sizeof(g_MpSlots[0]))) g_MpUnlocked = 1;
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
                  if (k >= 10) b[i++]=(char)('0'+(k/10));
                  b[i++]=(char)('0'+(k%10)); b[i++]=':';
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
    g_MpSpy = getenv_flag(L"AOE2LAN_MPSPY");
    if (g_MpSpy) log_line("mpspy: on (read-only object map)");
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
// session 25: 1 s re-read of the three re-pointed slots. Logs once per slot
// when it no longer holds our stub — "asked then overruled/reverted" vs
// "never asked" (the one-shot stub lines above).
static void mp_check_slots(void) {
    if (!g_MpUnlocked) return;
    for (unsigned k = 0; k < sizeof(g_MpSlots)/sizeof(g_MpSlots[0]); k++) {
        DWORD64 v = 0;
        if (g_MpReverted[k]) continue;
        __try { v = *(volatile DWORD64*)(g_Base + (g_MpSlots[k].va - (DWORD64)0x140000000)); }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        if (v != (DWORD64)g_MpSlots[k].repl) {
            char b[160]; int i = 0;
            g_MpReverted[k] = 1;
            i = cput(b, i, "mpunlock: slot reverted ");
            for (int j = 0; g_MpSlots[k].what[j] && i < 90; j++) b[i++] = g_MpSlots[k].what[j];
            i = cput(b, i, " now rva=0x"); i = chx(b, i, v - g_Base);
            b[i] = 0; log_line(b);
        }
    }
}
// session 26: read-only object map. s26 re-read of HasPlatformPrivilege shows
// platform.vtbl[0x98] forwards to [this+0x90].vtbl[0x90] and platform.vtbl[0x150]
// is a string-compare bool, so the object behind g_Platform may not own the
// vtable patched in s25. Print the live object, its vtable and the slot values so
// a later re-point is based on measurement, not assumption. Reads only.
#define PLATFORM_GLOBAL 0x4c9e5f0   // [0x144c9e5f0] = rlink platform object
static const unsigned g_SpyOffs[] = { 0x90, 0x98, 0xb0, 0xb8, 0xc0, 0xc8, 0x150, 0x158 };

static void spy_rva(const char *tag, DWORD64 va) {
    char b[160]; int i = 0;
    i = cput(b, i, "mpspy: ");
    for (const char *t = tag; t && *t && i < 40; t++) b[i++] = *t;
    i = cput(b, i, " rva=0x");
    if (va >= g_Base && va < g_Base + 0x5000000) i = chx(b, i, va - g_Base);
    else i = cput(b, i, "outside");
    b[i] = 0; log_line(b);
}

// one interface member of the platform object: pointer, vtable, and the four
// slots the privilege chain calls. Reads only.
static void spy_iface(const char *tag, unsigned off, DWORD64 plat) {
    DWORD64 p = 0, vt = 0;
    __try { p = *(volatile DWORD64*)(plat + off); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    { char b[160]; int i = 0;
      i = cput(b, i, "mpspy: ");
      for (const char *t = tag; t && *t && i < 40; t++) b[i++] = *t;
      i = cput(b, i, " ptr="); i = chx(b, i, p);
      b[i] = 0; log_line(b); }
    if (!p) return;
    __try { vt = *(volatile DWORD64*)p; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    spy_rva("  vtable", vt);
    if (!(vt >= g_Base && vt < g_Base + 0x5000000)) return;
    { const unsigned in[] = { 0xb0, 0xb8, 0xc0, 0xc8 };
      for (unsigned k = 0; k < sizeof(in)/sizeof(in[0]); k++) {
        DWORD64 s = 0;
        __try { s = *(volatile DWORD64*)(vt + in[k]); }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        { char b[160]; int i = 0;
          i = cput(b, i, "mpspy:     slot+0x"); i = chx(b, i, in[k]); i = cput(b, i, " -> ");
          if (s >= g_Base && s < g_Base + 0x5000000) { i = cput(b, i, "rva=0x"); i = chx(b, i, s - g_Base); }
          else i = cput(b, i, "outside");
          b[i] = 0; log_line(b); } }
    }
}

static void mp_spy(void) {
    if (!g_MpSpy) return;
    DWORD64 plat = 0, vt = 0;
    __try { plat = *(volatile DWORD64*)(g_Base + PLATFORM_GLOBAL); }
    __except (EXCEPTION_EXECUTE_HANDLER) { log_line("mpspy: read of platform failed"); return; }
    spy_rva("platform obj", plat);
    if (!plat) { log_line("mpspy: platform is null"); return; }
    __try { vt = *(volatile DWORD64*)plat; }
    __except (EXCEPTION_EXECUTE_HANDLER) { log_line("mpspy: read of vtable failed"); return; }
    spy_rva("platform vtable", vt);
    if (!(vt >= g_Base && vt < g_Base + 0x5000000)) return;
    for (unsigned k = 0; k < sizeof(g_SpyOffs)/sizeof(g_SpyOffs[0]); k++) {
        DWORD64 s = 0;
        __try { s = *(volatile DWORD64*)(vt + g_SpyOffs[k]); }
        __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
        { char b[160]; int i = 0; DWORD64 off = g_SpyOffs[k];
          i = cput(b, i, "mpspy:   slot+"); i = chx(b, i, off);
          i = cput(b, i, " -> ");
          if (s >= g_Base && s < g_Base + 0x5000000) { i = cput(b, i, "rva=0x"); i = chx(b, i, s - g_Base); }
          else i = cput(b, i, "outside");
          b[i] = 0; log_line(b); }
    }
    // the two interface members the privilege chain reads:
    //   [plat+0x1818] -> the object whose vtbl[0xb0] answers the keyed query
    //   [plat+0x12f8] -> the object whose vtbl[0xb8]/[0xc8] answer sign-in/privilege
    spy_iface("[plat+0x1818] svc", 0x1818, plat);
    spy_iface("[plat+0x12f8] usr", 0x12f8, plat);
    spy_iface("[plat+0x1820]",      0x1820, plat);
    spy_iface("[plat+0x1828]",      0x1828, plat);
    spy_iface("[plat+0x1830]",      0x1830, plat);
    spy_iface("[plat+0x1838]",      0x1838, plat);
}

// ---------------------------------------------------------------- UI probe (s27)
// Read-only. Nobody knows the Age2Button vtable (no class-name RTTI, and most of
// .text is Arxan-encrypted on disk so it cannot be found by reading the file).
// The live process does know it: every widget object starts with a pointer to a
// vtable in .rdata whose +0x68 slot is the enabled setter. So scan writable
// memory for such pointers and report the unique vtables whose +0x68 entry
// begins with a "store a byte through rcx" instruction. Nothing is written.
// Opt-in: AOE2LAN_UIW=1.
#define UIW_RDATA0 0x3197000ULL          // .rdata rva window (from the shipped PE)
#define UIW_RDATA1 0x3da60a8ULL
#define UIW_TEXT1  0x3197000ULL          // .text ends here

static int uiw_in_text(DWORD64 v) { return v >= g_Base + 0x1000 && v < g_Base + UIW_TEXT1; }
static int uiw_in_rdata(DWORD64 v) { return v >= g_Base + UIW_RDATA0 && v < g_Base + UIW_RDATA1; }

// does the code at p look like "mov byte ptr [rcx(+disp)], dl" in its first 32 bytes?
static int uiw_setbool(DWORD64 p) {
    int hit = 0;
    __try {
        const BYTE *c = (const BYTE*)p;
        for (int k = 0; k < 32; k++) {
            int b0 = c[k], b1 = c[k + 1];
            if (b0 >= 0x40 && b0 <= 0x4F) { b0 = c[k + 1]; b1 = c[k + 2]; }
            if (b0 == 0x88 && (b1 == 0x51 || b1 == 0x91)) { hit = 1; break; }  // [rcx+d], dl
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return hit;
}

static void uiw_log_vt(DWORD64 vt, unsigned hits) {
    char b[200]; int i = 0;
    i = cput(b, i, "uiw: vtable+0x"); i = chx(b, i, vt - g_Base);
    i = cput(b, i, " objs="); i = cpct(b, i, hits);
    i = cput(b, i, " setter+0x"); i = chx(b, i, *(volatile DWORD64*)(vt + 0x68) - g_Base);
    i = cput(b, i, " bytes=");
    __try {
        const BYTE *c = (const BYTE*)*(volatile DWORD64*)(vt + 0x68);
        for (int k = 0; k < 12 && i < 190; k++) {
            const char *hx = "0123456789abcdef";
            b[i++] = hx[c[k] >> 4]; b[i++] = hx[c[k] & 15];
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { i = cput(b, i, "?"); }
    b[i] = 0; log_line(b);
}

static void ui_widget_probe(void) {
    if (!getenv_flag(L"AOE2LAN_UIW")) return;
    DWORD64 found[64]; unsigned nfound = 0, nvt = 0;
    DWORDLONG scanned = 0;
    BYTE *a = 0;
    MEMORY_BASIC_INFORMATION mbi;
    for (;;) {
        if (!VirtualQuery(a, &mbi, sizeof mbi)) break;
        a = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((DWORD64)mbi.BaseAddress >= g_Base && (DWORD64)mbi.BaseAddress < g_Base + 0x5000000) continue;
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;
        if (mbi.RegionSize > (64u << 20)) continue;          // skip huge reserved blocks
        scanned += mbi.RegionSize;
        for (DWORD64 p = (DWORD64)mbi.BaseAddress; p + 8 <= (DWORD64)mbi.BaseAddress + mbi.RegionSize; p += 8) {
            DWORD64 v = 0;
            __try { v = *(volatile DWORD64*)p; } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (!uiw_in_rdata(v)) continue;
            DWORD64 s0 = 0, s1 = 0, s2 = 0, set = 0;
            __try { s0 = *(volatile DWORD64*)v; s1 = *(volatile DWORD64*)(v + 8);
                    s2 = *(volatile DWORD64*)(v + 16); set = *(volatile DWORD64*)(v + 0x68); }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (!uiw_in_text(s0) || !uiw_in_text(s1) || !uiw_in_text(s2)) continue;
            if (!uiw_in_text(set) || !uiw_setbool(set)) continue;
            unsigned k = 0;
            for (; k < nvt; k++) if (found[k] == v) break;
            if (k < nvt) continue;
            if (nvt < 64) { found[nvt++] = v; uiw_log_vt(v, (unsigned)(p & 0xffffffff)); }
        }
    }
    { char b[120]; int i = 0;
      i = cput(b, i, "uiw: scanned MB="); i = cpct(b, i, scanned >> 20);
      i = cput(b, i, " candidate vtables="); i = cpct(b, i, nvt);
      b[i] = 0; log_line(b); }
}

// Targeted variant: the widget manager's GetWidget(TestKey) call site in the game
// loads the key string "Background/ButtonMultiplayer" from .rdata, so every widget
// object holds that pointer. Find it, then report the object's vtable, the +0x68
// setter and the bytes at the object start. Read-only.
#define UIW_KEY_RVA 0x333af28ULL      // "Background/ButtonMultiplayer" in .rdata

static void ui_widget_keyprobe(void) {
    if (!getenv_flag(L"AOE2LAN_UIW")) return;
    const DWORD64 key = g_Base + UIW_KEY_RVA;
    DWORDLONG scanned = 0; unsigned n = 0;
    BYTE *a = 0;
    MEMORY_BASIC_INFORMATION mbi;
    for (;;) {
        if (!VirtualQuery(a, &mbi, sizeof mbi)) break;
        a = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((DWORD64)mbi.BaseAddress >= g_Base && (DWORD64)mbi.BaseAddress < g_Base + 0x5000000) continue;
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;
        if (mbi.RegionSize > (64u << 20)) continue;
        scanned += mbi.RegionSize;
        for (DWORD64 q = (DWORD64)mbi.BaseAddress; q + 8 <= (DWORD64)mbi.BaseAddress + mbi.RegionSize; q += 8) {
            DWORD64 v = 0;
            __try { v = *(volatile DWORD64*)q; } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (v != key) continue;
            if (n >= 8) continue;
            n++;
            { char b[200]; int i = 0;
              i = cput(b, i, "uiwK: hit at game+0x"); i = chx(b, i, q - g_Base);
              i = cput(b, i, " off_in_obj=-0x");
              b[i] = 0; log_line(b); }
            // the object base is not known; dump the 0x60 bytes before and after the pointer
            for (int back = 1; back <= 3; back++) {
                DWORD64 base = q - 8 * back, vt = 0, set = 0;
                __try { vt = *(volatile DWORD64*)base; set = *(volatile DWORD64*)(vt + 0x68); }
                __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
                { char b[200]; int i = 0;
                  i = cput(b, i, "uiwK:   base=q-"); i = cpct(b, i, 8 * back);
                  i = cput(b, i, " q0=");
                  __try {
                      const BYTE *c = (const BYTE*)base;
                      for (int k = 0; k < 8; k++) { const char *hx = "0123456789abcdef";
                          b[i++] = hx[c[k] >> 4]; b[i++] = hx[c[k] & 15]; }
                  } __except (EXCEPTION_EXECUTE_HANDLER) { i = cput(b, i, "?"); }
                  if (uiw_in_rdata(vt) && uiw_in_text(set)) {
                      i = cput(b, i, " VTBL+0x"); i = chx(b, i, vt - g_Base);
                      i = cput(b, i, " setter+0x"); i = chx(b, i, set - g_Base);
                      i = cput(b, i, " sb="); i = cpct(b, i, (unsigned long long)uiw_setbool(set));
                  } else i = cput(b, i, " no vtbl");
                  b[i] = 0; log_line(b); }
            }
            // byte map of the 0x100 bytes around the pointer, to spot the name field
            { char b[200]; int i = 0;
              unsigned nz = 0;
              __try {
                  const DWORD64 *c = (const DWORD64*)(q - 0x40);
                  for (int k = 0; k < 8; k++) if (c[k]) nz++;
              } __except (EXCEPTION_EXECUTE_HANDLER) { nz = 99; }
              i = cput(b, i, "uiwK:   nonzero qwords in q-0x40..q+0x00: "); i = cpct(b, i, nz);
              b[i] = 0; log_line(b); }
        }
    }
    { char b[120]; int i = 0;
      i = cput(b, i, "uiwK: scanned MB="); i = cpct(b, i, scanned >> 20);
      i = cput(b, i, " hits="); i = cpct(b, i, n);
      b[i] = 0; log_line(b); }
}


// ---------------------------------------------------------------- rule probe (s28)
// Read-only. The Multiplayer button's on/off state is decided by the twin-rule
// table: 0x141b126f0 registers the (enabled, disabled) widget pair,
// 0x141b12d60 fills one status per rule id, 0x141b12a00 evaluates every record,
// 0x141b12410 applies it (visibility of both twins + SetEnabled of the live one).
// Our pair uses ids {2,4,5,8,11,13}; 11 and 12 are constants and 8 needs the
// game's own privilege chain, so this prints 2, 4, 5, 13 and then, once, the live
// record for the pair - its computed status is the number that turns the button
// on or off.  Reads only; nothing here writes game memory.  Opt-in: AOE2LAN_RULES=1.
#define RULES_SVC 0x42dc4f0ULL       // [0x1442dc4f0] + 0x2e8 = online service object
#define RULES_CFG 0x43552b8ULL       // [0x1443552b8] = the settings/online singleton

static int rl_in_module(DWORD64 v) { return v >= g_Base && v < g_Base + 0x5000000; }

static void rl_h(const char *tag, const char *sub, DWORD64 v) {
    char b[160]; int i = 0;
    i = cput(b, i, "rules: "); i = cput(b, i, tag);
    if (sub) i = cput(b, i, sub);
    i = cput(b, i, " = 0x"); i = chx(b, i, v);
    b[i] = 0; log_line(b);
}
static void rl_rva(const char *tag, const char *sub, DWORD64 v) {
    char b[160]; int i = 0;
    i = cput(b, i, "rules: "); i = cput(b, i, tag);
    if (sub) i = cput(b, i, sub);
    i = cput(b, i, " = ");
    if (rl_in_module(v)) { i = cput(b, i, "game+0x"); i = chx(b, i, v - g_Base); }
    else i = cput(b, i, "outside");
    b[i] = 0; log_line(b);
}
static void rl_d(const char *tag, const char *sub, long long v) {
    char b[160]; int i = 0;
    i = cput(b, i, "rules: "); i = cput(b, i, tag);
    if (sub) i = cput(b, i, sub);
    i = cput(b, i, " = ");
    if (v < 0) { b[i++] = '-'; v = -v; }
    i = cpct(b, i, (unsigned long long)v);
    b[i] = 0; log_line(b);
}

typedef int (*PfnVoid)(void *self);
typedef int (*PfnInt)(void *self, int arg);

static int rl_call1(DWORD64 vt, unsigned off, DWORD64 self) {
    int r;
    __try { r = ((PfnVoid)*(volatile DWORD64*)(vt + off))((void*)self); }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = -2; }
    return r;
}
static int rl_call2(DWORD64 vt, unsigned off, DWORD64 self, int arg) {
    int r;
    __try { r = ((PfnInt)*(volatile DWORD64*)(vt + off))((void*)self, arg); }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = -2; }
    return r;
}

static void rules_probe(void) {
    DWORD64 cfg = 0, vt = 0, root = 0, svc = 0;
    if (!getenv_flag(L"AOE2LAN_RULES")) return;
    __try { cfg = *(volatile DWORD64*)(g_Base + RULES_CFG); }
    __except (EXCEPTION_EXECUTE_HANDLER) { cfg = 0; }
    rl_h("cfg", " [0x1443552b8]", cfg);
    if (cfg) {
        __try { vt = *(volatile DWORD64*)cfg; } __except (EXCEPTION_EXECUTE_HANDLER) { vt = 0; }
        rl_rva("cfg", " vtable", vt);
        { DWORD64 b698 = 0; long long d680 = 0, d6b4 = 0;
          __try { b698 = *(volatile BYTE*)(cfg + 0x698); } __except (EXCEPTION_EXECUTE_HANDLER) { b698 = 999; }
          __try { d680 = *(volatile int*)(cfg + 0x680); } __except (EXCEPTION_EXECUTE_HANDLER) { d680 = -999; }
          __try { d6b4 = *(volatile int*)(cfg + 0x6b4); } __except (EXCEPTION_EXECUTE_HANDLER) { d6b4 = -999; }
          rl_d("cfg", " byte+0x698  (rule 13)", (long long)b698);
          rl_d("cfg", " dword+0x680 (rule 15)", d680);
          rl_d("cfg", " dword+0x6b4 (rule 15)", d6b4); }
    }
    __try { root = *(volatile DWORD64*)(g_Base + RULES_SVC); }
    __except (EXCEPTION_EXECUTE_HANDLER) { root = 0; }
    rl_h("svc", " owner [0x1442dc4f0]", root);
    if (root) { __try { svc = *(volatile DWORD64*)(root + 0x2e8); } __except (EXCEPTION_EXECUTE_HANDLER) { svc = 0; } }
    rl_h("svc", " object [+0x2e8]", svc);
    if (svc) {
        __try { vt = *(volatile DWORD64*)svc; } __except (EXCEPTION_EXECUTE_HANDLER) { vt = 0; }
        rl_rva("svc", " vtable", vt);
        if (rl_in_module(vt)) {
            rl_d("svc", " slot+0x80        (rule 0)", (long long)rl_call1(vt, 0x80, svc));
            rl_d("svc", " slot+0x88        (rule 1)", (long long)rl_call1(vt, 0x88, svc));
            rl_d("svc", " slot+0x90        (rule 2)", (long long)rl_call1(vt, 0x90, svc));
            rl_d("svc", " slot+0x308 arg 2 (rule 5)", (long long)rl_call2(vt, 0x308, svc, 2));
            rl_d("svc", " slot+0x308 arg 4 (rule 4)", (long long)rl_call2(vt, 0x308, svc, 4));
            // 0x1418eee60 fills the create-lobby dropdown from the 0x50-stride item
            // vector at owner+0x2628, then appends "Use Local Lan Server"
            // (0x143322df0, index -1) only if this slot returns true.
            { DWORD64 f = 0;
              __try { f = *(volatile DWORD64*)(vt + 0x418); } __except (EXCEPTION_EXECUTE_HANDLER) { f = 0; }
              rl_rva("svc", " slot+0x418 fn", f); }
            rl_d("svc", " slot+0x418 LAN item gate", (long long)rl_call1(vt, 0x418, svc));
        }
    }
    if (root) {
        DWORD64 rb = 0, re = 0;
        __try { rb = *(volatile DWORD64*)(root + 0x2628); } __except (EXCEPTION_EXECUTE_HANDLER) { rb = 0; }
        __try { re = *(volatile DWORD64*)(root + 0x2630); } __except (EXCEPTION_EXECUTE_HANDLER) { re = 0; }
        rl_d("root", " dropdown item count (0x50)", (re >= rb) ? (long long)((re - rb) / 0x50) : -1);
    }
    // rule 2 is "logged in AND leaderboard registry non-empty"; the count is
    // (end-begin)/0xc0 of the vector at 0x1442e18b0.
    { DWORD64 beg = 0, end = 0, mroot = 0;
      __try { beg = *(volatile DWORD64*)(g_Base + 0x42e18b0ULL); } __except (EXCEPTION_EXECUTE_HANDLER) { beg = 0; }
      __try { end = *(volatile DWORD64*)(g_Base + 0x42e18b8ULL); } __except (EXCEPTION_EXECUTE_HANDLER) { end = 0; }
      __try { mroot = *(volatile DWORD64*)(g_Base + 0x42e18c8ULL); } __except (EXCEPTION_EXECUTE_HANDLER) { mroot = 0; }
      rl_h("lb", " registry begin [0x1442e18b0]", beg);
      rl_h("lb", " registry end   [0x1442e18b8]", end);
      rl_h("lb", " registry map   [0x1442e18c8]", mroot);
      rl_d("lb", " definition count", (end >= beg) ? (long long)((end - beg) / 0xc0) : -1); }
}

// Read-only shape scan for the live twin-rule records.  A record is 0x48 bytes:
//   +0 status (int), +8/+0x10 listA (int vector), +0x20/+0x28 listB (int vector),
//   +0x38 enabled widget, +0x40 disabled widget.
// The filter is deliberately strict: both lists non-empty, every id in 0..15, and
// both widget pointers must start with an .rdata vtable.  The status is the number
// that decides whether the live twin is enabled.  Nothing is written.
#define RL_RD0 0x3197000ULL
#define RL_RD1 0x3da60a8ULL

static int rl_in_rdata(DWORD64 v) { return v >= g_Base + RL_RD0 && v < g_Base + RL_RD1; }

static void rl_ids(const char *tag, DWORD64 beg, DWORD64 end) {
    char b[200]; int i = 0, n = 0;
    i = cput(b, i, "rules:   "); i = cput(b, i, tag); i = cput(b, i, " ids=");
    if (beg == end) i = cput(b, i, "(empty)");
    __try {
        for (DWORD64 q = beg; q + 4 <= end && n < 24; q += 4, n++) {
            int id = *(volatile int*)q;
            if (n) b[i++] = ',';
            if (id < 0) { b[i++] = '-'; id = -id; }
            i = cpct(b, i, (unsigned long long)id);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { i = cput(b, i, " ?"); }
    b[i] = 0; log_line(b);
}

static int rl_ids_ok(DWORD64 beg, DWORD64 end) {
    if (beg == end) return 0;
    if ((end - beg) > 64 || ((end - beg) & 3)) return 0;
    __try {
        for (DWORD64 q = beg; q + 4 <= end; q += 4) {
            int id = *(volatile int*)q;
            if (id < 0 || id > 15) return 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
    return 1;
}

static void rules_scan(void) {
    BYTE *a = 0;
    MEMORY_BASIC_INFORMATION mbi;
    unsigned n = 0;
    DWORDLONG scanned = 0;
    if (!getenv_flag(L"AOE2LAN_RULES")) return;
    for (;;) {
        if (!VirtualQuery(a, &mbi, sizeof mbi)) break;
        a = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((DWORD64)mbi.BaseAddress >= g_Base && (DWORD64)mbi.BaseAddress < g_Base + 0x5000000) continue;
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;
        if (mbi.RegionSize > (512u << 20)) continue;
        scanned += mbi.RegionSize;
        DWORD64 lo = (DWORD64)mbi.BaseAddress, hi = lo + mbi.RegionSize;
        for (DWORD64 p = lo; p + 0x48 <= hi; p += 8) {
            int st = 0; DWORD64 b0 = 0, e0 = 0, c0 = 0, b1 = 0, e1 = 0, c1 = 0, wa = 0, wb = 0;
            __try {
                st = *(volatile int*)p;
                if (st < 0 || st > 8) continue;
                b0 = *(volatile DWORD64*)(p + 8);    e0 = *(volatile DWORD64*)(p + 0x10); c0 = *(volatile DWORD64*)(p + 0x18);
                b1 = *(volatile DWORD64*)(p + 0x20); e1 = *(volatile DWORD64*)(p + 0x28); c1 = *(volatile DWORD64*)(p + 0x30);
                wa = *(volatile DWORD64*)(p + 0x38); wb = *(volatile DWORD64*)(p + 0x40);
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (b0 > e0 || e0 > c0 || b1 > e1 || e1 > c1) continue;
            if (!rl_ids_ok(b0, e0) || !rl_ids_ok(b1, e1)) continue;
            if (!wa || !wb || wa == wb) continue;
            { DWORD64 va = 0, vb = 0;
              __try { va = *(volatile DWORD64*)wa; vb = *(volatile DWORD64*)wb; }
              __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
              if (!rl_in_rdata(va) || !rl_in_rdata(vb)) continue; }
            if (n >= 24) continue;
            n++;
            { char b[200]; int i = 0;
              i = cput(b, i, "rules: RECORD at 0x"); i = chx(b, i, p);
              i = cput(b, i, " status="); i = cpct(b, i, (unsigned long long)st);
              i = cput(b, i, " A=0x"); i = chx(b, i, wa);
              i = cput(b, i, " B=0x"); i = chx(b, i, wb);
              b[i] = 0; log_line(b); }
            rl_ids("A list ", b0, e0);
            rl_ids("B skip ", b1, e1);
        }
    }
    { char b[140]; int i = 0;
      i = cput(b, i, "rules: scanned MB="); i = cpct(b, i, scanned >> 20);
      i = cput(b, i, " records="); i = cpct(b, i, n);
      b[i] = 0; log_line(b); }
}

static DWORD WINAPI HeartbeatThread(LPVOID p) {
    (void)p;
    for (int k = 1;; k++) {
        Sleep(1000);
        if (k == 6 || k == 10 || k == 20 || k == 40) mp_spy();   // once after login
        if (k == 60) ui_widget_probe();
        if (k == 60) ui_widget_keyprobe();
        if (k == 25 || k == 40 || k == 70) rules_probe();
        if (k == 75 || k == 95) rules_scan();
        mp_check_slots();
        if (k % 5 == 0) {   // keep the old 5 s liveness cadence
            char b[64]; int i = 0;
            i = cput(b, i, "hb alive sec="); i = cpct(b, i, (unsigned long long)k);
            b[i] = 0; log_line(b);
        }
        if (k > 20000) break;
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
