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

#ifdef __clang__
// clang/mingw has no MSVC intrinsic; with a frame pointer [rbp+8] IS the
// return-address slot, which is what the MSVC intrinsic returns a pointer to.
#define _AddressOfReturnAddress() ((void*)((char*)__builtin_frame_address(0) + 8))
#endif
static int cput(char *b, int i, const char *s);            // defined below
static int chx(char *b, int i, DWORD64 v);
static int cpct(char *b, int i, unsigned long long v);

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
static const BYTE EXP_MSTH[8]       = {0x40,0x53,0x48,0x83,0xEC,0x30,0x48,0x8B}; // 0x1407b66f0 push rbx; sub rsp,0x30; mov rbx,rcx

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
    // id 18 (s45): the MatchStartMessage factory THUNK 0x1407b66f0, grp=0 (opt-in
    // via AOE2LAN_HOOKS). The whole parse path below the envelope reader is
    // ENCRYPTED on disk and so unhookable (s44f: dispatch 0x1407a7070, factory
    // 0x1407cdf10, parser #9 0x1407b6710, all six member readers, all the
    // 0x14039xxxx bond helpers) - but this one 24 B thunk is CLEAN: its on-disk
    // bytes are identical to gametext.bin, which is the house rule for hookable.
    // It has no direct callers; dispatch reaches it through the runtime registry.
    // Fired => MatchStartMessage IS registered and the payload is the fault (H2).
    // Never fired while "failed to parse" appears => it is NOT registered (H1).
    // READ ONLY (HK_RAW logs rcx/rdx/r8/r9 + the indirect call site).
    {"MSThunk",         0x1407B66F0, EXP_MSTH,  600000, 0, HK_RAW    },
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
    HC_TRY
        p = HC_RD8((g_Base + (0x140F19680 - 0x140000000)));
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
static int g_NoHooks = 0;

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
    HC_TRY sp = (DWORD64*)_AddressOfReturnAddress(); }   // caller's rsp after the call
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
        HC_TRY v = HC_RD64((DWORD64)(sp + k)); } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
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
          } else {
              g_NoHooks = 1;
              log_line("hook filter: none (all E9 detours disabled)");
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
        if (!getenv_flag(L"AOE2LAN_NOREDIR")) g_IatRedirect = 1;
        else { g_IatRedirect = 0; log_line("stage=8: AOE2LAN_NOREDIR=1 (redirect disabled)"); }
        if (!getenv_flag(L"AOE2LAN_NOSRV")) {
            if (!loginsrv_start()) log_line("loginsrv: START FAILED");
            if (!getenv_flag(L"AOE2LAN_NOCERT")) g_LoginInjectCert = loginsrv_inject_cert();
        } else log_line("stage=8: AOE2LAN_NOSRV=1 (server disabled)");
        if (g_NoHooks || getenv_flag(L"AOE2LAN_NOHOOKS")) {
            log_line("stage=8: skipping all E9 detours");
            { WCHAR hv[16];
              if (GetEnvironmentVariableW(L"AOE2LAN_HOOKDELAY", hv, 16) && hv[0]) {
                  DWORD ms = 0;
                  for (int i = 0; hv[i] >= L'0' && hv[i] <= L'9'; i++) ms = ms * 10 + (DWORD)(hv[i] - L'0');
                  if (ms > 0) { logf1("stage=8: delaying wset_vt install ms=", ms); Sleep(ms); }
              } }
            hc_install_wset_vtables(g_Base);
            if (getenv_flag(L"AOE2LAN_MPUNLOCK")) mp_unlock();
            return 0;
        }
        { WCHAR hv[16];
          if (GetEnvironmentVariableW(L"AOE2LAN_HOOKDELAY", hv, 16) && hv[0]) {
              DWORD ms = 0;
              for (int i = 0; hv[i] >= L'0' && hv[i] <= L'9'; i++) ms = ms * 10 + (DWORD)(hv[i] - L'0');
              if (ms > 0) {
                  logf1("stage=8: delaying E9 hook install ms=", ms);
                  Sleep(ms);
              }
          } }
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
        HC_TRY
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
            HC_TRY v = HC_RD64((DWORD64)(sp + k)); } __except (EXCEPTION_EXECUTE_HANDLER) { break; }
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
        HC_TRY v = HC_RD64((g_Base + (g_MpSlots[k].va - (DWORD64)0x140000000))); }
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
    HC_TRY p = HC_RD64((plat + off)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    { char b[160]; int i = 0;
      i = cput(b, i, "mpspy: ");
      for (const char *t = tag; t && *t && i < 40; t++) b[i++] = *t;
      i = cput(b, i, " ptr="); i = chx(b, i, p);
      b[i] = 0; log_line(b); }
    if (!p) return;
    HC_TRY vt = HC_RD64(p); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return; }
    spy_rva("  vtable", vt);
    if (!(vt >= g_Base && vt < g_Base + 0x5000000)) return;
    { const unsigned in[] = { 0xb0, 0xb8, 0xc0, 0xc8 };
      for (unsigned k = 0; k < sizeof(in)/sizeof(in[0]); k++) {
        DWORD64 s = 0;
        HC_TRY s = HC_RD64((vt + in[k])); }
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
    HC_TRY plat = HC_RD64((g_Base + PLATFORM_GLOBAL)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { log_line("mpspy: read of platform failed"); return; }
    spy_rva("platform obj", plat);
    if (!plat) { log_line("mpspy: platform is null"); return; }
    HC_TRY vt = HC_RD64(plat); }
    __except (EXCEPTION_EXECUTE_HANDLER) { log_line("mpspy: read of vtable failed"); return; }
    spy_rva("platform vtable", vt);
    if (!(vt >= g_Base && vt < g_Base + 0x5000000)) return;
    for (unsigned k = 0; k < sizeof(g_SpyOffs)/sizeof(g_SpyOffs[0]); k++) {
        DWORD64 s = 0;
        HC_TRY s = HC_RD64((vt + g_SpyOffs[k])); }
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
    HC_TRY
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
    i = cput(b, i, " setter+0x");
    HC_TRY
        const BYTE *c = (const BYTE*)HC_RD64((vt + 0x68));
        i = chx(b, i, (DWORD64)c - g_Base);
        i = cput(b, i, " bytes=");
        for (int k = 0; k < 12 && i < 190; k++) {
            const char *hx = "0123456789abcdef";
            BYTE cb = HC_RD8((DWORD64)c + k);
            b[i++] = hx[cb >> 4]; b[i++] = hx[cb & 15];
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
            HC_TRY v = HC_RD64(p); } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (!uiw_in_rdata(v)) continue;
            DWORD64 s0 = 0, s1 = 0, s2 = 0, set = 0;
            HC_TRY s0 = HC_RD64(v); s1 = HC_RD64((v + 8));
                    s2 = HC_RD64((v + 16)); set = HC_RD64((v + 0x68)); }
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
            HC_TRY v = HC_RD64(q); } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
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
                HC_TRY vt = HC_RD64(base); set = HC_RD64((vt + 0x68)); }
                __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
                { char b[200]; int i = 0;
                  i = cput(b, i, "uiwK:   base=q-"); i = cpct(b, i, 8 * back);
                  i = cput(b, i, " q0=");
                  HC_TRY
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
              HC_TRY
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
    HC_TRY r = ((PfnVoid)HC_RD64((vt + off)))((void*)self); }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = -2; }
    return r;
}
static int rl_call2(DWORD64 vt, unsigned off, DWORD64 self, int arg) {
    int r;
    HC_TRY r = ((PfnInt)HC_RD64((vt + off)))((void*)self, arg); }
    __except (EXCEPTION_EXECUTE_HANDLER) { r = -2; }
    return r;
}

static void rules_probe(void) {
    DWORD64 cfg = 0, vt = 0, root = 0, svc = 0;
    if (!getenv_flag(L"AOE2LAN_RULES")) return;
    HC_TRY cfg = HC_RD64((g_Base + RULES_CFG)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { cfg = 0; }
    rl_h("cfg", " [0x1443552b8]", cfg);
    if (cfg) {
        HC_TRY vt = HC_RD64(cfg); } __except (EXCEPTION_EXECUTE_HANDLER) { vt = 0; }
        rl_rva("cfg", " vtable", vt);
        { DWORD64 b698 = 0; long long d680 = 0, d6b4 = 0;
          HC_TRY b698 = HC_RD8((cfg + 0x698)); } __except (EXCEPTION_EXECUTE_HANDLER) { b698 = 999; }
          HC_TRY d680 = HC_RD32((cfg + 0x680)); } __except (EXCEPTION_EXECUTE_HANDLER) { d680 = -999; }
          HC_TRY d6b4 = HC_RD32((cfg + 0x6b4)); } __except (EXCEPTION_EXECUTE_HANDLER) { d6b4 = -999; }
          rl_d("cfg", " byte+0x698  (rule 13)", (long long)b698);
          rl_d("cfg", " dword+0x680 (rule 15)", d680);
          rl_d("cfg", " dword+0x6b4 (rule 15)", d6b4); }
    }
    HC_TRY root = HC_RD64((g_Base + RULES_SVC)); }
    __except (EXCEPTION_EXECUTE_HANDLER) { root = 0; }
    rl_h("svc", " owner [0x1442dc4f0]", root);
    if (root) { HC_TRY svc = HC_RD64((root + 0x2e8)); } __except (EXCEPTION_EXECUTE_HANDLER) { svc = 0; } }
    rl_h("svc", " object [+0x2e8]", svc);
    if (svc) {
        HC_TRY vt = HC_RD64(svc); } __except (EXCEPTION_EXECUTE_HANDLER) { vt = 0; }
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
              HC_TRY f = HC_RD64((vt + 0x418)); } __except (EXCEPTION_EXECUTE_HANDLER) { f = 0; }
              rl_rva("svc", " slot+0x418 fn", f); }
            rl_d("svc", " slot+0x418 LAN item gate", (long long)rl_call1(vt, 0x418, svc));
        }
    }
    if (root) {
        DWORD64 rb = 0, re = 0;
        HC_TRY rb = HC_RD64((root + 0x2628)); } __except (EXCEPTION_EXECUTE_HANDLER) { rb = 0; }
        HC_TRY re = HC_RD64((root + 0x2630)); } __except (EXCEPTION_EXECUTE_HANDLER) { re = 0; }
        rl_d("root", " dropdown item count (0x50)", (re >= rb) ? (long long)((re - rb) / 0x50) : -1);
    }
    // rule 2 is "logged in AND leaderboard registry non-empty"; the count is
    // (end-begin)/0xc0 of the vector at 0x1442e18b0.
    { DWORD64 beg = 0, end = 0, mroot = 0;
      HC_TRY beg = HC_RD64((g_Base + 0x42e18b0ULL)); } __except (EXCEPTION_EXECUTE_HANDLER) { beg = 0; }
      HC_TRY end = HC_RD64((g_Base + 0x42e18b8ULL)); } __except (EXCEPTION_EXECUTE_HANDLER) { end = 0; }
      HC_TRY mroot = HC_RD64((g_Base + 0x42e18c8ULL)); } __except (EXCEPTION_EXECUTE_HANDLER) { mroot = 0; }
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
    HC_TRY
        for (DWORD64 q = beg; q + 4 <= end && n < 24; q += 4, n++) {
            int id = HC_RD32(q);
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
    HC_TRY
        for (DWORD64 q = beg; q + 4 <= end; q += 4) {
            int id = HC_RD32(q);
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
            HC_TRY
                st = HC_RD32(p);
                if (st < 0 || st > 8) continue;
                b0 = HC_RD64((p + 8));    e0 = HC_RD64((p + 0x10)); c0 = HC_RD64((p + 0x18));
                b1 = HC_RD64((p + 0x20)); e1 = HC_RD64((p + 0x28)); c1 = HC_RD64((p + 0x30));
                wa = HC_RD64((p + 0x38)); wb = HC_RD64((p + 0x40));
            } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (b0 > e0 || e0 > c0 || b1 > e1 || e1 > c1) continue;
            if (!rl_ids_ok(b0, e0) || !rl_ids_ok(b1, e1)) continue;
            if (!wa || !wb || wa == wb) continue;
            { DWORD64 va = 0, vb = 0;
              HC_TRY va = HC_RD64(wa); vb = HC_RD64(wb); }
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

// ---------------------------------------------------------------- host lobby AI gate
// The host-lobby populator 0x141a344f0 emits the settings rows only when
//   [screen+0x1cf8] == [0x14326b258]                          (0x141a35db1..dbf)
// and its arg4 is produced by 0x141a3e730 as
//   cl = ([screen+0x24f4]==1 && !+0x24e6 && !+0x24e5 && !+0x24c0)  (0x141a3ec9d..ecbf)
//   bl = (mode kind == 3|0xe|0xf) | cl ; [rsp+0x31] = bl           (0x141a3ed00..ed04)
//   bl==0 -> the call to 0x141a43d50 (the AI-slot rebuild) is skipped entirely.
// The cached-mode path (0x141a3ed47) also lands on `or bl,cl`, so cl=1 gives arg4=1
// and the rebuild either way. All five are plain fields of the 0x7df8-byte
// UIScreenMultiplayerLobbyHost object, so they can be held at the wanted values
// from outside - find the object by its primary vtable (base+0x33416e0, written by
// the ctor at 0x141a23ec0) and keep the fields set. Nothing in the image is touched,
// which is the whole point: Arxan checksums all of .text and at least the
// VCRUNTIME140!__RTDynamicCast IAT slot, and killed AOE2LAN_RTDYN=1 at t~3s
// (notes/linux-session4.md §4d/§4e). AOE2LAN_AIGATE=1 enables this thread.
#define LOBBY_SVC_RVA   0x42dc4f0ULL   // [0x1442dc4f0] = online service owner (+0xd10 = match state ptr)
#define LOBBY_VT_RVA    0x33416e0ULL   // UIScreenMultiplayerLobbyHost primary vtable
#define LOBBY_SUBVT_RVA 0x32dd198ULL   // subobject vtable at [screen+0x710] (ctor 0x141a238b2)
#define LOBBY_SENT_RVA  0x326b258ULL   // global the gate compares +0x1cf8 against
#define LOBBY_F_SUBVT   0x0710ULL      // qword, == g_Base + LOBBY_SUBVT_RVA
#define LOBBY_F_GATE    0x1cf8ULL      // qword, want == [LOBBY_SENT_RVA]
#define LOBBY_F_24F4    0x24f4ULL      // byte, want 1
#define LOBBY_F_24E6    0x24e6ULL      // byte, want 0
#define LOBBY_F_24E5    0x24e5ULL      // byte, want 0
#define LOBBY_F_24C0    0x24c0ULL      // byte, want 0

static DWORD64 g_LobbyObj = 0;

// The combo rebuild (0x141a344f0) is only reachable from the DSPM/0x1e receive
// path, and a self-hosted lobby gets no DSPM after the screen is built, so the AI
// list that 0x141a31940 fills (log 15090884: screen+0x588 span 0x18 = 3
// personalities) never reaches the combos, which stay at their creation item.
// Calling the populator from this thread crashed the game (log 15317557), so hand
// the request to the WidgetSetEn hook, which runs on the UI thread.
static int g_ComboTries = 0;

// First committed RW qword equal to the vtable whose +0x710 holds the secondary
// vtable and +0x1cf8 holds a plausible gate value (0 = open, -1 = the locked
// value the game writes, or the sentinel itself). Also skip our own stack region.
static DWORD64 lobby_find(DWORD64 vt, DWORD64 sent) {
    BYTE *a = 0;
    DWORD64 sp = (DWORD64)&a, subvt = g_Base + LOBBY_SUBVT_RVA;
    MEMORY_BASIC_INFORMATION mbi;
    for (;;) {
        if (!VirtualQuery(a, &mbi, sizeof mbi)) break;
        a = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
        if ((DWORD64)mbi.BaseAddress >= g_Base && (DWORD64)mbi.BaseAddress < g_Base + 0x5000000) continue;
        if (mbi.State != MEM_COMMIT || !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY))) continue;
        if (mbi.RegionSize > (64u << 20)) continue;
        if (sp >= (DWORD64)mbi.BaseAddress && sp < (DWORD64)mbi.BaseAddress + mbi.RegionSize) continue;
        for (DWORD64 p = (DWORD64)mbi.BaseAddress; p + 0x7df8 <= (DWORD64)mbi.BaseAddress + mbi.RegionSize; p += 8) {
            DWORD64 v = 0, sv = 0, f = 0;
            HC_TRY v = HC_RD64(p); } __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (v != vt) continue;
            (void)sent; (void)f;
            HC_TRY sv = HC_RD64((p + LOBBY_F_SUBVT)); }
            __except (EXCEPTION_EXECUTE_HANDLER) { continue; }
            if (sv != subvt) continue;
            return p;
        }
    }
    return 0;
}

static void lobby_gate(void) {
    DWORD64 obj = g_LobbyObj;
    int fixed = 0, found = 0;
    DWORD r24f4 = 0x100;                  // 0x100 = not read
    DWORD64 d_gate = 0, d_edit = 0, d_slots = 0, d_sent = 0;  // S17 diag
    DWORD64 d_5e0 = 0, d_beg0 = 0, d_span0 = 0;                // S17 diag: Block A gate + slot0 raw
    DWORD64 d_row0 = 0, d_dd0 = 0;                              // S17 diag: slot0 widget chain
    DWORD64 d_beg0w = 0;                                        // S17 diag: first qword at beg
    DWORD64 d_s588 = ~0ULL, d_558 = ~0ULL;                     // S17 diag: AI-list span + +0x558
    DWORD64 d_7d43 = ~0ULL;                                     // S17 diag: rebuild-request flag
    DWORD64 d_2988 = ~0ULL;                                     // DSPM-handler run counter
    DWORD64 d_item1 = 0, d_iq[8] = {0};                         // P2 first-item object dump
    DWORD64 d_msz = ~0ULL, d_mkey = ~0ULL, d_midx = ~0ULL, d_sb0 = ~0ULL;  // settings resolve
    HC_TRY
        DWORD64 vt = g_Base + LOBBY_VT_RVA, subvt = g_Base + LOBBY_SUBVT_RVA;
        DWORD64 sent = HC_RD64((g_Base + LOBBY_SENT_RVA));
        DWORD64 root = HC_RD64((g_Base + LOBBY_SVC_RVA));
        DWORD64 mobj = root ? HC_RD64((root + 0xd10)) : 0;
        if (mobj && HC_RD64((mobj + 0xc8)) != sent) { HC_WR64((mobj + 0xc8), sent); fixed |= 256; }
        if (obj && (HC_RD64(obj) != vt || HC_RD64((obj + LOBBY_F_SUBVT)) != subvt)) obj = 0; // screen freed or rebuilt
        if (!obj) obj = lobby_find(vt, sent);
        if (obj) {
            found = 1;
            r24f4 = HC_RD8((obj + LOBBY_F_24F4));
            if (HC_RD64((obj + LOBBY_F_GATE)) != sent) { HC_WR64((obj + LOBBY_F_GATE), sent); fixed |= 1; }
            if (r24f4 != 1)                            { HC_WR8((obj + LOBBY_F_24F4), 1);      fixed |= 2; }
            if (HC_RD8((obj + LOBBY_F_24E6)) != 0)     { HC_WR8((obj + LOBBY_F_24E6), 0);     fixed |= 4; }
            if (HC_RD8((obj + LOBBY_F_24E5)) != 0)     { HC_WR8((obj + LOBBY_F_24E5), 0);     fixed |= 8; }
            if (HC_RD8((obj + LOBBY_F_24C0)) != 0)     { HC_WR8((obj + LOBBY_F_24C0), 0);     fixed |= 16; }
            { DWORD64 p1cf0 = HC_RD64((obj + 0x1cf0));
              if (!p1cf0 && mobj) {
                  DWORD64 p1170 = HC_RD64((mobj + 0x1170));
                  p1cf0 = p1170 ? HC_RD64((p1170 + 0xa8)) : 0;
              }
              DWORD64 arr   = p1cf0 ? HC_RD64((p1cf0 + 0x170)) : 0;
              if (arr) {
                  for (int i = 0; i < 8; i++)
                      if (HC_RD32((arr + (unsigned)i * 4)) == 0) { HC_WR32((arr + (unsigned)i * 4), 1); fixed |= 64; }
              } }
            // No combo-vector clear: 0x141a43d50 only repopulates a combo whose
            // entry count is 0, and it runs only from the DSPM receive path, so
            // clearing it left every slot permanently blank (log 13329336).
            // 0x141a31940 (fills screen+0x588, the AI list 0x141a344f0 iterates at
            // 0x141a35e9a) runs only while screen+0x558 != 0, and 0x141a2885d ->
            // 0x141a3abb0 clears 0x558 after one send - so re-arm it while empty.
            // [screen+0x7d43] is the "rebuild every slot combo" request flag: the
            // DSPM handler at 0x141a27f7c runs the 0x141a344f0 loop for all 8 slots
            // when it is non-zero (or when any slot state changed), then CLEARS it.
            // Writing it ourselves makes the flag useless as evidence of whether a
            // DSPM ever arrives (we re-arm it 10 ms after the handler clears it) -
            // so the write is now opt-in only (AOE2LAN_7D43=1) and off by default.
            { DWORD64 r0 = HC_RD64((obj + 0x2688));
              DWORD64 d0 = r0 ? HC_RD64((r0 + 0x4a0)) : 0;
              DWORD64 b0 = d0 ? HC_RD64((d0 + 0x5a0)) : 0, e0 = d0 ? HC_RD64((d0 + 0x5a8)) : 0;
              if (getenv_flag(L"AOE2LAN_7D43")
                  && (!b0 || e0 < b0 + 0x28) && HC_RD64((obj + 0x588)) != HC_RD64((obj + 0x590))) {
                  HC_WR8((obj + 0x7d43), 1); fixed |= 1024;
              } }
            { DWORD64 r0 = HC_RD64((obj + 0x2688));
              DWORD64 d0 = r0 ? HC_RD64((r0 + 0x4a0)) : 0;
              DWORD64 b0 = d0 ? HC_RD64((d0 + 0x5a0)) : 0, e0 = d0 ? HC_RD64((d0 + 0x5a8)) : 0;
              static DWORD64 seen_at = 0;
              if (!seen_at && r0) seen_at = GetTickCount();
              // opt-in: calling the game's populator killed the process inside the
              // first 0x141a12820 on every delivery thread tried (logs 15317557,
              // 16061311, 16663214, 252-1368107). The proven path is leave/re-enter:
              // the screen is reused with the gate held, so the game's own first pass
              // adds AI. Default OFF.
              if (getenv_flag(L"AOE2LAN_COMBO") && (!b0 || e0 < b0 + 0x28)
                  && seen_at && GetTickCount() - seen_at > 3000
                  && HC_RD64((obj + 0x588)) != HC_RD64((obj + 0x590)) && g_ComboTries < 200) {
                  g_ComboTries++;
                  hc_lobby_request(obj, sent);
                  fixed |= 2048;
              } }
            int pulsed = 0;
            if (HC_RD64((obj + 0x588)) == HC_RD64((obj + 0x590))) { HC_WR8((obj + 0x558), 1); pulsed = 1; }
            {
                // Also clear the lock bit directly on the cached settings widgets.
                for (unsigned off = 0x2508; off <= 0x25f8; off += 8) {
                    DWORD64 w = HC_RD64((obj + off));
                    if (!w) continue;
                    DWORD64 fl = HC_RD64((w + 0x3d8));
                    if (fl & 4ULL) { HC_WR64((w + 0x3d8), fl & ~4ULL); HC_WR8((w + 0x3e0), 1); }
                    DWORD64 cb = HC_RD64((w + 0x70)), ce = HC_RD64((w + 0x78));
                    for (DWORD64 cp = cb; cp && cp + 8 <= ce && cp < cb + 128; cp += 8) {
                        DWORD64 cw = HC_RD64(cp);
                        if (!cw) continue;
                        DWORD64 cfl = HC_RD64((cw + 0x3d8));
                        if (cfl & 4ULL) { HC_WR64((cw + 0x3d8), cfl & ~4ULL); HC_WR8((cw + 0x3e0), 1); }
                    }
                }
                if (pulsed) fixed |= 128;
            }
            // S17 diagnostic: read-only field values + per-slot item counts.
            // No game-code calls; proves whether the vector stays empty after
            // the reset and what the gate/edit fields actually hold.
            { DWORD64 b588 = HC_RD64((obj + 0x588)), e588 = HC_RD64((obj + 0x590));
              d_s588 = (b588 && e588 >= b588) ? (e588 - b588) : ~0ULL; }
            d_558 = HC_RD8((obj + 0x558));
            d_7d43 = HC_RD8((obj + 0x7d43));
            d_2988 = HC_RD64((obj + 0x2988));   // DSPM-handler per-slot run counter
            { DWORD64 r1 = HC_RD64((obj + 0x2690));            // slot 1 (P2) row
              DWORD64 d1 = r1 ? HC_RD64((r1 + 0x4a0)) : 0;
              DWORD64 b1 = d1 ? HC_RD64((d1 + 0x5a0)) : 0;
              d_item1 = b1 ? HC_RD64(b1) : 0;                  // first item object
              for (int q = 0; q < 8; q++)
                  d_iq[q] = d_item1 ? HC_RD64((d_item1 + 8 + (unsigned)q * 8)) : 0; }
            // replicate 0x140e83240(id=0) read-only: map1 (0x1442e18c8) id->index,
            // table at [0x1442e18b0], 0xc0-byte entries; [entry+0xb0]==1 locks the
            // slot combo to a single current-value item (0x141a35c30 region).
            { DWORD64 h1 = HC_RD64(0x1442e18c8);
              d_msz = h1 ? HC_RD64((0x1442e18c8 + 8)) : ~0ULL;
              d_mkey = ~0ULL; d_midx = ~0ULL; d_sb0 = ~0ULL;
              if (h1) {
                  DWORD64 node = HC_RD64((h1 + 8)), best = h1;
                  for (int st = 0; st < 64 && node && !HC_RD8((node + 0x19)); st++) {
                      if ((long long)HC_RD64((node + 0x20)) < 0) node = HC_RD64((node + 0x10));
                      else best = node;
                      if (best == node) node = HC_RD64(node);     // left
                  }
                  if (!HC_RD8((best + 0x19)) && (long long)HC_RD64((best + 0x20)) <= 0) {
                      d_mkey = HC_RD64((best + 0x20));
                      d_midx = (DWORD64)(int)HC_RD32((best + 0x28));
                      DWORD64 tb = HC_RD64(0x1442e18b0);
                      if (tb) d_sb0 = HC_RD64((tb + d_midx * 0xc0 + 0xb0));
                      // [settings+0xb0]==1 makes 0x141a344f0 skip the Open/Closed+AI
                      // block and emit only the current-value item (measured live:
                      // P2="Open" only, P3-P8="Closed" only). Pin it to 0.
                      if (tb && d_midx < 64 && (int)d_sb0 == 1) {
                          HC_WR32((tb + d_midx * 0xc0 + 0xb0), 0); fixed |= 4096;
                      }
                  }
              } }
            d_gate = HC_RD64((obj + LOBBY_F_GATE));
            d_sent = sent;
            d_edit = HC_RD8((obj + 0x604));
            d_5e0 = HC_RD64((obj + 0x5e0));
            for (int s = 0; s < 8; s++) {
                DWORD64 row = HC_RD64((obj + 0x2688 + (unsigned)s * 8));
                DWORD64 dd  = row ? HC_RD64((row + 0x4a0)) : 0;
                DWORD64 beg = dd  ? HC_RD64((dd  + 0x5a0)) : 0;
                DWORD64 end = dd  ? HC_RD64((dd  + 0x5a8)) : 0;
                DWORD64 cnt = (beg && end >= beg) ? (end - beg) / 8 : 0;
                if (cnt > 15) cnt = 15;
                d_slots |= (cnt << (s * 4));
                if (s == 0) { d_row0 = row; d_dd0 = dd; d_beg0 = beg; d_span0 = (beg && end >= beg) ? (end - beg) : 0;
                              if (beg) d_beg0w = HC_RD64(beg); }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { g_LobbyObj = 0; return; }
    g_LobbyObj = obj;
    // Log only on a state change (new object / different fix mask / different
    // +0x24f4 read-back): proves whether our write survives the game's own
    // per-frame refresh, instead of spamming one line per 50 ms poll.
    { static DWORD64 last_obj = 0; static int last_fixed = -1; static DWORD last_24f4 = 0x101;
      static volatile LONG n = 0;
      // bit 0x2 (24f4 rewrite) and r24f4 flap every 20 ms; masking them out of
      // change detection keeps the cap for real transitions
      if (obj != last_obj || (fixed & ~2) != (last_fixed & ~2)) {
          last_obj = obj; last_fixed = fixed; last_24f4 = r24f4;
          if (InterlockedIncrement(&n) <= 20000) {
              char b[192]; int i = cput(b, 0, "lobbygate: obj=");
              i = chx(b, i, obj);
              i = cput(b, i, " 24f4_was="); i = chx(b, i, r24f4);
              i = cput(b, i, " fixed=0x"); i = chx(b, i, (DWORD64)(unsigned)fixed);
              b[i] = 0; log_line(b);
          } }
      (void)found; }
    // S17 diagnostic: log gate/edit/24f4 + per-slot item counts on change.
    // slots are packed 4 bits each, slot 7 (leftmost) .. slot 0 (rightmost).
    { static DWORD64 l_gate = ~0ULL, l_edit = ~0ULL, l_24f4 = ~0ULL, l_slots = ~0ULL, l_sent = 0;
      static DWORD64 l_5e0 = ~0ULL, l_beg0 = ~0ULL, l_span0 = ~0ULL, l_row0 = ~0ULL, l_dd0 = ~0ULL, l_beg0w = ~0ULL;
      static DWORD64 l_s588 = ~0ULL, l_558 = ~0ULL, l_7d43 = ~0ULL, l_2988 = ~0ULL, l_item1 = ~0ULL;
      static DWORD64 l_msz = ~0ULL, l_mkey = ~0ULL, l_sb0 = ~0ULL;
      static volatile LONG dn = 0;
      if (obj && (d_gate != l_gate || d_edit != l_edit || d_slots != l_slots || d_sent != l_sent
               || d_5e0 != l_5e0 || d_beg0 != l_beg0 || d_span0 != l_span0 || d_row0 != l_row0 || d_dd0 != l_dd0 || d_beg0w != l_beg0w
               || d_s588 != l_s588 || d_558 != l_558 || d_7d43 != l_7d43 || d_2988 != l_2988 || d_item1 != l_item1
               || d_msz != l_msz || d_mkey != l_mkey || d_sb0 != l_sb0)) {
          l_gate = d_gate; l_edit = d_edit; l_24f4 = r24f4; l_slots = d_slots; l_sent = d_sent;
          l_5e0 = d_5e0; l_beg0 = d_beg0; l_span0 = d_span0; l_row0 = d_row0; l_dd0 = d_dd0; l_beg0w = d_beg0w;
          l_s588 = d_s588; l_558 = d_558; l_7d43 = d_7d43; l_2988 = d_2988; l_item1 = d_item1;
          l_msz = d_msz; l_mkey = d_mkey; l_sb0 = d_sb0;
          if (InterlockedIncrement(&dn) <= 20000) {
              char b[384]; int i = cput(b, 0, "lobbydiag: gate=0x"); i = chx(b, i, d_gate);
              i = cput(b, i, " sent=0x"); i = chx(b, i, d_sent);
              i = cput(b, i, " eq="); i = cpct(b, i, (unsigned long long)(d_gate == d_sent));
              i = cput(b, i, " 5e0=0x"); i = chx(b, i, d_5e0);
              i = cput(b, i, " edit604="); i = chx(b, i, d_edit);
              i = cput(b, i, " 24f4="); i = chx(b, i, r24f4);
              i = cput(b, i, " s0row=0x"); i = chx(b, i, d_row0);
              i = cput(b, i, " s0dd=0x"); i = chx(b, i, d_dd0);
              i = cput(b, i, " s0beg=0x"); i = chx(b, i, d_beg0);
              i = cput(b, i, " s0w0=0x"); i = chx(b, i, d_beg0w);
              i = cput(b, i, " s0span=0x"); i = chx(b, i, d_span0);
              i = cput(b, i, " s588=0x"); i = chx(b, i, d_s588);
              i = cput(b, i, " 558="); i = chx(b, i, d_558);
              i = cput(b, i, " 7d43="); i = chx(b, i, d_7d43);
              i = cput(b, i, " 2988="); i = chx(b, i, d_2988);
              i = cput(b, i, " it1="); i = chx(b, i, d_item1);
              i = cput(b, i, " msz="); i = chx(b, i, d_msz);
              i = cput(b, i, " mkey="); i = chx(b, i, d_mkey);
              i = cput(b, i, " midx="); i = chx(b, i, d_midx);
              i = cput(b, i, " sb0="); i = chx(b, i, d_sb0);
              if (d_item1) { i = cput(b, i, " [");
                  for (int q = 0; q < 8; q++) { if (q) b[i++] = ' '; i = chx(b, i, d_iq[q]); }
                  i = cput(b, i, "]"); }
              i = cput(b, i, " slots=");
              for (int s = 7; s >= 0; s--) {
                  i = cpct(b, i, (unsigned long long)((d_slots >> (s * 4)) & 0xF));
                  if (s) b[i++] = ',';
              }
              b[i] = 0; log_line(b);
          } }
    }
}

// 10 ms while the object is cached (6 reads + at most 5 writes) - measured: the
// game resets screen+0x24f4 to 0 every ~250 ms, so a 50 ms poll only held our
// value ~50 % of the time; at 10 ms it holds ~95 % with negligible CPU. The full
// heap scan still only runs 1/s until the object is found.
static DWORD WINAPI LobbyGateThread(LPVOID p) {
    (void)p;
    log_line("lobbygate: thread up (AOE2LAN_AIGATE=1), scanning 1/s for the host lobby screen");
    for (int k = 0; k < 2000000; k++) {         // ~5.5 h, same lifetime as the heartbeat
        Sleep(10);
        if (g_LobbyObj || (k % 100) == 99) {
            static int miss = 0;
            lobby_gate();
            // twice, ~20 s in: distinguishes "thread dead" from "object not found"
            if (!g_LobbyObj && (++miss == 20 || miss == 21))
                log_line("lobbygate: no UIScreenMultiplayerLobbyHost in the heap yet");
        }
    }
    return 0;
}

// AOE2LAN_DUMPTEXT=1: write the live (Arxan-decrypted) .text — RVA 0x1000, the
// section's 0x3195000 raw bytes — to logs\gametext.bin, so dev/lanhook/{aoe2re,
// dz,fn,xr}.py can analyse the real image off-line. In-process because the
// decrypted bytes exist only here: yama ptrace_scope=1 blocks /proc/<pid>/mem
// from a non-ancestor, and the on-disk .text is still encrypted.
#define DUMPTEXT_RVA  0x1000ULL
#define DUMPTEXT_SIZE 0x3195000UL
static void dumptext(void) {
    if (!getenv_flag(L"AOE2LAN_DUMPTEXT")) return;
    HANDLE h = CreateFileW(L"logs\\gametext.bin", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) { log_line("dumptext: CreateFile failed"); return; }
    const BYTE *p = (const BYTE *)(g_Base + DUMPTEXT_RVA);
    DWORD off = 0;
    while (off < DUMPTEXT_SIZE) {
        DWORD want = DUMPTEXT_SIZE - off; if (want > (1u << 20)) want = 1u << 20;
        DWORD got = 0;
        if (!WriteFile(h, p + off, want, &got, NULL) || !got) break;
        off += got;
    }
    CloseHandle(h);
    { char b[96]; int i = 0;
      i = cput(b, i, "dumptext: wrote 0x"); i = chx(b, i, off);
      i = cput(b, i, " of 0x"); i = chx(b, i, DUMPTEXT_SIZE);
      b[i] = 0; log_line(b); }
}

// AOE2LAN_TEXTPOKE=<hexrva>:<same|flip> — the Step-3 discriminator. Two questions
// the RTDYN failure left open (its IAT-slot patch killed the process at t~3 s):
//   same  write the identical byte back -> does the sweep notice the write /
//         the VirtualProtect at all?
//   flip  change one byte of a function nothing ever calls in a boot-to-menu run
//         (0x141a23ec0 = the UIScreenMultiplayerLobbyHost ctor) -> is the sweep
//         blanket over .text, or per-function / on-call?
// Runs at k==20, after dumptext, so the byte is already Arxan-decrypted.
static void textpoke(void) {
    char v[48];
    DWORD64 rva = 0; int i = 0, flip = 0;
    if (!GetEnvironmentVariableA("AOE2LAN_TEXTPOKE", v, sizeof v) || !v[0]) return;
    while (v[i] && v[i] != ':') {
        char c = v[i++];
        if (c >= '0' && c <= '9') rva = rva * 16 + (unsigned)(c - '0');
        else if ((c | 32) >= 'a' && (c | 32) <= 'f') rva = rva * 16 + (unsigned)((c | 32) - 'a' + 10);
        else { log_line("poke: bad rva, expected <hex>[:same|flip]"); return; }
    }
    if (v[i] == ':') flip = (v[i + 1] == 'f' || v[i + 1] == 'F');
    { BYTE *p = (BYTE *)(g_Base + rva), was, now; DWORD old = 0;
      if (!VirtualProtect(p, 1, PAGE_EXECUTE_READWRITE, &old)) { log_line("poke: VirtualProtect failed"); return; }
      was = *p; now = (BYTE)(flip ? (was ^ 0x01) : was);
      *p = now;
      VirtualProtect(p, 1, old, &old);
      { char b[160]; int j = cput(b, 0, "poke: rva=0x"); j = chx(b, j, rva);
        j = cput(b, j, flip ? " FLIP was=0x" : " SAME was=0x"); j = chx(b, j, was);
        j = cput(b, j, " now=0x"); j = chx(b, j, now);
        b[j] = 0; log_line(b); } }
}

// ---------------------------------------------------------------- log sink probe
// Read-only. LogHelper (0x1402bcb30) is only a dispatcher: it loads the sink
// object out of the lazily-inited global 0x144c9e248 and calls [[sink]+0x20]
// (and [+0x30] when the record level >= 4). The E9 detours on the three log
// sinks do install on wine and produce real game-side lines (19 LogWarn hits),
// but the process dies at t~3.4 s - so .text is closed to us here, unlike on
// Windows where the same detours survive 600 s runs. This prints the sink chain
// to show whether the sink OBJECT is heap (then its vptr can be swapped for a
// fake vtable in our own memory - a heap write, the same class as lobbygate,
// which survives) or inside the image (then that route is dead too).
// Opt-in: AOE2LAN_LOGSINK=1.
#define LOGSINK_GLOBAL 0x4c9e248ULL

static void ls_line(const char *tag, DWORD64 v) {
    char b[176]; int i = 0;
    i = cput(b, i, "logsink: "); i = cput(b, i, tag);
    i = cput(b, i, " = 0x"); i = chx(b, i, v);
    if (v >= g_Base && v < g_Base + 0x5000000) {
        i = cput(b, i, " (image+0x"); i = chx(b, i, v - g_Base); i = cput(b, i, ")");
    } else if (v) { i = cput(b, i, " (outside image)"); }
    b[i] = 0; log_line(b);
}

static void logsink_probe(void) {
    if (!getenv_flag(L"AOE2LAN_LOGSINK")) return;
    HC_TRY
        DWORD64 sink = HC_RD64((g_Base + LOGSINK_GLOBAL));
        ls_line("sink ptr [0x144c9e248]", sink);
        if (sink) {
            DWORD64 vt = HC_RD64(sink);
            ls_line("sink vtable [sink+0]", vt);
            if (vt) for (unsigned off = 0; off <= 0x40; off += 8) {
                char t[24]; int j = cput(t, 0, "  slot+0x"); j = chx(t, j, off);
                ls_line(t, HC_RD64((vt + off)));
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { log_line("logsink: read faulted"); }
}

// The rlink sink object is HEAP (measured 0x660d1e0), its vtable is the 7-slot
// table at image+0x328a068, and slots 1..5 are all the same 5-instruction thunk
//   (rcx=self, rdx=fmt, r8=va_list) -> jmp 0x140f192f0("rlink - <level>", ...)
//   1=error 2=warning 3=notice 4=info 5=debug; slot 0 is the deleting dtor,
//   slot 6 is `ret 0`.
// E9 detours on the log sinks die at t~3.4 s on wine, so instead: copy the
// vtable (including the RTTI locator at [-1]) into our own VirtualAlloc block,
// aim slots 1..5 at stubs in THIS dll, and swap the object's vptr. That is one
// 8-byte heap write - the same class as lobbygate, which survives - and not one
// byte of the game image changes. Opt-in: AOE2LAN_LOGVT=1.
#define LOGSINK_VT_RVA 0x328a068ULL
#define LS_NSLOT       7

typedef void (*PFN_LSSLOT)(void *, const char *, void *);
static PFN_LSSLOT g_LsReal[LS_NSLOT];
static DWORD64    g_LsObj  = 0;   // sink object whose vptr we swapped
static DWORD64    g_LsFake = 0;   // our vtable copy; [0]=RTTI locator, [1..7]=slots

// NUL-terminated printable-ASCII read through the guarded accessor. -1 on fault
// or on any non-printable byte, so a %d argument is never mistaken for a string.
static int ls_cstr(DWORD64 p, char *out, int maxn) {
    int n = 0, bad = 0;
    if (!HC_IS_PTR(p)) return -1;
    HC_TRY
        for (; n < maxn - 1; n++) {
            BYTE c = HC_RD8((p + (unsigned)n));
            if (!c) break;
            if (c < 0x20 || c > 0x7e) { bad = 1; break; }
            out[n] = (char)c;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    if (bad) return -1;
    out[n] = 0;
    return n;
}

// Same readout style as the Windows E9 detours (hookcore.c HK_RDSTR): the raw
// format string plus the first four varargs as hex, and quoted when the value
// is a printable string. No CRT in this DLL, so no vsnprintf - and the argument
// home slots are left untouched for the real sink.
static volatile LONG g_LsLines = 0;

static void ls_emit(const char *lvl, const char *fmt, void *va) {
    char fs[160]; char b[640]; int i = 0;
    if (InterlockedIncrement(&g_LsLines) > 20000) return;
    if (ls_cstr((DWORD64)fmt, fs, sizeof fs) < 0) return;
    i = cput(b, i, "rlink "); i = cput(b, i, lvl); i = cput(b, i, ": \"");
    i = cput(b, i, fs); i = cput(b, i, "\"");
    HC_TRY
        for (int k = 0; k < 4 && i < (int)sizeof b - 128; k++) {
            DWORD64 a = HC_RD64(((DWORD64)va + 8 * (unsigned)k));
            char s[64];
            i = cput(b, i, " a"); b[i++] = (char)('0' + k);
            i = cput(b, i, "=0x"); i = chx(b, i, a);
            if (ls_cstr(a, s, sizeof s) > 0) {
                i = cput(b, i, " \""); i = cput(b, i, s); i = cput(b, i, "\"");
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { i = cput(b, i, " ?"); }
    b[i] = 0; log_line(b);
}

static void ls_error (void *s, const char *f, void *v) { ls_emit("ERROR",  f, v); g_LsReal[1](s, f, v); }
static void ls_warn  (void *s, const char *f, void *v) { ls_emit("WARN",   f, v); g_LsReal[2](s, f, v); }
static void ls_notice(void *s, const char *f, void *v) { ls_emit("NOTICE", f, v); g_LsReal[3](s, f, v); }
static void ls_info  (void *s, const char *f, void *v) { ls_emit("INFO",   f, v); g_LsReal[4](s, f, v); }
static void ls_debug (void *s, const char *f, void *v) { ls_emit("DEBUG",  f, v); g_LsReal[5](s, f, v); }
static const PFN_LSSLOT g_LsStub[LS_NSLOT] = { 0, ls_error, ls_warn, ls_notice, ls_info, ls_debug, 0 };

// Called every 5 s from the heartbeat: cheap (two reads + compare), and it
// re-hooks if the game ever recreates the sink object.
static void logsink_hook(void) {
    DWORD64 obj = 0, vt = 0, slots[LS_NSLOT];
    if (!getenv_flag(L"AOE2LAN_LOGVT")) return;
    HC_TRY
        obj = HC_RD64((g_Base + LOGSINK_GLOBAL));
        if (obj && obj != g_LsObj) {
            vt = HC_RD64(obj);
            if (vt == g_Base + LOGSINK_VT_RVA)
                for (int k = 0; k < LS_NSLOT; k++) slots[k] = HC_RD64((vt + 8 * (unsigned)k));
            else vt = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { log_line("logvt: read faulted"); return; }
    if (!vt) return;
    if (!g_LsFake) {
        DWORD64 *f = (DWORD64 *)VirtualAlloc(NULL, 8 * (LS_NSLOT + 1),
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!f) { log_line("logvt: VirtualAlloc failed"); return; }
        g_LsFake = (DWORD64)f;
        HC_TRY f[0] = HC_RD64((vt - 8)); }   // RTTI complete-object locator
        __except (EXCEPTION_EXECUTE_HANDLER) { f[0] = 0; }
    }
    { DWORD64 *f = (DWORD64 *)g_LsFake;
      for (int k = 0; k < LS_NSLOT; k++) {
          g_LsReal[k] = (PFN_LSSLOT)slots[k];
          f[1 + k] = g_LsStub[k] ? (DWORD64)g_LsStub[k] : slots[k];
      } }
    HC_TRY HC_WR64(obj, g_LsFake + 8); }
    __except (EXCEPTION_EXECUTE_HANDLER) { log_line("logvt: vptr write faulted"); return; }
    g_LsObj = obj;
    { char b[128]; int i = cput(b, 0, "logvt: sink obj=0x"); i = chx(b, i, obj);
      i = cput(b, i, " vptr -> fake vtable 0x"); i = chx(b, i, g_LsFake + 8);
      i = cput(b, i, " (error/warn/notice/info/debug)");
      b[i] = 0; log_line(b); }
}

// ---------------------------------------------------------------- game-layer log level
// The game drops every level-0 message before it reaches any sink:
//   cmp byte [0x144356c66], 2 ; jae emit ; test dl,dl ; je return
// and EVERY TComm_* message is level 0 (CreateLobby at 0x140ee75d5 is `xor edx,edx`).
// That is why 10 wine sessions saw no game-layer line at click time: the log was
// filtered, not silent. Raising the byte is a .data write (same class as
// lobbygate), so it is open on wine where the .text GLOG detour that owns this
// lever on Windows is not. hookcore.c's verbose_on() is that lever; it is only
// reachable from the GLOG hook, which dies on wine at t~3.4 s.
// Guard: the level-0 writer 0x14101bb50 dereferences [[0x144356c88]+0x6f0] with no
// null check (0x14101c6fa), so the byte only goes to 2 once the game has built
// that object. Measured safe on Windows (s43 N13b). Opt-in: AOE2LAN_VERBOSE=1.
#define GAME_LOGLEVEL_RVA  0x4356c66ULL
#define GAME_LOGSINK2_RVA  0x4356c88ULL
static int g_VerboseState = -1;   // -1 = not read yet, 0 = off, 1 = armed, 2 = written
static volatile LONG g_VerboseFixes = 0;

static void verbose_setup(void) {
    if (g_VerboseState < 0) {
        g_VerboseState = getenv_flag(L"AOE2LAN_VERBOSE") ? 1 : 0;
        if (g_VerboseState) log_line("verbose: AOE2LAN_VERBOSE=1, will raise [0x144356c66] to 2");
    }
    if (g_VerboseState == 0) return;
    { BYTE old = 0; DWORD64 sink = 0, sub = 0;
      HC_TRY
        old = HC_RD8((g_Base + GAME_LOGLEVEL_RVA));
        sink = HC_RD64((g_Base + GAME_LOGSINK2_RVA));
        if (sink) sub = HC_RD64((sink + 0x6f0));
      } __except (EXCEPTION_EXECUTE_HANDLER) { log_line("verbose: read faulted, giving up"); g_VerboseState = 0; return; }
      if (old >= 2) return;                                 // already verbose (re-checked: the game resets it)
      if (!sink || !HC_IS_PTR(sub)) return;                  // retry on the next pass
      HC_TRY HC_WR8((g_Base + GAME_LOGLEVEL_RVA), 2); }
      __except (EXCEPTION_EXECUTE_HANDLER) { log_line("verbose: write faulted"); g_VerboseState = 0; return; }
      g_VerboseState = 2;
      { LONG n = InterlockedIncrement(&g_VerboseFixes);
        if (n <= 8) { char b[160]; int i = cput(b, 0, "verbose: [0x144356c66] ");
          i = cput(b, i, "-> 2 (was "); i = chx(b, i, old);
          i = cput(b, i, "), fix #"); i = cpct(b, i, (unsigned long long)n);
          i = cput(b, i, "; sink2=0x"); i = chx(b, i, sink);
          b[i] = 0; log_line(b); } } }
}

static DWORD WINAPI HeartbeatThread(LPVOID p) {
    (void)p;
    for (int k = 1;; k++) {
        Sleep(1000);
        if (k == 20) { dumptext(); textpoke(); }   // past Main.txt=46: TLS login done, .text decrypted
        if (k == 6 || k == 10 || k == 20 || k == 40) mp_spy();   // once after login
        if (k == 60) ui_widget_probe();
        if (k == 60) ui_widget_keyprobe();
        if (k == 25 || k == 40 || k == 70) rules_probe();
        if (k == 25) logsink_probe();
        if (k % 5 == 0) logsink_hook();            // hook first: the verbose lines need the vptr swap
        if (k % 5 == 1) verbose_setup();           // then un-filter level 0 halfway between hooks
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
        { WCHAR fn[80]; WCHAR *w = fn; const WCHAR *pre = L"logs\\lanhook-";
          DWORD vals[2] = { GetCurrentProcessId(), t0 };
          while (*pre) *w++ = *pre++;
          for (int p = 0; p < 2; p++) {
              WCHAR rev[12]; int rl = 0; DWORD v = vals[p];
              if (p) *w++ = L'-';
              if (!v) *w++ = L'0';
              while (v) { rev[rl++] = (WCHAR)(L'0' + (v % 10)); v /= 10; }
              while (rl--) *w++ = rev[rl];
          }
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
        if (getenv_flag(L"AOE2LAN_AIGATE")) {
            HANDLE h = CreateThread(NULL, 0, LobbyGateThread, NULL, 0, NULL);
            if (h) CloseHandle(h); else log_line("lobby gate thread failed");
        }
        { HANDLE h = CreateThread(NULL, 0, MainThread, NULL, 0, NULL);
          if (h) CloseHandle(h); else { log_line("CreateThread failed"); return FALSE; } }
    }
    return TRUE;
}
