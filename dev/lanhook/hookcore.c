// hookcore.c — detour machinery shared by lanhook.dll and hooktest.exe.
//
// v1 bug fixed here: v1 copied a FIXED 5 bytes into the trampoline, but e.g.
// `40 53 48 83 EC 20` (push rbx; sub rsp,0x20) has its first instruction
// boundary at 6 — the trampoline executed a torn `sub rsp,0xE9` + garbage on
// the first hit. This version:
//  - copies an instruction-aligned N (5..11) via a mini LDE that refuses
//    anything it cannot pin exactly, including any rip-relative access;
//  - patches the target with ONE aligned 8-byte CAS write (a concurrent
//    execute can never observe a half-written detour);
//  - routes execution through hooks.asm's thunk which preserves all volatile
//    GPRs/XMMs and the whole stack, so unknown signatures are safe.
// Near-page slot layout (64 B): [0..N-1] original bytes, [N..N+4] E9 back to
// target+N, [16..33] stub: mov rax,thunk; mov r10d,id; jmp rax.
#include <windows.h>
#include <stdint.h>
#include "hookcore.h"

// ---------------------------------------------------------------- logging
static HANDLE g_hLog = INVALID_HANDLE_VALUE;
static volatile LONG g_logLock = 0;
static DWORD g_t0 = 0;

static DWORD64 g_ModBaseVal = 0;
DWORD64 g_ModBase(void) { return g_ModBaseVal; }
void hc_set_modbase(DWORD64 base) { g_ModBaseVal = base; }

void hc_set_log(HANDLE h, DWORD t0) { g_hLog = h; g_t0 = t0; }

void log_line(const char *s) {
    if (g_hLog == INVALID_HANDLE_VALUE) return;
    { char buf[1024];
      DWORD now = GetTickCount() - g_t0;
      int n = 0;
      DWORD sec = now / 1000, ms = now % 1000;
      buf[n++]='['; buf[n++]='t'; buf[n++]='=';
      { char tmp[8]; int tl=0; DWORD v=sec;
        do { tmp[tl++]=(char)('0'+(v%10)); v/=10; } while(v);
        while(tl--) buf[n++]=tmp[tl]; }
      buf[n++]='.'; buf[n++]=(char)('0'+(ms/100));
      buf[n++]=(char)('0'+((ms/10)%10)); buf[n++]=(char)('0'+(ms%10));
      buf[n++]='s'; buf[n++]=']'; buf[n++]=' ';
      while (*s && n < 1000) buf[n++]=*s++;
      buf[n++]='\r'; buf[n++]='\n';
      while (InterlockedCompareExchange(&g_logLock, 1, 0) != 0) Sleep(0);
      { DWORD w=0; WriteFile(g_hLog, buf, (DWORD)n, &w, NULL); }
      InterlockedExchange(&g_logLock, 0); }
}

void logf1(const char *pre, DWORD64 a) {
    char b[160]; int i=0; while(*pre) b[i++]=*pre++;
    b[i++]='0'; b[i++]='x';
    for (int k=15;k>=0;k--) { int d=(int)((a>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); }
    b[i]=0; log_line(b);
}

// tiny string builders (no CRT)
static int bsput(char *b, int i, const char *s) { while (*s) b[i++]=*s++; return i; }
static int bxput(char *b, int i, DWORD64 v) {
    for (int k=15;k>=0;k--) { int d=(int)((v>>(k*4))&15); b[i++]=(char)(d<10?'0'+d:'a'+d-10); }
    return i; }
static int bnput(char *b, int i, DWORD v) {
    char t[12]; int tl=0;
    if (!v) t[tl++]='0';
    while (v) { t[tl++]=(char)('0'+(v%10)); v/=10; }
    while (tl) b[i++]=t[--tl];
    return i; }

// ---------------------------------------------------------------- near page
static BYTE *g_NearPage = NULL;
static volatile LONG g_NearUsed = 0;
BYTE *hc_near_page(void) { return g_NearPage; }

void hc_alloc_near(BYTE *probe) {
    BYTE *lo = (BYTE*)((DWORD64)(probe - 0x20000000) & ~0xFFFFULL);
    BYTE *hi = (BYTE*)((DWORD64)(probe + 0x20000000) & ~0xFFFFULL);
    for (int attempt=0; attempt<8 && !g_NearPage; attempt++) {
        for (BYTE *cand=lo; cand<hi && !g_NearPage; cand+=0x4000000) {
            BYTE *a = (BYTE*)VirtualAlloc(cand, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (a) g_NearPage = a;
        }
    }
}

// ---------------------------------------------------------------- mini LDE
// decodes prologue-style x64 only; returns 0 for anything it cannot pin
// exactly (including rip-relative forms, which must never be relocated)
static int modrm_extra(const BYTE *p, int i, int *riprel) {
    BYTE m = p[i];
    int mod = m >> 6, rm = m & 7, n = 1;
    *riprel = 0;
    if (mod == 3) return n;                              // reg,reg
    if (rm == 4) {                                       // SIB follows
        n++;
        if (mod == 0 && (p[i+1] & 7) == 5) return n + 4; // no base, disp32
    }
    if (mod == 0) {
        if (rm == 5) { *riprel = 1; return n + 4; }      // [rip+disp32]
        return n;
    }
    return n + (mod == 1 ? 1 : 4);                       // disp8 / disp32
}

static int insn_len(const BYTE *p) {
    int i = 0, rex = 0;
    while (i < 2) {
        BYTE b = p[i];
        if (b >= 0x40 && b <= 0x4F) { rex = 1; i++; continue; }
        break;
    }
    { BYTE op = p[i]; i++;
      switch (op) {
      case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
      case 0x56: case 0x57: case 0x58: case 0x59: case 0x5A: case 0x5B:
      case 0x5C: case 0x5D: case 0x5E: case 0x5F:
          return i;                                      // push/pop r64
      case 0x68: return i + 4;                           // push imm32
      case 0x6A: return i + 1;                           // push imm8
      case 0x81: case 0x83: {                            // group1 r/m, imm
          int rl, me = modrm_extra(p, i, &rl);
          if (!me || rl) return 0;
          return i + me + (op == 0x81 ? 4 : 1); }
      case 0x89: case 0x8A: case 0x8B: case 0x8D: {      // mov/lea r/m
          int rl, me = modrm_extra(p, i, &rl);
          if (!me || rl) return 0;
          return i + me; }
      case 0xB8: case 0xB9: case 0xBA: case 0xBB: case 0xBC:
      case 0xBD: case 0xBE: case 0xBF:
          return i + (rex ? 8 : 4);                      // mov r, imm
      default:
          return 0;
      } }
}

// bytes to relocate: >=5, <=11, on instruction boundaries
static int hook_len(const BYTE *p) {
    int n = 0;
    for (;;) {
        int l = insn_len(p + n);
        if (l <= 0) return 0;
        n += l;
        if (n >= 5) return (n <= 11) ? n : 0;
    }
}

// ---------------------------------------------------------------- install
int hc_match_now(const BYTE *t, const BYTE *exp) {
    __try {
        for (int i=0;i<8;i++) if (t[i]!=exp[i]) return 0;
        return 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
}

int hc_install_hook(BYTE *target, int id) {
    BYTE ob[16];
    BYTE *slot;
    int n;
    if (id < 0 || id >= HK_MAX) return 0;
    if (((DWORD64)target & 15) != 0) { log_line("install: target not 16-aligned"); return 0; }
    if (!g_NearPage) { log_line("install: no near page"); return 0; }
    __try {
        for (int i=0;i<16;i++) ob[i] = ((volatile BYTE*)target)[i];
    } __except (EXCEPTION_EXECUTE_HANDLER) { log_line("install: target read fault"); return 0; }
    n = hook_len(ob);
    if (n < 5) { log_line("install: LDE rejected prologue"); return 0; }
    { LONG used;
      do { used = g_NearUsed;
           if (used + 64 > 4096) { log_line("install: near page full"); return 0; }
      } while (InterlockedCompareExchange(&g_NearUsed, used + 64, used) != used);
      slot = g_NearPage + used; }
    // trampoline: original N bytes + E9 back to target+N
    for (int i=0;i<n;i++) slot[i] = ob[i];
    { int64_t back = (int64_t)((BYTE*)target + n) - (int64_t)(slot + n + 5);
      slot[n]=0xE9; slot[n+1]=(BYTE)back; slot[n+2]=(BYTE)(back>>8);
      slot[n+3]=(BYTE)(back>>16); slot[n+4]=(BYTE)(back>>24); }
    // stub at slot+16: mov rax,thunk ; mov r10d,id ; jmp rax
    { BYTE *st = slot + 16;
      DWORD64 thunk = (DWORD64)&lanhook_thunk;
      st[0]=0x48; st[1]=0xB8;
      *(DWORD64*)(st+2) = thunk;
      st[10]=0x41; st[11]=0xBA; *(DWORD*)(st+12)=(DWORD)id;
      st[16]=0xFF; st[17]=0xE0; }
    g_TailTable[id] = (unsigned long long)slot;
    FlushInstructionCache(GetCurrentProcess(), slot, 40);
    // patch target: E9 rel32 -> slot+16, as ONE aligned qword (CAS)
    { DWORD old=0; int vpOk=0; int ok=1;
      __try { vpOk = VirtualProtect(target, 8, PAGE_EXECUTE_READWRITE, &old); }
      __except (EXCEPTION_EXECUTE_HANDLER) { log_line("install: VP fault"); vpOk = 0; }
      if (!vpOk) { log_line("install: VP fail"); return 0; }
      __try {
          BYTE nb[8]; DWORD64 new8, cur, orig8;
          int64_t rel = (int64_t)(slot + 16) - (int64_t)((BYTE*)target + 5);
          nb[0]=0xE9; nb[1]=(BYTE)rel; nb[2]=(BYTE)(rel>>8);
          nb[3]=(BYTE)(rel>>16); nb[4]=(BYTE)(rel>>24);
          nb[5]=ob[5]; nb[6]=ob[6]; nb[7]=ob[7];
          new8 = *(DWORD64*)nb;
          orig8 = *(DWORD64*)ob;
          cur = InterlockedCompareExchange64((volatile DWORD64*)target, new8, orig8);
          if (cur != orig8) { log_line("install: target bytes raced, aborting"); ok = 0; }
          else FlushInstructionCache(GetCurrentProcess(), target, 8);
      } __except (EXCEPTION_EXECUTE_HANDLER) { log_line("install: patch fault"); ok = 0; }
      VirtualProtect(target, 8, old, &old);
      if (!ok) return 0; }
    { char b[160]; int i = bsput(b, 0, "installed ");
      i = bsput(b, i, g_Hooks[id].name);
      i = bsput(b, i, " n=");  i = bnput(b, i, (DWORD)n);
      i = bsput(b, i, " slot=0x"); i = bxput(b, i, (DWORD64)slot);
      b[i]=0; log_line(b); }
    return 1;
}

// ---------------------------------------------------------------- hit logger
// thunk passes ctx: [0x00..0x5F]=xmm0-5, ctx[12]=r11, ctx[13]=r10(id),
// ctx[14]=r9, ctx[15]=r8, ctx[16]=rdx, ctx[17]=rcx, ctx[18]=rax,
// ctx[19]=original return address
static volatile LONG g_Hits[HK_MAX];
static volatile LONG g_HLines[HK_MAX];

static int read_cstr(const void *p, char *out, int maxn) {
    int i = 0;
    __try {
        const volatile char *q = (const volatile char*)p;
        for (i = 0; i < maxn-1; i++) {
            char c = q[i];
            if (c == 0 || c < 0x20 || c > 0x7e) break;
            out[i] = c;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    out[i] = 0;
    return i;
}

static int contains_ci(const char *h, const char *n) {
    int hl=0, nl=0;
    while (h[hl]) hl++;
    while (n[nl]) nl++;
    if (!nl || hl < nl) return 0;
    for (int i=0; i+nl<=hl; i++) {
        int ok=1;
        for (int j=0;j<nl;j++) {
            char a=h[i+j], b=n[j];
            if (a>='A'&&a<='Z') a=(char)(a+32);
            if (b>='A'&&b<='Z') b=(char)(b+32);
            if (a!=b) { ok=0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}

void lanhook_log_hit(int id, const unsigned long long *ctx) {
    char b[640];
    LONG n = InterlockedIncrement(&g_Hits[id]);
    int i;
    if (id < 0 || id >= HK_MAX) return;
    if (g_Hooks[id].kind == HK_RDSTR) {
        // rdx = format string; r8/r9 = first varargs; ctx[20]/ctx[21] = 5th/6th
        // (stack) args. entry_rsp = ctx+0x78, so arg5 = [ctx+0xA0] = ctx[20].
        const char *sp = (const char*)ctx[16];
        char s[112];
        int L;
        if ((DWORD64)sp < 0x10000) return;
        L = read_cstr(sp, s, 112);
        if (L <= 0) return;
        { LONG ln = InterlockedIncrement(&g_HLines[id]);
          if (ln > 512) return;
          i = bsput(b, 0, "HIT ");
          i = bsput(b, i, g_Hooks[id].name);
          i = bsput(b, i, " #"); i = bnput(b, i, (DWORD)n);
          i = bsput(b, i, ": \"");
          i = bsput(b, i, s);
          i = bsput(b, i, "\"");
          { char s8[72], s9[72]; int l8 = -1, l9 = -1;
            if (ctx[15] > 0x10000) l8 = read_cstr((const void*)ctx[15], s8, 72);
            if (ctx[14] > 0x10000) l9 = read_cstr((const void*)ctx[14], s9, 72);
            i = bsput(b, i, " r8=0x"); i = bxput(b, i, ctx[15]);
            if (l8 > 0) { i = bsput(b, i, " s8=\""); i = bsput(b, i, s8); i = bsput(b, i, "\""); }
            i = bsput(b, i, " r9=0x"); i = bxput(b, i, ctx[14]);
            if (l9 > 0) { i = bsput(b, i, " s9=\""); i = bsput(b, i, s9); i = bsput(b, i, "\""); }
            i = bsput(b, i, " a5=0x"); i = bxput(b, i, ctx[20]);
            i = bsput(b, i, " a6=0x"); i = bxput(b, i, ctx[21]); }
          i = bsput(b, i, " ret=0x"); i = bxput(b, i, ctx[19]);
          b[i]=0; log_line(b); }
        return;
    }
    if (g_Hooks[id].kind == HK_R8STR) {
        const char *sp = (const char*)ctx[15];
        char s[112];
        int L;
        if ((DWORD64)sp < 0x10000) return;
        L = read_cstr(sp, s, 112);
        if (L > 0 && contains_ci(s, "relay")) {
            LONG ln = InterlockedIncrement(&g_HLines[id]);
            if (ln <= 512) {
                i = bsput(b, 0, "HIT ");
                i = bsput(b, i, g_Hooks[id].name);
                i = bsput(b, i, " #"); i = bnput(b, i, (DWORD)n);
                i = bsput(b, i, ": \"");
                i = bsput(b, i, s);
                i = bsput(b, i, "\" ret=0x"); i = bxput(b, i, ctx[19]);
                b[i]=0; log_line(b); }
        }
        return;
    }
    if (g_Hooks[id].kind == HK_TLS) {
        // OpenSSL static fns (SSL_CTX_set_verify etc.): dump arg regs + the
        // CALLER's module+offset so the run answers: which ctx verifies how,
        // against which store, fed by which certs. Cap high: store adds fire
        // ~66x per pool build, set_verify once per ctx.
        LONG ln = InterlockedIncrement(&g_HLines[id]);
        if (ln > 512) {
            if (ln == 513) { i = bsput(b, 0, "HIT ");
                            i = bsput(b, i, g_Hooks[id].name);
                            i = bsput(b, i, " log capped at 512 lines");
                            b[i]=0; log_line(b); }
            return; }
        i = bsput(b, 0, "HIT ");
        i = bsput(b, i, g_Hooks[id].name);
        i = bsput(b, i, " #"); i = bnput(b, i, (DWORD)n);
        i = bsput(b, i, " rcx=0x"); i = bxput(b, i, ctx[17]);
        i = bsput(b, i, " rdx=0x"); i = bxput(b, i, ctx[16]);
        if (ctx[15] > 0x10000) {
            i = bsput(b, i, " r8=0x"); i = bxput(b, i, ctx[15]);
            i = bsput(b, i, " (off 0x"); i = bxput(b, i, ctx[15] - g_ModBase());
            i = bsput(b, i, ")"); }
        i = bsput(b, i, " r9=0x");  i = bxput(b, i, ctx[14]);
        i = bsput(b, i, " ret=0x"); i = bxput(b, i, ctx[19]);
        b[i]=0; log_line(b);
        return;
    }
    if (g_Hooks[id].kind == HK_WSET) {
        // 0x140ab6300: rcx = widget, rdx = new flags at [rcx+0x3d8] (old flags at [rcx+0x3d8]).
        // Bit 4 (0x4) = disabled/locked (dl=1 sets 0x4, dl=0 clears 0x4), bit 8 (0x8) = hidden.
        // Widget path is an MSVC std::string at rcx + 0x3e8 (s33c).
        static DWORD64 s_Seen[512];
        static volatile LONG s_NSeen = 0;
        DWORD64 w = ctx[17];
        DWORD64 newf = ctx[16];
        DWORD64 oldf = 0;
        DWORD64 vt = 0;
        DWORD64 caller = ctx[19];
        DWORD64 lcaller = 0;
        DWORD64 l24 = 0, l25 = 0, l26 = 0;   // s38: thunk-frame window, see below
        int suppressed = 0;                  // s38: set when we refuse a lobby lock
        char nm[96]; int nml = 0;
        // Skip boot-time screen creation (first 20 s) so Options/QueueButton0..63 don't eat the cap
        if (GetTickCount() - g_t0 < 20000) return;
        if (w < 0x10000) return;
        __try {
            vt = *(const volatile DWORD64*)w;
            oldf = *(const volatile DWORD64*)(w + 0x3d8);
            const volatile BYTE *s = (const volatile BYTE*)(w + 0x3e8);
            DWORD64 sz = *(const volatile DWORD64*)(s + 0x10);
            DWORD64 cap = *(const volatile DWORD64*)(s + 0x18);
            const void *p = (cap > 15) ? (const void*)*(const volatile DWORD64*)s : (const void*)s;
            if (sz > 0 && sz < 256 && cap >= sz && cap < 4096 && (DWORD64)p > 0x10000) {
                int r = read_cstr(p, nm, 96);
                if (r > 0) nml = r;
            }
            const volatile DWORD64 *sp = (const volatile DWORD64*)(ctx + 20);
            for (int k = 0; k < 12; k++) {
                DWORD64 v = sp[k];
                if (v >= g_ModBase() + 0x1aa0000 && v < g_ModBase() + 0x1ad0000) {
                    lcaller = v - g_ModBase();
                    break;
                }
            }
            // s38: proven frame. locker -> [vt+0x68] thunk 0x140acc950 -> WSE.
            // thunk prologue (push rsi; sub rsp,0x20) puts thunk_entry_rsp =
            // WSE_entry_rsp + 0x30 = ctx + 0xC8, so ctx[25] = return address into
            // the locker. The range filter above hid it (locker is outside
            // 0x1aa0000..0x1ad0000), so read the slot directly plus its neighbours.
            #define LKMOD(v) (((v) >= g_ModBase() && (v) < g_ModBase() + 0x4000000) ? (v) - g_ModBase() : (v))
            l24 = LKMOD(sp[4]);   // ctx[24]
            l25 = LKMOD(sp[5]);   // ctx[25] = locker return address
            l26 = LKMOD(sp[6]);   // ctx[26]
            #undef LKMOD
        } __except (EXCEPTION_EXECUTE_HANDLER) { nml = 0; }
        // s38 FIX: the host lobby locks every match-settings row in one pass. The
        // locker (entry 0x141a2ce20, gate `cmp [this+0x1cf8],[0x14326b258]` -> je
        // skips the locking) and the Victory/Team locker (0x141a31940) are both
        // ENCRYPTED ON DISK, so they cannot be hooked or patched. WidgetSetEn
        // (0x140ab6300) IS clean and already hooked (id 14), so refuse the lock
        // here: when the caller (ctx[25] = the [vt+0x68] thunk's saved return addr)
        // is inside a locker and bit 0x4 is being SET, clear it in rdx (ctx[16]).
        // hooks.asm restores rdx from ctx[16], so the original stores enabled flags.
        if ((newf & 4) &&
            ((l25 >= 0x1a2ce20 && l25 < 0x1a2d2dd) ||    // main match-settings locker
             (l25 >= 0x1a31940 && l25 < 0x1a32e31) ||    // Victory / Team locker
             (l25 >= 0x1a2e250 && l25 < 0x1a2f5e2) ||    // re-lock pass: Start/EndAge, Victory, Resources
             (l25 >= 0x1a48820 && l25 < 0x1a48cc2))) {   // ButtonCiv (civ / add-AI button)
            ((unsigned long long *)ctx)[16] = newf & ~4ULL;
            newf &= ~4ULL;
            suppressed = 1;
        }
        if (((oldf ^ newf) & 4) == 0 && !lcaller && !suppressed) return;
        if (!nml) return;
        { DWORD64 h = 1469598103934665603ULL;
          for (int k = 0; k < nml; k++) h = (h ^ (BYTE)nm[k]) * 1099511628211ULL;
          h = (h << 8) | (newf & 0xFF);
          LONG cur = s_NSeen;
          for (LONG k = 0; k < cur && k < 512; k++) if (s_Seen[k] == h) return;
          { LONG idx = InterlockedIncrement(&s_NSeen) - 1;
            if (idx < 512) s_Seen[idx] = h; } }
        { LONG ln = InterlockedIncrement(&g_HLines[id]);
          if (ln > 512) {
              if (ln == 513) log_line("HIT WidgetSetEn log capped at 512 lines");
              return;
          }
          i = bsput(b, 0, "HIT WidgetSetEn #"); i = bnput(b, i, (DWORD)n);
          i = bsput(b, i, " old=0x"); i = bxput(b, i, oldf);
          i = bsput(b, i, " new=0x"); i = bxput(b, i, newf);
          i = bsput(b, i, " name=\""); i = bsput(b, i, nm); i = bsput(b, i, "\"");
          i = bsput(b, i, " vt=0x"); i = bxput(b, i, vt - g_ModBase());
          i = bsput(b, i, " ret=0x"); i = bxput(b, i, caller - g_ModBase());
          if (suppressed) { i = bsput(b, i, " SUPPRESSED"); }
          if (lcaller) { i = bsput(b, i, " lobby_caller=0x"); i = bxput(b, i, lcaller); }
          i = bsput(b, i, " l24=0x"); i = bxput(b, i, l24);
          i = bsput(b, i, " l25=0x"); i = bxput(b, i, l25);
          i = bsput(b, i, " l26=0x"); i = bxput(b, i, l26);
          b[i] = 0; log_line(b); }
        return;
    }
    { LONG ln = InterlockedIncrement(&g_HLines[id]);
      if (ln > 64) {
          if (ln == 65) { i = bsput(b, 0, "HIT ");
                          i = bsput(b, i, g_Hooks[id].name);
                          i = bsput(b, i, " log capped at 64 lines");
                          b[i]=0; log_line(b); }
          return; }
      i = bsput(b, 0, "HIT ");
      i = bsput(b, i, g_Hooks[id].name);
      i = bsput(b, i, " #"); i = bnput(b, i, (DWORD)n);
      i = bsput(b, i, " rcx=0x"); i = bxput(b, i, ctx[17]);
      i = bsput(b, i, " rdx=0x"); i = bxput(b, i, ctx[16]);
      i = bsput(b, i, " r8=0x");  i = bxput(b, i, ctx[15]);
      i = bsput(b, i, " r9=0x");  i = bxput(b, i, ctx[14]);
      i = bsput(b, i, " ret=0x"); i = bxput(b, i, ctx[19]);
      b[i]=0; log_line(b); }
}
