// hcaccess.inc — the guarded memory accessors HC_TRY needs on clang-mingw.
//
// Shared by hookcore.c (shipped in dbghelp.dll) and sehprobe.c (the headless
// measurement that proves they are needed), so the probe tests the code that
// actually runs. Reason they exist: see the HC_TRY comment in hookcore.h —
// clang emits an SEH scope record only around call instructions, so a faulting
// access must live in a callee for the caller's __except to see it.
//
// Deliberately noinline and no __try of their own: the fault has to escape this
// frame so the unwind reaches the guarded call site.
//
// sz = 1/2/4/8. A faulting access raises out of this frame; *out is untouched.
#ifndef HCACCESS_INC
#define HCACCESS_INC

// Opaque no-op call: keeps clang from dropping the SEH handler of an HC_TRY
// block whose body would otherwise contain no call at all.
__attribute__((noinline)) void hc_seh_anchor(void) { __asm__ volatile(""); }

__attribute__((noinline)) void hc_rd(DWORD64 addr, void *out, int sz) {
    switch (sz) {
    case 1: *(BYTE  *)out = *(const volatile BYTE  *)addr; break;
    case 2: *(WORD  *)out = *(const volatile WORD  *)addr; break;
    case 4: *(DWORD *)out = *(const volatile DWORD *)addr; break;
    default:*(DWORD64 *)out = *(const volatile DWORD64 *)addr; break;
    }
}

__attribute__((noinline)) void hc_wr(DWORD64 addr, DWORD64 val, int sz) {
    switch (sz) {
    case 1: *(volatile BYTE  *)addr = (BYTE)val;  break;
    case 2: *(volatile WORD  *)addr = (WORD)val;  break;
    case 4: *(volatile DWORD *)addr = (DWORD)val; break;
    default:*(volatile DWORD64 *)addr = val;      break;
    }
}

#endif // HCACCESS_INC
