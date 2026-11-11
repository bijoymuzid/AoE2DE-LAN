// sehprobe.c — regression test for HC_TRY's crash guard on the clang-mingw
// build. Headless (no display): one case per wine process, because a case that
// is not caught kills the process and would mask every case after it.
//
//   case                expect    why
//   bare                DIED      call-less __try body -> clang emits no handler
//   inline_anchored     DIED      handler alive, but the inline load is in no
//                                 scope record (clang wraps call sites only)
//   hc_rd               GUARDED   the access is inside a callee -> the unwind
//   hc_wr               GUARDED   reaches this frame's guarded call site
//
// build (same flags as build.sh) + run:
//   cd dev/lanhook && for O in 0 1; do clang --target=x86_64-w64-mingw32 \
//     -fms-extensions -fms-compatibility-version=19.40 -O$O -DNDEBUG \
//     -fno-stack-protector -fno-omit-frame-pointer -o /tmp/sehprobe-O$O.exe \
//     sehprobe.c; done
//   WINEPREFIX=~/Games/aoe/winepfx/pfx WINEDEBUG=-all \
//     "$HOME/Games/aoe/Proton-CachyOS Latest-x86_64_v3/files/bin/wine" \
//     /tmp/sehprobe-O1.exe hc_rd
//   grade all four (exit 0 = the loop printed SEHPROBE: PASS):
//   for O in 0 1; do for c in hc_wr hc_rd inline_anchored bare; do
//     out=$(WINEPREFIX=~/Games/aoe/winepfx/pfx WINEDEBUG=-all \
//       "$HOME/Games/aoe/Proton-CachyOS Latest-x86_64_v3/files/bin/wine" \
//       /tmp/sehprobe-O$O.exe $c 2>&1)
//     got=$(echo "$out" | grep -qE '^rc=-1 GUARDED' && echo GUARDED || echo DIED)
//     case "$c" in hc_rd|hc_wr) exp=GUARDED;; *) exp=DIED;; esac
//     [ "$got" = "$exp" ] || fail=1
//     printf 'O%s %-16s %-8s expect=%-8s %s\n' $O $c $got $exp \
//       "$([ "$got" = "$exp" ] && echo ok || echo FAIL)"; done; done
//   echo "SEHPROBE: $([ ${fail:-0} = 0 ] && echo PASS || echo FAIL)"
//
// static view (region labels must wrap the hc_rd/hc_wr calls, not the loads):
//   clang ... -S -o /tmp/sehprobe.s sehprobe.c && grep -n 'EH_LABEL\|callq' /tmp/sehprobe.s
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "hookcore.h"      // HC_TRY / HC_RD64 / HC_WR64 + the clang workaround decls
#include "hcaccess.inc"    // their definitions, shared with hookcore.c

#define BAD 0xdeadbeef00ULL

// (1) no call in the body: clang emits no handler at all (unwind Flags: 0).
__attribute__((noinline)) static int bare(void) {
    DWORD64 v = 0;
    __try { v = *(const volatile DWORD64 *)BAD; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    return (int)v;
}

// (2) HC_TRY's anchor keeps a handler alive, but an access written inline in the
//     body still lands in no scope record -> uncaught. This is the defect.
__attribute__((noinline)) static int inline_anchored(void) {
    DWORD64 v = 0;
    HC_TRY v = *(const volatile DWORD64 *)BAD; }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    return (int)v;
}

// (3) the fix: the access is a call, so the fault happens in hc_rd's frame and
//     unwinds to this frame's guarded call site.
__attribute__((noinline)) static int via_hc_rd(void) {
    DWORD64 v = 0;
    HC_TRY v = HC_RD64(BAD); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    return (int)v;
}

// (4) same, for the write path (the AI-gate store to screen+0x1cf8 is a write).
__attribute__((noinline)) static int via_hc_wr(void) {
    HC_TRY HC_WR64(BAD, 1); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return -1; }
    return 0;
}

int main(int argc, char **argv) {
    const char *c = argc > 1 ? argv[1] : "hc_rd";
    int rc;
    printf("case=%s\n", c);
    fflush(stdout);
    if      (!strcmp(c, "bare"))            rc = bare();
    else if (!strcmp(c, "inline_anchored")) rc = inline_anchored();
    else if (!strcmp(c, "hc_wr"))           rc = via_hc_wr();
    else                                    rc = via_hc_rd();
    printf("rc=%d %s\n", rc, rc == -1 ? "GUARDED" : "NOT-FAULTED");
    fflush(stdout);
    return 0;
}
