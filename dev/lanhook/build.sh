#!/usr/bin/env bash
# Linux cross-build of lanhook.dll (dbghelp proxy) — the build.sh twin of build.cmd.
# Toolchain: clang --target=x86_64-w64-mingw32 (SEH via -fms-extensions), llvm-ml
# for the two MASM objects, lld for the .def / image-base link. No MSVC, no Windows.
#   Arch packages: clang llvm lld mingw-w64-gcc (objdump/md5 only)
# Output: ../../dbghelp.dll (same path build.cmd stages to).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

TARGET=x86_64-w64-mingw32
CFLAGS=(--target=$TARGET -fms-extensions -fms-compatibility-version=19.40
        -c -O1 -DNDEBUG -DWIN32_WINNT=0x0A00 -fno-stack-protector -fno-omit-frame-pointer
        ${AOE2LAN_CFLAGS:-})
OUT="${AOE2LAN_OUT:-../../dbghelp.dll}"

for a in stubs hooks; do llvm-ml64 /c "/Fo$a.obj" "$a.asm"; done
for c in hookcore iathook lanhook loginsrv; do clang "${CFLAGS[@]}" -o "$c.obj" "$c.c"; done

clang --target=$TARGET -shared -fuse-ld=lld -nostartfiles -Wl,-e,DllMain -o "$OUT" \
      lanhook.obj hookcore.obj stubs.obj hooks.obj iathook.obj loginsrv.obj \
      dbghelp.def -Wl,--image-base=0x180000000 -Wl,--disable-dynamicbase \
      -Wl,--disable-auto-import -Wl,--kill-at -lkernel32

echo "=== build ok: $OUT ($(stat -c%s "$OUT") bytes) md5 $(md5sum "$OUT" | cut -d' ' -f1)"
