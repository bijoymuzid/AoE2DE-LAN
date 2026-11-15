#!/usr/bin/env python3
# disasm.py <snapshot.bin> <base_va> <rva> [count] [back]
#   Slices snapshot at RVA (file offset = rva - (base section va - base)), shells
#   out to objdump. Default 80 insns forward, or <back> bytes of context before.
#   With --range A B: disassemble [A,B).
import sys, subprocess, tempfile, os

args = sys.argv[1:]
if args[0] == "--range":
    _, snap, base, a, b = args[:5]
    base, a, b = int(base, 16), int(a, 16), int(b, 16)
    data = open(snap, "rb").read()
    sec_rva = 0x1000  # .text starts at RVA 0x1000; snapshot offset 0 == image base+0x1000
    off_a, off_b = a - sec_rva, b - sec_rva
    chunk = data[off_a:off_b]
    vma = 0x140000000 + a
else:
    snap, base, rva = args[0], int(args[1], 16), int(args[2], 16)
    count = int(args[3]) if len(args) > 3 else 80
    back = int(args[4]) if len(args) > 4 else 0
    data = open(snap, "rb").read()
    sec_rva = 0x1000
    start = rva - back
    off = start - sec_rva
    chunk = data[off:off + count * 8 + back]
    vma = 0x140000000 + start

with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as t:
    t.write(chunk)
    tmp = t.name
try:
    subprocess.run(["objdump", "-D", "-b", "binary", "-m", "i386:x86-64",
                    "-M", "intel", f"--adjust-vma={vma:#x}", tmp], check=False)
finally:
    os.unlink(tmp)
