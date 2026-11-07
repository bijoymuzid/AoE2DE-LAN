"""For each caller of the AI-list builder, list the function bounds and every
string its code references (resolved from the exe's .rdata).

Usage: python work/aistr.py <hexva> [<hexva> ...]
"""
import struct
import sys

sys.path.insert(0, r"D:\Age of Empires II Definitive Edition\dev\lanhook")
import capstone  # noqa: E402
import aoe2re as A  # noqa: E402

B = 0x140001000
D = A.dump()
p = A.pe
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True

_p0 = p.va2off(0x144ca3000)
_ents = [struct.unpack_from("<III", p.data, _p0 + 12 * i)
         for i in range(0x1f08a8 // 12)]
BOUNDS = sorted((0x140000000 + b, 0x140000000 + e) for b, e, u in _ents)


def bounds(va):
    for b, e in BOUNDS:
        if b <= va <= e:
            return b, e
    return None


def clean(va):
    """True when the shipped exe bytes equal the decrypted dump bytes."""
    o = p.va2off(va)
    b, e = bounds(va) or (va, va + 16)
    n = min(e - b + 1, 64)
    return p.data[o:o + n] == D[va - B:va - B + n]


def strings(b, e):
    out = []
    for i in md.disasm(D[b - B:e - B + 1], b):
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM and \
               op.mem.base == capstone.x86.X86_REG_RIP:
                t = (i.address + i.size + op.mem.disp) & 0xffffffffffffffff
                s = A.cstr(t)
                if s and 2 < len(s) < 90 and all(32 <= ord(c) < 127 for c in s):
                    out.append((i.address, t, s))
    return out


for a in sys.argv[1:]:
    va = int(a, 16)
    r = bounds(va)
    if not r:
        print(f"{va:#x}: no pdata bounds")
        continue
    b, e = r
    print(f"\n=== fn {b:#x}..{e:#x} ({e-b+1} B)  clean={clean(b)}  "
          f"(call site {va:#x}) ===")
    seen = set()
    for at, t, s in strings(b, e):
        if s in seen:
            continue
        seen.add(s)
        print(f"  {at:#x} -> {t:#x} \"{s}\"")
