"""List pdata functions in a VA range with their string refs.

Usage: python work/fnstr.py <loVA> <hiVA> [minLen]
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

lo, hi = int(sys.argv[1], 16), int(sys.argv[2], 16)
for b, e in BOUNDS:
    if e < lo or b > hi:
        continue
    seen, out = set(), []
    for i in md.disasm(D[b - B:e - B + 1], b):
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM and \
               op.mem.base == capstone.x86.X86_REG_RIP:
                t = (i.address + i.size + op.mem.disp) & 0xffffffffffffffff
                s = A.cstr(t)
                if s and 2 < len(s) < 90 and all(32 <= ord(c) < 127 for c in s) \
                   and s not in seen:
                    seen.add(s)
                    out.append(f"{i.address:#x} \"{s}\"")
    o = p.va2off(b)
    clean = p.data[o:o + 48] == D[b - B:b - B + 48]
    print(f"\nfn {b:#x}..{e:#x} ({e-b+1} B) clean={clean}")
    for s in out[:20]:
        print(f"    {s}")
