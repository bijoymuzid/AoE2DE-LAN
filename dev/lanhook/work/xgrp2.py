"""Group rip-relative xrefs to string VAs by containing pdata function; report
clean/encrypted and the function's own string refs. numpy-backed, fast.

Usage: python work/xgrp2.py <strVA> [...]
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
    lo, hi = 0, len(BOUNDS) - 1
    while lo <= hi:
        m = (lo + hi) // 2
        s, e = BOUNDS[m]
        if va < s:
            hi = m - 1
        elif va >= e:
            lo = m + 1
        else:
            return s, e
    return None


def clean(b, e):
    o = p.va2off(b)
    n = min(e - b + 1, 64)
    return p.data[o:o + n] == D[b - B:b - B + n]


def fn_strings(b, e, limit=14):
    out, seen = [], set()
    for i in md.disasm(D[b - B:e - B + 1], b):
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM and \
               op.mem.base == capstone.x86.X86_REG_RIP:
                t = (i.address + i.size + op.mem.disp) & 0xffffffffffffffff
                s = A.cstr(t)
                if s and 3 < len(s) < 90 and all(32 <= ord(c) < 127 for c in s) \
                   and s not in seen:
                    seen.add(s)
                    out.append(f"{i.address:#x} \"{s}\"")
                    if len(out) >= limit:
                        return out
    return out


groups = {}
for a in sys.argv[1:]:
    t = int(a, 16)
    for site, txt in A.xrefs(t, limit=60):
        r = bounds(site) or (site, site)
        groups.setdefault(r, []).append((site, txt))

for (b, e), sites in sorted(groups.items()):
    print(f"\nfn {b:#x}..{e:#x} ({e-b+1} B) clean={clean(b,e)}")
    for s, txt in sites:
        print(f"    site {s:#x}  {txt}")
    for s in fn_strings(b, e):
        print(f"    {s}")
