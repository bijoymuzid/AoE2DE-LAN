"""Group rip-relative xrefs to given string VAs by containing function, then
print each function's bounds, clean/encrypted status and its own string refs.

Usage: python work/grp.py <strVA> [<strVA> ...]
"""
import re
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
TEXT_LO, TEXT_HI = 0x140001000, 0x143196000

_p0 = p.va2off(0x144ca3000)
_ents = [struct.unpack_from("<III", p.data, _p0 + 12 * i)
         for i in range(0x1f08a8 // 12)]
BOUNDS = sorted((0x140000000 + b, 0x140000000 + e) for b, e, u in _ents)


def bounds(va):
    for b, e in BOUNDS:
        if b <= va <= e:
            return b, e
    return None


def clean(b, e):
    o = p.va2off(b)
    n = min(e - b + 1, 64)
    return p.data[o:o + n] == D[b - B:b - B + n]


def rr_xref(target):
    """Every instruction whose rip-relative operand resolves to target."""
    out = []
    rex = set(range(0x40, 0x50))
    for i in range(len(D) - 7):
        pre = D[i]
        if pre in rex and (D[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", D, i + 3)[0]
            if (B + i + 7 + disp) == target:
                out.append(B + i)
        elif pre == 0x48 and (D[i + 2] & 0xC7) == 0x05:
            pass
    # also non-rex forms: 8D xx (modrm mod=00 rm=101)
    for i in range(len(D) - 6):
        if D[i] == 0x8D and (D[i + 1] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", D, i + 2)[0]
            if (B + i + 6 + disp) == target:
                out.append(B + i)
    return sorted(set(out))


def fn_strings(b, e, limit=8):
    out, seen = [], set()
    for i in md.disasm(D[b - B:e - B + 1], b):
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM and \
               op.mem.base == capstone.x86.X86_REG_RIP:
                t = (i.address + i.size + op.mem.disp) & 0xffffffffffffffff
                s = A.cstr(t)
                if s and 3 < len(s) < 80 and all(32 <= ord(c) < 127 for c in s) \
                   and s != "sss" and s not in seen:
                    seen.add(s)
                    out.append(s)
                    if len(out) >= limit:
                        return out
    return out


groups = {}
for a in sys.argv[1:]:
    t = int(a, 16)
    for site in rr_xref(t):
        r = bounds(site) or (site, site)
        groups.setdefault(r, []).append(site)

for (b, e), sites in sorted(groups.items()):
    print(f"\nfn {b:#x}..{e:#x} ({e-b+1} B) clean={clean(b,e)} "
          f"sites={[hex(s) for s in sites]}")
    for s in fn_strings(b, e):
        print(f"    \"{s}\"")
