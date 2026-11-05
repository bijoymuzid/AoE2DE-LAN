"""pdata function bounds + whole-function disasm helper.

Usage: python fn.py <hexva-or-name>            -> function bounds for address
       python fn.py <hexva> --dump             -> disassemble whole function
"""
import struct
import sys

import capstone

import aoe2re as A

p = A.pe
d = A.dump()
B = 0x140001000
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
            return BOUNDS[m]
    return None


def s_at(va):
    off = p.va2off(va)
    if off is None:
        return None
    e = p.data.find(b"\0", off)
    s = p.data[off:e]
    if 2 < len(s) < 200 and all(32 <= c < 127 for c in s):
        return s.decode("ascii")
    return None


def dump(va, mark=None):
    b = bounds(va)
    if not b:
        print("no function at", hex(va))
        return
    lo, hi = b
    print(f"func {lo:#x}..{hi:#x} ({hi - lo} bytes)")
    a = lo
    while a < hi:
        got = False
        for i in md.disasm(d[a - B:hi - B], a, count=1):
            got = True
            line = f"{i.address:x}  {i.mnemonic:9s} {i.op_str}"
            for op in i.operands:
                if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                    t = (i.address + i.size + op.mem.disp)
                    s = s_at(t)
                    line += f"   ; {t:#x}" + (f' "{s}"' if s else "")
                if op.type == capstone.x86.X86_OP_MEM and "0x68]" in i.op_str and i.mnemonic in ("call", "jmp"):
                    line += "   <<< +0x68 CALL"
            print(line)
            a = i.address + i.size
        if not got:
            print(f"{a:x}  .byte {d[a - B]:#04x}")
            a += 1


if __name__ == "__main__":
    va = int(sys.argv[1], 16)
    if "--dump" in sys.argv:
        dump(va)
    else:
        print(bounds(va))