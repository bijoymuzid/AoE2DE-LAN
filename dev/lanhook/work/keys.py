"""Dump the JSON key names a bond-generated reader probes, in parse order.

Usage: python work/keys.py <hexva> [<hexva>...]
"""
import sys

import capstone

sys.path.insert(0, r"D:\Age of Empires II Definitive Edition\dev\lanhook")
import aoe2re as A  # noqa: E402
import fn  # noqa: E402

p = A.pe
D = A.dump()
B = 0x140001000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True


def s_at(va):
    o = p.va2off(va)
    if o is None:
        return None
    e = p.data.find(b"\0", o)
    s = p.data[o:e]
    if 1 < len(s) < 80 and all(32 <= c < 127 for c in s):
        return s.decode()
    return None


for a in sys.argv[1:]:
    f = int(a, 16)
    b = fn.bounds(f)
    if not b:
        print(hex(f), "no bounds")
        continue
    keys = []
    for i in md.disasm(D[b[0] - B:b[1] - B], b[0]):
        if "rip" not in i.op_str:
            continue
        for op in i.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                t = (i.address + i.size + op.mem.disp) & 0xFFFFFFFFFFFFFFFF
                s = s_at(t)
                if s and not s.startswith("F:"):
                    keys.append(s)
    print("%-24s %s  (%d bytes)" % (hex(f), keys, b[1] - b[0]))
