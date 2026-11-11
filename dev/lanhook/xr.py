"""Rip-relative xref scan over the decrypted .text dump.

Usage: python xr.py <hexva> [<hexva> ...]

aoe2re.xrefs() is wrong (it indexes int32 slots, but instructions are not
4-byte aligned). This scans every byte offset for the disp32 value and then
confirms the instruction by disassembling backwards from its end.
"""
import struct
import sys

import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import aoe2re as A  # noqa: E402

D = A.dump()
B = 0x140001000


def xrefs(target, limit=200):
    """All instructions whose RIP-relative operand resolves to `target`."""
    import numpy as np
    out = []
    for off0 in range(4):                      # instructions are not 4-byte aligned
        buf = D[off0:len(D) - 3]
        arr = np.frombuffer(buf[:len(buf) // 4 * 4], dtype="<i4").astype(np.int64)
        eff = arr + (off0 + 4 * np.arange(len(arr)) + 4) + B
        idx = np.nonzero(eff == target)[0]
        for i in idx:
            end = B + off0 + 4 * int(i) + 4
            for back in range(10, 2, -1):   # longest form wins (REX prefixes)
                start = end - back
                for ins in A._md.disasm(D[start - B:start - B + 15], start):
                    if ins.address + ins.size == end and "rip" in ins.op_str:
                        out.append((ins.address, f"{ins.mnemonic} {ins.op_str}"))
                        break
                else:
                    continue
                break
            else:
                out.append((end - 4, "<unconfirmed>"))
            if len(out) >= limit:
                return out
    return out


if __name__ == "__main__":
    for a in sys.argv[1:]:
        t = int(a, 16)
        print(hex(t), [(hex(x), s) for x, s in xrefs(t)])
