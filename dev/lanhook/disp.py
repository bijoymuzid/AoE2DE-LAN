"""Find every instruction in the decrypted .text that uses a given disp32.

Usage: python disp.py <hexdisp> [--w]     --w = only stores (mem operand is dst)

aoe2re/xr only resolve rip-relative operands; struct-field gates like
screen+0x1cf8 are [reg+disp32], so scan for the disp bytes and confirm by
disassembling backwards over them.
"""
import struct
import sys

import capstone

import aoe2re as A

D = A.dump()
B = 0x140001000
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True


def scan(disp, writes_only=False):
    pat = struct.pack("<i", disp)
    out, i = [], 0
    while True:
        i = D.find(pat, i)
        if i < 0:
            break
        end = B + i + 4                      # disp ends here; imm may follow
        for back in range(3, 12):
            start = end - 4 - back
            if start < B:
                break
            for ins in md.disasm(D[start - B:start - B + 16], start):
                if ins.address <= end - 4 and ins.address + ins.size >= end \
                        and f"0x{disp:x}" in ins.op_str:
                    w = ins.operands and ins.operands[0].type == capstone.x86.X86_OP_MEM
                    if not writes_only or (w and ins.mnemonic not in ("cmp", "test", "lea")):
                        out.append((ins.address, f"{ins.mnemonic} {ins.op_str}"))
                    break
            else:
                continue
            break
        i += 1
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    wo = "--w" in sys.argv
    for a in args:
        for addr, t in scan(int(a, 16), wo):
            print(f"{addr:x}  {t}")
