"""Fast rip-relative xref finder using the precomputed xref_i32.npy index.

xref_i32.npy[o] == uint32_at(o) (the raw disp32, unsigned), so a rip-relative
operand whose disp32 sits at dump offset o and whose instruction ends at o+4
resolves to VA 0x140001000 + 4 + IDX[o] + o (IDX[o] taken as signed).

Usage: python work/rrx.py <targetVA> [...]     (optionally --ctx N to disasm)
"""
import sys

import numpy as np

sys.path.insert(0, r"D:\Age of Empires II Definitive Edition\dev\lanhook")
import capstone  # noqa: E402
import aoe2re as A  # noqa: E402
import fn as F  # noqa: E402

B = 0x140001000
_RAW = np.load(r"D:\Age of Empires II Definitive Edition\dev\lanhook\xref_i32.npy")
# re-interpret the unsigned disp32 as signed, then fold in the offset
IDX = np.where(_RAW >= 0x80000000, _RAW - 0x100000000, _RAW) \
    + np.arange(len(_RAW), dtype=np.int64)
del _RAW
D = A.dump()
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
md.detail = True


def offsets(target):
    """Dump offsets of every disp32 whose rip-relative operand hits target."""
    want = target - B - 4
    return (np.nonzero(IDX == want)[0]).tolist()


def sites(target):
    """(instruction VA, text) for every rip-relative reference to target."""
    out = []
    for o in offsets(target):
        end = B + o + 4
        for back in range(4, 12):
            start = end - back
            if start < B:
                break
            for ins in md.disasm(D[start - B:start - B + 16], start):
                if ins.address + ins.size == end and "rip" in ins.op_str:
                    out.append((start, f"{ins.mnemonic} {ins.op_str}"))
                    break
            else:
                continue
            break
    return out


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    ctx = 0
    for a in sys.argv[1:]:
        if a.startswith("--ctx"):
            ctx = int(a.split("=")[1])
    for a in args:
        t = int(a, 16)
        s = sites(t)
        print(f"\n=== {t:#x} \"{A.cstr(t)}\" -> {len(s)} site(s)")
        for va, txt in s:
            b = F.bounds(va)
            bs = f"{b[0]:#x}..{b[1]:#x}" if b else "?"
            print(f"  site {va:#x}  {txt}   fn {bs}")
            if ctx:
                F.dump(va - ctx)
