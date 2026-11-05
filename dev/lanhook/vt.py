"""vtable scan over .rdata of the shipped exe.

A vtable = 8-aligned run of >=4 consecutive qwords that all point into .text.
Reports each run with the value of a chosen slot index (default 13 = +0x68)
and a frequency histogram of that slot.
"""
import struct
import sys
from collections import Counter

import aoe2re as A

p = A.pe
IB = p.imagebase
T0, T1 = 0x140001000, 0x143196000


def sec_addrs(name):
    for n, va, vs, rp, rs in p.sections:
        if n == name:
            return IB + va, IB + va + rs
    raise KeyError(name)


R0, R1 = sec_addrs(".rdata")


def qwords(lo, hi):
    return [struct.unpack_from("<Q", p.data, p.va2off(a))[0] for a in range(lo, hi, 8)]


def vtables(minlen=4):
    out, run = [], []
    for a in range(R0, R1 - 8, 8):
        v = struct.unpack_from("<Q", p.data, p.va2off(a))[0]
        if T0 <= v < T1:
            run.append((a, v))
        else:
            if len(run) >= minlen:
                out.append(run)
            run = []
    if len(run) >= minlen:
        out.append(run)
    return out


if __name__ == "__main__":
    slot = int(sys.argv[1], 16) if len(sys.argv) > 1 else 0x68
    name = sys.argv[2] if len(sys.argv) > 2 else None
    vts = vtables()
    print(f"{len(vts)} candidate vtables")
    hist = Counter()
    for run in vts:
        i = slot // 8
        if i < len(run):
            hist[run[i][1]] += 1
    for fn, n in hist.most_common(12):
        print(f"  slot {slot:#x} -> {fn:#x}  in {n} vtables")
    if name:
        for run in vts:
            pass
