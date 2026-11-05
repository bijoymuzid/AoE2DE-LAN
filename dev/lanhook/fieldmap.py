"""fieldmap.py — dump TypesStream reader field tables.

For a function range, print: name, destination offset, reader function.
Usage: python fieldmap.py 0x140615b70 0x140616b3d
"""
import bisect
import json
import re
import struct
import sys

import aoe2re as R

_funcs = [tuple(x) for x in json.load(open(r"D:\Age of Empires II Definitive Edition\dev\lanhook\pdata_funcs.json"))]
_begins = [f[0] for f in _funcs]


def func_at(va):
    rva = va - 0x140000000
    i = bisect.bisect_right(_begins, rva) - 1
    while i >= 0:
        b, e = _funcs[i]
        if b <= rva < e:
            return (0x140000000 + b, 0x140000000 + e)
        if i - 1 >= 0 and _funcs[i - 1][0] == b:
            i -= 1
            continue
        break
    return None


def fields(start, end=None, verbose=False):
    if end is None:
        r = func_at(start)
        end = r[1] if r else start + 0x2000
    name = None
    name_va = None
    ins = R.dis(start, 20000, stop_ret=False)
    out = []
    for idx, (a, sz, t) in enumerate(ins):
        if a >= end:
            break
        m = re.search(r"lea rsi, \[rip \+ (0x[0-9a-f]+)\]", t)
        if m:
            name_va = a + sz + int(m.group(1), 16)
            name = R.cstr(name_va)
            continue
        m = re.search(r"lea rdx, \[(r\d+)(?: \+ (0x[0-9a-f]+))?\]", t)
        if m and name is not None:
            base, off = m.group(1), m.group(2)
            # look ahead for the reader call
            for a2, sz2, t2 in ins[idx + 1: idx + 6]:
                m2 = re.match(r"call (0x[0-9a-f]+)$", t2)
                if m2:
                    out.append((a, name, f"{base}+{off or '0'}", int(m2.group(1), 16)))
                    name = None
                    break
                if "call qword ptr" in t2:
                    break
            continue
        # second-phase pattern: lea r8, [rip+X] ; call <expect_key> ; call <reader>
        m = re.search(r"lea r8, \[rip \+ (0x[0-9a-f]+)\]", t)
        if m:
            va = a + sz + int(m.group(1), 16)
            nm = R.cstr(va)
            reader = None
            for a2, sz2, t2 in ins[idx + 1: idx + 8]:
                m2 = re.match(r"call (0x[0-9a-f]+)$", t2)
                if m2:
                    reader = int(m2.group(1), 16)
            out.append((a, nm, "?", reader))
    return out


if __name__ == "__main__":
    s = int(sys.argv[1], 16)
    e = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    for a, nm, off, rd in fields(s, e):
        print(f"{a:#x}  {nm!s:28s} -> {off:12s} reader {rd:#x}")