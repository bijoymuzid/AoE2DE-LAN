"""Report, for each function called from a given dump, whether it is clean on
disk (hookable) and how many call sites it has.

Usage: python work/cleanfns.py <dumpfile> [...]
"""
import re
import struct
import sys
from collections import Counter

sys.path.insert(0, r"D:\Age of Empires II Definitive Edition\dev\lanhook")
import aoe2re as A  # noqa: E402

B = 0x140001000
D = A.dump()
p = A.pe

_p0 = p.va2off(0x144ca3000)
_ents = [struct.unpack_from("<III", p.data, _p0 + 12 * i)
         for i in range(0x1f08a8 // 12)]
BOUNDS = sorted((0x140000000 + b, 0x140000000 + e) for b, e, u in _ents)


def bounds(va):
    for b, e in BOUNDS:
        if b <= va <= e:
            return b, e
    return None


# whole-dump call-site index: target -> [site, ...]
CALLS = {}
for m in re.finditer(rb"[\xe8\xe9]", D):
    o = m.start()
    if o + 5 > len(D):
        continue
    rel = struct.unpack_from("<i", D, o + 1)[0]
    t = (B + o + 5 + rel) & 0xffffffffffffffff
    if 0x140001000 <= t < 0x140001000 + len(D):
        CALLS.setdefault(t, []).append(B + o)


def clean(va, n=48):
    o = p.va2off(va)
    if o is None:
        return None
    return p.data[o:o + n] == D[va - B:va - B + n]


targets = Counter()
for fn in sys.argv[1:]:
    for line in open(fn, encoding="utf-8", errors="replace"):
        m = re.search(r"call\s+(0x[0-9a-f]+)", line)
        if m:
            targets[int(m.group(1), 16)] += 1

rows = []
for t, n in targets.items():
    b = bounds(t)
    start = b[0] if b else t
    c = clean(start)
    rows.append((c is True, len(CALLS.get(start, [])), t, start, n,
                 (b[1] - b[0] + 1) if b else 0))
rows.sort(key=lambda r: (not r[0], r[1]))
print(f"{'clean':6} {'sites':>6} {'calledVA':>12} {'fnStart':>12} "
      f"{'size':>7} {'uses':>5}")
for c, ns, t, s, n, sz in rows:
    print(f"{str(c):6} {ns:6d} {t:#12x} {s:#12x} {sz:7d} {n:5d}")
