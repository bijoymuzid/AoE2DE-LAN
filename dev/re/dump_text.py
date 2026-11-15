#!/usr/bin/env python3
# dump_text.py <pid> [out.bin] — snapshot AoE2DE_s.exe .text (and optionally other
# r-xp mappings of the exe) from /proc/<pid>/mem. Arxan decrypts pages at runtime,
# so this captures what the on-disk file hides. Run while game is up.
import sys, os, re, time

pid = int(sys.argv[1])
out = sys.argv[2] if len(sys.argv) > 2 else f"/tmp/aoe_text_{pid}_{int(time.time())}.bin"

maps = []
with open(f"/proc/{pid}/maps") as f:
    for line in f:
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
        if not m:
            continue
        lo, hi, perm, path = int(m[1], 16), int(m[2], 16), m[3], m[4]
        if "AoE2DE_s.exe" in path:
            maps.append((lo, hi, perm, path))

# Arxan remaps sections anonymously: keep exec mappings in the exe's .text VA range
if maps:
    base = maps[0][0]
    maps = []
    with open(f"/proc/{pid}/maps") as f:
        for line in f:
            m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
            if not m:
                continue
            lo, hi, perm = int(m[1], 16), int(m[2], 16), m[3]
            if "x" in perm and base + 0x1000 <= lo < base + 0x3197000:
                maps.append((lo, hi, perm, m[4]))

if not maps:
    sys.exit("no executable AoE2DE_s.exe mapping found (wrong pid? use the wineserver-child that has the exe mapped)")

lo0 = min(m[0] for m in maps)
hi0 = max(m[1] for m in maps)
print(f"mappings: {len(maps)}, range {lo0:#x}-{hi0:#x} ({hi0-lo0:#x} bytes)")
for m in maps:
    print(f"  {m[0]:#x}-{m[1]:#x} {m[2]} {m[3]}")

PAGE = 0x1000
buf = bytearray()
unread = []
with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem:
    for lo, hi, perm, path in maps:
        for page in range(lo, hi, PAGE):
            try:
                mem.seek(page)
                data = mem.read(min(PAGE, hi - page))
            except OSError:
                unread.append(page)
                data = b"\x00" * min(PAGE, hi - page)
            buf += data

with open(out, "wb") as f:
    f.write(buf)
print(f"wrote {out} ({len(buf):#x} bytes), base={lo0:#x}, unreadable pages: {len(unread)}")
if unread:
    print("unread:", " ".join(f"{p:#x}" for p in unread[:20]))
