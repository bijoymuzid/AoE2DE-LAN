"""Verify a rebuilt dbghelp.dll: walk g_Hooks in .rdata and print each entry,
then check the EXP bytes each entry points at. Parse-based, never a byte grep.

Usage: python work/verifydll.py [path-to-dll]
"""
import struct
import sys

sys.path.insert(0, r"D:\Age of Empires II Definitive Edition\dev\lanhook")
import aoe2re as A  # noqa: E402

DLL = sys.argv[1] if len(sys.argv) > 1 else \
    r"D:\Age of Empires II Definitive Edition\dev\lanhook\dbghelp.dll"
pe = A.PE(DLL)
d = pe.data
print("dll imagebase", hex(pe.imagebase))
for s in pe.sections:
    print("  sec", s[0], "rva", hex(s[1]), "vsize", hex(s[2]),
          "raw", hex(s[3]), "rawsize", hex(s[4]))


def cstr_at(off):
    e = d.find(b"\0", off, off + 128)
    return d[off:e].decode("ascii", "replace") if e > off else None


# find every HOOKDEF whose name points at a printable string and whose va is in
# the game image (0x140000000..0x145000000)
found = []
for sec in pe.sections:
    if sec[0] not in (".rdata", ".data"):
        continue
    base, vsize, raw, rawsize = sec[1], sec[2], sec[3], sec[4]
    for off in range(raw, raw + min(vsize, rawsize) - 40, 8):
        namep, va, expp = struct.unpack_from("<QQQ", d, off)
        wait, grp, kind = struct.unpack_from("<iii", d, off + 24)
        if not (0x140000000 <= va < 0x145000000):
            continue
        no = pe.va2off(namep)
        eo = pe.va2off(expp)
        if no is None or eo is None:
            continue
        nm = cstr_at(no)
        if not nm or not nm.isprintable() or " " in nm:
            continue
        if wait not in (60000, 600000) or grp not in (0, 1, 2, 3) \
           or kind not in (0, 1, 2, 3, 4, 5, 6, 7):
            continue
        found.append((off, nm, va, d[eo:eo + 8].hex(" "), wait, grp, kind))

print(f"\n{len(found)} HOOKDEF entries:")
for off, nm, va, exp, wait, grp, kind in sorted(found):
    rva = pe.off2va(off) - pe.imagebase
    print(f"  rva={rva:#07x} id? {nm:16s} "
          f"va={va:#011x} exp={exp} wait={wait} grp={grp} kind={kind}")
