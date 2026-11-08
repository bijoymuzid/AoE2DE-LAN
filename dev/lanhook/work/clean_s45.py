"""Cleanliness sweep: is the on-disk .text byte-identical to gametext.bin at these VAs?
An encrypted function cannot be hooked. Usage: python work/clean_s45.py <va> [<va>...]
Or: python work/clean_s45.py --s44f   (the whole §44f UNKNOWN list)
"""
import sys

sys.path.insert(0, r"D:\Age of Empires II Definitive Edition\dev\lanhook")
import aoe2re as A  # noqa: E402

p = A.pe
D = A.dump()
B = 0x140001000

S44F = [
    ("dispatch", 0x1407a7070),
    ("envelope-reader", 0x1407a7620),
    ("ms-thunk", 0x1407b66f0),
    ("ms-factory(ENC?)", 0x1407cdf10),
    ("parser#9(ENC?)", 0x1407b6710),
    ("hook17 GLog(CLEAN?)", 0x1407db520),
    ("m-read matchStartDate", 0x14039c900),
    ("m-read ownedAppIDs", 0x14057b600),
    ("m-read matchAdvertisement", 0x14056cce0),
    ("m-read profileRaces", 0x1407d4300),
    ("m-read equippedItems", 0x1403e3dc0),
    ("m-read inProgChallenges", 0x1407d4490),
    ("helper 0x14039a910", 0x14039a910),
    ("helper read-member", 0x14039b340),
    ("helper 0x14039b8e0", 0x14039b8e0),
    ("helper 0x14039b550", 0x14039b550),
    ("helper 0x14039b7c0", 0x14039b7c0),
    ("helper 0x14039bb50", 0x14039bb50),
    ("helper 0x14039b860", 0x14039b860),
    ("str-read m_type", 0x14039cc60),
    ("polling fn", 0x1406d1160),
]


def clean(va, n=48):
    o = p.va2off(va)
    if o is None:
        return None, b"", b""
    return p.data[o:o + n] == D[va - B:va - B + n], p.data[o:o + n], D[va - B:va - B + n]


if len(sys.argv) > 1 and sys.argv[1] == "--s44f":
    rows = S44F
else:
    rows = [("arg", int(a, 16)) for a in sys.argv[1:]]

for name, va in rows:
    c, dk, gt = clean(va)
    tag = {True: "CLEAN ", False: "ENCRYPT", None: "not-in-.text"}[c]
    print(f"{tag} {va:#012x}  {name}")
    if c is False:
        print(f"          disk {dk[:12].hex(' ')}")
        print(f"          gt   {gt[:12].hex(' ')}")
