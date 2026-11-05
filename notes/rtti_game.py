"""AoE2DE_s.exe RTTI/vtable survey (M0.3). Pure python, no Ghidra needed.
IMPORTANT: MSVC RTTI names live in BOTH .rdata and .data raw ranges
(.rdata raw 0x3195c00..0x3da4e00, .data raw 0x3da4e00..0x4254400); the bulk
of game class names (TComm_*, RLink::*) sits in .data. Scanning .rdata only
misses them. Writes notes/rtti_tables.json: {class_name: [{vtable, slots}]}.
TypeDescriptor anchor: first qword = 0x14365d5f8 (type_info vftable, PE32+).
COL is PE32+ form: [sig=1][off][cd][pTypeDescriptor RVA][pClassDescriptor RVA][pSelf RVA]."""
import re, pefile, struct, json, sys
BIN = sys.argv[1] if len(sys.argv) > 1 else 'AoE2DE_s.exe'
OUT = sys.argv[2] if len(sys.argv) > 2 else 'notes/rtti_tables.json'
pe = pefile.PE(BIN, fast_load=True); base = pe.OPTIONAL_HEADER.ImageBase
b = open(BIN, 'rb').read()
secs = [(s.Name.decode().strip('\0'), s.VirtualAddress, s.Misc_VirtualSize,
         s.PointerToRawData, s.SizeOfRawData) for s in pe.sections]
def fo2va(fo):
    for _, va, vs, raw, rsz in secs:
        if raw <= fo < raw + rsz: return base + va + (fo - raw)
def va2fo(va):
    rva = va - base
    for _, va_, vs, raw, rsz in secs:
        if va_ <= rva < va_ + vs: return raw + (rva - va_)
rdata = [s for s in secs if s[0] == '.rdata'][0]
data = [s for s in secs if s[0] == '.data'][0]
# 1. TypeDescriptor name scan (name at desc+0x10, desc starts with 0x14365d5f8 qword)
names = {}
for sec in (rdata, data):
    raw, rsz = sec[3], sec[4]
    region = b[raw:raw + rsz]
    for m in re.finditer(rb'\.\?A[^\x00]{4,300}', region):
        nm = m.group()
        if b'@@' not in nm: continue
        va = fo2va(raw + m.start())
        dfo = va2fo(va - 0x10)
        if dfo is None: continue
        if struct.unpack('<Q', b[dfo:dfo + 8])[0] == 0x14365d5f8:
            names[raw + m.start()] = nm
descs = {fo2va(fo) - 0x10: nm for fo, nm in names.items()}
print('descriptors:', len(descs))
# 2. COL scan: u32 rva of descriptor at COL+0x0C, sig==1, pself==col rva
cols = {}
for sec in (rdata, data):
    raw, rsz = sec[3], sec[4]
    for dva in descs:
        pat = struct.pack('<I', dva - base)
        st = raw
        while True:
            i = b.find(pat, st, raw + rsz)
            if i < 0: break
            colva = fo2va(i) - 0x0C
            cfo = va2fo(colva)
            if cfo is not None:
                try:
                    sig, off, cd, ptd, pcd, pself = struct.unpack('<IIIIII', b[cfo:cfo + 24])
                    if sig == 1 and ptd == dva - base and pself == colva - base:
                        cols[colva] = dva
                except struct.error: pass
            st = i + 1
print('cols:', len(cols))
# 3. vtable: qword == colva; vtable starts at that qword + 8
out = {}
for colva, dva in cols.items():
    pat = struct.pack('<Q', colva)
    for sec in (rdata, data):
        raw, rsz = sec[3], sec[4]
        st = raw
        while True:
            i = b.find(pat, st, raw + rsz)
            if i < 0: break
            out.setdefault(descs[dva], []).append(fo2va(i) + 8)
            st = i + 1
print('classes with vtables:', len(out))
# 4. slot counts via .pdata function starts
exc = pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
pfo = None
for s in pe.sections:
    if s.VirtualAddress <= exc.VirtualAddress < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
        pfo = s.PointerToRawData + (exc.VirtualAddress - s.VirtualAddress)
starts = set()
for i in range(exc.Size // 12):
    beg, _, _ = struct.unpack_from('<III', b, pfo + i * 12)
    starts.add(base + beg)
def slots(vva):
    n = 0
    while True:
        fo = va2fo(vva + n * 8)
        if fo is None: break
        if struct.unpack('<Q', b[fo:fo + 8])[0] not in starts: break
        n += 1
        if n > 200: break
    return n
res = {nm.decode(errors='replace'): [{'vtable': hex(v), 'slots': slots(v)}
        for v in sorted(set(vt))] for nm, vt in out.items()}
json.dump(res, open(OUT, 'w'), indent=1)
print('wrote', OUT)
