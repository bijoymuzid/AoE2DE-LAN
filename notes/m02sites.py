# m02sites.py — locate enclosing fns + prologues for the M0.2 logging-hook sites.
# Inputs: AoE2DE_s.exe (.pdata intact on disk), dev/lanhook/gametext.bin
# (runtime-decrypted .text dump, file_off = rva - 0x1000).
import pefile, struct, sys
sys.path.insert(0, r'C:\Python314\Lib\site-packages')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = 'AoE2DE_s.exe'
DUMP = 'dev/lanhook/gametext.bin'
IMAGEBASE = 0x140000000

pe = pefile.PE(EXE, fast_load=True)
pdata_sec = [s for s in pe.sections if s.Name.rstrip(b'\0') == b'.pdata'][0]
pdata_va = pdata_sec.VirtualAddress + IMAGEBASE
pdata = pdata_sec.get_data()

# RUNTIME_FUNCTION entries (rva begin, rva end, rva unwind)
funcs = []
for i in range(0, len(pdata) - 12 + 1, 12):
    b, e, u = struct.unpack_from('<III', pdata, i)
    if b == 0 and e == 0:
        continue
    funcs.append((b, e))
print('pdata functions: %d' % len(funcs))

import bisect
begins = [f[0] for f in funcs]

def find_enclosing(rva):
    i = bisect.bisect_right(begins, rva) - 1
    while i >= 0:
        b, e = funcs[i]
        if b <= rva < e:
            return (b, e)
        # chained pdata entries (same fn, multiple unwind infos) share begin
        if i - 1 >= 0 and funcs[i-1][0] == b:
            i -= 1
            continue
        break
    return None

d = open(DUMP, 'rb').read()
def dump_bytes(rva, n):
    off = rva - 0x1000
    if off < 0 or off + n > len(d):
        return None
    return d[off:off+n]

md = Cs(CS_ARCH_X86, CS_MODE_64)
md.detail = False

SITES = [
    ('LAN_online_decision_fn', 0x140351399),   # lea 'starting online hosting' (same fn as 0x14035143B)
    ('LAN_hosting_lea',         0x14035143B),   # lea 'starting LAN hosting'
    ('AddLANRelay_lea',         0x140359844),   # lea 'Adding LAN relay server'
    ('relayServers_getter_call',0x14061694A),   # lea 'relayServers' key
    ('BSRStart_logsite',        0x140771D64),   # 'BattleServerRelay::Start - m_next...' epilogue
    ('OnAppSuspending_cur',     0x140F19680),
    ('OnAppResumed_cur',        0x140F196F0),
    ('Stats1_cur',              0x140F1C900),
    ('Stats2_cur',              0x140F1CAB0),
    ('getLanAdv_string',        0x14367E4F0),   # string in .rdata, not .text — enclosing fn will be None
]

seen = {}
for name, va in SITES:
    rva = va - IMAGEBASE
    enc = find_enclosing(rva)
    if enc:
        b, e = enc
        key = (b, e)
        if key not in seen:
            pro = dump_bytes(b, 24)
            print('\n== %s site 0x%X -> fn 0x%X-0x%X (size %d) NEW' % (name, va, IMAGEBASE+b, IMAGEBASE+e, e-b))
            if pro:
                print('   prologue24: %s' % pro.hex(' '))
                for ins in md.disasm(pro, IMAGEBASE + b):
                    print('   0x%x  %-24s %s %s' % (ins.address, ins.bytes.hex(' '), ins.mnemonic, ins.op_str))
                    if ins.address - (IMAGEBASE+b) >= 20:
                        break
            else:
                print('   prologue: OUT OF DUMP RANGE')
            seen[key] = name
        else:
            print('\n== %s site 0x%X -> fn 0x%X-0x%X (== %s)' % (name, va, IMAGEBASE+b, IMAGEBASE+e, seen[key]))
    else:
        print('\n== %s site 0x%X: NO pdata function (rdata/data string?)' % (name, va))

# lea-site verification: disassemble around each of the 3 .text lea sites
print('\n--- lea site context ---')
for name, va in [('0x140351399', 0x140351399), ('0x14035143B', 0x14035143B),
                 ('0x140359844', 0x140359844), ('0x14061694A', 0x14061694A),
                 ('0x140771D64', 0x140771D64)]:
    rva = va - IMAGEBASE
    off = rva - 0x1000
    ctx = d[off-16:off+48]
    print('\n%s context (from -16):' % name)
    for ins in md.disasm(ctx, va - 16):
        mark = ' <<<' if ins.address == va else ''
        print('  0x%x  %-24s %s %s%s' % (ins.address, ins.bytes.hex(' '), ins.mnemonic, ins.op_str, mark))

# qword scan: getLanAdvertisements string VA/rva in gametext.bin + on disk
TARGETS = {'VA 0x14367E4F0': struct.pack('<Q', 0x14367E4F0),
           'RVA 0x367E4F0': struct.pack('<I', 0x367E4F0)}
print('\n--- qword/dword scan for getLanAdvertisements ---')
for tname, pat in TARGETS.items():
    hits = []
    start = 0
    while True:
        i = d.find(pat, start)
        if i < 0: break
        hits.append(i)
        start = i + 1
        if len(hits) > 32: break
    print('gametext.bin %s: %d hits %s' % (tname, len(hits), ['0x%X' % (0x140001000+h) for h in hits[:8]]))

ex = open(EXE, 'rb').read()
for tname, pat in TARGETS.items():
    hits = []
    start = 0
    while True:
        i = ex.find(pat, start)
        if i < 0: break
        hits.append(i)
        start = i + 1
    print('exe %s: %d hits %s' % (tname, len(hits), ['file 0x%X' % h for h in hits[:12]]))

# also: what's around the getLanAdvertisements string on disk (endpoint table shape?)
so = 0x367E4F0
# .rdata file mapping via pe
def rva2off(r):
    for s in pe.sections:
        if s.VirtualAddress <= r < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (r - s.VirtualAddress)
    return None
o = rva2off(so)
print('\ngetLanAdvertisements disk ctx (rva 0x367E4F0 file 0x%X):' % o)
print(ex[o-96:o+96])
