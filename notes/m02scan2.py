# m02scan2.py — follow-ups: getLanAdvertisements full-path lea, getter/log-helper
# prologues, on-disk-vs-dump (encrypted?) check for all hook targets.
import pefile, struct, sys
sys.path.insert(0, r'C:\Python314\Lib\site-packages')
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

EXE = 'AoE2DE_s.exe'
DUMP = 'dev/lanhook/gametext.bin'
IMAGEBASE = 0x140000000

ex = open(EXE, 'rb').read()
d = open(DUMP, 'rb').read()
pe = pefile.PE(EXE, fast_load=True)

def rva2off(r):
    for s in pe.sections:
        if s.VirtualAddress <= r < s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData):
            return s.PointerToRawData + (r - s.VirtualAddress)
    return None

def dump_at(va, n):
    return d[va - 0x140001000: va - 0x140001000 + n]

def disk_at(va, n):
    o = rva2off(va - IMAGEBASE)
    return ex[o:o+n]

md = Cs(CS_ARCH_X86, CS_MODE_64)

# 1. exact VA of the full path string "/game/advertisement/getLanAdvertisements"
o = ex.find(b'/game/advertisement/getLanAdvertisements\x00')
# file offset -> rva: find section containing
def off2rva(off):
    for s in pe.sections:
        if s.PointerToRawData <= off < s.PointerToRawData + s.SizeOfRawData:
            return s.VirtualAddress + (off - s.PointerToRawData)
    return None
fullpath_rva = off2rva(o)
fullpath_va = IMAGEBASE + fullpath_rva
print('fullpath "/game/advertisement/getLanAdvertisements" file 0x%X rva 0x%X VA 0x%X' % (o, fullpath_rva, fullpath_va))
bare_va = 0x14367E4F0
print('bare suffix at VA 0x%X (delta %d -> fullpath starts %d bytes before bare)' % (bare_va, bare_va - fullpath_va, bare_va - fullpath_va))

# 2. lea scan of decrypted dump for ANY rip-rel lea landing in [fullpath_va-0x40, fullpath_va+0x60]
lo, hi = fullpath_va - 0x40, fullpath_va + 0x60
hits = []
MODRM = {0x05,0x0D,0x15,0x1D,0x25,0x2D,0x35,0x3D}
for i in range(len(d) - 8):
    if d[i] in (0x48, 0x4C, 0x4D, 0x49) and d[i+1] == 0x8D and d[i+2] in MODRM:
        disp = struct.unpack_from('<i', d, i+3)[0]
        tgt = 0x140001000 + i + 7 + disp
        if lo <= tgt < hi:
            hits.append((0x140001000 + i, tgt))
print('leas into fullpath neighborhood: %d' % len(hits))
for a, t in hits:
    print('  lea at 0x%X -> 0x%X (offset %+d into string region)' % (a, t, t - fullpath_va))

# 3. prologue of the field getter 0x14039AAF0 + log helper 0x1402BCB30 (+0x1402ABC80 for Start)
for name, va in [('getter 0x14039AAF0', 0x14039AAF0),
                 ('loghelper 0x1402BCB30', 0x1402BCB30),
                 ('loghelper2 0x1402ABC80', 0x1402ABC80),
                 ('loghelper3 0x1402ABE60', 0x1402ABE60)]:
    pro = dump_at(va, 24)
    disk = disk_at(va, 24)
    enc = (pro == disk)
    print('\n%s dump: %s' % (name, pro.hex(' ')))
    print('  disk: %s   identical=%s' % (disk.hex(' '), enc))
    for ins in md.disasm(pro, va):
        print('  0x%x  %-20s %s %s' % (ins.address, ins.bytes.hex(' '), ins.mnemonic, ins.op_str))
        if ins.address - va >= 16: break

# 4. encrypted-or-not table for all hook targets (dump vs disk first 12 bytes)
print('\n--- target encryption check (dump==disk first 12B => never encrypted / dump captured pre-decrypt?) ---')
TG = [('OnAppSuspending', 0x140F19680), ('OnAppResumed', 0x140F196F0),
      ('Stats1', 0x140F1C900), ('Stats2', 0x140F1CAB0),
      ('HostDecision', 0x1403503A0), ('AddLANRelay', 0x1403593C0),
      ('RelayGetter', 0x14039AAF0), ('LoginParse', 0x140615B70),
      ('StartAdjacent', 0x140771600)]
for name, va in TG:
    pro = dump_at(va, 12)
    disk = disk_at(va, 12)
    print('%-14s 0x%X dump=%s disk=%s same=%s' % (name, va, pro.hex(), disk.hex(), pro == disk))

# 5. what are the lea target strings at the sites (verify)
def lea_str(va, ln=64):
    # resolve rip-rel lea at va (48 8d XX disp32)
    disp = struct.unpack_from('<i', d, va - 0x140001000 + 3)[0]
    tgt = va + 7 + disp
    return tgt, disk_at(tgt, ln)
for name, va in [('0x140351399', 0x140351399), ('0x14035143B', 0x14035143B),
                 ('0x140359844', 0x140359844), ('0x14061694A', 0x14061694A), ('0x140771D64', 0x140771D64)]:
    tgt, s = lea_str(va)
    print('%s -> 0x%X: %r' % (name, tgt, s.split(b'\0')[0][:80]))
