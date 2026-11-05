import pefile, struct, sys
sys.path.insert(0, r'C:\Python314\Lib\site-packages')
EXE='AoE2DE_s.exe'; DUMP='dev/lanhook/gametext.bin'; IB=0x140000000
ex=open(EXE,'rb').read(); d=open(DUMP,'rb').read()
pe=pefile.PE(EXE, fast_load=True)
pdata_sec=[s for s in pe.sections if s.Name.rstrip(b'\0')==b'.pdata'][0]
pdata=pdata_sec.get_data()
funcs=[struct.unpack_from('<III',pdata,i)[:2] for i in range(0,len(pdata)-11,12)]
funcs=[f for f in funcs if f[0]]
def off2rva(off):
    for s in pe.sections:
        if s.PointerToRawData<=off<s.PointerToRawData+s.SizeOfRawData:
            return s.VirtualAddress+(off-s.PointerToRawData)
MODRM={0x05,0x0D,0x15,0x1D,0x25,0x2D,0x35,0x3D}
def lea_targets():
    t={}
    for i in range(len(d)-8):
        if d[i] in (0x48,0x4C,0x4D,0x49) and d[i+1]==0x8D and d[i+2] in MODRM:
            disp=struct.unpack_from('<i',d,i+3)[0]
            tgt=0x140001000+i+7+disp
            t.setdefault(tgt,[]).append(0x140001000+i)
    return t
LT=lea_targets()
def find_str(s):
    o=ex.find(s+b'\x00'); return (o, IB+off2rva(o)) if o>=0 else (None,None)
STRS=[b'/game/advertisement/getLanAdvertisements', b'/game/advertisement/findAdvertisements',
      b'/game/advertisement/getAdvertisements', b'lanServerGuids', b'avatarAliases',
      b'/game/account/login', b'/game/advertisement/updateState', b'/game/advertisement/host',
      b'/game/advertisement/join', b'/game/advertisement/update']
print('--- endpoint string lea refs (decrypted dump) ---')
for s in STRS:
    o,va=find_str(s)
    if va is None: print('%-46s NOT FOUND' % s.decode()); continue
    hits=LT.get(va,[])
    print('%-46s VA 0x%X  lea-hits %d %s' % (s.decode(), va, len(hits), ['0x%X'%h for h in hits[:4]]))
# pdata bounds for getter
def enc(va):
    rva=va-IB
    for b,e in funcs:
        if b<=rva<e: return (IB+b, IB+e)
    return None
for name,va in [('RelayGetter 0x14039AAF0',0x14039AAF0),('LogHelper 0x1402BCB30',0x1402BCB30),
                ('HostDecision 0x1403503A0',0x1403503A0),('StartAdjacent 0x140771600',0x140771600),
                ('AddLANRelay 0x1403593C0',0x1403593C0),('LoginParse 0x140615B70',0x140615B70)]:
    print('%-26s pdata %s' % (name, enc(va)))
