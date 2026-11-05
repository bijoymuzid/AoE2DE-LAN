import struct
ex=open('AoE2DE_s.exe','rb').read()
# which endpoint VAs have qword refs on disk?
for va,name in [(0x14367E4F0,'getLanAdvertisements'),(0x14367DAB0,'host'),(0x14367DD38,'join'),
                (0x14367DB88,'update'),(0x14367DBC8,'updateState'),(0x14367DA00,'findAdvertisements'),
                (0x14367E520,'lanServerGuids'),(0x14367E4C0,'avatarAliases')]:
    pat=struct.pack('<Q',va); hits=[]; s=0
    while True:
        i=ex.find(pat,s)
        if i<0: break
        hits.append(i); s=i+1
    print('%-24s 0x%X qword-refs %d %s' % (name,va,len(hits),['file 0x%X'%h for h in hits[:6]]))
# what are the most-referenced pool strings?
from collections import Counter
c=Counter()
for i in range(0,len(ex)-8,4):
    v=struct.unpack_from('<Q',ex,i)[0]
    if 0x14367C000<=v<0x143682000: c[v]+=1
def rva2off(r):
    return r-0x1400 if 0x3197000<=r<0x3da60a8 else None
print('\ntop-referenced pool strings:')
for v,n in c.most_common(12):
    o=rva2off(v-0x140000000)
    s=ex[o:o+48].split(b'\0')[0] if o else b'?'
    print('  0x%X x%d  %r' % (v,n,s))
