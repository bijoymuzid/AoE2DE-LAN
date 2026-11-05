import struct
ex=open('AoE2DE_s.exe','rb').read()
# scan whole exe for qwords whose value lands in the endpoint string pool 0x14367C000-0x143682000
hits=[]
for i in range(0, len(ex)-8, 4):
    v=struct.unpack_from('<Q', ex, i)[0]
    if 0x14367C000 <= v < 0x143682000:
        hits.append((i, v))
print('qword ptrs into endpoint pool: %d' % len(hits))
for o,v in hits[:40]:
    print('  file 0x%08X -> 0x%X' % (o, v))
