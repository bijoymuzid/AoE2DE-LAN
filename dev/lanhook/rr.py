import re,struct,sys
d=open('gametext.bin','rb').read(); B=0x140001000
targets=set(int(x,16) for x in sys.argv[1:])
hits={t:[] for t in targets}
rex=set(range(0x40,0x50))
for i in range(len(d)-7):
    if d[i] not in rex: continue
    m=d[i+2]
    if (m & 0xC7)!=0x05: continue
    disp=struct.unpack_from('<i',d,i+3)[0]
    tgt=(B+i+7+disp)&0xffffffffffffffff
    if tgt in hits: hits[tgt].append((B+i,d[i:i+7].hex(' ')))
for t in targets:
    print(hex(t),[(hex(a),h) for a,h in hits[t]][:20])
