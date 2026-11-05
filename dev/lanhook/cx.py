import re,struct,sys
d=open('gametext.bin','rb').read(); B=0x140001000
targets=[int(x,16) for x in sys.argv[1:]]
hits={t:[] for t in targets}
for m in re.finditer(rb'\xe8',d):
    o=m.start()
    if o+5>len(d): continue
    rel=struct.unpack_from('<i',d,o+1)[0]
    tgt=(B+o+5+rel)&0xffffffffffffffff
    if tgt in hits: hits[tgt].append(B+o)
for t in targets: print(hex(t), [hex(h) for h in hits[t]])
