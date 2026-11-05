import aoe2re as R, re, sys, fieldmap as F
HELP={0x14039b7c0,0x14039bb50,0x14039b550,0x14039b8e0,0x14039aaf0,0x14039a910,0x14039b340}
def scan(start):
    r=F.func_at(start); end=r[1] if r else start+0x3000
    ins=R.dis(start,90000,stop_ret=False)
    key=None; off=None; out=[]
    for i,(a,sz,t) in enumerate(ins):
        if a>=end: break
        m=re.search(r'lea (r\w+), \[rip \+ (0x[0-9a-f]+)\]',t)
        if m:
            s=R.cstr(a+sz+int(m.group(2),16))
            if s and len(s)<40 and all(32<=ord(c)<127 for c in s): key=s
            continue
        m=re.search(r'lea rdx, \[(r\w+) \+ (0x[0-9a-f]+)\]',t)
        if m: off=(m.group(1),m.group(2)); continue
        m=re.match(r'call (0x[0-9a-f]+)$',t)
        if m:
            fn=int(m.group(1),16)
            if fn in HELP: continue
            out.append((a,key,off,fn)); key=None; off=None
    print(f'--- {hex(start)} .. {hex(end)}')
    for a,k,o,fn in out:
        print(f'  {a:#x} key={k!s:26s} dst={o} reader={fn:#x}')
scan(int(sys.argv[1],16))
