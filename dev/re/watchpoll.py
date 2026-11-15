#!/usr/bin/env python3
# watchpoll.py — ptrace-free peer-array poller. On a NEW peer appearing in the
# rlink manager, spawns the gdb armer (armcatch.py) with PEER=<addr>.
# env: TARGET_PID, GAME_BASE (default 0x140000000)
import os, struct, subprocess, sys, time

PID = int(os.environ["TARGET_PID"])
RE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "armcatch.py")

def read_u64(addr):
    with open(f"/proc/{PID}/mem", "rb", buffering=0) as m:
        m.seek(addr)
        return struct.unpack("<Q", m.read(8))[0]

def peer_list():
    g = read_u64(0x144C9E5F0)
    if not g:
        return []
    mgr = read_u64(g + 0x1880)
    if not mgr:
        return []
    beg, end = read_u64(mgr + 0x70), read_u64(mgr + 0x78)
    if not (0 < end - beg <= 0x1000):
        return []
    return [read_u64(beg + i * 16) for i in range((end - beg) // 16)]

known = set()
print(f"watchpoll: pid={PID}", flush=True)
while True:
    try:
        peers = peer_list()
    except OSError:
        time.sleep(0.05)
        continue
    for p in peers:
        if p and p not in known:
            known.add(p)
            print(f"watchpoll: NEW PEER {p:#x} -> arming gdb", flush=True)
            subprocess.Popen(["gdb", "-q", "-p", str(PID), "-batch", "-x", RE],
                             env={**os.environ, "PEER": hex(p), "TARGET_PID": str(PID)},
                             stdout=sys.stdout, stderr=sys.stderr)
    time.sleep(0.005)
