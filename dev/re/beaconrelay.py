#!/usr/bin/env python3
# beaconrelay.py — forward BattleServer.exe's UDP 9999 LAN beacons to a remote
# peer over tailscale (tailscale does not forward broadcasts, notes/linux-session4.md 4g).
# The game binds 0.0.0.0:9999 first; we co-listen with SO_REUSEADDR so broadcast
# datagrams are delivered to both sockets. Usage: beaconrelay.py <peer-ip> [peer-port]
import os, socket, sys, time

PEER = sys.argv[1] if len(sys.argv) > 1 else "100.79.215.72"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 9999
GAMEDIR = "/home/hexal/Games/aoe/winepfx/pfx/drive_c/Games/AoE2DE"

def game_bound_9999():
    # scan the host UDP table (game runs in the same netns under Wine)
    # hex port 270F = 9999
    try:
        with open("/proc/net/udp") as f:
            next(f)
            for line in f:
                if line.split()[1].endswith(":270F"):
                    return True
    except OSError:
        pass
    return False

print(f"beaconrelay: waiting for a :9999 bind (game) ...", flush=True)
while not game_bound_9999():
    time.sleep(0.5)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 9999))
s.settimeout(30.0)
print(f"beaconrelay: co-listening on 0.0.0.0:9999, forwarding to {PEER}:{PORT}", flush=True)

fwd = 0
while True:
    try:
        data, src = s.recvfrom(2048)
    except socket.timeout:
        print(f"beaconrelay: no beacon in 30s (forwarded total {fwd})", flush=True)
        continue
    # BattleServer beacon starts 0x21 0x24 0x00 ('!$.', 56 B). Forward anything
    # that looks like a beacon; log others once.
    if len(data) >= 4 and data[0] == 0x21 and data[1] == 0x24:
        s.sendto(data, (PEER, PORT))
        fwd += 1
        if fwd % 10 == 1:
            print(f"beaconrelay: fwd #{fwd} {len(data)}B from {src[0]} -> {PEER}:{PORT}", flush=True)
    else:
        print(f"beaconrelay: ignoring {len(data)}B from {src[0]}: {data[:16].hex()}", flush=True)
