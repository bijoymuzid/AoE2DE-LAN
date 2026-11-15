#!/usr/bin/env python3
# lobbyrelay.py — push the local hub's live lobby list to a remote peer's hub
# node port (47101), bypassing the broken hub-to-hub mesh: the peer's hub
# silently drops our hub's gossip floods while accepting the same ADVERT on a
# direct connection (proven 00:25, manual feed). Companion to beaconrelay.py.
# Advertisement id = the lobby's sessionID (stable per lobby), seq = increasing
# timestamp so the peer hub updates the entry every cycle; a lobby change
# (new sessionID) withdraws the old entry first.
import json, re, socket, sys, time

PEER = sys.argv[1] if len(sys.argv) > 1 else "100.79.215.72"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 47101
ORIGIN = "lobbyrelay000000000000000000000001"

def find_local():
    s = socket.create_connection(("127.0.0.1", 47100), timeout=2)
    s.sendall(b'{"type":"FIND"}\n')
    s.settimeout(2)
    d = b""
    try:
        while b"\n" not in d:
            c = s.recv(65536)
            if not c:
                break
            d += c
    except socket.timeout:
        pass
    s.close()
    try:
        return json.loads(d.decode(errors="replace"))
    except Exception:
        return {}

def send_peer(msg):
    try:
        s = socket.create_connection((PEER, PORT), timeout=4)
        s.settimeout(2)
        s.sendall((json.dumps(msg) + "\n").encode())
        try:
            s.recv(4096)
        except Exception:
            pass
        s.close()
        return True
    except Exception as e:
        print(f"lobbyrelay: send failed: {e!r}", flush=True)
        return False

last_id = None
print(f"lobbyrelay: feeding {PEER}:{PORT} from local hub FIND", flush=True)
while True:
    ads = find_local().get("advertisements", [])
    cur = None
    a = ads[0] if ads else None
    if a:
        m = re.search(r"sessionID=(\d+)", a.get("lobby", {}).get("body", ""))
        cur = m.group(1) if m else None
    if cur != last_id:
        if last_id:
            send_peer({"type": "WITHDRAW", "advertisementID": last_id, "originGUID": ORIGIN})
            print(f"lobbyrelay: withdrew {last_id}", flush=True)
        last_id = cur
        if cur:
            print(f"lobbyrelay: new lobby {cur}", flush=True)
    if cur:
        send_peer({"type": "ADVERT", "advertisementID": cur, "originGUID": ORIGIN,
                   "seq": int(time.time()) % 1000000, "ttlHops": 1,
                   "relayIP": a.get("relayIP", ""),
                   "relayPorts": a.get("relayPorts", {}),
                   "relayAuthToken": "lan", "lobby": a["lobby"]})
    time.sleep(5)
