#!/usr/bin/env python3
"""L1 acceptance test (PLAN §17.2): two lanhub instances on one machine, seeded at
each other; a lobby hosted on one must appear on the other via gossip, and a
HELLO -> HOST -> FIND -> JOIN walk must return the shapes of PLAN §5.1.

Usage: python3 test_walk.py   (expects target/release/lanhub; build first)
Exit code 0 = all checks passed.
"""
import json, os, socket, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
HUB = os.path.join(HERE, "target", "release", "lanhub")

CHECKS = []

def check(name, cond, detail=""):
    CHECKS.append((name, bool(cond)))
    print(f"{'PASS' if cond else 'FAIL'}  {name}" + (f"  ({detail})" if detail and not cond else ""))

def connect(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    return s, s.makefile("r")

def call(s, f, msg):
    s.sendall((json.dumps(msg) + "\n").encode())
    return json.loads(f.readline())

def main():
    a = subprocess.Popen([HUB, "--no-autodiscover", "--control-port", "47100", "--node-port", "47101",
                          "--nick", "Alice", "--peer", "127.0.0.1:47201"])
    b = subprocess.Popen([HUB, "--no-autodiscover", "--control-port", "47200", "--node-port", "47201",
                          "--nick", "Bob", "--peer", "127.0.0.1:47101"])
    try:
        sa, fa = None, None
        for _ in range(40):  # hubs may still be binding
            try:
                sa, fa = connect(47100); sb, fb = connect(47200); break
            except OSError:
                time.sleep(0.25)
        if sa is None:
            check("hubs start", False, "could not connect"); return 1

        r = call(sa, fa, {"type": "HELLO", "ver": 1, "nick": "Alice",
                          "appChecksum": "aa", "dataChecksum": "dd"})
        check("A: HELLO -> profileID/sessionToken/ports",
              r.get("ok") and r.get("profileID") and r.get("sessionToken") and r.get("ports"), r)
        r = call(sb, fb, {"type": "HELLO", "ver": 1, "nick": "Bob",
                          "appChecksum": "aa", "dataChecksum": "dd"})
        check("B: HELLO", r.get("ok"), r)

        r = call(sa, fa, {"type": "HOST", "lobby": {"name": "coop vs ai", "maxPlayers": 8,
                          "map": "arabia", "slots": [], "passworded": False}})
        adv = r.get("advertisementID")
        check("A: HOST -> advertisementID/relayAuthToken/relayIP",
              r.get("ok") and adv and r.get("relayAuthToken") and r.get("relayIP"), r)

        found = False
        for _ in range(24):  # gossip flood, seeds retry every 2 s
            r = call(sb, fb, {"type": "FIND", "filters": {}})
            if any(x.get("advertisementID") == adv for x in r.get("advertisements", [])):
                found = True; break
            time.sleep(0.5)
        check("B: FIND sees A's lobby via gossip", found, f"adv={adv}")

        r = call(sb, fb, {"type": "JOIN", "advertisementID": adv})
        check("B: JOIN remote lobby -> relayIP/relayAuthToken",
              r.get("ok") and r.get("relayIP") and r.get("relayAuthToken"), r)

        r = call(sa, fa, {"type": "JOIN", "advertisementID": adv})
        check("A: JOIN own lobby -> slot 0, peers[]",
              r.get("ok") and r.get("slot") == 0 and len(r.get("peers", [])) == 1, r)

        r = call(sa, fa, {"type": "PEERS", "advertisementID": adv})
        check("A: PEERS -> peers[]", r.get("ok") and isinstance(r.get("peers"), list), r)

        r = call(sa, fa, {"type": "UPDATE", "advertisementID": adv, "patch": {"map": "arena"}})
        check("A: UPDATE", r.get("ok"), r)

        r = call(sa, fa, {"type": "PING"})
        check("A: PING -> nodeName/path", r.get("ok") and r.get("nodeName") == "Alice", r)

        r = call(sa, fa, {"type": "LEAVE", "advertisementID": adv})
        check("A: LEAVE", r.get("ok"), r)
        gone = False
        for _ in range(24):  # last member left -> WITHDRAW floods to B
            r = call(sb, fb, {"type": "FIND", "filters": {}})
            if not any(x.get("advertisementID") == adv for x in r.get("advertisements", [])):
                gone = True; break
            time.sleep(0.5)
        check("B: lobby withdrawn after last LEAVE", gone, "")
    finally:
        for p in (a, b):
            p.terminate()
    fails = [c for c in CHECKS if not c[1]]
    print(f"\n{len(CHECKS) - len(fails)}/{len(CHECKS)} passed")
    return 1 if fails else 0

if __name__ == "__main__":
    sys.exit(main())
