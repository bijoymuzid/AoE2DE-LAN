#!/usr/bin/env python3
"""s48: push the shim's REAL variant-0 payload at the main menu, before any lobby.

Why: 47c only ever measured `[0,"MatchStartMessage",pid,{six empty members}]`. The
real 758-byte frame -- 21 advertisement keys, a populated matchMembers, a real
encodedSlots string -- has never been in front of the live parser. If it does not
parse, the in-game ladder silently falls back to variant 1 (empty body) and
Priority 1 fails for a reason we could have found without a lobby.

Also pushes a 4-member roster (host + 3 AI) as a pure parse-shape check. That is
Priority 2 information; it changes no code and is reported separately.

Usage: python work/s48.py            (needs the game up, livepush ping armed=1)
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import livepush  # noqa: E402

PID = 3842241165083521967
SESSION = 1193965098


def member(pid):
    # key order is irrelevant: the element reader 0x14056eb40 is a name cascade
    # that restarts at 'sessionID' for every key (measured from gametext.bin, s48).
    return {"profileID": pid, "sessionID": SESSION, "ranking": 0, "statGroupID": 0,
            "raceID": -1, "teamID": -1, "url": ""}


def main():
    print("ping:", livepush.ping())

    raw = open(os.path.join(HERE, "v0-s48.json")).read().strip()
    v0 = json.loads(raw)
    assert v0[0] == 0 and v0[1] == "MatchStartMessage" and v0[2] == PID, v0[:3]

    print("\n[1] shim variant 0 verbatim (%d B, 1 member)" % len(raw))
    print("   ", livepush.push(raw, 2))

    # same frame, roster grown to host + 3 AI
    multi = json.loads(raw)
    adv = multi[3]["matchAdvertisement"]
    adv["matchMembers"] = [member(PID)] + [member(-1) for _ in range(3)]
    s = json.dumps(multi, separators=(",", ":"))
    print("\n[2] same frame, matchMembers x4 (%d B)" % len(s))
    print("   ", livepush.push(s, 2))

    # control: the known-good floor from 47c, proves the channel still works
    floor = json.dumps([0, "MatchStartMessage", PID, {}], separators=(",", ":"))
    print("\n[3] control, empty body (%d B) -- must be parsefail=0" % len(floor))
    print("   ", livepush.push(floor, 2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
