#!/usr/bin/env python3
"""s48b: push modified copies of the REAL variant-0 frame into the live lobby.

Run 15416 proved the shim's real 1717-byte frame parses and fires
AET_MatchStartNotify -- but the match still does not load. The advertisement we
echo back omits six of reader 0x14056cce0's 27 keys, the first of which is `id`.
This pushes one override set at a time into the still-armed websocket so each
hypothesis costs ~4 s instead of a relaunch.

Usage: python work/s48b.py <label> '<json overrides for matchAdvertisement>'
       python work/s48b.py <label> --body '<json overrides for the body>'
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import livepush  # noqa: E402

# reader 0x14056cce0's full key order (work/keys.py). Order is not load-bearing --
# the reader is a name cascade that restarts per key (measured from gametext.bin)
# -- but emitting in reader order keeps every frame comparable.
ADV_ORDER = ["id", "steamLobbyID", "goodOldGamesLobbyID", "psnPlayerSessionID",
             "psnMatchId", "xboxSessionID", "hostProfileID", "matchState",
             "description", "filteredDescription", "visible", "mapName", "options",
             "isPassworded", "maxPlayerCount", "encodedSlots", "matchTypeID",
             "matchMembers", "observerNum", "observerMax", "isobservable",
             "observerDelay", "isObserverPassworded", "service", "matchStartTime",
             "matchRegion", "matchRegionLocalized"]


def main():
    label = sys.argv[1]
    which = "adv"
    over = {}
    if len(sys.argv) > 2:
        if sys.argv[2] == "--body":
            which = "body"
            over = json.loads(sys.argv[3])
        else:
            over = json.loads(sys.argv[2])

    frame = json.loads(open(os.path.join(HERE, "v0-real.json")).read())
    if which == "adv":
        adv = frame[3]["matchAdvertisement"]
        adv.update(over)
        frame[3]["matchAdvertisement"] = {k: adv[k] for k in ADV_ORDER if k in adv}
    else:
        frame[3].update(over)

    s = json.dumps(frame, separators=(",", ":"))
    print("%s: %d B, adv keys=%d, overrides=%s" % (label, len(s), len(frame[3]["matchAdvertisement"]), over))
    print("   ", livepush.push(s, 2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
