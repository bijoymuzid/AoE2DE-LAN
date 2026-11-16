# 2026-11-16 — lobby discovery FIXED (join works); kick still open

Result: friend browsed, saw the lobby, joined (NEWPEER t=1765.566, host log
lanhook-248-555723.log). Kick at t=1775.954 = 10.4 s after join, same as ever.

## The two discovery bugs and their fixes

### Bug 1 — stale relayRegion in the hub entry (friend's fix, commit fc24d69)

Host's BattleServer respawned mid-session; the hub kept advertising the dead
GUID while the beacons moved on. Joiner's HUBFILTER dropped the live lobby,
every join click died R_MatchExpired.

Fix: `adv_patch()` (dev/lanhook/loginsrv.c) now REPLACES any body relayRegion
that is not in the game's live `lanServerGuids` list (was: only filled a
missing one). One place covers host / update / 5 s republish. Log line:
`ADVPATCH: stale relayRegion -> <guid>`.

### Bug 2 — joiner without a local hub got an empty browser (commit 2525359)

`hub_open()` targets 127.0.0.1:47100 (LOCAL hub). A game-only joiner machine
runs no lanhub, so `hub_browse()` bailed at `if (s == INVALID_SOCKET) goto
out2` BEFORE merging the entries `hub_remote_find()` had just pulled from the
host's hub. Symptom signature: `REMOTEFIND: entries=1` immediately followed by
an empty serve with NO `HUBFILTER` line (friend log lanhook-3240-1826328
t=42.312). Regression from the s50 reorder (1eff369).

Fix: skip only the local FINDRAW block when the local hub is absent; the
remote-merge + HUBFILTER + emit still run. Joiner is now self-sufficient — no
local lanhub, no portproxy needed.

### Ops gotcha — beaconrelay must actually be running

The joiner's game must HEAR the host's UDP 9999 beacon (forwarded by
`dev/re/beaconrelay.py <friend-tailnet-ip>`) or its `lanServerGuids` lacks the
host's BS GUID and HUBFILTER drops the lobby even with both fixes. Check:
`tail /tmp/beaconrelay.log` should show rising `fwd #N`. Do NOT launch it
piped to `head` — SIGPIPE kills it silently (cost us a session).

## Verified-good state (host log lanhook-248-555723.log)

- hub FIND: lobby sessionID=1194811570, relayIP=100.109.201.126,
  relayRegion=8f0af57c-fa2d-4395-85cd-d92f1731939a (= live BS GUID)
- friend's dll: md5 765125643b6843c21ffc847b9dd0f167 (272896 B, clang/mingw
  build of 2525359 — Linux-built dlls run fine on the Windows joiner)

## Still open: the kick (unchanged)

- NEWPEER t=1765.566 → KICKSEND 00 t=1775.954 → 6b×2 t=1777.837 → peerremove
  t=1778.194 reasonID=1000, kicked profileID 2949963597078017023 (friend).
- RELSHAPE n=2 cand=2 served t=1765.972 (8-slot envelope + friend profileInfo
  row in lastConnection slot 6). ZERO RelationshipCache parse errors.
- Verdict: cand=2 does NOT prevent the kick. The content theory "host validates
  the readying peer against lastConnection" is dead for slot 6 content.
- Next rung on the ladder: AOE2LAN_REL=3 (row in friends slot) then =4 (both).
  Each needs a host restart (new beacon GUID → friend must restart after).
  Ladder details: notes/handoff-2026-11-16-joiner.md section 5.
