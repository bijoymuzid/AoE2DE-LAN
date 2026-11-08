#!/usr/bin/env python3
"""Live payload driver for the AoE2LAN shim control channel (127.0.0.1:47199).

Why this exists: the s45 ladder gets three guesses per ~10 minute game run and
all three MatchStartMessage shapes were rejected (logs/lanhook-5848.log). The
game's parse path is encrypted, so the expected shape cannot be read out
statically. This drives the shim's live channel instead: one game run to the
lobby, then as many payloads as we want, each answered in ~2.5 s.

Usage:
  livepush.py ping                  is a websocket armed?
  livepush.py get [n]               print the shim's own built payload (n=0..2)
  livepush.py push '<json>' [op]    push one payload, op = ws opcode (default 2)
  livepush.py sweep                 try the envelope hypothesis list, stop on a parse
  livepush.py bisect                binary-search the message BODY (needs a hosted lobby)
  livepush.py types                 push the minimal envelope under all 46 type names

parsefail=0 means that payload PARSED - that is the answer we are hunting.
"""
import json
import socket
import sys

HOST, PORT = "127.0.0.1", 47199
VERDICT_WAIT = 2.5          # shim already sleeps 2 s before replying


def _talk(req: bytes, read_body: int = 0, timeout: float = 20.0) -> bytes:
    with socket.create_connection((HOST, PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(req)
        head = b""
        while not head.endswith(b"\n"):
            b = s.recv(1)
            if not b:
                break
            head += b
        if read_body:
            body = b""
            while len(body) < read_body:
                b = s.recv(read_body - len(body))
                if not b:
                    break
                body += b
            return head + body
        return head


def ping() -> str:
    return _talk(b"PING\n").decode(errors="replace").strip()


def getvariant(n: int) -> str:
    """Ask the shim to build its own payload n so we can re-wrap real data."""
    with socket.create_connection((HOST, PORT), timeout=20) as s:
        s.settimeout(20)
        s.sendall(b"GETVARIANT %d\n" % n)
        head = b""
        while not head.endswith(b"\n"):
            b = s.recv(1)
            if not b:
                break
            head += b
        ln = int(head.strip() or 0)
        body = b""
        while len(body) < ln:
            b = s.recv(ln - len(body))
            if not b:
                break
            body += b
    return body.decode("utf-8", errors="replace")


def push(payload: str, opcode: int = 2) -> str:
    raw = payload.encode("utf-8")
    req = b"%d %d\n" % (opcode, len(raw)) + raw
    return _talk(req, timeout=VERDICT_WAIT + 15).decode(errors="replace").strip()


def _verdict(reply: str):
    """-> (sent, parsefail, thunkhits) or None if the reply was an error."""
    if not reply.startswith("sent=1"):
        return None
    d = dict(p.split("=") for p in reply.split() if "=" in p)
    return 1, int(d.get("parsefail", -1)), int(d.get("thunkhits", -1))


def candidates(env: dict, full: dict):
    """The envelope hypothesis list, cheapest discriminator first.

    Evidence: the client's own first WS frame is {"operation":0,"sessionToken":...}
    and its ack is {"operation":1,"ackCount":1} (format string at exe 0x3697c48),
    so `operation` is the RLink packet discriminator - and our push has no such
    field. Every s45 variant was rejected, including the 75-byte envelope-only
    one, which points at the envelope rather than any match member.
    """
    out = []

    def add(label, obj, opcode=2):
        out.append((label, opcode, json.dumps(obj, separators=(",", ":"))))

    # controls: these are the known-bad s45 shapes. If either parses, the whole
    # diagnosis is wrong and that is worth knowing first.
    add("control envelope-only bin", env)
    add("control envelope-only TEXT", env, 1)

    # H-op: `operation` is the discriminator, m_type is not enough / not used
    for op in range(0, 16):
        add("operation=%d + envelope" % op, dict([("operation", op)] + list(env.items())))
    for op in (2, 3, 4, 5):
        add("operation=%d + full" % op, dict([("operation", op)] + list(full.items())))

    # H-list: "failed to parse notification MESSAGES" is plural - maybe a list
    add("array[envelope]", [env])
    add("array[full]", [full])
    for key in ("messages", "notificationMessages", "notifications", "packets"):
        add("{%s:[envelope]}" % key, {key: [env]})
        add("{%s:[full]}" % key, {key: [full]})
    add("operation=2 + messages[full]", {"operation": 2, "messages": [full]})
    add("operation=1 ackCount=1 + full",
        dict([("operation", 1), ("ackCount", 1)] + list(full.items())))

    # H-lib: the client's own first frame carries clientLibVersion (format string
    # at exe 0x3697ab8: {"clientLibVersion":%d,"operation":%d,"sessionToken":"%s"})
    add("clientLibVersion+operation=2 + full",
        dict([("clientLibVersion", 194), ("operation", 2)] + list(full.items())))

    # H-int: maybe m_type is an enum index, not the 17-char name
    for n in (0, 1, 2, 3, 8, 9, 17, 36):
        e = dict(env)
        e["m_type"] = n
        add("m_type=%d (int)" % n, e)

    # H-noresult: `result` is a reply field, not a notification field
    add("envelope minus result", {k: v for k, v in env.items() if k != "result"})
    add("full minus result", {k: v for k, v in full.items() if k != "result"})

    # H-sess: SessionStatusMessage is the bond type that owns `operation`
    # (string table: ...PresenceMessage, operation, SessionStatusMessage...)
    add("SessionStatusMessage operation=2", {"m_type": "SessionStatusMessage", "operation": 2})
    add("operation=2 + m_type + advert",
        dict([("operation", 2)] + list(full.items())))
    return out


def fallback_payloads():
    """Used when GETVARIANT is empty, i.e. the game has not hosted yet so the
    shim holds no advertisement. The envelope is enough to settle the shape
    question; profileID 3842241165083521967 is the shim's own constant (it also
    shows up as hostProfileID in srvclient's updateTags reply)."""
    pid = 3842241165083521967
    env = {"result": 0, "m_type": "MatchStartMessage", "m_profileID": pid}
    full = dict(env)
    full["matchAdvertisement"] = {"advertisementid": 1, "hostid": pid, "maxplayers": 8,
                                  "matchtype": 0, "passworded": 0, "matchRegion": "LAN"}
    full["profileRaces"] = []
    full["inProgressChallenges"] = []
    return env, full


def sweep():
    print("ping:", ping())
    raw_env, raw_full = getvariant(1), getvariant(0)
    if raw_env.strip() and raw_full.strip():
        env, full = json.loads(raw_env), json.loads(raw_full)
        src = "shim-built (real advertisement)"
    else:
        env, full = fallback_payloads()
        src = "LOCAL FALLBACK - game has not hosted yet, no real advertisement"
    print("payload source: %s" % src)
    print("envelope-only payload: %d bytes" % len(json.dumps(env)))
    print("full payload:          %d bytes" % len(json.dumps(full)))
    print()
    cands = candidates(env, full)
    print("%-34s %-5s %-9s %s" % ("candidate", "op", "parsefail", "thunkhits"))
    for label, opcode, payload in cands:
        v = _verdict(push(payload, opcode))
        if v is None:
            print("%-34s -- channel error, stopping" % label)
            return 1
        _, fail, hits = v
        flag = ""
        if fail == 0:
            flag = "   <== PARSED"
        print("%-34s %-5d %-9d %-9d%s" % (label, opcode, fail, hits, flag))
        if fail == 0:
            print()
            print("WINNER: %s (opcode %d)" % (label, opcode))
            print(payload)
            return 0
    print()
    print("no candidate parsed - the envelope hypothesis list is exhausted")
    return 1


def bisect():
    """The dispatcher matches m_type and calls the MatchStartMessage factory
    (measured: thunkhits=1 only when m_type is the exact string), so the
    envelope is fine and the BODY is what fails to parse. Add one member at a
    time, then remove one at a time, and report every verdict."""
    full = json.loads(getvariant(0))
    if not full:
        print("no advertisement in the shim yet - host a game first")
        return 1
    env_keys = ("result", "m_type", "m_profileID")
    env = {k: full[k] for k in env_keys if k in full}
    members = [k for k in full if k not in env_keys]
    print("envelope keys: %s" % list(env))
    print("members:       %s" % members)
    print()
    winner = []

    def t(label, obj):
        v = _verdict(push(json.dumps(obj, separators=(",", ":"))))
        if v is None:
            print("%-40s -- channel error" % label)
            return False
        _, fail, hits = v
        ok = fail == 0
        print("%-40s parsefail=%-3d thunkhits=%-3d%s"
              % (label, fail, hits, "   <== PARSED" if ok else ""))
        if ok:
            winner.append((label, obj))
        return ok

    print("-- envelope plus ONE member --")
    for m in members:
        if t("env + %s" % m, dict(list(env.items()) + [(m, full[m])])):
            break
    if winner:
        return report(winner)

    print("-- full MINUS one member --")
    for m in members:
        obj = {k: v for k, v in full.items() if k != m}
        if t("full - %s" % m, obj):
            break
    if winner:
        return report(winner)

    print("-- full with members in bond string-table order --")
    # exe string table lists MatchStartMessage's own fields as
    # inProgressChallenges, matchAdvertisement, profileRaces (0x369d9d7..0x369da08)
    order = ["inProgressChallenges", "matchAdvertisement", "profileRaces"]
    ordered = dict(env)
    for k in order + [m for m in members if m not in order]:
        if k in full:
            ordered[k] = full[k]
    t("full reordered", ordered)

    print("-- matchAdvertisement as a positional array --")
    adv = full.get("matchAdvertisement")
    if isinstance(adv, dict):
        obj = dict(env)
        obj["matchAdvertisement"] = list(adv.values())
        t("env + advert as array", obj)
    return report(winner)


def report(winner):
    print()
    if winner:
        label, obj = winner[0]
        print("WINNER: %s" % label)
        print(json.dumps(obj, separators=(",", ":")))
        return 0
    print("no shape parsed yet")
    return 1


# All 46 RLink notification types (RTTI `U<Name>@RLink`). The dispatch registry
# dumped at runtime has exactly 46 nodes (logs/lanhook-5848.log MSREG nodes=46),
# and the MSThunk fires for ANY top-level JSON object - measured: it fired for
# m_type="SessionStatusMessage" and for an object with no m_type at all, but not
# for a top-level array or an integer m_type. So dispatch walks every factory and
# each one tries to parse; a thunk hit is NOT a type match.
RLINK_TYPES = [
    "AchievementGrantedMessage", "Automatch2GameMessage", "Automatch2LeaveMatchMessage",
    "Automatch2PollingMessage", "Automatch2StopPollingMessage", "AutomatchGameMessage",
    "AutomatchStartPollingMessage", "AutomatchStopPollingMessage", "AvatarDeletedMessage",
    "AvatarStatsUpdatedMessage", "AvatarUpdateMessage", "CancelInvitationMessage",
    "ChallengeUpdatedMessage", "ChannelChatMessage", "ChannelJoinMessage",
    "ChannelLeaveMessage", "ClanChangeClanMessage", "ClanChatMessage",
    "ClanMemberUpdateMessage", "ClanMembershipRequestUpdateMessage",
    "ClanPermissionsUpdateMessage", "ClanRemoveMessage", "ClanUpdateMessage",
    "CommunityEventChallengeUpdatedMessage", "ExtendInvitationMessage", "ExtensionMessage",
    "FriendAcceptMessage", "FriendClearMessage", "FriendRejectMessage",
    "FriendRequestMessage", "GameResultNotificationMessage", "IgnoreMessage",
    "ItemInstanceMessage", "ItemLocationMessage", "MatchHostedMessage",
    "MatchObserveMessage", "MatchReceivedChatMessage", "MatchStartMessage",
    "OfflineMessageMessage", "OutdatedVersionMessage", "PartyHostUpdatedMessage",
    "PersonalChatMessage", "PlatformSessionUpdateMessage", "PresenceMessage",
    "ReplyInvitationMessage", "SessionStatusMessage",
]


def types():
    """Push the same minimal envelope under all 46 type names.

    If NONE parses, the envelope shape itself is wrong and no amount of
    MatchStartMessage member fixing will help. If SOME parse, the envelope is
    right and MatchStartMessage simply needs members we are not sending."""
    pid = 3842241165083521967
    parsed = []
    print("%-42s %-9s %s" % ("m_type", "parsefail", "thunkhits"))
    for name in RLINK_TYPES:
        obj = {"result": 0, "m_type": name, "m_profileID": pid}
        v = _verdict(push(json.dumps(obj, separators=(",", ":"))))
        if v is None:
            print("channel error at %s - stopping" % name)
            break
        _, fail, hits = v
        mark = "   <== PARSED" if fail == 0 else ""
        print("%-42s %-9d %-9d%s" % (name, fail, hits, mark))
        if fail == 0:
            parsed.append(name)
    print()
    if parsed:
        print("PARSED with the minimal envelope: %s" % ", ".join(parsed))
        print("=> the envelope shape is correct; MatchStartMessage needs real members")
        return 0
    print("nothing parsed => the ENVELOPE shape is wrong, not the members")
    return 1


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "ping":
        print(ping())
    elif cmd == "get":
        n = int(argv[2]) if len(argv) > 2 else 0
        print(getvariant(n))
    elif cmd == "push":
        op = int(argv[3]) if len(argv) > 3 else 2
        print(push(argv[2], op))
    elif cmd == "sweep":
        return sweep()
    elif cmd == "bisect":
        return bisect()
    elif cmd == "types":
        return types()
    else:
        print("unknown command %r" % cmd)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
