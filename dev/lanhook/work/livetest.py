#!/usr/bin/env python3
"""Offline gate for the s46 live payload channel.

Needs srvtest.exe running with AOE2LAN_LIVE=1, and srvclient.py already run once
(that host request is what fills the advertisement GETVARIANT needs).

Holds a websocket open so g_LiveArmed is 1, then checks: ping reports armed=1,
GETVARIANT returns the shim's own payload, and a push comes back with a verdict.
Offline there is no hook 13, so parsefail comes from srvtest's 1 Hz bump - a
non-zero number there proves the counter plumbing, not a real parse failure.
"""
import base64
import os
import socket
import ssl
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import livepush  # noqa: E402

PORT = 443
HOST = "pb-live-release6-api.worldsedgelink.com"

fails = []


def chk(cond, msg):
    print(("  ok   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    key = base64.b64encode(os.urandom(16)).decode()
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                        server_hostname=HOST)
    s.sendall((f"GET /wss/?ack=0&pollNum=0 HTTP/1.1\r\nHost: {HOST}\r\n"
               f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head:
        d = s.recv(4096)
        if not d:
            break
        head += d
    chk(head.decode("latin1").startswith("HTTP/1.1 101"), "websocket upgraded")

    # drain whatever the shim pushes so its send buffer never blocks
    stop = False

    def drain():
        while not stop:
            try:
                if not s.recv(65536):
                    break
            except OSError:
                break

    th = threading.Thread(target=drain, daemon=True)
    th.start()

    try:
        p = livepush.ping()
        print("ping ->", p)
        chk("armed=1" in p, "channel reports a live websocket (armed=1)")

        v1 = livepush.getvariant(1)
        print("getvariant 1 -> %d bytes" % len(v1))
        chk(len(v1) > 20 and '"MatchStartMessage"' in v1 and v1.startswith("[0,"),
            "GETVARIANT 1 returned the positional empty-body payload")
        v0 = livepush.getvariant(0)
        print("getvariant 0 -> %d bytes" % len(v0))
        chk(len(v0) > len(v1), "GETVARIANT 0 returned the full payload (bigger than empty-body)")

        r = livepush.push('[0,"MatchStartMessage",1,{}]', 2)
        print("push ->", r)
        chk(r.startswith("sent=1 parsefail="), "push returned a verdict")
        chk("thunkhits=" in r, "verdict carries thunkhits")
    finally:
        stop = True
        try:
            s.close()
        except OSError:
            pass

    # the not-armed path: no websocket held, a push must refuse cleanly
    r = livepush.push('{"x":1}', 2)
    print("push with no ws ->", r)
    chk(r.startswith("ERR no live websocket"), "push refuses when no websocket is armed")

    print()
    print("FAIL: " + "; ".join(fails) if fails else "PASS")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
