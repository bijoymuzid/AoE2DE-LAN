"""Which field of the game's LOBBYCONNECT makes the relay stay silent?

work/bsprobe2.py proved the relay on :27012 speaks plaintext, u16-BE-framed
SessionMessages and echoes a well-formed LOBBYCONNECT. The game sent one at
t=156.969 (logs/lanhook-15584.log) and got zero bytes back for the rest of the
run. The two packets differ in exactly one field: the second u64.

  probe (echoed):  15 | 0df0ad0b00001800 | 0df0ad0b00000000 | 00 | 0500 | 00000000 | secret
  game  (silence): 15 | 725f2c4700001800 | 1bb61a0193809669 | 00 | 0500 | 00000000 | secret

This replays the game's packet field by field with a bogus sessionID, so it can
never collide with or replace a session the game has open.

Usage: C:/Python314/python.exe -X utf8 work/bslc.py [host] [port]
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 27012

TITLE = 0x18                    # decoded from the game's own packet
BOGUS = 0x0BADF00D              # a session that does not exist
SECRET = 0x355261FB8A2FB3AF     # the game's profileID
GAME_F2 = 0x69968093011AB61B    # the game's second u64, verbatim


def lc(session, field2, marker=0, version=5, secret=SECRET):
    out = bytearray([0x15])
    out += struct.pack("<Q", ((TITLE & 0xFFFF) << 48) | (session & 0xFFFFFFFFFFFF))
    out += struct.pack("<Q", field2)
    out += bytes([marker])
    if marker == 2:
        out += struct.pack("<I", 60)
    out += struct.pack("<H", version)
    out += struct.pack("<I", 0)
    if version > 4:
        out += struct.pack("<Q", secret)
    assert len(out) in (24, 28, 32, 36), len(out)
    return bytes(out)


def frame(p):
    return struct.pack(">H", len(p)) + p


def shot(label, payload, secs=2.5):
    try:
        s = socket.create_connection((HOST, PORT), timeout=3)
        s.sendall(payload)
        s.settimeout(secs)
        out = b""
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                out += d
        except socket.timeout:
            pass
        s.close()
        verdict = "ECHO" if out == payload else ("reply" if out else "SILENT")
        print(f"  {label:44s} {verdict:7s} {len(out)}B {out[:40].hex(' ')}")
    except OSError as e:
        print(f"  {label:44s} FAILED {e}")


print(f"=== {HOST}:{PORT} ===")
shot("f2 = sessionID (the probe that worked)", frame(lc(BOGUS, BOGUS)))
shot("f2 = the game's value, session bogus", frame(lc(BOGUS, GAME_F2)))
shot("f2 = 0", frame(lc(BOGUS, 0)))
shot("f2 = full 64-bit session, session bogus", frame(lc(BOGUS, BOGUS)))
shot("marker 2 (reconnect)", frame(lc(BOGUS, BOGUS, marker=2)))
shot("version 4 (no secret, 24B)", frame(lc(BOGUS, BOGUS, version=4)))
shot("LOBBYPING 0x14 alone", frame(bytes([0x14])))
