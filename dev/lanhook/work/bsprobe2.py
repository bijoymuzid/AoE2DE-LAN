"""Probe the live BattleServer with correctly-framed messages.

The first probe was wrong: its LOBBYCONNECT was 31 bytes, and notes/bs_client.py
says only 24/28/32/36 parse, so "no reply" proved nothing. This one replays the
game's real wire format, decoded byte-for-byte from logs/lanhook-15584.log:

  framing: u16 BIG-endian length prefix, then the bare SessionMessage
  LOBBYCONNECT (0x15, 32 B for marker 0 / version 5): fields LITTLE-endian
    u8 0x15 | u64 (titleID<<48 | sessionID&0xFFFFFFFFFFFF) | u64 sessionID
    | u8 marker | u16 version | u32 dataReceivedCount | u64 secret

The game's own values were titleID=0x18, sessionID=1194090354, secret=profileID.
Here the sessionID is deliberately bogus so the probe cannot collide with, or
replace the socket of, a session the game has open.

Usage: C:/Python314/python.exe -X utf8 work/bsprobe2.py [host] [port ...]
"""
import socket
import struct
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORTS = [int(a) for a in sys.argv[2:]] or [27012, 27112, 27212]

TITLE_ID = 0x18                      # decoded from the game's own LOBBYCONNECT
BOGUS_SESSION = 0x0BADF00D           # must NOT be a live session
SECRET = 0x355261FB8A2FB3AF          # the game used its profileID

# the game's exact 194-byte ClientHello, replayed verbatim (no SNI extension)
CLIENT_HELLO = bytes.fromhex(
    "16030100bd010000b9030319b2ea369c45e3680587f596ff06ed56dfb1dec932"
    "1799dd619f924b0f1b9b08000038c02cc030009fcca9cca8ccaac02bc02f009e"
    "c024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c"
    "0035002f00ff01000058000b000403000102000a000c000a001d0017001e0019"
    "0018002300000016000000170000000d0030002e040305030603080708080809"
    "080a080b08040805080604010501060103030203030102010302020204020502"
    "0602")


def lobbyconnect(session=BOGUS_SESSION, marker=0, version=5):
    out = bytearray([0x15])
    out += struct.pack("<Q", ((TITLE_ID & 0xFFFF) << 48) | (session & 0xFFFFFFFFFFFF))
    out += struct.pack("<Q", session)
    out += bytes([marker])
    if marker == 2:
        out += struct.pack("<I", 60)
    out += struct.pack("<H", version)
    out += struct.pack("<I", 0)
    if version > 4:
        out += struct.pack("<Q", SECRET)
    assert len(out) in (24, 28, 32, 36), len(out)
    return bytes(out)


def frame(payload):
    """The game's raw-port framing: u16 big-endian length, then the message."""
    return struct.pack(">H", len(payload)) + payload


def drain(s, secs=2.5):
    s.settimeout(secs)
    out = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                return out, "closed"
            out += d
    except socket.timeout:
        return out, "timeout"
    except OSError as e:
        return out, f"error {e}"


def send_and_watch(port, label, payload, secs=2.5):
    try:
        s = socket.create_connection((HOST, port), timeout=3)
    except OSError as e:
        print(f"  {label}: connect FAILED {e}")
        return
    try:
        s.sendall(payload)
    except OSError as e:
        print(f"  {label}: send FAILED {e}")
        s.close()
        return
    d, st = drain(s, secs)
    print(f"  {label}: sent {len(payload)}B -> reply {len(d)}B ({st}) {d[:48].hex(' ')}")
    s.close()


lc = lobbyconnect()
print(f"LOBBYCONNECT {len(lc)}B: {lc.hex(' ')}")
print(f"framed {len(frame(lc))}B: {frame(lc).hex(' ')}")

for p in PORTS:
    print(f"\n=== {HOST}:{p} ===")
    send_and_watch(p, "bare LC (u16be frame)", frame(lc))
    send_and_watch(p, "bare LC (no frame)", lc)
    send_and_watch(p, "game ClientHello", CLIENT_HELLO)
