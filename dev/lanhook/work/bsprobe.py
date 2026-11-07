"""Probe the live BattleServer ports: does each speak TLS or bare SessionMessages?

Read-only. Uses a bogus sessionID so it cannot collide with, or replace, the
socket of a session the game currently has open.

Usage: C:/Python314/python.exe -X utf8 work/bsprobe.py [host] [port ...]
"""
import socket
import ssl
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORTS = [int(a) for a in sys.argv[2:]] or [27012, 27112, 27212]

# the game's own ClientHello, replayed verbatim from logs/lanhook-15584.log
CLIENT_HELLO = bytes.fromhex(
    "16030100bd010000b9030325452391b6e743ca9fbf1fe12129df795513c6acf3"
    "00ce5d681b9fb950d47ece000038c02cc030009fcca9cca8ccaac02bc02f009e"
    "c024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c"
    "0035002f000a0100005800000018001600001370622d6c6976652d72656c6561"
    "736536000a000400020017000b00020100000d00080006040102010403020300"
    "050005010000000000"
)

# u16-BE length prefix + a LOBBYCONNECT(0x15) for a session that does not exist
BOGUS_SESSION = 0x0BADF00D
LOBBYCONNECT = bytes.fromhex("15") + (BOGUS_SESSION).to_bytes(8, "big") * 2 \
    + bytes.fromhex("0005") + bytes(4) + bytes.fromhex("0df0feca0df0ad0b")
BARE = len(LOBBYCONNECT).to_bytes(2, "big") + LOBBYCONNECT


def drain(s, secs=2.0):
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


def probe(port):
    print(f"\n=== {HOST}:{port} ===")
    # 1. does a listener exist at all, and does it speak first?
    try:
        s = socket.create_connection((HOST, port), timeout=3)
    except OSError as e:
        print(f"  connect: FAILED {e}")
        return
    d, st = drain(s, 1.0)
    print(f"  connect ok; server-first={len(d)}B ({st})")
    s.close()

    # 2. plaintext length-prefixed LOBBYCONNECT
    try:
        s = socket.create_connection((HOST, port), timeout=3)
        s.sendall(BARE)
        d, st = drain(s, 2.0)
        print(f"  bare LC ({len(BARE)}B): reply={len(d)}B ({st}) {d[:32].hex(' ')}")
        s.close()
    except OSError as e:
        print(f"  bare LC: FAILED {e}")

    # 3. TLS handshake
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((HOST, port), timeout=3)
        t = ctx.wrap_socket(raw, server_hostname="localhost")
        print(f"  TLS: OK version={t.version()} cipher={t.cipher()[0]}")
        t.close()
    except ssl.SSLError as e:
        print(f"  TLS: SSLError {e}")
    except OSError as e:
        print(f"  TLS: FAILED {e}")

    # 4. raw ClientHello bytes, read the literal reply
    try:
        s = socket.create_connection((HOST, port), timeout=3)
        s.sendall(CLIENT_HELLO)
        d, st = drain(s, 2.0)
        print(f"  raw hello ({len(CLIENT_HELLO)}B): reply={len(d)}B ({st}) {d[:32].hex(' ')}")
        s.close()
    except OSError as e:
        print(f"  raw hello: FAILED {e}")


for p in PORTS:
    probe(p)
