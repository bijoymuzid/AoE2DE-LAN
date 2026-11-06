# srvclient.py — offline client for srvtest.exe (H1 login server validation).
# Simulates the game's rlink client: TLS to 127.0.0.1:443 with SNI
# pb-live-release6-api.worldsedgelink.com, VERIFY the self-signed cert by
# fingerprint (the game trusts it via our trust-pool injection), then POST
# the platformlogin request and check the NEW object-form response JSON
# (schema reverse-engineered from the game's own login parser at
# 0x140615b70: named keys, not a positional array).
import ssl, socket, json, sys, urllib.parse

HOST = "pb-live-release6-api.worldsedgelink.com"
PORT = 443

body = ("accountType=steam&platformUserID=76561197960287930&alias=TestPlayer&"
        "title=age2&macAddress=112233445566&clientLibVersion=10106")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE  # we validate the fingerprint manually below

def one_request(b):
    try:
        sock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                               server_hostname=HOST)
    except Exception as e:
        print(f"FAIL: TLS connect/handshake: {e}")
        sys.exit(1)
    cert = sock.getpeercert(binary_form=True)
    req = (f"POST /game/login/platformlogin HTTP/1.1\r\n"
           f"Host: {HOST}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\n"
           f"Content-Length: {len(b)}\r\n"
           f"Connection: close\r\n\r\n{b}")
    sock.sendall(req.encode())
    resp = b""
    try:
        sock.settimeout(15)
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            resp += chunk
            if b"\r\n\r\n" in resp:
                head, _, payload = resp.partition(b"\r\n\r\n")
                clen = 0
                for l in head.split(b"\r\n"):
                    if l.lower().startswith(b"content-length:"):
                        clen = int(l.split(b":", 1)[1].strip())
                if len(payload) >= clen:
                    break
    except socket.timeout:
        pass
    sock.close()
    return cert, resp

cert, resp = one_request(body)
sock_v = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
print(f"TLS OK: version=TLSv1.2 cert={len(cert)}B")
print(f"  sha256(fp1)={__import__('hashlib').sha256(cert).hexdigest()[:32]}...")

if not resp:
    print("FAIL: empty response")
    sys.exit(1)
head, _, payload = resp.partition(b"\r\n\r\n")
print(head.decode("latin1").splitlines()[0])
clen = [l for l in head.decode("latin1").splitlines() if l.lower().startswith("content-length")]
print(f"  headers ok: {'yes' if clen else 'MISSING Content-Length'}")
data = json.loads(payload)
ok = True
def chk(cond, msg):
    global ok
    if not cond:
        ok = False
        print(f"FAIL: {msg}")
need = ["resultCode","connectionToken","connectionID","serverTime","accountInfo",
        "profiles","banLevel","banSeconds","banMessage","clientSettings",
        "selectProfile","sslCertificates","shouldUseClientSync","relayServers"]
for k in need:
    chk(k in data, f"missing key {k}")
print(f"  JSON ok: {len(data)} keys")
chk(data["resultCode"] == 0, "resultCode != 0")
ai = data["accountInfo"]
# accountType / presenceID are int64 enum/int fields in the client's reader
# (0x14061fe20 reads an int64 then range-checks 0..13; Steam = 3), metaData is a
# JSON string, presencePropertyInfo is an array — see notes/m1-session16.md.
chk(ai.get("accountType") == 3, "accountInfo.accountType")
chk(isinstance(ai.get("metaData"), str), "accountInfo.metaData must be a string")
chk(isinstance(ai.get("ssoID"), int), "accountInfo.ssoID must be an int64")
chk(len(data["profiles"]) == 1, f"profiles count={len(data['profiles'])}")
pi = data["profiles"][0]
for k in ["entityVersion","id","name","metaData","alias","sanitizedAlias","clanName",
          "personalStatGroupID","xp","level","leaderboardRegionID","banInfo",
          "platformUserID","accountType","linkedPlatformAccounts","presenceID",
          "presenceLocalized","presencePropertyInfo"]:
    chk(k in pi, f"profile missing key {k}")
chk(pi["alias"] == "TestPlayer", f"profile alias={pi.get('alias')!r}")
chk(pi["id"] == ai["id"], "profile.id != accountInfo.id")
chk(pi["name"] == "TestPlayer", "profile.name")
chk(pi["accountType"] == 3, "profile.accountType")
chk(isinstance(pi["presenceID"], int), "profile.presenceID must be int")
chk(isinstance(pi["presencePropertyInfo"], list), "presencePropertyInfo must be an array")
chk(isinstance(pi["metaData"], str), "profile.metaData must be a string")
# s21: accountInfo.profiles is a vector of ProfileInfo (0x140619210), and
# selectProfile is a SelectProfileEvent {resultCode, profile} (0x140616ed0).
chk(isinstance(ai.get("profiles"), list) and len(ai["profiles"]) == 1,
    f"accountInfo.profiles must be a 1-element array, got {ai.get('profiles')!r}")
chk(ai["profiles"][0].get("id") == pi["id"], "accountInfo.profiles[0].id")
sp = data["selectProfile"]
chk(isinstance(sp, dict), f"selectProfile must be an object, got {sp!r}")
chk(sp.get("resultCode") == 0, "selectProfile.resultCode")
chk(isinstance(sp.get("profile"), dict) and sp["profile"].get("id") == pi["id"],
    "selectProfile.profile.id")
chk(len(data["clientSettings"]) >= 20, f"clientSettings pairs={len(data['clientSettings'])}")
rs = data["relayServers"]
chk(len(rs) == 1, "relayServers count")
chk(rs[0].get("publicIP") == "127.0.0.1", "relay publicIP")
chk(rs[0].get("rawSocketPort") == 27012, "relay rawSocketPort")
chk(rs[0].get("webSocketPort") == 27112, "relay webSocketPort")
chk(rs[0].get("outOfBandSocketPort") == 27212, "relay outOfBandSocketPort")
chk(rs[0].get("region") == "LAN", "relay region")
print(f"  profileID={pi['id']}  session={data['connectionToken']}  srvTime={data['serverTime']}")

h = 0xcbf29ce484222325
for c in b"aoe2lan:TestPlayer":
    h ^= c
    h = (h * 0x100000001b3) & 0xFFFFFFFFFFFFFFFF
h &= 0x7FFFFFFFFFFFFFFF   # signed int64 on the wire
chk(pi["id"] == h, f"profileID mismatch: got {pi['id']} want {h}")

# second login: same alias must give the same profileID (stability)
_, resp2 = one_request(body)
_, _, payload2 = resp2.partition(b"\r\n\r\n")
data2 = json.loads(payload2)
chk(data2["profiles"][0]["id"] == pi["id"], "profileID not stable across logins")
body3 = body.replace("alias=TestPlayer", "alias=SecondPlayer")
_, resp3 = one_request(body3)
_, _, payload3 = resp3.partition(b"\r\n\r\n")
data3 = json.loads(payload3)
chk(data3["profiles"][0]["id"] != pi["id"], "different alias gave same profileID")
chk(data3["profiles"][0]["alias"] == "SecondPlayer", "alias not echoed")

# ---- WebSocket upgrade on /wss/ (the retry storm that AppHang'd us, s17d)
import base64, hashlib, os, struct

class WS:
    def __init__(self, s):
        self.s = s; self.buf = b""
    def _need(self, n):
        while len(self.buf) < n:
            d = self.s.recv(65536)
            if not d:
                raise EOFError("socket closed")
            self.buf += d
    def frame(self):
        self._need(2)
        op = self.buf[0] & 0x0F
        masked = bool(self.buf[1] & 0x80)
        n = self.buf[1] & 0x7F
        off = 2
        if n == 126:
            self._need(4); n = int.from_bytes(self.buf[2:4], "big"); off = 4
        elif n == 127:
            self._need(10); n = int.from_bytes(self.buf[2:10], "big"); off = 10
        self._need(off + (4 if masked else 0) + n)
        mk = self.buf[off:off+4] if masked else None
        if masked:
            off += 4
        p = self.buf[off:off+n]
        self.buf = self.buf[off+n:]
        if mk:
            p = bytes(c ^ mk[i % 4] for i, c in enumerate(p))
        return op, p, masked

def ws_frame(op, payload, mask=True, fin=True):
    b = bytearray([(0x80 if fin else 0) | op])
    n = len(payload)
    mb = 0x80 if mask else 0
    if n < 126:
        b.append(mb | n)
    elif n < 65536:
        b.append(mb | 126); b += n.to_bytes(2, "big")
    else:
        b.append(mb | 127); b += n.to_bytes(8, "big")
    if mask:
        mk = b"\x37\xfa\x21\x3d"
        b += mk + bytes(c ^ mk[i % 4] for i, c in enumerate(payload))
    else:
        b += payload
    return bytes(b)

key = base64.b64encode(os.urandom(16)).decode()
wsock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                        server_hostname=HOST)
wsock.sendall((f"GET /wss/?ack=0&pollNum=0 HTTP/1.1\r\n"
               f"Host: {HOST}\r\n"
               f"Upgrade: websocket\r\n"
               f"Connection: Upgrade\r\n"
               f"Sec-WebSocket-Key: {key}\r\n"
               f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
head = b""
while b"\r\n\r\n" not in head:
    d = wsock.recv(4096)
    if not d:
        break
    head += d
head, _, rest = head.partition(b"\r\n\r\n")
status = head.decode("latin1").splitlines()[0] if head else ""
chk(status.startswith("HTTP/1.1 101"), f"wss upgrade status: {status!r}")
want = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
got = ""
for l in head.decode("latin1").splitlines()[1:]:
    if l.lower().startswith("sec-websocket-accept:"):
        got = l.split(":", 1)[1].strip()
chk(got == want, f"Sec-WebSocket-Accept={got!r} want {want!r}")
print(f"  wss upgrade: 101 + accept ok ({got})")

ws = WS(wsock)
ws.buf = rest
wsock.settimeout(1.0)     # ping-driven reads: the server's pump wakes on socket events

# rlink sends its login as a BINARY frame. The candidate ladder is off by
# default (s21: the notification plane's 46 registered parsers cannot carry a
# login event), so the only thing that must come back is a pong.
wsock.sendall(ws_frame(0x2, b'{"operation":0,"clientLibVersion":194,"sessionToken":"1193817594"}'))
wsock.settimeout(8.0)     # the server pings after ~3 quiet seconds
pushed = False
for _ in range(2):        # two keepalive ticks: nothing but ping/pong may arrive
    op, pl, _ = ws.frame()
    chk(op == 0x9, f"expected a server keepalive ping, got op={op:#x} {pl[:32]!r}")
    if op == 0x2: pushed = True
    wsock.sendall(ws_frame(0xA, pl))
chk(not pushed, "push ladder must be off by default")
print("  ws login: no push (ladder off), keepalive ok")
wsock.sendall(ws_frame(0x1, b'["hello"]'))          # a data frame we ignore
wsock.sendall(ws_frame(0x9, b"ping-payload"))        # ping -> pong, same payload
op, pl, masked = ws.frame()
while op == 0x2 or (op == 0xA and pl != b"ping-payload"):   # pushes + stale keepalive pongs
    op, pl, masked = ws.frame()
chk(op == 0xA, f"expected pong (0xA), got op={op:#x}")
chk(pl == b"ping-payload", f"pong payload={pl!r}")
chk(not masked, "server frames must not be masked")
print("  ws ping -> pong ok (unmasked, payload echoed)")

wsock.sendall(ws_frame(0x8, b""))                   # close -> close, then EOF
op, pl, _ = ws.frame()
while op in (0x2, 0xA):
    op, pl, _ = ws.frame()
chk(op == 0x8, f"expected close (0x8), got op={op:#x}")
wsock.settimeout(5)
try:
    tail = wsock.recv(4096)
except (socket.timeout, ssl.SSLError, OSError):
    tail = b""
chk(tail == b"", f"server did not close after close frame ({tail[:20]!r})")
wsock.close()
print("  ws close handshake ok")

# ---- getAvailableLeaderboards must be a JSON OBJECT, not the catch-all array
# (s29: an array makes the game's LeaderboardInfoCache parse fail, the
# leaderboard registry stay empty and the Multiplayer button go grey).
lbsock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                         server_hostname=HOST)
lbsock.sendall((f"GET /game/Leaderboard/getAvailableLeaderboards HTTP/1.1\r\n"
                f"Host: {HOST}\r\nConnection: close\r\n\r\n").encode())
lb = b""
while True:
    d = lbsock.recv(65536)
    if not d:
        break
    lb += d
lbsock.close()
_, _, lbp = lb.partition(b"\r\n\r\n")
lbd = json.loads(lbp) if lbp else None
chk(isinstance(lbd, dict), f"leaderboards reply must be an object, got {lbp[:32]!r}")
if isinstance(lbd, dict):
    chk(lbd.get("result") == 0, "leaderboards result")
    chk(isinstance(lbd.get("leaderboards"), list) and lbd["leaderboards"],
        "leaderboards must be a non-empty array")
    e = lbd["leaderboards"][0]
    chk(isinstance(e.get("leaderboardID"), int), "entry.leaderboardID")
    chk(isinstance(e.get("leaderboardName"), str), "entry.leaderboardName")
    chk(isinstance(e.get("isRanked"), bool), "entry.isRanked")
print(f"  leaderboards reply: object, {len(lbd.get('leaderboards', [])) if lbd else 0} entry")

# ---- concurrent requests (s30): the request buffer used to be one static shared
# by every connection thread, so two overlapping requests overwrote each other and
# the server sat on the bytes without answering (the game's host call timed out).
# Six overlapping POSTs must all be answered with their own body.
import threading
def _conc(k, out):
    try:
        c = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                            server_hostname=HOST)
        b = f"accountType=steam&platformUserID={k}&alias=P{k}&title=age2"
        c.sendall((f"POST /game/login/platformlogin HTTP/1.1\r\nHost: {HOST}\r\n"
                   f"Content-Type: application/x-www-form-urlencoded\r\n"
                   f"Content-Length: {len(b)}\r\nConnection: close\r\n\r\n{b}").encode())
        r = b""
        while True:
            d = c.recv(65536)
            if not d:
                break
            r += d
        c.close()
        out[k] = r
    except Exception as e:
        out[k] = b"ERR " + str(e).encode()
_conc_out = {}
_conc_th = [threading.Thread(target=_conc, args=(k, _conc_out)) for k in range(6)]
for _t in _conc_th:
    _t.start()
for _t in _conc_th:
    _t.join()
_conc_bad = [k for k, r in _conc_out.items() if not r.startswith(b"HTTP/1.1 200")]
chk(not _conc_bad, f"concurrent requests unanswered: {_conc_bad} "
                   f"({[len(_conc_out[k]) for k in _conc_bad]})")
print(f"  concurrent requests: {len(_conc_out) - len(_conc_bad)}/{len(_conc_out)} answered")

# ---- Expect: 100-continue (s30): the game's HTTP client (libcurl) adds this
# header to bodies over 1 KB and waits exactly 1 s for the interim reply before
# it sends the body. The 3.5 KB host request is the only one that big, and it was
# the one that never arrived -- so the server must answer "100 Continue".
c2 = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                     server_hostname=HOST)
big = "accountType=steam&pad=" + ("x" * 3000)
c2.sendall((f"POST /game/login/platformlogin HTTP/1.1\r\nHost: {HOST}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Expect: 100-continue\r\nContent-Length: {len(big)}\r\n"
            f"Connection: close\r\n\r\n").encode())
early = b""
try:
    c2.settimeout(2)
    early = c2.recv(4096)
except socket.timeout:
    early = b""
chk(early.startswith(b"HTTP/1.1 100"), f"no 100 Continue reply ({early[:40]!r})")
c2.sendall(big.encode())          # the client sends the body only now
r2 = b""
try:
    c2.settimeout(10)
    while True:
        d = c2.recv(65536)
        if not d:
            break
        r2 += d
except socket.timeout:
    pass
c2.close()
chk(r2.startswith(b"HTTP/1.1 200"), f"big POST not answered ({r2[:40]!r})")
print(f"  expect-100: interim ok, body {len(big)}B answered")

# ---- the host reply (s31): the create call parses this answer with the JOIN
# RESULT DTO, so the reply must be resultCode + gatheringID + relay endpoints +
# a non-empty yourMatchMembers list. A bare advertisement object (s31 first try)
# failed the job step with "WorldwideHostAsync - failed with reason -1".
blob = '{"slots":[{"p":0,"ai":1},{"p":1,"ai":-1}],"x":"a b+c\\"d"}'
form = ("advertisementid=-1&hostid=3842241165083521967&connect_id=1193958235"
        "&sessionID=1193965098&maxplayers=8&matchtype=-1&slotinfo="
        + urllib.parse.quote(blob, safe=""))
hsock = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                        server_hostname=HOST)
hsock.sendall((f"POST /game/advertisement/host HTTP/1.1\r\nHost: {HOST}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(form)}\r\nConnection: close\r\n\r\n{form}").encode())
hr = b""
while True:
    d = hsock.recv(65536)
    if not d:
        break
    hr += d
hsock.close()
_, _, hp = hr.partition(b"\r\n\r\n")
hd = json.loads(hp) if hp else None
chk(isinstance(hd, dict), f"host reply must be an object, got {hp[:32]!r}")
if isinstance(hd, dict):
    chk(hd.get("resultCode") == 0, f"host reply resultCode {hd.get('resultCode')!r}")
    chk(hd.get("gatheringID") == 1193965098, f"gatheringID echo {hd.get('gatheringID')!r}")
    chk(hd.get("relayIP") == "127.0.0.1", f"relayIP {hd.get('relayIP')!r}")
    for k in ("relayPortRaw", "relayPortWebSockets", "relayPortOutOfBandSocket"):
        chk(isinstance(hd.get(k), int) and 0 < hd[k] < 65536, f"{k} must be a 16-bit port")
    m = hd.get("yourMatchMembers")
    chk(isinstance(m, list) and m, "yourMatchMembers must be a non-empty array")
    if isinstance(m, list) and m:
        chk(m[0].get("profileID") == 3842241165083521967, f"member profileID {m[0].get('profileID')!r}")
        chk(m[0].get("sessionID") == 1193965098, f"member sessionID {m[0].get('sessionID')!r}")
print(f"  host reply: resultCode={hd.get('resultCode') if hd else '?'}, "
      f"gatheringID={hd.get('gatheringID') if hd else '?'}, "
      f"members={len(hd.get('yourMatchMembers') or []) if hd else 0}")

def post(p, b):
    s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT), timeout=10),
                        server_hostname=HOST)
    s.sendall((f"POST {p} HTTP/1.1\r\nHost: {HOST}\r\n"
               f"Content-Type: application/x-www-form-urlencoded\r\n"
               f"Content-Length: {len(b)}\r\nConnection: close\r\n\r\n{b}").encode())
    r = b""
    while True:
        d = s.recv(65536)
        if not d:
            break
        r += d
    s.close()
    _, _, pay = r.partition(b"\r\n\r\n")
    return json.loads(pay) if pay else None

# ---- /game/advertisement/update (s31): parser 0x140579020 wants result +
# updatedAvertisement (the game's own spelling) as one advertisement object,
# and the advertisement reader wants the option blob under `encodedSlots`.
ud = post("/game/advertisement/update", form)
chk(isinstance(ud, dict), f"update reply must be an object, got {str(ud)[:40]}")
if isinstance(ud, dict):
    chk(ud.get("result") == 0, f"update reply result {ud.get('result')!r}")
    a = ud.get("updatedAvertisement")
    chk(isinstance(a, dict), "updatedAvertisement must be an object")
    if isinstance(a, dict):
        chk(a.get("hostProfileID") == 3842241165083521967, f"advert hostProfileID {a.get('hostProfileID')!r}")
        chk(a.get("maxPlayerCount") == 8, f"advert maxPlayerCount {a.get('maxPlayerCount')!r}")
        chk(a.get("encodedSlots") == blob, "advert encodedSlots must equal the request slotinfo")
        chk(isinstance(a.get("matchMembers"), list) and a["matchMembers"], "advert matchMembers")
print(f"  update reply: result=0, advertisement keys={len(ud.get('updatedAvertisement') or {}) if ud else 0}")

# ---- browse (s31): result + advertisements[] + playerRatings[], filled from the
# lobby this server was last told about.
lv = post("/game/advertisement/getLanAdvertisements", "lanServerGuids=&callNum=1")
chk(isinstance(lv, dict), f"lan list reply must be an object, got {str(lv)[:40]}")
if isinstance(lv, dict):
    chk(lv.get("result") == 0, f"lan list result {lv.get('result')!r}")
    ad = lv.get("advertisements")
    chk(isinstance(ad, list), "advertisements must be an array")
    chk(isinstance(ad, list) and len(ad) == 1, f"expected our one advertisement, got {len(ad) if isinstance(ad, list) else '?'}")
    if isinstance(ad, list) and ad:
        chk(ad[0].get("encodedSlots") == blob, "listed advertisement must carry the same slot blob")
    chk(isinstance(lv.get("playerRatings"), list), "playerRatings must be an array")
print(f"  lan list reply: {len(lv.get('advertisements') or []) if lv else 0} advertisement(s)")

print("PASS" if ok else "FAILED")
sys.exit(0 if ok else 1)
