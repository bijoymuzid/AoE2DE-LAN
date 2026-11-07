# Linux/Proton: login reply corrupted — TLS record framing bug (session 31)

## TL;DR

`tls_encrypt_send()` sends the TLS record using the SecBuffer sizes captured
**before** `EncryptMessage()`. Windows leaves those sizes unchanged; Wine
(wine-11.0, both GE-Proton11-12 and Proton-CachyOS) adjusts `cbHeader`/`cbTrailer`,
so the send over-counts and ships uninitialised bytes from the tail of `rec`.

Result: a valid `HTTP/1.1 200 OK` header record, then N garbage bytes, then the
valid body record. The game's TLS client aborts on the header/body boundary, so
`/game/login/platformlogin` appears to fail and the Multiplayer button stays grey.

## Evidence (captured 2026-11-06, GE-Proton11-12, wine-11.0)

Raw server->client TLS stream, parsed record by record:

```
record 0: off=0     type=0x16 ver=0x0303 len=91    OK    ServerHello
record 1: off=96    type=0x16 ver=0x0303 len=962   OK    Certificate
record 2: off=1063  type=0x16 ver=0x0303 len=300   OK    ServerKeyExchange
record 3: off=1368  type=0x16 ver=0x0303 len=4     OK    ServerHelloDone
record 4: off=1377  type=0x14 ver=0x0303 len=1     OK    ChangeCipherSpec
record 5: off=1383  type=0x16 ver=0x0303 len=40    OK    Finished
record 6: off=1428  type=0x17 ver=0x0303 len=185   OK    HTTP header (161B plaintext)
                 1618 .. 1850  = 232 bytes of 0x00     <<<< INJECTED GARBAGE
record 7: off=1850  type=0x17 ver=0x0303 len=3100  OK    HTTP body (3076B JSON + 8 + 16)
```

The body itself is perfect (`len=3100` == 3076 + 8 nonce + 16 GCM tag). Only the
zero run between the records breaks the client.

Client-side symptom, using plain tools from outside the game:

```
$ curl -k -X POST -d '{}' https://127.0.0.1/game/login/platformlogin
HTTP/1.1 200 OK
Content-Length: 3076
curl: (56) OpenSSL SSL_read: SSL routines::wrong version number   # dies right after the header
```

In-game symptom (lanhook log):

```
[t=2.740s] LOGIN: serving synthetic profile, alias=AnkerGames
[t=2.740s] HTTP RESP: sent
[t=2.790s] srv: closed pending#1 n=0
[t=2.848s] HIT LogWarn #5: "CallContext::SetComplete - ExtendedError ... for LoginAsync"
[t=2.848s] HIT LogWarn #6: "LoginAsync - response was failure: 0xffffffd2"
[t=2.849s] HIT LogWarn #7: "WorldwideLoginAsync::DoUpdateCrossplaySetting: Could not fetch local profile."
```

For contrast, on Windows the same reply yields:
`Found %zd profiles for account` -> `Found profile: AnkerGames` ->
`OnAccountEvent: Client is using WebSockets` -> `InitiateRelayServerQoSTest()` ->
`HTTP REQ /game/Leaderboard/getAvailableLeaderboards`.

## The fix

`loginsrv.c`, end of `tls_encrypt_send()`. Current code:

```c
    // after the call the DATA slot holds the ciphertext; sizes unchanged for
    // stream buffers — send the whole contiguous record
    if (!tls_send_all(t->s, (char*)rec, n0 + n1 + n2)) return 0;
    return 1;
```

`n0/n1/n2` were captured from `t->sizes` before `pEM` ran. Replace with the
post-call values:

```c
    // use the sizes AS ADJUSTED BY EncryptMessage: Wine changes cbHeader/cbTrailer,
    // Windows leaves them alone. Sending the pre-call total ships the zero-filled
    // tail of rec and corrupts the record framing (session 31).
    { int total = (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
      if (!tls_send_all(t->s, (char*)rec, total)) return 0; }
    return 1;
```

Nothing else in `tls_encrypt_send` needs to change: the buffers are already
correctly laid out, and `bufs[1].pvBuffer` still points at the DATA slot.

## Two more Linux-only issues (both already confirmed here)

1. **`WINEDLLOVERRIDES="dbghelp=n"` is wrong under Proton.** With `n` only, the
   proxy's `LoadLibraryExW(system32\dbghelp.dll)` fails and the DLL dies with
   `FATAL: could not load real dbghelp from System32`. Use `dbghelp=n,b` so the
   builtin stays loadable for forwarding.

2. **Port 443 is privileged on Linux.** The in-DLL server binds `127.0.0.1:443`
   and fails with `srv: bind 127.0.0.1:443 FAILED (port busy?)` (actually EACCES).
   Either document `net.ipv4.ip_unprivileged_port_start=0`, or listen on 4443 and
   rewrite the port in the `getaddrinfo` hook.

## How to verify the fix

From a Linux host, with the game running so the in-DLL server is live:

```bash
curl -k -sS -X POST -H 'Content-Type: application/json' -d '{}' \
     https://127.0.0.1/game/login/platformlogin -o /tmp/body.json
wc -c /tmp/body.json          # must be 3076, not 0
head -c 60 /tmp/body.json     # {"resultCode":0,"connectionToken":...
```

If `curl` returns the full JSON, the framing is fixed and the game will accept
the profile.

## Note on the futex deadlock

Before this bug was found, stage 8 was dying at ~3.9s with one thread spinning in
`RtlWakeAddressAll` (futex queue lock stuck at -1, no thread inside
`RtlWaitOnAddress`). That is very likely *downstream* of the rejected login: the
game takes an error path and hammers WaitOnAddress while tearing down service
threads. Re-test after the framing fix — if the spin is gone, no further action is
needed; if it persists, it is a separate Wine issue.