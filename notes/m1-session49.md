# Session 49 — Priority 3 started: `relayIP` is configurable, `join` has a handler

Supersedes `notes/m1-session48.md` for Priority 3 state; §48's findings all still hold.
Two game runs are referenced: `logs/lanhook-15940.log` (the operator's 7-AI run) and the
offline `srvtest` runs. Game exe untouched (`affb19f03ca96965abf9e56775cab688`).

## 49a. Shipped (three changes, all offline-gated)

1. **`relayIP` from the environment.** `loginsrv.c` has `g_RelayIP` + `relay_ip_init()`,
   called from `loginsrv_start()` before the cert is minted. It reads `AOE2LAN_RELAY_IP`
   once, logs `relayIP: AOE2LAN_RELAY_IP <value>`, and falls back to `127.0.0.1` when the
   variable is unset, 64 bytes or longer, or holds any character outside `[0-9A-Za-z.:-]`
   (the value is spliced into a JSON string, so that filter is a trust boundary).
   `build_host_reply()` emits `g_RelayIP`; the old literal is gone.
   `PLAY-stage8-VERBOSE.cmd` sets it to `127.0.0.1`.
   Measured offline three ways: unset → `127.0.0.1`; `100.99.88.77` → that value in the
   host reply AND the join reply; `1.2.3.4","evil":1` → `rejected (bad char)` + fallback.
   **Not yet measured against a real tailnet IP** — Tailscale is still down (49d).
2. **`/game/advertisement/join` has a handler.** It used to fall into the catch-all
   `[0,[]]`, an array, which the join-result DTO reader (`0x140572540`) cannot parse — the
   same class of failure s31 fixed for `host`. The new branch reuses `build_host_reply()`
   (no second builder, per §48j) by handing it a synthetic form body:
   `hostid=` this machine's own profileID (`mk_ids(g_Alias)`), `sessionID=` the lobby being
   joined, `description=` empty. Session id is taken from `advertisementid` unless that is
   `-1`, then `sessionID`, then `connect_id`, then `1`. It logs `JOIN: hostid=…&sessionID=…`.
   `shortcut:` comment in the code names the limit — the member id is recomputed from the
   last login's alias because **the join request's own key names are unmeasured**; no join
   has ever been attempted. The whole request body is logged, so the first live join settles it.
3. **Dead CNG/crypt32 pointers deleted.** Seven NCrypt function pointers
   (`NCryptOpenStorageProvider/CreatePersistedKey/SetProperty/FinalizeKey/DeleteKey/
   ExportKey/SignHash`), plus `CertCreateCertificateContext` and
   `CertSetCertificateContextProperty`, were resolved at startup and **never called** —
   nothing has used them since the CSP cert path won. They were also in the hard resolve
   check, so one missing `ncrypt.dll` export would have killed the whole shim at boot with
   `srv: proc resolve failed`. `ncrypt.dll` is no longer loaded at all. This is the single
   biggest Proton risk removed (49e). No behaviour change on Windows: cert and cred still
   come up (`dbg: cert ok`, `dbg: cred ok`).
   `pCertFCC`, `pFCH`, `pACT`, `pCRC` are also dead but were left alone — they are not in
   the resolve check and their DLLs are loaded anyway.

Not done: `matchMembers` still carries ONE member (the host). §48e says that is correct for
co-op-vs-AI; a human joiner needs a second entry, and the shape has **not** been A/B tested
live yet. There is also no producer for a second member until discovery exists.

## 49b. Gates (current build)

- `dbghelp.dll` MD5 **`d5cee0abac99629c36f13407f84985ef`**, identical in the game dir and
  `dev/lanhook/`. Backups: `.prev-s49b-before` = `bb31158c4dd13ba2706f1334aaf4e5e3`
  (relayIP + join, the build the 7-AI run used), `.prev-s49-before` =
  `fa9330748b0fe297675f44e2828e738d` (s48).
- **`d5cee0ab…` has not been in the game yet.** Only offline gates. The next launch is its
  first live run.
- `hooktest.exe`: `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`, `swapped 68 of 68`.
- `AOE2LAN_LIVE=1 srvtest.exe 90` → `srvclient.py` **PASS** → `work/livetest.py` **PASS**
  (same srvtest instance, srvclient first: livetest needs the advertisement srvclient stored).
- `work/verifydll.py`: **19** HOOKDEF entries, `MSThunk va=0x1407b66f0 … kind=0`,
  `GLog va=0x1407db520 … kind=7`. `dumpbin -IMPORTS`: **KERNEL32.dll only**.
- Warnings: the pre-existing C4090 five, now at loginsrv.c **675/677/679/1986/2017**
  (moved up because lines were deleted above them).
- `srvclient.py` now asserts the join reply (resultCode, gatheringID, relayIP, ports, one
  member = this shim's own profileID, and the `advertisementid=-1` → `sessionID` fallback)
  and reads `AOE2LAN_RELAY_IP` for the expected address. It re-logs in as `TestPlayer`
  before the join test because the expect-100 test posts a login body with no `alias=`,
  which clears the shim's stored alias.

## 49c. CLOSED: the `nAI` question and "does 7 AI work"

Operator run, `logs/lanhook-15940.log`, 7 AI placed, Start pressed at t≈1338:

```
t=1338.032  MSLADDER pushing variant=0
t=1338.078  "Sending final pregamehoststate packet."
t=1338.078  TComm_Provider_RL::SendSyncPacketRawMemCopy
t=1338.094  HIT AISlotPick val=0x2 kind=2 nAI=0x2
t=1341.032  MSLADDER variant=0 parsefail=0 thunkHits=1 / PARSED - ladder stops
```

**7 AI works** (operator confirmed in the match). And `nAI` is **still `0x2`** with 7 AI, as
it was with 3 AI in both s48 runs — and the same `val=0x2 kind=2 nAI=0x2` also fires at
t=29.4 s at the MAIN MENU with no lobby and no AI at all. So `nAI` is not the lobby's AI
count; it is a constant field the hook happens to read (looks like a kind/difficulty enum).
**Nothing to fix. Do not touch the AISlotPick hook or add AI to the advertisement.**

## 49d. Tailscale is still down — operator action, needs admin

- Service RUNNING, version `1.102.2`. Two `tailscaled.exe` (4128 = the service, 5392 = its
  child — normal, verified by parent PID).
- `BackendState: NoState`, `Self.Online: false`, `TailscaleIPs: null`, `AuthURL: ""`.
- Health: "Unable to connect to the Tailscale coordination server" + "Tailscale is starting.
  Please wait." — stuck like that for hours.
- The network is fine: `tailscale netcheck` completes (UDP true, IPv4 `118.179.44.73`, UPnP,
  no captive portal) and `curl https://controlplane.tailscale.com/` → 302. But netcheck
  printed "No DERP map from tailscaled", so the **daemon** never fetched one.
- `tailscale up` and `tailscale login` both hang with no output. `C:\ProgramData\Tailscale\`
  is not readable from this shell (not admin).
- Fix for the operator, admin terminal: `net stop tailscale` → `net start tailscale` →
  `tailscale up`; or reboot and log in from the tray. Success = `tailscale ip` prints a
  `100.x`. W2's box is already up: `cachyos-x8664-1` = `100.109.201.126`; ours is
  `DESKTOP-64DAV0P` = `100.79.215.72` (both from `notes/linux-session1.md`).

## 49e. Proton/Linux assessment — what is known, what is unknown

The DLL is a plain PE and the hooks are ordinary runtime patches, so the mechanism should
carry over. Ranked by risk, none of it measured yet:

| piece | under Wine/Proton | note |
|---|---|---|
| PE proxy `dbghelp.dll` + stub exports | should work | `WINEDLLOVERRIDES="dbghelp=n"`; our exports are stubs, not forwarders, and the game only uses dbghelp for crash reporting |
| inline hooks, pdata-bounded cleanliness, the VERBOSE byte write | should work | same exe, same VAs, `VirtualProtect` is implemented |
| ws2_32 sockets + the `ConnectEx` IAT hook | should work | Wine implements `SIO_GET_EXTENSION_FUNCTION_POINTER`; watch the `swapped N of 68` line |
| **SSPI server-side TLS** (`SSPICLI.dll`: `AcquireCredentialsHandleW`, `AcceptSecurityContext`, `Encrypt/DecryptMessage`) | **unknown, main risk** | Wine HAS `sspicli.dll` but it is 51 forwards + 45 stubs; the forwards point at `secur32`, whose implementations are real. Our code loads SSPICLI on purpose because on Windows `secur32`'s forwarder returns a stub. Whether Wine resolves those forwards to working functions is unmeasured. Failure looks like `srv: proc resolve failed` or a handshake that never completes |
| **cert minting** (`CryptAcquireContextA`, `CryptGenKey`, `CertCreateSelfSignedCertificate`, `CertStrToNameW`, `CryptEncodeObjectEx`, `CryptAcquireCertificatePrivateKey`) | **unknown** | all are implemented in Wine's crypt32/advapi32 in principle; `X509_ALTERNATE_NAME` encoding is the fiddly one |
| **root-store injection + consent dialog** | **unknown** | there is no Windows consent dialog under Wine, so the auto-clicker simply finds nothing (harmless). Whether `CertAddCertificateContextToStore` into `Root` is enough for the game's TLS client to trust us is the real question |
| `ncrypt.dll` | **no longer needed** | deleted in 49a; this was the most likely hard failure |
| the RUNE crack itself (`steam_emu`, `winmm.dll`, `steam_api64.dll`) | W2's to measure | unrelated to our DLL |

Cheap pre-flight check for W2, no game launch needed — every name below must be present:

```sh
P=~/Games/aoe/winepfx/pfx/drive_c/windows/system32
for d in sspicli secur32 crypt32 advapi32 ws2_32 user32; do
  printf '%-10s ' "$d"; [ -f "$P/$d.dll" ] && echo present || echo MISSING
done
objdump -p "$P/sspicli.dll" | grep -oE '\b(AcquireCredentialsHandleW|AcceptSecurityContext|DeleteSecurityContext|QueryContextAttributesW|EncryptMessage|DecryptMessage|ApplyControlToken|FreeCredentialsHandle)\b' | sort -u
objdump -p "$P/crypt32.dll"  | grep -oE '\b(CertCreateSelfSignedCertificate|CertStrToNameW|CryptAcquireCertificatePrivateKey|CryptEncodeObjectEx|CertFreeCertificateContext)\b' | sort -u
objdump -p "$P/advapi32.dll" | grep -oE '\b(CryptAcquireContextA|CryptGenKey|CryptCreateHash|CryptHashData|CryptGetHashParam|CryptDestroyHash)\b' | sort -u
```

An export being listed does not prove it works (Wine stubs are exported too), so the first
real signal is the shim log: `dbg: cert ok` → `dbg: cred ok` → `TLS: handshake complete
(server side)`.

## 49f. lanhub now builds and runs on Windows — but 9/11, not 11/11

Rust is installed here (`cargo 1.99.1`, `stable-x86_64-pc-windows-msvc`, at
`C:\Users\Bijoy\.cargo\bin`, not yet on this shell's PATH). From `D:\aoe2lan-repo\lanhub`:
`cargo build --release` → **Finished in 6.10 s**, binary
`lanhub/target/release/lanhub.exe` (628 KB). `lanhub/.gitignore` has `/target`, so the build
tree does not dirty the repo.

`python test_walk.py` → **9/11, twice, deterministic**. `CreateProcess` appends `.exe`, so
the script's extensionless `target/release/lanhub` path works unmodified. The two failures
are exactly the cross-instance gossip pair:

```
FAIL  B: FIND sees A's lobby via gossip  (adv=00000000000000000000000000000000)
FAIL  B: JOIN remote lobby -> relayIP/relayAuthToken  ({'error': 'unknown advertisementID', 'ok': False})
```

Everything local passes (HELLO ×2, HOST, JOIN own lobby slot 0, PEERS, UPDATE, PING, LEAVE,
WITHDRAW). So instance B never receives A's `ADVERT` over `127.0.0.1:47101 ↔ :47201` on
Windows. `lanhub/**` is W2's file (§17.1) — **not touched, reported only.** Likely suspects
for W2: Windows `SO_REUSEADDR` semantics, non-blocking-connect error mapping, or the 2 s
seed-retry window versus the walk's wait.

Consequence for Priority 3: the shim↔lanhub wiring for the **browse** endpoints can be
built and tested on one machine (control port only, all local), but **cross-machine
discovery is blocked until W2's gossip works on Windows** — or until we use the shortcut the
s49 brief pre-authorises: feed the joiner's shim the host's advertisement blob from a file
or env var for a first two-machine proof, named as a shortcut and not shipped as the design.

## 49g. Next session

1. Operator: fix Tailscale (49d), then put the `100.x` into `PLAY-stage8-VERBOSE.cmd`'s
   `AOE2LAN_RELAY_IP` and re-run the offline gate with that value set on both srvtest and
   srvclient.
2. One live run to (a) prove `d5cee0ab…` boots in the game, (b) read the `HTTP RESP BODY`
   for `/game/advertisement/host` and confirm the `100.x` address, (c) confirm the local
   match still loads through it (`SendSyncPacketRawMemCopy`). Change nothing else in that run.
3. Step 3: in the same live lobby, A/B the 2-member `matchMembers` shape with `work/s48b.py`
   before writing any code for it.
4. Step 4: wire the browse endpoints to lanhub `FIND` on `127.0.0.1:47100` (local-only test
   is possible now), and tell W2 about 49f.
5. Hand W2 the current `dbghelp.dll` (`d5cee0abac99629c36f13407f84985ef`) as a file — the
   repo git-ignores `*.dll`, and his L4 launcher is blocked on it.

## 49h. Files added / changed this session

| file | what changed |
|---|---|
| `loginsrv.c` | `g_RelayIP` + `relay_ip_init()`; `build_host_reply()` emits it; new `/game/advertisement/join` branch reusing `build_host_reply()`; dead NCrypt + 2 crypt32 pointers deleted and dropped from the resolve check; `ncrypt.dll` no longer loaded |
| `srvclient.py` | `RELAY_IP` from env; join-reply assertions incl. the `advertisementid=-1` fallback; re-login before the join test |
| `PLAY-stage8-VERBOSE.cmd` | `set AOE2LAN_RELAY_IP=127.0.0.1` + a comment on what to put there |
| `notes/prompt-next-session.md` | session 50 brief: asks the operator A (Tailscale) or B (the run) first |
| `dbghelp.dll` (both copies) | rebuilt → `d5cee0abac99629c36f13407f84985ef` |

Unchanged on purpose: the hook table (19 entries, ids 4/5/13/14/15/16/17/18 active),
`emit_advertisement()` (still one member, still `id` first), the s45 3-variant ladder and its
stop-on-no-failure rule, `srvtest.c`, `build_match_start()`'s positional array, the cert
auto-clicker, the live channel protocol, `registry_dump()`, everything in `lanhub/**`.
