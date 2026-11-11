# Linux session 4 (2026-11-10 → 11) — the .text wall, the wine-safe instruments, and where Create Lobby hangs

**Bottom line.** On wine the game image is closed to us: any `.text` byte change (E9 detour, IAT
slot that Arxan watches, even a one-byte poke of a function nothing calls) kills the process at
t≈3.4 s, while the same build survives 600 s runs on Windows. What *does* survive is a write to
heap or `.data`. That single fact produced every instrument this session: the lobbygate field
writer, the log-sink vptr swap (`AOE2LAN_LOGVT`), and the game log-level byte
(`AOE2LAN_VERBOSE`). With them: the relay beacon turned out to be eaten by ufw (fixed), and
"Create Lobby" still hangs — but the reason ten sessions saw *no* game-layer log at click time is
now known to be a **log filter**, not silence, so the earlier "the click does nothing" evidence is
void.

## 4a. Instrument → mechanism → does it survive wine?

| instrument | what it writes | wine |
|---|---|---|
| `AOE2LAN_HOOKS` (E9 detours, hookcore.c) | `.text` prologue bytes | **dies t≈3.4 s** (19 real lines, then gone) |
| `AOE2LAN_RTDYN=1` (`__RTDynamicCast` IAT slot) | `.data` IAT slot | **dies t≈3 s** (§4e) |
| `AOE2LAN_TEXTPOKE=…:flip` | one `.text` byte | **dies** (§4d) |
| `AOE2LAN_TEXTPOKE=…:same` | the identical byte back | survives (§4d) |
| `AOE2LAN_AIGATE=1` (lobbygate) | heap fields of the lobby screen | survives, holds ~95 % |
| `AOE2LAN_LOGVT=1` (log sink) | one heap vptr | survives, 489 lines/140 s |
| `AOE2LAN_VERBOSE=1` (new) | one `.data` byte | survives (see §4g) |

## 4b. clang-mingw SEH: two defects, and the accessors that work around them

`HC_TRY` is not `__try`. Measured with `dev/lanhook/sehprobe.c` (headless, one case per wine
process because an uncaught case kills the process), 4 cases × `-O0`/`-O1` on wine 11:

| case | expect | why |
|---|---|---|
| `bare` | DIED | a `__try` body with no call gets **no handler at all** (unwind Flags: 0) |
| `inline_anchored` | DIED | handler alive, but clang emits an SEH scope record **only around call instructions**, so an inline load is in no region; `__C_specific_handler` runs, finds no record, returns `ExceptionContinueSearch`, process dies |
| `hc_rd` | GUARDED | the faulting access is inside a callee, so the unwind reaches the caller's guarded call site |
| `hc_wr` | GUARDED | same |

So: `hc_seh_anchor()` (a no-op call) keeps a handler alive, and every game-memory access goes
through `hc_rd`/`hc_wr` in `hcaccess.inc` (`HC_RD8/16/32/64`, `HC_WR8/32/64`). `hcaccess.inc` is
shared by `hookcore.c` and `sehprobe.c` so the probe tests the code that ships. MSVC has neither
defect; this is a Linux-build-only rule.

## 4c. The telemetry URL rewrite is inert — removed

XAL's 1DS telemetry POST to `self.events.data.microsoft.com` fails every ~19 s with HC `E_FAIL` /
provider `0x80072f78` (`ERROR_HTTP_INVALID_SERVER_RESPONSE`). It is **not fatal**: three 100 s runs
took 5 failures each and held the menu. Rewriting the URL to our own TLS server was tried and
removed (`AOE2LAN_TELEMLOCAL` deleted): `libHttpClient.Win32.dll` resolves and connects through
its **own** IAT, so the rewrite never moved the socket — the server saw zero `/OneCollector`
requests with it enabled. Evidence: `/tmp/exp-{telem1,telem0,dumptext2}.shim.log` (gone with the
reboot; the conclusion is in the `iathook.c` comment).

## 4d. `.text` is checksummed blanket — the proof, and the IAT slot map

`AOE2LAN_TEXTPOKE=<hexrva>:<same|flip>` runs at k==20 (after `dumptext`, so the byte is already
Arxan-decrypted) and does one `VirtualProtect` + one byte write:

- `same` (write the identical byte back, on a function nothing calls in a boot-to-menu run):
  **survives** — the sweep does not care about the `VirtualProtect` or the write itself.
- `flip` (change one byte of `0x141a23ec0`, the `UIScreenMultiplayerLobbyHost` ctor, never called
  before the lobby): **dies at t≈3.4 s** — so the check is a blanket `.text` checksum, not
  per-function and not on-call.

IAT slots are **not** uniformly safe either. `VCRUNTIME140!__RTDynamicCast` at `base+0x3198960` is
watched (patching it kills the process, §4e), while the WS2_32 / WSOCK32 / libHttpClient slots the
login shim re-points are not. Treat "it is only `.data`" as a hypothesis to test, not a guarantee.

**Wine refinement (this session):** the E9 detours install fine and emit 19 real game-side lines,
then the process dies at t≈3.4 s (Main.txt stuck at 18, no crash-filter line) — the same signature
as `RTDYN=1`. Windows tolerates the identical build for 600 s. The wine-safe replacement for
"watch what the game logs" is the heap-vptr swap in §4f.

## 4e. `RTDYN=1` death, and the lobbygate field writer that replaced it

`AOE2LAN_RTDYN=1` re-points the `__RTDynamicCast` IAT slot so the host-lobby populator's
`dynamic_cast` can be intercepted and `screen+0x1cf8` written from inside the game's own call.
On wine it kills the game at t≈3 s: Main.txt stuck at 18, no heartbeat, no crash-filter line, no
clean shutdown (the log stops mid-TLS-record). Controlled: the same build with `RTDYN=0` boots to
46 and holds 69 s. Runs: `/tmp/exp-rt1.*`, `/tmp/exp-rt0.*` (gone with the reboot).

The wine-safe replacement is `AOE2LAN_AIGATE=1` (`LobbyGateThread`, `lanhook.c`): find the
`UIScreenMultiplayerLobbyHost` object by its primary vtable (`base+0x33416e0`) whose `+0x1cf8`
holds a plausible gate value, then hold, from outside:

| field | want | why |
|---|---|---|
| `+0x1cf8` (qword) | `[base+0x326b258]` | the populator's gate compare |
| `+0x24f4` (byte) | 1 | `arg4` for the AI-slot rebuild |
| `+0x24e6`, `+0x24e5`, `+0x24c0` (bytes) | 0 | the other three `arg4` terms |

Poll is 10 ms while the object is cached (the game resets `+0x24f4` to 0 every ~250 ms, so 50 ms
only held ~50 %; 10 ms holds ~95 %), full heap scan 1/s until found. Logs only on a state change.
Measured: the object is found at t≈1 s (screens are pre-created at boot) and the fields hold for
the whole run.

## 4f. The wine-safe log sink: `AOE2LAN_LOGVT=1`

`LogHelper` (`0x1402bcb30`) is only a dispatcher: it loads the sink object from the lazily-inited
global `0x144c9e248` (getter `0x1402abe60`, guard `0x144c9e240`) and calls `[[sink]+0x20]`
(`+0x30` when the record level ≥ 4). The sink is **heap** (`0x660d1e0` / `0x8b07050` in different
runs), its vtable is the 7-slot table at `image+0x328a068`:

| slot | meaning |
|---|---|
| `+0x00` | deleting dtor `0x140f3a7b0` |
| `+0x08` | error `0x140f3b270` |
| `+0x10` | warning `0x140f3b2d0` |
| `+0x18` | notice `0x140f3b2b0` |
| `+0x20` | info `0x140f3b290` |
| `+0x28` | debug `0x140f3b250` |
| `+0x30` | `ret 0` |

Each level slot is a 5-instruction thunk `(rcx=self, rdx=fmt, r8=va_list) -> jmp 0x140f192f0`
with `"rlink - <level>"` in adjacent `.rdata`. `logsink_hook()` (called every 5 s from the
heartbeat) VirtualAllocs 8 qwords, copies the RTTI locator from `vt-8` and all 7 slots, points
slots 1–5 at `ls_error/ls_warn/ls_notice/ls_info/ls_debug`, and writes the fake vtable+8 into the
heap object's vptr — **one 8-byte heap write, no image byte changed**. Each stub logs the raw
format string plus the first 4 varargs as hex and as quoted strings (`ls_cstr`, a guarded
printable-ASCII reader; there is no CRT in this DLL, so no `vsnprintf`), then tail-calls the real
slot. Cap 20000 lines. Measured: `t=5.005 logvt: sink obj=0x8b07050 vptr -> fake vtable
0x1750008`, then 489 rlink lines over 140 s with the game alive at the menu.

`AOE2LAN_LOGSINK=1` is the read-only probe of the same chain (prints the sink, its vtable and the
7 slots) — use it first when a new build's sink layout is in doubt.

## 4g. ufw ate the relay beacon (found and fixed)

`BattleServer.exe` broadcasts a 56 B beacon to `255.255.255.255:9999` every ~10 s; the game
listens on `0.0.0.0:9999`. With ufw active (`Default: deny (incoming)`, rules only for
1714:1764, 27000:27050, 4380 — **nothing on 9999**) a locally-sent broadcast is **not** delivered
to a local socket: measured 0/5 to `255.255.255.255` and 0/5 to `192.168.1.255`, while
`127.255.255.255` and `127.0.0.1` delivered 5/5 (`InErrors +0`, `NoPorts +0` ⇒ dropped in
netfilter INPUT). After `sudo ufw disable`: 5/5 and 10/10 delivered, and the game logged
`t=11.750 rlink INFO: "Adding LAN relay server: %s, GUID %s" a0="192.168.1.9"
a1="f887f3fb-9113-4f6b-8d85-82f473f11bf8"`.

Beacon bytes (`/tmp/beacon.log`, sniffer `/tmp/sniff9999.py`, which waits for the game to bind
:9999 first so it cannot steal the bind):

```
21240066383837663366622d393131332d346636622d386438352d38326634373366313162663809004d7920536572766572846900004c6a
= "!$." + 36-byte ASCII GUID + 09 00 + "My Server" + tail
```

Permanent fix: a narrow rule, `sudo ufw allow from 192.168.1.0/24 to any port 9999 proto udp`.
For cross-machine play (todo #8): **tailscale does not forward broadcasts at all**, so lanhub must
unicast a synthetic beacon to `127.0.0.1:9999` (loopback is always allowed by ufw). lanhub already
reports `relayIP=100.109.201.126` (tailscale) when it picks an interface; `AOE2LAN_RELAY_IP`
overrides it.

## 4h. Create Lobby: what is known, and why the old evidence was void

**Windows reference sequence** (`logs/lanhook-12008.log`, click at t=179.172, all within 31 ms):

```
GLOG [Network] "TComm_Matchmaking_RL::CreateLobby"
GLOG [Network] "SetLobbyDataString '%s' = '%s'[%zu byte]"
GLOG [Network] "MatchAdvertisementOptions::Write %d bytes"
HIT LogHelper "starting LAN hosting"   ret=0x7ff6f226144a  (= VA 0x14035144a)
HTTP REQ /game/advertisement/host
```

`0x14035144a` is the return address of the `call 0x1402bcb30` at `0x140351445`, inside
`WorldwideAdvertisementService::Host` (`0x1403503a0..0x1403526fc`). The three "starting … hosting"
strings are chosen by `[svc+0x1a8]`: 0 = online, 2 = offline, anything else = LAN.

**On wine** none of those lines appear, no TCP to `127.0.0.1:443` is opened at click time, and no
`/game/advertisement/host` request is made. **But that is not evidence of a stall**, because:

- the game-layer log fn `0x140f19210` starts with
  `cmp byte [0x144356c66], 2 ; jae emit ; test dl,dl ; je return`, i.e. **level-0 messages are
  dropped** unless the `.data` byte is ≥ 2, and every `TComm_*` message is level 0
  (`TComm_Matchmaking_RL::CreateLobby` logs `xor edx,edx` at `0x140ee75d5`);
- on Windows that byte was raised by `hookcore.c`'s `verbose_on()`, which is only reachable from
  the GLOG detour — a `.text` hook, i.e. dead on wine.

So the wine runs were **blind**, not idle. New lever: `AOE2LAN_VERBOSE=1` calls `verbose_setup()`
from the heartbeat and writes the byte to 2 — a `.data` write, the same class as lobbygate. It is
guarded on `[[0x144356c88]+0x6f0] != 0` because the level-0 writer `0x14101bb50` dereferences that
pointer with no null check at `0x14101c6fa`. With the byte at 2, level-0 lines reach the rlink
sink and `AOE2LAN_LOGVT=1` prints them, so the next click run shows the last line before the stall.

**Dead theory:** the `/wss/` live channel. Windows ran the *same* shim with the *same* silent
websocket (one `{"clientLibVersion":194,"operation":0,…}` frame, then only pings) and hosted
normally. The websocket is not what blocks Create Lobby.

**Environment gotcha (cost this session two runs):** with no monitor attached, Xwayland is
`0x0 pixels / 0 monitors`, wine's `lock_display_devices` fails, and the game exits 1 at t≈2 s
*before* writing Main.txt — with or without our DLL. Check
`cat /sys/class/drm/card*/status` (all `disconnected` = headless) before blaming a build.

## 4i. Knobs added or changed this session

| knob | effect |
|---|---|
| `AOE2LAN_LOGVT=1` | heap-vptr log sink hook (wine-safe); prints `rlink <LEVEL>: "<fmt>" a0..a3` |
| `AOE2LAN_LOGSINK=1` | read-only dump of the sink chain at k==25 |
| `AOE2LAN_VERBOSE=1` | raise `[0x144356c66]` to 2 once the level-0 writer exists (game-layer level-0 logs on) |
| `AOE2LAN_TEXTPOKE=<rva>:<same\|flip>` | the `.text` checksum discriminator (§4d) |
| `AOE2LAN_DUMPTEXT=1` | write the live decrypted `.text` to `logs\gametext.bin` |

`linux/launch.sh` defaults: `STAGE=8`, `NOHOOKS=1`, `AIGATE=1`, `RTDYN=0`,
`PROTON_NO_NTSYNC=1`, `WINEDLLOVERRIDES="dbghelp,winmm=n,b"`. `getenv_flag` treats `"0"` as
false, so `AOE2LAN_NOHOOKS=0` really enables the detours.

## 4j. Open

1. One click run with `AOE2LAN_LOGVT=1 AOE2LAN_VERBOSE=1` (needs a monitor attached): does
   `TComm_Matchmaking_RL::CreateLobby` appear? If yes, the stall is after it; if no, the click
   never reaches the network layer and the next instrument is the UI side.
2. If the level-0 flood eats the 20000-line cap before the click, filter `ls_emit` by substring
   (`TComm`, `Match`, `Lobby`, `Host`) instead of raising the cap.
3. `AOE2LAN_WSETVT=1` (the `.rdata` widget-vtable patch) is still untested on wine; it is the
   natural next instrument for UI-side visibility, but `.rdata` may be as watched as `.text`.
4. Todo #8: lanhub must unicast a synthetic beacon to `127.0.0.1:9999` (§4g).
