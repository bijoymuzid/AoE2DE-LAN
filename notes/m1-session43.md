# Session 43 — the game layer is finally visible; the match never receives `MatchStartMessage`

Supersedes `notes/m1-session42.md` for everything below. All addresses are VAs unless written `RVA`.
MEASURED items come from four runs with `PLAY-stage8-GLOG.cmd` / `PLAY-stage8-VERBOSE.cmd`:
`logs/lanhook-12568.log` (died clean at t=5.03 — the known transient), `logs/lanhook-11724.log`
(670 s, hook 17 alone), `logs/lanhook-9628.log` (560 s, the matchState fix), `logs/lanhook-17140.log`
(855 s, verbose — **the run that produced the answer**). Everything else was read from
`dev/lanhook/gametext.bin` (decrypted `.text`) and `AoE2DE_s.exe` `.rdata`. Game exe untouched.

**Code changes this session: one new hook (id 17 `GLog`, kind `HK_GLOG`=7), one opt-in data write
(`AOE2LAN_VERBOSE`), one new hooktest case (T7), two `loginsrv.c` fixes (matchState, the
`MatchStartMessage` push), matching `srvclient.py` checks, two new `PLAY-stage8-*.cmd`.**

## 43a. Result, up front

- **§42f N13 DONE and MEASURED.** Hook 17 on the CLEAN `0x1407db520`, caller-filtered to the log
  function, works. It printed game-layer text for the first time in 43 sessions.
- **N13 alone was not enough, and N13b is now SOLVED without the command line.** Hook 17 found only
  **9 unique messages in 670 s** — because the game's log function drops every level-0 message
  unless one `.data` byte is ≥ 2, and **every `TComm_Provider_RL` message is level 0**. Raising that
  byte (`AOE2LAN_VERBOSE=1`) took the same run to **81 unique messages**. §43d.
- **THE ANSWER: the game is waiting for a server push we have never sent.** The verbose log shows the
  countdown finish, `GCMessageMPLaunch`, and `TComm_Provider_RL::StartLaunchGame` → `ok`, then
  nothing for 730 s. The only thing that builds the roster a match loads from is advertisement event
  **case 7 = `AET_MatchStartNotify`**, fed by the websocket notification **`MatchStartMessage`**.
  Our shim never sent it, so it never fired. §43f. **The push is now implemented and passes offline;
  it has NOT been run in-game yet.**
- **Priority 1 still not reached.** Also fixed on the way: `/game/advertisement/updateState` answered
  `matchState:0` to `state=1`, forever. Real bug, now fixed and measured — and **not the blocker**
  (the game ignored the corrected reply exactly as before). §43g.
- Priority 2 and 3 not reached. The s41 AI dropdown fix is still working (24 `AISlotLabel` hits,
  17 `keepgate` repairs, again).

## 43b. Gates (final build)

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged.
- `hooktest.exe` PASS: `game-image iat walk: swapped 68 of 68`, `post-hook ok (21, 210, 2100, 6)`,
  and the new `T7 ok (210, 6)`.
- `srvtest.exe` + `srvclient.py` **PASS**, including the three new lines
  `updateState reply: matchState=1`, `MatchStartMessage push: 789B, matchState=1, members=1`,
  and the browse check that the listed advertisement keeps `matchState 1`.
- Staged `dbghelp.dll` MD5 **`bc3d5790215781bda16ba9dbe1381780`**, identical in the game dir and
  `dev/lanhook/`. Backups taken BEFORE each build: `.prev-s43-before` = `475c2ff7a37a382bf5336ac94da70597`
  (the s42 build), `.prev-s43-glog` = `e81212d9533bafe76e3683fff960b847`,
  `.prev-s43-matchstate` = `5da10aa6eaed12b7a2cf3e7011659f70`.
- `work/verifydll.py`: **18** HOOKDEF entries, kinds 0–7 all present, `GLog va=0x1407db520
  exp=4c 89 44 24 18 4c 89 4c wait=600000 grp=0 kind=7`.
- `dumpbin -DISASM` (never a byte grep) confirms all three new code paths — see §43j.

## 43c. Hook 17 `GLog` — as built, and where §42f's spec was wrong

- Target `0x1407db520`, CLEAN on disk (93/93 bytes identical), 16-aligned. Real prologue is
  `4c 89 44 24 18 4c 89 4c 24 20 53 55 56 57 48 83` = `mov [rsp+0x18],r8; mov [rsp+0x20],r9;
  push rbx; push rbp; push rsi; push rdi; sub rsp,0x38`. **§42f wrote the pushes as `55 56 57`;
  they are `53 55 56 57`.** `EXP_GLG[8] = 4c 89 44 24 18 4c 89 4c`.
- **`hook_len` resolves to 5, not 10.** `insn_len` measures `4c 89 44 24 18` (REX.W + `89` +
  ModRM 0x44 + SIB + disp8) as exactly 5, and `hook_len` returns as soon as n ≥ 5. The trampoline
  replays that one `mov` and jumps back to `0x1407db525`. Install log confirms `installed GLog n=5`.
- **Caller filter is a RANGE, not two exact addresses: `0xf19200..0xf19400`.** `ctx[19]` is the
  *return* address = call site + 5, so §42f's `0x140f19275` / `0x140f19347` would never have matched
  (the real values are `0xf1927a` / `0xf1934c`). `cx.py` proves only those two `E8` sites to
  `0x1407db520` exist in that window, so the range is exactly as precise and immune to the +5
  question. Both fired and are visible as `site=0x…f1927a` / `…f1934c`.
- Registers, MEASURED correct: `ctx[-7]` = rsi = the caller's **format string** (the log fn does
  `mov rsi,r8` at `0x140f1924b` / `0x140f1931d`, and the helper pushes rsi only at +12, so the
  thunk's entry snapshot still holds the caller's), `ctx[14]` = r9 = the **category**.
- Log line: `GLOG #<n> site=0x<caller-rva> [<category>] "<format>"`. Deduped on (category, format),
  **cap 2048** unique (not 512 — a full host+Start run needs the headroom), first 20 s skipped for
  logging only. READ ONLY: writes nothing to game memory.
- `HK_MAX` is 20, so id 17 needed no table change. `work/verifydll.py`'s kind filter was extended to
  `(0..7)` — §41b's trap, avoided.
- Opt-in via `AOE2LAN_HOOKS`; `grp=0`, so no stage selects it. Default stage-8 hooks unchanged.

## 43d. THE reason 43 sessions saw nothing: a level-0 filter and one zero byte

`0x140f19210` (the game-layer log fn) opens with:

```
140f1923c  cmp byte ptr [0x144356c66], 2
140f19243  lea rbp, [rsp + 0x1088]        ; rbp = the va_list (= &the r9 shadow slot)
140f1924b  mov rsi, r8                    ; the caller's format string
140f1924e  movzx edi, dl                  ; dl = the message level
140f19251  jae 0x140f19257                ; byte >= 2 -> log ANY level
140f19253  test dl, dl
140f19255  je  0x140f192d5                ; level 0 -> RETURN, nothing formatted, nothing logged
140f19257  ...                            ; builds "[%s] " via 0x1407db520 (hook 17), then writer A
```

**Every `TComm_Provider_RL` message is level 0.** `StartLaunchGame` does `xor edx,edx` at
`0x140f1609e` before `call 0x140f19210`; `UpdateConnectionState` likewise at `0x140f17106`. So they
were dropped *before* the vsnprintf call hook 17 sits on. That is the whole 43-session blindness —
not a missing call, not an encrypted writer. The one message that did get through
(`Setting mCancelCountdown…`) passes `mov edx,1`.

`0x144356c66` is in `.data` at RVA `0x4356c66`. `.data` is rva `0x3da7000`, vsize `0xefb9c8`,
**rawsize only `0x4af600`** — so our byte is `0x5AFC66` into the section, **past the raw data**: it
is zero-filled at boot. MEASURED: it read **0**, and the second sink pointer `[0x144356c88]` was
non-null (`0x000002c82ebc4d40`).

`0x140f19210` has **370 call sites** (`cx.py`), so it is the general logger, and raising this one
byte opened `[Network]`, `[rlink - info]`, `[rlink - warning]` and `[rlink - error]` all at once.
Related: `0x140b75820` indexes `[cl + 0x144356c58]` per log system, and `0x144356c66` =
`0x144356c58 + 14`; whether 14 is a system index or a separate global was **not** resolved and did
not need to be.

**Implementation (`AOE2LAN_VERBOSE=1`, `verbose_on()` in `hookcore.c`):** called from hook 17's
filtered path *before* the 20 s logging skip, so a level≥1 message (rlink errors, MEASURED at
t≈3.7–20) arms it long before Start. It is a **data** write, the same class as hooks 14/16, not a
code patch — no Arxan response in four runs.

**Guard (do not remove):** level 0 with the byte ≥ 2 also routes to writer **B** `0x14101bb50`,
which at `0x14101c6fa` does `mov rax,[rsp+0x50]; mov rcx,[rax+0x6f0]` — an **unconditional
dereference of the sink** with no null check. So `verbose_on()` only raises the byte once
`[0x144356c88]` is non-null, and logs `VERBOSE: sink [0x144356c88] still null, not raising the level
yet` (capped at 3 lines) otherwise. On an SEH fault it disables itself.

## 43e. MEASURED — the verbose run's game-layer timeline (`logs/lanhook-17140.log`)

81 unique `GLOG` lines. Hosting at t≈89.6, Start at t≈120.3. The load-bearing part:

```
t=89.625  [Network] OnMatchEvent/MET_MatchInfoUpdated/R_Success sess=%lld diff=%llu version=%d
t=89.625  [Network] OnMatchEvent/MET_AddPlayer/R_Success pl=%lld sess=%lld
t=89.625  [Network] TComm_Matchmaking_RL::OnPlayerAdded
t=89.625  [Network] TComm_Matchmaking_RL::UpdateSessionInfo SLOT %llu = '%s'   -> "…ok"
t=89.640  [Network] Got Advertisement Host event (profileID=%llu, hostResult=%d: %s)
t=89.640  [Network] OnAdvertisementEvent/AET_Host/R_Success - SESSID %lld, region='%s'
t=89.640  [Network] TComm_Matchmaking_RL::OnLobbyCreated  /  OnHost: Requesting slot %d …
t=89.703  [Network] TComm_Provider_RL::SendP2PPacketRawMemCopy PKT=%d/%s (%u bytes) -> %lu
t=89.703  [Network] Calling SetPlayerSlotInfo from UpdateSlotsOnProvider.
t=89.703  [Network] SetPlayerSlotInfo: Setting slot %d for player %lld, team %d
t=90.422  [Network] OnAdvertisementEvent/UNKNOWN %d            <- cases 4 and 12 are unhandled
t=120.344 [Network] Countdown finished, sending GCMessageMPLaunch.
t=120.344 [Network] TComm_Provider_RL::StartLaunchGame LAUNCH_GAME
t=120.344 [Network] TComm_Provider_RL::StartLaunchGame ok
t=120.359 [rlink-info] WorldwidePartyService::SetMatchState - state %d - updating server   (state 1)
t=121.047 [Network] OnMatchEvent/MET_PeerUpdate
t=122.062 [rlink-info] WorldwideAutomatchService::OnStartComplete - detected successful game start
t=122.062 [rlink-info] Match Started - %s, slot = %2zd, ranking = %4d
t=122.062 [rlink-error] Rejected PlayerReadyRequest, state is not MS_Setup
          ...then NOTHING but MessageCounts heartbeats until t=855.
```

Never fired in 855 s, at any level: `AET_MatchStartNotify`, `ReceiveNetworkData`, `ProcessPackets`,
`UpdateConnectionState`, `connectToGame`, `onPacketSendingTicket`, `InitProvider`,
`findOrInitiateP2PConnection`. (`ReceiveNetworkData` legitimately never fires for a host-only lobby —
there is no remote peer — so do not chase that one.)

`StartLaunchGame` = `0x140f16060..0x140f164db`, **ENCRYPTED**. It ends with
`S = 0x1402ab8a0()` (returns `[0x144c9e5f0]`, the central game object, 2612 xrefs), then
`O = S->vf[0x108]()`, `O->vf[0x130](1)`, `O->vf[0x140](0)`, `O->vf[0x150](…, L"unknown password")`,
`[r14+0x2f7c] = 1`, `0x140ef1740([r14+0x2b50])`, and finally `O->vf[0x118](1)`.
**`"StartLaunchGame ok"` is logged unconditionally** — the return value of `vf[0x118]` is never
checked, so `ok` means "reached the end", not "succeeded". `UpdateConnectionState` =
`0x140f17060..0x140f17167`, also ENCRYPTED.

The countdown function is `0x141a26fa0..0x141a296a1`; the launch send is at `0x141a2767d` (log) →
`0x141a2769b call 0x140d678c0` on `[0x1443552b8]`, message type `0x20`.
`Setting mCancelCountdown` is in `0x141a44520..0x141a44925` (ENCRYPTED) and logs only on a **0→1**
transition of `[rbx+0x551]`, with `bIsReady = [rbx+0x5f1]` and `mbAllPlayersReady = [rbx+0x7d41]`.
It fired at lobby build (t=53/131), **before** hosting completed. Normal — do not chase it.

## 43f. THE BLOCKER: `MatchStartMessage` — full derivation

**The dispatcher.** `0x140eeb930..0x140eeccb4` = `OnAdvertisementEvent`. It switches on
`movsxd r9, dword [rdx+0x10]`, `cmp r9d,0xd; ja UNKNOWN`, jump table at **`0x140eecc7c`** (14 dwords,
RVA-relative to `0x140000000`). **Cases 4 and 12 both land on the UNKNOWN branch `0x140eecc07`** —
that is the `OnAdvertisementEvent/UNKNOWN %d` we saw. **Case 7 → `0x140eec335` =
`AET_MatchStartNotify`**, and it is the only case that builds a match roster:

```
140eec370  cmp dword [rdi+0x48], 0 ; jne bail          ; result must be 0
140eec380  call [rax+0x160]                            ; our profileID
140eec386  cmp [rdi+0xa8], rax ; jne bail              ; the notify must be for US
140eec393  mov rcx,[0x1442dc4f0]; call 0x140e16500     ; same global StartLaunchGame uses
140eec3b3  r14=[rdi+0x88], r13=[rdi+0x90]              ; the roster vector
140eec3c1  cmp r14,r13; je 0x140eec4a6                 ; empty roster -> a different path
140eec430  add rbx,0x170                               ; element stride 0x170
```
Log args: `result=%d date=%lu session=%ls` from `[rdi+0x48]`, `[rdi+0x80]`, `[rdi+0x168]`.
There is **no `MET_Start` / `MET_Launch`** — the full `MET_*` set is AddPlayer, MatchInfoUpdated,
MatchInfoAck, RemovePlayer, HostMigration, ReportResults, PeerUpdate, ReconnectBegin,
ReconnectComplete. **The launch comes through the advertisement plane, not the match plane.**

**The wire name and parser.** Notification message names and their field names live in one packed
blob around `0x14369ed00` (`MatchHostedMessage`, `MatchObserveMessage`, `MatchStartMessage`
`0x14369ee08`, `SessionStatusMessage`, `GameResultNotificationMessage`, …). The **registered payload
parser table is `0x144116af0`, 46 entries × 0x10** (§s21). **Entry 9 = `0x1407b66f0`**, a 6-instruction
thunk → **`0x1407cdf10..0x1407ce0ce`**, which checks `[name+0x10] == 0x11` (17 chars) and compares
against `"MatchStartMessage"`, then allocates 0x2c8 bytes with vtable `0x143676890`.

**The exact payload** — reader `0x1407b6710..0x1407b721f`, and its **writer `0x1407b7220..0x1407b73e8`
gives the shapes for free**:

| member | Info offset | writer | notes |
|---|---|---|---|
| `ownedAppIDs` | +0x08 | `0x14057b8e0` | array |
| `profileRaces` | +0x20 | `0x1407d47b0` | array, copied stride 0x10 |
| `matchStartDate` | +0x38 | `0x14039bf40(…,1)` | a u64; only ever logged (`date=%lu`) |
| `equippedItems` | +0x40 | `0x1403e41d0` | array, copied stride 0x20 |
| `matchAdvertisement` | +0x58 | **`0x14056dda0`** | **the SAME advertisement dto `emit_advertisement` already builds** |
| `inProgressChallenges` | +0x2b0 | — | array |

Every member is **optional**: the reader calls `0x14039b8e0` ("at end of structure?") and skips
anything absent — the same shape as the peerAdd parser in §42c.

**The envelope** is fixed by the notification reader `0x1407a7620..0x1407a7d2b`, which consumes
exactly three members: **`result`, `m_type`, `m_profileID`**, then hands the cursor to the registered
parser — so the payload members are **siblings at the top level**, not nested.

**The consumer.** `WorldwideNotifier::ProcessNotification` = `0x140799300..0x14079c5fd`
(source path `…\rlink\internal\service\worldwide\WorldwideNotifier.cpp`), `MatchStartMessage` branch
at `0x14079a1a9`. It copies each Info member, then `0x140332790` / `0x140434eb0` on the copied
advertisement; failure paths log **`WorldwideNotifier::ProcessNotification: Failed to add profile
information to slots.`** (`0x14369e190`) and **`A match discrepancy has been detected, can't start
the match.`** (`0x14369e148`). So the roster is filled **from the advertisement's `matchMembers`** —
which is why `matchAdvertisement` is the member that matters and the other five can start empty.

**What was implemented (`loginsrv.c`):**

- `static volatile LONG g_MatchStart` — **one-shot 0→1→2**. `route()` arms it with
  `InterlockedCompareExchange(&g_MatchStart, 1, 0)` only when an advertisement request carries
  `state` in `'1'..'9'`. `ws_serve()` fires on the `1→2` transition, so a game that re-sends
  `updateState` once a second cannot spam the socket.
- `build_match_start(BUF*)` emits one frame:
  `{"result":0,"m_type":"MatchStartMessage","m_profileID":<hostid>,"matchStartDate":<unix secs>,
  "ownedAppIDs":[],"profileRaces":[],"equippedItems":[],"inProgressChallenges":[],
  "matchAdvertisement":<emit_advertisement(stored body)>},`
  — **with the mandatory trailing comma** (§s20: `"null,"` parses, `"null"` does not). Sent as
  `ws_send(t, 0x2, …)` (binary), which is how rlink sends its own JSON.
- Reuses the existing `unix_now()` at line ~116 — **do not add a second one** (I did, it broke the build).
- The websocket is alive for the entire run: `ws_serve` logs frames only `if (frames <= 6)`, so the
  absence of later `WS: frame` lines means nothing. There is no `WS: closed` line in run D.
  `SO_RCVTIMEO` is 1 s (`ConnWorker`), so the push lands within ~1 s of the arm.

**NOT YET RUN IN-GAME.** Offline it produces a 789-byte frame that `srvclient.py` validates.

## 43g. Also fixed: `updateState` answered `matchState:0` to `state=1`

`contains(path, "/game/advertisement/update")` also matches `updateState`, whose body is
`advertisementid=…&callNum=…&connect_id=…&sessionID=…&state=1` — **no `hostid`**. So the s32 fallback
echoed the *stored* lobby (last full `update`, `state=0`) and `adv_store` was skipped, so the new
state was never remembered. The game said "set state 1" and our reply said "you are in state 0",
every time.

Fix: `g_AdvState[8]` + `adv_set_state`/`adv_get_state` under their own `g_AdvStateLock` (same idiom as
`g_AdvBody`), captured in the update branch before the echo; `emit_advertisement` now prefers the
remembered state, then the body's own `state`, then `-1`. MEASURED: run C's reply carried
`matchState":1`. **The game ignored it and sat in the lobby exactly as before** — a real bug, closed,
**not the blocker**. Same shape as s42's peerAdd.

Host request for the record: `state=-1`, `visible=0`, `joinable=1`. First full `update`: `state=0`,
`visible=1`, `joinable=0`. `updateState`: `state=1`.

## 43h. Next session, in order

1. **RUN IT.** `PLAY-stage8-VERBOSE.cmd` (unchanged — it now also pushes). Host, 3 AI, Start, wait
   2 min. Read, in this order:
   - our log: `WS PUSH MatchStartMessage len=NNN` (≈789 B) — did we send it?
   - `GLOG … [Network] "OnAdvertisementEvent/AET_MatchStartNotify result=%d date=%lu session=%ls"`
     — **did the game accept it?** This is the single line that decides everything.
   - `[rlink-error] "WebSocketConnection - failed to parse notification messages [%s]"` → envelope or
     payload shape is wrong.
   - `"Failed to add profile information to slots."` / `"A match discrepancy has been detected,
     can't start the match."` → close; the roster/`matchMembers` is the problem.
2. **If `AET_MatchStartNotify` fires with `result != 0`** → fix the payload. Members are optional, so
   add them one at a time; `profileRaces` first (stride 0x10, almost certainly `{profileID, raceID}`
   pairs — read `0x1407d47b0` to confirm).
3. **If it fires with `result == 0` and the map still does not load** → follow case 7's roster build
   at `0x140eec3b3` and the empty-roster path `0x140eec4a6`, and check whether `matchMembers` must
   carry more than the host.
4. **N11** — once a match loads, verify the AI actually play (§41h item 2). `session+0xee0` holds the
   AI list (§40d).
5. **N12** — retire the s38 bit-0x4 suppression? Still unverified; run D shows it still firing.
6. **N7 / M2** — a second human over the tailnet. §42d still holds: the peer must reach **27012/TCP**
   and `relayIP` must become the tailnet IP. 27112 is dead.

**Do NOT:**
- re-open peerAdd/peerUpdate (§42) or the matchState reply (§43g) — both fixed and measured;
- build `lanrelay` (PLAN §6.4) — the stock relay is proven good (§42d);
- retry the `-VERBOSELOGGING` / `-LOGSYSTEMS` command-line syntaxes — **obsolete**: §43d gets the
  same result with one data byte, and the parser `0x1408fc0b0` is encrypted anyway;
- hook `0x140f19210`, `0x140f192f0`, `0x14101b4b0`, `0x14101bb50`, `0x140f16060`, `0x140f17060`,
  `0x140eeb930`, `0x140799300`, `0x141a44520`, `0x141a26fa0`, `0x1408fc0b0`, `0x140a89230`,
  `0x140a1b9f0`, `0x1404d01b0`, `0x140313810` — all ENCRYPTED on disk (read them from
  `gametext.bin` only);
- remove the sink null-guard in `verbose_on()` — writer B dereferences it unconditionally;
- chase `Setting mCancelCountdown` (lobby build, before hosting, normal), the 27212 TLS
  handshake_failure, `OnStartComplete`'s missing "forcing pollcomplete event", `Match Started` being
  logged once, who writes -1 into `screen+0x1cf8`, or `OnAdvertisementEvent/UNKNOWN %d` (cases 4/12
  are simply unhandled in the game's own switch);
- believe "0 recv from the relay" in our log (§42d — that socket's read path is not instrumented).

## 43i. Traps recorded so nobody pays for them twice

- **`ctx[19]` is the RETURN address = call site + 5.** Any exact-address caller filter must use +5.
  Prefer a range. This is why hook 17 filters `0xf19200..0xf19400`.
- **`hook_len` for `4c 89 44 24 18 …` is 5, not 10** (§42f guessed 10). The LDE returns as soon as
  n ≥ 5, so a 5-byte first instruction always gives 5.
- **A hooktest target function must store every shadow slot it reads.** The first T7 read
  `[rsp+0x08]`/`[rsp+0x10]` (the rcx/rdx shadows) without writing them; the caller leaves garbage
  there, so post-hook it returned a value that tracked `&lanhook_thunk` minus a constant. It looked
  exactly like a broken trampoline. T5 stores all four; T7 now does too. **The hook machinery was
  fine — the dumps proved n=5 and byte-perfect patching.**
- **`.data` past its rawsize is zero-filled at boot.** Reading such an address from the file returns
  the *next section's* bytes. `.data` rawsize is `0x4af600`; anything above rva `0x4256600` in that
  section is bss. Check `rva - section_rva < rawsize` before trusting an on-disk value.
- **MSVC folds short string constants into immediates.** `"GLOG #"` has no `lea` — it appears as
  `mov cl,47h` plus a byte-copy loop from the string's address. Verify new code by disassembling
  around the *neighbouring* `lea`s, never by grepping for the string's address.
- **MSVC link is not reproducible.** Rebuilding identical sources changed the DLL MD5 twice this
  session (`125dad70…` → `bc3d5790…`). Always re-run the gates on the final build, and re-md5sum both
  copies after `build.cmd`'s `copy`.
- **`loginsrv.c` already has `unix_now()` (line ~116) and `form_get` (line ~1381).** `BUF`/`bs`/`bnum`
  are at ~125–150, so a forward declaration of anything taking `BUF*` must come *after* line 130.
- `aoe2re.PE.find_string()` returns a list of `(offset, va)` tuples, not an offset.
  `A.pe.find_string(b'X')` → `[(off, va), …]`.
- A launch that dies under ~5 s with a clean boot log is a transient — run A died at t=5.03 with no
  crash line and relaunched fine. Relaunch before debugging.
- The launcher returns the **cmd.exe** PID. Run D: launcher said `Pid=14344`, the game was 17140.
  Always take the newest `logs/lanhook-<pid>.log`.

## 43j. Verification actually performed (not byte greps)

`dumpbin -DISASM` on the final DLL confirms:
- hook 17: `0x180007104 cmp eax,7` → `mov r12,[rdx+0x98]` (ctx[19]) → `sub r12,[g_ModBaseVal]` →
  `lea rax,[r12-0xF19200]` → `cmp rax,200h; ja` (the caller window) → `cmp eax,4E20h` (the 20 s skip)
  → `mov rcx,[rsi+70h]` (ctx[14]) / `cmp [rsi-38h],r13` (ctx[-7]) → two `read_cstr` calls with
  `r8d=0x28`/`0xB0` → FNV `mov rcx,14650FB0739D0383h` / `mov rdx,100000001B3h` →
  `cmp rax,800h` (the 2048 dedup cap) → `lea rcx,[0x180025E60]` = "HIT GLog capped at 2048 unique
  lines" → `mov cl,47h` ('G') + a byte loop over `[…+0x25E88]` = "GLOG #" → `lea r14,[0x180025DC8]`
  = " site=0x".
- `verbose_on`: `0x180007B04 movzx r10d,byte ptr [rcx+4356C66h]`,
  `0x180007B13 mov rbx,[rax+4356C88h]`, `0x180007B49 mov byte ptr [rcx+4356C66h],2`.
- the matchState fix: `0x1800105F0 xchg eax,[0x1800AEB28]` (the lock) → `lea rdx,[0x180028DD4]`
  ("state") → `form_get` → `lea rdx,[0x180028DE0]` (`,"matchState":`) → `lea r9,[0x180028DF0]` ("-1");
  and in `route()` `0x180012F06 lea r8,[rbp+0x4058]` / `mov r9d,8` / `lea rdx,[0x180028DD4]`.
- `hooktest.exe`: `T7 ok (210, 6)` proves the LDE, trampoline and thunk survive hook 17's exact
  prologue shape (`mov [rsp+imm],r8/r9` as the FIRST instruction).

## 43k. Files added / changed this session

| file | what changed |
|---|---|
| `hookcore.h` | `#define HK_GLOG 7` |
| `hookcore.c` | the `HK_GLOG` handler; `verbose_on()` + `g_Verbose` |
| `lanhook.c` | `EXP_GLG[8]`; hook id 17 `{"GLog", 0x1407DB520, EXP_GLG, 600000, 0, HK_GLOG}` |
| `hooktest.c` | `T7` + `E7`, `g_Hooks[3]`, the p7/slot7 dump, `T7 ok (210, 6)` |
| `loginsrv.c` | `g_AdvState`/`adv_set_state`/`adv_get_state`; `emit_advertisement`'s matchState; `g_MatchStart`; `build_match_start`; the `ws_serve` push |
| `srvclient.py` | `ws_connect()` extracted from the inline upgrade; the updateState matchState check; the browse matchState check; the MatchStartMessage push check |
| `work/verifydll.py` | kind filter widened to `0..7` |
| `PLAY-stage8-GLOG.cmd` | NEW — `AOE2LAN_HOOKS=4,5,13,14,15,16,17`, `AIGATE=1`, no verbose |
| `PLAY-stage8-VERBOSE.cmd` | NEW — the same plus `AOE2LAN_VERBOSE=1`. **Use this one.** |
| `work/disasm-dll-s43*.txt`, `work/f_advevent.txt`, `work/f_matchstart_parse.txt` | the disassembly these findings came from |

Unchanged and still armed: hooks 14/15/16, `AOE2LAN_AIGATE=1`, `lobby_keepgate`, the s38 bit-0x4
suppression, and every §42 conclusion.
