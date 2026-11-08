# Session 44 — the push runs in-game; the notification parser rejects it; the parse path is encrypted

Supersedes `notes/m1-session43.md` for everything below. All addresses are VAs unless written `RVA`.
MEASURED items come from three runs with `PLAY-stage8-VERBOSE.cmd`: `logs/lanhook-9388.log`
(first in-game push, 505 s), `logs/lanhook-5488.log` (died at t=18 — operator clicked **No** on the
Windows certificate dialog, TLS to the shim failed, login aborted — NOT a code bug),
`logs/lanhook-8656.log` (310 s, the cap-bypass build that captured the error string). Everything else
was read from `dev/lanhook/gametext.bin` (decrypted `.text`) and `AoE2DE_s.exe` `.rdata`. Game exe
untouched (`affb19f03ca96965abf9e56775cab688`).

**Code changes this session: one `loginsrv.c`-adjacent `hookcore.c` change (HK_RDSTR cap-bypass for
"failed to parse"), one reverted experiment (hook-17 `arg0`/rbp capture — produced garbage, removed).**

## 44a. WORKING RULE the operator set this session — obey it every session

**MEASURE FIRST. Do not spend tokens on long static reverse-engineering when one instrumented run
answers the question.** This session burned a lot of the operator's budget walking the bond
deserializer / registry linked list / descriptors statically and it did NOT pinpoint the bug. The
operator's standing instruction: go straight to a runtime measurement, and keep the number of game
runs to a minimum by making each run capture the maximum information. Before planning ANY hook,
check the target is CLEAN on disk (see 44f) — an encrypted function cannot be hooked, so a whole
class of "just hook it and log" plans is silently impossible. Check cleanliness FIRST, then design
the measurement.

## 44b. Result, up front

- **The §43 push WORKS at the transport level and was RUN IN-GAME for the first time.** Measured:
  `WS PUSH MatchStartMessage len=1740` (run 9388) / `len=1752` (run 8656) — the real in-game frame is
  ~1750 B, not the 789 B the offline `srvclient.py` produces, because the live advertisement body
  carries the real zlib `options` + `encodedSlots` blobs. The game RECEIVED it
  (`SOCK recv from 127.0.0.1:443 1768B`), logged `WebSocketConnection::ProcessMessages: message=%s`
  with our JSON, and **acked it** (`WS TEXT {"operation":1,"ackCount":1}`).
- **THE BLOCKER: the notification parser rejects the payload.** Immediately after the ack:
  `[rlink-error] "WebSocketConnection - failed to parse notification messages [%s]"`.
  `OnAdvertisementEvent/AET_MatchStartNotify` **NEVER fired** in any run. So the match still does not
  load. Priority 1 still not reached.
- **The `%s` in that error is NOT a field-level reason — it is the raw message echo.** Captured via
  hook 13 (see 44d): `s8="{"result":0,"m_type":"MatchStartMessage","m_profileID":3842241165083521"`
  (truncated at the 72-char `read_cstr` cap). So the log tells us the message failed, not which member.
- **The two functions that would tell us why are ENCRYPTED on disk and therefore NOT hookable:**
  the MatchStartMessage factory `0x1407cdf10` and payload parser #9 `0x1407b6710` (44f). This is the
  key new constraint.

## 44c. Gates (current build)

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged.
- Staged `dbghelp.dll` MD5 **`7a66dd36fe5dc3ac9e7c32aa0bd7c398`**, identical in the game dir and
  `dev/lanhook/`. This is the HK_RDSTR cap-bypass build.
- `hooktest.exe` PASS: `swapped 68 of 68`, `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`.
- `srvtest.exe` + `srvclient.py` PASS, incl. `updateState reply: matchState=1` and
  `MatchStartMessage push: 789B, matchState=1, members=1`.
- `work/verifydll.py`: 18 HOOKDEF entries, `GLog va=0x1407db520 … kind=7` present.
- `dumpbin -DISASM` (never a byte grep) confirms the cap-bypass: `lock xadd [g_HLines]` →
  `cmp eax,200h` → `jle log` → `lea rdx,[0x180025CE0]="failed to parse"` → `call contains_ci` →
  `je drop`. Backups taken BEFORE each build: `.prev-s44-arg0` = `bc3d5790215781bda16ba9dbe1381780`
  (the s43 build), `.prev-s44-cap` = `be87ef20aa1a21226f9e5adde3326f51` (the reverted arg0 build).

## 44d. What was changed in code, and why

- **HK_RDSTR 512-line cap bypass (`hookcore.c`, the `HK_RDSTR` branch of `lanhook_log_hit`).** Hook 13
  `LogWarn` (kind `HK_RDSTR`, target `0x1402bcc00`) already derefs `r8`→`s8=` and is the hook that
  covers the "failed to parse" log call (`0x1406d17e2 call 0x1402bcc00`). But `HK_RDSTR` capped at 512
  lines and the `"%s - response was failure"` / `"not formatted correctly"` cache spam (PLAN §W1-d)
  exhausts 512 long before Start — MEASURED: capped at t=76.5, push at t=85.7 (run 8308). Fix:
  `if (ln > 512 && !contains_ci(s, "failed to parse")) return;` so a "failed to parse" line is never
  dropped. That is what produced the `s8=` message echo in run 8656.
- **REVERTED: hook-17 `arg0` capture.** First attempt read `ctx[-5]` (rbp) at site `0xf1934c` as the
  `%s`. It produced garbage (`arg0="`"` for messages whose real first `%s` is `"SetDataAsync"`), so
  rbp is NOT vararg1 at that site — the varargs are repackaged between `0x1402bcc00` and the encrypted
  log fn `0x140f192f0`. Removed. Use hook 13's `s8=` (which reads `r8` at `0x1402bcc00` directly and
  is correct) instead.

## 44e. The parse path, as far as static reading got (do NOT re-derive; do NOT rabbit-hole here again)

Flow for a received WS notification (all read from `gametext.bin`):

1. `WorldwidePollingService` fn `0x1406d1160..0x1406d204f` reads each WS frame into a buffer
   (`call [vtable+0x88]`), makes ONE list node per frame (list head `[rsp+0x30]`, node stride 0x30,
   the message std::string at node+0x10), logs `WebSocketConnection::ProcessMessages: message=%s`
   (`0x1406d1448 call 0x1402bcb30`), sends the ack `{"operation":%d,"ackCount":%d}` (`0x1406d14a0`),
   then parses each node via `0x1406d16cc call 0x1407a7620`. **The frame is NOT comma-split** — one
   frame = one message, so our trailing comma is part of the message text.
2. On parse failure it logs `"WebSocketConnection - failed to parse notification messages [%s]"`
   (`0x1406d17d4`, format string `0x143699000`) with `r8` = a std::string copied from a list node —
   MEASURED to be the raw message text, not a reason.
3. **Envelope reader `0x1407a7620..0x1407a7d2b`** (name-based, order-independent): reads exactly
   `result` (u64 via `0x14039c900`, range-checked `result+0x80000000 <= 0xffffffff`, stored as DWORD),
   `m_type` (string via `0x14039cc60`), `m_profileID` (u64 via `0x14039c900`) — confirmed by the three
   string xrefs. Then at `0x1407a7ac8` calls **dispatch `0x1407a7070`**; if it returns false the whole
   reader returns false.
4. **Dispatch `0x1407a7070..0x1407a7220`** walks a RUNTIME linked list at **`[0x144c9e3e0]`**
   (node = `{fn at +0, next at +8}`, 0x10 stride). For each node it calls
   `fn(rcx=out, rdx=reader, r8=&m_type_string)`; the first node that returns a non-null object wins.
   **If no node handles `m_type`, dispatch returns false.** `[0x144c9e3e0]` is at RVA `0x4c9e3e0`,
   PAST `.data` rawsize (`0x4256600`), so it is **zero-filled at boot and populated at runtime** — its
   contents were NOT verified. **Open question H1: is "MatchStartMessage" actually in this runtime
   registry?**
5. The static parser table `0x144116af0` (46 entries × 0x10, entry 9 = `0x1407b66f0`) is a FLAT ARRAY
   (`+8 == 0` for every entry), so it is **not** the runtime linked list. Entry 9 `0x1407b66f0` is a
   thunk → **factory `0x1407cdf10`**.
6. **Factory `0x1407cdf10..0x1407ce0ce` (MatchStartMessage):** checks `m_type` length `== 0x11` and
   `strcmp == "MatchStartMessage"` (`0x14369ee08`); allocs 0x2c8 (vtable `0x143676890`) + an 0x18
   wrapper (vtable `0x143675f20`); calls the **bond deserializer `0x142d705a5`** (`jmp [0x143198960]`,
   an import) as `0x142d705a5(reader, 0, desc1=0x144239d20, desc2=0x14423ecb0, 0)` to make a
   sub-reader; if non-null → **parser #9 `0x1407b6710`**; if null → alternate
   `0x142d705a5(reader,0,0x144239d20,desc3=0x144239ce8,0)` → **alternate parser `0x1407b73f0`**. Any
   failure → out=null → dispatch false. The descriptors are objects with vtable `0x14365d5f8` and a
   space-padded numeric string at +0x10 (`0x144239d20`="98208722206527", `0x14423ecb0`="100454990111953",
   `0x144239ce8`="89571542967596") — bond type metadata, NOT decoded.
7. **Parser #9 `0x1407b6710..0x1407b721f`** is name-based/order-independent over the six optional
   members. Each member reader was checked and is individually fine for our values:
   `matchStartDate` `0x14039c900` (bare u64 → strtoull, OK), `ownedAppIDs` `0x14057b600` (array reader,
   `[]` → empty → OK; same shape for `profileRaces` `0x1407d4300`, `equippedItems` `0x1403e3dc0`,
   `inProgressChallenges` `0x1407d4490`), and **`matchAdvertisement` `0x14056cce0`** — this reader
   matches 26 field names, ALL optional, and our emitted 21 fields are a subset; the identical object
   parses fine as the `/game/advertisement/update` reply's `updatedAvertisement`, so **the
   advertisement is proven-valid and is NOT the failure.**

**Net: the failure is in dispatch (H1: registry) or in the factory's bond step (H2: `0x142d705a5`
returns null / parser #9 returns false). It is NOT a member value we can see, and NOT the
advertisement.** The trailing comma is a live but unproven suspect: the game's OWN WS frames
(`{"operation":1,"ackCount":1}`) carry no trailing comma, and §s20's "`null,` parses, `null` does not"
rule was derived for the readSession HTTP long-poll format, a different transport — it may have been
misapplied to the WS push. It has never been tested against the game's WS parser.

## 44f. CLEAN vs ENCRYPTED — measured this session (decides what is hookable)

Cleanliness = on-disk `AoE2DE_s.exe` `.text` bytes identical to `gametext.bin` (the decrypted dump).
`.text` rva `0x1000`, rawsize `0x3195000`; gametext.bin offset = `rva - 0x1000`. Quick checker used:
read both, compare 64 bytes at the RVA.

- **CLEAN (hookable):** `0x1407db520` (hook 17 GLog target) — re-confirmed clean.
- **ENCRYPTED on disk (NOT hookable — read from gametext.bin only):** **`0x1407cdf10` (factory)**
  disk `77 f1 91 1d 4e a6 f8 17 …` vs gt `48 89 5c 24 08 48 89 6c 24 10 56 57 41 56 48 83`;
  **`0x1407b6710` (parser #9)** disk `e4 86 11 ef 44 c3 78 78 …` vs gt `48 89 5c 24 08 48 89 74 24 …`.
- **UNKNOWN cleanliness (check before hooking):** dispatch `0x1407a7070`, envelope `0x1407a7620`,
  the member readers `0x14039c900 / 0x14057b600 / 0x14056cce0 / 0x1407d4300 / 0x1403e3dc0 /
  0x1407d4490`, the bond/JSON helpers `0x14039a910 / 0x14039b340 / 0x14039b8e0 / 0x14039b550 /
  0x14039b7c0 / 0x14039bb50 / 0x14039b860 / 0x14039cc60`, and the polling fn `0x1406d1160`. The
  `0x14039xxxx` JSON primitives are the most likely to be clean.
- Still ENCRYPTED from §43 (never hookable): `0x140f19210`, `0x140f192f0`, `0x14101b4b0`, `0x14101bb50`,
  `0x140f16060`, `0x140f17060`, `0x140eeb930`, `0x140799300`, `0x141a44520`, `0x141a26fa0`,
  `0x1408fc0b0`, and the rest of the §43h list.

## 44g. Next session — MEASURE, in this order (each is one run; make it count)

**Step 0 (no run): cleanliness sweep.** Run the 44f checker over the UNKNOWN list. Mark every
hookable function in the parse path. This decides which measurement is even possible. Do this BEFORE
designing a hook.

**Step 1 — answer H1 (is MatchStartMessage registered?) with ONE run, no new hook target needed.**
The registry head `[0x144c9e3e0]` can be read from any CLEAN hook already installed. Cheapest: extend
`verbose_on()` (or hook 17's filtered path) with a ONE-SHOT dump — read `[0x144c9e3e0]`, walk
`{fn,next}` nodes, and log each node's `fn` address (cap ~64 nodes, SEH-guarded). Then check whether
`0x1407b66f0` (the MatchStartMessage thunk) or `0x1407cdf10` appears. Do this dump once, late enough
that rlink init has run (e.g. arm it on the first GLog after t=30 s, or on the updateState that arms
the push). If a clean dispatch/registry function exists, hooking it to log its boolean return is even
more direct.
- **If MatchStartMessage is NOT in the registry → H1 is the bug.** The game never registered a parser
  for it in this (LAN/offline-shim) state. Fix direction: find what populates `[0x144c9e3e0]`
  (registration runs at rlink init; xref the QWORD writers of `0x144c9e3e0`, ignoring the
  `0x1400974xx` dword-copy init block which is noise) and whether registration is gated on a mode we
  are not in.
- **If it IS registered → H2 (payload/bond).** Go to Step 2.

**Step 2 — H2: isolate the failing stage without hooking the encrypted factory/parser.** Two options,
pick by what Step 0 found clean:
- (a) If a member reader (`0x14057b600`, `0x14039c900`, `0x14056cce0`, …) or a bond helper
  (`0x14039a910` = parser #9's first structural gate, `0x14039b340` = read-member) is CLEAN, hook it
  caller-filtered to the parser-#9 range and log which member is reached / which returns false. That
  names the bad member directly.
- (b) Otherwise **empirical payload binary-search**, one rebuild+run per variant, observed via hook 17
  (`OnAdvertisementEvent/AET_MatchStartNotify result=…` fires = success) and hook 13 (`failed to
  parse` = still broken). All six members are optional, so: variant A = envelope + `matchAdvertisement`
  only (drop the 5 others); variant B = envelope only (parser #9 accepts an empty payload →
  `0x1407b674b` at-end → success, proving the envelope+dispatch+factory chain works and isolating the
  fault to a member); variant C = current frame **minus the trailing comma** (tests the §44e suspect).
  Order: C first (one char, cheap, and the game's own frames have no comma), then B, then A.

**Step 3 — once a variant parses:** `AET_MatchStartNotify` fires; confirm `result==0` and that the map
loads. If it fires but the map still does not load, follow case 7's roster build at `0x140eec3b3` and
the empty-roster path `0x140eec4a6` (§43f), and check `matchMembers` carries what the roster needs.
Then Priority 2 (AI actually play — `session+0xee0` holds the AI list, §40d) and Priority 3 (second
human over the tailnet, PLAN §W1-c/M2: peer must reach 27012/TCP and `relayIP` must become the tailnet IP).

## 44h. Do NOT (all still settled, plus new)

- Do NOT re-derive anything in 44e — it is measured/read and the parse path is mapped as far as static
  reading can usefully go. The remaining unknowns (registry contents, which stage fails) need RUNTIME
  measurement, not more disassembly.
- Do NOT hook `0x1407cdf10` or `0x1407b6710` — ENCRYPTED on disk (44f). Check cleanliness before
  proposing ANY new hook.
- Do NOT re-add the hook-17 rbp/`arg0` capture — rbp is not vararg1 there; it yields garbage (44d).
- Do NOT chase the `%s` in "failed to parse notification messages" for a field reason — it is the raw
  message echo (44b/44e).
- Do NOT retry `-VERBOSELOGGING`/`-LOGSYSTEMS` cmd-line syntaxes, chase `Setting mCancelCountdown`, the
  27212 TLS handshake_failure, `OnStartComplete`'s missing "forcing pollcomplete event", `Match
  Started` logged once, who writes -1 into `screen+0x1cf8`, `OnAdvertisementEvent/UNKNOWN %d`
  (cases 4/12 unhandled), or `ReceiveNetworkData`/`ProcessPackets` never firing (host-only lobby) —
  all settled in §43h.
- Do NOT re-open peerAdd/peerUpdate (§42), the matchState reply (§43g), build `lanrelay` (§42d relay is
  proven good), or remove the s38 bit-0x4 lobby-row suppression / hook 17 / `AOE2LAN_VERBOSE` / the
  `verbose_on()` sink null-guard.
- Do NOT believe "0 recv from 192.168.0.101:27012" in our log (that socket's read path is not
  instrumented). `ws_serve` logs frames only `if (frames <= 6)`, so missing `WS: frame` lines mean
  nothing.

## 44i. Traps recorded so nobody pays twice

- **A Windows certificate dialog appears on first connection to the shim** (the self-signed root is
  added to the user Root store then — log line `cert: user-Root deferred to first connection`). The
  operator MUST click **Yes/Install**. Clicking **No** → TLS verification fails → login aborts → the
  game exits at ~t=18 with `response was failure` / `LogoutAsync` / `failed to load offline profile
  info after logging out`. This looks like a code failure but is not. A healthy boot shows
  `TLS: handshake complete (server side)` repeatedly and
  `OnAccountEvent: Client is using WebSockets to receive updates from the server`. Windows seems to
  cache the trust after the first Yes (run 8656 had no dialog).
- **HK_RDSTR (hooks 4/5/13) caps at 512 lines and the cache spam exhausts it before Start.** Any
  rlink-error you need late in a run must bypass the cap (44d) or it is silently dropped.
- `ctx[-5]` is rbp, `ctx[-7]` is rsi, `ctx[14]` is r9, `ctx[15]` is r8, `ctx[16]` is rdx, `ctx[19]` is
  the return address (= call site + 5). At hook 17's site `0xf1934c`, r9=category and rsi=format, but
  rbp is NOT the message's first vararg (44d).
- `read_cstr` caps at its `maxn` (hook 13 uses 72 for s8/s9), so a captured string is truncated — fine
  for a prefix, useless for a 1750-B frame.
- Everything in §43i still holds: `.data` past rawsize (`0x4af600`) is zero-filled at boot (reading it
  from the file returns the NEXT section's bytes); MSVC folds short strings into immediates and is not
  link-reproducible (re-run gates on the final build, re-md5sum both copies after `build.cmd`'s copy);
  close the game before building (Windows locks `dbghelp.dll`, the copy fails silently); the launcher
  returns the cmd.exe PID not the game's (take the newest `logs/lanhook-<pid>.log`); a launch that dies
  under ~5 s with a clean boot log is a transient — relaunch before debugging.

## 44j. Files added / changed this session

| file | what changed |
|---|---|
| `hookcore.c` | HK_RDSTR cap-bypass: `if (ln > 512 && !contains_ci(s, "failed to parse")) return;` (the hook-17 `arg0`/rbp experiment was added then reverted) |
| `dbghelp.dll` (both copies) | rebuilt → `7a66dd36fe5dc3ac9e7c32aa0bd7c398`; backups `.prev-s44-arg0`, `.prev-s44-cap` |
| `work/f_pollfail.txt` | disasm of `0x1406d1160` (WorldwidePollingService, the parse+error fn) |
| `work/f_notif_reader.txt` | disasm of `0x1407a7620` (envelope reader) |
| `work/f_dispatch.txt` | disasm of `0x1407a7070` (registry dispatch) |
| `work/f_msfactory.txt` | disasm of `0x1407cdf10` (MatchStartMessage factory) |
| `work/f_advreader.txt` | disasm of `0x14056cce0` (matchAdvertisement reader) |
| `work/disasm-dll-s44.txt`, `work/disasm-dll-s44b.txt` | dumpbin of the two s44 DLL builds |

Unchanged and still armed: hooks 14/15/16/17, `AOE2LAN_AIGATE=1`, `AOE2LAN_VERBOSE=1`,
`lobby_keepgate`, the s38 bit-0x4 suppression, the §43 `MatchStartMessage` push, and every §42/§43
conclusion. `PLAY-stage8-VERBOSE.cmd` is still the run config.
