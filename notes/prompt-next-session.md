# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Read `notes/m1-session46.md` in full before touching
anything; it supersedes `notes/m1-session45.md`. Then read `PLAN.md` §0–§2, §6.1, §6.2,
§6.4 and §17.

Say everything in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

WORKING RULE — obey it every turn: **MEASURE FIRST.** Do not burn time or tokens on long
static reverse-engineering when one instrumented run answers the question. Go straight to a
runtime measurement, and make each game run capture the maximum information so runs stay
few. Before proposing ANY new hook, check the target is CLEAN on disk (on-disk `.text`
bytes == `gametext.bin`, compared over the **pdata function bounds**, not a fixed window) —
an encrypted function cannot be hooked. Also: if the hard way genuinely raises the chance of
the thing working, take the hard way — do not hold back to stay minimal (operator, session 46).

Working dir: `D:\Age of Empires II Definitive Edition`. Repo: `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first. At the end run
`/c/WINDOWS/system32/cmd.exe //c 'D:\aoe2lan-repo\sync.cmd' "session 47 - <one line, no
parentheses, no colon after NN>"` (in this shell `cmd /c` must be written as
`/c/WINDOWS/system32/cmd.exe //c`, and the `sync.cmd` path must be in single quotes or bash
eats the backslashes).

## THE JOB, in priority order. Nothing else outranks these.

1. **Make a hosted match actually load and run.** Pressing Start is accepted and the game
   logs `StartLaunchGame ok` + `Match Started`, but the screen never leaves the lobby. The
   single known blocker is that our fake server's **MatchStartMessage websocket push does not
   parse** (§46e).
2. **Then confirm AI are in that match and actually play.** Separately broken, and it is the
   GAME that drops them: its own `slotinfo` has 8 slots with slots 1–7 empty (§46f).
3. Only after that: a second human joining over the tailnet (PLAN §W1-c / M2). Note the host
   reply still says `"relayIP":"127.0.0.1"`, which priority 3 will have to change.

Priorities 1 and 2 are independent — a match with only the human in it should still load, so
do not couple them.

## SOLVED IN SESSION 46 — do not redo any of it

- **The Windows certificate consent dialog is FIXED and fully automatic.** The DLL finds the
  `#32770` "Security Warning" window (owned by our own process, control **6** = "&Yes",
  **7** = "&No") and posts `BM_CLICK` to control 6. Measured: clicked in under 100 ms, both
  offline (`dlgprobe.exe`, `srvtest`, `work/livetest.py`) and in game (`t=0.188 cert:
  consent dialog found, posted BM_CLICK to IDYES`). **There is no dialog to click any more —
  do not wait for one, do not tell the operator to click anything.** §45e options (a)/(b)/(c)
  and `root_add_silent()`'s blob format are all dead ends and are now irrelevant.
- **The t≈1.2 s exit was NOT a tamper response.** `RootRegThread` runs at BOOT (`t=0.125`)
  and the prompting add BLOCKS on the dialog; nobody clicked, so the run died. §45d's
  "~5.6 s exit ⇒ drop `,18`" row never applied. Hook 18 is fine and stays.
- **H1 is dead — MatchStartMessage IS registered.** `MSREG nodes=46` and
  `MSREG[0x24] fn=0x7ff6f26c66f0` = VA `0x1407b66f0` (game base `0x7ff6f1f10000`).
  `HIT MSThunk ret` = VA `0x1407a70ce` = the `call rax` in dispatch `0x1407a7070`.
  Do NOT xref the QWORD writers of RVA `0x4c9e3e0`. Also: **46 registry nodes == 46 RLink
  `*Message` RTTI types** (full list in `work/livepush.py: RLINK_TYPES`).
- **`HIT MSThunk` is NOT a type-match signal** (corrects §45b). Measured: it fires for ANY
  top-level JSON object, including `m_type:"SessionStatusMessage"` and `{"messages":[…]}`,
  but not for a top-level array or an integer `m_type`. **Only `parsefail` is a verdict.**

## THE TOOL — use this, never re-run the game to test a payload

`AOE2LAN_LIVE=1` (already in `PLAY-stage8-VERBOSE.cmd`) opens a plain-TCP control channel on
**127.0.0.1:47199** inside the game process. Driver: `dev/lanhook/work/livepush.py`.

| command | what it does |
|---|---|
| `livepush.py ping` | `PONG armed=1` means a game websocket is live |
| `livepush.py get [n]` | the shim's own built MatchStartMessage payload n (needs a hosted lobby) |
| `livepush.py push '<json>' [opcode]` | push one payload, returns `sent=1 parsefail=N thunkhits=M` |
| `livepush.py sweep` / `bisect` / `types` | the three hypothesis batches from §46e |

**One game run to the lobby answers unlimited payload questions at ~2.6 s each.** `parsefail=0`
means it parsed — that is the win condition. Payloads are sent by the `ws_serve` loop that owns
the connection, never by the control thread, so no lock and no frame interleaving.

## WHERE SESSION 46 LEFT IT — the one open question

**~110 payload shapes were tested live in a real hosted lobby and EVERY ONE was rejected**
(§46e has the full list: all 46 type names, `operation=0..24`, array/wrapper/key-name shapes,
positional arrays, member add-one/remove-one/reorder, advert-as-array). **Conclusion: the
outer container is wrong, not the members. No MatchStartMessage member permutation can ever
fix this — that whole space is closed.**

Shape-guessing is exhausted. The next step must produce **ground truth**, not another guess.
Two routes, do them in this order:

1. **Force long polling and watch** (no rebuild needed). `RL_USE_WEBSOCKET_PERCENT`
   (exe `0x3698008`) picks WS vs long poll; it can be set as an env var in the PLAY cmd, or
   pushed through the login reply's `clientSettings` array (which already carries
   `RL_KEEPALIVE`/`RL_MISSPOLL`/`RL_DISCONNECT`). The long-poll path logs
   `LongPoller::Process: response good, processing=%lld: %s` and
   `…mismatched session IDs; lastPollSessionID=%s m_sessionToken=%s` — plain JSON over HTTP,
   in the dialect our other replies already parse in. Read **which URL the poller hits** (it is
   NOT among the 150 `/game/...` strings in the exe, so it is built at runtime) and what the
   response must look like.
2. **Ground truth from a reference implementation.** `github.com/luskaner/ageLANServer`,
   `server/internal/routes/wss/wss.go` — its `parseMessage` confirms inbound
   `operation`/`sessionToken`. The **outbound** envelope struct lives in the `common` package,
   which was not located before session 46 ran out.
   **DECISION PENDING — ask the operator once at the start of the session:** they forbade
   *using* ageLANServer as the mod (session 11, "make your own mod"), and we are building our
   own, but reading it purely for the wire format is their call. `loginsrv.c`'s header already
   credits it ("field order proven by the ageLANServer public source"). Do not rely on it
   without an explicit yes.

Useful static facts already gathered (§46e): only two `{"operation"` format strings exist and
both are client→server (`{"clientLibVersion":%d,"operation":%d,"sessionToken":"%s"}` @
`0x3697ab8`, `{"operation":%d,"ackCount":%d}` @ `0x3697c48`); the game sends
`{"clientLibVersion":194,"operation":0,"sessionToken":"1194178595"}` then
`{"operation":1,"ackCount":1}`; only five `m_` strings exist in the whole exe
(`m_rlinkLibVersion`, `m_resultCodes`, `m_scope`, `m_type`, `m_profileID`) and `m_type` sits in
the **PrivacyScope** region, so `m_type` as the notification discriminator is an unverified s43
assumption; MatchStartMessage's own fields per the bond string table @ `0x369d9d7..0x369da08`
are **{inProgressChallenges, matchAdvertisement, profileRaces}**.

**One risk to keep in view:** the exe has `SignatureManager.cpp` and `Error decrypting
signature, %lu`. Session 46 checked what it covers — inventory items, profile stats,
leaderboard match history (anti-cheat on numbers), **not** the match flow. If a notification
ever turns out to be signature-verified we cannot forge it. Not currently believed to block us.

## GATES before any run (all passed at the end of session 46 — re-run them all)

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688`
- `dbghelp.dll` MD5 **`21fb2d236ad342ac9647cd7bbdc97fef`**, identical in the game dir AND
  `dev/lanhook/`. If you rebuild: take a `.prev-*` backup of BOTH copies first, then re-run
  every gate.
- `hooktest.exe`: `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`, `swapped 68 of 68`
- `AOE2LAN_LIVE=1 srvtest.exe 90` + `C:/Python314/python.exe -X utf8 srvclient.py` → **PASS**
  incl. `updateState reply: matchState=1`, `MatchStartMessage push: 788B`, both ladder variant
  lines, `ladder terminated after variant2`; then `work/livetest.py` → **PASS**
- `work/verifydll.py` → **19** HOOKDEF entries, `MSThunk va=0x1407b66f0 … kind=0`,
  `GLog va=0x1407db520 … kind=7`
- verify any rebuilt DLL with `verifydll.py` + `dumpbin -DISASM` (path in §43/§44c), **never a
  byte grep**; `dumpbin -IMPORTS` must still show **KERNEL32.dll only**
- build warnings must be the pre-existing C4090 five only, now at loginsrv.c
  **690/692/694/1905/1936**

## To launch

`powershell -NoProfile -ExecutionPolicy Bypass -File
"dev\lanhook\work\launch-detached.ps1" -cmdFile PLAY-stage8-VERBOSE.cmd`, wait ~27 s, take the
**newest** `logs/lanhook-<pid>.log` (the launcher returns the cmd.exe PID, not the game's).
**Kill any leftover `AoE2DE_s.exe` first — it holds port 443** (pid 12008 was still running at
the end of session 46). No dialog will appear and nothing needs clicking. Healthy boot =
repeated `TLS: handshake complete (server side)` + `OnAccountEvent: Client is using
WebSockets` + `cert: user-Root registered via API (consent dialog auto-clicked)`.

Then: Multiplayer → Host Game → 3 AI. **Stop there — do NOT press Start.** Confirm
`livepush.py ping` says `armed=1` and `livepush.py get 0` returns the real payload, and iterate
live. Only press Start once a payload parses (`parsefail=0`).

## Do NOT

- Do NOT re-test any payload shape already listed in §46e — they are measured rejects.
- Do NOT try more MatchStartMessage **member** permutations (§46e closed that space).
- Do NOT treat `HIT MSThunk` as a type match (§46d).
- Do NOT re-open the certificate dialog problem, `root_add_silent()`'s blob format, or §45e.
- Do NOT chase the t=1.2 s exit as a tamper response (§46a).
- Do NOT hook anything on the §45a ENCRYPTED list (dispatch `0x1407a7070`, envelope reader
  `0x1407a7620`, factory `0x1407cdf10`, parser #9 `0x1407b6710`, all six member readers, the
  `0x14039xxxx` helpers, polling fn `0x1406d1160`).
- Do NOT re-run a cleanliness check with a fixed byte window — use the pdata bounds (§45a).
- Do NOT re-derive the registry node layout (`r14=[0x144c9e3e0]`, `fn=[r14]`, `next=[r14+8]`).
- Do NOT change the s45 ladder's stop-on-no-failure rule, add a 4th variant, or re-order the
  three, without a measurement that says to.
- Do NOT delete the `srvtest.c` 1 Hz `g_ParseFail` bump (the offline ladder stops after
  variant 0 without it), and do NOT let `root_add_silent()` skip its `root_present()` re-check.
- Do NOT initialise a `BUF` partially — it is `{char *p; size_t len, cap; int oom;}` and a
  wild `p` crashes the shim thread and takes the whole process with it. Always `BUF b = {0};`.
- Do NOT rebuild without a `.prev-*` backup of both `dbghelp.dll` copies first.
- Do NOT re-derive §44e, and do NOT re-open anything in §45g / §44h / §43h.

Method rules, traps, the encrypted-address list, fast tricks and tooling (`dz.py`, `fn.py`,
`cx.py`, `work/rrx.py`, `work/clean_s45.py`, `srvclient.py`, `livepush.py`, `livetest.py`,
`dlgprobe.c`) are in §46, §45, §44 and `notes/m1-session43.md` — all still in force.
