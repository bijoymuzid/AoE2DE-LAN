# Prompt for the next Windows session (paste this into a new chat)

Continue AoE2LAN (AoE2:DE LAN mod). Read `notes/m1-session48.md` in full before touching
anything; it supersedes `notes/m1-session47.md`. Then read `PLAN.md` §0–§3, §6.1, §6.2, §6.4
and §17.

Say everything in plain English: short sentences, no jargon, no code dumps, no leaps. If
something is unknown, say it is unknown.

WORKING RULE — obey it every turn: **MEASURE FIRST.** Do not burn time or tokens on long
static reverse-engineering when one instrumented run answers the question. Go straight to a
runtime measurement, and make each game run capture the maximum information so runs stay
few. Before proposing ANY new hook, check the target is CLEAN on disk (on-disk `.text` bytes
== `gametext.bin`, compared over the **pdata function bounds**, not a fixed window) — an
encrypted function cannot be HOOKED. But read this carefully, it cost four sessions:
"encrypted" means cannot-hook, NOT cannot-read. `dev/lanhook/gametext.bin` is a dump of the
**DECRYPTED** `.text`, so every function on the §45a ENCRYPTED list is fully disassemblable
offline. Read the dump; only the hooking is forbidden. Also: if the hard way genuinely raises
the chance of the thing working, take the hard way — do not hold back to stay minimal
(operator, session 46).

Working dir: `D:\Age of Empires II Definitive Edition`. Repo: `D:\aoe2lan-repo` →
https://github.com/bijoymuzid/AoE2DE-LAN. `git pull` first. At the end run
`/c/WINDOWS/system32/cmd.exe //c 'D:\aoe2lan-repo\sync.cmd' "session 49 - <one line, no
parentheses, no colon after NN>"` (in this shell `cmd /c` must be written as
`/c/WINDOWS/system32/cmd.exe //c`, and the `sync.cmd` path must be in single quotes or bash
eats the backslashes). Two "The system cannot find the path specified" lines from `sync.cmd`
are pre-existing noise; it still commits and pushes. `sync.cmd` now also copies
`dev/lanhook/work/*.json` (added s48).

## THE JOB, in priority order. Nothing else outranks these.

**Priority 1 (a hosted match loads and runs) and Priority 2 (AI in that match) are DONE —
measured, shipped, gated. Do not reopen them.** The front of the queue is now **Priority 3:
a second human joining over the tailnet** (PLAN §W1-c / M2). §48j has all the groundwork
already measured; start there, not from zero.

0. **BLOCKER, operator action, not code: Tailscale is logged out.** `BackendState: NoState`,
   `tailscale ip` → no address, the adapter has only a link-local IPv6. Ask the operator to
   log Tailscale in and confirm `tailscale ip` returns a `100.x` address **before** any
   two-machine measurement. Do not write code against an IP you cannot see.
1. **`relayIP`** — one hardcoded literal at `loginsrv.c:1551` inside `build_host_reply()`,
   currently `"127.0.0.1"`. Make it this machine's tailnet IP. Smallest source: an
   `AOE2LAN_*` env var read once at startup, with `127.0.0.1` as the fallback so single-machine
   hosting keeps working. Measure: host a lobby, read the `HTTP RESP BODY` for
   `/game/advertisement/host`, confirm the `100.x` address, and confirm the local game still
   connects to its own relay through it.
2. **`/game/advertisement/join`** — there is no handler; it falls into the catch-all empty
   success. Big head start: the comment at `loginsrv.c:1531` records that the *host* call
   parses its answer with the **join-result DTO** (parser `0x140572540`), so
   `build_host_reply()` already emits the right shape. Reuse it; do not write a second builder.
   The member element parser is `0x14056eb40`, keys already dumped (§48c).
3. **`matchMembers` must carry the joiner.** `emit_advertisement()` hardcodes ONE member (the
   host) — that is correct for co-op-vs-AI (§48e) and wrong the moment a human joins. Test the
   2-member shape with `work/s48b.py` against a live lobby **before** committing to it.
4. **Discovery — the biggest piece.** The four browse endpoints answer only from this shim's
   own `g_AdvBody`, so a second machine never sees the host's lobby. `lanhub` exists, is Rust,
   and passes its walk (`lanhub/test_walk.py`, 11/11: HELLO/HOST/cross-instance FIND via
   gossip/JOIN remote) on control `127.0.0.1:47100`, gossip `:47101`. Wire the shim's browse
   endpoints to lanhub `FIND`. **Lazy alternative for a first two-machine proof only:** feed
   the joiner's shim the host's advertisement blob out of a file or env var and skip lanhub —
   name it as a shortcut in the reply and do not ship it as the design.
5. **The relay itself needs no work.** Stock `BattleServer.exe` is already proven
   cross-tailnet by W2 (repo commit `a890ab3`, `GAMEDATA` funnelled, derp ~85 ms). Do not
   build `lanrelay`.

Steps 1–3 are shim-side and testable on ONE machine. Do them and gate them before touching 4.
Change one thing at a time and measure it; do not bundle `relayIP` with `matchMembers`.

### Also worth one cheap run (warm-up, answers an open question)

**Does 7 AI work?** The operator asked. Nothing we emit depends on the AI count — AI are
host-local simulation, they never enter `slotinfo` (slots 1–7 stay empty even with 3 AI) and
never enter `matchMembers`; `maxPlayerCount` is 8 and the blob has 8 slots, so 1 human + 7 AI
is inside the game's own limit. **But it is untested**, and there is an unexplained number: the
operator placed 3 AI and every `HIT AISlotPick` reports `nAI=0x2 val=0x2 kind=2`, in both s48
runs, before and after Start. One run with 7 AI settles both: host, 7 AI, Start, then read
`nAI` and ask the operator how many AI are visibly in the match. If `nAI` tracks the count,
the s48 reading was a stale or different counter and there is nothing to fix.

## SOLVED IN SESSION 48 — do not redo any of it

- **A hosted match loads and runs.** The one missing thing was the advertisement key **`id`**.
  Without it the frame parses, `MSThunk` fires, `AET_MatchStartNotify` logs — and the lobby
  never leaves. No error line at all. With it the same frame reaches `Sending final
  pregamehoststate packet.` → `SendSyncPacketRawMemCopy` → `AISlotPick nAI=0x2` → scenario
  load, 63 ms after the push. Measured A/B on one live lobby, 257 s apart, one key different,
  quiet window verified empty. `emit_advertisement()` now opens with `"id":<sessionID>`;
  `srvclient.py` asserts it.
- **§47's "advertisement key order matters" is WRONG.** Reader `0x14056cce0` and the
  `matchMembers` element reader `0x14056eb40` are **name cascades that restart at the first
  field for every key**: each block tries the current key against its own name, and on mismatch
  falls to the next block **without consuming anything**; the tail calls `NextKey` and jumps
  back to the top. Any permutation parses; unknown keys are skipped. **Presence matters, order
  does not.** The s47 reorder is harmless and stays. Do not spend a session on order again.
- **`matchMembers` element shape was never broken.** Keys in probe order: `sessionID,
  profileID, ranking, statGroupID, raceID, teamID, url`; element size `0x48`. Our
  `profileID`-first order is fine. §47h's suspicion is closed.
- **AI do not need to be in the advertisement.** §46f/§47h assumed the empty `slotinfo` was
  Priority 2's blocker. Re-measured: `slotinfo` still has slots 1–7 empty (`pid=-1
  station=-1 isReady=0`) and the AI play anyway. Do not "fix" `slotinfo` or add AI to
  `matchMembers` for co-op.
- **A live lobby is a reusable test bench.** The game keeps its rlink websocket **armed after
  Start** (`livepush.py ping` → `PONG armed=1` 257 s into a stalled lobby). One run supports
  unlimited A/B pushes against real lobby state at ~4 s each. This is what found `id`.

## THE TOOLS

`AOE2LAN_LIVE=1` (already in `PLAY-stage8-VERBOSE.cmd`) opens a plain-TCP control channel on
`127.0.0.1:47199` inside the game process.

    livepush.py ping                     -> "PONG armed=1" means a game websocket is live
    livepush.py get [n]                  -> the shim's own built payload n (needs a hosted lobby)
    livepush.py push '<json>' [opcode]   -> push one payload, returns "sent=1 parsefail=N thunkhits=M"
    livepush.py s47                      -> the batch that proved the positional-array envelope
    livepush.py selftest                 -> offline check of the s47 payload shapes
    livepush.py sweep / bisect / types   -> CLOSED, §46e evidence trail only, do NOT re-run

    s48.py                               -> real variant-0 frame + 4-member roster + {} control
    s48b.py <label> '<json>'             -> THE A/B TOOL: override any matchAdvertisement key
    s48b.py <label> --body '<json>'        in the captured real frame and push it live
    keys.py <va> [<va>...]               -> JSON key names a bond reader/writer probes, in order

**Playbook for the next blocker:** host a lobby, press Start, let it stall or reach the state
you want, then `livepush.py get 0 > work/v0-real.json` and A/B with `s48b.py`. Only relaunch
when the lobby state itself is the variable. `work/v0-real.json` is committed, but it holds
run 15416's sessionID — re-capture it for a new lobby.

`parsefail` is NOT the only verdict any more. A frame can parse and still do nothing. The line
that proves a match really started is **`TComm_Provider_RL::SendSyncPacketRawMemCopy`**.

## THE PARSE CHAIN (all readable in gametext.bin; §47b has the full version)

`WebSocketConnection::Process` `0x1406d1160..0x1406d204f` → envelope reader `0x1407a7620` →
dispatch `0x1407a7070` over the 46-node registry at RVA `0x4c9e3e0` → node `0x24` = MSThunk
`0x1407b66f0` → factory `0x1407cdf10` (memcmp's the exact 17 chars `"MatchStartMessage"`,
allocates `0x2c8`, vtable `0x143676890`) → body parser `0x1407b6710`, returns NULL if the body
parse fails. Fallback body parser `0x1407b73f0`. Body writer `0x1407b7220`.

**The WS notification frame is a POSITIONAL ARRAY**, never an object, never `{"messages":[…]}`:

    [ <result:int>, "<m_type:string>", <m_profileID:int64>, { <body> } ]

Body, six optional members in reader/writer order: `ownedAppIDs` +0x08 (`0x14057b600`),
`profileRaces` +0x20 (`0x1407d4300`), `matchStartDate` +0x38 int64 (`0x14039c900`),
`equippedItems` +0x40 (`0x1403e3dc0`), `matchAdvertisement` +0x58 (`0x14056cce0`),
`inProgressChallenges` +0x2b0 (`0x1407d4490`). `{}` alone measures `parsefail=0`.

Advertisement reader `0x14056cce0` / writer `0x14056dda0`, 27 keys in order: `id, steamLobbyID,
goodOldGamesLobbyID, psnPlayerSessionID, psnMatchId, xboxSessionID, hostProfileID, matchState,
description, filteredDescription, visible, mapName, options, isPassworded, maxPlayerCount,
encodedSlots, matchTypeID, matchMembers, observerNum, observerMax, isobservable, observerDelay,
isObserverPassworded, service, matchStartTime, matchRegion, matchRegionLocalized`. We emit 22
(`id` + 21); the five we skip are all foreign-platform lobby ids.

Host/join result DTO: parser `0x140572540`, builder `0x14032f5e0`, members in parser order
`resultCode, gatheringID, relayAuthToken, relayIP, relayPortRaw/WebSockets/OutOfBandSocket
(WORD), relayRegion, yourMatchMembers[], steamLobbyID…, filteredDescription`. Member element
parser `0x14056eb40`. The caller requires `resultCode == 0` AND a non-empty member vector
(DTO+0x78/+0x80), then copies `gatheringID` (DTO+8) into the service as the session id.

Tokenizer helpers: `0x14039b7c0` SkipWhitespace, `0x14039bb50` PeekChar, `0x14039b860`
SkipComma, `0x14039b8e0` IsNull, `0x14039a910` BeginContainer, `0x14039b340` NextKey,
`0x14039b5a0` ScanToken, `0x14039b550` consume-N, `0x14039c900` ReadInt64, `0x14039cc60`
ReadString. Browse-list reply parser `0x140571ae0` (`result`, `advertisements`, `playerRatings`).

## GATES before any run (all passed at the end of session 48 — re-run them all)

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688`
- `dbghelp.dll` MD5 **`fa9330748b0fe297675f44e2828e738d`**, identical in the game dir AND
  `dev/lanhook/`. If you rebuild: take a `.prev-*` backup of BOTH copies first, then re-run
  every gate. (`.prev-s48-before` = `cc68c98ec43e6fcb38a0aa5c6906fb16`, the s47 build;
  `.prev-s47-before` = `21fb2d236ad342ac9647cd7bbdc97fef`, s46.)
- `hooktest.exe`: `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`, `swapped 68 of 68`
- `AOE2LAN_LIVE=1 srvtest.exe 90` + `C:/Python314/python.exe -X utf8 srvclient.py` → **PASS**,
  incl. `update reply: result=0, advertisement keys=22`, `updateState reply: matchState=1`,
  `MatchStartMessage push: 774B`, `ladder variant1 empty-body: 46B`,
  `ladder variant2 advert-only: 666B`, `ladder terminated after variant2`; then
  `work/livetest.py` → **PASS** (`GETVARIANT 1` = 46 B, `GETVARIANT 0` = 774 B)
- `work/verifydll.py` → **19** HOOKDEF entries, `MSThunk va=0x1407b66f0 … kind=0`,
  `GLog va=0x1407db520 … kind=7`
- verify any rebuilt DLL with `verifydll.py` + `dumpbin -DISASM`, never a byte grep;
  `dumpbin -IMPORTS` must still show **KERNEL32.dll only**. dumpbin lives at
  `"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"`
- build with `dev/lanhook/build.cmd` (it stages the DLL into the game dir itself); warnings
  must be the pre-existing C4090 five only, now at loginsrv.c **690/692/694/1928/1959**

## To launch

FIRST: confirm `srvtest.exe` is not running (`tasklist | grep -i srvtest`) and that
`127.0.0.1:443` has **no LISTENING** socket (`netstat -ano | grep "127.0.0.1:443" | grep
LISTENING`) — `TIME_WAIT` entries are harmless. See the trap below. Then kill any leftover
`AoE2DE_s.exe` and `BattleServer.exe` (the game holds 443 and the next launch silently fails to
bind without it). Then:

    powershell -NoProfile -ExecutionPolicy Bypass -File
    "dev\lanhook\work\launch-detached.ps1" -cmdFile PLAY-stage8-VERBOSE.cmd

Wait ~45 s, take the newest `logs/lanhook-<pid>.log` (the launcher returns the cmd.exe PID, not
the game's). No dialog appears and nothing needs clicking — the certificate consent dialog is
found and auto-clicked by the DLL in under 100 ms. Healthy boot = repeated `TLS: handshake
complete (server side)` + `OnAccountEvent: Client is using WebSockets` + `cert: user-Root
registered via API (consent dialog auto-clicked)` + `VERBOSE: log level byte [0x144356c66] 0 -> 2`.

Then, for a Priority 1/2 regression check: Multiplayer → Host Game → AI → Start. Expected
within ~70 ms of `WS PUSH MatchStartMessage`: `AET_MatchStartNotify`, `Sending final
pregamehoststate packet.`, `SendSyncPacketRawMemCopy`, `HIT AISlotPick … nAI=0x…`, then
`MSLADDER PARSED - no failure logged, ladder stops`. The process grows to ~3 GB when the map
loads.

## TRAPS (each of these cost a run or a session)

- **`srvtest.exe` also binds `127.0.0.1:443`** and `loginsrv.c` sets `SO_REUSEADDR` before
  bind. On Windows that lets the game "bind" 443 while srvtest still owns it, so the game talks
  to srvtest and the game's own log shows ZERO handshakes. Always wait srvtest out.
- **`WebSocketConnection::ProcessMessages: message=%s` prints the exact bytes we pushed** (hook
  4 truncates to 70 chars, enough to see the shape). READ THAT LINE before believing any
  payload verdict. A Python helper once returned `(key, value)` tuples and `json.dumps`
  rendered them as arrays — the log showed it instantly. `livepush.py selftest` guards it.
- **`parsefail=0` does not mean success.** It means the frame parsed. `id` was missing for a
  whole session while every verdict read clean. Look for `SendSyncPacketRawMemCopy`.
- **Hook 17 dedupes by format string**, so a running match logs each network line once and then
  goes quiet. Silence after a successful start is normal, not a stall.

## Do NOT

- Do NOT reopen Priority 1 or 2. A hosted match loads and runs with AI; it is gated.
- Do NOT send the notification as a JSON object, and do NOT wrap it in `{"messages":[…]}` on the
  websocket. Both are measured rejects. `messages` is long-poll only. Do NOT pursue forcing long
  polling (§46h route 1) — the WS format is known.
- Do NOT spend time on advertisement or `matchMembers` **key order** (§48c). Presence matters,
  order does not.
- Do NOT remove `"id"` from `emit_advertisement`, and do not change its value away from the
  sessionID without a measurement. `srvclient.py` asserts it.
- Do NOT add AI to `slotinfo` or `matchMembers` to "fix" Priority 2 (§48e measures they already
  work). Answer the `nAI=0x2` vs 3-AI question first.
- Do NOT build `lanrelay`. Stock `BattleServer.exe` is proven cross-tailnet (§48j).
- Do NOT re-run `livepush.py sweep`/`bisect`/`types`, and do NOT re-test any §46e shape.
- Do NOT treat "on the §45a ENCRYPTED list" as "cannot be read" — see the working rule.
- Do NOT hook anything on the §45a ENCRYPTED list (dispatch `0x1407a7070`, envelope reader
  `0x1407a7620`, factory `0x1407cdf10`, body parser `0x1407b6710`, all six member readers, the
  `0x14039xxxx` helpers, polling fn `0x1406d1160`). `MSThunk 0x1407b66f0` and `GLog
  0x1407db520` are CLEAN and stay hooked (ids 18 and 17).
- Do NOT change the s45 ladder's stop-on-no-failure rule or add a 4th variant. The three
  variants are a real fallback: 0 = all six body members with the real advertisement,
  1 = empty body `{}` (measured `parsefail=0`), 2 = `matchAdvertisement` only.
- Do NOT re-run a cleanliness check with a fixed byte window — use the pdata bounds (§45a).
- Do NOT re-derive the registry node layout (`r14=[0x144c9e3e0]`, `fn=[r14]`, `next=[r14+8]`).
- Do NOT delete the `srvtest.c` 1 Hz `g_ParseFail` bump (the offline ladder needs it to
  escalate through all three variants), and do NOT let `root_add_silent()` skip its
  `root_present()` re-check.
- Do NOT initialise a `BUF` partially — it is `{char *p; size_t len, cap; int oom;}` and a wild
  `p` crashes the shim thread and takes the whole process with it. Always `BUF b = {0};`
- Do NOT rebuild without a `.prev-*` backup of both `dbghelp.dll` copies first.
- Do NOT edit W2's files (`lanhub/**`, `linux/**`, `notes/linux-*.md`) — §17.1. `PLAN.md` and
  `README.md` are shared: append only, never rewrite the other worker's section.
- Do NOT re-open the certificate dialog problem, `root_add_silent()`'s blob format, §45e, the
  t=1.2 s exit (§46a), or anything in §45g / §44h / §43h.

Method rules, traps, the encrypted-address list, fast tricks and tooling (`dz.py`, `fn.py`,
`cx.py`, `xr.py`, `work/keys.py`, `work/rrx.py`, `work/clean_s45.py`, `work/s48.py`,
`work/s48b.py`, `srvclient.py`, `livepush.py`, `livetest.py`, `dlgprobe.c`) are in §48, §47,
§46, §45, §44 and `notes/m1-session43.md` — all still in force.
