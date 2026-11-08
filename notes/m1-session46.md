# Session 46 — cert dialog auto-clicked (solved), live payload channel built, MatchStartMessage envelope proven wrong after 110+ live shapes

Supersedes `notes/m1-session45.md`. All addresses are VAs unless written `RVA`.
Two game runs this session (`logs/lanhook-12816.log` = died at t=1.2 s,
`logs/lanhook-5848.log` = full host attempt, `logs/lanhook-12008.log` = live-channel
session, still in the lobby at the end). Game exe untouched
(`affb19f03ca96965abf9e56775cab688`).

## 46a. The certificate dialog is SOLVED, and it was also the cause of the t=1.2 s death

**Measured with `dlgprobe.c` (new, host tool, offline, no game):** the consent dialog
crypt32 shows for a user-Root add is

- window class `#32770`, title `Security Warning`
- **owned by our own process**, on the thread that called
  `CertAddCertificateContextToStore`
- standard control IDs: **6 = "&Yes"**, **7 = "&No"**, 65535 = the static text
- one `PostMessageW(yesBtn, BM_CLICK, 0, 0)` dismissed it in **under 100 ms** and the
  add returned 1 with the cert in the store

**Shipped:** `root_add_prompting()` in loginsrv.c starts `DlgClickThread` immediately
before the prompting add. The watcher polls `EnumThreadWindows(g_rootTid)` every 100 ms
(and every 5th poll `EnumWindows` filtered to our own pid, in case crypt32 uses a helper
thread), and clicks control 6 on any visible window that has **both** control 6 and
control 7. It only runs while `g_rootAddLive` is set, i.e. only during our own root add.
`RootRegThread` also got an early-out: `root_present() == 1` → no add at all.

user32 is loaded with `LoadLibraryExW` + `GetProcAddress`; the DLL's import table is
still **KERNEL32.dll only** (verified with `dumpbin -IMPORTS`).

**Measured in game (run 12008):** `t=0.078 live: … listening`, `t=0.188 cert: consent
dialog found, posted BM_CLICK to IDYES` → `prompting add returned=1` →
`user-Root registered via API (consent dialog auto-clicked)`. **No human, no dialog
visible.** Same in offline `srvtest` and in `work/livetest.py`.

**This also explains the run-12816 death at t=1.219 s**, which looked like a tamper
response and was not: `RootRegThread` runs at **BOOT** (`t=0.125`), the prompting add
**blocks** on the dialog, and nobody clicked. There was no crash event in the Windows
Application log and no exception in our log. §45d's "~5.6 s exit ⇒ drop ,18" row never
applied — hook 18 is fine and stays.

`root_add_silent()` still fails (`CertSaveStore` yields 0 bytes) and is now irrelevant:
the auto-click path is what works. §45e options (a)/(b)/(c) are no longer needed.
`certsave.c` was moved from `work/` to `dev/lanhook/` so `sync.cmd` commits it.

## 46b. NEW CAPABILITY — the live payload channel (port 47199). Use this, do not re-run to test a payload

`AOE2LAN_LIVE=1` (set in `PLAY-stage8-VERBOSE.cmd`) starts `LiveThread`, a plain-TCP
listener on **127.0.0.1:47199**. Protocol, one request per connection:

| request | reply |
|---|---|
| `PING\n` | `PONG armed=N\n` (N=1 means a game websocket is live) |
| `GETVARIANT <n>\n` | `<len>\n` + len bytes: the shim's own built MatchStartMessage payload n (needs a hosted lobby, else `0`) |
| `<opcode> <len>\n` + len bytes | `sent=1 parsefail=N thunkhits=M\n` |

The payload is **sent by the `ws_serve` loop that owns the connection**, never by the
control thread, so no lock is needed and frames cannot interleave. `g_LiveArmed` is set
after the 101 and cleared at `out:`. Verdict window is 2 s (the parse-fail line lands
~30–60 ms after the frame, measured).

Driver: `dev/lanhook/work/livepush.py` — `ping`, `get [n]`, `push '<json>' [op]`,
`sweep`, `bisect`, `types`. Offline gate: `dev/lanhook/work/livetest.py` (**PASS**:
armed=1, GETVARIANT 75 B / 788 B, verdict returned, and the not-armed path refuses with
`ERR no live websocket`).

**One game run to the lobby now answers unlimited payload questions at ~2.6 s each.**
This is the tool to use for everything below.

Trap found while building it: `BUF` is `{char *p; size_t len, cap; int oom;}` —
initialising only `len`/`oom` leaves `p` wild and crashes the shim thread (killed the
whole `srvtest` process). Always `BUF b = {0};`.

## 46c. H1 vs H2 is SETTLED — MatchStartMessage IS registered (H1 is dead)

Run 5848, `registry_dump()` at t=144.578: `MSREG head=0x7ff6f6026dc0`,
**`MSREG nodes=46`**, and `MSREG[0x24] node=0x7ff6f6026b80 fn=0x7ff6f26c66f0`.
With `game base=0x7ff6f1f10000`, that fn is **VA `0x1407b66f0`** = the MSThunk.
`HIT MSThunk` fired with `ret=0x7ff6f26b70ce` = VA **`0x1407a70ce`**, i.e. the
`call rax` inside dispatch `0x1407a7070`. So dispatch really does reach it through the
`{fn,next}` registry. **§45d's H1 branch is closed; do not xref the QWORD writers of
RVA `0x4c9e3e0`.**

Also note **46 registry nodes == 46 RLink `*Message` types in RTTI** (one handler per
message type). Full list is in `work/livepush.py: RLINK_TYPES`.

## 46d. CORRECTION to §45b — `HIT MSThunk` is NOT a type-match signal

Measured live, not inferred:

| payload | parsefail | thunkhits |
|---|---|---|
| any top-level JSON **object** (`{"messages":[…]}`, `m_type:"SessionStatusMessage"`, `{"operation":7}`) | 1 | **1** |
| top-level JSON **array** `[{…}]` | 1 | **0** |
| `"m_type": 0` (integer instead of string) | 1 | **0** |

So the thunk is called for **every** top-level object that gets past the envelope read —
it is one of 46 factories being asked in turn, not proof that `m_type` matched.
`thunkhits` only tells you "object, and `m_type` absent-or-string". **`parsefail` is the
only verdict that matters.** Do not re-derive H2 from thunkHits.

## 46e. ~110 payload shapes tested live — ALL rejected. The envelope is wrong, not the members

Every test on the live channel in a real hosted lobby (run 12008), all `parsefail=1`:

- `sweep`: envelope-only (op 2 and op 1), `operation=0..15` + envelope, `operation=2..5`
  + full, `[env]`, `[full]`, `{messages|notificationMessages|notifications|packets:[…]}`,
  `operation=2 + messages[full]`, `operation+ackCount+full`, `clientLibVersion+operation`,
  `m_type` as int (0,1,2,3,8,9,17,36), envelope/full minus `result`, SessionStatusMessage
- `bisect`: envelope + **each single member** (all 6), full **minus each member** (all 6),
  full with members in bond string-table order, `matchAdvertisement` as a positional array
- `types`: the minimal envelope under **all 46** type names — every one identical
- operation-only frames `{"operation":N}` for N=0..24, and `{"operation":N,"ackCount":1}`
  for N=2..10
- key-name shapes: `{MatchStartMessage:{…}}`, `{m_matchStartMessage:{…}}`,
  `{m_matchStartEvent:{m_info:{…}}}`, env + `m_info|m_message|message|data`,
  env + `m_rlinkLibVersion`, env + `m_resultCodes`, newline-terminated
- positional arrays: `[0,"MatchStartMessage",pid]`, `["MatchStartMessage",env]`,
  `[0,env]`, `[0,type,pid,…body]`, `[[env]]`, `[0,[env]]`, `[194,0,env]`

**Conclusion: no MatchStartMessage member work can ever fix this.** The container/envelope
is wrong. §45d's "whichever variant stops the ladder names the fault" logic is void —
nothing stopped it, and the members are not the variable.

Static facts gathered (all that survives in the exe, the parse path itself is encrypted):

- only **two** `{"operation"` format strings exist, both client→server:
  `{"clientLibVersion":%d,"operation":%d,"sessionToken":"%s"}` @ `0x3697ab8` and
  `{"operation":%d,"ackCount":%d}` @ `0x3697c48`. There is **no** server→server/→client
  template, so the notification is bond-deserialized, not `sprintf`-built.
- observed from the game: `{"clientLibVersion":194,"operation":0,"sessionToken":"1194178595"}`
  then `{"operation":1,"ackCount":1}`. So `operation` 0 = session token, 1 = ack.
- only **five** `m_`-prefixed strings exist in the whole exe: `m_rlinkLibVersion`
  (`0x368bf78`), `m_resultCodes` (`0x3698f98`), `m_scope`, `m_type` (`0x369a5f0`),
  `m_profileID` (`0x369d200`). `m_type`/`m_scope` sit in the
  `AccountUpdateProfilePrivacy`/`PrivacyScope` region, **not** in a notification
  envelope — so `m_type` as the notification discriminator is an unverified s43 assumption.
- bond string table @ `0x369d9d7..0x369da08`: `inProgressChallenges`,
  `matchAdvertisement`, `profileRaces` immediately precede `MatchStartMessage`, and
  `goodOldGamesSessionID`, `steamSessionID` precede `ReplyInvitationMessage`. Reading
  "fields precede their type name" (which makes `ReplyInvitationMessage` = GOG/Steam
  session IDs, and `MatchObserveMessage` = `member`+`passwordedProfileInfos`) gives
  **MatchStartMessage = {inProgressChallenges, matchAdvertisement, profileRaces}**.
- signature-path block @ `0x368be58..0x368bfd0` shows the rlink event shape
  `m_<name>Event.m_info.<field>` and a sibling `m_rlinkLibVersion` — an aggregate, not
  obviously the WS envelope.
- there is **no** long-poll/notification endpoint among the 150 `/game/...` strings.

## 46f. Run 5848 (operator pressed Start) — how far hosting actually gets

New, measured, and it reframes Priority 1:

- `t=142.672 [Network] TComm_Provider_RL::StartLaunchGame LAUNCH_GAME` →
  `StartLaunchGame ok` (VERBOSE=1 was applied: `[0x144356c66] 0 -> 2`)
- `t=144.391` `WorldwideAutomatchService::OnStartComplete - detected successful game
  start`, `Match Started - [3842241165083521967 AnkerGames], slot = 0, ranking = 0`,
  and `[rlink - error] Rejected PlayerReadyRequest, state is not MS_Setup`
- then **nothing**. Zero `[Network]` lines for the remaining 8 minutes, no scenario load,
  no `GAMEDATA`. Only `MessageCounts: inval=0/0, seek=0/0, join=0/2, ichk=0/0, …`
  every ~61 s (join went 0/2 → 0/0) and 11-byte relay pings
  (`0009143024180000000000`) to `192.168.0.100:27012` every ~3 s.
- `BattleServer.exe` is spawned by the game (pid 11688, 4 s after the game) and
  `192.168.0.100` is this machine's Ethernet IP, so the relay is local and alive.
  LAN broadcast advertisements are received: `!$685113f3-8d85-4e14-a09e-6b9ba8aa2970\x09\x00My Serv…`
- **The operator stayed in the lobby the whole time.** `Match Started` is server-side
  bookkeeping only; the screen transition needs the parsed MatchStartMessage, which is
  why 46e matters and why the lobby never left.
- host reply still says `"relayIP":"127.0.0.1"` (PLAN §W1-c is untouched).

**AI are missing from the match, and it is the GAME that drops them.** The
`slotinfo=` field of the game's own `/game/advertisement/update` request (t=143.891)
base64+zlib-decodes to `12,[{…8 slots…}].` where slot 0 is
`{"profileInfo.id":3842241165083521967,"stationID":1,"teamID":0,"factionID":0,
"raceID":0,…,"isReady":1,"metaData":"IkFBPT0i"}` and **slots 1–7 are all
`profileInfo.id:-1, stationID:-1, isReady:0`**. Our shim only echoes that blob back.
`matchMembers` likewise has exactly one entry. Hooks 15/16 do fire
(`AIGATE=1`, `HIT AISlotPick … nAI=0x2 val=0x2 kind=2`, `HIT AISlotLabel` slots 1–7) so
the AI are in the lobby UI but never reach `slotinfo`. That is Priority 2's real blocker
and it is independent of 46e.

## 46g. Gates (current build — all re-runnable, all passed)

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged.
- `dbghelp.dll` MD5 **`21fb2d236ad342ac9647cd7bbdc97fef`**, identical in the game dir and
  `dev/lanhook/`. Backups taken BEFORE each build: `.prev-s46-before` =
  `350d6b6bdba952dd90e9ea9c03f3c8ba` (the s45 build), `.prev-s46b-before` =
  `94cb6236552b80c9aca27454a011c1aa` (intermediate). Two intermediate MD5s also existed:
  `9006a86d…` (auto-clicker only) and `102c360c…` (live channel, pre-`BUF` fix).
- `hooktest.exe`: `post-hook ok (21, 210, 2100, 6)`, `T7 ok (210, 6)`, `swapped 68 of 68`.
- `AOE2LAN_LIVE=1 srvtest.exe` + `srvclient.py`: **PASS**, including `updateState reply:
  matchState=1`, `MatchStartMessage push: 788B`, `ladder variant1 envelope-only: 75B`,
  `ladder variant2 envelope+advert: 680B`, `ladder terminated after variant2`; plus
  `work/livetest.py`: **PASS**.
- `work/verifydll.py`: **19** HOOKDEF entries; `MSThunk va=0x1407b66f0 … grp=0 kind=0`;
  `GLog va=0x1407db520 … kind=7`.
- `dumpbin -DISASM` → `work/disasm-dll-s46.txt`: `mov rax,1407B66F0h` @ `0x180007418`
  and `mov rbx,[rax+4C9E3E0h]` @ `0x180013783`. `dumpbin -IMPORTS` → **KERNEL32.dll only**.
- Build warnings are the pre-existing C4090 set only, now at loginsrv.c
  **690/692/694/1905/1936** (they moved because of the new code; still exactly five).

## 46h. Next session

Shape-guessing is exhausted (46e). The next step must produce **ground truth for the
server→client notification container**, not another guess. Two routes, in order of value:

1. **Force long polling and watch.** `RL_USE_WEBSOCKET_PERCENT` (exe `0x3698008`) decides
   WS vs long poll; the login reply's `clientSettings` array already carries
   `RL_KEEPALIVE`/`RL_MISSPOLL`/`RL_DISCONNECT`, so it can be set from the shim or as an
   env var in the PLAY cmd — **no rebuild needed for the env-var route**. The long-poll
   path logs `LongPoller::Process: response good, processing=%lld: %s` and
   `…mismatched session IDs; lastPollSessionID=%s m_sessionToken=%s`, i.e. plain JSON over
   HTTP, in the dialect our other replies already parse in. Run it and read which URL the
   poller hits (it is not among the 150 `/game/...` strings, so it is built at runtime)
   and what the response must look like.
2. **Get the envelope from a reference implementation.** The ageLANServer public source
   (`github.com/luskaner/ageLANServer`, `server/internal/routes/wss/wss.go`) documents the
   same message-type names we found in RTTI. `wss.go`'s `parseMessage` confirms inbound
   `operation`/`sessionToken`; the **outbound** struct (the `m_type`/`m_profileID`
   envelope) is in the `common` package, which I did not locate before running out of
   session. NOTE: the operator forbade *using* ageLANServer as the mod (session 11, "make
   your own mod"); reading it for wire-format reference is what loginsrv.c's header
   already credits ("field order proven by the ageLANServer public source"). **Ask before
   relying on it.**

Then Priority 2: the AI never reach `slotinfo` (46f) — that is the game's own slot
construction, so it needs hooks 15/16 re-examined against the populator that writes the
slot array, not against the lobby UI. Priority 3 (second human over the tailnet) also
needs `relayIP` to stop being `127.0.0.1` (PLAN §W1-c).

## 46i. Do NOT (new, on top of §45g / §44h / §43h which all still hold)

- Do NOT treat `HIT MSThunk` as a type match — it fires for any top-level object (46d).
- Do NOT try more MatchStartMessage **member** permutations; 46e closed that whole space.
- Do NOT re-test the envelope shapes already listed in 46e; they are all measured rejects.
- Do NOT re-open the cert dialog problem, `root_add_silent()`'s blob format, or §45e
  options (a)/(b)/(c). The auto-click works and is gated (46a).
- Do NOT chase the t=1.2 s exit as a tamper response — it was the blocking dialog (46a).
- Do NOT hook anything on the §45a ENCRYPTED list, re-run a cleanliness check with a fixed
  byte window, or re-derive the registry node layout.
- Do NOT delete the `srvtest.c` 1 Hz `g_ParseFail` bump, and do NOT let
  `root_add_silent()` skip its `root_present()` re-check.
- Do NOT initialise a `BUF` partially — `BUF b = {0};` or it crashes the shim (46b).
- Do NOT rebuild without taking a `.prev-*` backup of both `dbghelp.dll` copies first.

## 46j. Files added / changed this session

| file | what changed |
|---|---|
| `loginsrv.c` | s46 auto-clicker (`g_hUser` + 6 user32 fn ptrs, `user32_ready`, `dlg_try_click`, `dlgThreadProc`, `dlgPidProc`, `DlgClickThread`, `root_add_prompting`), `RootRegThread` early-out on `root_present()==1`, live channel (`g_LiveBuf/Len/Op`, `g_LiveReq/Ack/Armed`, `live_itoa`, `live_reply`, `live_puts`, `live_conn`, `LiveThread`), `WSAStartup` in `LiveThread`, `g_LiveArmed` set/cleared in `ws_serve`, `AOE2LAN_LIVE` gate in `loginsrv_start` |
| `dlgprobe.c` | **new** (in `dev/lanhook/`, so `sync.cmd` copies it) — offline dialog measurer + clicker; `--noclick`, `--cert <path>`; removes our root afterwards so every run still prompts |
| `mkdlg.cmd` | **new** — builds `dlgprobe.exe` (mkprobe.cmd flags + `user32.lib`) |
| `certsave.c` | **moved** from `work/` to `dev/lanhook/` so `sync.cmd` commits it (§45e note resolved); still uncompiled, now low value |
| `work/livepush.py` | **new** — the live-channel driver: `ping`/`get`/`push`/`sweep`/`bisect`/`types`, `RLINK_TYPES` (all 46), `fallback_payloads()` |
| `work/livetest.py` | **new** — offline gate for the live channel (holds a WS open, checks armed/GETVARIANT/verdict/not-armed) |
| `PLAY-stage8-VERBOSE.cmd` | `AOE2LAN_LIVE=1`; comment block on the auto-clicker (do not wait for a dialog) |
| `work/disasm-dll-s46.txt` | dumpbin of the s46 DLL |
| `dbghelp.dll` (both copies) | rebuilt → `21fb2d236ad342ac9647cd7bbdc97fef` |

Unchanged on purpose: the s45 payload ladder, `registry_dump()`, hook 18, `srvtest.c`,
`srvclient.py` — all still gated and still passing.
