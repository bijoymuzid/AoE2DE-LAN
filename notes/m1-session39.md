# Session 39 — three of four rows VERIFIED fixed in-game; "add-AI" reframed: it is not a lock problem

Supersedes `notes/m1-session38.md`. Everything below is MEASURED in a live run
(`logs/lanhook-3328.log`, PID 3328, launched 18:03, exited ~18:11, log ran to t=530s) or read
from `widgetui/*.json`, `resources/**` and the game's own `logs/.../Main.txt`. Game exe untouched.
**No code change this session.** The s38e fix is confirmed correct and confirmed working.

## 39a. Gates

- `AoE2DE_s.exe` MD5 `affb19f03ca96965abf9e56775cab688` — unchanged, matches s38a.
- `hooktest.exe`: PASS, `game-image iat walk: swapped 68 of 68`.
- `srvtest.exe`: PASS (`login server live on https://127.0.0.1:443/` → `srvtest done`). loginsrv unchanged.
- Staged `dbghelp.dll` MD5 **`d313af6964b08e0ab4fe6d908a6f1a01`**, identical in the game dir and
  `dev/lanhook/`, built 17:48 together with `hookcore.obj` and `hookcore.c`.
  **Correction to s38a:** the byte count there (242,176 B) is wrong; the file is **242,688 B**.
  The MD5 is authoritative and matches, so this IS the s38e build. Do not "fix" the size.
- Launch path used: `powershell -NoProfile -ExecutionPolicy Bypass -File
  "dev\lanhook\work\launch-detached.ps1"` (defaults to `PLAY-stage8-SETEN.cmd`,
  i.e. `AOE2LAN_STAGE=8`, `AOE2LAN_HOOKS=4,5,13,14`). Boot log confirms
  `hook filter: only 4:LogHelper,5:LogHelper2,13:LogWarn,14:WidgetSetEn`,
  `installed WidgetSetEn n=7` at `0x140ab6300`, `swapped 68 IAT slots`.

## 39b. Trap worth recording — you cannot byte-search the DLL for the locker ranges

A naive check (search `dbghelp.dll` for the 4-byte LE encoding of `0x1a2ce20` etc.) reports all
eight range constants MISSING, which looks like a stale build. **It is a false alarm.** MSVC `-O1`
compiles `x >= lo && x < hi` into the unsigned subtract idiom, so the `hi` constants never appear
at all and each `lo` appears only as the two's-complement 32-bit displacement of a `lea`:

```
0x180005FBC: test r14b,4                        ; newf & 4
0x180005FC2: lea  rax,[r15+FFFFFFFFFE5D31E0h]   ; r15 = l25; -0x1A2CE20
0x180005FC9: cmp  rax,4BCh                      ; span-1  (0x4BD)
0x180005FCF: jbe  MATCH                         ; R1 main match-settings locker
0x180005FD1: lea  rax,[r15+FFFFFFFFFE5CE6C0h]   ; -0x1A31940
0x180005FD8: cmp  rax,14F0h                     ; 0x14F1
0x180005FDE: jbe  MATCH                         ; R2 Victory / Team
0x180005FE0: lea  rax,[r15+FFFFFFFFFE5D1DB0h]   ; -0x1A2E250
0x180005FE7: cmp  rax,1391h                     ; 0x1392
0x180005FED: jbe  MATCH                         ; R3 re-lock pass
0x180005FEF: lea  rax,[r15+FFFFFFFFFE5B77E0h]   ; -0x1A48820
0x180005FF6: cmp  rax,4A1h                      ; 0x4A2
0x180005FFC: ja   skip                          ; R4 ButtonCiv
0x180005FFE: and  r14,0FFFFFFFFFFFFFFFBh        ; newf &= ~4
0x180006002: mov  qword ptr [r13],r14           ; ctx[16] = cleared flags -> restored into rdx
0x180006006: mov  ecx,ebx                       ; suppressed = 1 (forces the log line)
```

All four ranges present and correct. **Verify future builds with
`dumpbin -DISASM`, not with a byte grep.** Also note a linear capstone sweep of `.text` desyncs and
reports garbage here; dumpbin's `.pdata`-driven decode is the trustworthy one.

## 39c. Result — StartingAge, EndingAge, Victory: FIXED, confirmed by the operator

Operator in the host lobby: those three now open and hold a changed value. `Resources` and
`Difficulty` still work (no regression). **38 `SUPPRESSED` lines** in `logs/lanhook-3328.log`
(s38f had 36 with two ranges). The log shows the mechanism firing exactly where predicted:

```
t=56.484 #35097 old=0x8 new=0x8 name="ButtonCiv"          SUPPRESSED l25=0x1a48c63   (R4)
t=56.484 #35447 old=0x8 new=0x8 name="StartingAgeDropDown" SUPPRESSED l25=0x1a2d222   (R1)
t=56.484 #35448 old=0x8 new=0x8 name="EndingAgeDropDown"   SUPPRESSED l25=0x1a2d236   (R1)
t=56.484 #35453 old=0x8 new=0x8 name="VictoryDropDown"     SUPPRESSED l25=0x1a32a77   (R2)
t=56.484 #36250 old=0x0 new=0x0 name="VictoryDropDown"     SUPPRESSED l25=0x1a2e671   (R3)
```

The s38f diagnosis was right: R3 (the second re-lock pass at `0x1a2e250`) was what kept
StartingAge / EndingAge / Victory dead, and R4 was what kept ButtonCiv dead. Adding those two
ranges closed it. **No new re-lock site appeared** — the whack-a-mole did not continue.

## 39d. "add-AI" is NOT a lock problem — the s38 assumption was wrong

Operator: clicking it "says open close but no ai". Evidence:

1. **There is no `AddAI` widget.** Not in `AoE2DE_s.exe`, not in `gametext.bin`, not in any
   `widgetui/*.json`. s38g item 2 guessed `ButtonCiv`; that guess is now disproved.
2. **The real control is `NameDropDown`.** From `widgetui/screenmultiplayerlobbyhost.json`, each
   `Player1..Player8` slot is
   `{Team, Color, PlayerIconButton/PlayerIcon, NameDropDown, ButtonCiv, CivIcon}`.
   `NameDropDown` is `Type: DropDown`, `AccessibilityName: "IDS_SED2_PLAYER_TYPE"`,
   `Help: "IDS_MPS_NAME_TITLE_HELP_TEXT"` — the slot occupant picker. Its items are filled at
   runtime; the JSON carries no item list. `screensingleplayercreate.json` uses the **same** widget
   and the same accessibility name, so the AI list is shared code, not multiplayer-specific.
3. **`NameDropDown` is already ENABLED.** Its last transition in the run is an unlock by the engine
   itself, not by us:
   ```
   t=55.984 #27138 old=0x0 new=0x4 name="NameDropDown" l25=0x1a337d9            (lock, uncovered)
   t=56.484 #35022 old=0x8 new=0xc name="NameDropDown" l25=0x1a337d9            (lock, uncovered)
   t=56.484 #36281 old=0x4 new=0x0 name="NameDropDown" l25=0x1a2f19e            (UNLOCK, in R3)
   ```
   `0x1a2f19e` is inside R3 but `newf&4 == 0`, so our predicate correctly does not fire — this is a
   genuine engine unlock and it is the last write. The widget ends enabled, which matches the
   operator seeing the dropdown open.
4. **Therefore the dropdown opens and its item list contains only Open / Closed.** That is a
   *data* problem: the AI entries are missing from the list. No amount of bit-`0x4` suppression can
   add list items. `ButtonCiv` suppression did its job (naturally unlocked at `0x1a488c4`,
   re-lock at `0x1a48c63` suppressed) — `ButtonCiv` is the *civilization* button, not add-AI.

## 39e. Where the AI list comes from (measured, incomplete)

- `resources/en/strings/key-value/key-value-strings-utf8.txt` line **30549**:
  *"Select the personality of the computer player. Typically, you can select Standard (the default
  computer player script) or None (no AI for the computer player). **If you create and place a
  custom AI in the AI folder on your hard drive, it will appear in this list.**"*
  ⇒ **custom** entries come from `.ai` files. This was only half the story — see 39h: the three
  entries the operator actually saw are built-in localization tags, not `.ai` files.
- `Open` / `Closed` ARE localization entries — string-table ids **9685** and **9684**. That is why
  they still show when the `.ai` list is empty. Exact match to the reported symptom.
- Every `.ai` file in the whole install (3):
  `resources/_common/ai/AI (HD version).ai`, `resources/_common/ai/E3-p2.ai`,
  `resources/_common/drs/gamedata_x2/randomgame.ai`.
- The **user-profile AI folders are EMPTY**:
  `<data>/0/resources/_common/ai` and `<data>/76561197960271872/resources/_common/ai`
  (`<data>` = `C:\Users\Bijoy\Games\Age of Empires 2 DE`). No `.ai`/`.per` anywhere under `<data>`.
- `resources/_packages` is **EMPTY**. `_common/drs/gamedata_x2` holds 307 files, almost all `.rms`.
- The game's own log for this run (`<data>/logs/2026.11.07-1803.08/Main.txt`, 1994 B) mentions
  `Game::open resource packages` and loads the profile fine, but says **nothing** about AI — no
  error, no count. So which folder it scans, and why it finds zero, is **UNKNOWN**.
- `gametext.bin` is a code-only dump (no strings): `NameDropDown`, `ButtonCiv`,
  `ScreenMultiplayerLobbyHost`, `CivOptionAll` are all absent from it, and it contains **zero**
  `IDS_*` keys. Do not try to xref widget names through it.

## 39f. Other measurements from the same run (context, not symptoms)

- **59 lines** still set bit `0x4` from *uncovered* callers. None of them blocks a row that works, so
  **do not add ranges blindly.** The notable ones: the wide checkbox pass `l25=0x1a4687e`
  (TeamTogether, LockTeams, RecordGame, TeamPosition, LockSpeed, AllowCheats, SharedExploration,
  TurboMode, AllTechs, EmpireWarsMode, …), the button pass `l25=0x1a4675e` (ButtonLeave,
  ButtonReturn, ButtonStart, ButtonReadyStart, ButtonTechTree, ButtonInvite, ButtonScenario,
  ButtonLocation, ButtonLobbyBrowser, ButtonCopy, ButtonBalanceTeams, ButtonReset, ButtonRandomize,
  ButtonLobbySettings), `Color` from `0x1a48f04`, `Team` from `0x1a494fa` (later unlocked from
  `0x1a493ca`), `PlayerIconButton` from `0x1a33588`, `NameDropDown` from `0x1a337d9`, and
  `CivOptionAll/AoE2/Paphos` from `0x1a3af11/21/31` and `0x1a4687e`.
- **Dedup interacts usefully with suppression.** The seen-key is `fnv(name)<<8 | (newf & 0xFF)` and
  `newf` is cleared *before* hashing, so a suppressed line hashes differently from an unsuppressed
  one for the same widget. Any future re-lock from a new site therefore shows up as its own line
  with `new=…4` and no `SUPPRESSED` tag. Grep for exactly that when a row regresses.
- **Host plane is healthy.** `/game/advertisement/host` returned a real id: `advertisementid` went
  `-1` → **`1194070995`**, `sessionID=1194070995`, `connect_id=1194070995`. 28 distinct endpoints
  were served with no `not formatted correctly` line in this run.
- **`slotinfo` decodes** (URL-decode → base64 → zlib → JSON, prefixed `"12,"` = 12 slots). After the
  operator's edits, slot 0 is the host
  `{"profileInfo.id":3842241165083521967,"stationID":1,"teamID":0,"factionID":0,"raceID":0,
  "isReady":1,"status":0,"metaData":"IkFBPT0i"}` (`metaData` = base64 of `"AA=="`), slots 1–11 all
  `profileInfo.id:-1, stationID:-1, status:0`. **No slot ever got an AI occupant**, consistent with
  39d.
- **Unexplained but recorded:** `mapname=my%20map` and `matchtype=-1` never changed across all four
  advertisement bodies (t=56.250 / 57.625 / 61.172 / 68.188), with `maxplayers=8`. Whether
  `matchtype=-1` gates anything (AI list included) is **UNKNOWN**. Do not assume it is the cause.

## 39g. Where the next session starts

Items 1–2 are closed below; **39k holds the ordered plan** (N5 measure-first hook, N6 find the real
lobby builder, N7 M2).

1. **N1 — DONE, answered this session.** Operator ran Single Player → Skirmish in the same process
   (PID 9388) and the empty-slot dropdown listed **`AI`, `Closed`, `AI (CD version)`,
   `AI (HD Version)`**. So the AI list loads fine install-wide; the *multiplayer* path is what drops
   it. N2 (supplying `.ai` files) is dead — it was based on the wrong half of 39e. Go to 39i/39j.
2. **N1b — also DONE.** Operator then re-hosted a LAN lobby in the same process and switched the game
   mode to **Death Match**: still no AI names. So it is not a stale-lobby or game-mode-selection
   artefact. Measured side-effect, worth keeping: the lobby settings DO round-trip (39i).
3. **N3 — M2, now unblocked.** s38g item 3 gated this on "only after the rows respond"; they
   respond. Start an actual LAN game from the host lobby and confirm the settings round-trip to the
   sim and nothing desyncs. Remember the bit-`0x4` clear only makes the UI editable — it does not
   prove the click handlers commit the value. A real match is the first proof.
4. **N4 — optional real source fix (unchanged from s38g item 4).** Find what writes
   `this->field_0x1cf8` on the lobby screen and why it differs from the sentinel `[0x14326b258]`
   for LAN. If a clean (non-encrypted) writer exists, setting the field to the sentinel makes the
   engine unlock the rows itself — cleaner than suppression. The writer may also be encrypted.
5. **Do not re-open the four-row fix.** It is verified. R1–R4 stay as they are unless a *specific*
   log line shows a new re-lock site (see the grep recipe in 39f).

## 39h. Rules that still apply

Never patch or hook code encrypted on disk (`0x141aab4a0`, `0x141abc6c0`, `0x140ac4090`,
`0x140ab02a0`, `0x140acc950`, and the lockers `0x141a2ce20` / `0x141a31940` / `0x141a2e250` /
`0x141a48820`) — read those from `gametext.bin` only, and note `gametext.bin` has no strings.
`0x140ab6300` IS clean and is hook id 14. No whole-memory sweeps; never set `AOE2LAN_UIW=1` or
`rules_scan()`. Default stage-8 hooks stay 4, 5, 13; id 14 only via `AOE2LAN_HOOKS=4,5,13,14`.
`HK_WSET` skips the first 20 s after boot (`GetTickCount() - g_t0 < 20000`) and caps at 512 lines —
neither fired this run (no `capped` line). Do not edit `lanhub/**`, `linux/**`, `notes/linux-*.md`.
Edit the game-dir tree (`D:\Age of Empires II Definitive Edition\dev\lanhook`), then sync with
`sync.cmd`. Verify any rebuilt DLL with `dumpbin -DISASM` (39b).

## 39i. The lobby is healthy — `mapname` / `matchtype` are dead fields

The second multiplayer run (same PID 9388, operator switched the game mode to Death Match) still
advertised `mapname=my%20map` and `matchtype=-1`, unchanged across 16 bodies from t=1064 to t=1220.
That looked like a broken lobby. It is not:

- The real settings travel in the **`options`** field, not in `mapname`/`matchtype`.
- `options` is nested: URL-decode → base64 → **zlib** → strip the wrapping `"` → base64 again →
  a 1-byte entry count followed by that many `<len:4 LE><"key:value">` records. Decoded 74/74 and
  75/75 entries cleanly.
- Diffing the first lobby body (t=1064) against the post-Death-Match body (t=1220) shows **16 keys
  changed**, including `41: '2' -> '3'` (the game mode) and `5: '0' -> '11'`, `4: '0' -> '3'`,
  `28: '200' -> '100'`, `57: '0' -> '60'`, `65/66/75/77: y/n flips`.

So the lobby records and re-advertises settings correctly. **`mapname=my map` and `matchtype=-1`
are vestigial in DE and must not be chased.** This also kills the "no valid game setup" theory for
the missing AI. Decoder is worth keeping — it is the only way to read what the lobby actually
believes, and M2 will need it to prove settings reach the sim.

Also noted in this run: 39 `response was not formatted correctly` warnings, all on caches already
listed as W1-d backlog (`LeaderboardStatsCache`, `GetAvailableAchievementsCache`, `ItemCategoryCache`,
`ItemBundlesCache`, `ChallengeGetChallengesCache`, `CommunityEventsCache`). None is AI-related.
Unrelated curiosity: the Windows cert store contains
`/O=github.com/luskaner/ageLANServer/CN=ageLANServer Self-signed` — a prior LAN project's cert.

## 39j. Static RE on the AI list — how far it got, and where it stops

The three built-in AI names are localization keys, found in
`resources/en/strings/key-value/key-value-strings-utf8.txt`:

```
ORIG_AI_TAG "AI (CD version)"   NEW_AI_TAG "AI"
HD_AI_TAG   "AI (HD version)"   CUSTOM_AI_TAG "Custom AI"
UNRANKED_VIA_AI "Your ELO score has not changed. Match contained AI players."
13204 "NOT YET RANKED: There can be no AI Players in a ranked match"
```

`UNRANKED_VIA_AI` and `RESTOREMULTI_AI_ERROR` prove **AI in an online match is a real, supported
game feature**, so this is worth chasing and is not "the game never allowed it". The operator's
skirmish list was exactly NEW/ORIG/HD with no `Custom AI` — consistent with the empty profile AI
folder, and confirming the built-ins are tag strings, not `.ai` files.

String VAs (imagebase `0x140000000`, `.rdata` at RVA `0x3197000` / raw `0x3195c00`):
`ORIG_AI_TAG 0x1432d2740`, `NEW_AI_TAG 0x1432d2750`, `CUSTOM_AI_TAG 0x1432d2760`,
`HD_AI_TAG 0x14322a950`. `gametext.bin` (RVA `0x1000`, size `0x3195000`) is a **code-only** dump:
no strings, no `IDS_*` keys, so every string xref has to be found by scanning it for rip-relative
`lea`, not by grepping it.

**Dead end 1 — the four tag getters.** `0x1bf4f0` (ORIG), `0x1bf4c0` (NEW), `0x1be570` (HD),
`0x1be540` (CUSTOM) are 0x27-byte lazy static-string initializers, all **clean on disk**
(`disk == run`), each `lea rdx,[TAG]; call 0x140a1b9f0; lea rcx,[static]; jmp 0x142d6ded4`. They
appear as four consecutive pointers in `.rdata` at `0x319fef0..0x319ff08`. But: **zero `E8` call
sites and zero rip-relative references** to those slots anywhere in `.text`. The scanner was
validated first (473 call sites for `0xac54a0`, including the expected `0x192ae61`), so this is a
real result, not a scan bug. These getters are not how the dropdown is filled. Do not hook them.

**The three real users of the tag strings** (found by rip-relative `lea` scan):

| function | size | tag | `disk == run`? |
|---|---|---|---|
| `0xbf3c30..0xbf4363` | 1843 B | HD_AI_TAG (x2, `0xbf3e6f`, `0xbf3e88`) | **NO — encrypted** |
| `0x18aeb10..0x18af745` | 3125 B | ORIG_AI_TAG (`0x18aed3b`) | **NO — encrypted** |
| `0x192a4f0..0x192bba0` | 5808 B | NEW_AI_TAG (`0x192ae5a`) | **NO — encrypted** |

All three are encrypted on disk ⇒ readable from `gametext.bin`, **not hookable, not patchable**
(39h rule). No single function references all three tags, so the list is not built in one place —
or these three are three different contexts and the lobby builder is a fourth site not yet found.

**The one concrete gate found so far**, at `0x18aed3b` (ORIG_AI_TAG):

```
0x18aed1f: mov rcx,[rip+0x2aa6592]   ; global at RVA 0x2c352b8
0x18aed26: add rcx,0x680             ; member +0x680
0x18aed2d: call 0x140fa46c0
0x18aed32: cmp eax,2
0x18aed35: jne 0x1418aede6           ; != 2  ->  SKIP the AI entry
0x18aed3b: lea rdx,[ORIG_AI_TAG]
```

`0x140fa46c0` is 0x2f bytes and **clean on disk**. Full semantics:

```
kind = byte[rcx+4]
kind == 0 -> return dword[rcx]
kind == 1 -> return (dword[rcx] == 3) ? 2 : 0
else      -> tail-call 0x1408f6a00
```

**But it has 182 call sites** — it is a generic variant/optional accessor, not an AI-specific query.
A blanket hook is out of the question; only a caller-filtered one is safe (match the return address
`0x18aed32`). The other two tag functions make **zero** calls to it, so this gate explains at most
one of the three entries.

**Still UNKNOWN:** whether `0x18aeb10` is on the multiplayer lobby path at all; what
`[0x2c352b8]+0x680` holds in each context; and which code fills the *lobby* dropdown specifically.

## 39k. Next session, in order

**Operator priority, stated explicitly: the AI work comes FIRST, ahead of M2.** Reason: there are not
enough human players, so the target match is operator + one friend + AI in the host lobby. The
operator also wants to confirm that a match containing AI actually starts and runs. So N5/N6 below
outrank N7.

0. **N0 — chase the best lead first (see 39l).** Read `0x1ab4bd0..0x1ab6ab9` from `gametext.bin`:
   it is the only caller of a tag function inside the lobby widget range, calling the HD_AI_TAG
   function at `0x1ab4c54`. Find the condition under which that call is reached, and find a **clean**
   function on that path that can be hooked caller-filtered. That is the only shape of fix available,
   because the builder itself is encrypted.
1. **N5 — measure before patching.** Add a read-only hook on the clean getter `0x140fa46c0` that
   logs `(caller RVA, returned eax)` and is **filtered to caller `0x18aed32`** (plus a small cap),
   opt-in by a new hook id. Run it twice: once in Single Player → Skirmish, once in a LAN host
   lobby. Three outcomes:
   - fires in skirmish only ⇒ this function is not on the multiplayer path; stop looking here and
     go to N6.
   - fires in both, `eax==2` in skirmish and `!=2` in the lobby ⇒ **the gate is found**. Then a
     caller-filtered force of `eax=2` is the candidate fix, in the same shape as the `HK_WSET`
     bit-`0x4` suppression. Test whether all three AI entries appear or only the ORIG one.
   - fires in both with the same value ⇒ the gate is elsewhere; go to N6.
2. **N6 — find the lobby builder properly.** The three known sites are encrypted and none references
   all three tags. Anchor on something clean instead: `Open`/`Closed` are string-table ids **9685**
   and **9684**, and both screens' `DropDownListBox` child is the same widget. Find the code that
   adds those two ids, then read forward to where the AI entries would be appended — that is the
   lobby-specific builder, and its own gate is the answer.
3. **N7 — M2, unblocked but ranked BELOW the AI work by operator request.** The settings rows respond
   and 39i proves the lobby round-trips its settings. Start an actual LAN game and confirm the sim
   loads and nothing desyncs. Co-op-vs-AI needs the AI list; a 2-human LAN match does not.
4. **N4 (unchanged, optional)** — the real source fix for the row locks: find the clean writer of
   `this->field_0x1cf8` and why it differs from the sentinel `[0x14326b258]` for LAN.
5. **Do not re-open the four-row fix**, and do not re-add ranges without a specific log line (39f).

## 39l. Two more anchors tried, and the encryption wall (last work of s39)

Goal restated by the operator: **AI must appear in the multiplayer host lobby's slot dropdown**, so a
match can be you + one friend + AI. The operator also wants to know whether a match with AI actually
starts. This is now the top priority, ahead of M2.

**Anchor A — the `Open`/`Closed` string-table ids (9685 / 9684).** Searched `gametext.bin` for both
4-byte immediates and grouped by `.pdata` function: 34 raw hits for 9684, 22 for 9685, **17
functions contain both**. Too many to be a clean anchor — those small integers collide with ordinary
immediates. Best candidate by count and location: **`0x1a344f0..0x1a362aa`** (3x each id), which sits
immediately after the Victory/Team locker `0x1a31940..0x1a32e31`, i.e. inside lobby UI code.
Second candidate `0x1a1b6e0..0x1a1ea60`. Both are **encrypted on disk**.

**Anchor B — callers of the three tag functions.** This is the more useful result:

| tag function | callers | where |
|---|---|---|
| `0xbf3c30` HD_AI_TAG | **7** | `0xe72660` x2, `0xe733a0`, `0xe789d0`, `0x13d44f0`, **`0x1ab4bd0`**, `0x1c93cc0` |
| `0x18aeb10` ORIG_AI_TAG | 1 | `0x18ac240` (call at `0x18ad22c`) |
| `0x192a4f0` NEW_AI_TAG | **0** | — |

**`0x1ab4bd0..0x1ab6ab9` is the lead to chase.** It is the only caller inside the lobby widget range
(`0x1aa0000..0x1ad0000` — the same window the `lcaller` filter in `HK_WSET` uses), and it calls the
HD_AI_TAG function at `0x1ab4c54`. It is **encrypted on disk**, so readable from `gametext.bin` only.

Encryption status of every candidate checked: `0x1ab4bd0`, `0x1ab4c54`, `0x1a344f0`, `0x18ac240`,
`0x1a1b6e0` all `disk != run`. The **only clean** function on this whole path is the generic getter
`0x140fa46c0` (182 callers — caller-filtered only).

Consequence for method: the AI-list builder can be **read** but not **hooked**. So the fix has to be
either (a) a caller-filtered hook on a clean function that the builder itself calls — the `HK_WSET`
bit-`0x4` trick is the template — or (b) something server-side. `NEW_AI_TAG`'s function having zero
callers means at least one of the three tag sites is reached indirectly or is dead; do not assume the
three sites are one list.

Untested server-side idea, recorded so it is not lost: our shim already echoes the host's `slotinfo`
back as `encodedSlots`. Rewriting that blob to insert AI occupants would change what a **joining**
client sees, but the host's local lobby state is authoritative, so it probably does not make the host
actually run the AI. Low confidence; only worth trying if the code path proves unreachable.
