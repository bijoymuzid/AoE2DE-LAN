@echo off
rem session 43 N13b, SOLVED without the command line: PLAY-stage8-GLOG.cmd plus
rem AOE2LAN_VERBOSE=1. Same hook set, same AI fix, one extra byte written.
rem
rem WHY HOOK 17 ALONE SHOWED ALMOST NOTHING (measured, runs at t=670 and t=560)
rem Hook 17 works: it printed the game layer's own text for the first time ever.
rem But in 11 minutes it found only 9 unique messages, 7 of them rlink errors and
rem 1 harmless lobby line. The reason is a level filter, not a missing call.
rem
rem The game-layer log fn 0x140f19210 starts with:
rem     140f1923c  cmp byte ptr [0x144356c66], 2
rem     140f19251  jae  0x140f19257        ; level byte >= 2 -> log anything
rem     140f19253  test dl, dl             ; else dl = the message level
rem     140f19255  je   0x140f192d5        ; dl == 0 -> RETURN, nothing logged
rem so a level-0 message is dropped BEFORE the vsnprintf call hook 17 sits on.
rem Every TComm_Provider_RL message is level 0:
rem     140f1609e  xor edx, edx            ; StartLaunchGame, "LAUNCH_GAME"
rem     140f160a7  call 0x140f19210
rem and likewise UpdateConnectionState at 0x140f17106. StartLaunchGame is the fn
rem that actually launches the match, and 0x140f16060 / 0x140f17060 are both
rem ENCRYPTED on disk, so they cannot be hooked. Raising this one byte is the only
rem way in.
rem
rem 0x144356c66 is in .data at rva 0x4356c66, which is PAST .data's raw size
rem (0x4af600), so it is zero-filled at boot: the level starts at 0 and that is
rem exactly why level-0 vanished for 43 sessions. It is a data byte the game's own
rem settings code writes (setter 0x140b75820 does `cmp byte [sys+0x144356c58],dl`),
rem not code, so raising it is the same class of write hooks 14/16 already do.
rem
rem GUARD: level 0 with the byte >= 2 also routes to the second writer
rem 0x14101bb50, which does `mov rax,[sink]; mov rcx,[rax+0x6f0]` at 0x14101c6fa
rem with no null check. So the write only happens once [0x144356c88] is non-null,
rem and it says so in the log either way. Read the VERBOSE: lines first.
rem
rem Operator: Multiplayer -> Host Game, 3 AI, press Start, wait 2 minutes.
rem s46: the certificate consent dialog is now AUTO-CLICKED by the DLL (measured:
rem logs/lanhook-5848.log t=0.172 "consent dialog found, posted BM_CLICK to IDYES").
rem Do NOT wait for a dialog and do NOT click anything - there is nothing to click.
rem The answer is the [Network] TComm_Provider_RL lines around Start.
rem s45: after Start the shim dumps the dispatch registry (MSREG lines) and pushes
rem up to three MatchStartMessage payload variants ~3 s apart (MSLADDER lines),
rem stopping early if one parses. So wait ~60 s after Start, not 40.
rem s45: hook 18 added = MSThunk 0x1407b66f0, the MatchStartMessage factory thunk.
rem CLEAN on disk (its whole 24 B body == gametext.bin) even though the factory it
rem calls, 0x1407cdf10, and parser #9, 0x1407b6710, are ENCRYPTED and unhookable.
rem Nothing calls it directly - dispatch 0x1407a7070 reaches it through the runtime
rem {fn,next} registry at [0x144c9e3e0] - so if it fires, MatchStartMessage IS
rem registered and the payload is what fails (H2). If it never fires while "failed
rem to parse" appears, it is NOT registered (H1). grp=0: drop ",18" to disable it
rem without a rebuild if it turns out to trip the tamper response (~5.6 s exit).
rem s46: AOE2LAN_LIVE=1 opens a local control channel on 127.0.0.1:47199. Once the
rem game is sitting in the lobby, dev/lanhook/work/livepush.py can push ANY payload
rem down the live websocket and read the verdict (parsefail / thunkhits) in ~2 s.
rem That replaces "one guess per 10 minute run" with as many guesses as we want.
rem s49: relayIP in the host/join reply. Must be THIS machine's tailnet IP for a
rem second machine to reach BattleServer.exe (PLAN 3.3). Unset = 127.0.0.1, which
rem is what single-machine hosting needs. Once Tailscale is logged in, put the
rem 100.x address from `tailscale ip` here.
set AOE2LAN_RELAY_IP=127.0.0.1
set AOE2LAN_STAGE=8
set AOE2LAN_HOOKS=4,5,13,14,15,16,17,18
set AOE2LAN_AIGATE=1
set AOE2LAN_VERBOSE=1
set AOE2LAN_LIVE=1
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
