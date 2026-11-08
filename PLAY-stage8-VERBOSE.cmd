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
rem The answer is the [Network] TComm_Provider_RL lines around Start.
set AOE2LAN_STAGE=8
set AOE2LAN_HOOKS=4,5,13,14,15,16,17
set AOE2LAN_AIGATE=1
set AOE2LAN_VERBOSE=1
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
