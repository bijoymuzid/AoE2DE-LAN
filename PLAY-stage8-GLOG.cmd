@echo off
rem session 43 N13: PLAY-stage8-AIGATE.cmd plus hook 17 (GLog). Everything else
rem is identical - AOE2LAN_AIGATE=1, so the s41 AI-dropdown fix stays armed.
rem
rem WHY THIS RUN EXISTS
rem Everything below rlink is now known-good (s42): login, host, HostResult 0,
rem "Session is connected", EVENT_NEWPEER, peerAdd {"result":0}, ready accepted,
rem SetMatchState 1, updateState, "OnStartComplete - detected successful game
rem start", "Match Started - slot = 0". Then the game does NOTHING: no screen
rem change, zero widget activity, zero further relay traffic, no simulation.
rem The blocker is in the game layer ABOVE rlink and we have never been able to
rem see it: the game-layer log fn 0x140f19210 (and twin 0x140f192f0) and its two
rem writers 0x14101b4b0 / 0x14101bb50 are all ENCRYPTED on disk, so unhookable.
rem
rem WHAT HOOK 17 DOES (read-only, writes nothing)
rem Both log fns build their "[%s] " prefix by calling the CLEAN vsnprintf helper
rem 0x1407db520 (93 B, 16-aligned, prologue "mov [rsp+0x18],r8 / mov [rsp+0x20],r9
rem / push rbx / push rbp / push rsi / push rdi"). It has 60 call sites image-wide
rem and exactly two are inside the log fns: 0x140f19275 and 0x140f19347. Hook 17
rem keeps the range 0xf19200..0xf19400 (cx.py: only those two sites live there)
rem and prints r9 = the log category and the log fn's own rsi = the caller's
rem FORMAT STRING. rsi is safe because the helper pushes rsi only at +12, so the
rem thunk's entry snapshot ctx[-7] still holds the caller's value; both twins do
rem "mov rsi, r8" (0x140f1924b / 0x140f1931d) before the call.
rem Format string only, not the substituted values - still enough to see exactly
rem how far the game layer gets at and after "Match Started" (OnMatchEvent/MET_*,
rem "Got Advertisement Host event", InitProvider, connectToGame, UpdateConnectionState,
rem any TComm_Provider_RL line). Deduped on (category, format), cap 2048, first
rem 20 s skipped.
rem
rem Operator: Multiplayer -> Host Game, 3 AI, press Start, then sit and wait.
rem The answer is whatever GLOG prints around t=190-220.
set AOE2LAN_STAGE=8
set AOE2LAN_HOOKS=4,5,13,14,15,16,17
set AOE2LAN_AIGATE=1
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
