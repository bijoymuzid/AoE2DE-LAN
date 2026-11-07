@echo off
rem session 41, RUN 3 (THE FIX, v2): stage 8 login + WidgetSetEn (14) +
rem AISlotPick (15) + AISlotLabel (16), AOE2LAN_AIGATE=1.
rem
rem Three writes, all in service of ONE game field: screen+0x1cf8, which the host
rem lobby keeps setting to -1 and which must be 0 for a normal lobby.
rem  1. hook 16 (populator 0x1a344f0..0x1a362aa) writes the sentinel [0x14326b258]
rem     (=0) into it, and forces the populator's own arg4 byte [rbp-0xd0] to 1.
rem     field==0 + arg4==1 is what makes block C emit the "AI" item (id 0x29625,
rem     dropdown index 4) at 0x1a35df9. Both writes land at the block-C "Open"
rem     call, before the AI gate in the same pass, so slots 1..7 all get it.
rem  2. hook 14 (WidgetSetEn, ~6000 hits/s in a lobby) re-asserts field=0 whenever
rem     it sees -1 again, using the screen pointer hook 16 captured. Needed because
rem     the lobby restores -1 on every refresh (measured: rows still being locked
rem     at t=93.4s, 27 s after the populator pass).
rem Why it matters beyond the dropdown: the Start handler 0x141a3c700 branches on
rem the same field at 0x141a3c894 - field==0 skips ALL checks and starts the match,
rem field!=0 runs "even number of AI slots" (IDS_LOBBY_SCREEN_ERROR_UNEVEN_PLAYERS,
rem counts only status==2 slots) and then a team-balance check
rem (IDS_LOBBY_SCREEN_ERROR_UNBALANCED_TEAMS, record+0xb0/+0xb4).
rem Only ever writes 0, only when the field is exactly -1, only after the slot-1
rem widget chain [[screen+0x2690]+0x4a0] still resolves; drops the pointer on a fault.
set AOE2LAN_STAGE=8
set AOE2LAN_HOOKS=4,5,13,14,15,16
set AOE2LAN_AIGATE=1
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
