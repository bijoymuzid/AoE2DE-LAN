@echo off
rem session 41, RUN 1 (READ-ONLY): stage 8 login + WidgetSetEn (14) + AISlotPick (15)
rem + AISlotLabel (16). AOE2LAN_AIGATE is NOT set, so nothing is written.
rem
rem id 16 hooks the CLEAN localize-string-by-id fn 0x140ac5480 and keeps only the
rem calls made from inside the host lobby's slot-dropdown populator
rem 0x1a344f0..0x1a362aa. Each (call site, string id) pair names the exact item
rem being built, so one run shows which of the three item blocks ran:
rem   block B  0x1a35a41 Open / 0x1a35ae0 Closed        (no AI, ebx == 1)
rem   block C  0x1a35c5f Open / 0x1a35d1a Closed / 0x1a35dfe AI (id 0x29625)
rem It also prints screen=rsi, field=[screen+0x1cf8], sent=[0x14326b258],
rem arg4=[rbp-0xd0] (the populator's r9b, second AI gate) and slot=[rbp-0x7c].
rem
rem Operator: Multiplayer -> Host Game, wait for the lobby, open an EMPTY slot's
rem dropdown (Open/Closed), close it, then back out to the menu. Nothing else.
set AOE2LAN_STAGE=8
set AOE2LAN_HOOKS=4,5,13,14,15,16
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
