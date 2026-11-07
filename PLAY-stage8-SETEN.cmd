@echo off
rem session 36: stage 8 login + read-only logging hook on widget SetEnabled (0x140a74ca0, id 14).
rem Logs (widget name, dl, caller RVA) deduplicated by (name, dl), capped at 256 lines.
rem Operator: double-click, click Multiplayer -> Host Game, sit in the host lobby ~5 s, quit.
set AOE2LAN_STAGE=8
set AOE2LAN_HOOKS=4,5,13,14
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
