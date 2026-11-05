@echo off
rem AoE2LAN M1 H1 fake login (stage 8): in-DLL SChannel TLS server on
rem 127.0.0.1:443 + rlink DNS redirect + trust injection + LogHelper view.
rem Operator: double-click, sit at menu ~1 min, click Multiplayer once, quit.
rem Tell the assistant the new logs/lanhook-<pid>.log filename (or just done).
set AOE2LAN_STAGE=8
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
