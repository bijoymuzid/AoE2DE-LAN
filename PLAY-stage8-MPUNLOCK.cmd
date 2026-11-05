@echo off
rem AoE2LAN session 23 — stage 8 (working fake login) + MP unlock.
rem MP unlock = AOE2LAN_MPUNLOCK=1: dbghelp.dll re-points 3 slots of rlink's
rem XboxPlatform vtable (plain .rdata) at stubs that answer "signed in / allowed".
rem Nothing on disk changes; a normal relaunch is back to stock behaviour.
rem Operator: double-click, sit at the menu ~50 s, hover the Multiplayer button
rem (read its tooltip), press Tab once (focus ring), click Multiplayer once,
rem wait ~10 s, quit. Report the logs/lanhook-<pid>.log name.
set AOE2LAN_STAGE=8
set AOE2LAN_MPUNLOCK=1
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"