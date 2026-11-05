@echo off
rem session 28: stage 8 login + read-only readout of the five inputs that decide the
rem Multiplayer button, plus one scan for the live twin-rule record (AOE2LAN_RULES).
rem Reads game memory only; no detour, no .rdata re-point, nothing written.
rem Operator: double-click, sit at the main menu ~90 s (readout at 25/40/70 s, scan at 75 s), quit.
set AOE2LAN_STAGE=8
set AOE2LAN_RULES=1
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
