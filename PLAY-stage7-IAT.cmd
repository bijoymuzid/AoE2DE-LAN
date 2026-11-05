@echo off
rem AoE2LAN M1 socket capture: DNS + connect + TLS handshake + cert-validation
rem taps (game code untouched, fully transparent). Operator: double-click,
rem sit at the main menu ~3 min, click Multiplayer once, quit.
set AOE2LAN_STAGE=7
set RL_TELEMSHOULDNTSEND=1
set RL_TELEMREPORTPCT=0
start "" "AoE2DE_s.exe"
