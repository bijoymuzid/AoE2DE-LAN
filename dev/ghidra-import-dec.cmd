@echo off
rem Import the DECRYPTED copy with no auto-analysis (the full analysis pass dies with
rem "Can't checkpoint with locked buffers"). Functions are created later by
rem ghidra-scripts/PdataDecomp.py from the PE exception table.
setlocal
set TOOLS=%~dp0tools
set GHIDRA=%TOOLS%\ghidra_12.2_PUBLIC
set JAVA_HOME=%TOOLS%\jdk-25.0.5+8
set GHIDRA_HEADLESS_MAXMEM=10G
set PROJ=%~dp0ghidra-dec
call "%GHIDRA%\support\analyzeHeadless.bat" "%PROJ%" aoe2dec -import "%~dp0AoE2DE_dec.exe" -noanalysis -log "%PROJ%\import.log" -scriptlog "%PROJ%\script.log"
