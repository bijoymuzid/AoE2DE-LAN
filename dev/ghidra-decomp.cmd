@echo off
rem Decompile functions from the already-imported decrypted program.
rem Usage: ghidra-decomp.cmd out=<file.c> addr=0x... [addr=0x...]  (or start=/end=)
setlocal
set TOOLS=%~dp0tools
set GHIDRA=%TOOLS%\ghidra_12.2_PUBLIC
set JAVA_HOME=%TOOLS%\jdk-25.0.5+8
set GHIDRA_HEADLESS_MAXMEM=6G
set PROJ=%~dp0ghidra-dec
call "%GHIDRA%\support\analyzeHeadless.bat" "%PROJ%" aoe2dec -process AoE2DE_dec.exe -noanalysis -scriptPath "%~dp0ghidra-scripts" -postScript PdataDecomp.java %*
