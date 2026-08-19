@echo off
rem SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
rem SPDX-FileCopyrightText: (C) 2026 Gavin John
rem
rem SPDX-License-Identifier: GPL-3.0-or-later
rem
rem Build the chain, each link with the link below it.  Upstream drives the
rem equivalent sequence with kaem, a shell it has to bootstrap first; Windows
rem always has cmd.exe, so there is nothing to bootstrap here.

setlocal
set HERE=%~dp0
set ART=%HERE%artifact
set SEED=%HERE%..\bootstrap-seeds\PE32\i386\hex0-seed.exe
if not exist "%ART%" mkdir "%ART%"

rem Phase-0  hex0 from the seed.  This must reproduce the seed byte for byte.
"%SEED%" "%HERE%hex0_x86.hex0" "%ART%\hex0.exe" || goto :fail

rem Phase-1  hex1 adds single character labels
"%ART%\hex0.exe" "%HERE%hex1_x86.hex0" "%ART%\hex1.exe" || goto :fail

rem Phase-2  hex2 adds long labels and sized pointers, and so is a linker
"%ART%\hex1.exe" "%HERE%hex2_x86.hex1" "%ART%\hex2.exe" || goto :fail

rem Phase-2b catm removes the need for a shell to join files
"%ART%\hex2.exe" "%HERE%catm_x86.hex2" "%ART%\catm.exe" || goto :fail

rem Phase-3  M0, the macro assembler, is the first link built from two files
"%ART%\catm.exe" "%ART%\M0.hex2" "%HERE%PE32-i386.hex2" "%HERE%M0_x86.hex2" || goto :fail
"%ART%\hex2.exe" "%ART%\M0.hex2" "%ART%\M0.exe" || goto :fail

echo Built: hex0 hex1 hex2 catm M0
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
