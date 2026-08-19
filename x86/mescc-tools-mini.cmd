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

rem Phase-3  M0, the macro assembler, is the first link built from several files:
rem the header stub, the shared Windows plumbing, and the program itself.
"%ART%\catm.exe" "%ART%\M0.hex2" "%HERE%PE32-i386.hex2" "%HERE%ntdll-i386.hex2" "%HERE%M0_x86.hex2" || goto :fail
"%ART%\hex2.exe" "%ART%\M0.hex2" "%ART%\M0.exe" || goto :fail

rem Phase-4  cc_x86, a compiler for the subset of C that M2-Planet is written in.
rem This is the last link written by hand; everything above it is compiled.
"%ART%\M0.exe" "%HERE%cc_x86.M1" "%ART%\cc_x86-0.hex2" || goto :fail
"%ART%\catm.exe" "%ART%\cc_x86.hex2" "%HERE%PE32-i386.hex2" "%HERE%ntdll-i386.hex2" "%ART%\cc_x86-0.hex2" || goto :fail
"%ART%\hex2.exe" "%ART%\cc_x86.hex2" "%ART%\cc_x86.exe" || goto :fail

rem Phase-5  M2-Planet, a C compiler with more of the language than cc_x86 has.
rem M2-Planet and M2libc\bootstrappable.c are upstream's, unmodified, vendored
rem as git submodules.  x86\M2libc-windows\bootstrap.c is this project's own
rem port of M2libc\x86\linux\bootstrap.c and is the only Windows-specific piece.
"%ART%\catm.exe" "%ART%\M2-0.c" ^
	"%HERE%M2libc-windows\bootstrap.c" ^
	"%HERE%..\M2-Planet\cc.h" "%HERE%..\M2libc\bootstrappable.c" ^
	"%HERE%..\M2-Planet\cc_globals.c" "%HERE%..\M2-Planet\cc_reader.c" "%HERE%..\M2-Planet\cc_strings.c" ^
	"%HERE%..\M2-Planet\cc_types.c" "%HERE%..\M2-Planet\cc_emit.c" "%HERE%..\M2-Planet\cc_core.c" ^
	"%HERE%..\M2-Planet\cc_macro.c" "%HERE%..\M2-Planet\cc.c" || goto :fail
"%ART%\cc_x86.exe" "%ART%\M2-0.c" "%ART%\M2-0.M1" || goto :fail
"%ART%\catm.exe" "%ART%\M2-0-0.M1" "%HERE%..\M2libc\x86\x86_defs.M1" "%HERE%libc-core.M1" "%ART%\M2-0.M1" || goto :fail
"%ART%\M0.exe" "%ART%\M2-0-0.M1" "%ART%\M2-0.hex2" || goto :fail
"%ART%\catm.exe" "%ART%\M2-0-0.hex2" "%HERE%PE32-i386.hex2" "%HERE%ntdll-i386.hex2" "%ART%\M2-0.hex2" || goto :fail
"%ART%\hex2.exe" "%ART%\M2-0-0.hex2" "%ART%\M2.exe" || goto :fail

rem Phase-6  M1-macro, a fuller assembler than M0: more label and pointer
rem widths, more architectures in one binary.  Compiled by M2 like any other
rem program; upstream also runs this stage's output through blood-elf first,
rem to add an ELF symbol table purely so objdump and gdb can read it -- there
rem is no PE equivalent worth building, and nothing here needs it, so that
rem step is skipped and PE32-i386.hex2 stands in unchanged.
rem
rem M2's own C is unmodified, so it always ends its output with :ELF_end, the
rem label its ELF header expects; PE32-i386.hex2 expects :PE_end.  pe-end-shim.M1
rem defines :PE_end at that same address without touching the vendored source.
"%ART%\M2.exe" --architecture x86 --bootstrap-mode ^
	-f "%HERE%M2libc-windows\bootstrap.c" ^
	-f "%HERE%..\M2libc\bootstrappable.c" ^
	-f "%HERE%..\mescc-tools\stringify.c" ^
	-f "%HERE%..\mescc-tools\M1-macro.c" ^
	-o "%ART%\M1-macro.M1" || goto :fail
"%ART%\catm.exe" "%ART%\M1-macro-0.M1" "%HERE%..\M2libc\x86\x86_defs.M1" "%HERE%libc-core.M1" "%ART%\M1-macro.M1" "%HERE%pe-end-shim.M1" || goto :fail
"%ART%\M0.exe" "%ART%\M1-macro-0.M1" "%ART%\M1-macro.hex2" || goto :fail
"%ART%\catm.exe" "%ART%\M1-macro-0.hex2" "%HERE%PE32-i386.hex2" "%HERE%ntdll-i386.hex2" "%ART%\M1-macro.hex2" || goto :fail
"%ART%\hex2.exe" "%ART%\M1-macro-0.hex2" "%ART%\M1.exe" || goto :fail

rem Phase-7  hex2 from C.  The hand-written hex2 built everything up to here;
rem this one replaces it, and unlike that one it is not limited to a fixed
rem label table.  It needs the real preprocessor -- hex2.h says
rem "#define max_string 4096" where M1-macro.c used an enum -- so this stage
rem drops --bootstrap-mode, which in turn means the full M2libc rather than
rem M2libc-windows\bootstrap.c: stdio.c's FILE and its buffering, standing on
rem the POSIX layer in M2libc-windows\{unistd,fcntl,sys\stat}.c.
"%ART%\M2.exe" --architecture x86 ^
	-f "%HERE%..\M2libc\sys\types.h" ^
	-f "%HERE%..\M2libc\stddef.h" ^
	-f "%HERE%M2libc-windows\unistd.c" ^
	-f "%HERE%M2libc-windows\fcntl.c" ^
	-f "%HERE%..\M2libc\fcntl.c" ^
	-f "%HERE%M2libc-windows\sys\stat.c" ^
	-f "%HERE%..\M2libc\ctype.c" ^
	-f "%HERE%..\M2libc\stdlib.c" ^
	-f "%HERE%..\M2libc\stdarg.h" ^
	-f "%HERE%..\M2libc\stdio.h" ^
	-f "%HERE%..\M2libc\stdio.c" ^
	-f "%HERE%..\M2libc\bootstrappable.c" ^
	-f "%HERE%..\mescc-tools\hex2.h" ^
	-f "%HERE%..\mescc-tools\hex2_linker.c" ^
	-f "%HERE%..\mescc-tools\hex2_word.c" ^
	-f "%HERE%..\mescc-tools\hex2.c" ^
	-o "%ART%\hex2_linker.M1" || goto :fail
"%ART%\catm.exe" "%ART%\hex2_linker-0.M1" "%HERE%..\M2libc\x86\x86_defs.M1" "%HERE%libc-core.M1" "%ART%\hex2_linker.M1" "%HERE%pe-end-shim.M1" || goto :fail
"%ART%\M0.exe" "%ART%\hex2_linker-0.M1" "%ART%\hex2_linker.hex2" || goto :fail
"%ART%\catm.exe" "%ART%\hex2_linker-0.hex2" "%HERE%PE32-i386.hex2" "%HERE%ntdll-i386.hex2" "%ART%\hex2_linker.hex2" || goto :fail
"%ART%\hex2.exe" "%ART%\hex2_linker-0.hex2" "%ART%\hex2-new.exe" || goto :fail

echo Built: hex0 hex1 hex2 catm M0 cc_x86 M2 M1 hex2-new
exit /b 0

:fail
echo BUILD FAILED
exit /b 1
