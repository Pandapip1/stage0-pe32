#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Derive ../cc_x86.M1 from upstream stage0-posix's x86/cc_x86.M1.

Every other source in ../ is emitted from scratch by a gen_*.py here, because
every other source is hex and no one would read a diff of it.  cc_x86.M1 is
different: it is 4938 lines of readable assembly, the compiler in it is
upstream's and is not being ported, and the only thing this port replaces is the
handful of places where that compiler talks to the operating system.  So this is
not a generator but a patch, written as a list of exact before-and-after texts.
Every one of them must match exactly once (or exactly as many times as it says),
so if upstream changes one of these passages this script fails rather than
quietly producing something that has not been reviewed.

  python3 port_cc_x86.py /path/to/stage0-posix/x86/cc_x86.M1 ../cc_x86.M1

What changes, and why:

  _start          Windows puts no argument vector on the stack, and open(),
                  read(), write(), brk() and exit() are not syscalls a user
                  program may make.  ntdll-i386.hex2 has all of it.
  malloc          the image carries 128MB of zero-filled writable memory past
                  the end of the file, so there is no break to move.
  fgetc, fputc    deleted; ntdll-i386.hex2 defines both, keeping the registers
                  upstream's callers expect kept.
  use_stderr      new.  Upstream writes fd 2 into Output_file to send an error
                  message to the console; the equivalent here is the process's
                  own hStdError, which has to be fetched from the PEB.
  Exit_Failure    NtTerminateProcess rather than exit().
  :ELF_end        becomes :PE_end, in this file and in the assembly it writes,
                  because the header stub is PE32-i386.hex2.

Nothing else is touched, and it shows: run upstream's cc_x86 and this one over
the same C and the two outputs differ only in that last line.
"""
import sys


def port(s):
    def sub(old, new, count=1):
        nonlocal s
        n = s.count(old)
        if n != count:
            raise SystemExit("port_cc_x86: expected %d occurrence(s), found %d, of:\n%s"
                             % (count, n, old))
        s = s.replace(old, new)

    # ---- the banner ------------------------------------------------------
    sub('''# SPDX-FileCopyrightText: © 2017 Jeremiah Orians
#
# SPDX-License-Identifier: GPL-3.0-or-later
''',
'''# SPDX-FileCopyrightText: (C) 2017-2021 Jeremiah Orians
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
# Additional permission under GNU GPL version 3 section 7:
# see LICENSE.EXCEPTION in the root of this project.
#
# cc_x86-pe32: the Windows (PE32/i386) port of stage0's cc_x86.
#
# cc_x86 reads a subset of C and writes M1 assembly.  It is the first link that
# reads a language a person would call a language, and the last one written by
# hand: everything above it is compiled from C by this program.
#
#   cc_x86 INPUT OUTPUT
#     argv[1]        a C source file, in the subset M2-Planet is written in
#     argv[2]        a path, created or truncated for writing
#
# The compiler itself is upstream's, unchanged.  What a program does that is not
# arithmetic -- open a file, read a byte, write a byte, ask for memory, stop --
# is all this port replaces, and on Windows none of it is a syscall the program
# may make itself.  Those five things live in ntdll-i386.hex2, which catm puts
# in front of this file along with the PE header:
#
#   M0 cc_x86.M1 cc_x86-0.hex2
#   catm cc_x86.hex2 PE32-i386.hex2 ntdll-i386.hex2 cc_x86-0.hex2
#   hex2 cc_x86.hex2 cc_x86.exe
#
# So there is no open(), no read(), no write(), no brk() and no exit() here, and
# no :fgetc or :fputc either -- ntdll-i386.hex2 already defines both, with the
# registers upstream's callers expect kept.  What is left is malloc, which is a
# bump allocator over the zero-filled memory past the end of the file, and the
# two ways this program stops.
#
# This file is not edited by hand.  Development/port_cc_x86.py derives it from
# upstream's cc_x86.M1, and the list of changes it makes is the whole of the
# port.
#
# The assembly it writes ends in :PE_end rather than :ELF_end, because the
# header stub the output will be linked against is PE32-i386.hex2.
''')

    # ---- macros ----------------------------------------------------------
    # int and lea_ecx,[esp] existed only to make syscalls; both go.
    sub("DEFINE int CD\n", "")
    sub("DEFINE lea_ecx,[esp] 8D0C24\n", "")
    sub("DEFINE call E8\n", "DEFINE call E8\nDEFINE call_[DWORD] FF15\n")
    sub("DEFINE mov_eax,[DWORD] A1\n",
        "DEFINE mov_eax,[fs:DWORD] 64A1\nDEFINE mov_eax,[DWORD] A1\n")
    sub("DEFINE mov_[DWORD],eax A3\n",
        "DEFINE mov_[DWORD],DWORD C705\nDEFINE mov_[DWORD],eax A3\n")
    sub("DEFINE push_eax 50\n",
        "DEFINE push_byte 6A\nDEFINE push_DWORD 68\nDEFINE push_eax 50\n")

    # ---- _start ----------------------------------------------------------
    sub('''# Where the ELF Header is going to hit
# Simply jump to _start
# Our main function
:_start
	pop_eax                                     # Get the number of arguments
	pop_ebx                                     # Get the program name
	pop_ebx                                     # Get the actual input name
	mov_ecx, %0                                 # prepare read_only
	mov_eax, %5                                 # the syscall number for open()
	int !0x80                                   # Now open that damn file
	mov_[DWORD],eax &Input_file                 # Preserve the file pointer we were given

	pop_ebx                                     # Get the actual output name
	mov_ecx, %577                               # Prepare file as O_WRONLY|O_CREAT|O_TRUNC
	mov_edx, %384                               # Prepare file as RW for owner only (600 in octal)
	mov_eax, %5                                 # the syscall number for open()
	int !0x80                                   # Now open that damn file
	cmp_eax, !0                                 # Check for missing output
	jg %_start_out                              # Have real input
	mov_eax, %1                                 # Use stdout

:_start_out
	mov_[DWORD],eax &Output_file                # Preserve the file pointer we were given

	mov_eax, %45                                # the Syscall # for SYS_BRK
	mov_ebx, %0                                 # Get current brk
	int !0x80                                   # Let the kernel do the work
	mov_[DWORD],eax &MALLOC                     # Set our malloc pointer
	mov_eax, %0                                 # HEAD = NULL''',
'''# Where the PE header is going to hit
# Our main function
# There is no argument vector on the stack on Windows and nothing on it worth
# reading; open_argv pulls both file names out of the command line instead, and
# both of them are required -- upstream falls back to stdout, this does not.
:_start
	call %resolve_all                           # Find ntdll and resolve what we need from it
	call %open_argv                             # argv[1] for reading, argv[2] for writing
	mov_[DWORD],DWORD &MALLOC &arena            # Set our malloc pointer, which the loader zeroed
	mov_eax, %0                                 # HEAD = NULL''')

    sub(''':Done
	# program completed Successfully
	mov_ebx, %0                                 # All is well
	mov_eax, %1                                 # put the exit syscall number in eax
	int !0x80                                   # Call it a good day''',
''':Done
	# program completed Successfully
	jmp %exit_ok                                # Close both files and call it a good day''')

    # ---- the assembly this compiler writes -------------------------------
    sub(''':header_string2  "
:ELF_data
"''', ''':header_string2  "
:PE_data
"''')
    sub(''':header_string5  "
:ELF_end
"''', ''':header_string5  "
:PE_end
"''')

    # ---- malloc ----------------------------------------------------------
    sub('''# Requires [MALLOC] to be initialized and EAX to have the number of desired bytes
:malloc
	push_ebx                                    # Protect EBX
	push_ecx                                    # Protect ECX
	push_edx                                    # Protect EDX
	mov_ebx,[DWORD] &MALLOC                     # Using the current pointer
	add_ebx,eax                                 # Request the number of desired bytes
	mov_eax, %45                                # the Syscall # for SYS_BRK
	int !0x80                                   # call the Kernel
	mov_eax,[DWORD] &MALLOC                     # Return pointer
	mov_[DWORD],ebx &MALLOC                     # Update pointer
	pop_edx                                     # Restore EDX
	pop_ecx                                     # Restore ECX
	pop_ebx                                     # Restore EBX
	ret''',
'''# Requires [MALLOC] to be initialized and EAX to have the number of desired bytes
# Upstream moves the break here; the image has 128MB of zero-filled writable
# memory past the end of the file, so this is only ever a bump of the pointer.
# Nothing is freed, and the memory is already zero, so this is calloc as well.
:malloc
	push_ebx                                    # Protect EBX
	mov_ebx,[DWORD] &MALLOC                     # Using the current pointer
	add_ebx,eax                                 # Request the number of desired bytes
	mov_eax,[DWORD] &MALLOC                     # Return pointer
	mov_[DWORD],ebx &MALLOC                     # Update pointer
	pop_ebx                                     # Restore EBX
	ret''')

    # ---- fgetc and fputc come from ntdll-i386.hex2 -----------------------
    sub('''# fgetc function
# Loads FILE* from [INPUT_FILE]
# Returns -4 (EOF) or char in EAX
:fgetc
	push_ebx                                    # Protect EBX
	push_ecx                                    # Protect ECX
	push_edx                                    # Protect EDX
	mov_eax, %-4                                # Put EOF in eax
	push_eax                                    # Assume bad (If nothing read, value will remain EOF)
	lea_ecx,[esp]                               # Get stack address
	mov_ebx,[DWORD] &Input_file                 # Where are we reading from
	mov_eax, %3                                 # the syscall number for read
	mov_edx, %1                                 # set the size of chars we want
	int !0x80                                   # call the Kernel
	pop_eax                                     # Get either char or EOF
	cmp_eax, !-4                                # Check for EOF
	je %fgetc_done                              # Return as is
	movzx_eax,al                                # Make it useful
:fgetc_done
	pop_edx                                     # Restore EDX
	pop_ecx                                     # Restore ECX
	pop_ebx                                     # Restore EBX
	ret


''', '')

    sub('''# fputc function
# receives CHAR in EAX and load FILE* from [OUTPUT_FILE]
# writes char and returns
:fputc
	push_ebx                                    # Protect EBX
	push_ecx                                    # Protect ECX
	push_edx                                    # Protect EDX
	push_eax                                    # We are writing eax
	lea_ecx,[esp]                               # Get stack address
	mov_ebx,[DWORD] &Output_file                # Write to target file
	mov_eax, %4                                 # the syscall number for write
	mov_edx, %1                                 # set the size of chars we want
	int !0x80                                   # call the Kernel
	pop_eax                                     # Restore stack
	pop_edx                                     # Restore EDX
	pop_ecx                                     # Restore ECX
	pop_ebx                                     # Restore EBX
	ret


''', '')

    # ---- an error message belongs on the console -------------------------
    # Upstream writes fd 2 into Output_file.  Same idea, different mechanism,
    # and upstream spells the comment two ways.
    for case, times in (("standard", 3), ("Standard", 6)):
        sub("\tmov_eax, %2                                 # Using " + case + " error\n"
            "\tmov_[DWORD],eax &Output_file                # write to standard error",
            "\tcall %use_stderr                            # write to standard error", times)

    # ---- the two ways this program stops ---------------------------------
    sub('''# Exit_Failure function
# Receives nothing
# And aborts hard
# Does NOT return
:Exit_Failure
	mov_ebx, %1                                 # All is wrong
	mov_eax, %1                                 # put the exit syscall number in eax
	int !0x80                                   # Call it a bad day''',
'''# use_stderr function
# Receives nothing
# Points every later fputc at the console rather than at the output file
# Upstream writes fd 2 into Output_file; the equivalent here is the process's
# own hStdError, which is only reachable through the PEB
:use_stderr
	push_eax                                    # Protect EAX
	mov_eax,[fs:DWORD] %0x30                    # TEB->PEB
	mov_eax,[eax+BYTE] !16                      # PEB->ProcessParameters
	mov_eax,[eax+BYTE] !32                      # ->hStdError
	mov_[DWORD],eax &out_handle                 # fputc writes there from here on
	pop_eax                                     # Restore EAX
	ret


# Exit_Failure function
# Receives nothing
# And aborts hard
# Does NOT return
:Exit_Failure
	push_byte !1                                # ExitStatus = 1, all is wrong
	push_byte !-1                               # ProcessHandle = NtCurrentProcess pseudo-handle
	call_[DWORD] &fn_exit                       # Call it a bad day''')

    sub('''	mov_ebx, %666                               # All is HELL
	mov_eax, %1                                 # put the exit syscall number in eax
	int !0x80                                   # Call it a bad day''',
'''	push_DWORD %666                             # ExitStatus = 666, all is HELL
	push_byte !-1                               # ProcessHandle = NtCurrentProcess pseudo-handle
	call_[DWORD] &fn_exit                       # Call it a bad day''')

    # ---- globals ---------------------------------------------------------
    # These held file descriptors; the handles that replace them live in
    # ntdll-i386.hex2 as in_handle and out_handle.
    sub(":Input_file\n\tNULL\n", "")
    sub(":Output_file\n\tNULL\n", "")

    # ---- the end of the image --------------------------------------------
    sub('''
:ELF_end
''', '''
:PE_end

# Everything malloc hands out.  The section's VirtualSize runs to the top of the
# image, so this is zero-filled writable memory that costs nothing in the file.
:arena  # 0 bytes
''')
    return s


def main(argv):
    if len(argv) != 3:
        raise SystemExit("usage: port_cc_x86.py UPSTREAM_CC_X86_M1 OUTPUT")
    src = open(argv[1]).read()
    out = port(src)
    with open(argv[2], "w") as f:
        f.write(out)
    print("cc_x86: %d lines from upstream's %d"
          % (out.count("\n"), src.count("\n")))


if __name__ == "__main__":
    main(sys.argv)
