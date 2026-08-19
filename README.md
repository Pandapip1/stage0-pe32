<!--
SPDX-FileCopyrightText: (C) 2026 Gavin John

SPDX-License-Identifier: GPL-3.0-or-later
-->

# stage0-pe32

A full-source bootstrap for Windows, in the shape of
[stage0-posix](https://github.com/oriansj/stage0-posix).

Everything here is built from source by the chain itself, starting from a
1623-byte seed whose own annotated source is in the tree. Each link is written
in the language of the link below it, so the whole thing can be audited by
reading, from the bottom up.

    bootstrap-seeds/PE32/i386/hex0-seed.exe   1623 bytes, the trust anchor
    x86/hex0_x86.hex0                         hex0, written in hex0
    x86/hex1_x86.hex0                         hex1, written in hex0
    x86/hex2_x86.hex1                         hex2, written in hex1
    x86/catm_x86.hex2                         catm, written in hex2
    x86/PE32-i386.hex2                        the PE32 header, in hex2
    x86/ntdll-i386.hex2                       the shared Windows plumbing, in hex2
    x86/M0_x86.hex2                           M0, written in hex2
    x86/cc_x86.M1                             cc_x86, written in M1
    M2-Planet                                 a fuller C compiler, in C
    mescc-tools/M1-macro.c                    M1-macro, a fuller assembler, in C
    mescc-tools/hex2_linker.c                 hex2 again, in C, without the fixed table

| link | adds |
| ---- | ---- |
| hex0 | hexadecimal pairs become bytes |
| hex1 | single character labels, and relative pointers to them |
| hex2 | labels with names, pointers with widths: a linker |
| catm | concatenating files, so a header can be put in front of a program |
| M0   | macros, strings and immediates: the first real language |
| cc_x86 | a subset of C, large enough to compile M2-Planet |
| M2-Planet | the rest of the C this project's programs are written in |
| M1-macro | more label and pointer widths, and every architecture stage0 supports, in one binary |
| hex2 (from C) | the same linker without the hand-written one's fixed label table |

## Building

Clone with submodules -- from cc_x86 up, the build compiles C, and M2-Planet,
M2libc and mescc-tools are vendored as submodules rather than by hand, since
they are upstream's exactly as upstream wrote them:

    git clone --recurse-submodules <this repo>

On Windows:

    x86\mescc-tools-mini.cmd

Upstream drives the equivalent sequence with kaem, a shell it has to bootstrap
first. Windows always has cmd.exe, so there is nothing to bootstrap: the build
script is ordinary batch, and it is the only part of this that is not built
from source here.

The first thing the build does is assemble `hex0_x86.hex0` with the seed and
require the result to be identical to the seed. If that check fails, stop.

## How this differs from stage0-posix

There are no syscalls. A PE32 image here imports nothing at all: it finds ntdll
through the PEB at run time and resolves the handful of routines it needs from
ntdll's export table by name. There is no import table to inspect and nothing
between the file and the kernel.

That plumbing is the same in every program, so from M0 upward it lives in
`x86/ntdll-i386.hex2` and catm puts it in front of the program, the way it puts
the header stub in front of both. Part of it is splitting the command line,
because Windows hands a program one string rather than a vector: from M0 up
that split is the whole rule `CommandLineToArgvW` defines, backslash escaping
and all, since anything that launches another program writes an embedded quote
as `\"` and an argument cut off at the first one is worse than useless. hex0, hex1, hex2 and catm cannot use it --
there is no catm below catm to join files with -- so they carry their own
copies. Upstream has the same arrangement in `x86/libc-core.M1`.

There is no `brk`. `x86/PE32-i386.hex2` gives every program a section whose
VirtualSize runs to the top of a 128 MB image, so the memory past the end of
the file is already mapped and already zero. A program declares a buffer by
putting a label after `:PE_end` and never asks the operating system for memory.
16 MB was the original figure and was not enough: M0 processing the M1 that
builds M2-Planet wants over 22 MB of it.

`SectionAlignment` is the page size, and the header pads to 0x1000 to match.
The format permits less, and wine accepts less, but Windows 11 refuses such an
image with ERROR_BAD_EXE_FORMAT. `SizeOfRawData`, which the format says must be
a multiple of `FileAlignment`, is left as the exact length of the program, and
that Windows does accept. Both of these were measured rather than assumed.

There is no kaem, and there may never be one: see Building above.

## Where the sources come from

The `.hex0`, `.hex1` and `.hex2` files are generated, by the scripts in
`x86/Development/`, and they are the reviewable artefact -- every byte carries
the instruction it encodes and the reason for it. Regenerate and re-verify them
with:

    x86/Development/regenerate.sh

Each generator assembles its own output and compares it against the binary it
describes, so a source that has drifted from its binary fails there rather than
later.

`x86/cc_x86.M1` is the exception, because it is readable assembly rather than
hex and because the compiler in it is upstream's and is not being ported. It is
derived from upstream's `x86/cc_x86.M1` by `x86/Development/port_cc_x86.py`,
which is written as a list of exact before-and-after passages: every one of them
must match, so if upstream moves under any of the places this port replaces, the
script fails rather than quietly producing something nobody has read. Point
`CC_X86_UPSTREAM` at an upstream checkout's `x86/cc_x86.M1` to re-derive it:

    CC_X86_UPSTREAM=../stage0-posix/x86/cc_x86.M1 x86/Development/regenerate.sh

The whole of the port is `_start`, `malloc`, `fgetc`, `fputc`, `Exit_Failure`
and the name of the label that ends the image. Feed the same C to upstream's
`cc_x86` and to this one and the two outputs differ in exactly one line, the
`:ELF_end` that becomes `:PE_end`. The binaries share nothing -- different
format, different entry, different plumbing -- but the compiler between them is
demonstrably the same compiler.

From cc_x86 up, the chain compiles C rather than hand-written assembly, and the
C it compiles first is M2-Planet's own: `M2-Planet/`, `M2libc/` and
`mescc-tools/` are git submodules, pinned to the exact commits stage0-posix
itself vendors them at, because nothing in them is Windows-specific and there
is nothing to port. `x86/libc-core.M1` and `x86/M2libc-windows/bootstrap.c` are
what M2-Planet and M1-macro compile against instead of
`M2libc/x86/linux/bootstrap.c` -- the argc/argv/exit plumbing a C program
needs, standing on `x86/ntdll-i386.hex2` the same way `x86/cc_x86.M1` does. See
their own headers for what each routine does.

The two C libraries need different things set up before `main` runs, so
`libc-core.M1`'s `_start` calls `:__libc_init` and catm decides what that is:
`x86/libc-bootstrap.M1`, which does nothing, or `x86/libc-full.M1`, which calls
M2libc's `__init_malloc` and `__init_io`. The second is not optional and its
absence is quiet: `stdin`, `stdout` and `stderr` are globals that start NULL,
so a program linked without it works until the first time it tries to report an
error and then faults inside `fputs` instead of printing it. hex2 built from C
did exactly that, on every error path, until this existed.

`M2libc/x86/x86_defs.M1` -- the submodule's copy, not a copy of it -- matters
more than its name suggests: it is the mnemonic set M2's own code generator
actually emits, wider than what cc_x86.M1's hand-written assembly happens to
use. Getting this wrong doesn't fail loudly. M0 passes an unrecognized
mnemonic through as plain text rather than erroring, hex2 can't make sense of
it either, and the instruction is silently dropped: the build succeeds, the
binary comes out a few bytes short, and the failure surfaces later as an
illegal instruction somewhere unrelated.

That cost two debugging sessions -- the wrong `x86_defs.M1` entirely while
bringing up M1-macro, then three mnemonics missing from `libc-core.M1` while
bringing up hex2. The first was confirmed to be neither a PE32 issue nor an
upstream one by reproducing it identically on upstream's own native, ELF,
years-old `M1` binary once fed the same wrong file. `regenerate.sh` now runs
`x86/Development/check_mnemonics.py`, which fails on a mnemonic nothing
DEFINEs; it is checked against both of those bugs.

M2-Planet's own C is unmodified, so it always ends its output with `:ELF_end`,
the label its ELF header expects; `PE32-i386.hex2` expects `:PE_end`.
`x86/pe-end-shim.M1` defines `:PE_end` at that same address without touching
the vendored source -- catm puts it right after M2's output.

`x86/M2libc-windows/` is where the port actually lives. `bootstrap.c` is the
whole C library for the stages that can use `--bootstrap-mode`; `unistd.c`,
`fcntl.c` and `sys/stat.c` are the POSIX layer underneath M2libc's own
`stdio.c` for the stages that cannot. A file descriptor is a Windows HANDLE,
with 0, 1 and 2 still meaning the three standard streams -- no real handle is
that small, so nothing above can tell. `brk` has nothing to ask the kernel for,
since the image carries its writable memory with it, and `chmod` does nothing
and returns success, which is the honest answer on a system where a file is
executable because its PE header says so.

Everything M2libc's `unistd.h` and `sys/stat.h` declare is there.
`x86/M2libc-windows/ntdll.c` is what the rest of it stands on: `__ntdll(slot)`
hands back a routine ntdll-i386.hex2 resolved, and `__ntobject(path)` turns a
filename into the OBJECT_ATTRIBUTES around an NT path that every ntdll call
naming a file wants. `x86/M2libc-windows/ntdll-slots.h` says which slot is
which and is generated, from the same list `ntdll-i386.hex2` is, so the two
cannot drift apart. `x86/Development/posix-test.c` calls every routine once and
checks the answer.

Where Windows has no answer -- `chroot`, `mount`, `unshare`, `symlink`,
`mknod`, `fchdir` -- the call fails, and says why above itself. Failing is the
point: `chmod` returning 0 is honest because a PE runs on account of its
header, and `chroot` returning 0 would not be.

Calling ntdll from compiled C works because of an accident of M2-Planet's code
generator, and comes with a rule that has to be kept by hand. M2-Planet saves
the stack pointer in EBP before pushing arguments and restores it from there
afterwards, so it never adds back what it pushed -- which is what lets it call
stdcall routines that pop their own arguments. It also pushes the first
argument first, so every call below is written backwards. And it holds the
pointer it is about to call in EDX across the argument list without saving it,
so an argument that writes EDX -- a function call, a `*` or `/` or `%`, an
array subscript -- replaces the address about to be called, and the program
jumps to zero with nothing to say where it came from. That cost three
debugging rounds in one sitting, so `x86/Development/check_fnptr_args.py`
fails on one now, and is checked against all three.

`x86/M2libc-windows/process.c` is starting another program and waiting for it,
and it is the one place this port cannot keep the POSIX shape. fork's whole
meaning is that the child comes back from the same call with the same memory,
and Windows has no call that does that -- ntdll's `RtlCloneUserProcess` is the
nearest thing, clones an address space the Win32 side knows nothing about, and
cannot be tested here at all, since wine does not export it. So `fork` fails
and says why, and the three steps of fork-exec-wait are taken apart into ones
Windows can do:

    __spawn(path, argv, envp)   start a program; a handle to it comes back
    waitpid(pid, &status, 0)    wait for one of those to finish
    execve(path, argv, envp)    both of the above, and then exit as it did

A pid is the process handle, the way a file descriptor is a file handle.
`execve` does not replace the running image, because nothing on Windows can,
but it does not return either and the process's exit status is the child's.
A caller that today says `fork()` then `execve` in the child and `waitpid` in
the parent says `__spawn` then `waitpid` instead, and needs no fork; that is
the change `kaem` and M2-Mesoplanet would want, and it is two lines.

The child is meant to inherit this process's three standard handles, which is
what would make redirection possible, and here the port has a defect: it works
under wine and not on Windows. The handles are duplicated with `OBJ_INHERIT`
and their numbers written into the child's parameter block, the child reads the
same numbers back out of its own PEB, and `NtWriteFile` to them returns success
and a count -- and on Windows the bytes go nowhere. A child still runs, still
reads and writes files it opens itself, and still reports its exit status,
which are checked on Windows; only handles it was given rather than opened are
affected. Nothing built here depends on it, because every program in this chain
opens its own files, but a shell would. Windows hands a child one string rather than a vector,
so `__spawn` joins argv into one and the child splits it again; both halves
follow `CommandLineToArgvW`, so an argument survives whatever is in it.
`C:\dir\` is the case that makes the rule worth following exactly rather than
approximately: quoted naively it ends `...dir\"`, and the reader takes that
backslash to be protecting the closing quote and swallows the rest of the
command line.

`x86/Development/spawn-test.c` starts a program, waits for it, reads back what
it exited with, and ends by calling `execve` and not coming back.

M1-macro is a fuller assembler than M0: more label and pointer widths, every
architecture stage0 supports in one binary. Upstream also runs this stage's
output through `blood-elf`, and this port does not, which is worth setting out
properly because everything downstream of here -- GNU Mes included -- runs
blood-elf too.

Three things go together, and all three are debugging. `--debug` makes
M2-Planet end its output with `:ELF_data` instead of `:ELF_end`. blood-elf
then reads that output and writes an ELF string table, symbol table and
section headers -- and the `:ELF_end` M2-Planet did not write. The "debug" ELF
header declares five sections and refers to `:ELF_section_headers`, which is
why it needs blood-elf's output to link at all. Drop `--debug`, drop blood-elf
and use the plain ELF header, and M2-Planet emits `:ELF_end` itself; the plain
header wants nothing from outside but that label and `:_start`. Which is
exactly the shape `PE32-i386.hex2` has, with `:PE_end` for `:ELF_end`.

So there is nothing to port, and the symbol table is what `objdump` and `gdb`
read and nothing else does. Checked on GNU Mes rather than argued: built at
`f244b14` twice with native tools, once as `kaem.run` ships and once with
`--debug` and blood-elf removed and the plain ELF header in place. Both
`bin/mes-m2` binaries run, agree character for character on a program
exercising recursion, `map`, `assq`, strings and `write`, and pass the same ten
of Mes's own tests. The blood-elf one is 232686 bytes and the other 131262:
the whole difference is the debugging information.

## Licence

GNU General Public License version 3 or later, as upstream is. See `LICENSE`.

`LICENSE.EXCEPTION` adds a permission under section 7 for embedding these files
and the binaries built from them in a package repository without the repository
as a whole becoming GPL, so long as these files themselves stay GPL.

## Thanks

To Jeremiah Orians and everyone on #bootstrappable, whose work this is a port
of. The design is theirs; the mistakes in this port are not.
