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

| link | adds |
| ---- | ---- |
| hex0 | hexadecimal pairs become bytes |
| hex1 | single character labels, and relative pointers to them |
| hex2 | labels with names, pointers with widths: a linker |
| catm | concatenating files, so a header can be put in front of a program |
| M0   | macros, strings and immediates: the first real language |
| cc_x86 | a subset of C, large enough to compile M2-Planet |

## Building

Clone with submodules -- from cc_x86 up, the build compiles C, and M2-Planet
and M2libc's bootstrap C library are vendored as submodules rather than by
hand, since they are upstream's exactly as upstream wrote them:

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
the header stub in front of both. hex0, hex1, hex2 and catm cannot use it --
there is no catm below catm to join files with -- so they carry their own
copies. Upstream has the same arrangement in `x86/libc-core.M1`.

There is no `brk`. `x86/PE32-i386.hex2` gives every program a section whose
VirtualSize runs to the top of a 16 MB image, so the memory past the end of the
file is already mapped and already zero. A program declares a buffer by putting
a label after `:PE_end` and never asks the operating system for memory.

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
C it compiles first is M2-Planet's own: `M2-Planet/` and `M2libc/` are git
submodules, pinned to the exact commits stage0-posix itself vendors them at,
because nothing in them is Windows-specific and there is nothing to port.
`x86/libc-core.M1` and `x86/M2libc-windows/bootstrap.c` are what M2-Planet
compiles against instead of `M2libc/x86/linux/bootstrap.c` -- the argc/argv/exit
plumbing a C program needs, standing on `x86/ntdll-i386.hex2` the same way
`x86/cc_x86.M1` does. See their own headers for what each routine does.

## Licence

GNU General Public License version 3 or later, as upstream is. See `LICENSE`.

`LICENSE.EXCEPTION` adds a permission under section 7 for embedding these files
and the binaries built from them in a package repository without the repository
as a whole becoming GPL, so long as these files themselves stay GPL.

## Thanks

To Jeremiah Orians and everyone on #bootstrappable, whose work this is a port
of. The design is theirs; the mistakes in this port are not.
