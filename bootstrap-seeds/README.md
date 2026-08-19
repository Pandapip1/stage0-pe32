<!--
SPDX-FileCopyrightText: (C) 2026 Gavin John

SPDX-License-Identifier: GPL-3.0-or-later
-->

# bootstrap-seeds

`PE32/i386/hex0-seed.exe` is the one binary in this project that nothing else
here vouches for: everything above it is built from source by the chain, but
the chain has to start somewhere.

It is 1623 bytes, and `../x86/hex0_x86.hex0` is its annotated source. The first
thing `mescc-tools-mini.cmd` does is assemble that source with this binary and
require the result to be identical to it, so the seed can be audited by reading
1623 bytes of commented hex rather than by trusting whoever compiled it.

It imports nothing. ntdll is found through the PEB at run time and the handful
of routines it calls are resolved from ntdll's export table by name, so there
is no import table to inspect and nothing to tamper with between the file and
the kernel.
