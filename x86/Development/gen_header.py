#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write PE32-i386.hex2, the standalone header stub."""
import sys
from stage0asm import block, spdx, UPSTREAM, PORT
from pe32hdr import header_lines

BANNER = "\n".join(spdx([PORT])) + """PE32-i386.hex2: the PE32/i386 executable header, in hex2's language.

hex2 emits bytes; it knows nothing about executable formats.  This file is the
header a Windows program needs, written so that hex2 fills in the fields that
depend on the program:

  catm prog.hex2 PE32-i386.hex2 body.hex2
  hex2 prog.hex2 prog.exe

The program must define _start and must end with :PE_end.

hex2's pointers
  !name  one byte relative    $name  two bytes absolute
  @name  two bytes relative   &name  four bytes absolute
  %name  four bytes relative  name>base  measured from base, not from here

ip counts from the image base, so a label's value is the address it will have
once loaded.  For that to be right, an RVA has to be the same number as a file
offset, which is why SizeOfHeaders, the section's VirtualAddress and its
PointerToRawData are all 0x1000: the section begins at the same place in the
file as it does in memory, and hex2, which only counts bytes, needs nothing
more.

SectionAlignment is the page size.  The format allows less -- FileAlignment
must then match it -- but Windows rejects such an image with
ERROR_BAD_EXE_FORMAT, so the padding to 0x1000 below is not optional.
SizeOfRawData, by contrast, is left exactly as long as the program is, and no
multiple of FileAlignment, which Windows does accept.

The section's VirtualSize runs to the top of the image, so everything between
the end of the file and 0x8400000 is zero-filled writable memory.  A program
declares a buffer by putting a label after :PE_end and never has to ask for
memory at run time.

The image imports nothing: NumberOfRvaAndSizes is 0, so there is no import
directory.  A program reaches ntdll through the PEB instead."""

open(sys.argv[1], "w").write("\n".join(block(BANNER) + header_lines()) + "\n")
