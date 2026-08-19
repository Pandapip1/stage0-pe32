#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Write ntdll-i386.hex2, the routines every program above catm shares."""
import sys
from stage0asm import Asm, spdx, PORT
from pe32emit import emit_pe_hex2
from pe32shared import emit_shared, SHARED_DOC, BOUNDARY

a = Asm()
emit_shared(a)
BANNER = "\n".join(spdx([PORT])) + """ntdll-i386.hex2: what every program above catm needs from Windows.

There is no syscall a user program may make directly here, so each of these
programs has to find ntdll through the PEB, resolve what it needs out of the
export table by name, and turn a DOS path into the NT path NtCreateFile wants.
That cost is the same in every program, so from M0 upward it lives in this file
and catm puts it in front of the program:

  catm prog.hex2 PE32-i386.hex2 ntdll-i386.hex2 body.hex2

hex0, hex1, hex2 and catm cannot use it -- there is no catm below catm to join
files with -- so they carry their own copies.

  resolve_all()   fill in the eight fn_ slots; call it first
  open_argv()     argv[1] for reading, argv[2] for writing
  fgetc()         the next input byte, or -4 at end of file
  fputc(al)       one byte to the output
  exit_ok()       close both files and exit 0

The image imports nothing, so there is no import table to inspect and nothing
between these programs and the kernel."""

sys.exit(0 if emit_pe_hex2(a, BANNER, SHARED_DOC, "name_NtCreateFile",
                           sys.argv[1], sys.argv[2], "ntdll-i386",
                           inline_header=False, entry=BOUNDARY, verify=False, emit_tail=False) else 1)
