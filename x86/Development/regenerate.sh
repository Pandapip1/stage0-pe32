#!/bin/sh
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Regenerate every source in ../ from the generators here, and check that each
# one still assembles to exactly the binary it describes.
set -e
cd "$(dirname "$0")"
python3 gen_hex0.py   /tmp/hex0.exe ../hex0_x86.hex0 hex0_32-original.exe
python3 gen_hex1.py   /tmp/hex1.exe ../hex1_x86.hex0 hex0_32-original.exe
python3 gen_hex2.py   /tmp/hex2.exe ../hex2_x86.hex1 hex0_32-original.exe
python3 gen_header.py ../PE32-i386.hex2
python3 gen_catm.py   /tmp/catm.exe ../catm_x86.hex2
python3 gen_ntdll.py  /tmp/ntdll.exe ../ntdll-i386.hex2
python3 gen_m0.py     /tmp/M0.exe   ../M0_x86.hex2 ../ntdll-i386.hex2
cmp /tmp/hex0.exe ../../bootstrap-seeds/PE32/i386/hex0-seed.exe \
  && echo "seed still reproduces"

# cc_x86.M1 is readable assembly rather than hex, so it is not written from
# scratch here: port_cc_x86.py patches upstream's copy.  Point CC_X86_UPSTREAM
# at a stage0-posix checkout's x86/cc_x86.M1 to re-derive it and see whether
# upstream has moved under any of the passages the port replaces.
if [ -n "${CC_X86_UPSTREAM:-}" ]; then
  python3 port_cc_x86.py "$CC_X86_UPSTREAM" ../cc_x86.M1
else
  echo "cc_x86: not re-derived (set CC_X86_UPSTREAM to upstream's x86/cc_x86.M1)"
fi
