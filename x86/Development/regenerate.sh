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
python3 gen_m0.py     /tmp/M0.exe   ../M0_x86.hex2
cmp /tmp/hex0.exe ../../bootstrap-seeds/PE32/i386/hex0-seed.exe \
  && echo "seed still reproduces"
