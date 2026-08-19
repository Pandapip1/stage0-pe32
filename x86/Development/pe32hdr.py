#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""The PE32 header written in hex2's language, and a hex2 simulator.

The header stub is the PE counterpart of stage0's x86/ELF-i386.hex2: a fixed
prologue that hex2 assembles ahead of a program so the result is a runnable
executable.  Every field that depends on where the program ends is a hex2
pointer, so the same text serves any program.
"""
import struct

import os
IMAGE_BASE = 0x400000
HDR_SIZE   = int(os.environ.get("NOVA_HDR",   "0x1000"), 0)
SECT_ALIGN = int(os.environ.get("NOVA_SECT",  "0x1000"), 0)
FILE_ALIGN = int(os.environ.get("NOVA_FILE",  "0x200"), 0)
ALIGN      = SECT_ALIGN
IMAGE_SIZE = int(os.environ.get("NOVA_IMAGE", "0x1000000"), 0)
VSIZE      = IMAGE_SIZE - HDR_SIZE # the section covers the rest of it
TEXT_BASE  = IMAGE_BASE + HDR_SIZE

DOS = bytes.fromhex(
    "4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00"
    "B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    "00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 00".replace(" ", ""))
assert len(DOS) == 0x40

# (bytes-or-token, comment).  A str entry is a hex2 pointer, emitted verbatim.
def _f():
    F = []
    def b(hexstr, comment=None):
        F.append((bytes.fromhex(hexstr.replace(" ", "")), comment))
    def tok(t, comment):
        F.append((t, comment))
    def d4(v, comment):
        F.append((struct.pack("<I", v), comment + " = 0x%x" % v))

    F.append(("##label", "PE_base"))
    F.append(("##head", "DOS header"))
    b("4D 5A", "e_magic 'MZ'")
    for off, name in [(2,"e_cblp"),(4,"e_cp"),(6,"e_crlc"),(8,"e_cparhdr"),(10,"e_minalloc"),
                      (12,"e_maxalloc"),(14,"e_ss"),(16,"e_sp"),(18,"e_csum"),(20,"e_ip"),
                      (22,"e_cs"),(24,"e_lfarlc"),(26,"e_ovno")]:
        b("%02X %02X" % (DOS[off], DOS[off+1]), name)
    b("00 00 00 00 00 00 00 00", "e_res[4]")
    b("00 00", "e_oemid")
    b("00 00", "e_oeminfo")
    b("00 " * 20, "e_res2[10]")
    b("40 00 00 00", "e_lfanew -> the PE header at file offset 0x40 (no DOS stub program)")

    F.append(("##head", "COFF header"))
    b("50 45 00 00", "Signature 'PE\\0\\0'")
    b("4C 01", "Machine = 0x014c (i386)")
    b("01 00", "NumberOfSections = 1 (code and data share one section)")
    b("00 00 00 00", "TimeDateStamp = 0: nothing here depends on when it was built")
    b("00 00 00 00", "PointerToSymbolTable")
    b("00 00 00 00", "NumberOfSymbols")
    b("60 00", "SizeOfOptionalHeader = 0x60 (the PE32 optional header with no data directories)")
    b("0F 03", "Characteristics = 0x030f (executable, 32-bit, no relocations/line numbers/symbols)")

    F.append(("##head", "Optional header"))
    b("0B 01", "Magic = 0x010b (PE32)")
    b("00", "MajorLinkerVersion")
    b("00", "MinorLinkerVersion")
    tok("%PE_end>PE_text", "SizeOfCode: everything hex2 emits after this header")
    b("00 00 00 00", "SizeOfInitializedData")
    b("00 00 00 00", "SizeOfUninitializedData")
    tok("%_start>PE_base", "AddressOfEntryPoint: the program defines _start")
    d4(HDR_SIZE, "BaseOfCode")
    b("00 00 00 00", "BaseOfData")
    b("00 00 40 00", "ImageBase = 0x400000")
    d4(SECT_ALIGN, "SectionAlignment")
    d4(FILE_ALIGN, "FileAlignment")
    b("04 00", "MajorOperatingSystemVersion")
    b("00 00", "MinorOperatingSystemVersion")
    b("00 00", "MajorImageVersion")
    b("00 00", "MinorImageVersion")
    b("04 00", "MajorSubsystemVersion")
    b("00 00", "MinorSubsystemVersion")
    b("00 00 00 00", "Win32VersionValue")
    d4(IMAGE_SIZE, "SizeOfImage")
    d4(HDR_SIZE, "SizeOfHeaders")
    b("00 00 00 00", "CheckSum = 0, which is accepted for anything but a kernel image")
    b("03 00", "Subsystem = 3 (console)")
    b("00 01", "DllCharacteristics = 0x0100 (NX compatible)")
    b("00 00 20 00", "SizeOfStackReserve")
    b("00 10 00 00", "SizeOfStackCommit")
    b("00 00 10 00", "SizeOfHeapReserve")
    b("00 10 00 00", "SizeOfHeapCommit")
    b("00 00 00 00", "LoaderFlags")
    b("00 00 00 00", "NumberOfRvaAndSizes = 0 (no data directories, so no import table)")

    F.append(("##head", "Section header"))
    b("2E 74 65 78 74 00 00 00", "Name = '.text'")
    d4(IMAGE_SIZE - HDR_SIZE, "VirtualSize")
    d4(HDR_SIZE, "VirtualAddress")
    tok("%PE_end>PE_text", "SizeOfRawData: the rest is past the end of the file and zero-filled")
    d4(HDR_SIZE, "PointerToRawData")
    b("00 00 00 00", "PointerToRelocations")
    b("00 00 00 00", "PointerToLinenumbers")
    b("00 00", "NumberOfRelocations")
    b("00 00", "NumberOfLinenumbers")
    b("20 00 00 E0", "Characteristics = 0xe0000020 (code, executable, readable, writable)")

    F.append(("##head", "Padding to SizeOfHeaders"))
    n = HDR_SIZE - 0xE0
    for i in range(0, n, 16):
        b("00 " * min(16, n - i), None)
    F.append(("##label", "PE_text"))
    return F

FIELDS = _f()

def header_lines():
    """The stub as text, in ELF-i386.hex2's layout: one field per line."""
    L = []
    for x, c in FIELDS:
        if x == "##label":
            L += ["", ":" + c]
        elif x == "##head":
            L += ["", "## " + c]
        elif isinstance(x, str):
            L.append(("%-31s # %s" % (x, c)).rstrip())
        else:
            h = " ".join("%02X" % v for v in x)
            L.append(("%-31s # %s" % (h, c)).rstrip() if c else h)
    return L

def header_bytes(pe_end, start):
    """The same fields with the two pointers resolved, for cross-checking."""
    o = bytearray()
    for x, _c in FIELDS:
        if isinstance(x, str):
            if x.startswith("##"):
                continue
            v = {"%PE_end>PE_text": pe_end - TEXT_BASE,
                 "%_start>PE_base": start - IMAGE_BASE}[x]
            o += struct.pack("<I", v)
        else:
            o += x
    assert len(o) == HDR_SIZE, len(o)
    return bytes(o)


HEXDIGITS = "0123456789abcdefABCDEF"
NAMEEND = b" \t\n\r>"

def assemble_hex2(src):
    """hex2: hex0 plus ':name' labels and the five sized pointers, resolved over
    two passes exactly as the ported hex2 does.  ip counts from the image base."""
    def name_at(i):
        j = i
        while j < len(src) and src[j] not in NAMEEND:
            j += 1
        return src[i:j], j

    def walk(emit, table):
        o = bytearray(); ip = IMAGE_BASE; hi = None; i = 0
        while i < len(src):
            c = src[i]
            if c in (0x23, 0x3b):                       # '#' ';'
                while i < len(src) and src[i] != 0x0a: i += 1
                continue
            if c == 0x3a:                               # ':' label
                nm, i = name_at(i + 1)
                if not emit: table[nm] = ip
                continue
            if c in (0x21, 0x40, 0x25, 0x24, 0x26):     # ! @ % $ & pointer
                size = {0x21: 1, 0x40: 2, 0x25: 4, 0x24: 2, 0x26: 4}[c]
                absolute = c in (0x24, 0x26)
                nm, i = name_at(i + 1)
                base = None
                if i < len(src) and src[i] == 0x3e:      # '>' base label
                    base, i = name_at(i + 1)
                ip += size
                if emit:
                    v = table[nm] if absolute else \
                        table[nm] - (table[base] if base else ip)
                    o += struct.pack("<i", v & 0xffffffff if v >= 0 else v)[:size]
                continue
            ch = chr(c)
            if ch in HEXDIGITS:
                v = int(ch, 16)
                if hi is None: hi = v
                else:
                    if emit: o.append(hi * 16 + v)
                    ip += 1; hi = None
            i += 1
        return o
    table = {}
    walk(False, table)
    return walk(True, table)
