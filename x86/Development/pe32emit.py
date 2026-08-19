#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Emit a program as a hex2 source file with the PE32 header inlined.

hex0 and hex1 sources spell every address out, because their languages have no
way to name one.  hex2 does, so from here on a program is written with labels
and the header stub resolves them.  The .exe is still built here as well, purely
so the generated source can be checked against it before anything runs.
"""
import struct
from stage0asm import block, datline, insnline
from pe32hdr import (IMAGE_BASE, HDR_SIZE, TEXT_BASE, IMAGE_SIZE,
                     header_lines, header_bytes, assemble_hex2)


def emit_pe_hex2(a, banner, DOC, data_label, out_exe, out_hex, name,
                 inline_header=True, code_marks=(), prefix_files=(),
                 drop_through=None, entry="_start", verify=True, emit_tail=True):
    a.org = TEXT_BASE
    body, lines, labels = a.assemble()
    bss_total = sum(sz for _n, sz, _c in a.bss)
    assert TEXT_BASE + len(body) + bss_total <= IMAGE_BASE + IMAGE_SIZE, "image too small"
    pe_end = TEXT_BASE + len(body)
    exe = header_bytes(pe_end, labels[entry]) + body

    # A four-byte field that holds a label's address is written &label, and a
    # relative displacement %label; hex2 resolves both.
    at = {}
    for nm, ad in labels.items():
        at.setdefault(ad, nm)

    L = block(banner)
    if inline_header:
        L += header_lines()

    group, in_data = [], [False]
    def flush(comment):
        if not group:
            return
        text = " ".join(group)
        del group[:]
        if in_data[0]:
            L.append(("%-31s # %s" % (text, comment)).rstrip() if comment else text)
        elif comment is None:
            L.append("\t" + text)
        else:
            mn, _, prose = comment.partition("  -- ")
            L.append(("\t%-27s ; %-27s # %s" % (text, mn, prose)).rstrip() if prose
                     else ("\t%-27s ; %s" % (text, mn)).rstrip())

    L += ["", "## ==== .text : one line per instruction ===="]
    for kind, x, comment, meta in lines:
        if kind == "label":
            flush(None)
            L.append("")
            if x == data_label or x in getattr(emit_pe_hex2, "_extra_data", ()):
                L += ["## ==== .data ====", ""]
                in_data[0] = True
            if x in code_marks:
                in_data[0] = False
            if x in DOC:
                L += block(DOC[x])
            L.append(":" + x)
        elif kind == "note":
            flush(None)
            L += block(x)
        else:
            if meta and meta[0] == "rel32":
                group.append("%" + meta[1])
            elif len(x) == 4 and struct.unpack("<I", x)[0] in at:
                group.append("&" + at[struct.unpack("<I", x)[0]])
            else:
                group.append(" ".join("%02X" % b for b in x))
            if comment is not None:
                flush(comment)
    flush(None)

    if emit_tail:
        L += ["", "# SizeOfCode and SizeOfRawData are measured to here.", ":PE_end"]
    if emit_tail and a.bss:
        L += ["", "## ==== reserved, zero-filled by the loader (past the end of the file) ===="]
        for nm, sz, note in a.bss:
            L.append(":%s%s" % (nm, ("  # %d bytes  -- %s" % (sz, note)) if note
                                    else "  # %d bytes" % sz))

    if drop_through is not None:
        # Everything up to this label is in a file of its own, catm'd in ahead
        # of this one; keep it in the layout so labels resolve, drop it here.
        cut = next(i for i, line in enumerate(L) if line == ":" + drop_through)
        L = block(banner) + L[cut + 1:]

    open(out_exe, "wb").write(exe)
    open(out_hex, "w").write("\n".join(L) + "\n")

    if not verify:
        # Not a program on its own: it is checked where it is actually used.
        print("%s: code+data %d (checked as part of the program that includes it)"
              % (name, len(body)))
        return True

    text = open(out_hex, "rb").read()
    for extra in reversed(prefix_files):
        text = open(extra, "rb").read() + text
    if not inline_header:
        # what catm will hand hex2: the stub, then everything catm'd after it
        text = ("\n".join(header_lines()) + "\n").encode() + text
    got = bytes(assemble_hex2(text))
    ok = got == exe
    print("%s: code+data %d, file %d, entry 0x%x" % (name, len(body), len(exe), labels[entry]))
    print("  round-trip:", "IDENTICAL" if ok else "MISMATCH")
    if not ok:
        for i in range(min(len(got), len(exe))):
            if got[i] != exe[i]:
                print("  first difference at 0x%x: %02x != %02x" % (i, got[i], exe[i]))
                break
        print("  lengths: %d vs %d" % (len(got), len(exe)))
    return ok
