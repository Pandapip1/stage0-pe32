#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail if an .M1 file uses a mnemonic nothing DEFINEs.

M0 does not diagnose this.  An unrecognized token is passed through unchanged,
hex2 cannot make sense of it either, and the instruction is silently dropped --
so the build succeeds, the binary is short by a few bytes, and the failure
turns up later as an illegal instruction somewhere unrelated.  That has cost
this project a debugging session twice: once bringing up M1-macro (the wrong
x86_defs.M1 entirely, so every mnemonic M2's code generator emits beyond
cc_x86's narrower set was dropped), once bringing up hex2 (three mnemonics in
libc-core.M1 that only M2libc's x86_defs.M1 was expected to carry).

  python3 check_mnemonics.py FILE.M1 [MORE.M1 ...]

Every file is read for both its DEFINEs and its uses, so pass the whole set
that will be concatenated, in any order.

This tokenizes rather than reading lines, because neither indentation nor line
structure is reliable: hand-written M1 indents its instructions and M2's
generated M1 does not, a "string" may span lines, and '20 3A 00' is a hex
string that would otherwise read as code.  M1's lexical rules, from
mescc-tools/M1-macro.c: whitespace separates tokens, " and ' each open a
literal that runs to its matching close, and # and ; each open a comment that
runs to end of line.
"""
import re
import sys

SIGILS = '%&$@!<'


def tokenize(text):
    """Yield (lineno, token) for every M1 token outside strings and comments."""
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == '\n':
            line += 1
            i += 1
        elif c.isspace():
            i += 1
        elif c in '#;':
            while i < n and text[i] != '\n':
                i += 1
        elif c in '"\'':
            i += 1
            while i < n and text[i] != c:
                if text[i] == '\n':
                    line += 1
                i += 1
            i += 1  # the closing quote
        else:
            start, startline = i, line
            while i < n and not text[i].isspace() and text[i] not in '#;':
                i += 1
            yield startline, text[start:i]


def scan(paths):
    defined = set()
    used = []
    for path in paths:
        toks = list(tokenize(open(path, errors="replace").read()))
        skip_next = False
        for lineno, tok in toks:
            if skip_next:
                skip_next = False
                defined.add(tok)
                continue
            if tok == "DEFINE":
                skip_next = True
                continue
            if tok.startswith(':'):
                continue
            if tok[0] in SIGILS:
                continue
            if re.fullmatch(r'[0-9A-Fa-f]+', tok):
                continue
            used.append((path, lineno, tok))
    return defined, used


def main(argv):
    if len(argv) < 2:
        raise SystemExit(__doc__)
    defined, used = scan(argv[1:])
    bad = [(p, n, t) for p, n, t in used if t not in defined]
    seen = set()
    for path, n, tok in bad:
        if tok in seen:
            continue
        seen.add(tok)
        print("%s:%d: no DEFINE for %s" % (path, n, tok), file=sys.stderr)
    if bad:
        raise SystemExit("check_mnemonics: %d use(s) of %d undefined mnemonic(s)"
                         % (len(bad), len(seen)))
    print("mnemonics: %d used, all defined" % len(used))


if __name__ == "__main__":
    main(sys.argv)
