#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail on an argument to a function pointer call that would clobber EDX.

M2-Planet compiles `f(a, b)` where f is a pointer by moving the pointer into
EDX, evaluating the arguments, and moving EDX back into EAX to call it.  It
does not save EDX in between, so anything in the argument list that writes EDX
replaces the address about to be called.  What is left there is usually zero,
so the symptom is a jump to address 0 with nothing on the stack to say where it
came from.  Three things write EDX on x86:

  a function call        cc_core.c function_call, which uses EDX itself
  * / and %              imul_ebx, idiv_ebx: cc_core.c arithmetic_recursion
  subscripting an array  the index is multiplied by the element size

None of it is diagnosed by anything: it compiles, links and runs until it
doesn't.  This is the same shape of hazard as a mnemonic no x86_defs.M1
defines, and check_mnemonics.py is its sibling.

The rule this enforces is that every argument to a call through a pointer must
be a local, a global or a constant, with anything computed worked out onto a
line of its own first.
"""
import re
import sys

# `int (*name)(...)` -- how a function pointer is declared, and the only way
# this file knows a call is through one.
DECL = re.compile(r"\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\(")


def split_args(text, at):
    """The argument list starting at the '(' at `at`, split on top-level commas.

    Returns (args, end) or (None, None) if the parentheses do not close.
    """
    depth = 0
    args = []
    start = at + 1
    i = at
    while i < len(text):
        c = text[i]
        if c == '"' or c == "'":
            i = i + 1
            while i < len(text) and text[i] != c:
                if text[i] == "\\":
                    i = i + 1
                i = i + 1
        elif c in "([":
            depth = depth + 1
        elif c in ")]":
            depth = depth - 1
            if depth == 0:
                args.append(text[start:i])
                return args, i
        elif c == "," and depth == 1:
            args.append(text[start:i])
            start = i + 1
        i = i + 1
    return None, None


def offending(arg):
    """What in this argument writes EDX, if anything."""
    a = arg.strip()
    if not a:
        return None
    if re.search(r"[A-Za-z0-9_)\]]\s*\(", a):
        return "a function call"
    if "[" in a:
        return "an array subscript, which is a multiply"
    # A binary * or / or %, as opposed to a dereference or a pointer type.
    if re.search(r"[A-Za-z0-9_)\]]\s*[*/%]", a):
        return "a multiply, divide or remainder"
    return None


def check(path):
    text = open(path).read()
    names = set(DECL.findall(text))
    if not names:
        return []

    # Line numbers, for the message.
    starts = [0]
    for i, c in enumerate(text):
        if c == "\n":
            starts.append(i + 1)

    def lineno(pos):
        lo, hi = 0, len(starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    bad = []
    for name in sorted(names):
        for m in re.finditer(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"\s*\(", text):
            open_paren = m.end() - 1
            # The declaration itself, `int (*name)(int, int)`, is not a call.
            before = text[:m.start()].rstrip()
            if before.endswith("(*") or before.endswith("( *"):
                continue
            args, _end = split_args(text, open_paren)
            if args is None:
                continue
            for arg in args:
                why = offending(arg)
                if why:
                    bad.append((lineno(m.start()), name, arg.strip(), why))
    return bad


def main(paths):
    total = 0
    failed = 0
    for path in paths:
        for line, name, arg, why in check(path):
            print("%s:%d: %s(... %s ...) -- %s clobbers EDX; "
                  "work it out into a local first" % (path, line, name, arg, why))
            failed = failed + 1
        total = total + 1
    if failed:
        print("%d function pointer argument(s) would clobber EDX" % failed)
        return 1
    print("function pointer arguments: %d file(s), none clobber EDX" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
