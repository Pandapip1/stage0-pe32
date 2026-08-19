#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""hex2_pe32: hex1 plus multi-character labels, five pointer widths and
absolute addresses.  Semantics follow stage0-posix's x86/hex2_x86.hex1."""
import sys, struct
from stage0asm import *

OUT_BASE = 0x400000   # ip starts at the image base of the PE hex2 emits
NLAB, FIELD = 2048, 64

a = Asm()
emit_find_ntdll(a)
emit_resolve_export(a)

# ---- read_byte -> eax = byte, or -4 at end of file ----
a.label("read_byte")
a.push_imm(0, "Key"); a.push_imm(0, "ByteOffset")
a.push_imm(1, "Length = 1"); a.push_lbl("input", "Buffer"); a.push_lbl("iosb", "IoStatusBlock")
a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
a.push_mem("in_handle", "FileHandle")
a.call_mem("fn_read")
a.raw(b"\x85\xc0", "test eax, eax"); a.jcc("s", ".eof")
a.movzx_eax_mem("input"); a.ret()
a.label(".eof"); a.mov_r_imm("eax", -4); a.ret()

# ---- write_n(eax = buffer, ecx = length) ----
a.label("write_n")
a.mov_mem_r("w_buf", "eax"); a.mov_mem_r("w_len", "ecx")
a.push_imm(0, "Key"); a.push_imm(0, "ByteOffset")
a.push_mem("w_len", "Length"); a.push_mem("w_buf", "Buffer"); a.push_lbl("iosb", "IoStatusBlock")
a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
a.push_mem("out_handle", "FileHandle")
a.call_mem("fn_write"); a.ret()

emit_next_token(a)
emit_open_file(a)

# ---- consume_token(ebx = destination) -> eax = the terminating character ----
a.label("consume_token")
a.label(".ct")
a.call("read_byte")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".ct_end", "end of file also ends a token")
a.raw(b"\x83\xf8\x09", "cmp eax, '\\t'"); a.jcc("e", ".ct_end")
a.raw(b"\x83\xf8\x0a", "cmp eax, '\\n'"); a.jcc("e", ".ct_end")
a.raw(b"\x83\xf8\x0d", "cmp eax, '\\r'"); a.jcc("e", ".ct_end")
a.raw(b"\x83\xf8\x20", "cmp eax, ' '"); a.jcc("e", ".ct_end")
a.raw(b"\x83\xf8\x3e", "cmp eax, '>'"); a.jcc("e", ".ct_end")
a.raw(b"\x88\x03", "mov [ebx], al  -- store the character")
a.raw(b"\x43", "inc ebx")
a.jmp(".ct")
a.label(".ct_end")
a.raw(b"\xc6\x03\x00", "mov byte [ebx], 0  -- terminate the token")
a.ret()

# ---- get_target(eax = name) -> eax = the label's address ----
a.label("get_target")
a.mov_mem_r("gt_name", "eax")
a.raw(b"\x31\xff", "xor edi, edi  -- index of the candidate label")
a.label(".gt")
a.cmp_r_mem("edi", "nlab"); a.jcc("ge", ".gt_missing")
a.raw(b"\x89\xfe", "mov esi, edi")
a.raw(b"\xc1\xe6\x06", "shl esi, 6  -- %d bytes per name field" % FIELD)
a.add_r_lbl("esi", "names")
a.mov_r_mem("edx", "gt_name")
a.label(".gt_cmp")
a.raw(b"\x8a\x0e", "mov cl, [esi]")
a.raw(b"\x3a\x0a", "cmp cl, [edx]"); a.jcc("ne", ".gt_next")
a.raw(b"\x84\xc9", "test cl, cl"); a.jcc("e", ".gt_found", "both ended: a match")
a.raw(b"\x46", "inc esi"); a.raw(b"\x42", "inc edx")
a.jmp(".gt_cmp")
a.label(".gt_next")
a.raw(b"\x47", "inc edi")
a.jmp(".gt")
a.label(".gt_found")
a.mov_eax_idx4("targets")
a.ret()
a.label(".gt_missing")
a.push_imm(1, "ExitStatus = 1  -- an undefined label is fatal")
a.push_imm(-1, "ProcessHandle")
a.call_mem("fn_exit")

# ---- store_label: record the token that follows as a label at ip ----
a.label("store_label")
a.mov_r_lbl("ebx", "tok"); a.call("consume_token")
a.mov_r_mem("edi", "nlab")
a.raw(b"\x89\xfe", "mov esi, edi"); a.raw(b"\xc1\xe6\x06", "shl esi, 6")
a.add_r_lbl("esi", "names")
a.mov_r_lbl("edx", "tok")
a.label(".sl_copy")
a.raw(b"\x8a\x0a", "mov cl, [edx]")
a.raw(b"\x88\x0e", "mov [esi], cl")
a.raw(b"\x84\xc9", "test cl, cl"); a.jcc("e", ".sl_done")
a.raw(b"\x42", "inc edx"); a.raw(b"\x46", "inc esi")
a.jmp(".sl_copy")
a.label(".sl_done")
a.mov_r_mem("eax", "ip")
a.mov_idx4_eax("targets")
a.add_mem_imm8("nlab", 1)
a.ret()

# ---- store_pointer: emit one pointer.  [p_width] and [p_abs] chosen by caller ----
a.label("store_pointer")
a.mov_r_mem("eax", "p_width")
a.add_mem_reg("ip", "eax", "the pointer's own width is counted before the difference")
a.mov_r_lbl("ebx", "tok"); a.call("consume_token")
a.mov_mem_r("sep", "eax", "the character that ended the token")
a.mov_r_lbl("eax", "tok"); a.call("get_target")
a.mov_mem_r("p_target", "eax")
a.mov_r_mem("eax", "ip")
a.mov_mem_r("p_base", "eax", "by default a displacement is measured from here")
a.cmp_mem_imm8("sep", 0x3e, "was the token ended by '>'?"); a.jcc("ne", ".sp_have_base")
a.mov_r_lbl("ebx", "tok2"); a.call("consume_token", "the label naming the base")
a.mov_r_lbl("eax", "tok2"); a.call("get_target")
a.mov_mem_r("p_base", "eax")
a.label(".sp_have_base")
a.mov_r_mem("eax", "p_target")
a.cmp_mem_imm8("p_abs", 0); a.jcc("ne", ".sp_emit", "an absolute pointer is the target itself")
a.sub_eax_mem("p_base", "target - base")
a.label(".sp_emit")
a.mov_mem_r("outbuf", "eax", "little-endian; only the low [p_width] bytes are written")
a.mov_r_lbl("eax", "outbuf")
a.mov_r_mem("ecx", "p_width")
a.call("write_n")
a.ret()

# ---- classify_pointer: eax = character -> sets p_width/p_abs, returns 1 or 0 ----
a.label("classify")
a.raw(b"\x83\xf8\x21", "cmp eax, '!'"); a.jcc("e", ".c_rel1")
a.raw(b"\x83\xf8\x40", "cmp eax, '@'"); a.jcc("e", ".c_rel2")
a.raw(b"\x83\xf8\x24", "cmp eax, '$'"); a.jcc("e", ".c_abs2")
a.raw(b"\x83\xf8\x25", "cmp eax, '%'"); a.jcc("e", ".c_rel4")
a.raw(b"\x83\xf8\x26", "cmp eax, '&'"); a.jcc("e", ".c_abs4")
a.raw(b"\x31\xc0", "xor eax, eax  -- not a pointer"); a.ret()
a.label(".c_rel1"); a.mov_mem_imm("p_width", 1); a.mov_mem_imm("p_abs", 0); a.jmp(".c_yes")
a.label(".c_rel2"); a.mov_mem_imm("p_width", 2); a.mov_mem_imm("p_abs", 0); a.jmp(".c_yes")
a.label(".c_rel4"); a.mov_mem_imm("p_width", 4); a.mov_mem_imm("p_abs", 0); a.jmp(".c_yes")
a.label(".c_abs2"); a.mov_mem_imm("p_width", 2); a.mov_mem_imm("p_abs", 1); a.jmp(".c_yes")
a.label(".c_abs4"); a.mov_mem_imm("p_width", 4); a.mov_mem_imm("p_abs", 1)
a.label(".c_yes"); a.mov_r_imm("eax", 1); a.ret()

# ---- hex ----
a.label("hex")
a.raw(b"\x83\xf8\x23", "cmp eax, '#'"); a.jcc("e", "comment")
a.raw(b"\x83\xf8\x3b", "cmp eax, ';'"); a.jcc("e", "comment")
a.raw(b"\x83\xf8\x30", "cmp eax, '0'"); a.jcc("l", "other")
a.raw(b"\x83\xf8\x3a", "cmp eax, '9'+1"); a.jcc("l", "num")
a.raw(b"\x83\xf8\x41", "cmp eax, 'A'"); a.jcc("l", "other")
a.raw(b"\x83\xf8\x47", "cmp eax, 'F'+1"); a.jcc("l", "high")
a.raw(b"\x83\xf8\x61", "cmp eax, 'a'"); a.jcc("l", "other")
a.raw(b"\x83\xf8\x67", "cmp eax, 'f'+1"); a.jcc("l", "low")
a.jmp("other")
a.label("comment")
a.call("read_byte")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".ceof")
a.raw(b"\x83\xf8\x0a", "cmp eax, '\\n'"); a.jcc("ne", "comment")
a.jmp("other")
a.label(".ceof"); a.mov_r_imm("eax", -4); a.ret()
a.label("num");  a.raw(b"\x83\xe8\x30", "sub eax, '0'"); a.ret()
a.label("low");  a.raw(b"\x83\xe8\x57", "sub eax, 'a'-10"); a.ret()
a.label("high"); a.raw(b"\x83\xe8\x37", "sub eax, 'A'-10"); a.ret()
a.label("other"); a.mov_r_imm("eax", -1); a.ret()

# ---- first pass ----
a.label("first_pass")
a.label(".fp")
a.call("read_byte")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".fp_done")
a.raw(b"\x83\xf8\x3a", "cmp eax, ':'"); a.jcc("ne", ".fp_ptr")
a.call("store_label"); a.jmp(".fp")
a.label(".fp_ptr")
a.mov_mem_r("cur", "eax", "hex may consume a comment, so keep the character")
a.call("classify")
a.raw(b"\x85\xc0", "test eax, eax"); a.jcc("e", ".fp_other")
a.mov_r_mem("eax", "p_width")
a.add_mem_reg("ip", "eax")
a.mov_r_lbl("ebx", "tok"); a.call("consume_token", "the label name; only its width matters here")
a.raw(b"\x83\xf8\x3e", "cmp eax, '>'"); a.jcc("ne", ".fp")
a.mov_r_lbl("ebx", "tok"); a.call("consume_token", "and the base label")
a.jmp(".fp")
a.label(".fp_other")
a.mov_r_mem("eax", "cur")
a.call("hex")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".fp_done")
a.raw(b"\x83\xf8\x00", "cmp eax, 0"); a.jcc("l", ".fp")
a.cmp_mem_imm8("toggle", 0); a.jcc("e", ".fp_tog")
a.add_mem_imm8("ip", 1)
a.label(".fp_tog")
a.not_mem("toggle")
a.jmp(".fp")
a.label(".fp_done"); a.ret()

# ---- rewind ----
a.label("rewind_input")
a.mov_mem_imm("filepos", 0, off=0); a.mov_mem_imm("filepos", 0, off=4)
a.push_imm(14, "FilePositionInformation"); a.push_imm(8, "Length")
a.push_lbl("filepos"); a.push_lbl("iosb"); a.push_mem("in_handle")
a.call_mem("fn_setinfo", "the NT equivalent of upstream's lseek")
a.ret()

# ---- second pass ----
a.label("second_pass")
a.label(".sp2")
a.call("read_byte")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".sp2_done")
a.raw(b"\x83\xf8\x3a", "cmp eax, ':'"); a.jcc("ne", ".sp2_ptr")
a.mov_r_lbl("ebx", "tok"); a.call("consume_token", "the label is already recorded; drop it")
a.jmp(".sp2")
a.label(".sp2_ptr")
a.mov_mem_r("cur", "eax")
a.call("classify")
a.raw(b"\x85\xc0", "test eax, eax"); a.jcc("e", ".sp2_other")
a.call("store_pointer"); a.jmp(".sp2")
a.label(".sp2_other")
a.mov_r_mem("eax", "cur")
a.call("hex")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".sp2_done")
a.raw(b"\x83\xf8\x00", "cmp eax, 0"); a.jcc("l", ".sp2")
a.cmp_mem_imm8("toggle", 0); a.jcc("e", ".sp2_print")
a.mov_mem_r("accum", "eax"); a.mov_mem_imm("toggle", 0)
a.jmp(".sp2")
a.label(".sp2_print")
a.mov_r_mem("ecx", "accum")
a.raw(b"\xc1\xe1\x04", "shl ecx, 4")
a.raw(b"\x01\xc8", "add eax, ecx")
a.mov_mem_al("output")
a.mov_mem_imm("toggle", -1)
a.add_mem_imm8("ip", 1)
a.mov_r_lbl("eax", "output"); a.mov_r_imm("ecx", 1); a.call("write_n")
a.jmp(".sp2")
a.label(".sp2_done"); a.ret()

# ---- _start ----
a.label("_start")
a.call("find_ntdll")
a.raw(b"\x89\xc3", "mov ebx, eax  -- ntdll base")
for slot, nm in [("fn_create","name_NtCreateFile"), ("fn_read","name_NtReadFile"),
                 ("fn_write","name_NtWriteFile"), ("fn_close","name_NtClose"),
                 ("fn_exit","name_NtTerminateProcess"), ("fn_rtlpath","name_RtlDosPath"),
                 ("fn_setinfo","name_NtSetInformationFile")]:
    a.push_lbl(nm); a.push_r("ebx", "module_base"); a.call("resolve_export"); a.mov_mem_r(slot, "eax")
emit_cmdline(a)
a.mov_r_mem("eax", "arg_in"); a.mov_r_imm("ecx", 0x80100000, "GENERIC_READ|SYNCHRONIZE")
a.mov_r_imm("edx", 1, "FILE_OPEN"); a.call("open_file"); a.mov_mem_r("in_handle", "eax")
a.mov_r_mem("eax", "arg_out"); a.mov_r_imm("ecx", 0x40100000, "GENERIC_WRITE|SYNCHRONIZE")
a.mov_r_imm("edx", 5, "FILE_OVERWRITE_IF"); a.call("open_file"); a.mov_mem_r("out_handle", "eax")
a.mov_mem_imm("ip", OUT_BASE, "labels hold absolute addresses, so ip starts at the image base")
a.mov_mem_imm("toggle", -1)
a.call("first_pass")
a.call("rewind_input")
a.mov_mem_imm("ip", OUT_BASE)
a.mov_mem_imm("toggle", -1)
a.call("second_pass")
a.push_mem("out_handle"); a.call_mem("fn_close")
a.push_mem("in_handle"); a.call_mem("fn_close")
a.push_imm(0, "ExitStatus = 0"); a.push_imm(-1, "ProcessHandle"); a.call_mem("fn_exit")

# ===================== .data =====================
def asciiz(n, s): a.label(n); a.raw(s.encode()+b"\x00", '%s = "%s"' % (n, s))
def dd(n, v, note=None): a.label(n); a.raw(struct.pack("<i" if v < 0 else "<I", v), note)
def space(n, k, note=None): a.label(n); a.raw(b"\x00"*k, note)

asciiz("name_NtCreateFile", "NtCreateFile"); asciiz("name_NtReadFile", "NtReadFile")
asciiz("name_NtWriteFile", "NtWriteFile"); asciiz("name_NtClose", "NtClose")
asciiz("name_NtTerminateProcess", "NtTerminateProcess")
asciiz("name_NtSetInformationFile", "NtSetInformationFile")
asciiz("name_RtlDosPath", "RtlDosPathNameToNtPathName_U")
for n in ["fn_create","fn_read","fn_write","fn_close","fn_exit","fn_rtlpath","fn_setinfo"]: dd(n, 0)
dd("g_access", 0); dd("g_disp", 0); dd("g_handle", 0)
space("oa", 24, "OBJECT_ATTRIBUTES"); space("nt_path", 8); space("iosb", 8); space("filepos", 8)
dd("in_handle", 0); dd("out_handle", 0); dd("arg_in", 0); dd("arg_out", 0)
dd("w_buf", 0); dd("w_len", 0)
dd("ip", 0, "output position, an absolute address"); dd("toggle", -1); dd("accum", 0); dd("cur", 0)
dd("nlab", 0, "number of labels recorded"); dd("gt_name", 0)
dd("p_width", 0, "the pointer being emitted"); dd("p_abs", 0); dd("p_target", 0); dd("p_base", 0); dd("sep", 0)
space("outbuf", 4); space("input", 1); space("output", 1)

a.reserve("tok", 256, "the token being read")
a.reserve("tok2", 256, "the base label after '>'")
a.reserve("names", NLAB*FIELD, "%d name fields of %d bytes" % (NLAB, FIELD))
a.reserve("targets", NLAB*4, "one address per name")

DOC = {
"read_byte": "read_byte() -> eax = the next input byte, or -4 at end of file.",
"write_n": "write_n(eax = buffer, ecx = length): append to the output file.",
"consume_token": """consume_token(ebx = destination) -> eax = the character that ended it.
A token runs to a space, tab, newline, carriage return or '>'.  The terminator
is returned because '>' means a base label follows.""",
"get_target": """get_target(eax = name) -> eax = that label's address.
A linear scan of the recorded names.  An undefined label is fatal: the address
would otherwise be silently wrong, and everything above this link would inherit
the error.""",
"store_label": "store_label(): record the token that follows as a label at the current ip.",
"store_pointer": """store_pointer(): emit one pointer, [p_width] bytes wide.
An absolute pointer is the target itself; a relative one is target - base,
where base is the position after the pointer unless a '>' named another
label.""",
"classify": """classify(eax = character) -> 1 if it introduces a pointer, else 0.
  !  one byte, relative      @  two bytes, relative     %  four bytes, relative
  $  two bytes, absolute     &  four bytes, absolute""",
"hex": "hex(eax = byte) -> 0-15, -1 for no value, or -4 at end of file.",
"first_pass": """Read the input, recording where each label lands.
Nothing is written; ip advances by one per completed byte pair and by the
pointer's width per pointer.""",
"second_pass": "Read the input again, emitting bytes and resolving pointers.",
"rewind_input": "Seek the input back to the start for the second pass.",
"_start": "Resolve the seven ntdll routines, open both files, run the two passes.",
"name_NtCreateFile": "Export names, matched by resolve_export.",
"ip": "Conversion state.  ip is an absolute address, so a label's value is one too.",
"tok": "Reserved past the end of the file; the loader zero-fills it.",
}

BANNER = "\n".join(spdx([UPSTREAM, PORT])) + """hex2-pe32: the Windows (PE32/i386) port of stage0's hex2.

hex2 is hex1 with labels that have real names and pointers that have widths.
That is enough to write a program that refers to its own data by address, which
is what everything above this link needs.

  hex2 INPUT OUTPUT
    argv[1]        a path, opened for reading
    argv[2]        a path, created or truncated for writing
    [0-9A-Fa-f]    a hexadecimal digit; two of them make one output byte
    :name          define a label here; a name runs to space, tab, newline or '>'
    !name          one byte,   target - base
    @name          two bytes,  target - base
    %name          four bytes, target - base
    $name          two bytes,  the target itself
    &name          four bytes, the target itself
    !name>base     measure the displacement from base rather than from here
    '#' or ';'     begins a comment, ignored to end of line
    anything else  ignored

ip counts from the image base rather than from zero, so a label's value is the
address it will have once loaded and an absolute pointer needs no adjustment.
Relative pointers subtract, so the base cancels.

Labels may be used before they are defined, so the input is read twice with a
rewind between the passes.

This file is written in hex1's language: :X marks a position and %X is a
four-byte displacement to it, both resolved by hex1.

The image imports nothing.  The label table is reserved past the end of the
file and zero-filled by the loader, so it costs nothing in the source."""

sys.exit(0 if emit_pe(a, BANNER, DOC, "name_NtCreateFile", sys.argv[1], sys.argv[2], sys.argv[3], "hex2", lang="hex1") else 1)
