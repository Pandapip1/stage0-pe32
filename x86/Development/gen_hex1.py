#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate hex1_pe32: hex0 plus single-character labels and 4-byte relative
pointers.  Semantics follow stage0-posix's x86/hex1_x86.hex0."""
import sys, struct
from stage0asm import *

a = Asm()

emit_find_ntdll(a)
emit_resolve_export(a)

# ---- read_byte -> eax = byte, or -4 at end of file ----
a.label("read_byte")
a.push_imm(0, "Key"); a.push_imm(0, "ByteOffset = NULL: the file position is kept by the I/O manager")
a.push_imm(1, "Length = 1"); a.push_lbl("input", "Buffer"); a.push_lbl("iosb", "IoStatusBlock")
a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
a.push_mem("in_handle", "FileHandle")
a.call_mem("fn_read")
a.raw(b"\x85\xc0", "test eax, eax  -- NTSTATUS < 0 is STATUS_END_OF_FILE")
a.jcc("s", ".eof")
a.movzx_eax_mem("input")
a.ret()
a.label(".eof")
a.mov_r_imm("eax", -4, "the end-of-file marker the passes test for")
a.ret()

# ---- write_bytes: eax = buffer address, ecx = length ----
a.label("write_n")
a.mov_mem_r("w_buf", "eax"); a.mov_mem_r("w_len", "ecx")
a.push_imm(0, "Key"); a.push_imm(0, "ByteOffset")
a.push_mem("w_len", "Length"); a.push_mem("w_buf", "Buffer"); a.push_lbl("iosb", "IoStatusBlock")
a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
a.push_mem("out_handle", "FileHandle")
a.call_mem("fn_write")
a.ret()

# ---- next_token / open_file, as in hex0 ----
emit_next_token(a)
emit_open_file(a)

# ---- slot_for: read the label character, return &table[c] ----
a.label("slot_for")
a.call("read_byte", "the single character naming the label")
a.raw(b"\xc1\xe0\x02", "shl eax, 2  -- four bytes per slot")
a.add_eax_lbl("table")
a.ret()

# ---- store_label: table[c] = ip ----
a.label("store_label")
a.call("slot_for")
a.mov_r_mem("ecx", "ip")
a.raw(b"\x89\x08", "mov [eax], ecx  -- the label points at the current output position")
a.ret()

# ---- store_pointer: emit (table[c] - ip) as four bytes ----
a.label("store_pointer")
a.add_mem_imm8("ip", 4, "the pointer itself occupies four bytes, counted before the difference")
a.call("slot_for")
a.raw(b"\x8b\x00", "mov eax, [eax]  -- the label's target")
a.sub_eax_mem("ip", "target - ip, the relative displacement")
a.mov_mem_r("w4", "eax")
a.push_lbl("w4"); a.pop_r("eax")
a.mov_r_imm("ecx", 4)
a.call("write_n")
a.ret()

# ---- hex: classify one byte ----
a.label("hex")
a.raw(b"\x83\xf8\x23", "cmp eax, '#'"); a.jcc("e", "comment")
a.raw(b"\x83\xf8\x3b", "cmp eax, ';'  -- upstream honours both comment characters"); a.jcc("e", "comment")
a.raw(b"\x83\xf8\x30", "cmp eax, '0'"); a.jcc("l", "other")
a.raw(b"\x83\xf8\x3a", "cmp eax, '9'+1"); a.jcc("l", "num")
a.raw(b"\x83\xf8\x41", "cmp eax, 'A'"); a.jcc("l", "other")
a.raw(b"\x83\xf8\x47", "cmp eax, 'F'+1"); a.jcc("l", "high")
a.raw(b"\x83\xf8\x61", "cmp eax, 'a'"); a.jcc("l", "other")
a.raw(b"\x83\xf8\x67", "cmp eax, 'f'+1"); a.jcc("l", "low")
a.jmp("other")
a.label("comment")
a.call("read_byte")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".ceof", "end of file inside a comment ends the pass")
a.raw(b"\x83\xf8\x0a", "cmp eax, '\\n'"); a.jcc("ne", "comment")
a.jmp("other")
a.label(".ceof"); a.mov_r_imm("eax", -4); a.ret()
a.label("num");  a.raw(b"\x83\xe8\x30", "sub eax, '0'"); a.ret()
a.label("low");  a.raw(b"\x83\xe8\x57", "sub eax, 'a'-10"); a.ret()
a.label("high"); a.raw(b"\x83\xe8\x37", "sub eax, 'A'-10"); a.ret()
a.label("other"); a.mov_r_imm("eax", -1, "carries no value"); a.ret()

# ---- first pass: record where each label lands ----
a.label("first_pass")
a.label(".fp")
a.call("read_byte")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".fp_done")
a.raw(b"\x83\xf8\x3a", "cmp eax, ':'"); a.jcc("ne", ".fp_notlabel")
a.call("store_label"); a.jmp(".fp")
a.label(".fp_notlabel")
a.raw(b"\x83\xf8\x25", "cmp eax, '%'"); a.jcc("ne", ".fp_other")
a.call("read_byte", "discard the label character; only its width matters here")
a.add_mem_imm8("ip", 4)
a.jmp(".fp")
a.label(".fp_other")
a.call("hex")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".fp_done")
a.raw(b"\x83\xf8\x00", "cmp eax, 0"); a.jcc("l", ".fp", "not a hex digit, ignore")
a.cmp_mem_imm8("toggle", 0); a.jcc("e", ".fp_tog")
a.add_mem_imm8("ip", 1, "one byte per completed pair, counted on the first nibble")
a.label(".fp_tog")
a.not_mem("toggle")
a.jmp(".fp")
a.label(".fp_done"); a.ret()

# ---- rewind ----
a.label("rewind_input")
a.mov_mem_imm("filepos", 0, "CurrentByteOffset low", off=0)
a.mov_mem_imm("filepos", 0, "CurrentByteOffset high", off=4)
a.push_imm(14, "FileInformationClass = FilePositionInformation")
a.push_imm(8, "Length = sizeof(FILE_POSITION_INFORMATION)")
a.push_lbl("filepos", "FileInformation")
a.push_lbl("iosb", "IoStatusBlock")
a.push_mem("in_handle", "FileHandle")
a.call_mem("fn_setinfo", "the NT equivalent of upstream's lseek back to the start")
a.ret()

# ---- second pass: emit bytes, resolving pointers ----
a.label("second_pass")
a.label(".sp")
a.call("read_byte")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".sp_done")
a.raw(b"\x83\xf8\x3a", "cmp eax, ':'"); a.jcc("ne", ".sp_notlabel")
a.call("read_byte", "the label is already recorded; drop its name")
a.jmp(".sp")
a.label(".sp_notlabel")
a.raw(b"\x83\xf8\x25", "cmp eax, '%'"); a.jcc("ne", ".sp_other")
a.call("store_pointer"); a.jmp(".sp")
a.label(".sp_other")
a.call("hex")
a.raw(b"\x83\xf8\xfc", "cmp eax, -4"); a.jcc("e", ".sp_done")
a.raw(b"\x83\xf8\x00", "cmp eax, 0"); a.jcc("l", ".sp", "not a hex digit, ignore")
a.cmp_mem_imm8("toggle", 0); a.jcc("e", ".sp_print")
a.mov_mem_r("accum", "eax", "hold the first nibble")
a.mov_mem_imm("toggle", 0)
a.jmp(".sp")
a.label(".sp_print")
a.mov_r_mem("ecx", "accum")
a.raw(b"\xc1\xe1\x04", "shl ecx, 4")
a.raw(b"\x01\xc8", "add eax, ecx")
a.mov_mem_al("output")
a.mov_mem_imm("toggle", -1)
a.add_mem_imm8("ip", 1)
a.push_lbl("output"); a.pop_r("eax")
a.mov_r_imm("ecx", 1)
a.call("write_n")
a.jmp(".sp")
a.label(".sp_done"); a.ret()

# ---- _start ----
a.label("_start")
a.call("find_ntdll")
a.raw(b"\x89\xc3", "mov ebx, eax  -- ntdll base, held across every resolve_export call")
for slot, nm in [("fn_create","name_NtCreateFile"), ("fn_read","name_NtReadFile"),
                 ("fn_write","name_NtWriteFile"), ("fn_close","name_NtClose"),
                 ("fn_exit","name_NtTerminateProcess"), ("fn_rtlpath","name_RtlDosPath"),
                 ("fn_setinfo","name_NtSetInformationFile")]:
    a.push_lbl(nm); a.push_r("ebx", "module_base"); a.call("resolve_export"); a.mov_mem_r(slot, "eax")
emit_cmdline(a)

a.mov_r_mem("eax", "arg_in")
a.mov_r_imm("ecx", 0x80100000, "GENERIC_READ|SYNCHRONIZE")
a.mov_r_imm("edx", 1, "FILE_OPEN")
a.call("open_file")
a.mov_mem_r("in_handle", "eax")

a.mov_r_mem("eax", "arg_out")
a.mov_r_imm("ecx", 0x40100000, "GENERIC_WRITE|SYNCHRONIZE")
a.mov_r_imm("edx", 5, "FILE_OVERWRITE_IF  -- upstream opens with O_WRONLY|O_CREAT|O_TRUNC")
a.call("open_file")
a.mov_mem_r("out_handle", "eax")

a.mov_mem_imm("ip", 0, "output position, counted by both passes")
a.mov_mem_imm("toggle", -1)
a.call("first_pass")
a.call("rewind_input")
a.mov_mem_imm("ip", 0, "the second pass recomputes it as it emits")
a.mov_mem_imm("toggle", -1)
a.call("second_pass")
a.push_mem("out_handle"); a.call_mem("fn_close")
a.push_mem("in_handle"); a.call_mem("fn_close")
a.push_imm(0, "ExitStatus = 0")
a.push_imm(-1, "ProcessHandle = NtCurrentProcess pseudo-handle")
a.call_mem("fn_exit")

# ===================== .data =====================
def asciiz(name, s): a.label(name); a.raw(s.encode() + b"\x00", '%s = "%s"' % (name, s))
def dd(name, v, note=None): a.label(name); a.raw(struct.pack("<i" if v < 0 else "<I", v), note)
def space(name, n, note=None): a.label(name); a.raw(b"\x00" * n, note)

asciiz("name_NtCreateFile", "NtCreateFile")
asciiz("name_NtReadFile", "NtReadFile")
asciiz("name_NtWriteFile", "NtWriteFile")
asciiz("name_NtClose", "NtClose")
asciiz("name_NtTerminateProcess", "NtTerminateProcess")
asciiz("name_NtSetInformationFile", "NtSetInformationFile")
asciiz("name_RtlDosPath", "RtlDosPathNameToNtPathName_U")
for n in ["fn_create","fn_read","fn_write","fn_close","fn_exit","fn_rtlpath","fn_setinfo"]:
    dd(n, 0, "resolved %s" % n)
dd("g_access", 0); dd("g_disp", 0); dd("g_handle", 0)
space("oa", 24, "OBJECT_ATTRIBUTES")
space("nt_path", 8, "UNICODE_STRING filled by RtlDosPathNameToNtPathName_U")
space("iosb", 8, "IO_STATUS_BLOCK")
space("filepos", 8, "FILE_POSITION_INFORMATION.CurrentByteOffset")
dd("in_handle", 0); dd("out_handle", 0); dd("arg_in", 0); dd("arg_out", 0)
dd("w_buf", 0, "write_n arguments"); dd("w_len", 0)
dd("ip", 0, "output position")
dd("toggle", -1); dd("accum", 0)
space("w4", 4, "the four bytes of a resolved pointer")
space("input", 1); space("output", 1)
space("table", 1024, "256 slots of four bytes: table[c] is the output position of label c")

DOC = {
"find_ntdll": """find_ntdll() -> ntdll base address.
TEB (fs:0x30) -> PEB -> Ldr -> InMemoryOrderModuleList; the second entry is
ntdll by loader convention.""",
"resolve_export": """resolve_export(module_base, name) -> address, or 0 if not found.
Walks the export directory by hand: AddressOfNames is searched by string
compare, the index selects an ordinal, the ordinal indexes AddressOfFunctions.""",
"read_byte": """read_byte() -> eax = the next input byte, or -4 at end of file.
-4 rather than -1 because -1 is already the value hex returns for a byte that
carries no data.""",
"write_n": """write_n(eax = buffer, ecx = length): append to the output file.""",
"next_token": """next_token() -> eax = the next argument, or 0 when exhausted.
esi walks the command line; tokens are bare or double-quoted, and the
terminator is overwritten with a NUL in place.  Characters are UTF-16.""",
"open_file": """open_file(eax = path, ecx = DesiredAccess, edx = CreateDisposition) -> handle.
RtlDosPathNameToNtPathName_U converts the DOS path to an NT path, so a relative
argument resolves against the working directory.""",
"slot_for": """slot_for() -> eax = &table[c], reading the label character c from the input.
The table is flat: 256 slots of four bytes, indexed by the character itself, so
a lookup is a shift and an add rather than a search.""",
"store_label": """store_label(): record that label c sits at the current output position.""",
"store_pointer": """store_pointer(): emit table[c] - ip as four little-endian bytes.
ip is advanced by four first, so the displacement is measured from the end of
the pointer, which is what a relative jump expects.""",
"hex": """hex(eax = byte) -> 0-15, -1 for a byte that carries no value, or -4 at end
of file.  '#' and ';' both begin a comment.""",
"comment": """Discard bytes to end of line.""",
"first_pass": """Read the whole input, recording where each label lands.
Nothing is written; only ip advances -- one per completed byte pair, four per
pointer.  A pointer's label character is read and discarded, since its width is
fixed whatever it names.""",
"rewind_input": """Seek the input back to the start for the second pass.
NtSetInformationFile with FilePositionInformation is the NT equivalent of the
lseek upstream uses.""",
"second_pass": """Read the input again, this time emitting.
Labels are dropped, pointers become displacements, and hex pairs become bytes.
ip is recomputed as it goes so store_pointer can measure against it.""",
"_start": """Resolve the seven ntdll routines, parse the command line, open both files,
then run the two passes with a rewind between them.""",
"name_NtCreateFile": "Export names, matched by resolve_export.",
"fn_create": "Resolved routine addresses.",
"oa": "OBJECT_ATTRIBUTES: Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService.",
"ip": "Conversion state, reset before each pass.",
"table": "The label table.  Slot c holds the output position of label c, or 0 if never defined.",
}

BANNER = "\n".join(spdx([UPSTREAM, PORT])) + """hex1-pe32: the Windows (PE32/i386) port of stage0's hex1.

hex1 is hex0 plus two things: a label may be defined, and a four-byte relative
pointer to a label may be emitted.  That is enough to write code with jumps
whose displacements are computed rather than counted by hand.

  hex1 INPUT OUTPUT
    argv[1]        a path, opened for reading
    argv[2]        a path, created or truncated for writing
    [0-9A-Fa-f]    a hexadecimal digit; two of them make one output byte
    :X             define label X here, where X is a single character
    %X             emit (address of X) - (position after this pointer), 4 bytes
    '#' or ';'     begins a comment, ignored to end of line
    anything else  ignored

A label may be referred to before it is defined, so the input is read twice:
the first pass records where each label lands, the second emits.  Between them
the input is rewound.

This file is written in hex0's language, so hex0 assembles it.

The image imports nothing: NumberOfRvaAndSizes is 0, so there is no import
directory.  ntdll is located through the PEB at run time and the seven routines
this program calls are resolved from ntdll's export table by name.

One section holds the code followed by the data, mapped read/write/execute."""

sys.exit(0 if emit_pe(a, BANNER, DOC, "name_NtCreateFile", sys.argv[1], sys.argv[2], sys.argv[3], "hex1") else 1)
