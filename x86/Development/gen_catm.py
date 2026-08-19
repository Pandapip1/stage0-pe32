#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate catm_pe32: the Windows PE32 port of stage0's catm."""
import sys, struct
from stage0asm import *
from pe32emit import emit_pe_hex2

BUFSZ = 0x10000

a = Asm()

emit_find_ntdll(a)
emit_resolve_export(a)
emit_next_token(a)
emit_open_file(a)

a.label("_start")
a.call("find_ntdll", "call find_ntdll")
a.raw(b"\x89\xc3", "mov ebx, eax  -- ntdll base, held across every resolve_export call")
for slot, nm in [("fn_create","name_NtCreateFile"), ("fn_read","name_NtReadFile"),
                 ("fn_write","name_NtWriteFile"), ("fn_close","name_NtClose"),
                 ("fn_exit","name_NtTerminateProcess"), ("fn_rtlpath","name_RtlDosPath")]:
    a.push_lbl(nm)
    a.push_r("ebx", "module_base")
    a.call("resolve_export", "call resolve_export")
    a.mov_mem_r(slot, "eax")

a.raw(b"\x64\xa1\x30\x00\x00\x00", "mov eax, [fs:0x30]  -- PEB")
a.raw(b"\x8b\x40\x10", "mov eax, [eax+0x10]  -- PEB->ProcessParameters")
a.raw(b"\x8b\x70\x44", "mov esi, [eax+0x44]  -- ProcessParameters->CommandLine.Buffer (UNICODE_STRING at 0x40, Buffer at +4)")
a.call("next_token", "argv[0]: the program name, discarded")
a.call("next_token", "argv[1]: the output path")
a.mov_r_imm("ecx", 0x40100000, "GENERIC_WRITE|SYNCHRONIZE")
a.mov_r_imm("edx", 5, "FILE_OVERWRITE_IF  -- upstream opens with O_WRONLY|O_CREAT|O_TRUNC")
a.call("open_file", "call open_file")
a.mov_mem_r("out_handle", "eax", "mov [out_handle], eax")

a.label("next_input")
a.call("next_token", "argv[n]: the next input path")
a.raw(b"\x85\xc0", "test eax, eax")
a.jcc("e", "finish", "je finish  -- no arguments left")
a.mov_r_imm("ecx", 0x80100000, "GENERIC_READ|SYNCHRONIZE")
a.mov_r_imm("edx", 1, "FILE_OPEN")
a.call("open_file", "call open_file")
a.mov_mem_r("in_handle", "eax", "mov [in_handle], eax")

a.label("copy")
a.push_imm(0, "Key")
a.push_imm(0, "ByteOffset = NULL: FILE_SYNCHRONOUS_IO_NONALERT keeps the file position")
a.push_imm(BUFSZ, "Length")
a.push_lbl("buffer", "Buffer")
a.push_lbl("iosb", "IoStatusBlock")
a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
a.push_mem("in_handle", "FileHandle")
a.call_mem("fn_read")
a.raw(b"\x85\xc0", "test eax, eax  -- NTSTATUS < 0 (STATUS_END_OF_FILE) ends this input")
a.jcc("s", "close_input", "js close_input")
a.mov_r_mem("eax", "iosb_info", "mov eax, [iosb_info]  -- bytes actually read")
a.raw(b"\x85\xc0", "test eax, eax")
a.jcc("e", "close_input", "je close_input  -- a short read of nothing is the end")
a.mov_mem_r("count", "eax", "mov [count], eax")

a.push_imm(0, "Key"); a.push_imm(0, "ByteOffset")
a.push_mem("count", "Length = the bytes just read")
a.push_lbl("buffer", "Buffer")
a.push_lbl("iosb", "IoStatusBlock")
a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
a.push_mem("out_handle", "FileHandle")
a.call_mem("fn_write")
a.jmp("copy", "jmp copy")

a.label("close_input")
a.push_mem("in_handle", "push in_handle")
a.call_mem("fn_close")
a.jmp("next_input", "jmp next_input")

a.label("finish")
a.push_mem("out_handle", "push out_handle")
a.call_mem("fn_close")
a.push_imm(0, "ExitStatus = 0")
a.push_imm(-1, "ProcessHandle = NtCurrentProcess pseudo-handle")
a.call_mem("fn_exit")

# ===================== .data =====================
def asciiz(name, s):
    a.label(name); a.raw(s.encode() + b"\x00", '%s = "%s"' % (name, s))
def dd(name, v, note):
    a.label(name); a.raw(struct.pack("<i" if v < 0 else "<I", v), note)
def space(name, n, note):
    a.label(name); a.raw(b"\x00" * n, note)

asciiz("name_NtCreateFile", "NtCreateFile")
asciiz("name_NtReadFile", "NtReadFile")
asciiz("name_NtWriteFile", "NtWriteFile")
asciiz("name_NtClose", "NtClose")
asciiz("name_NtTerminateProcess", "NtTerminateProcess")
asciiz("name_RtlDosPath", "RtlDosPathNameToNtPathName_U")
dd("fn_create", 0, "fn_create: resolved NtCreateFile")
dd("fn_read", 0, "fn_read: resolved NtReadFile")
dd("fn_write", 0, "fn_write: resolved NtWriteFile")
dd("fn_close", 0, "fn_close: resolved NtClose")
dd("fn_exit", 0, "fn_exit: resolved NtTerminateProcess")
dd("fn_rtlpath", 0, "fn_rtlpath: resolved RtlDosPathNameToNtPathName_U")
dd("g_access", 0, "g_access: DesiredAccess held across the RtlDosPathNameToNtPathName_U call")
dd("g_disp", 0, "g_disp: CreateDisposition, same")
dd("g_handle", 0, "g_handle: NtCreateFile's out-parameter")
dd("oa", 0, "oa: OBJECT_ATTRIBUTES.Length")
dd("oa_root", 0, "oa_root: .RootDirectory")
dd("oa_name", 0, "oa_name: .ObjectName")
dd("oa_attr", 0, "oa_attr: .Attributes")
dd("oa_sd", 0, "oa_sd: .SecurityDescriptor")
dd("oa_sqos", 0, "oa_sqos: .SecurityQualityOfService")
space("nt_path", 8, "nt_path: UNICODE_STRING filled by RtlDosPathNameToNtPathName_U")
dd("iosb", 0, "iosb: IO_STATUS_BLOCK.Status")
dd("iosb_info", 0, "iosb_info: IO_STATUS_BLOCK.Information, the byte count of a read")
dd("in_handle", 0, "in_handle: the input being copied")
dd("out_handle", 0, "out_handle: argv[1], opened once and written to throughout")
dd("count", 0, "count: bytes read, and so bytes to write")

a.reserve("buffer", BUFSZ, "the copy buffer")

# ===================== prose attached to each label =====================
DOC = {
"find_ntdll": """find_ntdll() -> ntdll base address.
TEB (fs:0x30) -> PEB -> Ldr -> InMemoryOrderModuleList.  The first entry in that
list is the main EXE and the second is ntdll.  x86 offsets: PEB->Ldr at 0x0C,
Ldr->InMemoryOrderModuleList at 0x14.  The list pointer aims at
InMemoryOrderLinks (+0x08) while DllBase is at +0x18, hence the closing +0x10.""",

"resolve_export": """resolve_export(module_base, name) -> address, or 0 if not found.
stdcall: arguments pushed right to left, callee cleans the stack.
Reads e_lfanew (+0x3C) to reach the PE header, then the export directory.
AddressOfNames is searched by string compare; the matching index selects an
ordinal from AddressOfNameOrdinals, and that ordinal indexes AddressOfFunctions.""",

"next_token": """next_token() -> eax = the next argument, or 0 when exhausted.
esi is the cursor into the command line and is left past the token returned.
Skips leading spaces, then takes a bare token up to the next space, or a
double-quoted token up to the closing quote.  The terminator is overwritten with
a NUL, leaving the token as a NUL-terminated wide string.
Characters are UTF-16, so the cursor advances two bytes at a time.""",

"open_file": """open_file(eax = path, ecx = DesiredAccess, edx = CreateDisposition) -> handle.
RtlDosPathNameToNtPathName_U converts the DOS path into the NT path
NtCreateFile requires, resolving a relative path against the working directory.
ntdll allocates the result buffer.  DesiredAccess and CreateDisposition are
saved to memory first because that call clobbers the registers holding them.
OBJECT_ATTRIBUTES.Length is 24, the x86 size of the structure.
FILE_SYNCHRONOUS_IO_NONALERT keeps the file position in the I/O manager, which
is why every read and write below passes a NULL ByteOffset and still advances.""",

"_start": """Resolve the six ntdll routines, then open argv[1] for writing.  ebx holds the
ntdll base across the six resolve_export calls.  The command line is
PEB->ProcessParameters->CommandLine, a UNICODE_STRING at 0x40 whose Buffer field
is at 0x44.  argv[0] is the program name and is discarded.""",

"next_input": """Take the next argument.  When there are none left the output is complete.""",

"copy": """Copy one input to the output in buffer-sized pieces.
NtReadFile returns an NTSTATUS; end of file is STATUS_END_OF_FILE (0xC0000011),
which is negative.  A successful read reports its length in
IO_STATUS_BLOCK.Information, and that is what gets written, so a final short
read copies exactly its own bytes.""",

"close_input": "Done with this input; go back for the next argument.",
"finish": """Close the output and exit.  NtTerminateProcess takes -1, the pseudo-handle for
the current process.""",
"name_NtCreateFile": "Export names, matched by resolve_export.",
"fn_create": "Resolved routine addresses.  Kept in memory because six will not fit in registers.",
"g_access": "Arguments that must survive the RtlDosPathNameToNtPathName_U call.",
"oa": "OBJECT_ATTRIBUTES, one label per field so hex2 can address each of them.",
"nt_path": "UNICODE_STRING (Length, MaximumLength, Buffer) filled in by RtlDosPathNameToNtPathName_U.",
"iosb": "IO_STATUS_BLOCK.  Unlike the links below this one, catm reads Information.",
"in_handle": "The two open files and the size of the piece in flight.",
}

BANNER = "\n".join(spdx([UPSTREAM, PORT])) + """catm-pe32: the Windows (PE32/i386) port of stage0's catm.

catm concatenates files.  Nothing above this link has a shell, so joining a
header to a program is a job for a program.

  catm OUTPUT INPUT...
    argv[1]        a path, created or truncated for writing
    argv[2...]     paths, read in order and appended to it

The copy buffer is 0x10000 bytes and lives past the end of the file, in the
memory the header stub leaves zero-filled, so catm never asks for memory.

This file is written in hex2's language and includes the PE32 header, because
catm is what joins that header to everything built after it."""

sys.exit(0 if emit_pe_hex2(a, BANNER, DOC, "name_NtCreateFile", sys.argv[1], sys.argv[2], "catm") else 1)
