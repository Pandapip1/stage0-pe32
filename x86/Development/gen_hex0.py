#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate hex0_pe32: the Windows PE32 port of stage0's hex0 seed."""
import sys, struct
from stage0asm import *

# ===================== the program =====================
a = Asm()

# Proven position-independent routines, lifted byte-for-byte out of the original
# hex0_32.exe: they use only relative jumps and register/displacement operands,
# so they relocate freely.
emit_find_ntdll(a)
emit_resolve_export(a)

# ---- read_byte: NtReadFile(in_handle, ..., input, 1, NULL, NULL) ----
def read_byte(tag):
    a.push_imm(0, "Key")
    a.push_imm(0, "ByteOffset = NULL: FILE_SYNCHRONOUS_IO_NONALERT keeps the file position")
    a.push_imm(1, "Length = 1")
    a.push_lbl("input", "Buffer")
    a.push_lbl("iosb", "IoStatusBlock")
    a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
    a.push_mem("in_handle", "FileHandle")
    a.call_mem("fn_read", tag)

# ---- next_token: esi = cursor, returns eax = token start or 0 ----
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

emit_cmdline(a)
a.mov_r_mem("eax", "arg_in", "mov eax, [arg_in]")
a.mov_r_imm("ecx", 0x80100000, "GENERIC_READ|SYNCHRONIZE")
a.mov_r_imm("edx", 1, "FILE_OPEN")
a.call("open_file", "call open_file")
a.mov_mem_r("in_handle", "eax", "mov [in_handle], eax")

a.mov_r_mem("eax", "arg_out", "mov eax, [arg_out]")
a.mov_r_imm("ecx", 0x40100000, "GENERIC_WRITE|SYNCHRONIZE")
a.mov_r_imm("edx", 5, "FILE_OVERWRITE_IF  -- upstream opens with O_WRONLY|O_CREAT|O_TRUNC")
a.call("open_file", "call open_file")
a.mov_mem_r("out_handle", "eax", "mov [out_handle], eax")

a.label("loop")
read_byte("main loop")
a.raw(b"\x85\xc0", "test eax, eax  -- NTSTATUS < 0 (STATUS_END_OF_FILE) ends the run")
a.jcc("s", "done", "js done")
a.raw(b"\x0f\xb6\x05"); a.patch(4, lambda ad, L: L["input"], "movzx eax, byte [input]")
a.call("hex", "call hex")
a.raw(b"\x83\xf8\x00", "cmp eax, 0")
a.jcc("l", "loop", "jl loop  -- not a hex digit, ignore")
a.cmp_mem_imm8("toggle", 0, "cmp dword [toggle], 0")
a.jcc("ge", "print", "jge print")
a.mov_mem_r("accum", "eax", "mov [accum], eax  -- first nibble")
a.mov_mem_imm("toggle", 0, "mov dword [toggle], 0")
a.jmp("loop", "jmp loop")

a.label("print")
a.mov_r_mem("ecx", "accum", "mov ecx, [accum]")
a.raw(b"\xc1\xe1\x04", "shl ecx, 4")
a.raw(b"\x01\xc8", "add eax, ecx")
a.raw(b"\xa2"); a.patch(4, lambda ad, L: L["output"], "mov [output], al")
a.mov_mem_imm("toggle", -1, "mov dword [toggle], -1")
a.push_imm(0, "Key"); a.push_imm(0, "ByteOffset"); a.push_imm(1, "Length = 1")
a.push_lbl("output", "Buffer"); a.push_lbl("iosb", "IoStatusBlock")
a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
a.push_mem("out_handle", "FileHandle")
a.call_mem("fn_write")
a.jmp("loop", "jmp loop")

a.label("done")
a.push_mem("out_handle", "push out_handle")
a.call_mem("fn_close")
a.push_mem("in_handle", "push in_handle")
a.call_mem("fn_close")
a.push_imm(0, "ExitStatus = 0")
a.push_imm(-1, "ProcessHandle = NtCurrentProcess pseudo-handle")
a.call_mem("fn_exit")

# ---- hex: classify one byte ----
a.label("hex")
a.raw(b"\x83\xf8\x23", "cmp eax, '#'")
a.jcc("e", "comment", "je comment")
a.raw(b"\x83\xf8\x3b", "cmp eax, ';'  -- upstream hex0 treats BOTH '#' and ';' as comments")
a.jcc("e", "comment", "je comment")
a.raw(b"\x83\xf8\x30", "cmp eax, '0'"); a.jcc("l", "other", "jl other")
a.raw(b"\x83\xf8\x3a", "cmp eax, '9'+1"); a.jcc("l", "num", "jl num")
a.raw(b"\x83\xf8\x41", "cmp eax, 'A'"); a.jcc("l", "other", "jl other")
a.raw(b"\x83\xf8\x47", "cmp eax, 'F'+1"); a.jcc("l", "high", "jl high")
a.raw(b"\x83\xf8\x61", "cmp eax, 'a'"); a.jcc("l", "other", "jl other")
a.raw(b"\x83\xf8\x67", "cmp eax, 'f'+1"); a.jcc("l", "low", "jl low")
a.jmp("other", "jmp other")

a.label("comment")
read_byte("comment: discard to end of line")
a.raw(b"\x85\xc0", "test eax, eax")
a.jcc("s", "other", "js other  -- EOF inside a comment")
a.raw(b"\x0f\xb6\x05"); a.patch(4, lambda ad, L: L["input"], "movzx eax, byte [input]")
a.raw(b"\x83\xf8\x0a", "cmp eax, '\\n'")
a.jcc("ne", "comment", "jne comment")
a.jmp("other", "jmp other")

a.label("num");  a.raw(b"\x83\xe8\x30", "sub eax, '0'"); a.ret("ret")
a.label("low");  a.raw(b"\x83\xe8\x57", "sub eax, 'a'-10"); a.ret("ret")
a.label("high"); a.raw(b"\x83\xe8\x37", "sub eax, 'A'-10"); a.ret("ret")
a.label("other"); a.mov_r_imm("eax", -1, "mov eax, -1  -- ignored byte"); a.ret("ret")

# ===================== .data =====================
def asciiz(name, s, note):
    a.label(name); a.raw(s.encode() + b"\x00", '%s = "%s"' % (name, s))
def dd(name, v, note):
    a.label(name); a.raw(struct.pack("<i" if v < 0 else "<I", v), note)
def space(name, n, note):
    a.label(name); a.raw(b"\x00" * n, note)

asciiz("name_NtCreateFile", "NtCreateFile", None)
asciiz("name_NtReadFile", "NtReadFile", None)
asciiz("name_NtWriteFile", "NtWriteFile", None)
asciiz("name_NtClose", "NtClose", None)
asciiz("name_NtTerminateProcess", "NtTerminateProcess", None)
asciiz("name_RtlDosPath", "RtlDosPathNameToNtPathName_U", None)
dd("fn_create", 0, "fn_create: resolved NtCreateFile")
dd("fn_read", 0, "fn_read: resolved NtReadFile")
dd("fn_write", 0, "fn_write: resolved NtWriteFile")
dd("fn_close", 0, "fn_close: resolved NtClose")
dd("fn_exit", 0, "fn_exit: resolved NtTerminateProcess")
dd("fn_rtlpath", 0, "fn_rtlpath: resolved RtlDosPathNameToNtPathName_U")
dd("g_access", 0, "g_access: DesiredAccess held across the RtlDosPathNameToNtPathName_U call")
dd("g_disp", 0, "g_disp: CreateDisposition, same")
dd("g_handle", 0, "g_handle: NtCreateFile's out-parameter")
space("oa", 24, "oa: OBJECT_ATTRIBUTES (Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService)")
space("nt_path", 8, "nt_path: UNICODE_STRING filled by RtlDosPathNameToNtPathName_U")
space("iosb", 8, "iosb: IO_STATUS_BLOCK, required by the ABI")
dd("in_handle", 0, "in_handle: argv[1] opened for reading")
dd("out_handle", 0, "out_handle: argv[2] opened for writing")
dd("arg_in", 0, "arg_in: PWSTR argv[1]")
dd("arg_out", 0, "arg_out: PWSTR argv[2]")
dd("toggle", -1, "toggle: -1 = waiting for the first nibble, 0 = have it")
dd("accum", 0, "accum: the first nibble of a pair")
space("input", 1, "input: 1-byte read buffer")
space("output", 1, "output: 1-byte write buffer")

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

"_start": """Resolve the six ntdll routines, parse the command line, open both files, then
fall into the conversion loop.  ebx holds the ntdll base across the six
resolve_export calls.  The command line is PEB->ProcessParameters->CommandLine,
a UNICODE_STRING at 0x40 whose Buffer field is at 0x44.  argv[0] is the program
name and is discarded.""",

"loop": """Read one byte, classify it, and emit one byte per completed pair.
NtReadFile returns an NTSTATUS; end of file is STATUS_END_OF_FILE (0xC0000011),
which is negative, so a sign test ends the run.""",

"print": """A pair is complete: write (first << 4) | second as one byte and set toggle back
to -1 to await the next pair.""",

"done": """Close both handles and exit.  NtTerminateProcess takes -1, the pseudo-handle
for the current process.""",

"hex": """hex(eax = byte) -> 0-15, or -1 for a byte that carries no value.
'#' and ';' both begin a comment.  Anything that is not a hex digit is ignored.""",

"comment": """Discard bytes to end of line, then return -1 through other.
End of file inside a comment gives the same result.""",

"num": "'0'-'9' -> 0-9.",
"low": "'a'-'f' -> 10-15.",
"high": "'A'-'F' -> 10-15.",
"other": "Not part of a hex pair: return -1 so the caller ignores this byte.",
"name_NtCreateFile": "Export names, matched by resolve_export.",
"fn_create": "Resolved routine addresses.  Kept in memory because six will not fit in registers.",
"g_access": "Arguments that must survive the RtlDosPathNameToNtPathName_U call.",
"oa": "OBJECT_ATTRIBUTES: Length, RootDirectory, ObjectName, Attributes, SecurityDescriptor, SecurityQualityOfService.",
"nt_path": "UNICODE_STRING (Length, MaximumLength, Buffer) filled in by RtlDosPathNameToNtPathName_U.",
"iosb": "IO_STATUS_BLOCK.  Unused here, required by the ABI.",
"in_handle": "The two open files and the argv pointers they came from.",
"toggle": "toggle is -1 while awaiting a pair's first nibble, 0 once accum holds it.",
"input": "One-byte read and write buffers.",
}

# ===================== emit =====================
BANNER = "\n".join(spdx([UPSTREAM, PORT])) + """hex0-pe32: the Windows (PE32/i386) port of stage0's hex0 seed.

hex0 reads a file of hexadecimal digit pairs and writes the bytes they denote.
Assembling this file reproduces hex0.exe byte for byte.

  hex0 INPUT OUTPUT
    argv[1]        a path, opened for reading
    argv[2]        a path, created or truncated for writing
    [0-9A-Fa-f]    a hexadecimal digit; two of them make one output byte
    '#' or ';'     begins a comment, ignored to end of line
    anything else  ignored

The POSIX build also does chmod(argv[2], 0700); Windows has no executable bit,
so that step has no counterpart here.

The image imports nothing: NumberOfRvaAndSizes is 0, so there is no import
directory.  ntdll is located through the PEB at run time and the six routines
this program calls are resolved from ntdll's export table by name.

One section holds the code followed by the data, mapped read/write/execute."""

sys.exit(0 if emit_pe(a, BANNER, DOC, "name_NtCreateFile", sys.argv[1], sys.argv[2], sys.argv[3], "hex0") else 1)
