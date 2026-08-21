#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""The routines every program above catm needs, and the data they use.

Windows has no syscall a program may make directly, so every one of these
programs has to find ntdll through the PEB, resolve what it needs out of the
export table by name, and turn a DOS path into the NT path NtCreateFile wants.
That is a fixed cost of the platform and it is the same in every program, so
from M0 upward it lives here and catm puts it in front of the program, the way
it puts the header stub in front of both.

hex0, hex1, hex2 and catm cannot use this: there is no catm below catm to join
files with, so they carry their own copies.
"""
import struct
from stage0asm import (Asm, emit_find_ntdll, emit_resolve_export,
                       emit_next_token, emit_open_file)

BOUNDARY = "__shared_end"

# Every ntdll routine any program here resolves, in the order resolve_all fills
# them in.  That order is the slot numbering libc-core.M1's __ntdll indexes and
# M2libc/x86/windows/ntdll-slots.h names, so it is the one place it is written
# down: append here, never insert, and regenerate.
#
# The first eight are what the hand-written stages need and are reached from
# assembly by name.  The rest are for the POSIX layer above, which reaches them
# by slot from C.  A name ntdll does not export leaves its slot 0 rather than
# failing -- resolve_export returns 0 when it runs off the end of the export
# table -- so a routine that only some Windows-alikes have can be listed here
# and checked for by the one caller that wants it.  Resolving all of them in every program costs a walk of
# ntdll's export table each, at startup, which is not measurable next to the
# rest of what these programs do.
NTDLL = [
    ("fn_create",     "NtCreateFile",                 "open a file, or make one"),
    ("fn_read",       "NtReadFile",                   "read"),
    ("fn_write",      "NtWriteFile",                  "write"),
    ("fn_close",      "NtClose",                      "close, and any other handle"),
    ("fn_exit",       "NtTerminateProcess",           "_exit"),
    ("fn_rtlpath",    "RtlDosPathNameToNtPathName_U", "a DOS path becomes an NT path"),
    ("fn_setinfo",    "NtSetInformationFile",         "lseek, and unlink"),
    ("fn_queryinfo",  "NtQueryInformationFile",       "lseek, and fstat"),
    ("fn_queryattr",  "NtQueryAttributesFile",        "access"),
    ("fn_queryfull",  "NtQueryFullAttributesFile",    "stat"),
    ("fn_setcwd",     "RtlSetCurrentDirectory_U",     "chdir"),
    ("fn_getcwd",     "RtlGetCurrentDirectory_U",     "getcwd"),
    ("fn_dup",        "NtDuplicateObject",            "dup and dup2"),
    ("fn_time",       "NtQuerySystemTime",            "time, gettimeofday, clock_gettime"),
    ("fn_queryvol",   "NtQueryVolumeInformationFile", "isatty"),
    ("fn_wait",       "NtWaitForSingleObject",        "waitpid"),
    ("fn_queryproc",  "NtQueryInformationProcess",    "waitpid, for the exit status"),
    ("fn_delete",     "NtDeleteFile",                 "unlink and rmdir"),
    ("fn_version",    "RtlGetVersion",                "uname"),
    ("fn_makeparams", "RtlCreateProcessParameters",   "__spawn, for the child's parameter block"),
    ("fn_createproc", "RtlCreateUserProcess",         "__spawn"),
    ("fn_resume",     "NtResumeThread",               "__spawn: a new process starts suspended"),
    ("fn_alloc",      "NtAllocateVirtualMemory",      "a real brk, for a program too big to live inside the image"),
    ("fn_clone",      "RtlCloneUserProcess",          "fork; absent on wine, where the slot stays 0"),
    ("fn_getcontext", "NtGetContextThread",           "fork: the context a suspended child would start with"),
    ("fn_setcontext", "NtSetContextThread",           "fork: point that child at where its parent was instead"),
    ("fn_writevm",    "NtWriteVirtualMemory",         "fork: copy this process's memory into that child"),
    ("fn_readvm",     "NtReadVirtualMemory",          "fork: watch for the child to say it has parked"),
    ("fn_suspend",    "NtSuspendThread",              "fork: stop that child before overwriting it"),
    ("fn_wow64qinfo", "NtWow64QueryInformationProcess64", "wow64 clone fix: this process's own 64-bit PEB address"),
    ("fn_wow64readvm","NtWow64ReadVirtualMemory64",   "wow64 clone fix: read the 64-bit ntdll/wow64cpu images to resolve BTCpuSimulate"),
]

def emit_shared(a):
    """Code first, then the data it uses, then the boundary label."""
    emit_find_ntdll(a)
    emit_resolve_export(a)
    emit_next_token(a, tabs=True, escapes=True)
    emit_open_file(a, check_status=True, inheritable=True)

    def I(hx, mn, prose=None):
        a.raw(bytes.fromhex(hx.replace(" ", "")), a._c(mn, prose))

    # ---- fgetc ----
    a.label("fgetc")
    a.push_r("ebx", "an ntdll call keeps ebx, esi, edi and ebp, but not ecx or edx")
    a.push_r("ecx")
    a.push_r("edx")
    a.push_imm(0, "Key")
    a.push_imm(0, "ByteOffset = NULL: FILE_SYNCHRONOUS_IO_NONALERT keeps the file position")
    a.push_imm(1, "Length = 1")
    a.push_lbl("inbuf", "Buffer")
    a.push_lbl("iosb", "IoStatusBlock")
    a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
    a.push_mem("in_handle", "FileHandle")
    a.call_mem("fn_read")
    I("85 C0", "test eax, eax", "NTSTATUS < 0 (STATUS_END_OF_FILE) is the end")
    a.jcc("s", "fgetc.eof", "js fgetc.eof")
    a.movzx_eax_mem("inbuf", "movzx eax, byte [inbuf]")
    a.jmp("fgetc.done", "jmp fgetc.done")
    a.label("fgetc.eof")
    a.mov_r_imm("eax", -4, "mov eax, -4  -- EOF, as upstream reports it")
    a.label("fgetc.done")
    a.pop_r("edx")
    a.pop_r("ecx")
    a.pop_r("ebx")
    a.ret("ret")

    # ---- fputc ----
    a.label("fputc")
    a.push_r("eax", "the byte written comes back in eax, as upstream's fputc leaves it")
    a.push_r("ebx")
    a.push_r("ecx")
    a.push_r("edx")
    a.mov_mem_al("outbuf", "mov [outbuf], al")
    a.push_imm(0, "Key"); a.push_imm(0, "ByteOffset"); a.push_imm(1, "Length = 1")
    a.push_lbl("outbuf", "Buffer"); a.push_lbl("iosb", "IoStatusBlock")
    a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
    a.push_mem("out_handle", "FileHandle")
    a.call_mem("fn_write")
    a.pop_r("edx")
    a.pop_r("ecx")
    a.pop_r("ebx")
    a.pop_r("eax")
    a.ret("ret")

    # ---- resolve_all: fill in every fn_ slot ----
    a.label("resolve_all")
    a.call("find_ntdll", "call find_ntdll")
    I("89 C3", "mov ebx, eax", "ntdll base, held across every resolve_export call")
    for slot, export, _why in NTDLL:
        a.push_lbl("name_" + export)
        a.push_r("ebx", "module_base")
        a.call("resolve_export", "call resolve_export")
        a.mov_mem_r(slot, "eax")
    a.ret("ret")

    # ---- open_argv: argv[1] for reading, argv[2] for writing ----
    a.label("open_argv")
    a.raw(b"\x64\xa1\x30\x00\x00\x00", "mov eax, [fs:0x30]  -- PEB")
    a.raw(b"\x8b\x40\x10", "mov eax, [eax+0x10]  -- PEB->ProcessParameters")
    a.raw(b"\x8b\x70\x44", "mov esi, [eax+0x44]  -- CommandLine.Buffer (UNICODE_STRING at 0x40, Buffer at +4)")
    a.call("next_token", "argv[0]: the program name, discarded")
    a.call("next_token", "argv[1]: the input path")
    a.mov_r_imm("ecx", 0x80100000, "GENERIC_READ|SYNCHRONIZE")
    a.mov_r_imm("edx", 1, "FILE_OPEN")
    a.call("open_file", "call open_file")
    a.mov_mem_r("in_handle", "eax", "mov [in_handle], eax")
    a.call("next_token", "argv[2]: the output path")
    a.mov_r_imm("ecx", 0x40100000, "GENERIC_WRITE|SYNCHRONIZE")
    a.mov_r_imm("edx", 5, "FILE_OVERWRITE_IF")
    a.call("open_file", "call open_file")
    a.mov_mem_r("out_handle", "eax", "mov [out_handle], eax")
    a.ret("ret")

    # ---- exit_ok ----
    a.label("exit_ok")
    a.push_mem("out_handle", "push out_handle")
    a.call_mem("fn_close")
    a.push_mem("in_handle", "push in_handle")
    a.call_mem("fn_close")
    a.push_imm(0, "ExitStatus = 0")
    a.push_imm(-1, "ProcessHandle = NtCurrentProcess pseudo-handle")
    a.call_mem("fn_exit")

    # ---- data ----
    def asciiz(name, s):
        a.label(name); a.raw(s.encode() + b"\x00", '%s = "%s"' % (name, s))
    def dd(name, v, note):
        a.label(name); a.raw(struct.pack("<i" if v < 0 else "<I", v), note)
    def space(name, n, note):
        a.label(name); a.raw(b"\x00" * n, note)

    for _slot, export, _why in NTDLL:
        asciiz("name_" + export, export)
    # The fn_ slots are one contiguous array of resolved addresses, and
    # fn_table names its start: libc-core.M1's __ntdll indexes it, so C above
    # can reach an ntdll routine without a hand-written stub for each one.
    a.label("fn_table")
    for i, (slot, export, why) in enumerate(NTDLL):
        dd(slot, 0, "%s: slot %d, resolved %s -- %s" % (slot, i, export, why))
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
    dd("iosb_info", 0, "iosb_info: IO_STATUS_BLOCK.Information")
    dd("in_handle", 0, "in_handle: argv[1]")
    dd("out_handle", 0, "out_handle: argv[2]")
    space("inbuf", 1, "inbuf: one-byte read buffer")
    space("outbuf", 1, "outbuf: one-byte write buffer")

    a.label(BOUNDARY)

SHARED_DOC = {
"find_ntdll": """find_ntdll() -> ntdll base address.
TEB (fs:0x30) -> PEB -> Ldr -> InMemoryOrderModuleList.  The first entry in
that list is the main EXE and the second is ntdll, by loader convention.""",
"resolve_export": """resolve_export(module_base, name) -> address, or 0 if not found.
stdcall: arguments pushed right to left, callee cleans the stack.  Reads
e_lfanew to reach the PE header, then walks the export directory: a name match
gives an index, that index gives an ordinal, that ordinal gives an address.""",
"next_token": """next_token() -> eax = the next argument, or 0 when exhausted.
esi is the cursor into the command line.  Characters are UTF-16, so it advances
two bytes at a time, and the terminator is overwritten with a NUL in place.  A
separator is space or tab; see emit_next_token's own docstring for why tab
matters here.""",
"open_file": """open_file(eax = path, ecx = DesiredAccess, edx = CreateDisposition)
-> handle, or 0 if the file could not be opened.
RtlDosPathNameToNtPathName_U turns the DOS path into the NT path NtCreateFile
needs, resolving a relative path against the working directory.
FILE_SYNCHRONOUS_IO_NONALERT keeps the file position in the I/O manager, which
is why every read and write passes a NULL ByteOffset and still advances.
The path is UTF-16, which is the only kind ntdll takes.""",
"fgetc": """fgetc() -> eax = the next byte of the input, or -4 at end of file.
-4 rather than -1 because that is what upstream's fgetc returns and what its
callers compare against.  Every register but eax comes back untouched, which is
what upstream's callers assume of it.""",
"fputc": """fputc(al = byte): one write per byte, as upstream does it.  Every
register comes back untouched, eax included, so a caller may write the same byte
twice without reloading it.""",
"resolve_all": """resolve_all(): fill in the eight fn_ slots.  Call this before anything
else; nothing below works until it has run.""",
"open_argv": """open_argv(): argv[1] opened for reading, argv[2] created or truncated for
writing.  Every program in this chain takes exactly those two arguments.""",
"exit_ok": "exit_ok(): close both files and exit 0.  Does not return.",
"name_NtCreateFile": "Export names, matched by resolve_export.",
"fn_create": "Resolved routine addresses.  Kept in memory because eight will not fit in registers.",
"g_access": "Arguments that must survive the RtlDosPathNameToNtPathName_U call.",
"oa": "OBJECT_ATTRIBUTES, one label per field so hex2 can address each of them.",
"iosb": "IO_STATUS_BLOCK.  Information is the byte count of a read.",
"in_handle": "The two open files.",
"inbuf": "One-byte read and write buffers.",
}
