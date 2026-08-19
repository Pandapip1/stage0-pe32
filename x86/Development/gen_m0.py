#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate M0_pe32: the Windows PE32 port of stage0's M0 macro assembler.

Unlike the links below it, this source carries no PE header: catm puts
PE32-i386.hex2 in front of it, exactly as upstream catms ELF-i386.hex2 in front
of M0_x86.hex2.
"""
import sys, struct
from stage0asm import *
from pe32emit import emit_pe_hex2

a = Asm()

# Token struct, laid out as upstream lays it out (32 bytes, fields 8 apart).
NEXT, TYPE, TEXT, EXPR, TOKSZ = 0, 8, 16, 24, 32
MACRO, STRING = 1, 2
STRSZ = 256          # upstream calloc's 64 and never bounds-checks; this is the
                     # same code with more room, not different behaviour

def I(hx, mn, prose=None):
    a.raw(bytes.fromhex(hx.replace(" ", "")), a._c(mn, prose))

emit_find_ntdll(a)
emit_resolve_export(a)
emit_next_token(a)
emit_open_file(a)

# ---------------------------------------------------------------- fgetc
a.label("fgetc")
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
a.ret("ret")
a.label("fgetc.eof")
a.mov_r_imm("eax", -4, "mov eax, -4  -- EOF, as upstream reports it")
a.ret("ret")

# ---------------------------------------------------------------- fputc
a.label("fputc")
a.mov_mem_al("outbuf", "mov [outbuf], al")
a.push_imm(0, "Key"); a.push_imm(0, "ByteOffset"); a.push_imm(1, "Length = 1")
a.push_lbl("outbuf", "Buffer"); a.push_lbl("iosb", "IoStatusBlock")
a.push_imm(0, "ApcContext"); a.push_imm(0, "ApcRoutine"); a.push_imm(0, "Event")
a.push_mem("out_handle", "FileHandle")
a.call_mem("fn_write")
a.ret("ret")

# ---------------------------------------------------------------- malloc
a.label("malloc")
I("53", "push ebx")
a.mov_r_mem("ebx", "malloc_ptr", "mov ebx, [malloc_ptr]")
a.add_mem_reg("malloc_ptr", "eax", "add [malloc_ptr], eax")
I("89 D8", "mov eax, ebx", "the block starts where the cursor was")
I("5B", "pop ebx")
a.ret("ret")

# ---------------------------------------------------------------- In_Set
a.label("In_Set")
I("53", "push ebx"); I("51", "push ecx")
a.label("In_Set.loop")
I("8A 0B", "mov cl, [ebx]"); I("0F B6 C9", "movzx ecx, cl")
I("85 C9", "test ecx, ecx")
a.jcc("e", "In_Set.false", "je In_Set.false  -- the NUL ends the set")
I("39 C8", "cmp eax, ecx")
a.jcc("e", "In_Set.true", "je In_Set.true")
I("43", "inc ebx")
a.jmp("In_Set.loop", "jmp In_Set.loop")
a.label("In_Set.true")
a.mov_r_imm("eax", 1, "mov eax, 1")
I("59", "pop ecx"); I("5B", "pop ebx"); a.ret("ret")
a.label("In_Set.false")
I("31 C0", "xor eax, eax")
I("59", "pop ecx"); I("5B", "pop ebx"); a.ret("ret")

# ---------------------------------------------------------------- match
a.label("match")
I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx")
I("89 C2", "mov edx, eax", "walk both strings together")
a.label("match.loop")
I("8A 0A", "mov cl, [edx]"); I("0F B6 C9", "movzx ecx, cl")
I("8A 03", "mov al, [ebx]"); I("0F B6 C0", "movzx eax, al")
I("39 C1", "cmp ecx, eax")
a.jcc("ne", "match.false", "jne match.false")
I("85 C9", "test ecx, ecx")
a.jcc("e", "match.true", "je match.true  -- both hit NUL together")
I("42", "inc edx"); I("43", "inc ebx")
a.jmp("match.loop", "jmp match.loop")
a.label("match.true")
I("31 C0", "xor eax, eax", "0 means equal, as upstream returns it")
a.jmp("match.done", "jmp match.done")
a.label("match.false")
a.mov_r_imm("eax", 1, "mov eax, 1")
a.label("match.done")
I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx"); a.ret("ret")

# ---------------------------------------------------------------- string_length
a.label("string_length")
I("53", "push ebx"); I("51", "push ecx")
I("89 C3", "mov ebx, eax"); I("31 C9", "xor ecx, ecx")
a.label("string_length.loop")
I("8A 04 0B", "mov al, [ebx+ecx]"); I("0F B6 C0", "movzx eax, al")
I("85 C0", "test eax, eax")
a.jcc("e", "string_length.done", "je string_length.done")
I("41", "inc ecx")
a.jmp("string_length.loop", "jmp string_length.loop")
a.label("string_length.done")
I("89 C8", "mov eax, ecx")
I("59", "pop ecx"); I("5B", "pop ebx"); a.ret("ret")

# ---------------------------------------------------------------- hex output
a.label("hex32l")
I("50", "push eax", "protect the top half")
a.call("hex16l", "call hex16l")
I("58", "pop eax")
I("C1 E8 10", "shr eax, 16", "the low half went out first, so this is little-endian")
a.label("hex16l")
I("50", "push eax")
a.call("hex8", "call hex8")
I("58", "pop eax")
I("C1 E8 08", "shr eax, 8")
a.label("hex8")
I("50", "push eax")
I("C1 E8 04", "shr eax, 4", "high nibble first")
a.call("hex4", "call hex4")
I("58", "pop eax")
a.label("hex4")
I("83 E0 0F", "and eax, 0xf")
I("04 30", "add al, '0'")
I("3C 39", "cmp al, '9'")
a.jcc("be", "hex1", "jbe hex1")
I("04 07", "add al, 7", "shift into 'A'-'F'")
a.label("hex1")
I("88 03", "mov [ebx], al")
I("83 C3 01", "add ebx, 1")
a.ret("ret")

# ---------------------------------------------------------------- numerate_string
a.label("numerate_string")
I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx"); I("57", "push edi")
I("89 C3", "mov ebx, eax", "S")
I("31 C0", "xor eax, eax", "VALUE = 0")
I("31 FF", "xor edi, edi", "NEGATIVE = 0  -- upstream never initialises this; see the note")
I("8A 4B 01", "mov cl, [ebx+1]"); I("0F B6 C9", "movzx ecx, cl", "S[1]")
I("83 F9 78", "cmp ecx, 'x'")
a.jcc("e", "numerate_string.hex", "je numerate_string.hex  -- tested before the sign, so 0x is only ever positive")
I("B9 00 00 00 00", "mov ecx, 0")
I("8A 0B", "mov cl, [ebx]"); I("0F B6 C9", "movzx ecx, cl", "S[0]")
I("83 F9 2D", "cmp ecx, '-'")
a.jcc("ne", "numerate_string.dec", "jne numerate_string.dec")
a.mov_r_imm("edi", 1, "mov edi, 1")
I("83 C3 01", "add ebx, 1")
a.label("numerate_string.dec")
I("8A 0B", "mov cl, [ebx]"); I("0F B6 C9", "movzx ecx, cl")
I("83 F9 00", "cmp ecx, 0")
a.jcc("e", "numerate_string.decdone", "je numerate_string.decdone")
I("6B C0 0A", "imul eax, 10")
I("83 E9 30", "sub ecx, '0'")
I("83 F9 09", "cmp ecx, 9")
a.jcc("g", "numerate_string.fail", "jg numerate_string.fail")
I("83 F9 00", "cmp ecx, 0")
a.jcc("l", "numerate_string.fail", "jl numerate_string.fail")
I("01 C8", "add eax, ecx")
I("83 C3 01", "add ebx, 1")
a.jmp("numerate_string.dec", "jmp numerate_string.dec")
a.label("numerate_string.decdone")
I("83 FF 01", "cmp edi, 1")
a.jcc("ne", "numerate_string.done", "jne numerate_string.done")
I("6B C0 FF", "imul eax, -1")
a.jmp("numerate_string.done", "jmp numerate_string.done")
a.label("numerate_string.hex")
I("83 C3 02", "add ebx, 2", "step over the 0x")
a.label("numerate_string.hexloop")
I("8A 0B", "mov cl, [ebx]"); I("0F B6 C9", "movzx ecx, cl")
I("83 F9 00", "cmp ecx, 0")
a.jcc("e", "numerate_string.done", "je numerate_string.done")
I("C1 E0 04", "shl eax, 4")
I("83 E9 30", "sub ecx, '0'")
I("83 F9 0A", "cmp ecx, 10")
a.jcc("l", "numerate_string.digit", "jl numerate_string.digit")
I("83 E9 07", "sub ecx, 7", "push A-F into range; lower case does not survive this")
a.label("numerate_string.digit")
I("83 F9 0F", "cmp ecx, 15")
a.jcc("g", "numerate_string.fail", "jg numerate_string.fail")
I("83 F9 00", "cmp ecx, 0")
a.jcc("l", "numerate_string.fail", "jl numerate_string.fail")
I("01 C8", "add eax, ecx")
I("83 C3 01", "add ebx, 1")
a.jmp("numerate_string.hexloop", "jmp numerate_string.hexloop")
a.label("numerate_string.fail")
I("31 C0", "xor eax, eax", "not a number: return zero and let the caller decide")
a.label("numerate_string.done")
I("5F", "pop edi"); I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx")
a.ret("ret")

# ---------------------------------------------------------------- express_number
a.label("express_number")
I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx")
I("89 D9", "mov ecx, ebx", "CH")
I("89 C3", "mov ebx, eax", "protect VALUE")
I("83 F9 25", "cmp ecx, '%'")
a.jcc("ne", "express_number.at", "jne express_number.at")
a.mov_r_imm("eax", 9, "mov eax, 9  -- eight digits and a NUL")
a.call("malloc", "call malloc")
I("93", "xchg eax, ebx", "eax = VALUE, ebx = S")
I("53", "push ebx", "protect S; the hex routines advance it")
a.call("hex32l", "call hex32l")
a.jmp("express_number.done", "jmp express_number.done")
a.label("express_number.at")
I("83 F9 40", "cmp ecx, '@'")
a.jcc("ne", "express_number.one", "jne express_number.one")
a.mov_r_imm("eax", 5, "mov eax, 5")
a.call("malloc", "call malloc")
I("93", "xchg eax, ebx"); I("53", "push ebx")
a.call("hex16l", "call hex16l")
a.jmp("express_number.done", "jmp express_number.done")
a.label("express_number.one")
a.mov_r_imm("eax", 3, "mov eax, 3")
a.call("malloc", "call malloc")
I("93", "xchg eax, ebx"); I("53", "push ebx")
a.call("hex8", "call hex8")
a.label("express_number.done")
I("58", "pop eax", "S")
I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx")
a.ret("ret")

# ---------------------------------------------------------------- Store_Atom
a.label("Store_Atom")
I("53", "push ebx"); I("56", "push esi"); I("57", "push edi")
a.mov_r_imm("eax", STRSZ, "mov eax, %d" % STRSZ)
a.call("malloc", "call malloc")
I("89 C6", "mov esi, eax", "keep the start to return; esi survives a call, edx does not")
I("89 C7", "mov edi, eax", "cursor")
a.label("Store_Atom.loop")
I("89 C8", "mov eax, ecx")
I("88 07", "mov [edi], al")
I("47", "inc edi")
a.call("fgetc", "call fgetc")
I("89 C1", "mov ecx, eax")
I("83 F8 FC", "cmp eax, -4")
a.jcc("e", "Store_Atom.done", "je Store_Atom.done  -- end of file ends the atom too")
a.mov_r_lbl("ebx", "terminators", "mov ebx, terminators")
a.call("In_Set", "call In_Set")
I("85 C0", "test eax, eax")
a.jcc("e", "Store_Atom.loop", "je Store_Atom.loop")
a.label("Store_Atom.done")
I("89 F0", "mov eax, esi")
I("5F", "pop edi"); I("5E", "pop esi"); I("5B", "pop ebx")
a.ret("ret")

# ---------------------------------------------------------------- Store_String
a.label("Store_String")
I("53", "push ebx"); I("56", "push esi"); I("57", "push edi")
I("51", "push ecx", "the quote is also the terminator")
a.mov_r_imm("eax", STRSZ, "mov eax, %d" % STRSZ)
a.call("malloc", "call malloc")
I("89 C6", "mov esi, eax"); I("89 C7", "mov edi, eax")
I("5B", "pop ebx", "ebx = the quote character")
a.label("Store_String.loop")
I("89 C8", "mov eax, ecx")
I("88 07", "mov [edi], al")
I("47", "inc edi")
a.call("fgetc", "call fgetc")
I("89 C1", "mov ecx, eax")
I("83 F8 FC", "cmp eax, -4")
a.jcc("e", "Store_String.done", "je Store_String.done")
I("39 D8", "cmp eax, ebx")
a.jcc("ne", "Store_String.loop", "jne Store_String.loop")
a.label("Store_String.done")
I("89 F0", "mov eax, esi", "the opening quote is kept, the closing one is not")
I("5F", "pop edi"); I("5E", "pop esi"); I("5B", "pop ebx")
a.ret("ret")

# ---------------------------------------------------------------- Tokenize_Line
a.label("Tokenize_Line")
a.label("Tokenize_Line.restart")
a.call("fgetc", "call fgetc")
a.mov_mem_r("tok_c", "eax", "mov [tok_c], eax")
I("83 F8 FC", "cmp eax, -4")
a.jcc("e", "Tokenize_Line.eof", "je Tokenize_Line.eof")
a.mov_r_lbl("ebx", "comments", "mov ebx, comments")
a.call("In_Set", "call In_Set")
I("85 C0", "test eax, eax")
a.jcc("ne", "Tokenize_Line.comment", "jne Tokenize_Line.comment")
a.mov_r_mem("eax", "tok_c", "mov eax, [tok_c]")
a.mov_r_lbl("ebx", "terminators", "mov ebx, terminators")
a.call("In_Set", "call In_Set")
I("85 C0", "test eax, eax")
a.jcc("ne", "Tokenize_Line.restart", "jne Tokenize_Line.restart  -- whitespace between tokens")
a.mov_r_imm("eax", TOKSZ, "mov eax, %d" % TOKSZ)
a.call("malloc", "call malloc")
a.mov_mem_r("tok_p", "eax", "mov [tok_p], eax")
a.mov_r_mem("ebx", "head", "mov ebx, [head]")
I("89 18", "mov [eax], ebx", "p->NEXT = head; the list is built backwards")
a.mov_mem_r("head", "eax", "mov [head], eax")
a.mov_r_mem("eax", "tok_c", "mov eax, [tok_c]")
a.mov_r_lbl("ebx", "string_char", "mov ebx, string_char")
a.call("In_Set", "call In_Set")
I("85 C0", "test eax, eax")
a.jcc("ne", "Tokenize_Line.string", "jne Tokenize_Line.string")
a.mov_r_mem("ecx", "tok_c", "mov ecx, [tok_c]")
a.call("Store_Atom", "call Store_Atom")
a.mov_r_mem("ebx", "tok_p", "mov ebx, [tok_p]")
I("89 43 10", "mov [ebx+16], eax", "p->TEXT")
a.ret("ret")
a.label("Tokenize_Line.string")
a.mov_r_mem("ecx", "tok_c", "mov ecx, [tok_c]")
a.call("Store_String", "call Store_String")
a.mov_r_mem("ebx", "tok_p", "mov ebx, [tok_p]")
I("89 43 10", "mov [ebx+16], eax", "p->TEXT")
I("C7 43 08 02 00 00 00", "mov dword [ebx+8], 2", "p->TYPE = STRING")
a.ret("ret")
a.label("Tokenize_Line.comment")
a.call("fgetc", "call fgetc")
I("83 F8 FC", "cmp eax, -4")
a.jcc("e", "Tokenize_Line.eof", "je Tokenize_Line.eof")
I("83 F8 0A", "cmp eax, 10")
a.jcc("ne", "Tokenize_Line.comment", "jne Tokenize_Line.comment")
a.jmp("Tokenize_Line.restart", "jmp Tokenize_Line.restart")
a.label("Tokenize_Line.eof")
a.mov_mem_imm("eof_flag", 1, "mov dword [eof_flag], 1")
a.ret("ret")

# ---------------------------------------------------------------- Reverse_List
a.label("Reverse_List")
I("53", "push ebx"); I("51", "push ecx")
I("31 DB", "xor ebx, ebx", "prev = NULL")
a.label("Reverse_List.loop")
I("85 C0", "test eax, eax")
a.jcc("e", "Reverse_List.done", "je Reverse_List.done")
I("8B 08", "mov ecx, [eax]", "next")
I("89 18", "mov [eax], ebx", "cur->NEXT = prev")
I("89 C3", "mov ebx, eax")
I("89 C8", "mov eax, ecx")
a.jmp("Reverse_List.loop", "jmp Reverse_List.loop")
a.label("Reverse_List.done")
I("89 D8", "mov eax, ebx")
I("59", "pop ecx"); I("5B", "pop ebx")
a.ret("ret")

# ---------------------------------------------------------------- Identify_Macros
a.label("Identify_Macros")
I("50", "push eax"); I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx")
I("89 C2", "mov edx, eax", "I = HEAD")
a.label("Identify_Macros.loop")
I("8B 42 10", "mov eax, [edx+16]", "I->TEXT")
a.mov_r_lbl("ebx", "DEFINE_str", "mov ebx, DEFINE_str")
a.call("match", "call match")
I("85 C0", "test eax, eax")
a.jcc("ne", "Identify_Macros.next", "jne Identify_Macros.next")
I("C7 42 08 01 00 00 00", "mov dword [edx+8], 1", "I->TYPE = MACRO")
I("8B 02", "mov eax, [edx]", "I->NEXT, the name")
I("8B 48 10", "mov ecx, [eax+16]")
I("89 4A 10", "mov [edx+16], ecx", "I->TEXT = name")
I("8B 18", "mov ebx, [eax]", "the expansion token")
I("8B 4B 10", "mov ecx, [ebx+16]")
I("8B 43 08", "mov eax, [ebx+8]", "its TYPE")
I("83 F8 02", "cmp eax, 2")
a.jcc("ne", "Identify_Macros.plain", "jne Identify_Macros.plain")
I("41", "inc ecx", "a string expansion starts after the quote")
a.label("Identify_Macros.plain")
I("89 4A 18", "mov [edx+24], ecx", "I->EXPRESSION")
I("8B 03", "mov eax, [ebx]")
I("89 02", "mov [edx], eax", "I->NEXT skips the two tokens just consumed")
a.label("Identify_Macros.next")
I("8B 12", "mov edx, [edx]")
I("85 D2", "test edx, edx")
a.jcc("ne", "Identify_Macros.loop", "jne Identify_Macros.loop")
I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx"); I("58", "pop eax")
a.ret("ret")

# ---------------------------------------------------------------- Set_Expression
a.label("Set_Expression")
I("50", "push eax"); I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx"); I("56", "push esi")
I("89 C2", "mov edx, eax", "I")
I("89 CE", "mov esi, ecx", "EXP")
a.label("Set_Expression.loop")
I("8B 42 08", "mov eax, [edx+8]")
I("83 F8 01", "cmp eax, 1")
a.jcc("e", "Set_Expression.next", "je Set_Expression.next  -- leave macros alone")
I("8B 42 10", "mov eax, [edx+16]")
a.call("match", "call match")
I("85 C0", "test eax, eax")
a.jcc("ne", "Set_Expression.next", "jne Set_Expression.next")
I("89 72 18", "mov [edx+24], esi", "I->EXPRESSION = EXP")
a.label("Set_Expression.next")
I("8B 12", "mov edx, [edx]")
I("85 D2", "test edx, edx")
a.jcc("ne", "Set_Expression.loop", "jne Set_Expression.loop")
I("5E", "pop esi"); I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx"); I("58", "pop eax")
a.ret("ret")

# ---------------------------------------------------------------- Line_Macro
a.label("Line_Macro")
I("50", "push eax"); I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx")
I("89 C2", "mov edx, eax")
a.label("Line_Macro.loop")
I("8B 42 08", "mov eax, [edx+8]")
I("83 F8 01", "cmp eax, 1")
a.jcc("ne", "Line_Macro.next", "jne Line_Macro.next")
I("8B 02", "mov eax, [edx]")
I("85 C0", "test eax, eax")
a.jcc("e", "Line_Macro.next", "je Line_Macro.next  -- nothing follows to substitute into")
I("8B 5A 10", "mov ebx, [edx+16]", "the macro name")
I("8B 4A 18", "mov ecx, [edx+24]", "its expansion")
a.call("Set_Expression", "call Set_Expression")
a.label("Line_Macro.next")
I("8B 12", "mov edx, [edx]")
I("85 D2", "test edx, edx")
a.jcc("ne", "Line_Macro.loop", "jne Line_Macro.loop")
I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx"); I("58", "pop eax")
a.ret("ret")

# ---------------------------------------------------------------- Process_String
a.label("Process_String")
I("50", "push eax"); I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx")
I("89 C1", "mov ecx, eax", "I")
a.label("Process_String.loop")
I("8B 41 08", "mov eax, [ecx+8]")
I("83 F8 02", "cmp eax, 2")
a.jcc("ne", "Process_String.next", "jne Process_String.next")
I("8B 59 10", "mov ebx, [ecx+16]", "I->TEXT")
I("8A 03", "mov al, [ebx]"); I("0F B6 C0", "movzx eax, al")
I("83 F8 27", "cmp eax, 0x27")
a.jcc("ne", "Process_String.raw", "jne Process_String.raw")
I("83 C3 01", "add ebx, 1")
I("89 59 18", "mov [ecx+24], ebx", "'...' passes through as written")
a.jmp("Process_String.next", "jmp Process_String.next")
a.label("Process_String.raw")
I("89 D8", "mov eax, ebx")
a.call("string_length", "call string_length")
I("C1 E8 02", "shr eax, 2")
I("83 C0 01", "add eax, 1")
I("C1 E0 03", "shl eax, 3", "room enough for two digits a character")
a.call("malloc", "call malloc")
I("89 DA", "mov edx, ebx")
I("83 C2 01", "add edx, 1", "S = I->TEXT + 1, past the quote")
I("89 41 18", "mov [ecx+24], eax")
I("89 C3", "mov ebx, eax", "the hex cursor")
a.label("Process_String.rawloop")
I("8A 02", "mov al, [edx]"); I("0F B6 C0", "movzx eax, al")
I("83 C2 01", "add edx, 1")
I("3C 00", "cmp al, 0")
I("9C", "pushf", "the NUL is emitted too, then ends the loop")
a.call("hex8", "call hex8")
I("9D", "popf")
a.jcc("ne", "Process_String.rawloop", "jne Process_String.rawloop")
a.label("Process_String.next")
I("8B 09", "mov ecx, [ecx]")
I("85 C9", "test ecx, ecx")
a.jcc("ne", "Process_String.loop", "jne Process_String.loop")
I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx"); I("58", "pop eax")
a.ret("ret")

# ---------------------------------------------------------------- Eval_Immediates
a.label("Eval_Immediates")
I("50", "push eax"); I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx")
I("89 C2", "mov edx, eax")
a.label("Eval_Immediates.loop")
I("8B 42 08", "mov eax, [edx+8]")
I("83 F8 01", "cmp eax, 1")
a.jcc("e", "Eval_Immediates.next", "je Eval_Immediates.next")
I("8B 42 18", "mov eax, [edx+24]")
I("85 C0", "test eax, eax")
a.jcc("ne", "Eval_Immediates.next", "jne Eval_Immediates.next  -- already has an expression")
I("8B 42 10", "mov eax, [edx+16]")
I("8A 18", "mov bl, [eax]"); I("0F B6 DB", "movzx ebx, bl", "TEXT[0], the width prefix")
I("83 C0 01", "add eax, 1")
I("8A 08", "mov cl, [eax]"); I("0F B6 C9", "movzx ecx, cl", "TEXT[1]")
a.call("numerate_string", "call numerate_string")
I("85 C0", "test eax, eax")
a.jcc("ne", "Eval_Immediates.value", "jne Eval_Immediates.value")
I("83 F9 30", "cmp ecx, '0'")
a.jcc("ne", "Eval_Immediates.next", "jne Eval_Immediates.next  -- zero only counts if written as one")
a.label("Eval_Immediates.value")
a.call("express_number", "call express_number")
I("89 42 18", "mov [edx+24], eax")
a.label("Eval_Immediates.next")
I("8B 12", "mov edx, [edx]")
I("85 D2", "test edx, edx")
a.jcc("ne", "Eval_Immediates.loop", "jne Eval_Immediates.loop")
I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx"); I("58", "pop eax")
a.ret("ret")

# ---------------------------------------------------------------- Preserve_Other
a.label("Preserve_Other")
I("50", "push eax"); I("53", "push ebx"); I("51", "push ecx"); I("52", "push edx")
I("89 C2", "mov edx, eax")
a.label("Preserve_Other.loop")
I("8B 42 08", "mov eax, [edx+8]")
I("83 F8 01", "cmp eax, 1")
a.jcc("e", "Preserve_Other.next", "je Preserve_Other.next")
I("8B 42 18", "mov eax, [edx+24]")
I("85 C0", "test eax, eax")
a.jcc("ne", "Preserve_Other.next", "jne Preserve_Other.next")
I("8B 42 10", "mov eax, [edx+16]")
I("89 42 18", "mov [edx+24], eax", "anything left over stands for itself")
a.label("Preserve_Other.next")
I("8B 12", "mov edx, [edx]")
I("85 D2", "test edx, edx")
a.jcc("ne", "Preserve_Other.loop", "jne Preserve_Other.loop")
I("5A", "pop edx"); I("59", "pop ecx"); I("5B", "pop ebx"); I("58", "pop eax")
a.ret("ret")

# ---------------------------------------------------------------- File_Print
a.label("File_Print")
I("53", "push ebx"); I("51", "push ecx")
I("89 C3", "mov ebx, eax")
I("85 C0", "test eax, eax")
a.jcc("e", "File_Print.done", "je File_Print.done  -- a NULL expression prints as nothing")
a.label("File_Print.loop")
I("8A 03", "mov al, [ebx]"); I("0F B6 C0", "movzx eax, al")
I("85 C0", "test eax, eax")
a.jcc("e", "File_Print.done", "je File_Print.done")
a.call("fputc", "call fputc")
I("83 C3 01", "add ebx, 1")
a.jmp("File_Print.loop", "jmp File_Print.loop")
a.label("File_Print.done")
I("59", "pop ecx"); I("5B", "pop ebx")
a.ret("ret")

# ---------------------------------------------------------------- Print_Hex
a.label("Print_Hex")
I("53", "push ebx"); I("51", "push ecx")
I("89 C3", "mov ebx, eax")
a.label("Print_Hex.loop")
I("8B 43 08", "mov eax, [ebx+8]")
I("83 F8 01", "cmp eax, 1")
a.jcc("e", "Print_Hex.next", "je Print_Hex.next  -- a macro defines, it does not emit")
I("8B 43 18", "mov eax, [ebx+24]")
a.call("File_Print", "call File_Print")
a.mov_r_imm("eax", 10, "mov eax, 10")
a.call("fputc", "call fputc")
a.label("Print_Hex.next")
I("8B 1B", "mov ebx, [ebx]")
I("85 DB", "test ebx, ebx")
a.jcc("ne", "Print_Hex.loop", "jne Print_Hex.loop")
I("59", "pop ecx"); I("5B", "pop ebx")
a.ret("ret")

# ---------------------------------------------------------------- _start
a.label("_start")
a.call("find_ntdll", "call find_ntdll")
I("89 C3", "mov ebx, eax", "ntdll base, held across every resolve_export call")
for slot, nm in [("fn_create","name_NtCreateFile"), ("fn_read","name_NtReadFile"),
                 ("fn_write","name_NtWriteFile"), ("fn_close","name_NtClose"),
                 ("fn_exit","name_NtTerminateProcess"), ("fn_rtlpath","name_RtlDosPath")]:
    a.push_lbl(nm)
    a.push_r("ebx", "module_base")
    a.call("resolve_export", "call resolve_export")
    a.mov_mem_r(slot, "eax")
a.mov_mem_lbl("malloc_ptr", "arena", "mov dword [malloc_ptr], arena  -- the loader zeroed it for us")
emit_cmdline(a)
a.mov_r_mem("eax", "arg_in", "mov eax, [arg_in]")
a.mov_r_imm("ecx", 0x80100000, "GENERIC_READ|SYNCHRONIZE")
a.mov_r_imm("edx", 1, "FILE_OPEN")
a.call("open_file", "call open_file")
a.mov_mem_r("in_handle", "eax", "mov [in_handle], eax")
a.mov_r_mem("eax", "arg_out", "mov eax, [arg_out]")
a.mov_r_imm("ecx", 0x40100000, "GENERIC_WRITE|SYNCHRONIZE")
a.mov_r_imm("edx", 5, "FILE_OVERWRITE_IF")
a.call("open_file", "call open_file")
a.mov_mem_r("out_handle", "eax", "mov [out_handle], eax")
a.label("_start.tokenize")
a.call("Tokenize_Line", "call Tokenize_Line")
a.mov_r_mem("eax", "eof_flag", "mov eax, [eof_flag]")
I("85 C0", "test eax, eax")
a.jcc("e", "_start.tokenize", "je _start.tokenize")
a.mov_r_mem("eax", "head", "mov eax, [head]")
I("85 C0", "test eax, eax")
a.jcc("e", "_start.done", "je _start.done  -- an empty input makes an empty output")
a.call("Reverse_List", "call Reverse_List")
a.mov_mem_r("head", "eax", "mov [head], eax")
for fn in ["Identify_Macros", "Line_Macro", "Process_String",
           "Eval_Immediates", "Preserve_Other", "Print_Hex"]:
    a.mov_r_mem("eax", "head", "mov eax, [head]")
    a.call(fn, "call %s" % fn)
a.label("_start.done")
a.push_mem("out_handle", "push out_handle")
a.call_mem("fn_close")
a.push_mem("in_handle", "push in_handle")
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
asciiz("DEFINE_str", "DEFINE")
a.label("terminators"); a.raw(b"\x0a\x0d\x09\x20\x00", 'terminators = "\\n\\r\\t "')
a.label("comments");    a.raw(b"\x3b\x23\x00", 'comments = ";#"')
a.label("string_char"); a.raw(b"\x22\x27\x00", 'string_char = "\\"\'"')
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
dd("iosb_info", 0, "iosb_info: IO_STATUS_BLOCK.Information")
dd("in_handle", 0, "in_handle: argv[1]")
dd("out_handle", 0, "out_handle: argv[2]")
dd("arg_in", 0, "arg_in: PWSTR argv[1]")
dd("arg_out", 0, "arg_out: PWSTR argv[2]")
dd("malloc_ptr", 0, "malloc_ptr: the bump allocator's cursor")
dd("head", 0, "head: the token list")
dd("eof_flag", 0, "eof_flag: set once the input is exhausted")
dd("tok_c", 0, "tok_c: the character Tokenize_Line is looking at")
dd("tok_p", 0, "tok_p: the token being filled in")
space("inbuf", 1, "inbuf: one-byte read buffer")
space("outbuf", 1, "outbuf: one-byte write buffer")

a.reserve("arena", 0, "everything malloc hands out, zero-filled by the loader")

DOC = {
"find_ntdll": """find_ntdll() -> ntdll base address.
TEB (fs:0x30) -> PEB -> Ldr -> InMemoryOrderModuleList.  The first entry in that
list is the main EXE and the second is ntdll.""",
"resolve_export": """resolve_export(module_base, name) -> address, or 0 if not found.
stdcall: arguments pushed right to left, callee cleans the stack.""",
"next_token": """next_token() -> eax = the next argument, or 0 when exhausted.
esi is the cursor into the command line.  Characters are UTF-16, so it advances
two bytes at a time.""",
"open_file": """open_file(eax = path, ecx = DesiredAccess, edx = CreateDisposition) -> handle.
RtlDosPathNameToNtPathName_U converts the DOS path into the NT path
NtCreateFile requires.""",
"fgetc": """fgetc() -> eax = the next input byte, or -4 at end of file.
-4 rather than -1 because that is the value upstream's fgetc returns, and
Store_Atom and Tokenize_Line compare against it.""",
"fputc": "fputc(al = byte).  One write per byte, as upstream does it.",
"malloc": """malloc(eax = size) -> eax = pointer.
A bump allocator over the memory past the end of the file.  The loader zeroed
it, so this is calloc as well, which is what every caller assumes.  Nothing is
ever freed; upstream calls brk twice for the same effect.""",
"In_Set": "In_Set(eax = char, ebx = set) -> 1 if the character is in the NUL-terminated set.",
"match": "match(eax, ebx) -> 0 if the two strings are equal, 1 if not.",
"string_length": "string_length(eax) -> the number of bytes before the NUL.",
"hex32l": """hex32l/hex16l/hex8(eax = value, ebx = destination): write the value as hex
digits and advance ebx past them.  Each falls into the next, and each half is
written low part first, so a 32-bit value comes out in little-endian byte
order: 0x00100000 becomes 00001000.""",
"numerate_string": """numerate_string(eax = string) -> its value.
"0x" selects hex and anything else is decimal, with a leading '-' to negate.
The 0x test comes first and looks at S[1], so a negative hex number is not a
thing: "-0x10" takes the decimal path and fails on the 'x'.  Hex digits are
upper case only, for the same reason -- 'a' lands past 15 and fails.  A string
that is not a number returns 0, which the caller tells from a real zero by
looking at the first digit.

Upstream leaves the negation flag in EDI uninitialised, and gets away with it
because EDI holds its malloc pointer and is never 1.  This zeroes it, which is
the same behaviour for every input and no behaviour for none.""",
"express_number": """express_number(eax = value, ebx = prefix) -> a fresh hex string.
The prefix chooses the width: '%' four bytes, '@' two, anything else one.  That
is how an M1 source says how wide an immediate should be.""",
"Store_Atom": """Store_Atom(ecx = first character) -> a fresh string.
Reads to the next space, tab or newline, consuming it.
The string's start is held in esi, not edx: every read goes through NtReadFile,
and the Windows calling convention leaves eax, ecx and edx to the callee.""",
"Store_String": """Store_String(ecx = quote) -> a fresh string.
Reads to the matching quote.  The opening quote is kept as the first character,
which is how Process_String later tells '...' from "..." ; the closing one is
dropped.""",
"Tokenize_Line": """Tokenize_Line(): read one token and put it on the front of the list.
'#' and ';' begin a comment that runs to end of line.  The list is built
backwards and reversed once the input is exhausted, which costs one pass and
saves walking to the end for every token.""",
"Reverse_List": "Reverse_List(eax = list) -> the same list, reversed.",
"Identify_Macros": """Identify_Macros(eax = list): find DEFINE.
A DEFINE token takes over the two tokens after it: it keeps the name as its
TEXT and the expansion as its EXPRESSION, and unlinks both.  It stays in the
list as a MACRO so Line_Macro can find it, and Print_Hex skips it.""",
"Set_Expression": """Set_Expression(eax = list, ebx = name, ecx = expansion):
give every later token with that name this expansion.  Macros are left alone,
so a definition cannot rewrite another definition's name.""",
"Line_Macro": "Line_Macro(eax = list): apply each macro to everything after it.",
"Process_String": """Process_String(eax = list): turn a quoted token into hex.
'...' is already hex and passes through as written.  "..." is text, and becomes
two hex digits per character plus a 00 terminator.""",
"Eval_Immediates": """Eval_Immediates(eax = list): turn a prefixed number into hex.
Only tokens that no macro claimed are considered.""",
"Preserve_Other": """Preserve_Other(eax = list): anything with no expression yet stands for
itself.  That is what carries hex2's labels and pointers through untouched.""",
"File_Print": "File_Print(eax = string): write it, if it is not NULL.",
"Print_Hex": "Print_Hex(eax = list): write each expression on its own line.",
"_start": """Resolve the six ntdll routines, open both files, read every token, then run the
passes in order: reverse, find macros, apply them, convert strings, convert
immediates, preserve the rest, print.""",
"name_NtCreateFile": "Export names, matched by resolve_export.",
"terminators": "The character sets the tokenizer splits on.",
"fn_create": "Resolved routine addresses.",
"g_access": "Arguments that must survive the RtlDosPathNameToNtPathName_U call.",
"oa": "OBJECT_ATTRIBUTES, one label per field so hex2 can address each of them.",
"iosb": "IO_STATUS_BLOCK.",
"in_handle": "The two open files and the argv pointers they came from.",
"malloc_ptr": "Allocator and tokenizer state.",
"inbuf": "One-byte read and write buffers.",
}

BANNER = "\n".join(spdx([UPSTREAM, PORT])) + """M0-pe32: the Windows (PE32/i386) port of stage0's M0 macro assembler.

M0 reads an M1 source file and writes hex2.  It is the first link that reads a
language rather than an encoding: a name can stand for a sequence of bytes.

  M0 INPUT OUTPUT
    argv[1]        an M1 source file
    argv[2]        a path, created or truncated for writing

  DEFINE name body   name means body from here on
  'ABCD'             hex, passed through as written
  "text"             text, emitted as two hex digits a character and a 00
  !5 @577 %0x100000  an immediate, one/two/four bytes, little-endian
  # or ;             a comment, to end of line
  anything else      passed through, which is what carries hex2's own syntax

A carriage return separates tokens here as well as a newline, which upstream
does not do: an M1 file written on Windows would otherwise carry a stray \r
into every token at the end of a line.

Tokens become a linked list, and the work is a sequence of passes over it.
Nothing is ever freed: malloc hands out the zero-filled memory past the end of
the file, so the passes can be as careless with it as upstream's are.

This file carries no PE header.  catm puts PE32-i386.hex2 in front of it, the
same way upstream catms ELF-i386.hex2 in front of M0_x86.hex2."""

sys.exit(0 if emit_pe_hex2(a, BANNER, DOC, "name_NtCreateFile",
                           sys.argv[1], sys.argv[2], "M0", inline_header=False) else 1)
