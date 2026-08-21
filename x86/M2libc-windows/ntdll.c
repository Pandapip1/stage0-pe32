/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * The pieces every ntdll call from C needs: how to reach a routine, and how to
 * hand it a filename.
 *
 * Calling ntdll from C
 * --------------------
 * x86/ntdll-i386.hex2 resolves each routine out of ntdll's export table into a
 * numbered slot -- ntdll-slots.h says which -- and __ntdll returns the address
 * in one.  What comes back is called through a function pointer, and there are
 * two things about that which are not obvious and are not optional:
 *
 *   The arguments go in backwards.  M2-Planet pushes the first argument
 *   first, so it ends up furthest from the stack pointer, and a stdcall callee
 *   wants the first argument nearest.  Every call below is therefore written
 *   in reverse and carries a comment saying what it reads as forwards.
 *
 *   Nothing else has to be done about stdcall.  ntdll pops its own arguments,
 *   which would strand a caller that popped them again -- but M2-Planet saves
 *   the stack pointer in EBP before pushing and restores it from there
 *   afterwards, so it never adds back what it pushed.  See x86/libc-core.M1.
 *
 *   No argument may touch EDX.  M2-Planet keeps the pointer it is about to
 *   call in EDX while it evaluates the arguments and never puts it back, so
 *   anything in the argument list that writes EDX sends the outer call to
 *   whatever is left there -- in practice zero, and a jump to address zero.
 *   Three things write it: a function call; `*`, `/` or `%`, which compile to
 *   imul and idiv; and subscripting an array, because that is a multiply by
 *   the element size whether or not the index is a constant.  So every argument to a call through a pointer
 *   here is a local or a constant, and anything computed -- including
 *   doubling a length for UTF-16 -- is worked out into a local on the line
 *   before.  That is a property of M2-Planet's code generator rather than of
 *   these routines, and holds for every function pointer call in this port.
 *
 * Filenames
 * ---------
 * ntdll takes UTF-16, and takes it inside an OBJECT_ATTRIBUTES around a
 * UNICODE_STRING, and for anything that names a file on disk it wants an NT
 * path (\??\C:\...) rather than the DOS path a program was given.
 * RtlDosPathNameToNtPathName_U does that last conversion; __ntobject does the
 * rest, and is what the routines below hand a filename to ntdll with.
 *
 * Widening is done by putting a zero byte after each byte, which is right for
 * ASCII and wrong for everything else.  A path with a character above 127 in
 * it will not survive this, and this is not the layer that could say so.
 *
 * Nothing here frees anything.  The buffer RtlDosPathNameToNtPathName_U
 * allocates comes from ntdll's own heap and is leaked, as it already was in
 * the assembly this replaces; the rest comes from a malloc that never returns
 * memory anyway.  These are programs that run once over one input and exit.
 */

#ifndef __NTDLL_C
#define __NTDLL_C

#define NULL 0

void* calloc(int count, int size);

/* An ntdll routine, by the slot resolve_all put it in. */
void* __ntdll(int slot)
{
	asm("lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__ntdll");
}

/* This thread's TEB, which is the only way to reach StackBase and StackLimit
 * -- the committed stack fork has to copy into a child. */
int* __teb()
{
	asm("call %__teb");
}

/* This process's own PEB, the root of __ntdll_resolve's module walk below. */
int __peb()
{
	asm("call %__peb");
}

/* __ntdll_rd/__ntdll_rw/__ntdll_rb: read a dword/word/byte at an address held
 * as a plain int rather than a typed pointer, matching how every address in
 * process.c's WOW64 walk (__wow64_rd64_dword and friends) is carried too --
 * these differ only in reading this process's own memory directly, with no
 * NtWow64ReadVirtualMemory64 call, since resolving a native 32-bit ntdll
 * export needs no cross-bitness read at all. */
int __ntdll_rd(int addr)
{
	int* p;
	p = addr;
	return p[0];
}

int __ntdll_rw(int addr)
{
	char* p;
	p = addr;
	return (255 & p[0]) + (256 * (255 & p[1]));
}

int __ntdll_rb(int addr)
{
	char* p;
	p = addr;
	return 255 & p[0];
}

/* Walk this process's own PEB -> Ldr -> InMemoryOrderModuleList for a module
 * named (ASCII) `want`, matched against its UTF-16 BaseDllName one code unit
 * at a time -- the in-process, native-bitness counterpart of process.c's
 * __wow64_find_module, needing no cross-bitness read since this is the same
 * process's own memory. PEB->Ldr is at +0x0C and Ldr->InMemoryOrderModuleList's
 * head is at +0x14, the same two fields libc-core.M1's hand-written
 * find_ntdll and x86/Development/stage0asm.py's FIND_NTDLL already rely on.
 * Walking the list keeps a pointer to each entry's InMemoryOrderLinks field
 * (LDR_DATA_TABLE_ENTRY +0x08) rather than the entry's own base, which is why
 * DllBase (real offset +0x18) reads back at cur+0x10 and BaseDllName.Length/
 * Buffer (real offsets +0x2C/+0x30) at cur+0x24/+0x28 below -- the same
 * offset-from-the-list-link trick find_ntdll's own "mov eax,[eax+0x10]" uses.
 * Returns the module base, or 0 if the (circular) list runs out first. */
int __ntdll_find_module(char* want)
{
	int peb;
	int ldr;
	int head;
	int cur;
	int base;
	int name_len;
	int name;
	int i;
	int match;
	int guard;

	peb = __peb();
	ldr = __ntdll_rd(peb + 0x0C);
	head = ldr + 0x14;
	cur = __ntdll_rd(head);

	guard = 0;
	while(guard < 512)
	{
		if(cur == head) break;
		if(0 == cur) break;

		base = __ntdll_rd(cur + 0x10);
		name_len = __ntdll_rw(cur + 0x24);
		name = __ntdll_rd(cur + 0x28);

		match = 1;
		i = 0;
		while(0 != want[i])
		{
			if((2 * i) >= name_len) { match = 0; break; }
			if(__ntdll_rb(name + (2 * i)) != want[i]) { match = 0; break; }
			i = i + 1;
		}
		if(match)
		{
			if(name_len == (2 * i)) return base;
		}

		cur = __ntdll_rd(cur);
		guard = guard + 1;
	}
	return 0;
}

/* Resolve one export by name out of a PE32 image already mapped at `base` in
 * this process -- the native-bitness counterpart of process.c's
 * __wow64_resolve_export. IMAGE_NT_HEADERS32's export data directory is at
 * +0x78 (0x18 for the Signature+FileHeader plus 0x60 for the sixteen-entry
 * DataDirectory's own offset within IMAGE_OPTIONAL_HEADER32 -- +0x88 in the
 * PE32+ header process.c's own export walk uses, matching the width
 * difference between the two headers' pointer-sized fields); the export
 * directory's four arrays (NumberOfNames +24, AddressOfFunctions +28,
 * AddressOfNames +32, AddressOfNameOrdinals +36) are the same ordinary
 * 32-bit-RVA fields regardless of image bitness. Returns 0 if `name` is not
 * among the exports. */
int __ntdll_resolve_export(int base, char* name)
{
	int e_lfanew;
	int nt;
	int export_rva;
	int export_dir;
	int num_names;
	int addr_funcs; int addr_names; int addr_ords;
	int i;
	int name_rva;
	int match;
	int j;
	int ord;
	int func_rva;

	e_lfanew = __ntdll_rd(base + 0x3C);
	nt = base + e_lfanew;
	export_rva = __ntdll_rd(nt + 0x78);
	export_dir = base + export_rva;

	num_names  = __ntdll_rd(export_dir + 24);
	addr_funcs = __ntdll_rd(export_dir + 28);
	addr_names = __ntdll_rd(export_dir + 32);
	addr_ords  = __ntdll_rd(export_dir + 36);

	i = 0;
	while(i < num_names)
	{
		name_rva = __ntdll_rd(base + addr_names + (4 * i));
		match = 1;
		j = 0;
		while(0 != name[j])
		{
			if(__ntdll_rb(base + name_rva + j) != name[j]) { match = 0; break; }
			j = j + 1;
		}
		if(match)
		{
			if(0 == __ntdll_rb(base + name_rva + j))
			{
				ord = __ntdll_rw(base + addr_ords + (2 * i));
				func_rva = __ntdll_rd(base + addr_funcs + (4 * ord));
				return base + func_rva;
			}
		}
		i = i + 1;
	}
	return 0;
}

/* One ntdll routine, resolved by name rather than by resolve_all's fixed
 * slot table -- the portable replacement ntdll-slots.h's NT_* constants are
 * meant to give way to, once a program is built with a C compiler at all
 * (hex0 through M0 have none yet and must go on using resolve_all; see
 * x86/Development/gen_ntdll.py's own comment on that). ntdll.dll's base is
 * cached, since every caller wants a different export out of the same
 * module. Returns 0 if ntdll.dll's export table has no such name -- ntdll
 * always resolves, so a 0 here rather than at __ntdll_find_module's return
 * means the name itself was wrong, same as resolve_all leaving an unknown
 * export's slot at 0 does today. */
int __ntdll_base_cache;
int __ntdll_base_have;
void* __ntdll_resolve(char* name)
{
	if(0 == __ntdll_base_have)
	{
		__ntdll_base_cache = __ntdll_find_module("ntdll.dll");
		__ntdll_base_have = 1;
	}
	if(0 == __ntdll_base_cache) return NULL;
	return __ntdll_resolve_export(__ntdll_base_cache, name);
}

/* setjmp, in the one shape fork needs: it writes down where its caller would
 * have carried on and returns 0, and a thread pointed back at that spot with
 * EAX set to 1 comes up believing it returned 1.  See fork in process.c and
 * :__fork_setjmp in x86/libc-core.M1. */
int __fork_setjmp()
{
	asm("call %__fork_setjmp");
}

int __fork_exitaddr()
{
	asm("call %__fork_exitaddr");
}

int __fork_flagaddr()
{
	asm("call %__fork_flagaddr");
}

int __fork_parkedaddr()
{
	asm("call %__fork_parkedaddr");
}

int __fork_geteip()
{
	asm("call %__fork_geteip");
}

int __fork_getesp()
{
	asm("call %__fork_getesp");
}

/* Where one of the three standard handles lives in the process parameters, so
 * that dup2 can replace it and not merely read it. */
int* __stdslot(int n)
{
	asm("lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__stdslot");
}

/* An ASCII string as the UTF-16 ntdll insists on. */
char* __widen(char* s)
{
	int n;
	int i;
	char* w;

	n = 0;
	while(0 != s[n]) n = n + 1;

	w = calloc(n + 2, 2);
	i = 0;
	while(i < n)
	{
		w[2 * i] = s[i];
		i = i + 1;
	}
	return w;
}

/* A UNICODE_STRING over a DOS path: two words, the first holding Length and
 * MaximumLength as two 16-bit halves, the second the widened text.  Both
 * lengths are in bytes, and MaximumLength counts the terminator that Length
 * does not.  RtlSetCurrentDirectory_U is the one caller that wants a DOS path
 * in this shape rather than the NT path __ntobject produces. */
int* __dosustring(char* path)
{
	int n;
	int* u;

	n = 0;
	while(0 != path[n]) n = n + 1;

	u = calloc(2, 4);
	u[0] = (2 * n) + (65536 * ((2 * n) + 2));
	u[1] = __widen(path);
	return u;
}

/* An OBJECT_ATTRIBUTES naming a file: six words, of which only the length, the
 * name and the attributes are ever anything but zero.  NULL if the path could
 * not be turned into an NT path at all. */
int* __ntobject(char* path)
{
	int (*RtlDosPathNameToNtPathName_U)(int, int, int, int);
	char* wide;
	int* name;
	int* oa;

	RtlDosPathNameToNtPathName_U = __ntdll(NT_RTLPATH);
	name = calloc(2, 4);
	wide = __widen(path);          /* not in the argument list: see above */

	/* forwards: RtlDosPathNameToNtPathName_U(wide, name, NULL, NULL) */
	if(0 == RtlDosPathNameToNtPathName_U(0, 0, name, wide)) return NULL;

	oa = calloc(6, 4);
	oa[0] = 24;                          /* Length: the size of this struct */
	oa[2] = name;                        /* ObjectName */
	oa[3] = 0x40;                        /* Attributes = OBJ_CASE_INSENSITIVE */
	return oa;
}
#endif
