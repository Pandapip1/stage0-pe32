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
