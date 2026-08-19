/* SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
 * SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * The Windows half of M2libc's POSIX layer: what M2libc/stdio.c and
 * M2libc/stdlib.c call when they want the operating system.  It stands in for
 * M2libc/x86/linux/unistd.c and keeps the same signatures, so the generic C
 * above it -- all of stdio.c, stdlib.c, ctype.c -- compiles unchanged.
 *
 * Linux puts a syscall in each of these.  Each of these is a call into
 * x86/libc-core.M1 instead, which is where the argument pushing and the ntdll
 * entry points live.
 *
 * A file descriptor here is a Windows HANDLE, not a small integer, with 0, 1
 * and 2 reserved to mean stdin, stdout and stderr as C expects; __stdhandle
 * translates those three out of the PEB when they are used.  No real handle is
 * that small, so the two never collide, and nothing above this file can tell
 * the difference.
 *
 * What is NOT here: fork, execve, waitpid, chdir, access, uname and the rest
 * of the process and filesystem surface M2libc/x86/linux/unistd.c also
 * provides.  Nothing this bootstrap builds calls them -- kaem, the one program
 * that would, is not built here, because Windows already has cmd.exe -- and
 * writing them without a caller to check them against would be writing
 * untested code.  Add them when something needs them.
 */

#ifndef __UNISTD_C
#define __UNISTD_C

#define NULL 0
#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

int read(int fd, char* buf, unsigned count)
{
	asm("lea_eax,[esp+DWORD] %12"
	    "mov_eax,[eax]"
	    "lea_ebx,[esp+DWORD] %8"
	    "mov_ebx,[ebx]"
	    "lea_ecx,[esp+DWORD] %4"
	    "mov_ecx,[ecx]"
	    "call %__read_block");
}

int write(int fd, char* buf, unsigned count)
{
	asm("lea_eax,[esp+DWORD] %12"
	    "mov_eax,[eax]"
	    "lea_ebx,[esp+DWORD] %8"
	    "mov_ebx,[ebx]"
	    "lea_ecx,[esp+DWORD] %4"
	    "mov_ecx,[ecx]"
	    "call %__write_block");
}

int lseek(int fd, int offset, int whence)
{
	asm("lea_eax,[esp+DWORD] %12"
	    "mov_eax,[eax]"
	    "lea_ebx,[esp+DWORD] %8"
	    "mov_ebx,[ebx]"
	    "lea_ecx,[esp+DWORD] %4"
	    "mov_ecx,[ecx]"
	    "call %__lseek");
}

int close(int fd)
{
	asm("lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__close");
}

void _exit(int value)
{
	asm("lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__exit");
}

void* __heap_start()
{
	asm("call %__heap_start");
}

/* exit is what C calls; _exit is what the layer below calls.  M2libc declares
 * both and defines neither -- on Linux they come from libc-full.M1's _start,
 * which aliases them onto the same syscall.  Here they are the same call into
 * libc-core.M1, and neither returns. */
void exit(int value)
{
	asm("lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__exit");
}

/* Backs remove().  Nothing this bootstrap builds deletes a file -- hex2 only
 * ever creates its output -- but stdio.c references it, so it has to link.
 * Rather than guess at NtDeleteFile's shape with no caller to check it
 * against, this reports the failure it would be if it were ever reached. */
int unlink(char* filename)
{
	return -1;
}

/* The image carries its writable memory with it -- everything past the end of
 * the file to the top of a 128MB image is mapped and already zero -- so there
 * is no break to ask the kernel to move, only a number to keep.  brk(0)
 * reports where it is, as M2libc's malloc expects, and brk(addr) accepts any
 * address at or above the start: there is nothing to allocate, so the only way
 * to fail is to run off the top of the image, which faults rather than
 * returning -1. */
long _the_brk;

int brk(void* addr)
{
	if(NULL == _the_brk) _the_brk = __heap_start();
	if(NULL == addr) return _the_brk;
	_the_brk = addr;
	return _the_brk;
}
#endif
