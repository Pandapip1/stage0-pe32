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
 * Everything M2libc/x86/linux/unistd.c declares is here.  Where Windows has an
 * answer, it is given; where it has none -- chroot, mount, unshare, symlink --
 * the call fails and says why in a comment above it, rather than returning
 * success and leaving the caller to find out later.  fork, execve and waitpid
 * are the exception and live in process.c, because between them they are more
 * code than the rest of this file.
 *
 * The calls into ntdll all go through M2libc-windows/ntdll.c, which is where
 * the two things worth knowing about them are written down: the arguments go
 * in backwards, and the filename has to be turned into an OBJECT_ATTRIBUTES
 * around an NT path first.
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

#define F_OK 0
#define X_OK 1
#define W_OK 2
#define R_OK 4

#define __PATH_MAX 4096

/* Defined further along the file list than this, and used here. */
void* calloc(int count, int size);
void* malloc(unsigned size);
char* int2str(int x, int base, int signed_p);

/* Fill in one field of a struct whose fields are fixed size character arrays,
 * starting at `at`, and say where the next piece would go.  M2libc's string.c
 * is not part of the build this file belongs to, and this is the only place
 * anything here copies a string. */
int __strput(char* dst, int at, char* src)
{
	int i;

	i = 0;
	while(0 != src[i])
	{
		dst[at + i] = src[i];
		i = i + 1;
	}
	dst[at + i] = 0;
	return at + i;
}

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
 * which aliases them onto the same syscall.
 *
 * They are not aliases here, because M2libc's stdout is buffered 512 bytes at
 * a time and exiting without flushing it throws away whatever has not reached
 * the handle yet.  __kill_io is stdio.c's own flush-everything, the same one
 * upstream's libc-full.M1 calls on the way out; it is declared here because
 * this file is compiled before the stdio.c that defines it. */
void __kill_io();

void exit(int value)
{
	__kill_io();
	_exit(value);
}

/* Backs remove(), and rmdir would be the same call.  NtDeleteFile opens the
 * file for delete and marks it gone in one step, so unlike the POSIX one this
 * fails on a file something else still has open: Windows will not unlink an
 * open file out from under its readers the way Unix will. */
int unlink(char* filename)
{
	int (*NtDeleteFile)(int);
	int* oa;

	oa = __ntobject(filename);
	if(NULL == oa) return -1;

	NtDeleteFile = __ntdll(NT_DELETE);
	if(0 != NtDeleteFile(oa)) return -1;
	return 0;
}

/* Windows has symbolic links, and refuses to make one without
 * SeCreateSymbolicLinkPrivilege, which an ordinary account does not hold
 * unless the machine is in developer mode.  A call that usually fails is not
 * worth the code to sometimes succeed, so this always fails. */
int symlink(char* path1, char* path2)
{
	return -1;
}

/* F_OK is answered by whether the file is there at all, and W_OK by the read
 * only attribute.  R_OK and X_OK have no Windows counterpart worth consulting:
 * a file that exists can be read, and one runs because of what is inside it
 * rather than because of a bit beside it. */
int access(char* pathname, int mode)
{
	int (*NtQueryAttributesFile)(int, int);
	int* oa;
	int* basic;

	oa = __ntobject(pathname);
	if(NULL == oa) return -1;

	/* FILE_BASIC_INFORMATION: four timestamps and then FileAttributes */
	basic = calloc(10, 4);
	NtQueryAttributesFile = __ntdll(NT_QUERYATTR);
	/* forwards: NtQueryAttributesFile(oa, basic) */
	if(0 != NtQueryAttributesFile(basic, oa)) return -1;

	/* FILE_ATTRIBUTE_READONLY */
	if((0 != (mode & W_OK)) && (0 != (basic[8] & 1))) return -1;
	return 0;
}

int chdir(char* path)
{
	int (*RtlSetCurrentDirectory_U)(int);
	int* dos;

	RtlSetCurrentDirectory_U = __ntdll(NT_SETCWD);
	/* The one ntdll call here that wants a DOS path rather than an NT one:
	 * it does the conversion itself, and keeps the DOS path for getcwd. */
	dos = __dosustring(path);      /* not in the argument list: see ntdll.c */
	if(0 != RtlSetCurrentDirectory_U(dos)) return -1;
	return 0;
}

/* A file descriptor here is a handle, and a handle does not know the path it
 * was opened by -- FileNameInformation gives the name within the device, with
 * no drive letter to put in front of it.  Reconstructing one is more work than
 * a call with no caller deserves, so this fails rather than guessing. */
int fchdir(int fd)
{
	return -1;
}

/* Returns the length including the terminator, as the Linux syscall does, or
 * -1.  RtlGetCurrentDirectory_U counts in bytes both ways, and when the buffer
 * is too small it returns the size it wanted rather than filling it. */
int _getcwd(char* buf, int size)
{
	int (*RtlGetCurrentDirectory_U)(int, int);
	char* w;
	int room;
	int bytes;
	int n;
	int i;

	w = calloc(size + 1, 2);
	room = 2 * size;               /* not in the argument list: see ntdll.c */
	RtlGetCurrentDirectory_U = __ntdll(NT_GETCWD);
	/* forwards: RtlGetCurrentDirectory_U(room, w) */
	bytes = RtlGetCurrentDirectory_U(w, room);
	if(0 == bytes) return -1;

	n = bytes / 2;
	if(n >= size) return -1;

	i = 0;
	while(i < n)
	{
		buf[i] = w[2 * i];
		i = i + 1;
	}
	buf[n] = 0;
	return n + 1;
}

char* getcwd(char* buf, unsigned size)
{
	int c = _getcwd(buf, size);
	if(0 >= c) return NULL;
	return buf;
}

char* getwd(char* buf)
{
	return getcwd(buf, __PATH_MAX);
}

char* get_current_dir_name()
{
	return getcwd(malloc(__PATH_MAX), __PATH_MAX);
}

/* sysname, release, version and machine are answerable; nodename is not.
 * Windows keeps the computer name in the registry, under
 * \Registry\Machine\System\CurrentControlSet\Control\ComputerName, which
 * is two more ntdll routines and a key walk for a field nothing here reads --
 * so it is left empty, which calloc already made it.
 *
 * RtlGetVersion is used rather than the documented GetVersionEx because it is
 * the one that does not lie: since Windows 8.1 the Win32 call reports what the
 * process manifest asks for, and tells an unmanifested program it is running
 * on 6.2, while this one reports what is actually there.  Checked on Windows
 * 11, where it gives 10.0 build 22621 to a program with no manifest at all. */
int uname(struct utsname* unameData)
{
	int (*RtlGetVersion)(int);
	int* info;
	int at;

	RtlGetVersion = __ntdll(NT_VERSION);
	/* RTL_OSVERSIONINFOW: five words and then 128 UTF-16 characters */
	info = calloc(69, 4);
	info[0] = 276;
	if(0 != RtlGetVersion(info)) return -1;

	__strput(unameData->sysname, 0, "Windows_NT");
	__strput(unameData->machine, 0, "i686");

	at = __strput(unameData->release, 0, int2str(info[1], 10, 0));
	at = __strput(unameData->release, at, ".");
	__strput(unameData->release, at, int2str(info[2], 10, 0));

	__strput(unameData->version, 0, int2str(info[3], 10, 0));
	return 0;
}

/* Windows identifies who you are by a SID rather than by a number, and has
 * nothing to return here that a caller comparing against 0 would read
 * correctly.  0 is what these report, which says "the only user there is" --
 * true of the single-user picture the rest of this presents, and not a claim
 * about privilege. */
int geteuid()
{
	return 0;
}

int getegid()
{
	return 0;
}

/* Three Linux ideas with no Windows counterpart at all.  Windows has no mount
 * syscall of this shape, no chroot, and namespaces are not a thing a process
 * asks for by flag.  Nothing in this bootstrap calls them; they are here
 * because M2libc's unistd.h declares them. */
int unshare(int flags)
{
	return -1;
}

int chroot(char* path)
{
	return -1;
}

int mount(char* source, char* target, char* filesystemtype, SCM mountflags, void* data)
{
	return -1;
}

/* The image carries its own writable memory with it -- everything past the
 * end of the file to the top of a 128MB image is mapped and already zero --
 * so brk(addr) is free, a number to keep rather than a call to make, for as
 * long as addr stays inside it: there is nothing to allocate, so the only
 * way to fail is to run off the top of the image, which faults rather than
 * returning -1.
 *
 * That ceiling used to be the whole allocator's ceiling too, because
 * M2libc/stdlib.c's own _malloc_brk called this function and trusted its
 * return value directly. It no longer does: M2libc's own stdlib.c (a fork,
 * https://github.com/Pandapip1/M2libc, branch windows-malloc-brk -- see
 * .gitmodules) gives _malloc_brk a #ifdef __windows__ path that tracks
 * several regions rather than one linear range, growing past this image
 * into further, separately-reserved ones as needed, without ever asking
 * this brk() to pretend the image itself is bigger than it is. See that
 * comment for why -- a design that instead tried to make brk() grow, or one
 * that tried to make the image bigger, were both tried first and are
 * written up there, with what was actually wrong with each. This function's
 * own job stays exactly what it always was. */
long _the_brk;

int brk(void* addr)
{
	if(NULL == _the_brk) _the_brk = __heap_start();
	if(NULL == addr) return _the_brk;
	_the_brk = addr;
	return _the_brk;
}
#endif
