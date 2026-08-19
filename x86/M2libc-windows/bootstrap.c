/* SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
 * SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * The Windows backend of M2libc's bootstrap C library: what a program compiled
 * by cc_x86 gets before anything of M2libc proper exists.  It stands in for
 * M2libc/x86/linux/bootstrap.c and has the same functions, with the same
 * signatures, so a source that includes one can include the other instead.
 *
 * Linux puts a syscall in each of these.  Windows has none a user program may
 * make, so each is a call into x86/libc-core.M1, which is where the argument
 * pushing and the PEB reading live.  The two files are meant to be read
 * together; between them they are the whole of the operating system as far as
 * anything compiled here is concerned.
 *
 * A FILE* is a Windows HANDLE, except for 0, 1 and 2, which mean stdin, stdout
 * and stderr and are looked up in the PEB when used.  No real handle is that
 * small, so the two never collide.
 */

enum
{
	stdin = 0,
	stdout = 1,
	stderr = 2,
};

enum
{
	EOF = 0xFFFFFFFF,
	NULL = 0,
};

enum
{
	EXIT_FAILURE = 1,
	EXIT_SUCCESS = 0,
};

enum
{
	TRUE = 1,
	FALSE = 0,
};


int fgetc(FILE* f)
{
	asm("lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__read_byte");
}

unsigned fread(char* buffer, unsigned size, unsigned count, FILE* f) {
	count = size * count;

	unsigned i = 0;
	for(; i < count; i = i + 1) {
		buffer[i] = fgetc(f);
	}

	return i;
}

void fputc(char s, FILE* f)
{
	asm("lea_ebx,[esp+DWORD] %8"
	    "mov_ebx,[ebx]"
	    "lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__write_byte");
}

void fputs(char* s, FILE* f)
{
	while(0 != s[0])
	{
		fputc(s[0], f);
		s = s + 1;
	}
}

unsigned fwrite(char* buffer, unsigned size, unsigned count, FILE* f) {
	count = size * count;

	unsigned i = 0;
	for(; i < count; i = i + 1) {
		fputc(buffer[i], f);
	}

	return i;
}

/* flag is nonzero to write and zero to read; mode has no meaning on Windows
 * and is here only so that this takes the same arguments as the Linux one */
FILE* open(char* name, int flag, int mode)
{
	asm("lea_eax,[esp+DWORD] %12"
	    "mov_eax,[eax]"
	    "lea_ebx,[esp+DWORD] %8"
	    "mov_ebx,[ebx]"
	    "call %__open");
}

FILE* fopen(char* filename, char* mode)
{
	FILE* f;
	if('w' == mode[0])
	{ /* Made if it is not there, emptied if it is */
		f = open(filename, 1, 0);
	}
	else
	{ /* Everything else is a read */
		f = open(filename, 0, 0);
	}

	/* __open gives back 0 for a file it could not open */
	if(0 == f)
	{
		return 0;
	}
	return f;
}

int close(int fd)
{
	asm("lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__close");
}

int fclose(FILE* stream)
{
	int error = close(stream);
	return error;
}

void* __heap_start()
{
	asm("call %__heap_start");
}

long _malloc_ptr;

/* The image runs to 16MB and everything past the end of the file is mapped,
 * writable and already zero, so there is no break to move and no way for this
 * to fail.  Nothing is ever freed; the heap only ever grows.  Running off the
 * end of the image would fault, and there is no layer here that could say so
 * more clearly than that. */
void* malloc(int size)
{
	if(NULL == _malloc_ptr)
	{
		_malloc_ptr = __heap_start();
	}

	long old_malloc = _malloc_ptr;
	_malloc_ptr = _malloc_ptr + size;
	return old_malloc;
}

int strlen(char* str )
{
	int i = 0;
	while(0 != str[i]) i = i + 1;
	return i;
}

void* memset(void* ptr, int value, int num)
{
	char* s;
	for(s = ptr; 0 < num; num = num - 1)
	{
		s[0] = value;
		s = s + 1;
	}
}

/* malloc only ever hands out memory the loader already zeroed, so the memset
 * is not needed.  It is here anyway: it is what makes this calloc rather than
 * something that happens to behave like it. */
void* calloc(int count, int size)
{
	void* ret = malloc(count * size);
	if(NULL == ret) return NULL;
	memset(ret, 0, (count * size));
	return ret;
}

void free(void* l)
{
	return;
}

void exit(int value)
{
	asm("lea_eax,[esp+DWORD] %4"
	    "mov_eax,[eax]"
	    "call %__exit");
}
