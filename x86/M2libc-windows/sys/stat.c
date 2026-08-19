/* SPDX-FileCopyrightText: (C) 2016-2021 Jeremiah Orians
 * SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * Stands in for M2libc/x86/linux/sys/stat.c.
 *
 * Only chmod is here, and on Windows it does nothing and says so by returning
 * 0.  hex2 calls chmod(output, 0750) to make what it just linked executable;
 * on Linux that bit is what lets the file run at all, and on Windows nothing
 * consults it -- an image runs because its PE header says it is an executable,
 * which x86/PE32-i386.hex2 has already arranged by the time this is reached.
 * Returning success is therefore the honest answer to "is the output now
 * executable", not a stub papering over a missing feature.
 *
 * fchmod is chmod by another name and does nothing for the same reason.
 * mkdir is a real call.  mknod has no Windows counterpart -- there are no
 * device nodes in the filesystem to make -- and umask has nothing to keep,
 * since none of the bits it would mask reach anything here.
 */

#ifndef __SYS_STAT_C
#define __SYS_STAT_C

#define S_IRWXU 00700
#define S_IXUSR 00100
#define S_IWUSR 00200
#define S_IRUSR 00400

int chmod(char* pathname, int mode)
{
	return 0;
}

/* The same answer, for the same reason, about a file already open. */
int fchmod(int a, mode_t b)
{
	return 0;
}

/* NtCreateFile makes a directory as readily as a file, given
 * FILE_DIRECTORY_FILE and FILE_CREATE, and the handle it hands back is closed
 * straight away because the directory is what was wanted, not a way in to it.
 * mode goes the way it does in chmod: accepted and ignored. */
int mkdir(char* a, mode_t b)
{
	int (*NtCreateFile)(int, int, int, int, int, int, int, int, int, int, int);
	int (*NtClose)(int);
	int* oa;
	int* iosb;
	int* handle;
	int h;

	oa = __ntobject(a);
	if(NULL == oa) return -1;

	iosb = calloc(2, 4);
	handle = calloc(1, 4);
	NtCreateFile = __ntdll(NT_CREATE);

	/* forwards: NtCreateFile(handle, FILE_LIST_DIRECTORY|SYNCHRONIZE, oa,
	 *                        iosb, NULL, FILE_ATTRIBUTE_NORMAL,
	 *                        FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_CREATE,
	 *                        FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT,
	 *                        NULL, 0) */
	if(0 != NtCreateFile(0, 0, 0x21, 2, 3, 0x80, 0, iosb, oa, 0x00100001, handle)) return -1;

	NtClose = __ntdll(NT_CLOSE);
	h = handle[0];                 /* not in the argument list: see ntdll.c */
	NtClose(h);
	return 0;
}

/* A device is not a file on Windows and there is nothing in a directory to
 * make one out of.  Nothing here calls this; M2libc's sys/stat.h declares it. */
int mknod(char* a, mode_t b, dev_t c)
{
	return -1;
}

/* There is nothing to mask.  chmod does nothing here, so the bits this would
 * take away from it were never going to reach anything; what it keeps is the
 * number, so that a caller which sets a mask and puts the old one back sees
 * what it expects. */
mode_t _the_umask;

mode_t umask(mode_t m)
{
	mode_t was;

	was = _the_umask;
	_the_umask = m;
	return was;
}
#endif
