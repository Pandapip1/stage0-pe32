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
 * The rest of the file's surface -- fchmod, mkdir, mknod, umask, stat, fstat --
 * has no caller anywhere in this bootstrap, so it is not written.  Windows has
 * an answer for each of them; none is worth guessing at without a caller to
 * check it against.
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
#endif
