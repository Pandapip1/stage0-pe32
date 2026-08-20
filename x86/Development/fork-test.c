/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * fork, exercised.  Build it the way Phase 7 builds hex2 -- the same -f list,
 * with this file last -- and run it with no arguments.
 *
 * What this shows: that fork returns twice, once in each process; that the
 * child gets the parent's memory, both a local on the stack and something
 * malloc handed out before the fork; that the child's standard handles are
 * the parent's, so its output lands in the same place; and that waitpid
 * brings back what the child exited with.
 *
 * Given arguments -- a program and its own arguments -- it also does the one
 * thing fork is really for: forks, execs that program in the child, and waits
 * for it in the parent.
 *
 *   fork-test x86\artifact\hex0.exe x86\hex0_x86.hex0 out.exe
 *
 * See fork in x86/M2libc-windows/process.c for how it is done and what it
 * rests on.
 */

int main(int argc, char** argv)
{
	int pid;
	int* status;
	int local;
	char* heaped;
	char** a;
	int i;

	local = 12345;
	heaped = calloc(32, 1);
	heaped[0] = 'h';
	heaped[1] = 'e';
	heaped[2] = 'a';
	heaped[3] = 'p';
	heaped[4] = 0;

	fputs("before fork: local = ", stdout);
	fputs(int2str(local, 10, TRUE), stdout);
	fputs(", heap = <", stdout);
	fputs(heaped, stdout);
	fputs(">\n", stdout);
	fflush(stdout);

	pid = fork();

	if(0 > pid)
	{
		fputs("fork failed\n", stdout);
		fflush(stdout);
		return 1;
	}

	if(0 == pid)
	{
		fputs("CHILD:  fork returned 0, local = ", stdout);
		fputs(int2str(local, 10, TRUE), stdout);
		fputs(", heap = <", stdout);
		fputs(heaped, stdout);
		fputs(">\n", stdout);
		fflush(stdout);
		return 7;
	}

	fputs("PARENT: fork returned a child, local = ", stdout);
	fputs(int2str(local, 10, TRUE), stdout);
	fputs(", heap = <", stdout);
	fputs(heaped, stdout);
	fputs(">\n", stdout);
	fflush(stdout);

	status = calloc(1, 4);
	if(0 > waitpid(pid, status, 0))
	{
		fputs("PARENT: waitpid failed\n", stdout);
		fflush(stdout);
		return 1;
	}

	fputs("PARENT: child exited with ", stdout);
	fputs(int2str(status[0] / 256, 10, TRUE), stdout);
	fputs("   (expected 7)\n", stdout);
	fflush(stdout);

	if(argc < 2) return 0;

	/* fork and exec, which is what fork is for. */
	a = calloc(argc, 4);
	i = 1;
	while(i < argc)
	{
		a[i - 1] = argv[i];
		i = i + 1;
	}

	fputs("fork+exec of ", stdout);
	fputs(a[0], stdout);
	fputs("\n", stdout);
	fflush(stdout);

	pid = fork();
	if(0 > pid)
	{
		fputs("second fork failed\n", stdout);
		fflush(stdout);
		return 1;
	}
	if(0 == pid) execve(a[0], a, NULL);

	if(0 > waitpid(pid, status, 0))
	{
		fputs("PARENT: waitpid failed\n", stdout);
		fflush(stdout);
		return 1;
	}
	fputs("PARENT: exec'd child exited with ", stdout);
	fputs(int2str(status[0] / 256, 10, TRUE), stdout);
	fputs("\n", stdout);
	fflush(stdout);
	return 0;
}
