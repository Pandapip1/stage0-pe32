/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * x86/M2libc-windows/process.c, exercised.  Build it the way Phase 7 builds
 * hex2 -- the same -f list, with this file last -- and give it a program to
 * start, followed by whatever that program wants:
 *
 *   spawn-test x86\artifact\hex0.exe x86\hex0_x86.hex0 out.exe
 *
 * The program named must be one whose output tells you it ran.  hex0
 * assembling hex0_x86.hex0 is the obvious one: the result should be the seed,
 * byte for byte, which is worth checking afterwards.
 *
 * What this shows, in order: fork fails and says so; a spawned child gets this
 * process's standard handles, so anything it prints lands here; waitpid brings
 * back what it exited with; a program that is not there fails rather than
 * hanging; and execve does not return.
 */

int main(int argc, char** argv)
{
	char** a;
	int* status;
	int pid;
	int i;

	fputs("fork() = ", stdout);
	fputs(int2str(fork(), 10, TRUE), stdout);
	fputs("   (expected -1: Windows has no call that returns twice)\n", stdout);
	fflush(stdout);

	/* argv[1] onwards, in an array of its own */
	a = calloc(argc, 4);
	i = 1;
	while(i < argc)
	{
		a[i - 1] = argv[i];
		i = i + 1;
	}

	fputs("spawning ", stdout);
	fputs(a[0], stdout);
	fputs("\n", stdout);
	fflush(stdout);

	pid = __spawn(a[0], a, NULL);
	if(0 >= pid)
	{
		fputs("__spawn failed\n", stdout);
		return 1;
	}

	status = calloc(1, 4);
	if(0 > waitpid(pid, status, 0))
	{
		fputs("waitpid failed\n", stdout);
		return 1;
	}

	fputs("it exited with ", stdout);
	fputs(int2str(status[0] / 256, 10, TRUE), stdout);
	fputs("\n", stdout);

	fputs("a program that is not there: ", stdout);
	fputs(int2str(__spawn("no-such-program.exe", a, NULL), 10, TRUE), stdout);
	fputs("   (expected -1)\n", stdout);

	fputs("execve now; nothing after this line should print, and this\n", stdout);
	fputs("process should exit with what the child exits with\n", stdout);
	fflush(stdout);

	execve(a[0], a, NULL);

	fputs("execve RETURNED, which it must not do\n", stdout);
	fflush(stdout);
	return 1;
}
