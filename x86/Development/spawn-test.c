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
 * What this shows, in order: a spawned child gets this process's standard
 * handles, so anything it prints lands here; waitpid brings back what it
 * exited with; a program that is not there fails rather than hanging;
 * arguments survive being joined into one command line and split again, which
 * it checks by spawning itself; and execve does not return.
 *
 * fork is not exercised here -- x86/Development/fork-test.c is where that
 * lives.  An earlier version of this file called it once to show that it
 * failed, which stopped being true.
 *
 * The first and fourth of those are the ones worth watching on Windows: they
 * used to fail there and pass under wine, because a child's startup replaced
 * the standard handles it had been given before it ran.  The "and what arrived
 * was" list coming out empty is that failure, rather than an argument that did
 * not survive being quoted.  See the head of x86/M2libc-windows/process.c for
 * what the child was doing and which flag stops it.
 */

int main(int argc, char** argv)
{
	char** a;
	char** AWKWARD;
	int* status;
	int pid;
	int i;

	/* Spawned by the run below, to say what actually arrived. */
	if((argc > 1) && match("--echo-args", argv[1]))
	{
		i = 2;
		while(i < argc)
		{
			fputs("    <", stdout);
			fputs(argv[i], stdout);
			fputs(">\n", stdout);
			i = i + 1;
		}
		fflush(stdout);
		return 0;
	}

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

	/* The arguments spawning has to survive: a space, quotes, and the
	 * trailing backslash that a naive quoter turns into an escape for the
	 * closing quote, losing the rest of the command line with it. */
	AWKWARD = calloc(6, 4);
	AWKWARD[0] = "a b";
	AWKWARD[1] = "has \"quotes\" in it";
	AWKWARD[2] = "C:\\dir\\";
	AWKWARD[3] = "back\\\\slash";
	AWKWARD[4] = "lone\\slash";
	AWKWARD[5] = "plain";

	fputs("spawning myself; these should come back exactly as written:\n", stdout);
	i = 0;
	while(i < 6)
	{
		fputs("    <", stdout);
		fputs(AWKWARD[i], stdout);
		fputs(">\n", stdout);
		i = i + 1;
	}
	fputs("and what arrived was:\n", stdout);
	fflush(stdout);

	a = calloc(9, 4);
	a[0] = argv[0];
	a[1] = "--echo-args";
	i = 0;
	while(i < 6)
	{
		a[i + 2] = AWKWARD[i];
		i = i + 1;
	}
	a[8] = NULL;
	pid = __spawn(a[0], a, NULL);
	if(0 >= pid)
	{
		fputs("could not spawn myself\n", stdout);
		return 1;
	}
	waitpid(pid, status, 0);

	/* argv[1] onwards again, for the execve below. */
	a = calloc(argc, 4);
	i = 1;
	while(i < argc)
	{
		a[i - 1] = argv[i];
		i = i + 1;
	}

	fputs("execve now; nothing after this line should print, and this\n", stdout);
	fputs("process should exit with what the child exits with\n", stdout);
	fflush(stdout);

	execve(a[0], a, NULL);

	fputs("execve RETURNED, which it must not do\n", stdout);
	fflush(stdout);
	return 1;
}
