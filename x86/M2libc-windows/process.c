/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * Starting another program, and waiting for it.
 *
 * Windows really does have a fork primitive, and it really does not work.
 * There are four ways in, and all four were measured on Windows 11 22621:
 *
 *   RtlCloneUserProcess    clones, and the child never comes back
 *   NtCreateProcessEx      clones, and the clone cannot be given a thread
 *   NtCreateProcess        the same, by the older name
 *   NtCreateUserProcess    the supported one, which does not clone at all
 *
 * The first three are written up at __clone_process.  The fourth is what
 * RtlCreateUserProcess calls underneath and what __spawn therefore already
 * uses; calling it directly buys the PS_ATTRIBUTE_LIST, which is the only way
 * to ask for PsAttributeStdHandleInfo -- and asking for it, with
 * PsAlwaysDuplicate, does not fix the standard handles either.  That was
 * tried: it needs every structure 8-aligned, since PS_CREATE_INFO holds
 * ULONGLONGs and the kernel says STATUS_DATATYPE_MISALIGNMENT otherwise, and
 * with that done it returns PsCreateSuccess and the child runs -- hex0
 * started that way assembles the seed byte for byte -- and its writes to the
 * standard handles still go nowhere.  So __spawn keeps RtlCreateUserProcess,
 * which is the same call with less to get wrong.
 *
 * NtCreateProcessEx given a parent and no section handle clones the parent's
 * address space rather than mapping an image -- ReactOS's own PspCreateProcess
 * reaches that branch and says "This is a clone!" before declining to
 * implement it -- and RtlCloneUserProcess is the wrapper around it that makes
 * a thread in the result and is meant to return in both processes, telling the
 * child which it is by handing it STATUS_PROCESS_CLONED where the parent gets
 * STATUS_SUCCESS.  __clone_process below is that call, and what it does on
 * Windows 11 is written up there.  fork returns -1, because a fork whose child
 * never runs is worse than no fork at all.
 *
 * So three steps rather than four, and a caller wanting a child says __spawn
 * and waitpid where it would have said fork and execve:
 *
 *   __spawn(path, argv, envp)  start a program; a handle to it comes back
 *   waitpid(pid, &status, 0)   wait for one of those to finish
 *   execve(path, argv, envp)   __spawn and waitpid, and then exit as it did
 *
 * A pid here is the process handle, the same way a file descriptor elsewhere
 * in this port is a file handle.  execve does not replace the running image --
 * nothing on Windows can -- but it does not return either, and the process's
 * exit status is the child's, so the only way to tell is to look at the
 * process list while it runs.
 *
 * A program that says
 *
 *   pid = fork(); if(0 == pid) execve(f, argv, envp); else waitpid(pid, &s, 0);
 *
 * says this instead, which is two lines and no fork:
 *
 *   pid = __spawn(f, argv, envp); waitpid(pid, &s, 0);
 *
 * Windows hands a child one string rather than a vector, so argv is joined
 * into one here and split again at the other end.  Both halves follow the rule
 * CommandLineToArgvW defines, which is the one every Windows program is parsed
 * by: an argument with a space or a quote in it is wrapped in quotes, a quote
 * inside it becomes \", and a backslash run before either becomes twice as
 * long so that the split can tell the two apart.  So an argument survives the
 * round trip whatever is in it -- see next_token in x86/ntdll-i386.hex2 for
 * the other side of the same rule.
 *
 * The child inherits this process's three standard handles, which is what
 * makes redirection work at all, but only those three.
 *
 * That last part works under wine and does NOT work on Windows, and the
 * difference is not understood.  What is known: the three handles are
 * duplicated with OBJ_INHERIT and their numbers written into the child's
 * parameter block; the child reads those same numbers back out of its own
 * PEB; and NtWriteFile to them returns success and a count.  On Windows the
 * bytes then go nowhere -- not to the parent's console and not to the file
 * the parent's output was redirected to, with the parent writing nothing
 * afterwards that could land on top of them.  A child still runs, still reads
 * and writes files it opens itself, and still reports its exit status, all of
 * which are checked on Windows; only handles it was given rather than opened
 * are affected.  Everything this bootstrap builds opens its own files, so
 * nothing here depends on it, but a shell would.
 *
 * The calling rules for everything below are in M2libc-windows/ntdll.c: the
 * arguments go in backwards, and none of them may write EDX.
 */

#ifndef __PROCESS_C
#define __PROCESS_C

/* The closing quote of a quoted argument.  A function of its own because
 * __quote_arg reaches the end from two places. */
int __quote_close(char* dst, int at)
{
	dst[at] = '"';
	return at + 1;
}

/* One argument, written into dst at `at` the way CommandLineToArgvW will read
 * it back, and where the next one would go.
 *
 * An argument with nothing awkward in it is written as it stands.  One with a
 * space, a tab or a quote is wrapped in quotes, and then two things have to be
 * escaped inside: a quote becomes \", and any run of backslashes that is
 * about to be followed by a quote -- the one being escaped, or the one that
 * closes the argument -- is doubled, so that the reader can tell a backslash
 * that is text from one that is protecting the quote after it.  A run of
 * backslashes anywhere else is left alone.
 *
 * `C:\dir\` is the case that makes this necessary rather than pedantic:
 * written naively it would end ...dir\", and the reader would take that
 * backslash to be protecting the closing quote and swallow the rest of the
 * command line. */
int __quote_arg(char* dst, int at, char* arg)
{
	int i;
	int n;
	int plain;

	plain = 1;
	if(0 == arg[0]) plain = 0;
	i = 0;
	while(0 != arg[i])
	{
		if((' ' == arg[i]) || ('\t' == arg[i]) || ('"' == arg[i])) plain = 0;
		i = i + 1;
	}

	if(plain)
	{
		i = 0;
		while(0 != arg[i])
		{
			dst[at] = arg[i];
			at = at + 1;
			i = i + 1;
		}
		return at;
	}

	dst[at] = '"';
	at = at + 1;
	i = 0;
	while(0 != arg[i])
	{
		n = 0;
		while('\\' == arg[i])
		{
			n = n + 1;
			i = i + 1;
		}

		if(0 == arg[i])
		{
			/* The run runs into the closing quote, so it doubles. */
			n = 2 * n;
		}
		else if('"' == arg[i])
		{
			/* The run protects nothing, but the quote after it needs
			 * protecting, which is the odd one on the end. */
			n = 2 * n + 1;
		}

		while(0 < n)
		{
			dst[at] = '\\';
			at = at + 1;
			n = n - 1;
		}

		if(0 == arg[i]) return __quote_close(dst, at);

		dst[at] = arg[i];
		at = at + 1;
		i = i + 1;
	}
	return __quote_close(dst, at);
}

/* argv as the single command line Windows gives a child.  Room for twice each
 * argument plus its quotes, which is the worst an argument of nothing but
 * backslashes and quotes could come to. */
char* __cmdline(char** argv)
{
	int n;
	int i;
	int j;
	char* out;
	int at;

	n = 0;
	i = 0;
	while(NULL != argv[i])
	{
		j = 0;
		while(0 != argv[i][j]) j = j + 1;
		n = n + 2 * j + 3;
		i = i + 1;
	}

	out = calloc(n + 1, 1);
	at = 0;
	i = 0;
	while(NULL != argv[i])
	{
		if(0 != at)
		{
			out[at] = ' ';
			at = at + 1;
		}
		at = __quote_arg(out, at, argv[i]);
		i = i + 1;
	}
	out[at] = 0;
	return out;
}

/* envp as the block Windows wants: the entries one after another in UTF-16,
 * each ended by a zero, and a second zero after the last.  NULL in means NULL
 * out, which tells RtlCreateProcessParameters to give the child this
 * process's environment rather than a new one. */
char* __envblock(char** envp)
{
	int n;
	int i;
	int j;
	char* w;
	int at;

	if(NULL == envp) return NULL;

	n = 0;
	i = 0;
	while(NULL != envp[i])
	{
		j = 0;
		while(0 != envp[i][j]) j = j + 1;
		n = n + j + 1;
		i = i + 1;
	}

	/* One more character for the zero that ends the block, and calloc has
	 * already written every zero this needs. */
	w = calloc(n + 2, 2);
	at = 0;
	i = 0;
	while(NULL != envp[i])
	{
		j = 0;
		while(0 != envp[i][j])
		{
			w[2 * at] = envp[i][j];
			at = at + 1;
			j = j + 1;
		}
		at = at + 1;
		i = i + 1;
	}
	return w;
}

/* The same handle again, marked so that a child may inherit it.
 *
 * A handle is only passed to a child if it was created inheritable, and the
 * three this process was handed need not have been -- on Windows the parent
 * has to say so, and duplicating with OBJ_INHERIT is how.  If the duplicate
 * fails the original is used, which is no worse than not trying. */
int __inheritable(int handle)
{
	int (*NtDuplicateObject)(int, int, int, int, int, int, int);
	int* out;

	if(0 == handle) return 0;

	out = calloc(1, 4);
	NtDuplicateObject = __ntdll(NT_DUP);
	/* forwards: NtDuplicateObject(-1, handle, -1, out, 0, OBJ_INHERIT,
	 *                             DUPLICATE_SAME_ACCESS) */
	if(0 != NtDuplicateObject(2, 2, 0, out, -1, handle, -1)) return handle;
	return out[0];
}

/* Start a program.  Returns a handle to it, which waitpid takes, or -1.
 *
 * RtlCreateProcessParameters builds the block the child's PEB will point at --
 * its command line, its environment, and the three standard handles, which
 * are copied out of this process's own block so that the child reads and
 * writes wherever this one does.  RtlCreateUserProcess then makes the process
 * from the image named by an NT path, with the initial thread suspended,
 * which is why nothing runs until NtResumeThread. */
int __spawn(char* file_name, char** argv, char** envp)
{
	int (*RtlCreateProcessParameters)(int, int, int, int, int, int, int, int, int, int);
	int (*RtlCreateUserProcess)(int, int, int, int, int, int, int, int, int, int);
	int (*NtResumeThread)(int, int);
	int* oa;
	int* ntpath;
	int* image;
	int* cmd;
	char* line;
	char* env;
	int* out;
	int* params;
	int* info;
	int* slot;
	int h;
	int thread;
	int rc;

	oa = __ntobject(file_name);
	if(NULL == oa) return -1;
	ntpath = oa[2];                /* the UNICODE_STRING __ntobject made */

	line = __cmdline(argv);
	image = __dosustring(file_name);
	cmd = __dosustring(line);
	env = __envblock(envp);
	out = calloc(1, 4);

	RtlCreateProcessParameters = __ntdll(NT_MAKEPARAMS);
	/* forwards: RtlCreateProcessParameters(out, image, NULL, NULL, cmd, env,
	 *                                      NULL, NULL, NULL, NULL) */
	rc = RtlCreateProcessParameters(0, 0, 0, 0, env, cmd, 0, 0, image, out);
	if(0 != rc) return -1;
	params = out[0];

	/* hStdInput, hStdOutput and hStdError, at 0x18, 0x1c and 0x20 into the
	 * block -- the same three words __stdslot points into here.  Each is
	 * duplicated inheritable first: writing the number into the child's
	 * parameters says which handle it should use, but only a handle marked
	 * inheritable is actually copied into the child, and the three this
	 * process was given need not be. */
	slot = __stdslot(0);
	h = slot[0];
	params[6] = __inheritable(h);
	slot = __stdslot(1);
	h = slot[0];
	params[7] = __inheritable(h);
	slot = __stdslot(2);
	h = slot[0];
	params[8] = __inheritable(h);

	/* RTL_USER_PROCESS_INFORMATION: Length, Process, Thread, a CLIENT_ID and
	 * a SECTION_IMAGE_INFORMATION, which is 68 bytes altogether.  The room is
	 * larger than that because only the first three words are read here and
	 * the cost of being generous is nothing. */
	info = calloc(32, 4);
	info[0] = 68;

	RtlCreateUserProcess = __ntdll(NT_CREATEPROC);
	/* forwards: RtlCreateUserProcess(ntpath, OBJ_CASE_INSENSITIVE, params,
	 *                                NULL, NULL, NULL, TRUE, NULL, NULL, info) */
	rc = RtlCreateUserProcess(info, 0, 0, 1, 0, 0, 0, params, 0x40, ntpath);
	if(0 != rc) return -1;

	NtResumeThread = __ntdll(NT_RESUME);
	thread = info[2];
	/* forwards: NtResumeThread(thread, NULL) */
	NtResumeThread(0, thread);

	return info[1];
}

/* Wait for one of those to finish.  options is accepted and ignored: WNOHANG
 * would be a zero timeout on the wait below, and nothing here asks for it.
 *
 * The status goes back in the shape POSIX put it in, with the exit code in the
 * second byte up, so that a caller's WEXITSTATUS shifts it back down and gets
 * what the child returned.  Nothing here can be killed by a signal, so the low
 * byte -- which is where that would be reported -- is always zero. */
int waitpid(int pid, int* status_ptr, int options)
{
	int (*NtWaitForSingleObject)(int, int, int);
	int (*NtQueryInformationProcess)(int, int, int, int, int);
	int* basic;
	int rc;

	if(0 >= pid) return -1;

	NtWaitForSingleObject = __ntdll(NT_WAIT);
	/* forwards: NtWaitForSingleObject(pid, FALSE, NULL) -- NULL is no timeout */
	rc = NtWaitForSingleObject(0, 0, pid);
	if(0 > rc) return -1;

	/* PROCESS_BASIC_INFORMATION, class 0, with ExitStatus first */
	basic = calloc(8, 4);
	NtQueryInformationProcess = __ntdll(NT_QUERYPROC);
	/* forwards: NtQueryInformationProcess(pid, ProcessBasicInformation, basic,
	 *                                     24, NULL) */
	rc = NtQueryInformationProcess(0, 24, basic, 0, pid);
	if(0 != rc) return -1;

	if(NULL != status_ptr) status_ptr[0] = 256 * basic[0];
	return pid;
}

/* Start a program and become it, as far as anything watching can tell: this
 * does not return, and what this process exits with is what the child exited
 * with.  The image is not replaced, because no Windows call replaces one; the
 * process stays alive doing nothing but waiting. */
int execve(char* file_name, char** argv, char** envp)
{
	int pid;
	int* status;

	pid = __spawn(file_name, argv, envp);
	if(0 >= pid) return -1;

	status = calloc(1, 4);
	if(0 > waitpid(pid, status, 0)) return -1;
	exit(status[0] / 256);
}

/* What fork would be, if the clone's child ever came back.
 *
 * Kept, and not called, because the knowledge is worth more than the code and
 * because a system where this works would get a real fork for free.  What was
 * measured on Windows 11 22621, from this and independently from elsewhere:
 *
 *   The parent gets STATUS_SUCCESS and a genuine cloned process -- tasklist
 *   shows two, and NtQueryInformationProcess reports the child as
 *   STATUS_PENDING, so it exists and has not exited.
 *
 *   Its one thread is not suspended: NtResumeThread returns a previous
 *   suspend count of 0.  It sits in Wait, and never reaches the first
 *   statement after the call -- checked by having that statement be a single
 *   fopen of a file whose presence is the whole test.
 *
 *   Every flag combination behaves the same: 0, CREATE_SUSPENDED,
 *   INHERIT_HANDLES, both, NO_SYNCHRONIZE, and NO_SYNCHRONIZE with
 *   INHERIT_HANDLES.
 *
 *   Doing it by hand does not help.  NtCreateProcessEx and NtCreateProcess,
 *   each given this process as the parent and no section handle, both clone
 *   successfully and hand back a process handle -- and NtCreateThreadEx then
 *   refuses to put a thread in either of them, with
 *   STATUS_PROCESS_IS_TERMINATING, whatever thread flags are asked for,
 *   SKIP_LOADER_INIT included.  A clone with no thread is torn down before it
 *   can be given one.
 *
 *   It is not this port's doing and not WOW64's.  The same call from 64-bit
 *   PowerShell and from 32-bit PowerShell, through P/Invoke, clones the
 *   process and never returns in the child either.
 *
 * wine does not export RtlCloneUserProcess at all, so the slot stays 0 there,
 * which is checked rather than assumed: resolve_export returns 0 for a name
 * that is not in the export table.
 *
 * The parent would get the child's process handle, which is what waitpid here
 * takes -- POSIX would give a pid, and this is the same substitution as a file
 * descriptor being a handle. */
int __clone_process()
{
	int (*RtlCloneUserProcess)(int, int, int, int, int);
	int (*NtResumeThread)(int, int);
	int* info;
	int thread;
	int i;
	int rc;

	RtlCloneUserProcess = __ntdll(NT_CLONE);
	if(NULL == RtlCloneUserProcess) return -1;

	/* RTL_USER_PROCESS_INFORMATION, as __spawn fills in */
	info = calloc(32, 4);
	i = 0;
	while(i < 32)
	{
		info[i] = 0;
		i = i + 1;
	}
	info[0] = 68;

	/* forwards: RtlCloneUserProcess(RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
	 *                               NULL, NULL, NULL, info) */
	rc = RtlCloneUserProcess(info, 0, 0, 0, 2);

	if(0x129 == rc) return 0;        /* STATUS_PROCESS_CLONED: this is the child */
	if(0 != rc) return -1;

	/* The clone's first thread starts suspended, the same way the one
	 * RtlCreateUserProcess makes does, so the child does not come back from
	 * the call above until it is let go. */
	NtResumeThread = __ntdll(NT_RESUME);
	thread = info[2];
	/* forwards: NtResumeThread(thread, NULL) */
	NtResumeThread(0, thread);

	return info[1];                  /* and the parent gets a handle to it */
}

/* Windows has the primitive and the primitive does not work; see
 * __clone_process.  Failing here is deliberate: a fork whose parent gets a
 * child handle and whose child never runs would hang the first caller to wait
 * for it, which is worse than a fork that says it cannot. */
int fork()
{
	return -1;
}
#endif
