/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * Starting another program, and waiting for it.
 *
 * There is no fork here, and there is not going to be one.  fork's whole
 * meaning is that the child comes back from the same call with the same memory
 * and carries on from the same line, and Windows has no call that does that.
 * ntdll exports RtlCloneUserProcess, which is the closest thing, but it clones
 * an address space the Win32 side of the system knows nothing about, and this
 * port cannot test it: wine does not export it at all.  So fork fails, and
 * says why.
 *
 * What is here instead is the three steps of the fork-exec-wait pattern taken
 * apart, so a caller can spell it the way Windows can actually do it:
 *
 *   __spawn(path, argv, envp)  start a program; a handle to it comes back
 *   waitpid(pid, &status, 0)   wait for one of those to finish
 *   execve(path, argv, envp)   both of the above, and then exit as it did
 *
 * A pid here is the process handle, the same way a file descriptor elsewhere
 * in this port is a file handle.  execve does not replace the running image --
 * nothing on Windows can -- but it does not return either, and the process's
 * exit status is the child's, so the only way to tell is to look at the
 * process list while it runs.
 *
 * A program that today says
 *
 *   pid = fork(); if(0 == pid) execve(f, argv, envp); else waitpid(pid, &s, 0);
 *
 * says this instead, and needs no fork:
 *
 *   pid = __spawn(f, argv, envp); waitpid(pid, &s, 0);
 *
 * Two limits worth knowing.  Windows hands a child one string rather than a
 * vector, so argv is joined with spaces and the child splits it again -- and
 * the splitting in x86/libc-core.M1 knows nothing about quotes, so an argument
 * with a space in it arrives as two.  And the child inherits this process's
 * three standard handles, which is what makes redirection work at all, but
 * only those three.
 *
 * The calling rules for everything below are in M2libc-windows/ntdll.c: the
 * arguments go in backwards, and none of them may write EDX.
 */

#ifndef __PROCESS_C
#define __PROCESS_C

/* argv as the single command line Windows gives a child. */
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
		n = n + j + 1;
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
		j = 0;
		while(0 != argv[i][j])
		{
			out[at] = argv[i][j];
			at = at + 1;
			j = j + 1;
		}
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
	 * block -- the same three words __stdslot points into here. */
	slot = __stdslot(0);
	params[6] = slot[0];
	slot = __stdslot(1);
	params[7] = slot[0];
	slot = __stdslot(2);
	params[8] = slot[0];

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

/* See the top of this file.  Windows has no call that returns twice, and a
 * caller that wants a child should use __spawn and waitpid, which are what
 * fork and execve would have been built out of anyway. */
int fork()
{
	return -1;
}
#endif
