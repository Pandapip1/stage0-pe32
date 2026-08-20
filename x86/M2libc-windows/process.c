/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * Starting another program, and waiting for it.
 *
 * fork works here, and not by any of the means Windows offers for it.
 *
 * Windows really does have a fork primitive, and it really does not work.
 * There are four ways in, and all four were measured on Windows 11 22621:
 *
 *   RtlCloneUserProcess    clones, and under WOW64 the child never comes back
 *   NtCreateProcessEx      clones, and the clone cannot be given a thread
 *   NtCreateProcess        the same, by the older name
 *   NtCreateUserProcess    the supported one, which does not clone at all
 *
 * The first of those was measured again from a native 64-bit caller on the
 * same machine, and there the clone's child does come back, and runs.  So the
 * defect is WOW64's rather than cloning's -- which is no help at all to a
 * 32-bit bootstrap, but does say where to look in an x86_64 one.
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
 * implement it.  An earlier version of this comment said RtlCloneUserProcess
 * wraps that call.  It does not: disassembling ntdll32.dll shows
 * RtlCloneUserProcess calling a private helper that ends in
 * ZwCreateUserProcess, the same syscall behind ordinary process creation, not
 * NtCreateProcessEx.  So there are two unrelated clone paths through the
 * kernel, not one built on the other, and a defect found in one says nothing
 * about the other.  RtlCloneUserProcess makes a thread in the result and is
 * meant to return in both processes, telling the child which it is by handing
 * it STATUS_PROCESS_CLONED where the parent gets STATUS_SUCCESS.
 * __clone_process below is that call, and what it does on Windows 11 is
 * written up there.  It is kept, and not called.
 *
 * What fork does instead is start this same program again and overwrite the
 * copy with this one: the way Cygwin has always done it, and possible here
 * for a reason particular to this bootstrap, which is that its image is at a
 * fixed address with everything -- code, globals, heap, even the stack the
 * kernel hands out -- laid out identically in every process that runs it.  So
 * one copy's memory means the same thing in another copy, and no fixups are
 * needed at all.  The whole of it is written up at fork below.
 *
 * So four calls, and a caller wanting a child may say either what POSIX says
 * or the shorter thing Windows can do directly:
 *
 *   fork()                     twice-returning, 0 in the child
 *   __spawn(path, argv, envp)  start a program; a handle to it comes back
 *   waitpid(pid, &status, 0)   wait for one of those to finish
 *   execve(path, argv, envp)   __spawn and waitpid, and then exit as it did
 *
 * fork and execve together do what fork and exec do anywhere.  __spawn is the
 * cheaper way to say the same thing when the child is only ever going to
 * exec: it is one process where fork plus execve is two.
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
 * now works as written, and may still say this instead, which is two lines
 * and one process rather than two:
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
 * Handing a child those three takes one thing beyond the obvious, and without
 * it the failure is silent.  The obvious part is that each handle is
 * duplicated with OBJ_INHERIT and its number written into the parameter block
 * the child's PEB will point at.  Do only that, and on Windows the child runs,
 * reads its numbers back out of its own PEB, writes to them, and is told by
 * the kernel that the bytes went out -- STATUS_SUCCESS and a count in the
 * IO_STATUS_BLOCK -- and nothing arrives anywhere.
 *
 * What happens in between is that the child's own startup replaces them.  It
 * copies the parameter block onto its heap, and unless it is told otherwise it
 * fills the three handle fields in with console handles of its own making
 * before the first instruction of the program runs.  The numbers the parent
 * wrote are gone by then, and writes to what replaced them are accepted and
 * discarded.  Measured, with the child suspended and then asked from the
 * inside: its PEB->ProcessParameters is not the address the parent poked, the
 * handle it ends up with is not the one it was given, and
 * NtQueryInformationFile on it answers STATUS_INVALID_DEVICE_REQUEST where the
 * parent's own handle names the pipe it really is.  The handle the parent
 * duplicated is still there and still works -- writing to it by number, from
 * the child, reaches the parent's pipe -- so it is the three fields that are
 * lost rather than the handles.
 *
 * Being told otherwise is STARTF_USESTDHANDLES in WindowFlags.  ReactOS's
 * SetUpHandles -- dll/win32/kernel32/client/console/init.c -- is the same
 * decision written down: it assigns the three console handles over the
 * parameter block's only `if ((dwStartupFlags & STARTF_USESTDHANDLES) == 0)`.
 * That flag is what a Win32 caller sets by filling in STARTUPINFO's hStdInput,
 * hStdOutput and hStdError, and there is no way to reach it from
 * RtlCreateUserProcess's arguments, so __spawn writes it into the block
 * directly.  With it set the handles survive, and a child's output lands
 * wherever the parent's does.
 *
 * wine never had the problem for a reason that flatters nobody: it does this
 * in kernelbase rather than in ntdll -- init_console_std_handles, called from
 * dlls/kernelbase/console.c -- and a program that imports ntdll and nothing
 * else never loads kernelbase, so on wine there is nothing to overwrite the
 * three fields and the flag is never consulted.  Every program this bootstrap
 * builds is such a program.  Worth remembering as a shape rather than a
 * detail: wine agreeing is not evidence that Windows will.
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
/* __spawn, up to but not including letting the child go.
 *
 * A process Windows has created is suspended until something resumes its one
 * thread, and fork wants that gap: it has a whole address space to copy in and
 * a thread to point somewhere else before the child may run a single
 * instruction.  __spawn is this and then a resume; fork is this and then a
 * great deal more.  info comes back filled in -- Process at [1], Thread at
 * [2] -- and is the caller's to resume. */
int __spawn_suspended(char* file_name, char** argv, char** envp, int* info)
{
	int (*RtlCreateProcessParameters)(int, int, int, int, int, int, int, int, int, int);
	int (*RtlCreateUserProcess)(int, int, int, int, int, int, int, int, int, int);
	int* oa;
	int* ntpath;
	int* image;
	int* cmd;
	char* line;
	char* env;
	int* out;
	int* params;
	int* slot;
	int h;
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

	/* STARTF_USESTDHANDLES, in WindowFlags at 0x68 into the block, which is
	 * what stops the three handles just written from being thrown away
	 * before the child's first instruction.  See the head of this file. */
	params[26] = 256;

	info[0] = 68;

	RtlCreateUserProcess = __ntdll(NT_CREATEPROC);
	/* forwards: RtlCreateUserProcess(ntpath, OBJ_CASE_INSENSITIVE, params,
	 *                                NULL, NULL, NULL, TRUE, NULL, NULL, info) */
	rc = RtlCreateUserProcess(info, 0, 0, 1, 0, 0, 0, params, 0x40, ntpath);
	if(0 != rc) return -1;

	return info[1];
}

int __spawn(char* file_name, char** argv, char** envp)
{
	int (*NtResumeThread)(int, int);
	int (*NtClose)(int);
	int* info;
	int thread;
	int pid;

	/* RTL_USER_PROCESS_INFORMATION: Length, Process, Thread, a CLIENT_ID and
	 * a SECTION_IMAGE_INFORMATION, which is 68 bytes altogether.  The room is
	 * larger than that because only the first three words are read here and
	 * the cost of being generous is nothing. */
	info = calloc(32, 4);
	info[0] = 68;

	pid = __spawn_suspended(file_name, argv, envp, info);
	if(0 >= pid) return -1;

	NtResumeThread = __ntdll(NT_RESUME);
	thread = info[2];
	/* forwards: NtResumeThread(thread, NULL) */
	NtResumeThread(0, thread);

	/* The thread handle has done its one job.  The process handle is what
	 * comes back and is the caller's; this one would otherwise be leaked a
	 * handle at a time, once per child ever started. */
	NtClose = __ntdll(NT_CLOSE);
	NtClose(thread);

	return pid;
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
 * Kept, and not called.  fork does work now -- see fork below -- but by
 * copying one process into another rather than by asking Windows to clone
 * anything, and everything in this note is still true of the thing Windows
 * actually offers.  It is worth keeping for two reasons: a system where the
 * clone worked would get a cheaper fork than the one below for free, and the
 * measurements cost enough to find that throwing them away would be a waste.
 * What was measured on Windows 11 22621, from this and independently from
 * elsewhere:
 *
 *   The parent gets STATUS_SUCCESS and a genuine cloned process -- tasklist
 *   shows two, and NtQueryInformationProcess reports the child as
 *   STATUS_PENDING, so it exists and has not exited.
 *
 *   Its one thread is not suspended: NtResumeThread returns a previous
 *   suspend count of 0.  It never reaches the first statement after the call
 *   -- checked by having that statement be a single fopen of a file whose
 *   presence is the whole test.
 *
 *   How it stops is not the same for every flag combination.  With 0,
 *   CREATE_SUSPENDED, INHERIT_HANDLES or both, the child deadlocks.  With
 *   NO_SYNCHRONIZE, with or without the others, it does not deadlock: it runs
 *   and dies of an access violation.  Two earlier versions of this note got
 *   that wrong in opposite directions -- one said the outcome was the same
 *   for every combination, the next said the child stopped in a different
 *   place depending on them.  It stops in the same place either way; what the
 *   flags change is whether it can say so.
 *
 *   The deadlock is an inherited lock.  RtlCloneUserProcess takes the SRW
 *   lock at ntdll+0x12d7a4 exclusively across the clone -- disassembling it
 *   shows that address four times inside the one routine -- so the child's
 *   address space is a snapshot in which that lock is held, and anything on
 *   the child's side that wants it shared waits in NtWaitForAlertByThreadId
 *   to be alerted by a thread that does not exist on this side of the fork.
 *   Read out of the child: EIP in ZwWaitForAlertByThreadId, the lock's
 *   address twice on the stack, and LdrInitializeThunk further up it.
 *
 *   An earlier version of this note called that "fully understood" and put
 *   the deadlock first, with the fs:0x18 fault below as a second, later
 *   failure that only appears once the lock is out of the way.  That is
 *   backwards, and the same stack that settled the LdrInitializeThunk
 *   question says so.  Without touching the lock at all, the deadlocked
 *   child's stack holds, above the frames it is currently in:
 *
 *       0x85ff300   an EXCEPTION_RECORD: ExceptionCode 0xc0000005,
 *                   ExceptionAddress ntdll+0x8c5d6, NumberParameters 2,
 *                   ExceptionInformation 0 (a read) and 0x18
 *       0x85ff350   the CONTEXT paired with it: ContextFlags 0x1007f,
 *                   Eip ntdll+0x8c5d6, Cs 0x23, Esp 0x85ff7b8, SegFs 0x53
 *       0x85ff2ec   a return address in KiUserExceptionDispatcher+0x26
 *
 *   and below that nothing but exception dispatch -- RtlUnwind,
 *   _except_handler4_common, _local_unwind4 -- ending in
 *   RtlAcquireSRWLockShared+0x148 with ntdll+0x12d7a4 as its argument, at
 *   ZwWaitForAlertByThreadId.
 *
 *   So the fault comes first, every time, lock or no lock.  What waits on the
 *   inherited lock is the exception dispatcher, trying to report a fault that
 *   has already happened; the child is not stopped short of the fault by a
 *   lock, it is stopped short of ever saying so.  Zeroing the lock does not
 *   let the child get further, it lets the fault be reported, so the process
 *   dies instead of hanging.  One defect, not two, and the second symptom was
 *   only ever the first one being unable to speak.
 *
 *   That "like any new thread" is worth checking rather than assuming, since
 *   the clone's own thread was a real, running thread before the clone -- it
 *   had a working FS base once, or it could not have gotten anywhere, so
 *   something about the clone loses what it already had.  Whether the clone
 *   is dispatched exactly like a brand-new thread (EIP set to 32-bit
 *   LdrInitializeThunk from the start, the same place a genuinely new WOW64
 *   thread's native bring-up hands off to) or instead resumes wherever the
 *   parent was -- inside RtlCloneUserProcess itself, the way POSIX fork
 *   resumes both sides from the same program counter -- is answerable
 *   without running anything: clone with CREATE_SUSPENDED, never resume, and
 *   read NtGetContextThread before the thread has executed a single
 *   instruction.  Measured: Eip is ZwCreateUserProcess+0xc, Cs is 0x23.  Not
 *   LdrInitializeThunk.  ZwCreateUserProcess+0xc is inside that syscall's own
 *   stub, right where `mov eax,<number>; mov edx,[Wow64Transition]; call
 *   edx' returns -- so the clone's saved context is not "start a new
 *   thread", it is "come back from this same system call", exactly the way
 *   a POSIX fork's child continues from the same program counter as its
 *   parent.  Cs already being 0x23 says the mode switch back to 32-bit was
 *   already done by whoever built this context, same as everywhere else in
 *   this note.
 *
 *   That sat in tension with "the child's new thread then runs
 *   LdrInitializeThunk" above, which was read off the stack of an actually
 *   resumed, actually deadlocked child rather than off its context before
 *   running, and the tension is now settled: both readings are right, and
 *   neither of the two guesses about which one described the entry point was.
 *   Clone with CREATE_SUSPENDED, read the context, resume, wait, read the
 *   context again and read the stack it deadlocked on.  Before resuming, Eip
 *   is ZwCreateUserProcess+0xc and Esp is 0x85ffce8.  After, Eip is
 *   ZwWaitForAlertByThreadId+0xc, and on the stack, laid out from the top
 *   down:
 *
 *       0x85ffce8                the Esp the context before resuming had
 *       0x85ffa1c..0x85ffce8     a whole 716-byte i386 CONTEXT, ContextFlags
 *                                0x1003f, Eip ZwCreateUserProcess+0xc,
 *                                Cs 0x23, Esp 0x85ffce8
 *       0x85ffa10                a pointer to 0x85ffa1c
 *       0x85ffa00                a return address in LdrInitializeThunk+0x11
 *       0x85ff9ec                another, LdrInitializeThunk+0x70
 *
 *   So the thread's first 32-bit instruction is 32-bit LdrInitializeThunk,
 *   entered with a pointer to a CONTEXT written immediately beneath the
 *   parent's stack pointer -- 716 bytes of it, ending exactly at 0x85ffce8 --
 *   and that CONTEXT is precisely what NtGetContextThread reported before the
 *   thread ran.  The pre-resume context is the destination, not the entry
 *   point: loader init runs first and is meant to continue into it when it is
 *   done, which is the same shape as a genuinely new WOW64 thread, whose
 *   32-bit side also begins in LdrInitializeThunk with a context to resume.
 *   Nothing detours; the detour IS the start, and the "true" context is where
 *   it was always going to end up.
 *
 *   Which is a nicer answer than either guess.  The clone is dispatched like
 *   a brand-new thread AND it resumes from the same program counter as its
 *   parent -- the first describes where it begins, the second where loader
 *   init would hand it off to, and there was never a contradiction between
 *   them.  No debug port was needed for this after all; the stack said it.
 *
 *   Zeroing that lock in the child before letting it go therefore turns the
 *   hang into what NO_SYNCHRONIZE already showed: an access violation at
 *   ntdll+0x8c5d6, which is `mov eax, fs:0x18', in a function whose only
 *   caller in the whole DLL is LdrInitializeThunk.  Same fault either way --
 *   only its reporting differs.
 *
 *   Loader init is the wrong thing for a fork's child to be running at all,
 *   and there is a flag for that -- THREAD_CREATE_FLAGS_SKIP_LOADER_INIT --
 *   which NtCreateUserProcess will not take.  Forcing RtlCloneUserProcess to
 *   pass it anyway gets STATUS_INVALID_PARAMETER, which is what the note in
 *   the public headers saying "NtCreateThreadEx only" means.
 *
 *   NtCreateThreadEx will take it, and against a clone that already has a
 *   thread it returns STATUS_SUCCESS.  The earlier claim that it always
 *   answers STATUS_PROCESS_IS_TERMINATING is true only of the thread-less
 *   clones NtCreateProcessEx and NtCreateProcess make; it is not true here.
 *
 *   That road is closed all the same, and closed for a reason that has
 *   nothing to do with cloning: SKIP_LOADER_INIT cannot be used by a 32-bit
 *   process on a 64-bit Windows at all.  Make such a thread in an ordinary
 *   process -- no clone anywhere near it, every scrap of state known good --
 *   point it at a function whose first act is one system call, and the
 *   process dies of STATUS_ACCESS_VIOLATION at ntdll+0x98800, which is
 *   `jmp dword ptr [Wow64Transition]'.  Measured directly, because it is much
 *   easier to believe of a clone than of a process that was never cloned.
 *
 *   Why it dies there is worth writing down, because it is the reason this
 *   cannot be worked around.  Every 32-bit system call is `mov eax,<number>;
 *   mov edx,[Wow64Transition]; call edx', and what that reaches is seven
 *   bytes in wow64cpu.dll:
 *
 *       jmp  far 0x33:<next>          ; put the CPU in 64-bit mode
 *       jmp  qword ptr [r15+0xf8]     ; and dispatch through r15
 *
 *   The stub never loads r15.  It is a register the 64-bit dispatch loop
 *   leaves live when it hands control down to 32-bit code -- BTCpuSimulate
 *   sets r12 from gs:0x30, the 64-bit TEB, r13 from the thread's WOW64 CPU
 *   area at TEB+0x1488, and r15 to wow64cpu's dispatch table, and then runs
 *   the 32-bit code with those still in the registers.  A thread enters that
 *   loop as part of its startup, which is precisely what SKIP_LOADER_INIT
 *   skips.  So the first system call from such a thread makes the far jump
 *   with r15 holding whatever was there, and dereferences it.  The fault is
 *   reported against the last 32-bit instruction, which is why the event log
 *   points at ntdll rather than at wow64cpu.
 *
 *   There is nothing to poke: r15 is live register state, not memory.  And
 *   the whole problem is a 32-bit-on-64-bit one -- a native x86_64 program
 *   makes system calls with the syscall instruction and has no dispatch loop
 *   to be thrown out of, so this particular objection would not arise in an
 *   x86_64 port of this bootstrap.
 *
 *   Worth tracing further than "nothing to poke", because the actual
 *   question is whether that setup can be run again, later, from user mode
 *   -- and the answer is no, for a reason worth having by name rather than
 *   by symptom.  A new WOW64 thread's real first instruction is not 32-bit
 *   at all: the kernel (nt!PspAllocateThread / PspWow64InitThread) hands it
 *   a synthetic exception whose address is the 64-bit ntdll's own
 *   LdrInitializeThunk.  Disassembling that export in ntdll64.dll shows
 *   exactly the gate this predicts: a bit test against a flag word in the
 *   64-bit TEB (`test word [rax+0x17ee], 0x4000', rax from `mov rax,
 *   gs:0x30') that skips a call when already set and takes it on a fresh
 *   thread -- the call being the one-time WOW64 bring-up.  Public research on
 *   this exact sequence (wbenny, "WoW64 internals", 2018) names every step
 *   the disassembly only shows the shape of: LdrInitializeThunk ->
 *   LdrpInitialize -> LdrpLoadWow64, which loads wow64.dll and hands off to
 *   Wow64LdrpInitialize, which calls ProcessInit and ThreadInit (this is
 *   where r12 and r13 come from, via RtlWow64GetCpuAreaInfo) and then
 *   RunCpuSimulation, which calls wow64cpu!BTCpuSimulate, which sets r15 and
 *   enters RunSimulatedCode -- the loop that never returns and is what
 *   finally executes a 32-bit instruction for this thread, for the first
 *   time.  Every part of that chain runs in 64-bit mode, reached only by the
 *   kernel choosing LdrInitializeThunk as where a new thread starts.
 *   SKIP_LOADER_INIT is exactly the kernel choosing something else instead --
 *   the caller's 32-bit StartRoutine, directly -- which is why the fault
 *   above is a clean 32-bit instruction at a sensible ntdll address rather
 *   than garbage: the mode switch to CS=0x23 did happen, correctly, by
 *   whatever set up the thread's context in the first place.  What did not
 *   happen is everything upstream of it.  There is no way from the 32-bit
 *   side to reach that chain after the fact: the only sanctioned 32-to-64
 *   transition a WOW64 thread has is the one at the top of this note, and it
 *   needs r15 to work -- which is exactly what is missing.  Asking it to
 *   bootstrap itself is circular, not merely hard.
 *
 *   It is not a missing page: the Wow64Transition pointer holds the same
 *   value in the clone as here, the code it points at can be read in both,
 *   and NtQueryVirtualMemory gives both the same State, the same Protect --
 *   PAGE_EXECUTE_READ -- and the same Type.
 *
 *   So the child has to run loader init, and with the lock cleared it does
 *   run it, and dies inside it at `mov eax, fs:0x18'.  Attaching a debug port
 *   to the clone -- NtCreateDebugObject and NtDebugActiveProcess, so that it
 *   stops at the fault instead of dying of it -- says what that is, and it is
 *   the end of the road:
 *
 *       ExceptionCode     0xc0000005
 *       ExceptionAddress  ntdll+0x8c5d6      ; mov eax, fs:0x18
 *       access            0                  ; a read
 *       faulting address  0x18
 *       SegFs             0x53
 *       SegCs             0x23
 *       TebBaseAddress    0x21e000
 *
 *   It reads fs:0x18 and faults on linear address 0x18, so the base behind FS
 *   is zero.  Not the selector -- 0x53 is the right one -- and not the TEB,
 *   which exists and can be read from the parent.  The descriptor that
 *   selector names simply has no base.
 *
 *   Which looks like the same illness as the r15 one above.  A 32-bit process
 *   on a 64-bit Windows runs inside a WOW64 layer: the kernel programs the
 *   compatibility-mode TEB base for each thread, and the 64-bit dispatch loop
 *   keeps r12, r13 and r15 live for it.  Both are established when a process
 *   and its threads are made the ordinary way, and a clone is not made the
 *   ordinary way.
 *
 *   That is as far as the evidence goes, and it is worth being careful about
 *   how far that is.  What is measured is that this clone's child has an FS
 *   with no base.  What is NOT established is the tempting generalisation --
 *   that a cloned 32-bit process can never have WOW64 state -- because
 *   something in ntdll says otherwise, loudly.  RtlCreateProcessReflection,
 *   the one caller RtlCloneUserProcess has in the whole 32-bit ntdll, does
 *   this in its child on getting STATUS_PROCESS_CLONED back:
 *
 *       ba979:  mov eax, fs:0x30      ; reads FS straight away
 *       ba9c9:  call esi              ; then calls a caller's start routine
 *
 *   So Windows expects a clone's child to have a working FS and to run
 *   ordinary code.  Either reflection is broken here for every 32-bit process
 *   on the machine, or reflection does something this code does not and the
 *   direct use of RtlCloneUserProcess is what is wrong.  Trying to settle it
 *   did not settle it: called on a spawned copy of this program, both with a
 *   start routine and with none at all -- the plain passive snapshot that is
 *   what reflection is actually for -- RtlCreateProcessReflection does not
 *   return, and the calling process disappears without so much as a fault
 *   record.  That is not understood either, and a conclusion built on top of
 *   it would not be worth having.
 *
 *   So: the clone stops here, at an FS with no base, for a reason not yet
 *   pinned on either Windows or this code.  Whichever it is, nothing in
 *   reach fixes it from user mode -- a segment base lives in a descriptor the
 *   kernel owns, and the SegFs in a 32-bit CONTEXT is the selector, which is
 *   already right.
 *
 *   The r15 finding above does not depend on any of this.  That one was
 *   measured with no clone anywhere near it, and it stands on its own.
 *
 *   An earlier version of this note said it was "not WOW64's doing", on the
 *   strength of the same call failing from 64-bit PowerShell too.  That was
 *   the wrong conclusion from a true observation: the PowerShell child was
 *   stopped by the inherited lock, which is a different failure and one that
 *   has since been fixed here.  Being 32-bit on a 64-bit Windows is at least
 *   what the r15 objection is.  A native x86_64 program has no WOW64
 *   layer -- it makes system calls with the syscall instruction and reaches
 *   its TEB through GS, whose base the kernel programs for every thread it
 *   creates -- so the question is worth asking again, from scratch, in an
 *   x86_64 port of this bootstrap, and only there.
 *
 *   Worth knowing for whoever picks this up: the supported consumer of
 *   RtlCloneUserProcess is process reflection, whose child is a passive
 *   snapshot that is read and discarded rather than run.  Nothing measured
 *   here contradicts the possibility that a clone cannot be made to run
 *   ordinary code at all.
 *
 *   One thing does not depend on any of the above and was worth checking on
 *   its own: whether this machine can clone a 32-bit process by ANY in-box
 *   route, which would rule the whole failure in or out as a platform limit
 *   rather than a misuse of one specific call.  PssCaptureSnapshot, the
 *   documented Windows 8.1+ snapshotting API, answers yes -- called against a
 *   real 32-bit process with PSS_CAPTURE_VA_CLONE it returns ERROR_SUCCESS,
 *   and PssQuerySnapshot(PSS_QUERY_VA_CLONE_INFORMATION) hands back a clone
 *   that GetExitCodeProcess reports STILL_ACTIVE and IsWow64Process reports
 *   genuinely 32-bit.  So this machine, this hypervisor, this WOW64 -- none of
 *   them are categorically incapable of a working 32-bit clone.
 *
 *   That does not settle the question above, though, and it would be the same
 *   mistake again to claim it did.  PssCaptureSnapshot is not
 *   RtlCloneUserProcess by another name: it calls PssNtCaptureSnapshot, which
 *   goes through NtCreateProcessEx -- the very call ReactOS's PspCreateProcess
 *   was seen declining to implement, and, per the correction above, a
 *   different syscall from the one RtlCloneUserProcess actually uses.  What is
 *   confirmed is narrower than "cloning works here": the NtCreateProcessEx
 *   clone path works here, completely, for a 32-bit target, with whatever
 *   WOW64 setup that path does that RtlCloneUserProcess's does not.  Whether
 *   RtlCloneUserProcess's own path -- through ZwCreateUserProcess -- shares
 *   that defect, has a different one, or has none at all under different
 *   handling is exactly as open as it was.  What this does rule out is the
 *   broadest excuse available: "this VM just can't do it."  Something here
 *   can.  Whether the thing __clone_process calls is that something remains
 *   unknown.
 *
 *   One question about RtlCloneUserProcess's own clone can be answered
 *   without running anything on the side that is broken: is the FS-with-no-
 *   base defect a property of the one thread the clone hands back, or of the
 *   clone process itself?  Clone with CREATE_SUSPENDED and never resume that
 *   thread -- so neither the lock deadlock nor the FS fault above can happen
 *   -- and ask NtQueryInformationProcess(ProcessWow64Information, class 26)
 *   about the child's process handle.  It answers with a real PEB32 address,
 *   not zero and not a failing status.  So the clone's process-level WOW64
 *   association came through intact; what is missing is scoped to the one
 *   thread, not the process.  That keeps open a narrower question than the
 *   one above: whether a thread made the ordinary way afterwards -- fresh,
 *   with NtCreateThreadEx, never touching the cloned thread at all -- would
 *   get the segment setup that thread did not.
 *
 *   Tried, and inconclusive rather than answered.  RtlExitUserThread needs no
 *   hand-written assembly to satisfy "never returns through an ordinary call
 *   frame": it is documented DECLSPEC_NORETURN, and handed to
 *   NtCreateThreadEx directly as StartRoutine with a distinctive NTSTATUS as
 *   Argument, it ends the (single) thread -- and so the process -- with that
 *   value if it ever gets there.  Against the clone: STATUS_ACCESS_DENIED,
 *   even from a handle freshly opened with NtOpenProcess asking for
 *   PROCESS_ALL_ACCESS -- which is not a DACL problem, since NtOpenProcess
 *   granting that access is itself proof the security check already passed,
 *   and NtCreateThreadEx failed anyway with the same already-granted handle.
 *   So this was not going to settle the clone question either way, which
 *   running the identical sequence against an ordinary __spawn child instead
 *   of a clone confirmed: STATUS_ACCESS_DENIED there too.  The conclusion
 *   drawn from that -- that cross-process thread creation is refused here as
 *   a matter of the caller's privileges, SeDebugPrivilege not being enabled
 *   -- is wrong, and wrong in both halves.
 *
 *   SeDebugPrivilege does not need advapi32 to reach.  RtlAdjustPrivilege is
 *   an ntdll export, and it takes the privilege as a plain ULONG LUID rather
 *   than the LUID_AND_ATTRIBUTES that LookupPrivilegeValue exists to fill in,
 *   so the objection about it being out of reach of an ntdll-only port was
 *   simply mistaken.  The number is 20, which is what phnt's ntseapi.h calls
 *   SE_DEBUG_PRIVILEGE -- and rather than take that on faith,
 *   LookupPrivilegeValue("SeDebugPrivilege") was asked on this machine and
 *   answers 20 as well.
 *
 *   And the privilege was never missing.  RtlAdjustPrivilege(20, TRUE, FALSE,
 *   &was) from inside the probe returns STATUS_SUCCESS with WasEnabled
 *   already 1: this token has had SeDebugPrivilege enabled the whole time,
 *   which whoami /priv agrees with.  So the denial had some other cause, and
 *   the likeliest is a handle asked for too little rather than a caller
 *   granted too little.  A missing access right is indistinguishable from a
 *   missing privilege from the outside -- both are STATUS_ACCESS_DENIED --
 *   and this port walked into that again while writing the probes below:
 *   NtGetContextThread on a thread handle created without
 *   THREAD_GET_CONTEXT answers STATUS_ACCESS_DENIED and nothing else.
 *
 *   Written again and measured, cross-process thread creation is not refused
 *   here at all.  NtCreateThreadEx into an ordinary __spawn child, with a
 *   DesiredAccess made of bits that are written down -- SYNCHRONIZE,
 *   THREAD_TERMINATE, THREAD_SUSPEND_RESUME, THREAD_QUERY_INFORMATION -- and
 *   RtlExitUserProcess as StartRoutine with 0x5a5a as its Argument, returns
 *   STATUS_SUCCESS, and the child exits with 0x5a5a.  A fresh thread in
 *   another process runs, and runs ordinary code that reaches the system.
 *   THREAD_ALL_ACCESS is deliberately not used for this: its value is not
 *   written down anywhere authoritative, and those four bits are.
 *
 *   The same injection with CreateFlags = THREAD_CREATE_FLAGS_SKIP_LOADER_INIT
 *   also returns STATUS_SUCCESS, and the child then dies of
 *   STATUS_ACCESS_VIOLATION -- the r15 finding above, reproduced across a
 *   process boundary rather than within one.
 *
 *   Which finally makes the fresh-thread question above answerable, and the
 *   answer is no.  Clone with CREATE_SUSPENDED, never resume the clone's own
 *   thread at all, and inject the same RtlExitUserProcess thread into the
 *   clone: NtCreateThreadEx returns STATUS_SUCCESS.  Two seconds later the
 *   clone has not exited -- NtWaitForSingleObject times out, ExitStatus is
 *   still STATUS_PENDING -- and NtGetContextThread on the thread just made
 *   reports Eip RtlUserThreadStart, Cs 0x23, SegFs 0x53 and Esp 0x8a7fff0,
 *   which is the very top of its own fresh stack.  That is its initial
 *   context, unchanged: the thread has not executed one 32-bit instruction.
 *
 *   Zeroing the inherited loader lock first makes no difference to that,
 *   which places whatever holds it up upstream of any 32-bit code at all --
 *   in the native bring-up, or in the kernel, not in the 32-bit loader.  And
 *   the control says the call itself is sound: the identical injection into
 *   an ordinary __spawn child runs and exits with the value it was handed.
 *
 *   So a thread made the ordinary way in a clone does not get the segment
 *   setup the cloned thread lacked, because it does not get as far as needing
 *   it.  Not refused, not faulting, not deadlocked in the 32-bit loader: it
 *   never starts.  The clone has a PEB32 and a process-level WOW64
 *   association, and still no thread of any provenance runs 32-bit code in
 *   it.  Where in the 64-bit bring-up that stops is the next thing anyone
 *   picking this up would have to find, and it cannot be found from the
 *   32-bit side, which is the same wall the r15 finding ends at.
 *
 *   Which was written as an open question, and is now answered -- in the
 *   negative, and not for want of asking properly.  No flag makes an
 *   NtCreateProcessEx clone take a thread.  Against a real 32-bit target,
 *   every PROCESS_CREATE_FLAGS_ value that could mean anything to a clone was
 *   tried -- NONE, INHERIT_HANDLES (4), INHERIT_FROM_PARENT (0x100), both
 *   together, and CREATE_SUSPENDED (0x200), the numbers being phnt's -- and
 *   all five clone successfully, each answering
 *   NtQueryInformationProcess(ProcessBasicInformation) with ExitStatus
 *   STILL_ACTIVE, so each is a live process by every measure available from
 *   outside it.  CLONE_MINIMAL (0x2000) is refused outright,
 *   STATUS_INVALID_PARAMETER, so it is not a clone flag for this at all.
 *   Into every one of the five, NtCreateThreadEx answers
 *   STATUS_PROCESS_IS_TERMINATING -- with CreateFlags 0 and with
 *   CREATE_SUSPENDED alike, from a 32-bit caller and from a 64-bit one, the
 *   same 0xc000010a in all ten attempts.
 *
 *   Published research says why, and says it is deliberate: the kernel marks
 *   a threadless clone as awaiting deletion, so thread creation is refused
 *   the way it would be refused for a process already on its way out -- and
 *   has been since Windows 8.1, before which such clones could be given
 *   threads.  (Hunt & Hackett, "The Definitive Guide To Process Cloning on
 *   Windows".)  So this is not a gap in what this port knows about the call.
 *   It is the call not being for this.
 *
 *   Which closes the loose end left above, and closes it the other way from
 *   the way it was hoped.  The clone this machine demonstrably CAN make is
 *   the same clone that cannot run.  PssCaptureSnapshot with
 *   PSS_CAPTURE_VA_CLONE against that same 32-bit target returns
 *   ERROR_SUCCESS; PssQuerySnapshot(PSS_QUERY_VA_CLONE_INFORMATION) hands
 *   back a live clone handle whose ExitStatus is STILL_ACTIVE too; and
 *   NtCreateThreadEx into it answers STATUS_PROCESS_IS_TERMINATING, the
 *   identical 0xc000010a, for CreateFlags 0 and for CREATE_SUSPENDED.
 *
 *   So "something here can clone; whether the thing __clone_process calls is
 *   that something remains unknown" was the right caution attached to the
 *   wrong hope.  The documented API is a wrapper over the very call already
 *   known to make unrunnable clones, and being documented does not make its
 *   clone runnable.  Nothing in the box runs code in a VA clone, and the
 *   reason is not that no one wrote the code to: the kernel will not have it.
 *
 *   That is both roads shut for NtCreateProcessEx.  The other road --
 *   RtlCloneUserProcess, through ZwCreateUserProcess -- turns out not to be
 *   shut at all.  It is shut under WOW64, and only there.
 *
 *   The same script, run twice within a minute on this machine, differing in
 *   nothing but which PowerShell ran it, cloning itself with
 *   CREATE_SUSPENDED|NO_SYNCHRONIZE so that the inherited lock cannot be the
 *   story, reading the new thread's context before it runs and its exit
 *   status after:
 *
 *     32-bit caller   Eip ZwCreateUserProcess+0xc, Cs 0x23, Fs 0x53;
 *                     resumed, the clone dies, exit status 0xc0000409
 *     64-bit caller   Rip ZwCreateUserProcess+0x14, Cs 0x33;
 *                     resumed, the clone RUNS
 *
 *   Runs, and not a little.  The 64-bit clone comes back from the call,
 *   compares the returned status against STATUS_PROCESS_CLONED, takes that
 *   branch, calls out through kernel32 into the kernel, finds that call
 *   failed, and exits with the value its own code picks for a failed call
 *   rather than the one it picks for a successful one.  Choosing correctly
 *   between two exit codes is the proof: that is a comparison, a call, a
 *   system call and a return, all after the clone.
 *
 *   Both entry points are the return from the same system call -- number
 *   0xcf either way.  ZwCreateUserProcess+0xc is the `ret 0x2c' after
 *   `call edx' in the 32-bit stub; ZwCreateUserProcess+0x14 is the `ret'
 *   after `syscall' in the 64-bit one.  Same call, same kernel, same minute;
 *   one clone runs and the other cannot.
 *
 *   Which finally puts a name on the fs:0x18 fault, and it is not this
 *   port's name and not this machine's.  A 64-bit thread reaches its TEB
 *   through GS, whose base is a model-specific register the kernel reloads
 *   on every switch to the thread, out of the thread object itself -- there
 *   is nothing per-process to arrange and so nothing for a clone to lose.  A
 *   32-bit thread on the same machine reaches its TEB through FS, whose base
 *   lives in a descriptor the kernel programs from that thread's 32-bit TEB,
 *   and that is the piece a cloned thread does not get.  The defect is in
 *   the WOW64 half of process cloning.  The earlier suggestion that an
 *   x86_64 port should ask this question again now rests on a measurement
 *   instead of on hope.
 *
 *   So, for a 32-bit program on a 64-bit Windows, a copy-on-write fork is
 *   out of reach from user mode, by both roads and for two unrelated
 *   reasons: the NtCreateProcessEx clone is refused a thread as a matter of
 *   kernel policy, and the ZwCreateUserProcess clone is given a thread with
 *   no FS base.  Neither is something a caller can hold differently.  The
 *   fork below copies, and will go on copying.
 *
 *   That stood as the conclusion, and it was wrong about the second reason,
 *   not the first: NtCreateProcessEx is still refused a thread, no way
 *   around it, but "no FS base" turned out to be a symptom a user-mode
 *   caller can reach past, not a wall. wow64cpu!RunSimulatedCode -- the loop
 *   that runs 32-bit code at all -- does not take r13/r15 as arguments, it
 *   loads them itself from the thread's own TEB and CPU area on every entry,
 *   which means a cloned thread's initial context can be pointed at
 *   RunSimulatedCode's own exported entry (BTCpuSimulate) directly, from
 *   user mode, with nothing but NtSetContextThread called natively (a
 *   heaven's-gate call, since the ordinary WOW64-thunked one only reaches
 *   the 32-bit CPU-area CONTEXT) and the ordinary NtSetContextThread this
 *   file already uses elsewhere. That alone still deadlocked -- a different,
 *   unrelated lock inside RtlCloneUserProcess itself, held by the parent
 *   across the clone syscall and never released on the child's side -- and
 *   clearing that one is the rest of the fix. __clone_process_wow64fix
 *   below is all of it, measured running to a real STATUS_PROCESS_CLONED
 *   return in the child, not just free of the fault above; fork lower in
 *   this file now prefers it, WOW64 or not, and falls back to copying only
 *   when the clone path itself cannot be made to work. x86/Development/
 *   wow64-clone-driver.md has the disassembly and every measurement in full.
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

/* __wow64fix_fail_at: which of __clone_process_wow64fix's own -1 returns ran,
 * set right before each one and otherwise left alone (never reset to 0 on
 * success -- a caller that cares reads it only after seeing -1). This is not
 * part of fork()'s contract and never will be: every one of those -1 returns
 * still reaches fork() as a plain -1, so "if(-1 != wow64fix_rc) return
 * wow64fix_rc;" and every ordinary caller of fork() keeps seeing exactly
 * what POSIX promises, nothing more. It exists because this whole function
 * is a measured-on-one-VM, one-Windows-build fix layered over undocumented
 * WOW64 internals (see wow64-clone-driver.md sec 8-9) -- exactly the kind of
 * thing this file already keeps hard-won detail about in comments rather
 * than discarding once it works, and a future build, a future VM, or this
 * same VM after an update is the likeliest place this ever fails again. When
 * that happens the fault is one of thirteen fixed points, not a stack trace,
 * so the number this records is the whole diagnosis:
 *
 *   1  NT_CLONE (RtlCloneUserProcess) did not resolve at all
 *   2  __wow64_selfpeb could not read this process's own 64-bit PEB
 *   3  the 64-bit ntdll.dll was not found in the 64-bit module list (wow64cpu.dll
 *      absent takes the plain-__clone_process fallback instead, not this path)
 *   4  NtGetContextThread did not resolve in the 64-bit ntdll
 *   5  NtSetContextThread did not resolve in the 64-bit ntdll
 *   6  BTCpuSimulate did not resolve in wow64cpu.dll
 *   7  the heaven's-gate trampoline (__gate_init) could not be built
 *   8  RtlCloneUserProcess itself failed (rc not 0 and not STATUS_PROCESS_CLONED)
 *   9  Step A: native NtGetContextThread on the clone's initial thread failed
 *   10 Step B: native NtSetContextThread (Rip -> BTCpuSimulate) failed
 *   11 Step C: the thunked NtGetContextThread on the 32-bit CPU-area CONTEXT failed
 *   12 Step C: the thunked NtSetContextThread (Eax -> STATUS_PROCESS_CLONED) failed
 *   13 Step C.5: NtWriteVirtualMemory zeroing RtlCloneUserProcess's internal
 *      lock in the child failed
 *
 * (there is no failure tag between RtlCloneUserProcess's own 0x129-without-a-
 * fix check and Step A: that check returns 0, not -1, and is not a failure.)
 */
int __wow64fix_fail_at;

/* __wow64fix_dup_status / __wow64fix_qinfo_status: the raw NTSTATUS from,
 * respectively, the NtDuplicateObject call inside __wow64_selfhandle and the
 * NtWow64QueryInformationProcess64 call inside __wow64_selfpeb -- the two
 * calls tag 2 above can only say "one of these failed" about, not which, nor
 * with what status. Same philosophy as __wow64fix_fail_at and kept for the
 * same reason: written on every call, success or failure (0 means
 * STATUS_SUCCESS ran there, not "never called"), so a future tag-2 failure is
 * diagnosable by reading two more numbers instead of reproducing this
 * investigation. Neither is part of fork()'s contract for the same reason
 * __wow64fix_fail_at is not. */
int __wow64fix_dup_status;
int __wow64fix_qinfo_status;

/* __clone_process_wow64fix: the same RtlCloneUserProcess as __clone_process
 * above, with the fix x86/Development/wow64-clone-driver.md sec 8-9 measured
 * applied before the child is ever let run.
 *
 * __clone_process's own note works out where the unfixed clone dies: FS has
 * no base (fs:0x18 faults reading a TEB that is not there), because a clone's
 * initial thread resumes directly in 32-bit mode instead of going through the
 * 64-bit bring-up (LdrInitializeThunk -> ... -> wow64cpu!RunSimulatedCode)
 * that programs the FS base and leaves r13/r15 live for the first 32-bit
 * syscall. wow64-clone-driver.md sec 8 disassembles RunSimulatedCode and
 * finds that r12/r13/r15 are not inputs to it -- they are loaded from the
 * 64-bit TEB (gs:0x30) and the thread's CPU area (TEB+0x1488) on entry -- so a
 * thread does not need those registers set by hand, it only needs its native
 * RIP pointed at RunSimulatedCode's entry, wow64cpu!BTCpuSimulate (exported,
 * so nameable; RunSimulatedCode is not). Sec 9 built exactly that redirect as
 * a real 32-bit .exe on this project's win11 VM and it worked as far as user
 * mode can be asked to prove: the clone's FS became 0x53-based-on-a-real-TEB
 * (the fault this note's own child never got past), no exception of any kind
 * was seen, and the thread settled at a 32-bit ntdll syscall stub rather than
 * dying. What it had not done, as of that measurement, is come back and run
 * ordinary code -- see the note at the end of this function for exactly how
 * far short, and why this is kept and not wired into fork() yet.
 *
 * The redirect needs three things __clone_process does not:
 *
 *   a native (64-bit) CONTEXT on the clone's own initial thread, which this
 *     32-bit process cannot get with its own ordinary NtGetContextThread/
 *     NtSetContextThread -- those are thunked by wow64 down to the 32-bit
 *     CPU-area CONTEXT, which is exactly what step C below still wants. The
 *     native ones have to be called as 64-bit code, so a small heaven's-gate
 *     trampoline (32->64->32, __gate_init/__gate_call below) makes the call
 *     directly, bypassing the 32-bit wow64 thunk entirely.
 *
 *   the native VAs of NtGetContextThread, NtSetContextThread and
 *     BTCpuSimulate -- all in the 64-bit ntdll.dll and wow64cpu.dll images
 *     that share this process's address space above 4GB, which a 32-bit
 *     pointer cannot name. Two ntdll32 exports resolve them: one for this
 *     process's own 64-bit PEB, NtWow64QueryInformationProcess64, and one
 *     for everything after that -- Ldr, the module list, each image's own
 *     PE32+ export directory -- NtWow64ReadVirtualMemory64. Slots
 *     NT_WOW64QINFO and NT_WOW64READVM resolve them. Every address involved
 *     from here down is
 *     genuinely 64 bits -- ntdll64 is ASLR'd independently and measured as
 *     high as 0x00007ffb55110000 -- and this dialect has no 64-bit int, so
 *     each one is carried as two ints (*_lo, *_hi) and added to with __qadd64,
 *     which does the carry by hand rather than assume it away.
 *
 *   the redirect itself: a native NtSetContextThread call through the gate,
 *     asking for Rip = BTCpuSimulate, Rsp = the thread's own already-native
 *     Rsp, and SegCs = 0x33 -- then the ordinary (wow64-thunked)
 *     NtSetContextThread already used everywhere else in this file, asked
 *     for CONTEXT_INTEGER, with Eax
 *     written to STATUS_PROCESS_CLONED -- which, per sec 8.2's disassembly of
 *     wow64cpu!BTCpuSetContext, also forces the CPU area's status word bit 0,
 *     the flag that makes the next RunSimulatedCode entry reprogram FS rather
 *     than skip straight to 32-bit code with whatever was already there. */

/* One 8-byte quantity, as (lo, hi). Adding a small positive RVA to a 64-bit
 * base can carry into the high word even though every base and RVA here is
 * itself a small positive number, so the carry is worked out from the bit
 * pattern rather than assumed away: newlo = lo + delta wraps in two's
 * complement exactly the way an unsigned add would, and XORing both sides
 * with the sign bit before comparing turns that wrapped unsigned comparison
 * into one this dialect's signed `<` gets right, because XORing the sign bit
 * is a monotonic reordering from unsigned into signed. hi_out is a one-word
 * scratch buffer the caller owns, matching how the rest of this file returns
 * a second value: written, not returned. */
int __qadd64(int lo, int hi, int delta, int* hi_out)
{
	int newlo;
	int carry;

	newlo = lo + delta;
	carry = 0;
	if((newlo ^ -2147483648) < (lo ^ -2147483648)) carry = 1;
	hi_out[0] = hi + carry;
	return newlo;
}

/* __wow64_align16: round a heap pointer up to the next 16-byte boundary.
 *
 * calloc's own bump allocator (M2libc's stdlib.c, via _malloc_brk) makes no
 * alignment promise at all beyond whatever __heap_start happens to be --
 * measured directly on this VM (Development/align-probe.c, not kept), three
 * successive callocs of 4, 4 and 48 bytes came back 6 mod 8, not even
 * 4-byte-aligned, every time. Every buffer this file hands to a WOW64
 * 64-bit call -- NtWow64QueryInformationProcess64's PROCESS_BASIC_
 * INFORMATION64, NtWow64ReadVirtualMemory64's PULONG64 byte count, and the
 * CONTEXT_AMD64 buffers the heaven's-gate calls in __clone_process_wow64fix
 * use -- holds 64-bit fields the kernel probes for natural alignment,
 * answering STATUS_DATATYPE_MISALIGNMENT (0x80000002) rather than fixing it
 * up: __wow64fix_qinfo_status read exactly that value, measured against
 * __wow64_selfpeb's unaligned `info` buffer, which is what sent
 * __wow64fix_fail_at to 2 every time this was run before this function
 * existed. 16 rather than 8 matches fork()'s own already-working
 * CONTEXT_AMD64 rounding elsewhere in this file (ctx_raw, below). Every
 * caller must over-allocate 15 extra bytes so the rounded-up address still
 * has room for what it asked for. */
int __wow64_align16(int raw)
{
	raw = raw + 15;
	return raw - (raw % 16);
}

/* A real (non-pseudo) handle to this process, cached in a global because
 * every 64-bit read this file makes wants one. NtWow64ReadVirtualMemory64
 * and NtWow64QueryInformationProcess64 both answer STATUS_INVALID_HANDLE
 * (0xc0000008) to -1, the NtCurrentProcess pseudo-handle every other Nt* call
 * in this file accepts without complaint -- measured directly, with a gcc
 * stand-in harness (/tmp/claude/wow64demo/m2check.c) that first came back
 * with an all-zero PEB and no visible error, then, once __wow64_rd64 was
 * made to report its own NTSTATUS, showed 0xc0000008 on every call until the
 * pseudo-handle was swapped for a real one. NtDuplicateObject already does
 * exactly this trick elsewhere in this file (__inheritable, above): given
 * -1 as both the source and target process, and -1 as the source handle, it
 * hands back a genuine handle value that means the same process. */
int __wow64_self_handle_cache;
int __wow64_self_handle_have;
int __wow64_selfhandle()
{
	int (*NtDuplicateObject)(int, int, int, int, int, int, int);
	int* out;

	if(0 != __wow64_self_handle_have) return __wow64_self_handle_cache;

	out = calloc(1, 4);
	NtDuplicateObject = __ntdll(NT_DUP);
	/* forwards: NtDuplicateObject(-1, -1, -1, out, 0, 0,
	 *                             DUPLICATE_SAME_ACCESS) */
	__wow64fix_dup_status = NtDuplicateObject(2, 0, 0, out, -1, -1, -1);
	if(0 != __wow64fix_dup_status) return -1;
	__wow64_self_handle_cache = out[0];
	__wow64_self_handle_have = 1;
	return out[0];
}

/* Read len bytes (at most 8, everything this file asks for) from the 64-bit
 * address (lo, hi) of this same process's own 64-bit view, into buf, which
 * the caller owns and which need only be as big as len. Returns the NTSTATUS
 * from NtWow64ReadVirtualMemory64; a failure leaves buf whatever it was. */
int __wow64_rd64(int lo, int hi, int* buf, int len)
{
	int (*NtWow64ReadVirtualMemory64)(int, int, int, int, int, int, int);
	int* got;
	char* scratch;
	char* dst;
	int rc;
	int self;
	int i;

	self = __wow64_selfhandle();
	got = calloc(8 + 16, 1);
	got = __wow64_align16(got);
	/* NumberOfBytesRead is PULONG64 in the real signature, not plain ULONG,
	 * so it gets the same treatment as the Buffer below rather than being
	 * left as the caller-owned buf-sized pointer __inheritable-style calls
	 * would use. */
	scratch = calloc(len + 16, 1);
	scratch = __wow64_align16(scratch);
	NtWow64ReadVirtualMemory64 = __ntdll(NT_WOW64READVM);
	/* forwards: NtWow64ReadVirtualMemory64(self, lo, hi, scratch, len, 0, got) --
	 * everything read here is this process's own 64-bit view of itself, but
	 * by the real handle above, not the -1 pseudo-handle. scratch, 16-aligned,
	 * rather than buf directly: buf is a caller-owned heap pointer with no
	 * alignment guarantee (see __wow64_align16), and this is the same call
	 * family as __wow64_selfpeb's, measured returning
	 * STATUS_DATATYPE_MISALIGNMENT against an unaligned buffer. */
	rc = NtWow64ReadVirtualMemory64(got, 0, len, scratch, hi, lo, self);
	if(0 == rc)
	{
		dst = buf;
		i = 0;
		while(i < len)
		{
			dst[i] = scratch[i];
			i = i + 1;
		}
	}
	return rc;
}

int __wow64_rd64_dword(int lo, int hi)
{
	int* v;

	v = calloc(1, 4);
	__wow64_rd64(lo, hi, v, 4);
	return v[0];
}

int __wow64_rd64_word(int lo, int hi)
{
	int* v;

	v = calloc(1, 4);
	__wow64_rd64(lo, hi, v, 2);
	return 65535 & v[0];
}

/* Walk this process's own 64-bit PEB -> Ldr -> InLoadOrderModuleList looking
 * for a module named (in ASCII) `want`, matched against the wide
 * BaseDllName one UTF-16 code unit at a time so that no wide string literal
 * -- which would need embedded NUL bytes a C string literal cannot hold -- is
 * needed on either side. Returns the module's base (lo), writes the high
 * word to base_hi_out, or returns 0 (writing 0) if the list runs out first.
 * LDR_DATA_TABLE_ENTRY64 offsets (InLoadOrderLinks +0x00, DllBase +0x30,
 * BaseDllName.Length +0x58, BaseDllName.Buffer +0x60) and PEB64.Ldr (+0x18)
 * are the standard ones photographed in wow64-clone-driver.md sec 9.2. */
int __wow64_find_module(int peb_lo, int peb_hi, char* want, int* base_hi_out)
{
	int pebldr_lo; int pebldr_hi;
	int ldr_lo; int ldr_hi;
	int head_lo; int head_hi;
	int cur_lo; int cur_hi;
	int next_lo; int next_hi;
	int base_lo; int base_hi;
	int name_len;
	int name_lo; int name_hi;
	int guard;
	int i;
	int wc;
	int match;

	/* PEB64.Ldr is a pointer at +0x18; +0x18 never carries out of the low
	 * word (a PEB address is never within 24 bytes of the top of the
	 * address space), so the hi word of that intermediate address is the
	 * PEB's own hi word, unchanged. */
	pebldr_lo = __qadd64(peb_lo, peb_hi, 0x18, calloc(1,4));
	pebldr_hi = peb_hi;
	ldr_lo = __wow64_rd64_dword(pebldr_lo, pebldr_hi);
	ldr_hi = __wow64_rd64_dword(__qadd64(pebldr_lo, pebldr_hi, 4, calloc(1,4)), pebldr_hi);
	head_lo = __qadd64(ldr_lo, ldr_hi, 16, calloc(1,4));
	head_hi = ldr_hi;         /* +0x10 never carries out of the low word either */
	cur_lo = __wow64_rd64_dword(head_lo, head_hi);
	cur_hi = __wow64_rd64_dword(__qadd64(head_lo, head_hi, 4, calloc(1,4)), head_hi);

	guard = 0;
	while(guard < 512)
	{
		if(cur_lo == head_lo)
		{
			if(cur_hi == head_hi) break;
		}
		if((0 == cur_lo) && (0 == cur_hi)) break;

		base_lo = __wow64_rd64_dword(__qadd64(cur_lo, cur_hi, 0x30, calloc(1,4)), cur_hi);
		base_hi = __wow64_rd64_dword(__qadd64(cur_lo, cur_hi, 0x34, calloc(1,4)), cur_hi);
		name_len = __wow64_rd64_word(__qadd64(cur_lo, cur_hi, 0x58, calloc(1,4)), cur_hi);
		name_lo = __wow64_rd64_dword(__qadd64(cur_lo, cur_hi, 0x60, calloc(1,4)), cur_hi);
		name_hi = __wow64_rd64_dword(__qadd64(cur_lo, cur_hi, 0x64, calloc(1,4)), cur_hi);

		match = 1;
		i = 0;
		while(0 != want[i])
		{
			if((2 * i) >= name_len) { match = 0; break; }
			wc = __wow64_rd64_word(__qadd64(name_lo, name_hi, 2 * i, calloc(1,4)), name_hi);
			if(wc != want[i]) { match = 0; break; }
			i = i + 1;
		}
		if(match)
		{
			if(name_len == (2 * i))
			{
				base_hi_out[0] = base_hi;
				return base_lo;
			}
		}

		/* InLoadOrderLinks.Flink, the first 8 bytes of the current node,
		 * both halves read at the CURRENT node's address before either half
		 * of cur_lo/cur_hi is overwritten -- reusing the just-updated low
		 * word to address the high word would read the wrong place. */
		next_lo = __wow64_rd64_dword(cur_lo, cur_hi);
		next_hi = __wow64_rd64_dword(__qadd64(cur_lo, cur_hi, 4, calloc(1,4)), cur_hi);
		cur_lo = next_lo;
		cur_hi = next_hi;
		guard = guard + 1;
	}
	base_hi_out[0] = 0;
	return 0;
}

/* Resolve one export by name out of a PE32+ image at (base_lo, base_hi) in
 * this process's own 64-bit view, over the same NtWow64ReadVirtualMemory64
 * this file already uses for the module walk. IMAGE_NT_HEADERS64's export
 * data directory is at +0x88 (the PE32+ optional header, wider than the
 * PE32 one this file's own image uses), and the export directory's four
 * arrays (NumberOfNames +24, AddressOfFunctions +28, AddressOfNames +32,
 * AddressOfNameOrdinals +36) are the ordinary 32-bit-RVA ones documented for
 * every PE image regardless of bitness -- RVAs stay 32 bits even inside a
 * 64-bit image, so this part needs no carry logic beyond __qadd64 already
 * doing it. */
int __wow64_resolve_export(int base_lo, int base_hi, char* name, int* va_hi_out)
{
	int e_lfanew;
	int nt_lo; int nt_hi;
	int export_rva;
	int num_names;
	int addr_funcs; int addr_names; int addr_ords;
	int i;
	int name_rva;
	int match;
	int j;
	int ch;
	int ord;
	int func_rva;

	e_lfanew = __wow64_rd64_dword(__qadd64(base_lo, base_hi, 0x3C, calloc(1,4)), base_hi);
	nt_lo = __qadd64(base_lo, base_hi, e_lfanew, calloc(1,4));
	nt_hi = base_hi;
	export_rva = __wow64_rd64_dword(__qadd64(nt_lo, nt_hi, 0x88, calloc(1,4)), nt_hi);
	num_names  = __wow64_rd64_dword(__qadd64(base_lo, base_hi, export_rva + 24, calloc(1,4)), base_hi);
	addr_funcs = __wow64_rd64_dword(__qadd64(base_lo, base_hi, export_rva + 28, calloc(1,4)), base_hi);
	addr_names = __wow64_rd64_dword(__qadd64(base_lo, base_hi, export_rva + 32, calloc(1,4)), base_hi);
	addr_ords  = __wow64_rd64_dword(__qadd64(base_lo, base_hi, export_rva + 36, calloc(1,4)), base_hi);

	i = 0;
	while(i < num_names)
	{
		name_rva = __wow64_rd64_dword(__qadd64(base_lo, base_hi, addr_names + (4 * i), calloc(1,4)), base_hi);
		match = 1;
		j = 0;
		while(0 != name[j])
		{
			ch = __wow64_rd64_word(__qadd64(base_lo, base_hi, name_rva + j, calloc(1,4)), base_hi);
			if((255 & ch) != name[j]) { match = 0; break; }
			j = j + 1;
		}
		if(match)
		{
			ch = __wow64_rd64_word(__qadd64(base_lo, base_hi, name_rva + j, calloc(1,4)), base_hi);
			if(0 == (255 & ch))
			{
				ord = __wow64_rd64_word(__qadd64(base_lo, base_hi, addr_ords + (2 * i), calloc(1,4)), base_hi);
				func_rva = __wow64_rd64_dword(__qadd64(base_lo, base_hi, addr_funcs + (4 * ord), calloc(1,4)), base_hi);
				va_hi_out[0] = base_hi;
				return __qadd64(base_lo, base_hi, func_rva, va_hi_out);
			}
		}
		i = i + 1;
	}
	va_hi_out[0] = 0;
	return 0;
}

/* The heaven's-gate trampoline itself: a fixed 64-bit payload
 * (x86_64-linux-gnu-as + objcopy -O binary of x86/Development's gate.S,
 * bytes identical to /tmp/claude/wow64demo/gate.bin, validated on the win11
 * VM per wow64-clone-driver.md sec 9.1) sitting in a page this process
 * allocates PAGE_EXECUTE_READWRITE. Layout (byte offsets, matching gate.S's
 * layout.inc, unchanged by the port from C to this dialect since it is
 * machine code either way): 0x000 a 32-bit entry stub; 0x040 a data area of
 * six 8-byte slots (Target, Arg1..Arg4, Result -- Arg5 unused here); 0x0C0 the
 * 64-bit payload; 0x120 a 32-bit return stub. calloc already zeroes the page,
 * so only the 89 non-zero bytes out of 289 are written here. */
int __gate_init()
{
	int (*NtAllocateVirtualMemory)(int, int, int, int, int, int);
	char* g;
	int* base;
	int* size;
	int rc;

	base = calloc(1, 4);
	size = calloc(1, 4);
	size[0] = 0x1000;
	NtAllocateVirtualMemory = __ntdll(NT_ALLOC);
	/* forwards: NtAllocateVirtualMemory(-1, base, 0, size, MEM_COMMIT|
	 *   MEM_RESERVE, PAGE_EXECUTE_READWRITE) -- -1 is NtCurrentProcess: the
	 *   gate lives in this same process, not the clone's. */
	rc = NtAllocateVirtualMemory(0x40, 0x3000, size, 0, base, -1);
	if(0 != rc) return 0;

	g = base[0];
	g[0x0] = 106; g[0x1] = 51; g[0x2] = 80; g[0x3] = 232;
	g[0x8] = 88; g[0x9] = 5; g[0xa] = 184; g[0xe] = 135;
	g[0xf] = 4; g[0x10] = 36; g[0x11] = 255; g[0x12] = 44;
	g[0x13] = 36; g[0xc0] = 72; g[0xc1] = 131; g[0xc2] = 196;
	g[0xc3] = 8; g[0xc4] = 72; g[0xc5] = 141; g[0xc6] = 29;
	g[0xc7] = 117; g[0xc8] = 255; g[0xc9] = 255; g[0xca] = 255;
	g[0xcb] = 72; g[0xcc] = 139; g[0xcd] = 75; g[0xce] = 8;
	g[0xcf] = 72; g[0xd0] = 139; g[0xd1] = 83; g[0xd2] = 16;
	g[0xd3] = 76; g[0xd4] = 139; g[0xd5] = 67; g[0xd6] = 24;
	g[0xd7] = 76; g[0xd8] = 139; g[0xd9] = 75; g[0xda] = 32;
	g[0xdb] = 72; g[0xdc] = 137; g[0xdd] = 224; g[0xde] = 72;
	g[0xdf] = 131; g[0xe0] = 228; g[0xe1] = 240; g[0xe2] = 72;
	g[0xe3] = 131; g[0xe4] = 236; g[0xe5] = 64; g[0xe6] = 72;
	g[0xe7] = 137; g[0xe8] = 68; g[0xe9] = 36; g[0xea] = 56;
	g[0xeb] = 72; g[0xec] = 139; g[0xed] = 67; g[0xee] = 40;
	g[0xef] = 72; g[0xf0] = 137; g[0xf1] = 68; g[0xf2] = 36;
	g[0xf3] = 32; g[0xf4] = 72; g[0xf5] = 139; g[0xf6] = 3;
	g[0xf7] = 255; g[0xf8] = 208; g[0xf9] = 72; g[0xfa] = 139;
	g[0xfb] = 100; g[0xfc] = 36; g[0xfd] = 56; g[0xfe] = 72;
	g[0xff] = 137; g[0x100] = 67; g[0x101] = 48; g[0x102] = 72;
	g[0x103] = 141; g[0x104] = 5; g[0x105] = 23; g[0x109] = 106;
	g[0x10a] = 35; g[0x10b] = 80; g[0x10c] = 72; g[0x10d] = 203;
	g[0x120] = 195;

	return base[0];
}

/* __gate_invoke: cast gate to a cdecl void(void) and call it. Declared here
 * and defined below __gate_call, which is the one caller needing it before
 * its own definition -- this dialect resolves a call against whatever has
 * been declared or defined so far, not against the whole file, the same way
 * every forward reference in this port is handled. */
int __gate_invoke(int gate);

/* One call across the gate: target(a1, a2), both args and the target zero-
 * extended to 64 bits (every target and argument this file passes is really
 * 32 bits wide -- a HANDLE or a heap pointer of this process's own, or a VA
 * this file already carries as (lo, hi) -- so hi halves are written 0 or the
 * caller's own hi word directly). Returns the low 32 bits of the 64-bit
 * result, which is all STATUS codes and everything else this file reads back
 * ever need. */
int __gate_call(int gate, int target_lo, int target_hi, int a1, int a1_hi, int a2, int a2_hi)
{
	int* data;

	data = gate + 0x40;
	data[0] = target_lo; data[1] = target_hi;
	data[2] = a1; data[3] = a1_hi;
	data[4] = a2; data[5] = a2_hi;
	data[12] = -572662307;   /* 0xDCDCDCDC: a recognisable poison result, so a
	                          * gate call that never touches Result reads back
	                          * as obviously wrong rather than as a plausible
	                          * STATUS_SUCCESS of 0. */

	__gate_invoke(gate);

	return data[12];
}

/* __gate_invoke: cast gate to a cdecl void(void) and call it. Split out of
 * __gate_call only because this dialect's function-pointer declarations name
 * their argument count, and the gate genuinely takes none -- everything it
 * needs is already sitting in its own data area. */
int __gate_invoke(int gate)
{
	int (*entry)();

	entry = gate;
	entry();
	return 0;
}

/* This process's own 64-bit PEB address (PROCESS_BASIC_INFORMATION64.
 * PebBaseAddress, at +8 into the 48-byte structure, class 0 --
 * ProcessBasicInformation, the same class number the 32-bit
 * NtQueryInformationProcess already used elsewhere in this file answers for
 * the 32-bit view). Every module walk and export resolution below starts
 * here. Returns the low word; writes the high word to hi_out, 0/0 on
 * failure. */
int __wow64_selfpeb(int* hi_out)
{
	int (*NtWow64QueryInformationProcess64)(int, int, int, int, int);
	int* info;
	int* retlen;
	int self;
	int rc;

	/* 16-aligned, not the plain calloc(12, 4) this used to be: this exact
	 * call, against that unaligned buffer, is what __wow64fix_qinfo_status
	 * measured returning STATUS_DATATYPE_MISALIGNMENT (0x80000002) -- see
	 * __wow64_align16. retlen gets the same treatment since it is also
	 * handed to a WOW64 64-bit call, even though ReturnLength's own type is
	 * a plain ULONG rather than one of the 64-bit ones. */
	info = calloc(48 + 16, 1);
	info = __wow64_align16(info);
	retlen = calloc(4 + 16, 1);
	retlen = __wow64_align16(retlen);
	self = __wow64_selfhandle();
	NtWow64QueryInformationProcess64 = __ntdll(NT_WOW64QINFO);
	/* forwards: NtWow64QueryInformationProcess64(self, 0, info, 48, retlen) --
	 * self, not -1: see __wow64_selfhandle's note on __wow64_rd64 above,
	 * which this same call was the other half of that measurement. */
	rc = NtWow64QueryInformationProcess64(retlen, 48, info, 0, self);
	__wow64fix_qinfo_status = rc;
	if(0 != rc) { hi_out[0] = 0; return 0; }
	hi_out[0] = info[3];
	return info[2];
}

/* CONTEXT_AMD64 byte offsets used below (ContextFlags +0x30, SegCs +0x38,
 * SegSs +0x42, EFlags +0x44, Rsp +0x98, Rip +0xF8), carried as word indices
 * since this file addresses every buffer as int*: divide by 4. Values from
 * mingw-w64's winnt.h struct _CONTEXT (x86_64), cross-checked in
 * wow64-clone-driver.md sec 9.2/9.3 against a live read on the VM. The buffer
 * is 0x4D0 bytes, same as demo.c's CTX_SIZE. */
int __clone_process_wow64fix()
{
	int (*RtlCloneUserProcess)(int, int, int, int, int);
	int (*NtResumeThread)(int, int);
	int (*NtGetContextThread)(int, int);
	int (*NtSetContextThread)(int, int);
	int (*NtTerminateProcess)(int, int);
	int (*NtWriteVirtualMemory)(int, int, int, int, int);
	int (*NtClose)(int);
	int* info;
	int gate;
	int* peb_hi;
	int peb_lo;
	int ntdll64_lo; int* ntdll64_hi;
	int wow64cpu_lo; int* wow64cpu_hi;
	int getctx_lo; int* getctx_hi;
	int setctx_lo; int* setctx_hi;
	int btcpu_lo; int* btcpu_hi;
	int thread;
	int child;
	int* ctxA;
	int* ctxB;
	int rspA_lo; int rspA_hi;
	int rtlclone_rva;
	int lock_rva;
	int lock_addr;
	int* zero;
	int* wrote;
	int rc;
	int i;

	RtlCloneUserProcess = __ntdll(NT_CLONE);
	if(NULL == RtlCloneUserProcess) { __wow64fix_fail_at = 1; return -1; }

	/* -- resolve everything the fix needs before touching the clone at all -- */
	peb_hi = calloc(1, 4);
	i = __wow64_selfpeb(peb_hi);        /* see below: NtWow64QueryInformationProcess64 */
	peb_lo = i;
	if((0 == peb_lo) && (0 == peb_hi[0])) { __wow64fix_fail_at = 2; return -1; }

	/* Everything from here down exists only because of WOW64: a 32-bit
	 * process under a 64-bit kernel resumes a cloned thread directly in
	 * 32-bit mode instead of through the 64-bit bring-up that would have
	 * programmed its FS base and put it inside wow64cpu!RunSimulatedCode
	 * (see __clone_process's own note, and wow64-clone-driver.md sec 1-2).
	 * On genuine 32-bit Windows there is no 64-bit kernel underneath, no
	 * simulator to enter, no compat-mode FS-base indirection to miss -- a
	 * clone's thread gets its FS base the same native way any other 32-bit
	 * thread does, so this whole defect class has nowhere to come from.
	 * wow64cpu.dll not being findable in this process's own 64-bit module
	 * list is the authoritative signal for that: it is not "the 64-bit-view
	 * query failed" (checked separately above, and left a hard failure,
	 * because that can fail on genuine WOW64 for reasons unrelated to which
	 * Windows this is), it is "there is no second, 64-bit image of anything
	 * loaded in this process at all" -- exactly the shape this file already
	 * uses for NT_CLONE itself, whose own slot comment notes it stays 0 on
	 * wine rather than erroring the caller out. Fall back to the plain
	 * clone, the same one __clone_process above already is and which its own
	 * note argues should just work without WOW64 in the way: no gate, no
	 * 64-bit resolution, none of it. Not tested against real 32-bit Windows
	 * -- this project has no such hardware or VM to test on -- so this is a
	 * reasoned-through fallback shape, not a measured one. */
	ntdll64_hi = calloc(1, 4);
	ntdll64_lo = __wow64_find_module(peb_lo, peb_hi[0], "ntdll.dll", ntdll64_hi);
	wow64cpu_hi = calloc(1, 4);
	wow64cpu_lo = __wow64_find_module(peb_lo, peb_hi[0], "wow64cpu.dll", wow64cpu_hi);
	if((0 == wow64cpu_lo) && (0 == wow64cpu_hi[0])) return __clone_process();
	if((0 == ntdll64_lo) && (0 == ntdll64_hi[0])) { __wow64fix_fail_at = 3; return -1; }

	getctx_hi = calloc(1, 4);
	getctx_lo = __wow64_resolve_export(ntdll64_lo, ntdll64_hi[0], "NtGetContextThread", getctx_hi);
	setctx_hi = calloc(1, 4);
	setctx_lo = __wow64_resolve_export(ntdll64_lo, ntdll64_hi[0], "NtSetContextThread", setctx_hi);
	btcpu_hi = calloc(1, 4);
	btcpu_lo = __wow64_resolve_export(wow64cpu_lo, wow64cpu_hi[0], "BTCpuSimulate", btcpu_hi);
	if((0 == getctx_lo) && (0 == getctx_hi[0])) { __wow64fix_fail_at = 4; return -1; }
	if((0 == setctx_lo) && (0 == setctx_hi[0])) { __wow64fix_fail_at = 5; return -1; }
	if((0 == btcpu_lo) && (0 == btcpu_hi[0])) { __wow64fix_fail_at = 6; return -1; }

	gate = __gate_init();
	if(0 == gate) { __wow64fix_fail_at = 7; return -1; }

	/* -- clone, suspended -- */
	info = calloc(32, 4);
	i = 0;
	while(i < 32) { info[i] = 0; i = i + 1; }
	info[0] = 68;
	/* forwards: RtlCloneUserProcess(RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED |
	 *                               RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
	 *                               NULL, NULL, NULL, info) -- 3, not the bare
	 *                               CREATE_SUSPENDED (1) this used to pass.
	 * wow64-clone-driver.md sec 8-9's own validation never opened a file or
	 * wrote through an inherited handle in the child, so CREATE_SUSPENDED
	 * alone was never wrong for what it measured; fork() actually running
	 * ordinary programs is what exposed the gap. Measured directly:
	 * fork-test's own child print (stdout) and fork-file-test's child write
	 * (an opened file) both went missing with flags=1, and __clone_process
	 * above -- the older, un-preferred clone -- already asks for
	 * INHERIT_HANDLES (flags=2) for exactly this reason, so this brings the
	 * fixed-up clone in line with the one call in this file that already got
	 * it right. */
	rc = RtlCloneUserProcess(info, 0, 0, 0, 3);
	if(0x129 == rc) return 0;   /* the clone ran with no fix at all -- never
	                             * observed on this project's VM, kept as a
	                             * cheap check in case a future Windows build
	                             * no longer needs any of this. */
	if(0 != rc) { __wow64fix_fail_at = 8; return -1; }
	thread = info[2];
	/* Hoisted once, here, and used everywhere below instead of info[1]
	 * directly: this dialect's calling convention keeps the target of an
	 * indirect call in EDX while it evaluates that call's arguments (see
	 * libc-core.M1's own note on __ntdll), and info[1] as an argument is an
	 * array subscript -- a multiply -- which clobbers EDX before the call it
	 * is an argument to ever runs. check_fnptr_args.py already flags every
	 * such site; this is the fix, not just a suppression, matching how
	 * fork() below already hoists the same field into a local called
	 * child. */
	child = info[1];

	/* -- Step A: native NtGetContextThread on the never-run initial thread -- */
	ctxA = calloc(0x4D0 + 16, 1);
	ctxA = __wow64_align16(ctxA);
	i = 0;
	while(i < (0x4D0 / 4)) { ctxA[i] = 0; i = i + 1; }
	ctxA[12] = 0x100007;              /* ContextFlags at +0x30: CONTROL|INTEGER|SEGMENTS */
	rc = __gate_call(gate, getctx_lo, getctx_hi[0], thread, 0, ctxA, 0);
	if(0 != rc)
	{
		NtTerminateProcess = __ntdll(NT_EXIT);
		NtTerminateProcess(1, child);
		__wow64fix_fail_at = 9;
		return -1;
	}
	rspA_lo = ctxA[0x98 / 4];
	rspA_hi = ctxA[(0x98 / 4) + 1];

	/* -- Step B: native NtSetContextThread, redirecting Rip -> BTCpuSimulate -- */
	ctxB = calloc(0x4D0 + 16, 1);
	ctxB = __wow64_align16(ctxB);
	i = 0;
	while(i < (0x4D0 / 4)) { ctxB[i] = 0; i = i + 1; }
	ctxB[12] = 0x100001;              /* CTXF_CONTROL: Rip/Rsp/SegCs/SegSs/EFlags */
	ctxB[0xF8 / 4] = btcpu_lo; ctxB[(0xF8 / 4) + 1] = btcpu_hi[0];   /* Rip */
	ctxB[0x98 / 4] = rspA_lo;  ctxB[(0x98 / 4) + 1] = rspA_hi;       /* Rsp: the thread's own */
	i = ctxB[0x38 / 4]; ctxB[0x38 / 4] = (i & -65536) | 0x33;        /* SegCs, low 16 bits */
	i = ctxB[0x40 / 4]; ctxB[0x40 / 4] = (i & 65535) | (0x2B * 65536); /* SegSs at +0x42 */
	ctxB[0x44 / 4] = 0x202;           /* EFlags */
	rc = __gate_call(gate, setctx_lo, setctx_hi[0], thread, 0, ctxB, 0);
	if(0 != rc)
	{
		NtTerminateProcess = __ntdll(NT_EXIT);
		NtTerminateProcess(1, child);
		__wow64fix_fail_at = 10;
		return -1;
	}

	/* -- Step C: the ordinary (wow64-thunked) NtSetContextThread this file
	 * already uses elsewhere, on the 32-bit CPU-area CONTEXT, asking only for
	 * CONTEXT_INTEGER|CONTEXT_CONTROL|CONTEXT_SEGMENTS (0x10007, the same
	 * CONTEXT_FULL fork() below already uses) with Eax forced to
	 * STATUS_PROCESS_CLONED. wow64-clone-driver.md sec 8.2's disassembly of
	 * BTCpuSetContext is why this is enough: asking for that flag set is what
	 * makes it OR bit 0 into the CPU area's status word, which is the same
	 * bit RunSimulatedCode's own entry tests to decide whether to reprogram
	 * FS. Get first, so nothing already correct in the CPU-area CONTEXT
	 * (Eip, Esp, the segment selectors) is stepped on -- only Eax changes. */
	NtGetContextThread = __ntdll(NT_GETCONTEXT);
	NtSetContextThread = __ntdll(NT_SETCONTEXT);
	ctxA = calloc(0x2CC + 16, 1);
	ctxA = __wow64_align16(ctxA);
	i = 0;
	while(i < 179) { ctxA[i] = 0; i = i + 1; }
	ctxA[0] = 0x10007;
	rc = NtGetContextThread(ctxA, thread);
	if(0 != rc)
	{
		NtTerminateProcess = __ntdll(NT_EXIT);
		NtTerminateProcess(1, child);
		__wow64fix_fail_at = 11;
		return -1;
	}
	ctxA[44] = 0x129;                 /* Eax at +0xB0 */
	rc = NtSetContextThread(ctxA, thread);
	if(0 != rc)
	{
		NtTerminateProcess = __ntdll(NT_EXIT);
		NtTerminateProcess(1, child);
		__wow64fix_fail_at = 12;
		return -1;
	}

	/* -- Step C.5: zero RtlCloneUserProcess's own internal SRW lock, in the
	 * CHILD's copy, before it ever runs an instruction. wow64-clone-driver.md
	 * sec 10's CFG walk of RtlCloneUserProcess (radare2 agf/pdf, not a linear
	 * read) found the parent's own call -- CREATE_SUSPENDED, no
	 * NO_SYNCHRONIZE -- takes the branch that does
	 * RtlAcquireSRWLockExclusive(ntdll+0x12d534) then
	 * RtlAcquireSRWLockExclusive(ntdll+0x12d52c), in that order, and holds
	 * BOTH across the NtCreateUserProcess syscall inside it, releasing them
	 * only on the parent's own return path. The child's branch (taken when
	 * Eax==STATUS_PROCESS_CLONED, which Step C just wrote) reinitialises and
	 * releases +0x12d534 by itself, unconditionally -- so that one is
	 * self-healing regardless of what this function does. It never releases
	 * +0x12d52c first, though, before reaching
	 * RtlAcquireReleaseSRWLockExclusive(ntdll+0x12d52c) a few instructions
	 * later -- an acquire-then-release memory-barrier call that blocks
	 * forever on a lock nothing in this process will ever Release, because
	 * the release for it belongs to a branch the child does not take. That
	 * is the wait this function's own note below used to end at
	 * (NtWaitForAlertByThreadId, parked, unchanging). This is not the same
	 * lock as the one a previous version of this note zeroed and found no
	 * effect from (ntdll+0x12d7a4, a third SRW lock acquired earlier in the
	 * same preamble and, like +0x12d534, unconditionally fixed up by the
	 * child's own code either way) -- that null result is exactly what this
	 * CFG reading predicts, since +0x12d7a4 was never the one the child gets
	 * stuck on.
	 *
	 * ntdll.dll carries no relocations for this component (confirmed
	 * unchanging across repeated runs, wow64-clone-driver.md sec 9.2), so the
	 * parent's own already-resolved RtlCloneUserProcess pointer and this
	 * process's own copy of ntdll.dll sit at the same offset from each other
	 * as the child's do; RtlCloneUserProcess's RVA (0xbaa60) and the lock's
	 * RVA (0x12d52c), both measured this session against the exact ntdll.dll
	 * pulled off the VM, get from one to the other without ever naming
	 * ntdll's base directly. NtWriteVirtualMemory here is the same call
	 * __fork_write below wraps for fork()'s own copy into a child; it is
	 * inlined rather than shared because __fork_write is declared later in
	 * this file than this function is. child (info[1]) is the child's
	 * process handle (RTL_USER_PROCESS_INFORMATION.Process), the same field
	 * fork()'s own note reads. */
	rtlclone_rva = 0xbaa60;
	lock_rva = 0x12d52c;
	lock_addr = RtlCloneUserProcess - rtlclone_rva + lock_rva;
	zero = calloc(1, 4);
	zero[0] = 0;
	wrote = calloc(1, 4);
	NtWriteVirtualMemory = __ntdll(NT_WRITEVM);
	/* forwards: NtWriteVirtualMemory(child, lock_addr, zero, 4, wrote) */
	rc = NtWriteVirtualMemory(wrote, 4, zero, lock_addr, child);
	if(0 != rc)
	{
		NtTerminateProcess = __ntdll(NT_EXIT);
		NtTerminateProcess(1, child);
		__wow64fix_fail_at = 13;
		return -1;
	}

	/* -- Step D: let it go -- */
	NtResumeThread = __ntdll(NT_RESUME);
	/* forwards: NtResumeThread(thread, NULL) */
	NtResumeThread(0, thread);

	/* The thread handle has done its one job, same as __spawn's own (above)
	 * and fork()'s spawn+copy fallback's own (below) -- both already close
	 * theirs; this one leaked it on every successful clone until now, one
	 * handle per fork(). */
	NtClose = __ntdll(NT_CLOSE);
	NtClose(thread);

	return child;
}

/* Measured on this project's win11 VM (wow64-clone-driver.md sec 9.3-9.4):
 * every step above took -- Step A read back a sane native context, Step B's
 * Rip/SegCs read back exactly as written, Step C's Eax read back 0x129 --
 * and the clone, resumed, threw no exception at all across two 3-4 second
 * observation windows: no fs:[0x18] fault, no r15-dispatch fault, nothing.
 * Its 32-bit SegFs was 0x53 with a real base behind it -- the fault this
 * whole file's __clone_process note ends on -- and it settled at a 32-bit
 * ntdll syscall stub (measured at ntdll+0x77f70, NtWaitForAlertByThreadId)
 * with an identical context on a second look 3-4 seconds later: parked, not
 * crashing, not making progress either.
 *
 * A follow-up measurement that same session (zeroing the loader-lock SRW at
 * ntdll+0x12d7a4 in the child before resuming, the same falsifiable test
 * __clone_process's own note already ran against the unfixed clone) changed
 * nothing: identical Eip/Esp/SegFs with or without it.
 *
 * The next session found why, by disassembling RtlCloneUserProcess with
 * radare2's CFG-aware graph mode (agf), not the linear pd dump the earlier
 * static-analysis pass had used -- the function is only 475 bytes and the
 * whole of it, branches included, fits on one screen once read that way.
 * With RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED (1) and no NO_SYNCHRONIZE,
 * the *parent's own call* takes the branch that does
 * RtlAcquireSRWLockExclusive(ntdll+0x12d534) then
 * RtlAcquireSRWLockExclusive(ntdll+0x12d52c) -- a different lock from the
 * one this note zeroed last session -- and holds both across the
 * NtCreateUserProcess syscall inside it, releasing them only on its own
 * (Eax != STATUS_PROCESS_CLONED) return path. The child's branch
 * (Eax == STATUS_PROCESS_CLONED, which Step C forces) reinitialises and
 * releases +0x12d534 unconditionally, by itself -- so zeroing +0x12d7a4
 * last session touched neither lock that actually mattered, which is why it
 * changed nothing. But the child's branch never releases +0x12d52c before
 * reaching RtlAcquireReleaseSRWLockExclusive(ntdll+0x12d52c) a few
 * instructions later -- an acquire-then-release memory-barrier call, on a
 * lock the parent left held, that nothing in the child process will ever
 * Release, because the release for it belongs to the branch the child does
 * not take. That is the wait this note used to end at: not a reading, a
 * traced control-flow fact.
 *
 * Step C.5 above tests it the same way __clone_process's own note tested the
 * loader lock: zero the raw bytes and see what changes. Confirmed live, this
 * session, on win11 (two independent runs, identical result): before the
 * zero, the child parked forever, as recorded above. After it -- with
 * nothing else about steps A-D touched -- the child ran. The debugger
 * attached in the test harness saw real LOAD_DLL events beyond the
 * synthetic attach catch-up, a CREATE_THREAD/EXIT_THREAD pair, one
 * first-chance STATUS_INVALID_HANDLE (0xc0000008, the kind of otherwise-
 * silent handle-table noise a debugger attach turns visible, not a sign of
 * failure), and then EXIT_PROCESS with code 0x77 -- which is reachable in
 * that test harness (probe4.c, kept locally per the task's instructions,
 * not in this tree) from exactly one place: `if (cst ==
 * STATUS_PROCESS_CLONED) ExitProcess(0x77);`, the harness's own
 * fork()-shaped child branch, taken immediately after RtlCloneUserProcess
 * itself returns 0x129 into the harness's C code. That is unambiguous: the
 * child ran genuine 32-bit C past the clone, correctly took the child
 * branch, and exited exactly as told. Both walls fall, the lock releases
 * cleanly, and the clone reaches ordinary running code -- not just "no more
 * exceptions."
 *
 * This is why the function is wired into fork() below now, ahead of the
 * spawn+copy path, whenever NT_CLONE resolves (RtlCloneUserProcess exists;
 * the slot comment already notes it is absent on Wine). A failure return
 * here after the clone succeeds terminates the half-set-up child first, so
 * falling back to spawn+copy never leaves an orphaned suspended process
 * behind. The spawn+copy path itself is untouched and is still what runs
 * whenever NT_CLONE fails to resolve, or whenever this function returns -1
 * for any other reason. */

/* This process's own image path, out of the PEB, narrowed the way everything
 * else in this port narrows.  fork needs it because the only way to get a
 * child with a working address space is to start this same program again. */
char* __self_path()
{
	int* slot;
	int* pp;
	char* wide;
	char* out;
	int addr;
	int n;
	int i;

	/* __stdslot(0) is &ProcessParameters->StandardInput, at 0x18 into the
	 * block, so 24 bytes back is the block itself -- counted in bytes, as a
	 * plain integer, because this dialect does not scale pointer arithmetic
	 * and quietly gives the wrong address if asked to.  ImagePathName is the
	 * UNICODE_STRING at 0x38 and its Buffer is at 0x3c, which is word 15. */
	slot = __stdslot(0);
	addr = slot;
	addr = addr - 24;
	pp = addr;
	wide = pp[15];
	if(NULL == wide) return NULL;

	n = 0;
	while(0 != wide[2 * n]) n = n + 1;

	out = calloc(n + 1, 1);
	i = 0;
	while(i < n)
	{
		out[i] = wide[2 * i];
		i = i + 1;
	}
	out[n] = 0;
	return out;
}

/* One span of this process's memory, written into another process.  fork
 * calls this with src and dst the same number, which is the whole trick: see
 * below. */
int __fork_write(int proc, int dst, int src, int len)
{
	int (*NtWriteVirtualMemory)(int, int, int, int, int);
	int* wrote;
	int rc;

	if(0 >= len) return 0;
	wrote = calloc(1, 4);
	NtWriteVirtualMemory = __ntdll(NT_WRITEVM);
	/* forwards: NtWriteVirtualMemory(proc, dst, src, len, wrote) */
	rc = NtWriteVirtualMemory(wrote, len, src, dst, proc);
	return rc;
}

/* One word out of another process.  The caller passes the scratch for the
 * count as well as the buffer, because the one caller reads in a loop and a
 * calloc per turn of it would leak a word a time into the very heap it is
 * about to copy. */
int __fork_peek(int proc, int addr, int* out, int* got)
{
	int (*NtReadVirtualMemory)(int, int, int, int, int);
	int rc;

	NtReadVirtualMemory = __ntdll(NT_READVM);
	/* forwards: NtReadVirtualMemory(proc, addr, out, 4, got) */
	rc = NtReadVirtualMemory(got, 4, out, addr, proc);
	return rc;
}

/* fork, by starting this program again and then overwriting the copy.
 *
 * Windows has a fork primitive and it does not work; the whole of why is
 * written up at __clone_process, and none of it is fixable from user mode.
 * What is left is the way Cygwin has always done it, and it works here for a
 * reason particular to this bootstrap rather than to Cygwin's cleverness.
 *
 * The reason is that every program this chain builds is one section at a fixed
 * address.  x86/PE32-i386.hex2 sets IMAGE_FILE_RELOCS_STRIPPED and does not
 * set DYNAMIC_BASE, so there is no relocation and no address-space layout
 * randomisation: the image is at 0x400000 in every process that runs it, it
 * runs to 128MB with code, data and heap all inside it and all writable, and
 * even the stack the kernel hands out lands at the same address every time.
 * So a second copy of this same program is laid out identically to the first,
 * and copying memory from one into the other needs no fixups of any kind -- a
 * pointer means the same thing on both sides, because it points at the same
 * offset of the same image mapped at the same place.  A program built the
 * ordinary way, relocatable and randomised, could not do this.  This one can
 * only do it.
 *
 * That the stacks coincide is what makes the child's locals and its whole
 * chain of callers real without a single fixup, and it is also the one thing
 * that has to be worked around: the child has its own loader init to run, on
 * that same stack, before it can be trusted with anything.  So the child is
 * made to run all of its own startup first and then stop dead:
 *
 *   __fork_setjmp writes down where the caller would have carried on.
 *   The same program is started again, suspended -- a process Windows made in
 *     the ordinary way, so its thread has everything the clone's never had:
 *     an FS base the kernel programmed, the WOW64 registers its own bring-up
 *     will set, a stack, a PEB.
 *   Before letting it go, one word is written into it: the flag _start reads
 *     to learn it is a fork child.  It is the only thing that distinguishes
 *     this child from an ordinary run of the same program.
 *   It is let go, does its loader init, resolves ntdll, sets up the C library,
 *     and then parks in a spin rather than calling main, saying so in a second
 *     word the parent watches.  Its startup is over and its stack is finished
 *     with.
 *   It is suspended, and everything from the image base to the top of the heap
 *     is copied into it -- every global and every byte malloc has handed out,
 *     at the addresses they already have -- and then the parent's committed
 *     stack, at its own address, over the top of the child's spent one.
 *   Its thread is pointed at what __fork_setjmp wrote down, with EAX set to 1,
 *     and let go.
 *
 * It comes up believing it has just returned from __fork_setjmp, on its
 * parent's stack, with its parent's memory, and returns 0 from here.  The
 * parent gets the child's process handle, which is what this port calls a pid.
 *
 * What this leans on, and what would break it:
 *
 *   ntdll is at one address for a whole boot, shared by every process, so the
 *   routine addresses resolve_all found in the parent are the same numbers in
 *   the child.  The child resolves them again anyway, before it parks, and is
 *   then given the parent's copies on top; the two agree.
 *
 *   A file the parent had open is open in the child, at the same descriptor,
 *   which is the whole reason open_file asks for OBJ_INHERIT: an inheritable
 *   handle is the one kind a child receives, and it receives it under the
 *   same number -- which is what keeps the number the copied memory is
 *   holding meaningful.  POSIX hands every descriptor to a child across both
 *   fork and exec unless it is marked FD_CLOEXEC, and there is no FD_CLOEXEC
 *   here to ask for the other behaviour.
 *
 *   The child is a second process, so it has its own pid and its own parent as
 *   far as Windows is concerned.  Nothing that asks Windows rather than this
 *   library will see a fork.
 *
 * fork's children are not waited for here.  waitpid takes what this returns. */
int fork()
{
	int (*NtGetContextThread)(int, int);
	int (*NtSetContextThread)(int, int);
	int (*NtResumeThread)(int, int);
	int (*NtSuspendThread)(int, int);
	int (*NtTerminateProcess)(int, int);
	int (*NtAllocateVirtualMemory)(int, int, int, int, int, int);
	int (*NtClose)(int);
	char* path;
	char** argv;
	int* info;
	int* teb;
	int* ctx;
	int* one;
	int* seen;
	int* got;
	int* base;
	int* size;
	int ctx_raw;
	int stack_low;
	int stack_high;
	int stack_len;
	int heap_top;
	int child;
	int thread;
	int flag_at;
	int parked_at;
	int spins;
	int rc;
	int i;
	int wow64fix_rc;

	/* __clone_process_wow64fix above is the real fork() Windows almost has:
	 * one syscall, whole address space, no second process started from
	 * scratch. Preferred whenever it can run at all -- it already returns -1
	 * immediately, before touching anything, if NT_CLONE did not resolve
	 * (RtlCloneUserProcess absent, e.g. on Wine per the slot's own comment),
	 * so this is exactly "preferred when NT_CLONE resolves" without probing
	 * the slot twice. It also cleans up any suspended child it created
	 * before returning -1 for any other reason, so falling through to the
	 * spawn+copy path below never starts it behind an orphaned process. What
	 * it returns otherwise -- 0 in the child, the child's PID in the parent
	 * -- is already exactly what fork() promises, so it is handed straight
	 * back. */
	wow64fix_rc = __clone_process_wow64fix();
	if(-1 != wow64fix_rc) return wow64fix_rc;

	/* Where fork returns to, written down before there is a child to send
	 * there.  Nothing comes back into fork on the child's side: the child is
	 * started in fork's caller, with fork already returned and 0 in EAX. */
	__fork_setjmp();

	path = __self_path();
	if(NULL == path) return -1;

	argv = calloc(2, 4);
	argv[0] = path;
	argv[1] = NULL;

	info = calloc(32, 4);
	child = __spawn_suspended(path, argv, NULL, info);
	if(0 >= child) return -1;
	thread = info[2];

	NtTerminateProcess = __ntdll(NT_EXIT);
	NtResumeThread = __ntdll(NT_RESUME);

	/* Tell it what it is, before it has run an instruction. */
	one = calloc(1, 4);
	one[0] = 1;
	flag_at = __fork_flagaddr();
	rc = __fork_write(child, flag_at, one, 4);
	if(0 != rc)
	{
		NtTerminateProcess(1, child);
		return -1;
	}

	/* Let it run its own startup, all the way to the spin in _start. */
	NtResumeThread(0, thread);

	parked_at = __fork_parkedaddr();
	seen = calloc(1, 4);
	seen[0] = 0;
	got = calloc(1, 4);
	spins = 0;
	while(0 == seen[0])
	{
		rc = __fork_peek(child, parked_at, seen, got);
		if(0 != rc)
		{
			NtTerminateProcess(1, child);
			return -1;
		}
		spins = spins + 1;
		if(spins > 100000000)
		{
			/* It should take microseconds.  Something is wrong. */
			NtTerminateProcess(1, child);
			return -1;
		}
	}

	/* Parked.  Stop it before touching anything it is standing on. */
	NtSuspendThread = __ntdll(NT_SUSPEND);
	/* forwards: NtSuspendThread(thread, NULL) */
	rc = NtSuspendThread(0, thread);
	if(0 > rc)
	{
		NtTerminateProcess(1, child);
		return -1;
	}

	/* CONTEXT is 0x2cc bytes and the kernel insists on 16-byte alignment. */
	ctx_raw = calloc(0x2CC + 16, 1);
	ctx_raw = ctx_raw + 15;
	ctx_raw = ctx_raw - (ctx_raw % 16);
	ctx = ctx_raw;
	i = 0;
	while(i < 179)
	{
		ctx[i] = 0;
		i = i + 1;
	}
	ctx[0] = 0x10007;                     /* CONTEXT_FULL */

	NtGetContextThread = __ntdll(NT_GETCONTEXT);
	/* forwards: NtGetContextThread(thread, ctx) */
	rc = NtGetContextThread(ctx, thread);
	if(0 != rc)
	{
		NtTerminateProcess(1, child);
		return -1;
	}

	/* This thread's committed stack, which is what the child has to be given
	 * a copy of.  StackBase and StackLimit are at 0x04 and 0x08 in the TEB;
	 * the stack grows down, so StackLimit is the low end. */
	teb = __teb();
	stack_high = teb[1];
	stack_low = teb[2];
	stack_len = stack_high - stack_low;
	if(0 >= stack_len)
	{
		NtTerminateProcess(1, child);
		return -1;
	}

	/* Everything this program has: the one section, from where it starts to
	 * the top of the heap -- code, globals and every byte malloc has handed
	 * out.  The copy starts at 0x401000 rather than at the image base
	 * because the page below that is the PE header, which the loader maps
	 * read-only; writing there answers STATUS_PARTIAL_COPY and there is
	 * nothing in it that differs between two runs of one program anyway. */
	heap_top = brk(0);
	rc = __fork_write(child, 0x401000, 0x401000, heap_top - 0x401000);
	if(0 != rc)
	{
		NtTerminateProcess(1, child);
		return -1;
	}

	/* The child has barely touched its own stack: it started, ran its loader
	 * init and its startup, and parked, all within a page or two of the top.
	 * Everything below that is reserved rather than committed there, and a
	 * write to a page that is only reserved answers STATUS_PARTIAL_COPY --
	 * which is what made fork fail from any depth at all.  A parent that had
	 * recursed far enough to grow its own stack had more committed than the
	 * child did, and the difference was exactly the part that could not be
	 * written; shallow callers happened to fit, and so happened to work.
	 *
	 * Committing just the parent's committed range is not enough, though,
	 * and the reason is the guard page.  Windows grows a stack by putting a
	 * PAGE_GUARD page below what is committed and committing one more when
	 * it is touched; the child's guard page sits high, where its own short
	 * stack ended, and is inside the range being written.  Overwrite it and
	 * the child has no guard anywhere, so the first call that reaches past
	 * the copied region touches reserved memory and dies rather than growing
	 * -- which is what a child that forked deep and then recursed did.
	 *
	 * So commit the whole reservation instead.  It is 0x200000, because that
	 * is the SizeOfStackReserve x86/PE32-i386.hex2 writes into every image
	 * this chain builds, and StackBase is its top.  A child then has its
	 * whole stack already there and needs no guard page to grow into it, at
	 * the cost of 2MB of committed memory per fork -- which is the same 2MB
	 * the parent would have ended up committing anyway had it recursed that
	 * far.  Committing what is already committed is not an error. */
	base = calloc(1, 4);
	size = calloc(1, 4);
	base[0] = stack_high - 0x200000;
	size[0] = 0x200000;
	NtAllocateVirtualMemory = __ntdll(NT_ALLOC);
	/* forwards: NtAllocateVirtualMemory(child, base, 0, size, MEM_COMMIT,
	 *                                   PAGE_READWRITE) */
	rc = NtAllocateVirtualMemory(4, 0x1000, size, 0, base, child);
	if(0 != rc)
	{
		NtTerminateProcess(1, child);
		return -1;
	}

	rc = __fork_write(child, stack_low, stack_low, stack_len);
	if(0 != rc)
	{
		NtTerminateProcess(1, child);
		return -1;
	}

	/* Point it at what __fork_setjmp wrote down.  Everything else in the
	 * context is left exactly as Windows built it -- the segment registers
	 * above all, which is the whole difference between this and the clone. */

	ctx[46] = __fork_geteip();            /* where fork returns to */
	ctx[49] = __fork_getesp();            /* on its caller's stack */
	ctx[44] = 0;                          /* EAX: and fork returned 0 */

	NtSetContextThread = __ntdll(NT_SETCONTEXT);
	/* forwards: NtSetContextThread(thread, ctx) */
	rc = NtSetContextThread(ctx, thread);
	if(0 != rc)
	{
		NtTerminateProcess(1, child);
		return -1;
	}

	/* Suspended twice: once by us just now, once by the spin it was in.  Let
	 * it go the once; it was resumed out of its creation suspend already. */
	NtResumeThread(0, thread);

	/* As in __spawn: the thread handle is finished with, and a fork that
	 * leaked one per call would run a program out of handles long before it
	 * ran it out of anything else. */
	NtClose = __ntdll(NT_CLOSE);
	NtClose(thread);

	return child;
}
#endif
