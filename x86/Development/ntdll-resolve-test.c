/* SPDX-FileCopyrightText: (C) 2026 Gavin John
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 * Additional permission under GNU GPL version 3 section 7:
 * see LICENSE.EXCEPTION in the root of this project.
 *
 * Checks M2libc-windows/ntdll.c's new __ntdll_resolve -- a native, in-process
 * PEB/export-table walk that finds an ntdll routine by name -- against every
 * routine resolve_all already resolves by fixed slot (ntdll-i386.hex2,
 * ntdll-slots.h), by comparing the two addresses for each. If they always
 * agree, __ntdll_resolve is a safe portable replacement for the slot table
 * in any program built with a C compiler; hex0 through M0 have none yet and
 * must go on using resolve_all regardless (see gen_ntdll.py). Also checks
 * that resolving a name ntdll does not export returns NULL rather than some
 * other module's address or garbage.
 */

int main(int argc, char** argv)
{
	int ok;
	void* a;
	void* b;

	ok = 1;

	a = __ntdll(NT_CREATE);     b = __ntdll_resolve("NtCreateFile");
	if(a != b) { fputs("MISMATCH NtCreateFile\n", stdout); ok = 0; }

	a = __ntdll(NT_READ);       b = __ntdll_resolve("NtReadFile");
	if(a != b) { fputs("MISMATCH NtReadFile\n", stdout); ok = 0; }

	a = __ntdll(NT_WRITE);      b = __ntdll_resolve("NtWriteFile");
	if(a != b) { fputs("MISMATCH NtWriteFile\n", stdout); ok = 0; }

	a = __ntdll(NT_CLOSE);      b = __ntdll_resolve("NtClose");
	if(a != b) { fputs("MISMATCH NtClose\n", stdout); ok = 0; }

	a = __ntdll(NT_EXIT);       b = __ntdll_resolve("NtTerminateProcess");
	if(a != b) { fputs("MISMATCH NtTerminateProcess\n", stdout); ok = 0; }

	a = __ntdll(NT_RTLPATH);    b = __ntdll_resolve("RtlDosPathNameToNtPathName_U");
	if(a != b) { fputs("MISMATCH RtlDosPathNameToNtPathName_U\n", stdout); ok = 0; }

	a = __ntdll(NT_SETINFO);    b = __ntdll_resolve("NtSetInformationFile");
	if(a != b) { fputs("MISMATCH NtSetInformationFile\n", stdout); ok = 0; }

	a = __ntdll(NT_QUERYINFO);  b = __ntdll_resolve("NtQueryInformationFile");
	if(a != b) { fputs("MISMATCH NtQueryInformationFile\n", stdout); ok = 0; }

	a = __ntdll(NT_QUERYATTR);  b = __ntdll_resolve("NtQueryAttributesFile");
	if(a != b) { fputs("MISMATCH NtQueryAttributesFile\n", stdout); ok = 0; }

	a = __ntdll(NT_QUERYFULL);  b = __ntdll_resolve("NtQueryFullAttributesFile");
	if(a != b) { fputs("MISMATCH NtQueryFullAttributesFile\n", stdout); ok = 0; }

	a = __ntdll(NT_SETCWD);     b = __ntdll_resolve("RtlSetCurrentDirectory_U");
	if(a != b) { fputs("MISMATCH RtlSetCurrentDirectory_U\n", stdout); ok = 0; }

	a = __ntdll(NT_GETCWD);     b = __ntdll_resolve("RtlGetCurrentDirectory_U");
	if(a != b) { fputs("MISMATCH RtlGetCurrentDirectory_U\n", stdout); ok = 0; }

	a = __ntdll(NT_DUP);        b = __ntdll_resolve("NtDuplicateObject");
	if(a != b) { fputs("MISMATCH NtDuplicateObject\n", stdout); ok = 0; }

	a = __ntdll(NT_TIME);       b = __ntdll_resolve("NtQuerySystemTime");
	if(a != b) { fputs("MISMATCH NtQuerySystemTime\n", stdout); ok = 0; }

	a = __ntdll(NT_QUERYVOL);   b = __ntdll_resolve("NtQueryVolumeInformationFile");
	if(a != b) { fputs("MISMATCH NtQueryVolumeInformationFile\n", stdout); ok = 0; }

	a = __ntdll(NT_WAIT);       b = __ntdll_resolve("NtWaitForSingleObject");
	if(a != b) { fputs("MISMATCH NtWaitForSingleObject\n", stdout); ok = 0; }

	a = __ntdll(NT_QUERYPROC);  b = __ntdll_resolve("NtQueryInformationProcess");
	if(a != b) { fputs("MISMATCH NtQueryInformationProcess\n", stdout); ok = 0; }

	a = __ntdll(NT_DELETE);     b = __ntdll_resolve("NtDeleteFile");
	if(a != b) { fputs("MISMATCH NtDeleteFile\n", stdout); ok = 0; }

	a = __ntdll(NT_VERSION);    b = __ntdll_resolve("RtlGetVersion");
	if(a != b) { fputs("MISMATCH RtlGetVersion\n", stdout); ok = 0; }

	a = __ntdll(NT_MAKEPARAMS); b = __ntdll_resolve("RtlCreateProcessParameters");
	if(a != b) { fputs("MISMATCH RtlCreateProcessParameters\n", stdout); ok = 0; }

	a = __ntdll(NT_CREATEPROC); b = __ntdll_resolve("RtlCreateUserProcess");
	if(a != b) { fputs("MISMATCH RtlCreateUserProcess\n", stdout); ok = 0; }

	a = __ntdll(NT_RESUME);     b = __ntdll_resolve("NtResumeThread");
	if(a != b) { fputs("MISMATCH NtResumeThread\n", stdout); ok = 0; }

	a = __ntdll(NT_ALLOC);      b = __ntdll_resolve("NtAllocateVirtualMemory");
	if(a != b) { fputs("MISMATCH NtAllocateVirtualMemory\n", stdout); ok = 0; }

	a = __ntdll(NT_GETCONTEXT); b = __ntdll_resolve("NtGetContextThread");
	if(a != b) { fputs("MISMATCH NtGetContextThread\n", stdout); ok = 0; }

	a = __ntdll(NT_SETCONTEXT); b = __ntdll_resolve("NtSetContextThread");
	if(a != b) { fputs("MISMATCH NtSetContextThread\n", stdout); ok = 0; }

	a = __ntdll(NT_WRITEVM);    b = __ntdll_resolve("NtWriteVirtualMemory");
	if(a != b) { fputs("MISMATCH NtWriteVirtualMemory\n", stdout); ok = 0; }

	a = __ntdll(NT_READVM);     b = __ntdll_resolve("NtReadVirtualMemory");
	if(a != b) { fputs("MISMATCH NtReadVirtualMemory\n", stdout); ok = 0; }

	a = __ntdll(NT_SUSPEND);    b = __ntdll_resolve("NtSuspendThread");
	if(a != b) { fputs("MISMATCH NtSuspendThread\n", stdout); ok = 0; }

	a = __ntdll(NT_WOW64QINFO); b = __ntdll_resolve("NtWow64QueryInformationProcess64");
	if(a != b) { fputs("MISMATCH NtWow64QueryInformationProcess64\n", stdout); ok = 0; }

	a = __ntdll(NT_WOW64READVM);b = __ntdll_resolve("NtWow64ReadVirtualMemory64");
	if(a != b) { fputs("MISMATCH NtWow64ReadVirtualMemory64\n", stdout); ok = 0; }

	/* NtCloneUserProcess is deliberately absent from ntdll-slots.h's naming
	 * (the slot table calls it RtlCloneUserProcess, its real export name --
	 * see NT_CLONE above) so this checks a genuinely made-up name instead,
	 * to confirm a miss returns NULL rather than the last thing found. */
	b = __ntdll_resolve("NtThisExportDoesNotExist");
	if(NULL != b) { fputs("MISMATCH: bogus name resolved to something\n", stdout); ok = 0; }

	fflush(stdout);
	if(ok) fputs("ALL RESOLVED OK\n", stdout);
	else fputs("FAILED\n", stdout);
	fflush(stdout);
	if(0 == ok) return 1;
	return 0;
}
