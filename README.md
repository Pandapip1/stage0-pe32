<!--
SPDX-FileCopyrightText: (C) 2026 Gavin John

SPDX-License-Identifier: GPL-3.0-or-later
-->

# stage0-pe32

A full-source bootstrap for Windows, in the shape of
[stage0-posix](https://github.com/oriansj/stage0-posix).

Everything here is built from source by the chain itself, starting from a
1623-byte seed whose own annotated source is in the tree. Each link is written
in the language of the link below it, so the whole thing can be audited by
reading, from the bottom up.

    bootstrap-seeds/PE32/i386/hex0-seed.exe   1623 bytes, the trust anchor
    x86/hex0_x86.hex0                         hex0, written in hex0
    x86/hex1_x86.hex0                         hex1, written in hex0
    x86/hex2_x86.hex1                         hex2, written in hex1
    x86/catm_x86.hex2                         catm, written in hex2
    x86/PE32-i386.hex2                        the PE32 header, in hex2
    x86/ntdll-i386.hex2                       the shared Windows plumbing, in hex2
    x86/M0_x86.hex2                           M0, written in hex2
    x86/cc_x86.M1                             cc_x86, written in M1
    M2-Planet                                 a fuller C compiler, in C
    mescc-tools/M1-macro.c                    M1-macro, a fuller assembler, in C
    mescc-tools/hex2_linker.c                 hex2 again, in C, without the fixed table

| link | adds |
| ---- | ---- |
| hex0 | hexadecimal pairs become bytes |
| hex1 | single character labels, and relative pointers to them |
| hex2 | labels with names, pointers with widths: a linker |
| catm | concatenating files, so a header can be put in front of a program |
| M0   | macros, strings and immediates: the first real language |
| cc_x86 | a subset of C, large enough to compile M2-Planet |
| M2-Planet | the rest of the C this project's programs are written in |
| M1-macro | more label and pointer widths, and every architecture stage0 supports, in one binary |
| hex2 (from C) | the same linker without the hand-written one's fixed label table |

## Building

Clone with submodules -- from cc_x86 up, the build compiles C, and M2-Planet,
M2libc and mescc-tools are vendored as submodules rather than by hand, since
they are upstream's exactly as upstream wrote them:

    git clone --recurse-submodules <this repo>

On Windows:

    x86\mescc-tools-mini.cmd

Upstream drives the equivalent sequence with kaem, a shell it has to bootstrap
first. Windows always has cmd.exe, so there is nothing to bootstrap: the build
script is ordinary batch, and it is the only part of this that is not built
from source here.

The first thing the build does is assemble `hex0_x86.hex0` with the seed and
require the result to be identical to the seed. If that check fails, stop.

## How this differs from stage0-posix

There are no syscalls. A PE32 image here imports nothing at all: it finds ntdll
through the PEB at run time and resolves the handful of routines it needs from
ntdll's export table by name. There is no import table to inspect and nothing
between the file and the kernel.

That plumbing is the same in every program, so from M0 upward it lives in
`x86/ntdll-i386.hex2` and catm puts it in front of the program, the way it puts
the header stub in front of both. Part of it is splitting the command line,
because Windows hands a program one string rather than a vector: from M0 up
that split is the whole rule `CommandLineToArgvW` defines, backslash escaping
and all, since anything that launches another program writes an embedded quote
as `\"` and an argument cut off at the first one is worse than useless. hex0, hex1, hex2 and catm cannot use it --
there is no catm below catm to join files with -- so they carry their own
copies. Upstream has the same arrangement in `x86/libc-core.M1`.

There is no `brk`. `x86/PE32-i386.hex2` gives every program a section whose
VirtualSize runs to the top of a 128 MB image, so the memory past the end of
the file is already mapped and already zero. A program declares a buffer by
putting a label after `:PE_end` and never asks the operating system for memory.
16 MB was the original figure and was not enough: M0 processing the M1 that
builds M2-Planet wants over 22 MB of it.

`SectionAlignment` is the page size, and the header pads to 0x1000 to match.
The format permits less, and wine accepts less, but Windows 11 refuses such an
image with ERROR_BAD_EXE_FORMAT. `SizeOfRawData`, which the format says must be
a multiple of `FileAlignment`, is left as the exact length of the program, and
that Windows does accept. Both of these were measured rather than assumed.

There is no kaem, and there may never be one: see Building above.

## Where the sources come from

The `.hex0`, `.hex1` and `.hex2` files are generated, by the scripts in
`x86/Development/`, and they are the reviewable artefact -- every byte carries
the instruction it encodes and the reason for it. Regenerate and re-verify them
with:

    x86/Development/regenerate.sh

Each generator assembles its own output and compares it against the binary it
describes, so a source that has drifted from its binary fails there rather than
later.

`x86/cc_x86.M1` is the exception, because it is readable assembly rather than
hex and because the compiler in it is upstream's and is not being ported. It is
derived from upstream's `x86/cc_x86.M1` by `x86/Development/port_cc_x86.py`,
which is written as a list of exact before-and-after passages: every one of them
must match, so if upstream moves under any of the places this port replaces, the
script fails rather than quietly producing something nobody has read. Point
`CC_X86_UPSTREAM` at an upstream checkout's `x86/cc_x86.M1` to re-derive it:

    CC_X86_UPSTREAM=../stage0-posix/x86/cc_x86.M1 x86/Development/regenerate.sh

The whole of the port is `_start`, `malloc`, `fgetc`, `fputc`, `Exit_Failure`
and the name of the label that ends the image. Feed the same C to upstream's
`cc_x86` and to this one and the two outputs differ in exactly one line, the
`:ELF_end` that becomes `:PE_end`. The binaries share nothing -- different
format, different entry, different plumbing -- but the compiler between them is
demonstrably the same compiler.

From cc_x86 up, the chain compiles C rather than hand-written assembly, and the
C it compiles first is M2-Planet's own: `M2-Planet/`, `M2libc/` and
`mescc-tools/` are git submodules, pinned to the exact commits stage0-posix
itself vendors them at, because nothing in them is Windows-specific and there
is nothing to port. `x86/libc-core.M1` and `x86/M2libc-windows/bootstrap.c` are
what M2-Planet and M1-macro compile against instead of
`M2libc/x86/linux/bootstrap.c` -- the argc/argv/exit plumbing a C program
needs, standing on `x86/ntdll-i386.hex2` the same way `x86/cc_x86.M1` does. See
their own headers for what each routine does.

The two C libraries need different things set up before `main` runs, so
`libc-core.M1`'s `_start` calls `:__libc_init` and catm decides what that is:
`x86/libc-bootstrap.M1`, which does nothing, or `x86/libc-full.M1`, which calls
M2libc's `__init_malloc` and `__init_io`. The second is not optional and its
absence is quiet: `stdin`, `stdout` and `stderr` are globals that start NULL,
so a program linked without it works until the first time it tries to report an
error and then faults inside `fputs` instead of printing it. hex2 built from C
did exactly that, on every error path, until this existed.

`M2libc/x86/x86_defs.M1` -- the submodule's copy, not a copy of it -- matters
more than its name suggests: it is the mnemonic set M2's own code generator
actually emits, wider than what cc_x86.M1's hand-written assembly happens to
use. Getting this wrong doesn't fail loudly. M0 passes an unrecognized
mnemonic through as plain text rather than erroring, hex2 can't make sense of
it either, and the instruction is silently dropped: the build succeeds, the
binary comes out a few bytes short, and the failure surfaces later as an
illegal instruction somewhere unrelated.

That cost two debugging sessions -- the wrong `x86_defs.M1` entirely while
bringing up M1-macro, then three mnemonics missing from `libc-core.M1` while
bringing up hex2. The first was confirmed to be neither a PE32 issue nor an
upstream one by reproducing it identically on upstream's own native, ELF,
years-old `M1` binary once fed the same wrong file. `regenerate.sh` now runs
`x86/Development/check_mnemonics.py`, which fails on a mnemonic nothing
DEFINEs; it is checked against both of those bugs.

M2-Planet's own C is unmodified, so it always ends its output with `:ELF_end`,
the label its ELF header expects; `PE32-i386.hex2` expects `:PE_end`.
`x86/pe-end-shim.M1` defines `:PE_end` at that same address without touching
the vendored source -- catm puts it right after M2's output.

`x86/M2libc-windows/` is where the port actually lives. `bootstrap.c` is the
whole C library for the stages that can use `--bootstrap-mode`; `unistd.c`,
`fcntl.c` and `sys/stat.c` are the POSIX layer underneath M2libc's own
`stdio.c` for the stages that cannot. A file descriptor is a Windows HANDLE,
with 0, 1 and 2 still meaning the three standard streams -- no real handle is
that small, so nothing above can tell. `brk` has nothing to ask the kernel for,
since the image carries its writable memory with it, and `chmod` does nothing
and returns success, which is the honest answer on a system where a file is
executable because its PE header says so.

Everything M2libc's `unistd.h` and `sys/stat.h` declare is there.
`x86/M2libc-windows/ntdll.c` is what the rest of it stands on: `__ntdll(slot)`
hands back a routine ntdll-i386.hex2 resolved, and `__ntobject(path)` turns a
filename into the OBJECT_ATTRIBUTES around an NT path that every ntdll call
naming a file wants. `x86/M2libc-windows/ntdll-slots.h` says which slot is
which and is generated, from the same list `ntdll-i386.hex2` is, so the two
cannot drift apart. `x86/Development/posix-test.c` calls every routine once and
checks the answer.

Where Windows has no answer -- `chroot`, `mount`, `unshare`, `symlink`,
`mknod`, `fchdir` -- the call fails, and says why above itself. Failing is the
point: `chmod` returning 0 is honest because a PE runs on account of its
header, and `chroot` returning 0 would not be.

Calling ntdll from compiled C works because of an accident of M2-Planet's code
generator, and comes with a rule that has to be kept by hand. M2-Planet saves
the stack pointer in EBP before pushing arguments and restores it from there
afterwards, so it never adds back what it pushed -- which is what lets it call
stdcall routines that pop their own arguments. It also pushes the first
argument first, so every call below is written backwards. And it holds the
pointer it is about to call in EDX across the argument list without saving it,
so an argument that writes EDX -- a function call, a `*` or `/` or `%`, an
array subscript -- replaces the address about to be called, and the program
jumps to zero with nothing to say where it came from. That cost three
debugging rounds in one sitting, so `x86/Development/check_fnptr_args.py`
fails on one now, and is checked against all three.

`x86/M2libc-windows/process.c` is starting another program and waiting for it,
and it is the one place this port cannot keep the POSIX shape.

Windows does have a fork primitive. `NtCreateProcessEx` given a parent and no
section handle clones the parent's address space instead of mapping an image --
ReactOS's own `PspCreateProcess` reaches that branch and says *"This is a
clone!"* before declining to implement it -- and `RtlCloneUserProcess` wraps
it, makes a thread in the result, and is meant to return in both processes,
handing the child `STATUS_PROCESS_CLONED` where the parent gets
`STATUS_SUCCESS`.

It does not work, by any of the four routes in, all measured on Windows 11
22621:

| | |
| --- | --- |
| `RtlCloneUserProcess` | clones, and the child deadlocks or faults in loader init |
| `NtCreateProcessEx` | clones, and the clone cannot be given a thread |
| `NtCreateProcess` | the same, by the older name |
| `NtCreateUserProcess` | the supported one, which does not clone at all |

The parent gets success and a genuine cloned process -- two in `tasklist`, the
child reported `STATUS_PENDING` -- and the child's one thread, which is not
suspended, never reaches the first statement after the call. It is neither this
port's doing nor WOW64's: the identical call from 64-bit and from 32-bit
PowerShell clones the process and never returns in the child either.

Where it stops depends on the flags, and an earlier version of this section
saying otherwise was wrong. Without `NO_SYNCHRONIZE` the child **deadlocks**;
with it the child **runs and dies** of an access violation. The deadlock is an
inherited lock and is now understood. `RtlCloneUserProcess` holds the SRW lock
at `ntdll+0x12d7a4` exclusively across the clone, so the child's address space
is a snapshot in which it is held; the child's new thread then runs
`LdrInitializeThunk` like any new thread, loader init wants that same lock
shared, and it waits in `NtWaitForAlertByThreadId` to be alerted by a thread
that does not exist on this side of the fork. Read out of the suspended child:
EIP in `ZwWaitForAlertByThreadId`, the lock's address twice on the stack, and
`LdrInitializeThunk` further up it.

Zeroing that lock in the child before letting it go removes the deadlock, and
the child then gets exactly as far as the `NO_SYNCHRONIZE` one: an access
violation at `ntdll+0x8c5d6`, which is `mov eax, fs:0x18`, inside a function
whose only caller in the whole DLL is `LdrInitializeThunk`.

Loader init is the wrong thing for a fork's child to run at all, and there is a
flag for that -- `THREAD_CREATE_FLAGS_SKIP_LOADER_INIT` -- which
`NtCreateUserProcess` will not take, answering `STATUS_INVALID_PARAMETER`;
that is what "NtCreateThreadEx only" in the public headers means.
`NtCreateThreadEx` does take it, and against a clone that already has a thread
it returns `STATUS_SUCCESS`. The older claim that it always answers
`STATUS_PROCESS_IS_TERMINATING` holds only for the thread-less clones
`NtCreateProcessEx` and `NtCreateProcess` make.

That road is closed anyway, for a reason that has nothing to do with cloning:
**`SKIP_LOADER_INIT` cannot be used by a 32-bit process on a 64-bit Windows at
all.** Make such a thread in an ordinary process -- no clone anywhere near it --
point it at a function whose first act is one system call, and the process dies
of `STATUS_ACCESS_VIOLATION` at `ntdll+0x98800`, which is
`jmp dword ptr [Wow64Transition]`.

Why it dies there is the reason it cannot be worked around. Every 32-bit system
call is `mov eax,<number>; mov edx,[Wow64Transition]; call edx`, and what that
reaches is seven bytes in `wow64cpu.dll`:

    jmp  far 0x33:<next>          ; put the CPU in 64-bit mode
    jmp  qword ptr [r15+0xf8]     ; and dispatch through r15

The stub never loads `r15`. It is a register the 64-bit dispatch loop leaves
live when it hands control down to 32-bit code -- `BTCpuSimulate` sets `r12`
from `gs:0x30`, the 64-bit TEB, `r13` from the thread's WOW64 CPU area at
`TEB+0x1488`, and `r15` to wow64cpu's dispatch table, and then runs 32-bit code
with those still in registers. A thread enters that loop as part of its
startup, which is exactly what `SKIP_LOADER_INIT` skips, so its first system
call far-jumps into 64-bit mode with `r15` holding whatever was there and
dereferences it. The fault is reported against the last 32-bit instruction,
which is why the event log points at `ntdll` rather than at `wow64cpu`.

There is nothing to poke: `r15` is live register state, not memory. And the
whole problem is a 32-bit-on-64-bit one -- a native x86_64 program makes system
calls with the `syscall` instruction and has no dispatch loop to be thrown out
of, so this particular objection would not arise in an x86_64 port. It is not a
missing page either: the pointer holds the same value in the clone as in the
parent, the code it points at reads in both, and `NtQueryVirtualMemory` reports
the same `State`, the same `Protect` (`PAGE_EXECUTE_READ`) and the same `Type`.

So the child has to run loader init, and with the lock cleared it does, and
dies inside it at `mov eax, fs:0x18`. That is the one thing left.

It stops there because both obvious explanations are measured to be false: the thread has a real TEB -- `NtQueryInformationThread` gives its
address, the parent can read it, and the `Self` pointer at `TEB+0x18` matches
-- and its `FS` is the same `0x53` every thread in the parent runs with.
Telling the difference needs the faulting data address from an exception
record, which needs a debugger port rather than the event log's module offsets.
Worth knowing for whoever picks this up: the supported consumer of
`RtlCloneUserProcess` is process reflection, whose child is a passive snapshot
that is read and discarded rather than run, and nothing measured here rules out
a clone being unable to run ordinary code at all.

`__clone_process` keeps the call and the measurements; `fork` returns -1,
because a fork whose child never runs would hang the first caller to wait for
it.

So the three steps of fork-exec-wait, taken apart into ones Windows can do:

    __spawn(path, argv, envp)   start a program; a handle to it comes back
    waitpid(pid, &status, 0)    wait for one of those to finish
    execve(path, argv, envp)    both of the above, and then exit as it did

A pid is the process handle, the way a file descriptor is a file handle.
`execve` does not replace the running image, because nothing on Windows can,
but it does not return either and the process's exit status is the child's.
A caller that today says `fork()` then `execve` in the child and `waitpid` in
the parent says `__spawn` then `waitpid` instead, and needs no fork; that is
the change `kaem` and M2-Mesoplanet would want, and it is two lines.

The child inherits this process's three standard handles, which is what makes
redirection possible, and getting that right took one thing beyond the obvious.
The obvious part is that each handle is duplicated with `OBJ_INHERIT` and its
number written into the child's parameter block, where the child reads it back
out of its own PEB. Do only that and the child writes, `NtWriteFile` answers
`STATUS_SUCCESS` with a count in the `IO_STATUS_BLOCK`, and nothing arrives
anywhere -- under wine it works, on Windows it does not.

What happens in between is that the child's own startup replaces those handles.
It copies the parameter block onto its heap and fills the three handle fields
in with console handles of its own before the program's first instruction, so
the numbers the parent wrote are already gone, and writes to what replaced them
are accepted and discarded. Measured, with the child suspended and then asked
from the inside: its `PEB->ProcessParameters` is not the address the parent
poked, the handle it ends up with is not the one it was given, and
`NtQueryInformationFile` on it answers `STATUS_INVALID_DEVICE_REQUEST` where the
parent's own handle names the pipe it really is. The handle the parent
duplicated is still there and still works -- writing to it by number, from
inside the child, reaches the parent's pipe -- so what is lost is the three
fields, not the handles.

The flag that stops it is `STARTF_USESTDHANDLES`, in the parameter block's
`WindowFlags` at `0x68`. ReactOS's `SetUpHandles`
(`dll/win32/kernel32/client/console/init.c`) is the same decision written down:
it assigns the console's handles over the parameter block's only
`if ((dwStartupFlags & STARTF_USESTDHANDLES) == 0)`. A Win32 caller sets that
flag by filling in `STARTUPINFO`'s `hStdInput`, `hStdOutput` and `hStdError`,
and nothing in `RtlCreateUserProcess`'s arguments reaches it, so `__spawn`
writes it into the block directly. With it set the handles survive and a
child's output lands wherever the parent's does -- console, pipe or redirected
file, all three checked on Windows 11.

Two things are worth keeping from the way this was found. `NtCreateUserProcess`
called directly rather than through `RtlCreateUserProcess` was tried first,
because its `PS_ATTRIBUTE_LIST` is the only way to ask for
`PsAttributeStdHandleInfo` and `PsAlwaysDuplicate` -- "always duplicate standard
handles" -- and it does not fix this, since the replacement happens in the child
afterwards regardless. It needs every structure 8-aligned, `PS_CREATE_INFO`
holding `ULONGLONG`s and the kernel answering `STATUS_DATATYPE_MISALIGNMENT`
otherwise; with that done it returns `PsCreateSuccess` and the child runs. So
`__spawn` keeps `RtlCreateUserProcess`, which is the same call with less to get
wrong. And wine never had the problem for a reason that flatters nobody: it
does this in kernelbase rather than in ntdll -- `init_console_std_handles`,
called from `dlls/kernelbase/console.c` -- and a program that imports ntdll and
nothing else never loads kernelbase, so there is nothing there to overwrite the
three fields and the flag is never consulted. Every program this bootstrap
builds is such a program. Worth remembering as a shape rather than a detail:
wine agreeing is not evidence that Windows will.

Windows hands a child one string rather than a vector,
so `__spawn` joins argv into one and the child splits it again; both halves
follow `CommandLineToArgvW`, so an argument survives whatever is in it.
`C:\dir\` is the case that makes the rule worth following exactly rather than
approximately: quoted naively it ends `...dir\"`, and the reader takes that
backslash to be protecting the closing quote and swallows the rest of the
command line.

`x86/Development/spawn-test.c` starts a program, waits for it, reads back what
it exited with, and ends by calling `execve` and not coming back.

M1-macro is a fuller assembler than M0: more label and pointer widths, every
architecture stage0 supports in one binary. Upstream also runs this stage's
output through `blood-elf`, and this port does not, which is worth setting out
properly because everything downstream of here -- GNU Mes included -- runs
blood-elf too.

Three things go together, and all three are debugging. `--debug` makes
M2-Planet end its output with `:ELF_data` instead of `:ELF_end`. blood-elf
then reads that output and writes an ELF string table, symbol table and
section headers -- and the `:ELF_end` M2-Planet did not write. The "debug" ELF
header declares five sections and refers to `:ELF_section_headers`, which is
why it needs blood-elf's output to link at all. Drop `--debug`, drop blood-elf
and use the plain ELF header, and M2-Planet emits `:ELF_end` itself; the plain
header wants nothing from outside but that label and `:_start`. Which is
exactly the shape `PE32-i386.hex2` has, with `:PE_end` for `:ELF_end`.

So there is nothing to port, and the symbol table is what `objdump` and `gdb`
read and nothing else does. Checked on GNU Mes rather than argued: built at
`f244b14` twice with native tools, once as `kaem.run` ships and once with
`--debug` and blood-elf removed and the plain ELF header in place. Both
`bin/mes-m2` binaries run, agree character for character on a program
exercising recursion, `map`, `assq`, strings and `write`, and pass the same ten
of Mes's own tests. The blood-elf one is 232686 bytes and the other 131262:
the whole difference is the debugging information.

## Licence

GNU General Public License version 3 or later, as upstream is. See `LICENSE`.

`LICENSE.EXCEPTION` adds a permission under section 7 for embedding these files
and the binaries built from them in a package repository without the repository
as a whole becoming GPL, so long as these files themselves stay GPL.

## Thanks

To Jeremiah Orians and everyone on #bootstrappable, whose work this is a port
of. The design is theirs; the mistakes in this port are not.
