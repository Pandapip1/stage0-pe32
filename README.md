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

`x86/M2libc-windows/process.c` is starting another program and waiting for it.

`fork` works here, and not by any of the means Windows offers for it. Windows'
own fork primitive does not work at all, for reasons worth writing down and
written down below; what `fork` does instead is start this same program again
and overwrite the copy with this one. That is how Cygwin has always done it,
and it is possible here for a reason particular to this bootstrap:

`x86/PE32-i386.hex2` sets `IMAGE_FILE_RELOCS_STRIPPED` and does not set
`DYNAMIC_BASE`, so there is no relocation and no address-space layout
randomisation. The image is at `0x400000` in every process that runs it, it
runs to 128MB with code, globals and heap all inside it and all writable, and
even the stack the kernel hands out lands at the same address every time. So a
second copy of the same program is laid out identically to the first, and
copying memory from one into the other needs no fixups of any kind -- a pointer
means the same thing on both sides. A program built the ordinary way,
relocatable and randomised, could not do this. This one can only do it.

The awkward part is that the child has its own loader init to run, on that same
stack, before it can be trusted with anything -- so it is made to run all of its
own startup first and then stop dead. `_start` reads one word: a flag the parent
writes into it before letting it go, which is the only thing distinguishing a
fork child from an ordinary run. Seeing it set, the child does its loader init,
resolves ntdll, sets up the C library, and then parks in a spin instead of
calling `main`, saying so in a second word the parent watches. Its startup is
over and its stack is finished with. The parent suspends it, copies the image
from `0x401000` to the top of the heap and then its own committed stack over the
child's spent one, points the child's thread at where `fork` was going to return
with `0` in `EAX`, and lets it go. It comes up believing `fork` has just
returned 0, on its parent's stack, with its parent's memory.

Two details, because both cost a debugging round. The copy starts at
`0x401000` rather than the image base, because the page below is the PE header,
which the loader maps read-only; writing there answers `STATUS_PARTIAL_COPY`.
And the child is aimed at `fork`'s *caller*, not back into `fork` -- this
dialect begins every function with `mov_esi,esp`, so `[ESI]` is where `fork`
returns to and `ESI+4` is the stack its caller will have, and that frame is
above everything `fork`'s own later calls reuse. Aiming into `fork`'s middle
resumes onto slots the spawn and the copies have long since overwritten.

A file the parent had open is open in the child, at the same descriptor. That
is why the shared `open_file` asks for `OBJ_INHERIT`: an inheritable handle is
the one kind a child receives, and it receives it under the *same number*,
which is what keeps the number the copied memory is holding meaningful. POSIX
hands every descriptor to a child across both fork and exec unless it is marked
`FD_CLOEXEC`, and there is no `FD_CLOEXEC` here to ask for the other behaviour.
Only the shared copy asks for it: `hex0`, `hex1`, `hex2` and `catm` carry their
own `open_file`, none of them forks, and `hex0`'s bytes *are* the seed the
chain is checked against -- so changing theirs would move the trust anchor to
no purpose.

What it does not do: the child is a second process as far as Windows is
concerned, with its own pid and its own parent, so nothing that asks Windows
rather than this library will see a fork.

`x86/Development/fork-test.c` exercises it -- a local, something malloc handed
out, the child's output landing in the parent's stream, `waitpid` bringing back
what the child exited with, and `fork` with `execve` after it.

## Windows' own fork primitive, and why it is not used

Windows does have a fork primitive. `NtCreateProcessEx` given a parent and no
section handle clones the parent's address space instead of mapping an image --
ReactOS's own `PspCreateProcess` reaches that branch and says *"This is a
clone!"* before declining to implement it. An earlier version of this section
said `RtlCloneUserProcess` wraps that call. It does not: disassembling
`ntdll32.dll` shows it calling a private helper that ends in
`ZwCreateUserProcess`, the same syscall behind ordinary process creation, not
`NtCreateProcessEx`. Two unrelated clone paths through the kernel, not one
built on the other -- so a defect found in one says nothing about the other.
`RtlCloneUserProcess` makes
a thread in the result and is meant to return in both processes, handing the
child `STATUS_PROCESS_CLONED` where the parent gets `STATUS_SUCCESS`.

It does not work, by any of the four routes in, all measured on Windows 11
22621:

| | |
| --- | --- |
| `RtlCloneUserProcess` | clones, and the clone's child runs with no FS base |
| `NtCreateProcessEx` | clones, and the clone cannot be given a thread |
| `NtCreateProcess` | the same, by the older name |
| `NtCreateUserProcess` | the supported one, which does not clone at all |

The parent gets success and a genuine cloned process -- two in `tasklist`, the
child reported `STATUS_PENDING` -- and the child's one thread, which is not
suspended, never reaches the first statement after the call. It is not this
port's doing: the identical call from 64-bit and from 32-bit PowerShell clones
the process and never returns in the child either -- though see below for what
that observation does and does not establish.

How it stops depends on the flags. Without `NO_SYNCHRONIZE` the child
**deadlocks**; with it the child **runs and dies** of an access violation. Two
earlier versions of this section got this wrong in opposite directions -- one
said the outcome was the same for every flag combination, the next said the
child stopped in a different *place* depending on them. It stops in the same
place either way; what the flags change is whether it can say so. The deadlock is an
inherited lock. `RtlCloneUserProcess` holds the SRW lock at `ntdll+0x12d7a4`
exclusively across the clone -- disassembling it shows that address four times
inside the one routine -- so the child's address space is a snapshot in which it
is held, and anything on the child's side that wants it shared waits in
`NtWaitForAlertByThreadId` to be alerted by a thread that does not exist on this
side of the fork. Read out of the child: EIP in `ZwWaitForAlertByThreadId`, the
lock's address twice on the stack, and `LdrInitializeThunk` further up it.

An earlier version of this section called that "now understood" and put the
deadlock first, with the `fs:0x18` fault below as a second, later failure that
only shows up once the lock is out of the way. That is backwards, and the same
stack that settled the `LdrInitializeThunk` question says so. Without touching
the lock at all, the deadlocked child's stack holds, above the frames it is
currently in:

    0x85ff300   an EXCEPTION_RECORD: ExceptionCode 0xc0000005,
                ExceptionAddress ntdll+0x8c5d6, NumberParameters 2,
                ExceptionInformation 0 (a read) and 0x18
    0x85ff350   the CONTEXT paired with it: ContextFlags 0x1007f,
                Eip ntdll+0x8c5d6, Cs 0x23, Esp 0x85ff7b8, SegFs 0x53
    0x85ff2ec   a return address in KiUserExceptionDispatcher+0x26

and below that nothing but exception dispatch -- `RtlUnwind`,
`_except_handler4_common`, `_local_unwind4` -- ending in
`RtlAcquireSRWLockShared+0x148` with `ntdll+0x12d7a4` as its argument, at
`ZwWaitForAlertByThreadId`.

So the fault comes first, every time, lock or no lock. What waits on the
inherited lock is the *exception dispatcher*, trying to report a fault that has
already happened. The child is not stopped short of the fault by a lock; it is
stopped short of ever saying so. Zeroing the lock does not let the child get
further, it lets the fault be reported, so the process dies instead of hanging.
One defect, not two, and the second symptom was only ever the first one being
unable to speak.

That "like any new thread" is worth checking rather than assuming, since the
clone's own thread was a real, running thread before the clone -- it had a
working FS base once, or it could not have gotten anywhere, so something
about the clone loses what it already had. Whether the clone is dispatched
exactly like a brand-new thread (EIP set to 32-bit `LdrInitializeThunk` from
the start, the same place a genuinely new WOW64 thread's native bring-up
hands off to) or instead resumes wherever the parent was -- inside
`RtlCloneUserProcess` itself, the way POSIX `fork` resumes both sides from
the same program counter -- is answerable without running anything: clone
with `CREATE_SUSPENDED`, never resume, and read `NtGetContextThread` before
the thread has executed a single instruction. Measured: `Eip` is
`ZwCreateUserProcess+0xc`, `Cs` is `0x23`. Not `LdrInitializeThunk`.
`ZwCreateUserProcess+0xc` is inside that syscall's own stub, right where `mov
eax,<number>; mov edx,[Wow64Transition]; call edx` returns -- so the clone's
saved context is not "start a new thread", it is "come back from this same
system call", exactly the way a POSIX fork's child continues from the same
program counter as its parent. `Cs` already being `0x23` says the mode
switch back to 32-bit was already done by whoever built this context, same
as everywhere else in this section.

That sat in tension with "the child's new thread then runs
`LdrInitializeThunk`" above, which was read off the stack of an actually
resumed, actually deadlocked child rather than off its context before running,
and the tension is now settled: both readings are right, and neither of the two
guesses about which one described the entry point was. Clone with
`CREATE_SUSPENDED`, read the context, resume, wait, read the context again and
read the stack it deadlocked on. Before resuming, `Eip` is
`ZwCreateUserProcess+0xc` and `Esp` is `0x85ffce8`. After, `Eip` is
`ZwWaitForAlertByThreadId+0xc`, and on the stack, from the top down:

    0x85ffce8                the Esp the context before resuming had
    0x85ffa1c..0x85ffce8     a whole 716-byte i386 CONTEXT, ContextFlags
                             0x1003f, Eip ZwCreateUserProcess+0xc,
                             Cs 0x23, Esp 0x85ffce8
    0x85ffa10                a pointer to 0x85ffa1c
    0x85ffa00                a return address in LdrInitializeThunk+0x11
    0x85ff9ec                another, LdrInitializeThunk+0x70

So the thread's first 32-bit instruction is 32-bit `LdrInitializeThunk`,
entered with a pointer to a `CONTEXT` written immediately beneath the parent's
stack pointer -- 716 bytes of it, ending exactly at `0x85ffce8` -- and that
`CONTEXT` is precisely what `NtGetContextThread` reported before the thread
ran. The pre-resume context is the *destination*, not the entry point: loader
init runs first and is meant to continue into it when it is done, which is the
same shape as a genuinely new WOW64 thread, whose 32-bit side also begins in
`LdrInitializeThunk` with a context to resume. Nothing detours; the detour
**is** the start, and the "true" context is where it was always going to end
up.

Which is a nicer answer than either guess. The clone is dispatched like a
brand-new thread *and* it resumes from the same program counter as its parent
-- the first describes where it begins, the second where loader init would hand
it off to, and there was never a contradiction between them. No debug port was
needed for this after all; the stack said it.

Zeroing that lock in the child before letting it go therefore turns the hang
into what `NO_SYNCHRONIZE` already showed: an access violation at
`ntdll+0x8c5d6`, which is `mov eax, fs:0x18`, inside a function whose only
caller in the whole DLL is `LdrInitializeThunk`. The same fault either way --
only its reporting differs.

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
of, so this particular objection would not arise in an x86_64 port.

Worth tracing further than "nothing to poke", because the actual question is
whether that setup can be run again, later, from user mode -- and the answer
is no, for a reason worth having by name rather than by symptom. A new WOW64
thread's real first instruction is not 32-bit at all: the kernel
(`nt!PspAllocateThread` / `PspWow64InitThread`) hands it a synthetic exception
whose address is the **64-bit** ntdll's own `LdrInitializeThunk`.
Disassembling that export in `ntdll64.dll` shows exactly the gate this
predicts: a bit test against a flag word in the 64-bit TEB (`test word
[rax+0x17ee], 0x4000`, `rax` from `mov rax, gs:0x30`) that skips a call when
already set and takes it on a fresh thread -- the call being the one-time
WOW64 bring-up. Public research on this exact sequence -- [wbenny, "WoW64
internals",
2018](https://wbenny.github.io/2018/11/04/wow64-internals.html) -- names
every step the disassembly only shows the shape of: `LdrInitializeThunk` ->
`LdrpInitialize` -> `LdrpLoadWow64`, which loads `wow64.dll` and hands off to
`Wow64LdrpInitialize`, which calls `ProcessInit` and `ThreadInit` (this is
where `r12` and `r13` come from, via `RtlWow64GetCpuAreaInfo`) and then
`RunCpuSimulation`, which calls `wow64cpu!BTCpuSimulate`, which sets `r15` and
enters `RunSimulatedCode` -- the loop that never returns and is what finally
executes a 32-bit instruction for this thread, for the first time. Every part
of that chain runs in 64-bit mode, reached only by the kernel choosing
`LdrInitializeThunk` as where a new thread starts. `SKIP_LOADER_INIT` is
exactly the kernel choosing something else instead -- the caller's 32-bit
`StartRoutine`, directly -- which is why the fault above is a clean 32-bit
instruction at a sensible ntdll address rather than garbage: the mode switch
to `CS=0x23` did happen, correctly, by whatever set up the thread's context
in the first place. What did not happen is everything upstream of it. There
is no way from the 32-bit side to reach that chain after the fact: the only
sanctioned 32-to-64 transition a WOW64 thread has is the one at the top of
this section, and it needs `r15` to work -- which is exactly what is
missing. Asking it to bootstrap itself is circular, not merely hard.

It is not a missing page either: the pointer holds the same value in the
clone as in the parent, the code it points at reads in both, and
`NtQueryVirtualMemory` reports the same `State`, the same `Protect`
(`PAGE_EXECUTE_READ`) and the same `Type`.

So the child has to run loader init, and with the lock cleared it does, and
dies inside it at `mov eax, fs:0x18`. Attaching a debug port to the clone --
`NtCreateDebugObject` and `NtDebugActiveProcess`, so it stops at the fault
instead of dying of it -- says what that is:

    ExceptionCode     0xc0000005
    ExceptionAddress  ntdll+0x8c5d6      ; mov eax, fs:0x18
    access            0                  ; a read
    faulting address  0x18
    SegFs             0x53
    SegCs             0x23
    TebBaseAddress    0x21e000

It reads `fs:0x18` and faults on linear address `0x18`, so **the base behind FS
is zero**. Not the selector -- `0x53` is the right one -- and not the TEB, which
exists and can be read from the parent. The descriptor that selector names
simply has no base.

Which *looks* like the same illness as the `r15` one. A 32-bit process on a
64-bit Windows runs inside a WOW64 layer: the kernel programs the
compatibility-mode TEB base for each thread, and the 64-bit dispatch loop keeps
`r12`, `r13` and `r15` live for it. Both are established when a process and its
threads are made the ordinary way, and a clone is not made the ordinary way.

That is as far as the evidence goes, and it is worth being careful about how far
that is. What is measured is that **this** clone's child has an FS with no base.
What is **not** established is the tempting generalisation -- that a cloned
32-bit process can never have WOW64 state -- because something in ntdll says
otherwise, loudly. `RtlCreateProcessReflection`, the only caller
`RtlCloneUserProcess` has in the whole 32-bit ntdll, does this in its child on
getting `STATUS_PROCESS_CLONED` back:

    ba979:  mov eax, fs:0x30      ; reads FS straight away
    ba9c9:  call esi              ; then calls a caller's start routine

So Windows expects a clone's child to have a working FS and to run ordinary
code. Either reflection is broken here for every 32-bit process on the machine,
or reflection does something this code does not and the direct use of
`RtlCloneUserProcess` is what is wrong. Trying to settle it did not settle it:
called on a spawned copy of this program, both with a start routine and with
none at all -- the plain passive snapshot reflection is actually for --
`RtlCreateProcessReflection` does not return, and the calling process
disappears without so much as a fault record. That is not understood either, and
a conclusion built on top of it would not be worth having.

One check does not depend on any of the above, and is worth doing on its own:
whether this machine can clone a 32-bit process by *any* in-box route at all,
which would rule the whole failure in or out as a platform limit rather than a
misuse of one specific call.
[`PssCaptureSnapshot`](https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/nf-processsnapshot-psscapturesnapshot),
the documented Windows 8.1+ snapshotting API, says yes: called against a real
32-bit `cmd.exe` with
[`PSS_CAPTURE_VA_CLONE`](https://learn.microsoft.com/en-us/windows/win32/api/processsnapshot/ne-processsnapshot-pss_capture_flags)
it returns `ERROR_SUCCESS`, and
[`PssQuerySnapshot`](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/api/processsnapshot/nf-processsnapshot-pssquerysnapshot)`(PSS_QUERY_VA_CLONE_INFORMATION)`
hands back a clone process handle that `GetExitCodeProcess` reports
`STILL_ACTIVE` and `IsWow64Process` reports genuinely 32-bit. So this machine,
this hypervisor, this WOW64 -- none of them are categorically incapable of a
working 32-bit clone.

That does not settle the question above, though, and claiming it did would be
the same mistake again. `PssCaptureSnapshot` is not `RtlCloneUserProcess` by
another name: internally it calls `PssNtCaptureSnapshot`, which -- per
[Hunt & Hackett's write-up of process cloning on
Windows](https://www.huntandhackett.com/blog/the-definitive-guide-to-process-cloning-on-windows)
-- relies on `NtCreateProcessEx`-based cloning: the very call
`PspCreateProcess` was seen declining to implement, and, per the correction
above, a different syscall from the one `RtlCloneUserProcess` actually uses.
What is confirmed is narrower than "cloning works here": the
`NtCreateProcessEx` clone path works, completely, for a 32-bit target, with
whatever WOW64 setup that path does that `RtlCloneUserProcess`'s does not.
Whether `RtlCloneUserProcess`'s own path -- through `ZwCreateUserProcess` --
shares that defect, has a different one, or has none at all under different
handling is exactly as open as it was. What this does rule out is the
broadest excuse available: "this VM just can't do it." Something here can.
Whether the thing `__clone_process` calls is that something remains unknown.

One question about `RtlCloneUserProcess`'s own clone can be answered without
running anything on the side that is broken: is the FS-with-no-base defect a
property of the one thread the clone hands back, or of the clone process
itself? Clone with `CREATE_SUSPENDED` and never resume that thread -- so
neither the lock deadlock nor the FS fault above can happen -- and ask
`NtQueryInformationProcess(ProcessWow64Information, class 26)` about the
child's process handle. It answers with a real PEB32 address, not zero and
not a failing status. So the clone's process-level WOW64 association came
through intact; what is missing is scoped to the one thread, not the process.
That keeps open a narrower question than the one above: whether a thread made
the ordinary way afterwards -- fresh, with `NtCreateThreadEx`, never touching
the cloned thread at all -- would get the segment setup that thread did not.

Tried, and inconclusive rather than answered. `RtlExitUserThread` needs no
hand-written assembly to satisfy "never returns through an ordinary call
frame": it is documented `DECLSPEC_NORETURN`, and handed to
`NtCreateThreadEx` directly as `StartRoutine` with a distinctive `NTSTATUS`
as `Argument`, it ends the (single) thread -- and so the process -- with that
value if it ever gets there. Against the clone: `STATUS_ACCESS_DENIED`, even
from a handle freshly opened with `NtOpenProcess` asking for
`PROCESS_ALL_ACCESS` -- which is not a DACL problem, since `NtOpenProcess`
granting that access is itself proof the security check already passed, and
`NtCreateThreadEx` failed anyway with the same already-granted handle. So
this was not going to settle the clone question either way, which running the
identical sequence against an ordinary `__spawn` child instead of a clone
confirmed: `STATUS_ACCESS_DENIED` there too. The conclusion drawn from that --
that cross-process thread creation is refused here as a matter of the caller's
privileges, `SeDebugPrivilege` not being enabled -- is wrong, and wrong in both
halves.

`SeDebugPrivilege` does not need `advapi32` to reach.
[`RtlAdjustPrivilege`](https://ntdoc.m417z.com/rtladjustprivilege) is an
`ntdll` export, and it takes the privilege as a plain `ULONG` LUID rather than
the `LUID_AND_ATTRIBUTES` that
[`LookupPrivilegeValue`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluew)
exists to fill in, so the objection about it being out of reach of an
ntdll-only port was simply mistaken. The number is 20, which is what phnt's
`ntseapi.h` calls
[`SE_DEBUG_PRIVILEGE`](https://ntdoc.m417z.com/se_debug_privilege) -- and
rather than take that on faith,
`LookupPrivilegeValue("SeDebugPrivilege")` was asked on this machine and
answers 20 as well.

And the privilege was never missing. `RtlAdjustPrivilege(20, TRUE, FALSE,
&was)` from inside the probe returns `STATUS_SUCCESS` with `WasEnabled`
already 1: this token has had `SeDebugPrivilege` enabled the whole time, which
`whoami /priv` agrees with. So the denial had some other cause, and the
likeliest is a handle asked for too little rather than a caller granted too
little. A missing access right is indistinguishable from a missing privilege
from the outside -- both are `STATUS_ACCESS_DENIED` -- and this port walked
into that again while writing the probes below: `NtGetContextThread` on a
thread handle created without
[`THREAD_GET_CONTEXT`](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights)
answers `STATUS_ACCESS_DENIED` and nothing else.

Written again and measured, cross-process thread creation is not refused here
at all. [`NtCreateThreadEx`](https://ntdoc.m417z.com/ntcreatethreadex) into an
ordinary `__spawn` child, with a `DesiredAccess` made of bits that are written
down -- `SYNCHRONIZE`, `THREAD_TERMINATE`, `THREAD_SUSPEND_RESUME`,
`THREAD_QUERY_INFORMATION` -- and `RtlExitUserProcess` as `StartRoutine` with
`0x5a5a` as its `Argument`, returns `STATUS_SUCCESS`, and the child exits with
`0x5a5a`. A fresh thread in another process runs, and runs ordinary code that
reaches the system. `THREAD_ALL_ACCESS` is deliberately not used for this: its
value is not written down anywhere authoritative, and those four bits are.

The same injection with `CreateFlags = THREAD_CREATE_FLAGS_SKIP_LOADER_INIT`
also returns `STATUS_SUCCESS`, and the child then dies of
`STATUS_ACCESS_VIOLATION` -- the `r15` finding above, reproduced across a
process boundary rather than within one.

Which finally makes the fresh-thread question above answerable, and the answer
is no. Clone with `CREATE_SUSPENDED`, never resume the clone's own thread at
all, and inject the same `RtlExitUserProcess` thread into the clone:
`NtCreateThreadEx` returns `STATUS_SUCCESS`. Two seconds later the clone has not
exited -- `NtWaitForSingleObject` times out, `ExitStatus` is still
`STATUS_PENDING` -- and
[`NtGetContextThread`](https://ntdoc.m417z.com/ntgetcontextthread) on the thread
just made reports `Eip` `RtlUserThreadStart`, `Cs` `0x23`, `SegFs` `0x53` and
`Esp` `0x8a7fff0`, the very top of its own fresh stack. That is its initial
context, unchanged: the thread has not executed one 32-bit instruction.

Zeroing the inherited loader lock first makes no difference to that, which
places whatever holds it up upstream of any 32-bit code at all -- in the native
bring-up, or in the kernel, not in the 32-bit loader. And the control says the
call itself is sound: the identical injection into an ordinary `__spawn` child
runs and exits with the value it was handed.

So a thread made the ordinary way in a clone does not get the segment setup the
cloned thread lacked, because it never gets as far as needing it. Not refused,
not faulting, not deadlocked in the 32-bit loader: it never starts. The clone
has a PEB32 and a process-level WOW64 association, and still no thread of any
provenance runs 32-bit code in it. Where in the 64-bit bring-up that stops is
what anyone picking this up would have to find next, and it cannot be found from
the 32-bit side -- the same wall the `r15` finding ends at.

So `fork` stops here, at an FS with no base, for a reason not yet pinned on
either Windows or this code. Whichever it is, nothing in reach fixes it from
user mode: a segment base lives in a descriptor the kernel owns, and the `SegFs`
in a 32-bit `CONTEXT` is the selector, which is already right.

The `r15` finding does not depend on any of this. That one was measured with no
clone anywhere near it, and it stands on its own.

An earlier version of this section said the failure was "neither this port's
doing nor WOW64's", on the strength of the same call failing from 64-bit
PowerShell. That was the wrong conclusion from a true observation: the
PowerShell child was stopped by the inherited lock, a different failure, and one
since fixed here. Being 32-bit on a 64-bit Windows is at least what the `r15`
objection is. A native x86_64 program has no WOW64 layer -- `syscall` for system
calls, and its TEB through `GS`, whose base the kernel programs for every thread
-- so the question is worth asking again, from scratch, in an x86_64 port.

`__clone_process` keeps the call and the measurements, and is not called. A
system where the clone worked would get a cheaper fork than the one above for
free, so the measurements are worth keeping even now that they are not on the
path anything takes.

So four calls, and a caller wanting a child may say either what POSIX says or
the shorter thing Windows can do directly:

    fork()                      twice-returning, 0 in the child
    __spawn(path, argv, envp)   start a program; a handle to it comes back
    waitpid(pid, &status, 0)    wait for one of those to finish
    execve(path, argv, envp)    both of the above, and then exit as it did

`fork` and `execve` together do what fork and exec do anywhere. `__spawn` is
the cheaper way to say the same thing when the child is only ever going to
exec: one process where fork plus execve is two.

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
