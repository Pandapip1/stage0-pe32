#!/usr/bin/env python3
# SPDX-FileCopyrightText: (C) 2026 Gavin John
#
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate hex0_pe32 (annotated .hex0 + .exe) with upstream stage0 hex0 semantics.

Upstream (stage0-posix High Level Prototypes/hex0.c, x86/hex0_x86.hex0):
    input  = fopen(argv[1], "r")     -- required
    output = fopen(argv[2], "w")     -- required by the asm build
    '#' and ';' both begin a line comment
"""
import struct, sys

IMAGE_BASE   = 0x400000
SECT_ALIGN   = 0x1000
FILE_ALIGN   = 0x200
HDR_SIZE     = 0x200
CODE_RVA     = 0x1000

R = dict(eax=0, ecx=1, edx=2, ebx=3, esp=4, ebp=5, esi=6, edi=7)

class Asm:
    def __init__(self):
        self.items = []          # (kind, size, payload, comment, meta)
        self.labels = {}
        self.bss = []            # (name, size) reserved past the file image
        self.org = CODE_RVA + IMAGE_BASE

    def label(self, name):
        self.items.append(("label", 0, name, None, None))

    def reserve(self, name, size, note=None):
        """Reserve zeroed space past the end of the file: VirtualSize exceeds
        SizeOfRawData and the loader zero-fills the difference, so a large
        table costs nothing in the source."""
        self.bss.append((name, size, note))

    def note(self, text):
        self.items.append(("note", 0, text, None, None))

    def raw(self, bs, comment=None):
        self.items.append(("raw", len(bs), bytes(bs), comment, None))

    def patch(self, size, fn, comment=None, meta=None):
        """fn(addr_of_this_field, labels) -> int"""
        self.items.append(("patch", size, fn, comment, meta))

    # ---- layout / emit -------------------------------------------------
    def _layout(self):
        addr = self.org
        self.labels = {}
        for kind, size, payload, _c, _m in self.items:
            if kind == "label":
                self.labels[payload] = addr
            elif kind != "note":
                addr += size
        self.image_end = addr
        for name, size, _n in self.bss:
            self.labels[name] = addr
            addr += size
        return addr

    def assemble(self):
        for _ in range(3):
            end = self._layout()
        out = bytearray()
        lines = []
        addr = self.org
        for kind, size, payload, comment, meta in self.items:
            if kind in ("label", "note"):
                lines.append((kind, payload, None, meta))
                continue
            if kind == "raw":
                bs = payload
            else:
                v = payload(addr, self.labels)
                bs = struct.pack("<i" if v < 0 else "<I", v)[:size] if size == 4 else \
                     struct.pack("<b" if v < 0 else "<B", v)[:1] if size == 1 else \
                     struct.pack("<h" if v < 0 else "<H", v)[:2]
            out += bs
            lines.append(("bytes", bs, comment, meta))
            addr += size
        return bytes(out), lines, self.labels

    # ---- instruction helpers ------------------------------------------
    # Every helper knows its own mnemonic; the caller supplies only the prose.
    # The two are joined with "  -- " and split apart again at emit time into
    # the ';' mnemonic column and the '#' prose column.
    @staticmethod
    def _c(mn, prose):
        if prose and prose.startswith(mn):
            prose = prose[len(mn):].lstrip(" -")
        return mn + ("  -- " + prose if prose else "")

    @staticmethod
    def _imm(v):
        return ("-0x%x" % -v) if v < 0 else ("0x%x" % v)

    def _rel32(self, target, prose, opc, mn):
        self.raw(opc)
        self.patch(4, lambda a, L, t=target: L[t] - (a + 4), self._c(mn, prose),
                   meta=("rel32", target))

    def call(self, target, prose=None):
        self._rel32(target, prose, b"\xe8", "call %s" % target)

    def jmp(self, target, prose=None):
        self._rel32(target, prose, b"\xe9", "jmp %s" % target)

    def jcc(self, cc, target, prose=None):
        opc = {"e":0x84,"ne":0x85,"l":0x8c,"ge":0x8d,"s":0x88,"g":0x8f,"le":0x8e,"be":0x86,"a":0x87}[cc]
        self._rel32(target, prose, bytes([0x0f, opc]), "j%s %s" % (cc, target))

    def push_imm(self, v, prose=None):
        mn = "push %s" % self._imm(v)
        if -0x80 <= v <= 0x7f:
            self.raw(bytes([0x6a, v & 0xff]), self._c(mn, prose))
        else:
            self.raw(b"\x68" + struct.pack("<i" if v < 0 else "<I", v), self._c(mn, prose))

    def push_lbl(self, name, prose=None):
        self.raw(b"\x68"); self.patch(4, lambda a, L, n=name: L[n], self._c("push %s" % name, prose))

    def push_mem(self, name, prose=None):
        self.raw(b"\xff\x35"); self.patch(4, lambda a, L, n=name: L[n], self._c("push dword [%s]" % name, prose))

    def call_mem(self, name, prose=None):
        self.raw(b"\xff\x15"); self.patch(4, lambda a, L, n=name: L[n], self._c("call [%s]" % name, prose))

    def push_r(self, r, prose=None): self.raw(bytes([0x50 + R[r]]), self._c("push %s" % r, prose))
    def pop_r(self, r, prose=None):  self.raw(bytes([0x58 + R[r]]), self._c("pop %s" % r, prose))
    def ret(self, prose=None):       self.raw(b"\xc3", self._c("ret", prose))

    def mov_r_mem(self, r, name, prose=None):
        if r == "eax":
            self.raw(b"\xa1")
        else:
            self.raw(bytes([0x8b, (R[r] << 3) | 0x05]))
        self.patch(4, lambda a, L, n=name: L[n], self._c("mov %s, [%s]" % (r, name), prose))

    def mov_mem_r(self, name, r, prose=None):
        if r == "eax":
            self.raw(b"\xa3")
        else:
            self.raw(bytes([0x89, (R[r] << 3) | 0x05]))
        self.patch(4, lambda a, L, n=name: L[n], self._c("mov [%s], %s" % (name, r), prose))

    def _slot(self, name, off):
        return name if not off else "%s+%d" % (name, off)

    def mov_mem_imm(self, name, v, prose=None, off=0):
        self.raw(b"\xc7\x05")
        self.patch(4, lambda a, L, n=name, o=off: L[n] + o, None)
        self.raw(struct.pack("<i" if v < 0 else "<I", v),
                 self._c("mov dword [%s], %s" % (self._slot(name, off), self._imm(v)), prose))

    def mov_mem_lbl(self, name, target, prose=None, off=0):
        self.raw(b"\xc7\x05")
        self.patch(4, lambda a, L, n=name, o=off: L[n] + o, None)
        self.patch(4, lambda a, L, t=target: L[t],
                   self._c("mov dword [%s], %s" % (self._slot(name, off), target), prose))

    def mov_r_imm(self, r, v, prose=None):
        self.raw(bytes([0xb8 + R[r]]) + struct.pack("<i" if v < 0 else "<I", v),
                 self._c("mov %s, %s" % (r, self._imm(v)), prose))

    def mov_r_lbl(self, r, name, prose=None):
        self.raw(bytes([0xb8 + R[r]])); self.patch(4, lambda a, L, n=name: L[n], self._c("mov %s, %s" % (r, name), prose))

    def add_r_lbl(self, r, name, prose=None):
        self.raw(bytes([0x81, 0xc0 + R[r]])); self.patch(4, lambda a, L, n=name: L[n], self._c("add %s, %s" % (r, name), prose))

    def add_mem_reg(self, name, r, prose=None):
        self.raw(bytes([0x01, (R[r] << 3) | 0x05])); self.patch(4, lambda a, L, n=name: L[n], self._c("add [%s], %s" % (name, r), prose))

    def cmp_r_mem(self, r, name, prose=None):
        self.raw(bytes([0x3b, (R[r] << 3) | 0x05])); self.patch(4, lambda a, L, n=name: L[n], self._c("cmp %s, [%s]" % (r, name), prose))

    def mov_eax_idx4(self, name, prose=None):
        self.raw(b"\x8b\x04\xbd"); self.patch(4, lambda a, L, n=name: L[n], self._c("mov eax, [edi*4 + %s]" % name, prose))

    def mov_idx4_eax(self, name, prose=None):
        self.raw(b"\x89\x04\xbd"); self.patch(4, lambda a, L, n=name: L[n], self._c("mov [edi*4 + %s], eax" % name, prose))

    def add_eax_lbl(self, name, prose=None):
        self.raw(b"\x05"); self.patch(4, lambda a, L, n=name: L[n], self._c("add eax, %s" % name, prose))

    def sub_eax_mem(self, name, prose=None):
        self.raw(b"\x2b\x05"); self.patch(4, lambda a, L, n=name: L[n], self._c("sub eax, [%s]" % name, prose))

    def not_mem(self, name, prose=None):
        self.raw(b"\xf7\x15"); self.patch(4, lambda a, L, n=name: L[n], self._c("not dword [%s]" % name, prose))

    def add_mem_imm8(self, name, v, prose=None):
        self.raw(b"\x83\x05"); self.patch(4, lambda a, L, n=name: L[n], None)
        self.raw(bytes([v & 0xff]), self._c("add dword [%s], %d" % (name, v), prose))

    def movzx_eax_mem(self, name, prose=None):
        self.raw(b"\x0f\xb6\x05"); self.patch(4, lambda a, L, n=name: L[n], self._c("movzx eax, byte [%s]" % name, prose))

    def mov_mem_al(self, name, prose=None):
        self.raw(b"\xa2"); self.patch(4, lambda a, L, n=name: L[n], self._c("mov [%s], al" % name, prose))

    def cmp_mem_imm8(self, name, v, prose=None):
        self.raw(b"\x83\x3d"); self.patch(4, lambda a, L, n=name: L[n], None)
        self.raw(bytes([v & 0xff]), self._c("cmp dword [%s], %s" % (name, self._imm(v)), prose))

    def cmp_mem_imm32(self, name, v, prose=None):
        self.raw(b"\x81\x3d"); self.patch(4, lambda a, L, n=name: L[n], None)
        self.raw(struct.pack("<i", v), self._c("cmp dword [%s], %s" % (name, self._imm(v)), prose))


# ===================== PE emitter =====================
def datline(bs, comment):
    h = " ".join("%02X" % b for b in bs)
    return ("%-31s # %s" % (h, comment)).rstrip() if comment else h

def insnline(bs, comment):
    h = " ".join("%02X" % b for b in bs)
    if not comment:
        return "\t" + h
    mn, _, prose = comment.partition("  -- ")
    if not prose:
        return ("\t%-27s ; %s" % (h, mn)).rstrip()
    return ("\t%-27s ; %-27s # %s" % (h, mn, prose)).rstrip()

UPSTREAM = "2016-2021 Jeremiah Orians"
PORT     = "2026 Gavin John"

def spdx(holders):
    """The licence banner every file in this project carries, in the shape
    reuse.software expects and upstream stage0 uses."""
    L = ["SPDX-FileCopyrightText: (C) " + h for h in holders]
    return L + ["", "SPDX-License-Identifier: GPL-3.0-or-later",
                "Additional permission under GNU GPL version 3 section 7:",
                "see LICENSE.EXCEPTION in the root of this project.", "", ""]

def block(text, prefix="# "):
    return [(prefix + l).rstrip() for l in text.split("\n")]

def assemble_hex0(src):
    """hex0: hex digit pairs become bytes; '#' and ';' begin comments."""
    o = bytearray(); hi = None; i = 0
    while i < len(src):
        c = src[i]
        if c in (0x23, 0x3b):
            while i < len(src) and src[i] != 0x0a: i += 1
            continue
        ch = chr(c)
        if ch in "0123456789abcdefABCDEF":
            v = int(ch, 16)
            if hi is None: hi = v
            else: o.append(hi * 16 + v); hi = None
        i += 1
    return o

def assemble_hex1(src):
    """hex1: hex0 plus ':X' labels and '%X' four-byte relative pointers,
    resolved over two passes exactly as the ported hex1 does."""
    def walk(emit, table):
        o = bytearray(); ip = 0; hi = None; i = 0
        while i < len(src):
            c = src[i]
            if c in (0x23, 0x3b):
                while i < len(src) and src[i] != 0x0a: i += 1
                continue
            if c == 0x3a:                      # ':' label
                i += 2
                if not emit: table[src[i - 1]] = ip
                continue
            if c == 0x25:                      # '%' pointer
                name = src[i + 1]; i += 2; ip += 4
                if emit:
                    o += struct.pack("<i", table.get(name, 0) - ip)
                continue
            ch = chr(c)
            if ch in "0123456789abcdefABCDEF":
                v = int(ch, 16)
                if hi is None: hi = v
                else:
                    if emit: o.append(hi * 16 + v)
                    ip += 1; hi = None
            i += 1
        return o
    table = {}
    walk(False, table)
    return walk(True, table)

def pechecksum(b, o):
    b = bytearray(b); struct.pack_into("<I", b, o, 0)
    s = 0
    for i in range(0, len(b) & ~1, 2):
        s += struct.unpack_from("<H", b, i)[0]; s = (s & 0xffff) + (s >> 16)
    s = (s >> 16) + (s & 0xffff); s = (s >> 16) + (s & 0xffff)
    return (s + len(b)) & 0xffffffff

def emit_pe(a, banner, DOC, data_label, out_exe, out_hex, dos_source, exe_name, lang="hex0"):
    body, lines, labels = a.assemble()
    bss_total = sum(sz for _n, sz, _c in a.bss)
    vsize = len(body) + bss_total          # VirtualSize: the loader zero-fills past the file
    raw = len(body)                        # no padding: the file ends where the program does
    image = (CODE_RVA + vsize + SECT_ALIGN - 1) // SECT_ALIGN * SECT_ALIGN
    entry = labels["_start"] - IMAGE_BASE

    dos = open(dos_source, "rb").read()[:0x40]
    assert len(dos) == 0x40 and dos[:2] == b"MZ" and struct.unpack_from("<I", dos, 0x3c)[0] == 0x40
    coff = b"PE\0\0" + struct.pack("<HHIIIHH", 0x14c, 1, 0, 0, 0, 0x60, 0x030f)
    opt = struct.pack("<HBBIIIIII", 0x10b, 2, 0x29, raw, 0, 0, entry, CODE_RVA, CODE_RVA + raw)
    opt += struct.pack("<III", IMAGE_BASE, SECT_ALIGN, FILE_ALIGN)
    opt += struct.pack("<HHHHHHI", 4, 0, 1, 0, 4, 0, 0)
    opt += struct.pack("<IIIHH", image, HDR_SIZE, 0, 3, 0x0100)
    opt += struct.pack("<IIII", 0x200000, 0x1000, 0x100000, 0x1000)
    opt += struct.pack("<II", 0, 0)
    assert len(opt) == 0x60
    sect = b".text\0\0\0" + struct.pack("<IIII", vsize, CODE_RVA, raw, HDR_SIZE) + b"\0" * 12 + struct.pack("<I", 0xE0000020)
    hdr = dos + coff + opt + sect
    hdr += b"\0" * (HDR_SIZE - len(hdr))
    exe = bytearray(hdr + body)
    CKOFF = 0x40 + 24 + 64
    ck = pechecksum(exe, CKOFF)
    struct.pack_into("<I", exe, CKOFF, ck)
    exe = bytes(exe); hdr = exe[:HDR_SIZE]

    HDRF = [
     (2,"e_magic 'MZ'"),(2,"e_cblp"),(2,"e_cp"),(2,"e_crlc"),(2,"e_cparhdr"),(2,"e_minalloc"),
     (2,"e_maxalloc"),(2,"e_ss"),(2,"e_sp"),(2,"e_csum"),(2,"e_ip"),(2,"e_cs"),(2,"e_lfarlc"),
     (2,"e_ovno"),(8,"e_res[4]"),(2,"e_oemid"),(2,"e_oeminfo"),(20,"e_res2[10]"),
     (4,"e_lfanew -> PE header at file offset 0x40 (no DOS stub program)"),
     (4,"Signature 'PE\\0\\0'"),
     (2,"Machine = 0x014c (i386)"),(2,"NumberOfSections = 1 (code and data share one section)"),
     (4,"TimeDateStamp = 0: nothing here depends on when it was built"),
     (4,"PointerToSymbolTable"),(4,"NumberOfSymbols"),
     (2,"SizeOfOptionalHeader = 0x60 (96 = the PE32 optional header with no data directories)"),
     (2,"Characteristics = 0x030f (executable, 32-bit, no relocations/line numbers/symbols)"),
     (2,"Magic = 0x010b (PE32)"),(1,"MajorLinkerVersion"),(1,"MinorLinkerVersion"),
     (4,"SizeOfCode = 0x%x" % raw),(4,"SizeOfInitializedData"),(4,"SizeOfUninitializedData" + (" = 0x%x" % bss_total if bss_total else "")),
     (4,"AddressOfEntryPoint = 0x%x -> _start" % entry),
     (4,"BaseOfCode = 0x%x" % CODE_RVA),(4,"BaseOfData"),
     (4,"ImageBase = 0x%x" % IMAGE_BASE),
     (4,"SectionAlignment = 0x%x" % SECT_ALIGN),(4,"FileAlignment = 0x%x" % FILE_ALIGN),
     (2,"MajorOperatingSystemVersion"),(2,"MinorOperatingSystemVersion"),
     (2,"MajorImageVersion"),(2,"MinorImageVersion"),
     (2,"MajorSubsystemVersion"),(2,"MinorSubsystemVersion"),(4,"Win32VersionValue"),
     (4,"SizeOfImage = 0x%x" % image),(4,"SizeOfHeaders = 0x%x" % HDR_SIZE),
     (4,"CheckSum = 0x%x" % ck),
     (2,"Subsystem = 3 (console)"),(2,"DllCharacteristics = 0x0100 (NX compatible)"),
     (4,"SizeOfStackReserve"),(4,"SizeOfStackCommit"),(4,"SizeOfHeapReserve"),(4,"SizeOfHeapCommit"),
     (4,"LoaderFlags"),
     (4,"NumberOfRvaAndSizes = 0 (no data directories, so no import table)"),
     (8,"Section[0].Name = '.text'"),
     (4,"VirtualSize = 0x%x (%s)" % (vsize, "code, data, and zero-filled reservations" if bss_total else "code + data actually used")),
     (4,"VirtualAddress = 0x%x" % CODE_RVA),
     (4,"SizeOfRawData = 0x%x, the exact length of the program" % raw),
     (4,"PointerToRawData = 0x%x" % HDR_SIZE),
     (4,"PointerToRelocations"),(4,"PointerToLinenumbers"),
     (2,"NumberOfRelocations"),(2,"NumberOfLinenumbers"),
     (4,"Characteristics = 0xE0000020 (code, executable, readable, writable)"),
    ]
    assert sum(n for n, _ in HDRF) == 0xE0

    L = block(banner)
    L += ["", "## ==== headers ===="]
    off = 0
    for n, c in HDRF:
        L.append(datline(hdr[off:off + n], c)); off += n
    L.append(datline(hdr[off:HDR_SIZE], "padding to SizeOfHeaders"))

    # In hex1's language a relative displacement is written %X and resolved by
    # hex1 itself, so each rel32 target needs a single-character name.
    relchars = {}
    if lang == "hex1":
        pool = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        for k, x, c, m in lines:
            if m and m[0] == "rel32" and m[1] not in relchars:
                relchars[m[1]] = pool[len(relchars)]
        assert len(relchars) <= len(pool), "more relative targets than single-character names"

    _merged, _pending = [], b""
    for _k, _x, _c, _m in lines:
        if _k in ("label", "note"):
            if _pending:
                _merged.append(("bytes", _pending, None, None)); _pending = b""
            _merged.append((_k, _x, _c, _m))
        elif _c is None:
            _pending += _x
        else:
            _merged.append(("bytes", _pending + _x, _c, (_m, _pending, _x))); _pending = b""
    if _pending:
        _merged.append(("bytes", _pending, None, None))
    lines = _merged

    in_data = [False]
    L += ["", "## ==== .text : one line per instruction ===="]
    for kind, x, c, meta in lines:
        if kind == "label":
            L.append("")
            if x == data_label:
                L += ["## ==== .data ====", ""]
                in_data[0] = True
            if x in DOC:
                L += block(DOC[x])
            L.append("#:%s ; (0x%X)" % (x, labels[x]))
            if x in relchars:
                L.append(":%s" % relchars[x])
        elif kind == "note":
            L += block(x)
        elif in_data[0]:
            L.append(datline(x, c))
        else:
            m = meta[0] if meta else None
            if lang == "hex1" and m and m[0] == "rel32":
                opc = meta[1]
                hx = " ".join("%02X" % b for b in opc) + " %" + relchars[m[1]]
                mn, _, prose = c.partition("  -- ")
                L.append(("\t%-27s ; %-27s # %s" % (hx, mn, prose)).rstrip() if prose
                         else ("\t%-27s ; %s" % (hx, mn)).rstrip())
            else:
                L.append(insnline(x, c))
    if a.bss:
        L += ["", "## ==== reserved, zero-filled by the loader (past the end of the file) ===="]
        for nm, sz, note in a.bss:
            L.append("#:%s ; (0x%X) %d bytes%s" % (nm, labels[nm], sz, ("  -- " + note) if note else ""))

    open(out_exe, "wb").write(exe)
    open(out_hex, "w").write("\n".join(L) + "\n")

    src = open(out_hex, "rb").read()
    o = assemble_hex1(src) if lang == "hex1" else assemble_hex0(src)
    ok = bytes(o) == exe
    print("%s: code+data %d, file %d, entry 0x%x, checksum 0x%x" % (exe_name, vsize, len(exe), labels["_start"], ck))
    print("  round-trip:", "IDENTICAL" if ok else "MISMATCH")
    return ok


# ===================== routines shared by every link =====================
FIND_NTDLL_ASM = [
    ("64 A1 30 00 00 00", 'mov eax, [fs:0x30]', 'eax = PEB (TEB->PEB at fs:0x30 on x86)'),
    ("8B 40 0C", 'mov eax, [eax + 0x0c]', 'eax = PEB->Ldr (PEB_LDR_DATA*)'),
    ("8B 40 14", 'mov eax, [eax + 0x14]', 'eax = Ldr->InMemoryOrderModuleList.Flink'),
    ("8B 00", 'mov eax, [eax]', '-> 2nd entry: ntdll, by loader convention'),
    ("8B 40 10", 'mov eax, [eax + 0x10]', None),
    ("C3", 'ret', None),
]

RESOLVE_ASM = [
    ("53", 'push ebx', None),
    ("56", 'push esi', None),
    ("57", 'push edi', None),
    ("55", 'push ebp', None),
    ("89 E5", 'mov ebp, esp', None),
    ("8B 5D 14", 'mov ebx, [ebp + 20]', 'module_base'),
    ("8B 43 3C", 'mov eax, [ebx + 0x3c]', 'e_lfanew'),
    ("01 D8", 'add eax, ebx', 'PE header'),
    ("8B 40 78", 'mov eax, [eax + 0x78]', 'DataDirectory[0].VirtualAddress'),
    ("01 D8", 'add eax, ebx', 'IMAGE_EXPORT_DIRECTORY*'),
    ("8B 70 20", 'mov esi, [eax + 0x20]', 'AddressOfNames RVA'),
    ("01 DE", 'add esi, ebx', None),
    ("8B 78 24", 'mov edi, [eax + 0x24]', 'AddressOfNameOrdinals RVA'),
    ("01 DF", 'add edi, ebx', None),
    ("FF 70 1C", 'push dword [eax + 0x1c]', 'AddressOfFunctions RVA (stash)'),
    ("59", 'pop ecx', None),
    ("01 D9", 'add ecx, ebx', 'ecx = AddressOfFunctions (abs)'),
    ("8B 40 18", 'mov eax, [eax + 0x18]', 'NumberOfNames'),
    ("50", 'push eax', 'loop bound'),
    ("31 C0", 'xor eax, eax', 'eax = index i = 0'),
    ("3B 04 24", 'cmp eax, [esp]', None),
    ("7D 2D", 'jge .not_found', None),
    ("51", 'push ecx', 'save AddressOfFunctions'),
    ("8B 0C 86", 'mov ecx, [esi + eax*4]', 'Names[i] RVA'),
    ("01 D9", 'add ecx, ebx', '-> absolute candidate name ptr'),
    ("50", 'push eax', 'save loop index'),
    ("52", 'push edx', 'save target-name ptr'),
    ("8B 55 18", 'mov edx, [ebp + 24]', 'reload target name ptr fresh'),
    ("8A 01", 'mov al, [ecx]', "AL as scratch, not DL: dl is edx's"),
    ("3A 02", 'cmp al, [edx]', None),
    ("75 08", 'jne .no_match', None),
    ("84 C0", 'test al, al', None),
    ("74 0A", 'je .found', None),
    ("41", 'inc ecx', None),
    ("42", 'inc edx', None),
    ("EB F2", 'jmp .cmp_chars', None),
    ("5A", 'pop edx', None),
    ("58", 'pop eax', 'restore loop index'),
    ("59", 'pop ecx', None),
    ("40", 'inc eax', None),
    ("EB DC", 'jmp .scan_loop', None),
    ("5A", 'pop edx', None),
    ("58", 'pop eax', 'restore loop index'),
    ("59", 'pop ecx', 'ecx = AddressOfFunctions (abs)'),
    ("0F B7 14 47", 'movzx edx, word [edi + eax*2]', 'NameOrdinals[i]'),
    ("8B 04 91", 'mov eax, [ecx + edx*4]', 'Functions[ordinal] RVA'),
    ("01 D8", 'add eax, ebx', '-> absolute address'),
    ("EB 02", 'jmp .cleanup', None),
    ("31 C0", 'xor eax, eax', None),
    ("59", 'pop ecx', 'drop the loop-bound we pushed'),
    ("5D", 'pop ebp', None),
    ("5F", 'pop edi', None),
    ("5E", 'pop esi', None),
    ("5B", 'pop ebx', None),
    ("C2 08 00", 'ret 8', 'stdcall, callee-clean, 2 args'),
]

def emit_asm(rows, blob):
    """Emit a reused routine one instruction per line, and prove the bytes are
    still exactly the blob lifted from the original seed."""
    acc = b""
    for hx, mn, prose in rows:
        bs = bytes.fromhex(hx.replace(" ", ""))
        acc += bs
        a.raw(bs, a._c(mn, prose))
    assert acc == blob, "annotated instructions do not reconstitute the blob"


def _emit_asm(a, rows, blob):
    """Emit a reused routine one instruction per line, and prove the bytes are
    still exactly the blob lifted from the original seed."""
    acc = b""
    for hx, mn, prose in rows:
        bs = bytes.fromhex(hx.replace(" ", ""))
        acc += bs
        a.raw(bs, a._c(mn, prose))
    assert acc == blob, "annotated instructions do not reconstitute the blob"

def emit_find_ntdll(a):
    a.label("find_ntdll"); _emit_asm(a, FIND_NTDLL_ASM, FIND_NTDLL)

def emit_resolve_export(a):
    a.label("resolve_export"); _emit_asm(a, RESOLVE_ASM, RESOLVE)

def emit_next_token(a, tabs=False, escapes=False):
    """Split the command line into arguments; see the DOC entry.

    tabs=True also treats a tab as a separator, alongside space.  It matters
    because cmd.exe's ^ line continuation joins a wrapped command onto one
    line by dropping the ^ and the newline and nothing else -- a continuation
    line indented with a tab, which is this project's own convention, leaves
    that tab sitting in the child's actual command line right where the space
    before it already was.  hex0 and hex1 are always invoked on one line, so
    they keep the plain, space-only version: hex0's own copy has to stay
    exactly what it always was, byte for byte, for the seed to keep
    reproducing itself.

    escapes=True is the full rule CommandLineToArgvW defines rather than only
    "..." grouping: a run of n backslashes before a quote is n/2 backslashes,
    and the quote is a literal one if n was odd and a delimiter if it was
    even; backslashes not before a quote are themselves.  Without it an
    argument with a quote inside it arrives cut off at the first one, which is
    what every argument becomes when one program launches another -- wine and
    the Windows runtimes alike escape an embedded quote that way.  It costs
    an argument being rewritten shorter than it was found, so this version
    compacts as it goes, with a write cursor trailing the read cursor; the
    plain version only had to write one NUL.

    Both are off by default so hex0's bytes are whatever they always were.
    Only the shared plumbing in ntdll-i386.hex2, which is what anything above
    catm parses its arguments with, asks for either.
    """
    def I(hx, mn, prose=None):
        a.raw(bytes.fromhex(hx.replace(" ", "")), a._c(mn, prose))

    a.label("next_token")
    a.label(".skip")
    a.raw(b"\x66\x83\x3e\x20", "cmp word [esi], ' '")
    if tabs:
        a.jcc("e", ".skip_adv", "je .skip_adv")
        a.raw(b"\x66\x83\x3e\x09", "cmp word [esi], TAB")
        a.jcc("ne", ".tok_start", "jne .tok_start")
        a.label(".skip_adv")
    else:
        a.jcc("ne", ".tok_start", "jne .tok_start")
    a.raw(b"\x83\xc6\x02", "add esi, 2")
    a.jmp(".skip", "jmp .skip")
    a.label(".tok_start")
    a.raw(b"\x66\x83\x3e\x00", "cmp word [esi], 0")
    a.jcc("e", ".none", "je .none  -- end of command line")

    if not escapes:
        a.raw(b"\x66\x83\x3e\x22", 'cmp word [esi], \'"\'')
        a.jcc("e", ".quoted", "je .quoted")
        a.raw(b"\x89\xf0", "mov eax, esi  -- token starts here")
        a.label(".scan")
        a.raw(b"\x66\x83\x3e\x00", "cmp word [esi], 0")
        a.jcc("e", ".done", "je .done  -- last token, already NUL-terminated")
        a.raw(b"\x66\x83\x3e\x20", "cmp word [esi], ' '")
        a.jcc("e", ".cut", "je .cut")
        if tabs:
            a.raw(b"\x66\x83\x3e\x09", "cmp word [esi], TAB")
            a.jcc("e", ".cut", "je .cut")
        a.raw(b"\x83\xc6\x02", "add esi, 2")
        a.jmp(".scan", "jmp .scan")
        a.label(".quoted")
        a.raw(b"\x83\xc6\x02", "add esi, 2  -- skip the opening quote")
        a.raw(b"\x89\xf0", "mov eax, esi")
        a.label(".qscan")
        a.raw(b"\x66\x83\x3e\x00", "cmp word [esi], 0")
        a.jcc("e", ".done", "je .done")
        a.raw(b"\x66\x83\x3e\x22", 'cmp word [esi], \'"\'')
        a.jcc("e", ".cut", "je .cut")
        a.raw(b"\x83\xc6\x02", "add esi, 2")
        a.jmp(".qscan", "jmp .qscan")
        a.label(".cut")
        a.raw(b"\x66\xc7\x06\x00\x00", "mov word [esi], 0  -- NUL-terminate in place (ProcessParameters is writable)")
        a.raw(b"\x83\xc6\x02", "add esi, 2")
        a.label(".done")
        a.ret("ret")
        a.label(".none")
        a.raw(b"\x31\xc0", "xor eax, eax  -- no token")
        a.ret("ret")
        return

    # ESI reads, EDX writes behind it, and EDX never passes ESI: a quote or a
    # backslash is dropped, and nothing is ever added, so the argument only
    # ever gets shorter.  EBX counts a run of backslashes and ECX says whether
    # we are inside quotes; both belong to the caller and are put back.
    a.push_r("ebx", "the caller's, and needed here")
    a.push_r("ecx")
    I("89 F2", "mov edx, esi", "the write cursor starts where the token does")
    a.push_r("edx", "and that is what gets returned")
    I("31 C9", "xor ecx, ecx", "not inside quotes yet")

    a.label(".scan")
    I("66 8B 06", "mov ax, [esi]")
    I("66 85 C0", "test ax, ax")
    a.jcc("e", ".done", "je .done  -- the end of the command line ends the token")
    I("85 C9", "test ecx, ecx")
    a.jcc("ne", ".quoting", "jne .quoting  -- inside quotes, whitespace is text")
    I("66 83 F8 20", "cmp ax, ' '")
    a.jcc("e", ".cut", "je .cut")
    if tabs:
        I("66 83 F8 09", "cmp ax, TAB")
        a.jcc("e", ".cut", "je .cut")
    a.label(".quoting")
    I("66 83 F8 5C", "cmp ax, '\\'")
    a.jcc("e", ".backslash", "je .backslash")
    I("66 83 F8 22", 'cmp ax, \'"\'')
    a.jcc("e", ".quote", "je .quote")
    I("66 89 02", "mov [edx], ax", "an ordinary character, kept")
    I("83 C2 02", "add edx, 2")
    I("83 C6 02", "add esi, 2")
    a.jmp(".scan", "jmp .scan")

    a.label(".quote")
    I("83 F1 01", "xor ecx, 1", "a quote with no backslashes before it only opens or closes")
    I("83 C6 02", "add esi, 2")
    a.jmp(".scan", "jmp .scan")

    a.label(".backslash")
    I("31 DB", "xor ebx, ebx", "count the whole run before deciding what it means")
    a.label(".bs_count")
    I("66 83 3E 5C", "cmp word [esi], '\\'")
    a.jcc("ne", ".bs_end", "jne .bs_end")
    I("43", "inc ebx")
    I("83 C6 02", "add esi, 2")
    a.jmp(".bs_count", "jmp .bs_count")
    a.label(".bs_end")
    I("66 83 3E 22", 'cmp word [esi], \'"\'')
    a.jcc("e", ".bs_quote", "je .bs_quote")
    a.label(".bs_plain")
    I("85 DB", "test ebx, ebx", "not before a quote: every one of them is itself")
    a.jcc("e", ".scan", "je .scan")
    I("66 C7 02 5C 00", "mov word [edx], '\\'")
    I("83 C2 02", "add edx, 2")
    I("4B", "dec ebx")
    a.jmp(".bs_plain", "jmp .bs_plain")

    a.label(".bs_quote")
    I("89 D8", "mov eax, ebx", "before a quote: half of them survive")
    I("83 E0 01", "and eax, 1", "and an odd one makes the quote a literal")
    I("D1 EB", "shr ebx, 1")
    a.label(".bsq_emit")
    I("85 DB", "test ebx, ebx")
    a.jcc("e", ".bsq_end", "je .bsq_end")
    I("66 C7 02 5C 00", "mov word [edx], '\\'")
    I("83 C2 02", "add edx, 2")
    I("4B", "dec ebx")
    a.jmp(".bsq_emit", "jmp .bsq_emit")
    a.label(".bsq_end")
    I("85 C0", "test eax, eax")
    a.jcc("e", ".scan", "je .scan  -- an even run leaves the quote to open or close")
    I("66 C7 02 22 00", 'mov word [edx], \'"\'', "an odd one leaves a quote in the text")
    I("83 C2 02", "add edx, 2")
    I("83 C6 02", "add esi, 2", "and consumes it")
    a.jmp(".scan", "jmp .scan")

    a.label(".cut")
    I("83 C6 02", "add esi, 2", "step past the separator, for the next call")
    a.label(".done")
    I("66 C7 02 00 00", "mov word [edx], 0", "terminate what was written, which is at or before what was read")
    a.pop_r("eax", "the token")
    a.pop_r("ecx")
    a.pop_r("ebx")
    a.ret("ret")
    a.label(".none")
    I("31 C0", "xor eax, eax", "no token")
    a.ret("ret")

def emit_open_file(a, check_status=False, inheritable=False):
    """Open one file by DOS path; see the DOC entry.

    check_status adds a test of the returned NTSTATUS, so a file that could not
    be opened comes back as 0 rather than as whatever NtCreateFile left in its
    out-parameter.  It is off by default because hex0 carries its own copy of
    this routine and hex0 has to keep assembling to exactly the seed; only the
    shared plumbing, which nothing below M0 uses, asks for it.
    """
    a.label("open_file")
    a.mov_mem_r("g_access", "ecx", "stash DesiredAccess")
    a.mov_mem_r("g_disp", "edx", "stash CreateDisposition")
    a.push_imm(0, "DirectoryInfo"); a.push_imm(0, "NtFileNamePart")
    a.push_lbl("nt_path", "NtPathName (UNICODE_STRING, ntdll allocates the buffer)")
    a.push_r("eax", "DosPathName")
    a.call_mem("fn_rtlpath", "resolves a relative path against the working directory")
    a.mov_mem_imm("oa", 24, "OBJECT_ATTRIBUTES.Length = 24 (x86 sizeof)", off=0)
    a.mov_mem_imm("oa", 0, "OBJECT_ATTRIBUTES.RootDirectory = NULL", off=4)
    a.mov_mem_lbl("oa", "nt_path", "OBJECT_ATTRIBUTES.ObjectName = &nt_path", off=8)
    # OBJ_INHERIT is what makes a handle cross into a child, and cross under
    # the same number, which is what fork needs of every file its caller had
    # open.  Only the shared copy asks for it: hex0, hex1, hex2 and catm carry
    # their own open_file, none of them forks, and hex0's bytes are the seed
    # this whole chain is checked against -- so changing theirs would change
    # the trust anchor to no purpose.
    attrs = 0x42 if inheritable else 0x40
    a.mov_mem_imm("oa", attrs,
                  "OBJECT_ATTRIBUTES.Attributes = OBJ_CASE_INSENSITIVE"
                  + ("|OBJ_INHERIT" if inheritable else ""), off=12)
    a.mov_mem_imm("oa", 0, "OBJECT_ATTRIBUTES.SecurityDescriptor = NULL", off=16)
    a.mov_mem_imm("oa", 0, "OBJECT_ATTRIBUTES.SecurityQualityOfService = NULL", off=20)
    a.push_imm(0, "EaLength"); a.push_imm(0, "EaBuffer")
    a.push_imm(0x60, "CreateOptions = FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE")
    a.push_mem("g_disp", "CreateDisposition")
    a.push_imm(1, "ShareAccess = FILE_SHARE_READ")
    a.push_imm(0x80, "FileAttributes = FILE_ATTRIBUTE_NORMAL (imm32: 6A 80 would sign-extend)")
    a.push_imm(0, "AllocationSize = NULL")
    a.push_lbl("iosb", "IoStatusBlock")
    a.push_lbl("oa", "ObjectAttributes")
    a.push_mem("g_access", "DesiredAccess")
    a.push_lbl("g_handle", "FileHandle (out)")
    a.call_mem("fn_create")
    if check_status:
        a.raw(bytes.fromhex("85C0"), a._c("test eax, eax", "NTSTATUS < 0 is a failure to open"))
        a.jcc("s", "open_file.fail", "js open_file.fail")
    a.mov_r_mem("eax", "g_handle", "mov eax, [g_handle]")
    a.ret("ret")
    if check_status:
        a.label("open_file.fail")
        a.raw(bytes.fromhex("31C0"), a._c("xor eax, eax", "0, which is what fopen in C tests for"))
        a.ret("ret")

    # ---- _start ----

def emit_cmdline(a):
    """Read the command line from the PEB and take argv[1] and argv[2]."""
    a.raw(b"\x64\xa1\x30\x00\x00\x00", "mov eax, [fs:0x30]  -- PEB")
    a.raw(b"\x8b\x40\x10", "mov eax, [eax+0x10]  -- PEB->ProcessParameters")
    a.raw(b"\x8b\x70\x44", "mov esi, [eax+0x44]  -- ProcessParameters->CommandLine.Buffer (UNICODE_STRING at 0x40, Buffer at +4)")
    a.call("next_token", "argv[0]: the program name, discarded")
    a.call("next_token", "argv[1]: the input path")
    a.mov_mem_r("arg_in", "eax", "mov [arg_in], eax")
    a.call("next_token", "argv[2]: the output path")
    a.mov_mem_r("arg_out", "eax", "mov [arg_out], eax")




# the proven blobs, for the assertion in _emit_asm
FIND_NTDLL = bytes.fromhex("64a1300000008b400c8b40148b008b4010c3")
RESOLVE = bytes.fromhex(
    "5356575589e58b5d148b433c01d88b407801d88b702001de8b782401dfff701c5901d9"
    "8b40185031c03b04247d2d518b0c8601d950528b55188a013a02750884c0740a4142eb"
    "f25a58594 0ebdc5a58590fb714478b049101d8eb0231c0595d5f5e5bc20800".replace(" ", ""))

