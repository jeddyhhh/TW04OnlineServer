"""Shared helpers for poking at the TW04/TW05 PS2 EE master ELFs.

The ELF is one big PT_LOAD, so the vaddr<->file-offset map is a single
constant shift.  Everything here works in VADDRs; strings dumped with
strings.py are FILE OFFSETS, so convert before you go looking for xrefs.
"""
import struct
from elftools.elf.elffile import ELFFile


class Image:
    def __init__(self, path):
        with open(path, 'rb') as f:
            elf = ELFFile(f)
            segs = [s.header for s in elf.iter_segments()
                    if s.header.p_type == 'PT_LOAD' and s.header.p_filesz]
            seg = max(segs, key=lambda h: h.p_filesz)
            f.seek(seg.p_offset)
            self.data = f.read(seg.p_filesz)
            self.base = seg.p_vaddr
            self.off = seg.p_offset
            self.entry = elf.header.e_entry
            # $gp lives in the last word of .reginfo
            self.gp = None
            ri = elf.get_section_by_name('.reginfo')
            if ri:
                self.gp = struct.unpack('<I', ri.data()[-4:])[0]

    # -- address conversion ------------------------------------------------
    # `data` holds the segment, so an index into it is `vaddr - base`, which is
    # what every reader below uses.  These two convert to and from an offset in
    # the FILE, which is that index plus the segment's own offset -- the pair
    # used to disagree with the readers by exactly `off`.
    def va(self, file_off):
        return file_off - self.off + self.base

    def fo(self, vaddr):
        return vaddr - self.base + self.off

    def index(self, vaddr):
        """Where `vaddr` sits in `self.data`."""
        return vaddr - self.base

    def valid(self, vaddr):
        return self.base <= vaddr < self.base + len(self.data)

    # -- reads -------------------------------------------------------------
    def word(self, vaddr):
        i = vaddr - self.base
        return struct.unpack_from('<I', self.data, i)[0]

    def bytes(self, vaddr, n):
        i = vaddr - self.base
        return self.data[i:i + n]

    def cstr(self, vaddr, maxlen=256):
        i = vaddr - self.base
        if i < 0 or i >= len(self.data):
            return None
        end = self.data.find(b'\0', i, i + maxlen)
        if end < 0:
            return None
        try:
            return self.data[i:end].decode('ascii')
        except UnicodeDecodeError:
            return None


# ---------------------------------------------------------------------------
# Hand-rolled decode of just the opcodes we care about.  Capstone is fine for
# reading, but for xref scanning we want to be exact about R5900 oddities and
# we only need a handful of forms.
# ---------------------------------------------------------------------------
OP_J, OP_JAL = 0x02, 0x03
OP_ADDIU, OP_ORI, OP_LUI = 0x09, 0x0D, 0x0F
LOAD_STORE = {0x20, 0x21, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2B, 0x37, 0x3F}


def _s16(x):
    return x - 0x10000 if x & 0x8000 else x


def scan_constants(img, start=None, end=None):
    """Find 32-bit constants built by lui+{addiu,ori,load,store}.

    Returns {target_vaddr: [vaddr_of_the_completing_instruction, ...]}.
    Tracks per-register hi halves, which is enough for MW-compiler output
    where the pair is nearly always adjacent or a few instructions apart.
    """
    start = start if start is not None else img.base
    end = end if end is not None else img.base + len(img.data)
    hi = {}
    xrefs = {}
    pending_clear = False
    for va in range(start & ~3, end & ~3, 4):
        w = img.word(va)
        op = w >> 26
        rs = (w >> 21) & 31
        rt = (w >> 16) & 31
        imm = w & 0xFFFF
        if op == OP_LUI:
            hi[rt] = (imm << 16, va)
            continue
        if op in (OP_ADDIU, OP_ORI) and rs in hi:
            base, _ = hi[rs]
            tgt = (base + _s16(imm)) & 0xFFFFFFFF if op == OP_ADDIU else (base | imm)
            xrefs.setdefault(tgt, []).append(va)
            if rt == rs:
                hi.pop(rs, None)
            continue
        if op in LOAD_STORE and rs in hi:
            base, _ = hi[rs]
            tgt = (base + _s16(imm)) & 0xFFFFFFFF
            xrefs.setdefault(tgt, []).append(va)
            continue
        # a write to the register kills the pending hi half
        if pending_clear:
            hi.clear()
            pending_clear = False
            continue
        if op == 0:  # SPECIAL: rd is the destination
            rd = (w >> 11) & 31
            hi.pop(rd, None)
        elif op in (OP_J, OP_JAL):
            # the delay slot still runs, and MW routinely puts the addiu of a
            # lui/addiu pair there -- so defer the clear by one instruction
            pending_clear = True
        else:
            hi.pop(rt, None)
    return xrefs


def scan_calls(img, start=None, end=None):
    """Return {callee_vaddr: [call_site_vaddr, ...]} for every jal."""
    start = start if start is not None else img.base
    end = end if end is not None else img.base + len(img.data)
    calls = {}
    for va in range(start & ~3, end & ~3, 4):
        w = img.word(va)
        if w >> 26 == OP_JAL:
            tgt = ((va + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
            calls.setdefault(tgt, []).append(va)
    return calls


def func_start(img, vaddr, limit=0x4000):
    """Walk back to the most likely prologue for the function containing vaddr.

    Looks for `addiu $sp, $sp, -N` (or the R5900 `daddiu`), which is how every
    non-leaf function here opens.
    """
    va = vaddr & ~3
    for _ in range(limit // 4):
        w = img.word(va)
        op = w >> 26
        rs = (w >> 21) & 31
        rt = (w >> 16) & 31
        if op in (0x09, 0x19) and rs == 29 and rt == 29 and (w & 0x8000):
            return va
        va -= 4
        if va < img.base:
            break
    return None


def disasm(img, start, count=None, end=None):
    """Yield (vaddr, mnemonic, op_str) using capstone."""
    from capstone import Cs, CS_ARCH_MIPS, CS_MODE_MIPS32, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 | CS_MODE_LITTLE_ENDIAN)
    md.skipdata = True
    if end is None:
        end = start + (count or 64) * 4
    code = img.bytes(start, end - start)
    for ins in md.disasm(code, start):
        yield ins.address, ins.mnemonic, ins.op_str
