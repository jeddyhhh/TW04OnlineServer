"""Disassemble a function, annotating string/constant operands.

usage: disfn.py <elf> <hex-vaddr> [n_instructions]
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ee
import mips
from xref import load

PRINTABLE = set(range(0x20, 0x7f))


def annotate(img, va, mnem, ops, hi):
    """Return a comment for this instruction, tracking lui/lo pairs."""
    w = img.word(va)
    op = w >> 26
    rs, rt, imm = (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
    note = ''
    if op == 0x0F:                       # lui
        hi[rt] = imm << 16
    elif rs in hi and op in (0x09, 0x0D) or (rs in hi and op in
            (0x20, 0x21, 0x23, 0x24, 0x25, 0x28, 0x29, 0x2B, 0x37, 0x3F)):
        base = hi[rs]
        simm = imm - 0x10000 if imm & 0x8000 else imm
        tgt = (base | imm) if op == 0x0D else (base + simm) & 0xFFFFFFFF
        note = '-> 0x%08x' % tgt
        if img.valid(tgt):
            s = img.cstr(tgt, 120)
            if s and len(s) >= 2 and all(c in PRINTABLE for c in s.encode()):
                note += '  %r' % s
            else:
                try:
                    note += '  = 0x%08x' % img.word(tgt)
                except Exception:
                    pass
        if op in (0x09, 0x0D) and rt == rs:
            hi.pop(rs, None)
    elif op == 0x03:                     # jal
        note = ''
    # a 4-character immediate is very often a 4CC
    if op in (0x09, 0x0D, 0x24, 0x25) and rs not in hi:
        b = imm.to_bytes(2, 'little')
        if all(c in PRINTABLE for c in b):
            note = note or "imm %r" % b.decode()
    return note


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    path, start = sys.argv[1], int(sys.argv[2], 16)
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 80
    img, _consts, _calls = load(path)
    hi = {}
    for va, mnem, ops in ee.disasm(img, start, n):
        manual = mips.decode(img.word(va))
        if manual:
            mnem, ops = manual
        note = annotate(img, va, mnem, ops, hi)
        if mnem in ('jal',):
            tgt = int(ops, 16) if ops.startswith('0x') else None
            note = 'call 0x%08x' % tgt if tgt else ''
        print('0x%08x  %-9s %-34s %s' % (va, mnem, ops, note))


if __name__ == '__main__':
    main()
