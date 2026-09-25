"""Recover the constant arguments at every call site of a function.

The MW compiler that built these ELFs sets up arguments with plain
lui/addiu/daddu sequences, so a tiny forward constant-propagation pass over
the enclosing function recovers nearly every (key, value) literal.

usage: tagscan.py <elf> <hex-callee> [argcount] [--sort]
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ee
from xref import load

A0, A1, A2, A3 = 4, 5, 6, 7
ARGS = [A0, A1, A2, A3]
PRINTABLE = set(range(0x20, 0x7f))


def _s16(x):
    return x - 0x10000 if x & 0x8000 else x


def track(img, start, stop):
    """Constant-propagate from `start` up to and including `stop`'s delay slot."""
    reg = {0: 0}
    va = start
    while va <= stop + 4:
        w = img.word(va)
        op = w >> 26
        rs, rt, rd = (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
        imm = w & 0xFFFF
        if op == 0x0F:                                   # lui
            reg[rt] = (imm << 16)
        elif op in (0x09, 0x19):                         # addiu / daddiu
            reg[rt] = ((reg[rs] + _s16(imm)) & 0xFFFFFFFF) if reg.get(rs) is not None else None
        elif op == 0x0D:                                 # ori
            reg[rt] = (reg[rs] | imm) if reg.get(rs) is not None else None
        elif op == 0x00 and (w & 0x3F) in (0x21, 0x2D, 0x20, 0x2C):   # addu/daddu
            a, b = reg.get(rs), reg.get(rt)
            reg[rd] = ((a + b) & 0xFFFFFFFF) if (a is not None and b is not None) else None
        elif op == 0x00:
            reg[rd] = None
        elif op in (0x02, 0x03):                         # j / jal clobber caller-saved
            pass
        else:
            reg[rt] = None
        if op == 0x03 and va != stop:                    # an intervening call
            for r in list(reg):
                if r != 0:
                    reg[r] = None
        va += 4
    return reg


def render(img, val):
    if val is None:
        return '?'
    if img.valid(val):
        s = img.cstr(val, 160)
        if s is not None and (s == '' or all(c in PRINTABLE for c in s.encode())):
            return repr(s)
    if 0x20 <= val <= 0x7e:
        return "%d" % val
    return '0x%x' % val if val > 0xffff else str(val)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    path, callee = sys.argv[1], int(sys.argv[2], 16)
    argc = int(sys.argv[3]) if len(sys.argv) > 3 and not sys.argv[3].startswith('--') else 4
    img, _consts, calls = load(path)
    sites = calls.get(callee, [])
    rows = []
    for site in sites:
        fs = ee.func_start(img, site)
        if fs is None:
            rows.append((0, site, ['?'] * argc))
            continue
        reg = track(img, fs, site)
        rows.append((fs, site, [render(img, reg.get(ARGS[i])) for i in range(argc)]))
    if '--sort' in sys.argv:
        rows.sort(key=lambda r: (r[2][2] if argc > 2 else '', r[0]))
    print('# %d call sites of 0x%08x' % (len(rows), callee))
    for fs, site, args in rows:
        print('func 0x%08x  @0x%08x  (%s)' % (fs, site, ', '.join(args)))


if __name__ == '__main__':
    main()
