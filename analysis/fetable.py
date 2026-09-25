"""Dump the online front-end handler table that sub_0020D6F0 builds.

The online UI does not call its handlers directly -- it writes each one into a
slot of a table around 0x00354D00-0x00355000 and dispatches through that, which
is why none of them show up in a static call graph. The registration code is a
long run of:

    lui   $v1, <hi>
    lui   $at, 0x35
    addiu $v1, $v1, <lo>      ; the handler address
    sw    $v1, <slot>($at)    ; the table slot

usage: fetable.py <elf> [start] [end]
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import names as namemod
from xref import load


def s16(x):
    return x - 0x10000 if x & 0x8000 else x


def scan(img, start, end):
    """Return [(slot_addr, handler_addr, store_pc)] in registration order."""
    hi = {}
    val = {}
    out = []
    for va in range(start, end, 4):
        w = img.word(va)
        op, rs, rt, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        if op == 0x0F:                       # lui
            hi[rt] = imm << 16
            val.pop(rt, None)
        elif op == 0x09 and rs in hi:        # addiu completing a constant
            val[rt] = (hi[rs] + s16(imm)) & 0xFFFFFFFF
            if rt == rs:
                hi.pop(rs, None)
        elif op == 0x2B:                     # sw rt, imm(rs)
            if rs in hi and rt in val:
                out.append(((hi[rs] + s16(imm)) & 0xFFFFFFFF, val[rt], va))
    return out


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    start = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x0020D6F0
    end = int(sys.argv[3], 16) if len(sys.argv) > 3 else 0x00211000
    img, consts, _calls = load(path)
    fname = namemod.build(img, consts)

    rows = [r for r in scan(img, start, end)
            if 0x00354000 <= r[0] < 0x00356000 and img.valid(r[1])]
    print('%d handlers registered between 0x%08x and 0x%08x\n' % (len(rows), start, end))
    print('%-10s %-10s %-10s %s' % ('slot', 'handler', 'store@', 'name'))
    for slot, fn, pc in rows:
        print('0x%08x 0x%08x 0x%08x %s'
              % (slot, fn, pc, fname.get(fn, '')))

    online = [r for r in rows if 0x00299000 <= r[1] < 0x002B0000]
    print('\n%d of them live in the online cluster (0x00299000-0x002B0000):' % len(online))
    for slot, fn, pc in online:
        print('   slot 0x%08x -> 0x%08x' % (slot, fn))


if __name__ == '__main__':
    main()
