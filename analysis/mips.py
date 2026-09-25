"""Manual decode for the forms capstone's MIPS32 mode gets wrong on R5900.

The MW compiler emits 64-bit ops (daddu/daddiu/sd/ld) constantly -- `daddu rd,
rs, $zero` is its `move` -- and capstone in MIPS32 mode renders them as .byte
or as bogus DSP/MSA instructions.  Anything this function returns overrides
capstone's opinion.
"""
REG = ['zero', 'at', 'v0', 'v1', 'a0', 'a1', 'a2', 'a3',
       't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
       's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
       't8', 't9', 'k0', 'k1', 'gp', 'sp', 's8', 'ra']


def _s16(x):
    return x - 0x10000 if x & 0x8000 else x


def decode(w):
    """Return (mnemonic, op_str) or None to fall back to capstone."""
    op = w >> 26
    rs, rt, rd = (w >> 21) & 31, (w >> 16) & 31, (w >> 11) & 31
    imm = w & 0xFFFF
    R = lambda n: '$' + REG[n]

    if op == 0:
        func = w & 0x3F
        if func in (0x2D, 0x2C):                      # daddu / dadd
            if rt == 0:
                return 'move', '%s, %s' % (R(rd), R(rs))
            if rs == 0:
                return 'move', '%s, %s' % (R(rd), R(rt))
            return ('daddu' if func == 0x2D else 'dadd',
                    '%s, %s, %s' % (R(rd), R(rs), R(rt)))
        if func == 0x2F:
            return 'dsubu', '%s, %s, %s' % (R(rd), R(rs), R(rt))
        if func == 0x38:
            return 'dsll', '%s, %s, %d' % (R(rd), R(rt), (w >> 6) & 31)
        if func == 0x3A:
            return 'dsrl', '%s, %s, %d' % (R(rd), R(rt), (w >> 6) & 31)
        if func == 0x3B:
            return 'dsra', '%s, %s, %d' % (R(rd), R(rt), (w >> 6) & 31)
        if func == 0x3C:
            return 'dsll32', '%s, %s, %d' % (R(rd), R(rt), (w >> 6) & 31)
        if func == 0x3E:
            return 'dsrl32', '%s, %s, %d' % (R(rd), R(rt), (w >> 6) & 31)
        if func == 0x3F:
            return 'dsra32', '%s, %s, %d' % (R(rd), R(rt), (w >> 6) & 31)
        return None
    if op == 0x19:
        return 'daddiu', '%s, %s, %d' % (R(rt), R(rs), _s16(imm))
    if op == 0x37:
        return 'ld', '%s, %d(%s)' % (R(rt), _s16(imm), R(rs))
    if op == 0x3F:
        return 'sd', '%s, %d(%s)' % (R(rt), _s16(imm), R(rs))
    if op == 0x1C and (w & 0x3F) == 0x12:             # R5900 MMI
        return 'mflo1', R(rd)
    if op == 0x1C and (w & 0x3F) == 0x18:
        return 'mult1', '%s, %s, %s' % (R(rd), R(rs), R(rt))
    if op == 0x1C and (w & 0x3F) == 0x1B:
        return 'divu1', '%s, %s' % (R(rs), R(rt))
    return None
