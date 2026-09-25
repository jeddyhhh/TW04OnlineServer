"""The obfuscation TW04 applies to PASS before an auth/acct/pass request.

Transcribed from SLUS_207.57:
    0x002C5780  ssc_init(state, key, keylen, reset)   -- RC4-shaped KSA
    0x002C5900  ssc_gen(state, dst, count)            -- PRGA, XORs into dst
    0x002C59A0  pass_encode(dst, dstlen, src, key, keylen, rounds)
    0x00314BF8  the CRC-32 table it steps j through (reflected, 0xEDB88320)

It is RC4's shape -- 256-byte permutation, swap on every output -- with the
running index j replaced by a 32-bit CRC-32 register, and with the output byte
taken from S[(si - sj) & 0xff] instead of S[(si + sj) & 0xff].  Do not reach for
a stock RC4 here; it will not match.

Two details that look like bugs but are not, and that any reimplementation has
to copy exactly:

  * ssc_gen XORs into the destination, it does not overwrite it.  pass_encode
    reuses one scratch byte across the whole loop without re-zeroing, so the
    keystream byte for position n is the XOR of every byte generated so far.
  * The plaintext is padded out to a fixed 30 characters with output from a
    SECOND generator, so ciphertext length never reveals password length.  That
    generator is a GLOBAL: it is seeded once with "hello world" and then absorbs
    key + "ru paranoid?" on every call without resetting, so the padding differs
    on every encode.  encode() here re-seeds it fresh, so it reproduces only the
    FIRST encode after the game boots.  Confirmed live: two logins, same key and
    password, identical up to the 0x7F terminator and different after it.
    Decryption is unaffected -- it uses the local state only.
  * The KSA runs j in a local register starting at zero and NEVER writes it back
    to the state.  The PRGA therefore starts from j = 0, not from whatever the
    KSA ended on.  Getting this wrong yields a keystream that looks perfectly
    reasonable and is completely wrong.

CONFIRMED against the real client on 2026-09-17: encode() reproduces a captured
ciphertext byte for byte, padding included.  See KNOWN_GOOD at the bottom.
"""

CRC32TAB = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ (0xEDB88320 if _c & 1 else 0)
    CRC32TAB.append(_c)

GLOBAL_SEED = b'hello world'     # 0x00314FF8, rounds 0x0A, one-time
PARANOID = b'ru paranoid?'       # 0x00315008
ALPHA_LO = 0x20                  # the 96-char alphabet is 0x20..0x7F
ALPHA_N = 0x60


class State:
    """The 0x110-byte state: S[256] at +0, i at +0x100, j32 at +0x104."""

    def __init__(self):
        self.s = list(range(256))
        self.i = 0
        self.j = 0

    def init(self, key, keylen=None, reset=0x10):
        """ssc_init.  reset < 0 absorbs into the existing state instead of
        resetting it; keylen < 0 means 'measure the key'."""
        if isinstance(key, str):
            key = key.encode('latin-1')
        if keylen is None or keylen < 0:
            keylen = len(key)
        if reset >= 0:
            self.s = list(range(256))
            self.i = 0
            self.j = 0
        rounds = abs(reset) << 8
        # The KSA runs on a LOCAL j that starts at zero (`move $a1, $zero` at
        # 0x002C5850) and is never written back -- there is no store to
        # state+0x100 or +0x104 anywhere between 0x002C5844 and the epilogue.
        # So the KSA permutes S and leaves the stored i/j exactly as the reset
        # left them.  Carrying the KSA's final j into the PRGA, as an RC4-shaped
        # implementation naturally would, produces a plausible but wrong
        # keystream.
        j = 0
        for n in range(rounds):
            idx_i = n & 0xFF
            old = self.s[idx_i]
            b = ((j & 0xFF) ^ key[n % keylen]) & 0xFF
            j = (j >> 8) ^ CRC32TAB[b]
            b2 = ((j & 0xFF) ^ old) & 0xFF
            j = (j >> 8) ^ CRC32TAB[b2]
            idx_j = j & 0xFF
            self.s[idx_i] = self.s[idx_j]
            self.s[idx_j] = old
        return self

    def gen(self, prev=0, count=1):
        """ssc_gen for a single destination byte, XORing into `prev`."""
        out = prev
        for _ in range(count):
            i_old = self.i
            b = ((self.j & 0xFF) ^ self.s[i_old]) & 0xFF
            j = self.j >> 8
            self.i = (i_old + 1) & 0xFF
            si = self.s[self.i]
            j ^= CRC32TAB[b]
            jj = j & 0xFF
            sj = self.s[jj]
            self.s[self.i] = sj
            self.s[jj] = si
            self.j = j
            out ^= self.s[(si - sj) & 0xFF]
        return out & 0xFF


def _make_states(key):
    """The local keystream state and the global padding state, as pass_encode
    sets them up."""
    local = State().init(key, len(key), 0x10)
    glob = State().init(GLOBAL_SEED, -1, 0x0A)      # one-time global init
    glob.init(key, len(key), -0x10)                  # absorb, no reset
    glob.init(PARANOID, -1, -1)                      # absorb, no reset
    return local, glob


def encode(plain, key, dstlen=0x1F):
    """pass_encode.  Returns the 31-char ciphertext WITHOUT the '~' prefix."""
    if isinstance(plain, str):
        plain = plain.encode('latin-1')
    local, glob = _make_states(key)
    out = bytearray()
    src = list(plain) + [0]      # the source is a C string; the NUL is encoded
    pos = 0
    reading = True
    cur = 0          # the sp+0x110 scratch byte
    ks = 0           # the sp+0x111 scratch byte, never re-zeroed
    remaining = dstlen
    while remaining >= 2:
        if reading:
            cur = src[pos] if pos < len(src) else 0
            pos += 1
            if cur == 0:
                reading = False          # movz $s4, $zero, $v1
        else:
            cur = (glob.gen(cur) & 0x3F) + 0x20
        if not (0 <= cur - ALPHA_LO < 0x5F):
            cur = 0x7F                   # out of range, including that NUL
        ks = local.gen(ks)
        remaining -= 1
        v = (cur + (ks % ALPHA_N) + 0x40) % ALPHA_N + ALPHA_LO
        out.append(v)
    return bytes(out)


def decode(cipher, key):
    """Invert encode() and cut the password out of the padding.

    The encoder runs the source string's NUL terminator through the same path
    as the text, and a NUL is out of the 0x20..0x7E range, so it lands in the
    ciphertext as 0x7F.  That byte is the end-of-password marker -- the server
    does not have to guess the length.
    """
    if isinstance(cipher, str):
        cipher = cipher.encode('latin-1')
    if cipher[:1] == b'~':
        cipher = cipher[1:]
    local, _ = _make_states(key)
    out = bytearray()
    ks = 0
    for c in cipher:
        ks = local.gen(ks)
        m = (c - ALPHA_LO - (ks % ALPHA_N) - 0x40) % ALPHA_N
        # the encoder added the raw ASCII value, so fold 0..31 back up to
        # 96..127 to undo the mod on the high half of the alphabet
        out.append(m if m >= ALPHA_LO else m + ALPHA_N)
    end = out.find(0x7F)
    return bytes(out if end < 0 else out[:end])


# Captured from the real TW04 client, 2026-09-17, against lobbyd.py.
# Key issued in SKEY, password typed at the game's login screen, ciphertext
# taken off the wire.  If a change to this module breaks this vector, the change
# is wrong.
KNOWN_GOOD = (
    bytes.fromhex('a1b2c3d4e5f60718293a4b5c6d7e8f90'),
    'hunter2',
    '~zP< 1JZD\x7f$WeC5m4$76&/DAe}1n<WH',
)


def selftest():
    key, pw, expect = KNOWN_GOOD
    got = '~' + encode(pw, key).decode('latin-1')
    ok = got == expect
    print('%s captured vector: %r -> %r' % ('ok  ' if ok else 'FAIL', pw, got))
    if not ok:
        print('     expected %r' % expect)
    back = decode(expect, key).decode('latin-1')
    ok2 = back == pw
    print('%s decrypt of the captured ciphertext -> %r' % ('ok  ' if ok2 else 'FAIL', back))
    return ok and ok2


if __name__ == '__main__':
    passed = selftest()
    print()
    key = bytes.fromhex('a1b2c3d4e5f60718293a4b5c6d7e8f90')
    for pw in ('hunter2', 'a', 'correct horse battery staple'[:31], ''):
        ct = encode(pw, key)
        pt = decode(ct, key)
        status = 'ok ' if pt.decode('latin-1') == pw else 'FAIL'
        print('%s %-31r -> %r' % (status, pw, ct.decode('latin-1')))
        if status == 'FAIL':
            print('     round-tripped to %r' % pt)
    print('\nciphertext length is always %d, plus the ~ prefix'
          % len(encode('x', key)))
