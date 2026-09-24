"""EA DirtySock TagField encode/decode, as implemented in TW04's SLUS_207.57.

Encoder read from TagFieldSetString (0x002BE400), binary form from
TagFieldSetBinary (0x002BE578) / TagFieldGetBinary (0x002BF7F0).

Rules:
  * a payload is `KEY=VALUE` pairs separated by NEWLINES, with a trailing
    newline after the last field.  Confirmed against the real client:

        PROD=tiger-ps2-2004\nVERS=PS2/B10\nLANG=en\nSLUS=SLUS_20757\n\0

    Some payloads are space-separated instead -- but every one seen so far is a
    string constant the game sends verbatim rather than building through
    TagFieldSetString (`ROOMS=1 GAMES=1 USERS=1 RANKS=1 MESGS=1` lives at
    0x003114D0 in the ELF).  So: emit newlines, accept either.
  * a value containing a space is wrapped in double quotes
  * `=`, `"`, `:`, `%` and anything outside 0x20..0x7E are escaped `%xx`,
    lowercase hex on the way out, either case accepted on the way in
  * binary values are `$` followed by two lowercase hex digits per byte
  * the key `~~` means a bare leading token with no `KEY=` in front
"""

ESCAPED = set(b'="%:')


def esc(value):
    if isinstance(value, str):
        value = value.encode('latin-1')
    out = []
    for b in value:
        if b in ESCAPED or not (0x20 <= b <= 0x7E):
            out.append('%%%02x' % b)
        else:
            out.append(chr(b))
    return ''.join(out)


def unesc(text):
    out = bytearray()
    i = 0
    while i < len(text):
        c = text[i]
        if c == '%' and i + 2 < len(text) + 1:
            try:
                out.append(int(text[i + 1:i + 3], 16))
                i += 3
                continue
            except ValueError:
                pass
        out.append(ord(c))
        i += 1
    return bytes(out)


def encode(pairs):
    """pairs: dict or list of (key, value).  bytes values become $hex."""
    if hasattr(pairs, 'items'):
        pairs = list(pairs.items())
    out = []
    for key, value in pairs:
        if isinstance(value, (bytes, bytearray)) and key != '~~':
            text = '$' + value.hex()
        elif isinstance(value, int):
            text = str(value)
        else:
            text = esc(value)
            if ' ' in (value if isinstance(value, str) else value.decode('latin-1')):
                text = '"%s"' % text
        out.append(text if key == '~~' else '%s=%s' % (key, text))
    return '\n'.join(out) + ('\n' if out else '')


SEPARATORS = ' \n\r\t'


def _split(payload):
    """Split on whitespace, but not inside double quotes.

    Both separators are accepted because the client uses both -- newlines for
    anything it builds, spaces for the literals it ships prebuilt.
    """
    fields, cur, quoted = [], [], False
    for ch in payload:
        if ch == '"':
            quoted = not quoted
            continue
        if ch in SEPARATORS and not quoted:
            if cur:
                fields.append(''.join(cur))
                cur = []
            continue
        cur.append(ch)
    if cur:
        fields.append(''.join(cur))
    return fields


def decode(payload):
    """Return {key: value}.  Binary ($hex) values come back as bytes, and a
    bare leading token lands under the key '~~'."""
    if isinstance(payload, (bytes, bytearray)):
        payload = payload.rstrip(b'\0').decode('latin-1')
    out = {}
    for field in _split(payload):
        if '=' in field:
            key, _, raw = field.partition('=')
        else:
            key, raw = '~~', field
        if raw.startswith('$'):
            hexpart = raw[1:]
            if len(hexpart) % 2:
                hexpart = hexpart[:-1]
            try:
                out[key] = bytes.fromhex(hexpart)
                continue
            except ValueError:
                pass
        out[key] = unesc(raw).decode('latin-1')
    return out


# ---------------------------------------------------------------------------
# Flag fields are NOT decimal.  `F` on a +msg push, `ATTR` on a mesg request and
# every other flag word travels as one character per set bit:
#
#   writer 0x002BE1A8:  for c in ALPHABET: if v & 1: emit c;  v >>= 1; stop at 0
#   reader 0x002BF228:  for c in text: v |= TABLE[c];  stop at the first
#                       character that is not in the table
#
# ALPHABET is the literal at 0x003145B0 and TABLE the 256-word array at
# 0x003145D0, which is exactly its inverse.  Bit 0 is '@', bits 1..26 are
# 'A'..'Z', bits 27..30 are '0'..'3'.  There is no bit 31.
#
# Sending a decimal here is silently read as zero: '6' is not in the table, so
# `F=65536` stops on the first character and yields 0.  That cost an evening --
# every challenge arrived as an ordinary chat line.
FLAG_ALPHABET = '@ABCDEFGHIJKLMNOPQRSTUVWXYZ0123'
FLAG_BITS = {c: 1 << i for i, c in enumerate(FLAG_ALPHABET)}


def flags_encode(value):
    """0x40010000 -> 'P3'.  Lowest bit first, the way the game writes them."""
    return ''.join(c for i, c in enumerate(FLAG_ALPHABET) if value >> i & 1)


def flags_decode(text):
    """'P3' -> 0x40010000.  Stops at the first unknown character, as the
    game's reader does, so a decimal like '65536' decodes to 0."""
    value = 0
    for c in text or '':
        bit = FLAG_BITS.get(c)
        if bit is None:
            break
        value |= bit
    return value


if __name__ == '__main__':
    for v in (0x4, 0x10000, 0x40000000, 0x40010000, 0x08000000):
        t = flags_encode(v)
        assert flags_decode(t) == v, (v, t)
        print('  0x%08x <-> %-4s' % (v, t or "''"))
    assert flags_decode('65536') == 0
    assert flags_encode(0x40000000) == '3'      # ATTR3, as the client sends it

    p = encode([('PROD', 'tiger-ps2-2004'), ('NAME', 'a room with spaces'),
                ('SKEY', bytes(range(16))), ('ODD', 'a=b:c%d"e')])
    print(p)
    for k, v in decode(p).items():
        print('  %-6s %r' % (k, v))
