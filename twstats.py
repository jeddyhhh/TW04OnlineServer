"""The TW04 packed-record codec: the `S` statistics blob and `CRPIN` golfers.

Two layers, both read straight out of the ELF.

LAYER 1 -- high-bit escaping (`0x002736C0`)

The wire form must survive a text field, so no byte may be NUL.  The record is
therefore carried in groups of eight: one mask byte followed by **seven**
payload bytes, with bit *n* of the mask supplying the top bit of payload byte
*n*.  Every transmitted byte has its own top bit set, so none can be zero.

    0x00273710  t0 = *group                       ; the mask byte
    0x00273714  v1 = (1 << n) & t0
    0x00273724  if v1: *dst = *payload |  0x80
    0x00273738  else:  *dst = *payload & ~0x80
    0x0027374C  slti v1, t2, 7                    ; SEVEN per group, not eight

The captured 665-byte `CRPIN` blob is exactly 83 groups plus a trailing `'!'`,
which is what confirms the group size.

LAYER 2 -- bit fields (`0x00273780`)

The decoded bytes are a little-endian bit stream, LSB first, carved into 56
fields by the table at `0x00302440`.  A field's offset is the sum of every
earlier field's width; there is no padding and no alignment.

    0x002738C8  v1 = word[a0] & (1 << t3)
    0x002738F8  if v1: v0 |= (1 << a3)            ; LSB first
    0x00273900  t3 += 1; at 32 move on a word

THE MARKER

`0x00276C34` refuses the whole record unless the byte at `ctx+0xF4` is `'!'` --
that is `S + 0x78`, immediately after the fifteen groups the statistics record
uses.  Without it every value on the resume screen falls back to the defaults in
the table, which is why the screen read zero however the fields were filled.
"""
import sys

MARKER = 0x21                 # '!'
GROUP_PAYLOAD = 7             # bytes of payload per mask byte
GROUP_SIZE = GROUP_PAYLOAD + 1

# The statistics record: 0x002736C0 is called with 0x78, so ceil(0x78/8) = 15
# groups, 120 escaped bytes, 105 decoded bytes, then the marker at [120].
STAT_GROUPS = 15
STAT_ESCAPED = STAT_GROUPS * GROUP_SIZE          # 120
STAT_DECODED = STAT_GROUPS * GROUP_PAYLOAD       # 105

# (width, signed, default, invert) for each of the 56 fields, from 0x00302440.
# 707 bits in total, comfortably inside the 105 decoded bytes.
#
# The four words were originally read in the wrong order.  Each one is used at
# a known site, so the order is not a guess:
#
#   +0x00  width    0x002737C8, summing widths to reach a field's bit offset
#   +0x04  signed   0x00273930 -- `if word[1] == 1` and the top bit is set,
#                   0x00273960 floods bits upward to 31.  Only fields 13 and
#                   14, the two streaks, have it, and 0x002A1048 then reads the
#                   result with `blez`: positive draws "W%d", negative negates
#                   and draws "L%d", zero prints a bare "0".
#   +0x08  default  0x002739B0, the value returned when the record has no '!'
#   +0x0C  invert   0x002727A0, display-only: the leaderboard draws
#                   (1 << width) - value instead of the value
FIELDS = [
    (32, 0, 0, 0), (17, 0, 0, 0), (15, 0, 0, 0), (10, 0, 0, 0),
    (17, 0, 0, 0), (17, 0, 0, 0), (3, 0, 0, 0), (13, 0, 0, 0),
    (13, 0, 0, 0), (13, 0, 0, 0), (13, 0, 0, 0), (13, 0, 0, 0),
    (13, 0, 0, 0), (8, 1, 0, 0), (8, 1, 0, 0), (11, 0, 0, 0),
    (11, 0, 0, 0), (3, 0, 0, 0), (3, 0, 0, 0), (13, 0, 0, 0),
    (13, 0, 0, 0), (20, 0, 0, 0), (20, 0, 0, 0), (18, 0, 0, 0),
    (17, 0, 0, 0), (17, 0, 0, 0), (10, 0, 0, 0), (10, 0, 0, 0),
    (10, 0, 0, 0), (10, 0, 0, 0), (17, 0, 0, 0), (17, 0, 0, 0),
    (16, 0, 0, 0), (17, 0, 0, 0), (8, 0, 0, 0), (17, 0, 0, 0),
    (17, 0, 0, 0), (9, 0, 0, 0), (9, 0, 0, 0), (8, 0, 0, 1),
    (13, 0, 0, 0), (8, 0, 0, 1), (7, 0, 0, 0), (10, 0, 0, 1),
    (7, 0, 0, 1), (7, 0, 0, 0), (7, 0, 0, 0), (16, 0, 0, 0),
    (1, 0, 0, 0), (1, 0, 0, 0), (25, 0, 0, 0), (18, 0, 0, 0),
    (8, 0, 255, 1), (16, 0, 0, 0), (20, 0, 0, 0), (17, 0, 0, 0),
]

OFFSETS = []
_bit = 0
for _w, _s, _d, _i in FIELDS:
    OFFSETS.append(_bit)
    _bit += _w
TOTAL_BITS = _bit

# ---------------------------------------------------------------------------
# What each index is, read off the MY RESUME screen with probe() -- every field
# set to its own index, so each line of the screen named its own field.  These
# are observed, not inferred.
# ---------------------------------------------------------------------------
POINTS = 1          # ONLINE POINTS
# Points come in three: one per mode and one overall.  Field 5 was read as
# TOTAL EARNINGS off MY RESUME, which cannot have been right -- 5 is not among
# the indices 0x002A0620 reads -- and the STATISTICS screen names it plainly as
# "Stroke Points".
MATCH_POINTS = 4                                  # "Match Points"
STROKE_POINTS = 5                                 # "Stroke Points"
TIGER_STATUS = 6    # ONLINE TIGER STATUS, 3 bits; 6 renders "T-I-G-E-R"

MATCH_WIN, MATCH_LOSS, MATCH_TIE = 7, 8, 9        # MATCH PLAY RECORD (W-L)
STROKE_WIN, STROKE_LOSS, STROKE_TIE = 10, 11, 12  # STROKE PLAY RECORD (W-L-T)
STROKE_STREAK = 13                                # STROKE PLAY CURRENT STREAK
MATCH_STREAK = 14                                 # MATCH PLAY CURRENT STREAK
STROKE_INC = 15                                   # STROKE PLAY INCOMPLETES
MATCH_INC = 16                                    # MATCH PLAY INCOMPLETES
STROKE_DONE = 19                                  # STROKE PLAY COMPLETES
MATCH_DONE = 20                                   # MATCH PLAY COMPLETES

# 15/19 and 16/20 are the two halves of the leaderboard's DROP% column.  The
# renderer at 0x00272458 reads four fields for a row and computes the fifth:
#
#     inc  = field(15)            ; 16 on the match board
#     done = field(19)            ; 20
#     if inc + done == 0:  drop = 0
#     elif inc >= inc + done:  drop = 100          ; 0x002724BC
#     else: drop = inc / (inc + done) * 100.0f     ; 0x002724D0, 0x42C80000
#
# So a player with completed rounds and no incompletes reads 0%, and one whose
# `done` was never sent reads 100% however many rounds they finished -- which
# is exactly what the first working leaderboard showed.

# ONLINE GAME MODES -> STATISTICS, read straight off the screen under
# --probe-stats.  None of these six appear anywhere in the code: they are bound
# by frontend script (section 43), so the screen was the only way to name them.
TOTAL_EAGLES = 30
TOTAL_BIRDIES = 31
TOTAL_GIR = 33
FAIRWAYS_HIT = 36
GIR_PERCENT = 42                                  # 7 bits, drawn with a '%'
PUTTS_PER_HOLE = 43                               # 10 bits, HUNDREDTHS
HOLES_PER_EAGLE = 44                              # 7 bits
BIRDIE_AVERAGE = 45                               # 7 bits
DRIVING_ACCURACY = 46                             # 7 bits, a percentage

# Scale, measured under --probe-stats: a field holding its own index drew
#
#     GIR PERCENTAGE   42       ->  "42%"     whole percent
#     PUTTS PER HOLE   43       ->  "0.43"    hundredths
#     BIRDIE AVERAGE   45       ->  "45"      a whole number, no decimal
#     DRIVING ACCURACY 46       ->  "46"      whole percent
#
# so only 43 is fixed point.  PUTTS_PER_HOLE is the one field that has to be
# multiplied by 100 before it is packed.
PUTTS_SCALE = 100

# The three above are RATIOS THE SERVER HAS TO WORK OUT.  The client does not
# divide anything -- "HOLES PER EAGLE" read back 44 and "DRIVING ACCURACY %"
# read back 46, their own indices, so each is a plain stored field.

EVENTS_ENTERED = 26
EVENTS_WON = 27
TOP10 = 28
TOP25 = 29

HOLES_IN_ONE = 32
LONGEST_PUTT = 34
LONGEST_DRIVE = 37
BEST_ROUND = 39                                   # signed, 8 bits
SCORING_AVERAGE = 41                              # signed, 8 bits

NAMED = {
    POINTS: 'ONLINE POINTS',
    MATCH_POINTS: 'MATCH POINTS', STROKE_POINTS: 'STROKE POINTS',
    TIGER_STATUS: 'TIGER STATUS',
    MATCH_WIN: 'MATCH W', MATCH_LOSS: 'MATCH L', MATCH_TIE: 'MATCH T',
    STROKE_WIN: 'STROKE W', STROKE_LOSS: 'STROKE L', STROKE_TIE: 'STROKE T',
    STROKE_STREAK: 'STROKE STREAK', MATCH_STREAK: 'MATCH STREAK',
    STROKE_INC: 'STROKE INC', MATCH_INC: 'MATCH INC',
    STROKE_DONE: 'STROKE DONE', MATCH_DONE: 'MATCH DONE',
    EVENTS_ENTERED: 'EVENTS ENTERED', EVENTS_WON: 'EVENTS WON',
    TOP10: 'TOP 10', TOP25: 'TOP 25',
    TOTAL_EAGLES: 'TOTAL EAGLES', TOTAL_BIRDIES: 'TOTAL BIRDIES',
    TOTAL_GIR: 'TOTAL GIR', GIR_PERCENT: 'GIR %',
    PUTTS_PER_HOLE: 'PUTTS/HOLE x100',
    FAIRWAYS_HIT: 'FAIRWAYS HIT', HOLES_PER_EAGLE: 'HOLES PER EAGLE',
    BIRDIE_AVERAGE: 'BIRDIE AVERAGE', DRIVING_ACCURACY: 'DRIVING ACCURACY',
    HOLES_IN_ONE: 'HOLES IN ONE', LONGEST_PUTT: 'LONGEST PUTT',
    LONGEST_DRIVE: 'LONGEST DRIVE', BEST_ROUND: 'BEST ROUND',
    SCORING_AVERAGE: 'SCORING AVERAGE',
}

# Still unaccounted for: 0, 2, 3, 17, 18, 21-25, 35, 38, 40, 47-55.  38 and 50
# are read by the resume renderer 0x002A0620 but have not named themselves on a
# screen yet.  The STATISTICS screen has no "Match Ties" line even though 9 is
# read by the challenge blob, so match play may simply not record one.
# EARNINGS RANK reads N/A, so whichever field feeds it was zero in the probe --
# a rank of 0 is how both rank lines render "N/A".  Fields 17 and 18 are only
# three bits and clamped to 7 in the probe, so they could not name themselves;
# they are NOT the W/L prefix -- that comes from the sign of 13 and 14
# themselves, and the leaderboard's row getter is only ever called with
# 13, 14, 15, 16, 19 and 20 (every `jal 0x00273990` in the image).


# The course names, in order, from the string block at 0x00308550.  `COUR` in a
# challenge is an index into this list: the capture that carried `COUR=5` was
# the challenge whose setup screen read COURSE: BETHPAGE BLACK, which is index 5
# here.  The tee colours follow the courses in the same block at 0x00308768.
COURSES = [
    'Pebble Beach', 'Princeville Resort', 'TPC at Sawgrass', 'Black Rock Cove',
    'Penguin Falls', 'Bethpage Black', 'Royal Birkdale', 'Skillz',
    'Bay Hill Club', 'The Predator', 'Spyglass Hill', 'Poppy Hills',
    'The Highlands', 'TPC of Scottsdale', 'Torrey Pines', 'St Andrews',
    'Sahalee CC', 'Emerald Dragon', 'Wallaby Creek', 'Kapalua Plantation',
    'Pinehurst No. 2', 'NA', "Tiger's Dream 18", 'Random 18',
    'Compilation 1', 'Compilation 2', 'Compilation 3', 'Compilation 4',
    'Compilation 5', 'Compilation 6',
]
TEES = ['Black', 'Blue', 'White', 'Red']


# CFLG -- the match conditions from a challenge.  It is NOT a packed integer:
# each setting is ONE-HOT, one bit per possible value.  Four single-variable
# challenges named four of the five groups outright:
#
#   0x10024864  pins=0 green=0 rough=0 fairway=0   baseline, everything lowest
#   0x040248A4  pins=1                             only the pins were changed
#   0x08025064         green=1                     only the green speed
#   0x04028864                rough=1              only the rough length
#   0x080450A4  pins=1 green=1        fairway=1    pins Med, green+fairway Hard
#
# Only bits 2 and 5 are fixed across every sample.  Bit 14 looked fixed until a
# rough-length change moved it to 15, which is what a "one-hot group" model
# catches and an "it is a constant" assumption does not.
CFLG_FIXED = (2, 5)
CFLG_GROUPS = (6, 11, 14, 17, 26)   # base bit of each one-hot group
CFLG_GROUP_SPAN = 3                 # Easy/Med/Hard, Short/Average/Long

# Named by changing exactly one setting per challenge and watching which group
# moved.  Group 26 moves on its own -- see below.
CFLG_NAMES = {6: 'pins', 11: 'green speed', 14: 'rough length',
              17: 'fairway speed', 26: 'unknown'}

# Group 26 is NOT a condition.  It took three different values across three
# challenges whose settings were identical, and changed in every single-variable
# sample without being touched.  Whatever it is -- a nonce, a counter, a menu
# cursor -- it does not describe the match, so the server does not report it.
CFLG_UNEXPLAINED_GROUP = 26


def cflg_groups(value):
    """Decompose a CFLG into (fixed_bits_present, {base: index}, leftover).

    `index` is which option within the group is selected, or None when no bit
    in that group is set.  `leftover` is every set bit the model does not
    explain -- if that is ever non-empty, the model is wrong, which is exactly
    how bit 14 was caught.
    """
    try:
        value = int(value)
    except (TypeError, ValueError):
        return (), {}, []
    bits = {i for i in range(32) if value >> i & 1}
    fixed = tuple(b for b in CFLG_FIXED if b in bits)
    groups, claimed = {}, set(fixed)
    for base in CFLG_GROUPS:
        groups[base] = None
        for n in range(CFLG_GROUP_SPAN):
            if base + n in bits:
                groups[base] = n
                claimed.add(base + n)
                break
    return fixed, groups, sorted(bits - claimed)


def conditions(value):
    """{name: index} for the settings a CFLG describes.

    The unexplained group is left out: reporting a number nobody can interpret
    is worse than reporting nothing.
    """
    _fixed, groups, _leftover = cflg_groups(value)
    return {CFLG_NAMES[base]: idx for base, idx in groups.items()
            if base != CFLG_UNEXPLAINED_GROUP and idx is not None}


def describe_cflg(value):
    """A short readable form for the log."""
    fixed, groups, leftover = cflg_groups(value)
    parts = ['%s=%s' % (CFLG_NAMES[base], '-' if idx is None else idx)
             for base, idx in sorted(groups.items())]
    if len(fixed) != len(CFLG_FIXED):
        parts.append('fixed=%s' % (','.join(map(str, fixed)) or 'none'))
    if leftover:
        parts.append('UNEXPLAINED=%s' % ','.join(map(str, leftover)))
    return ' '.join(parts)


def course_name(index):
    """The course a `COUR` value names, or a readable fallback."""
    try:
        index = int(index)
    except (TypeError, ValueError):
        return ''
    if 0 <= index < len(COURSES):
        return COURSES[index]
    return 'course %d' % index


# ---------------------------------------------------------------------------
# Layer 1: escaping
# ---------------------------------------------------------------------------
def unescape(data, groups=None):
    """Escaped bytes -> the raw record.  Mirrors 0x002736C0."""
    if groups is None:
        groups = len(data) // GROUP_SIZE
    out = bytearray()
    for g in range(groups):
        base = g * GROUP_SIZE
        if base + GROUP_SIZE > len(data):
            break
        mask = data[base]
        for n in range(GROUP_PAYLOAD):
            byte = data[base + 1 + n]
            out.append((byte & 0x7F) | (0x80 if mask & (1 << n) else 0))
    return bytes(out)


def escape(raw, groups=None):
    """The raw record -> escaped bytes, every one of them >= 0x80.

    The top bit of each transmitted byte is forced on so the result can never
    contain a NUL and terminate the text field early.  0x002736C0 ignores bit 7
    of a mask byte and replaces bit 7 of a payload byte, so setting both is
    free.
    """
    if groups is None:
        groups = (len(raw) + GROUP_PAYLOAD - 1) // GROUP_PAYLOAD
    raw = bytes(raw).ljust(groups * GROUP_PAYLOAD, b'\0')
    out = bytearray()
    for g in range(groups):
        chunk = raw[g * GROUP_PAYLOAD:(g + 1) * GROUP_PAYLOAD]
        mask = 0x80
        for n, byte in enumerate(chunk):
            if byte & 0x80:
                mask |= 1 << n
        out.append(mask)
        for byte in chunk:
            out.append((byte & 0x7F) | 0x80)
    return bytes(out)


# ---------------------------------------------------------------------------
# Layer 2: bit fields
# ---------------------------------------------------------------------------
def get_field(raw, index):
    """Field `index` out of the decoded record.  Mirrors 0x00273780."""
    width, signed, _default, _invert = FIELDS[index]
    bit = OFFSETS[index]
    value = 0
    for n in range(width):
        pos = bit + n
        byte = pos >> 3
        if byte >= len(raw):
            break
        if raw[byte] & (1 << (pos & 7)):
            value |= 1 << n
    if signed and width and value & (1 << (width - 1)):
        value -= 1 << width
    return value


def set_field(raw, index, value):
    """Write field `index` into a mutable bytearray."""
    width, signed, _d, _inv = FIELDS[index]
    if signed:
        value &= (1 << width) - 1
    elif value < 0:
        value = 0
    value = min(value, (1 << width) - 1)
    bit = OFFSETS[index]
    for n in range(width):
        pos = bit + n
        byte = pos >> 3
        if byte >= len(raw):
            return
        if value & (1 << n):
            raw[byte] |= 1 << (pos & 7)
        else:
            raw[byte] &= ~(1 << (pos & 7)) & 0xFF


def unpack(escaped):
    """Every field of an escaped statistics record."""
    raw = unescape(escaped, STAT_GROUPS)
    return [get_field(raw, i) for i in range(len(FIELDS))]


def pack(values):
    """{index: value} -> the complete `S` field, marker included.

    121 bytes: fifteen escaped groups then `'!'`.  Anything not given keeps the
    field's own default from the table, so a caller only has to fill in what it
    knows.
    """
    raw = bytearray(STAT_DECODED)
    for i, (_w, _s, default, _inv) in enumerate(FIELDS):
        if default:
            set_field(raw, i, default)
    for index, value in (values or {}).items():
        set_field(raw, index, int(value))
    return escape(bytes(raw), STAT_GROUPS) + bytes([MARKER])


def probe():
    """Every field set to its own index, so a screen names its own fields.

    Ten of the 56 indices are known, all from the challenge blob, and the
    guesses made from them were wrong: writing points into index 1 did not move
    ONLINE POINTS.  Rather than guess again, fill each field with its own index
    and read the answers off the screen -- SCORING AVERAGE showing 21 means
    scoring average is field 21.

    Field 0 is indistinguishable from an unset field this way, and fields
    narrower than the index they hold are clamped, so a screen value equal to a
    field's maximum means "this field, or a wider one that got clamped".
    """
    values = {}
    for i, (width, signed, _d, _inv) in enumerate(FIELDS):
        top = (1 << (width - 1)) - 1 if signed else (1 << width) - 1
        values[i] = min(i, top)
    return pack(values)


def main():
    """Round-trip the codec, and decode a real captured CRPIN blob."""
    fails = []
    print('%d fields, %d bits, %d decoded bytes available'
          % (len(FIELDS), TOTAL_BITS, STAT_DECODED))
    if TOTAL_BITS > STAT_DECODED * 8:
        fails.append('the fields do not fit in the record')

    # 1. every field round-trips at its full width
    probe = {}
    for i, (width, signed, _d, _inv) in enumerate(FIELDS):
        probe[i] = (1 << (width - 1)) - 1 if signed else (1 << width) - 1
    blob = pack(probe)
    print('packed S is %d bytes, marker 0x%02X, min byte 0x%02X'
          % (len(blob), blob[-1], min(blob[:-1])))
    if len(blob) != STAT_ESCAPED + 1:
        fails.append('S should be %d bytes, got %d' % (STAT_ESCAPED + 1, len(blob)))
    if blob[-1] != MARKER:
        fails.append('missing the 0x21 marker')
    if min(blob[:-1]) < 0x80:
        fails.append('an escaped byte was below 0x80 and could terminate the field')
    back = unpack(blob[:-1])
    for i in sorted(probe):
        if back[i] != probe[i]:
            fails.append('field %d round-tripped %r -> %r' % (i, probe[i], back[i]))

    # 2. a realistic record
    sample = {POINTS: 1234, TIGER_STATUS: 5, MATCH_WIN: 7, MATCH_LOSS: 2,
              MATCH_TIE: 1, STROKE_INC: 3}
    got = unpack(pack(sample)[:-1])
    print('sample: ' + ', '.join('%s=%d' % (NAMED[i], got[i]) for i in sorted(NAMED)))
    for i, v in sample.items():
        if got[i] != v:
            fails.append('%s should be %d, got %d' % (NAMED.get(i, i), v, got[i]))
    # 3. the streaks are the only signed fields, so they are the only ones
    #    that can come back negative -- a losing streak the client draws "L3".
    for streak in (STROKE_STREAK, MATCH_STREAK):
        for run in (5, 0, -1, -3, -128, 127):
            if unpack(pack({streak: run})[:-1])[streak] != run:
                fails.append('field %d lost the sign of %d' % (streak, run))
    if unpack(pack({})[:-1])[13] != 0:
        fails.append('an unset streak should be 0, not the old default of 1')

    # 3. the escaping, against a real captured golfer blob.  665 bytes is
    #    83 groups plus the marker -- that is what fixes the group size at 7.
    crpin_len = 665
    groups, rest = divmod(crpin_len - 1, GROUP_SIZE)
    print('a %d-byte CRPIN is %d groups + %d spare, decoding to %d bytes'
          % (crpin_len, groups, rest, groups * GROUP_PAYLOAD))
    if rest:
        fails.append('CRPIN does not divide into whole groups')
    payload = bytes(range(256)) * 3
    payload = payload[:groups * GROUP_PAYLOAD]
    if unescape(escape(payload, groups), groups) != payload:
        fails.append('escape/unescape is not a round trip over all byte values')

    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: escaping round-trips every byte value, all 56 fields round-trip '
          'at full\n    width, defaults survive, and the marker is in place')
    return 0


if __name__ == '__main__':
    sys.exit(main())
