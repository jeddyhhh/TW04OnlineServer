"""Generate the PCSX2 .pnach that redirects TW04's lobby and skips DNAS.

    python make_pnach.py 192.168.1.50
    python make_pnach.py 192.168.1.50 --port 10200 --out <pcsx2>/cheats
    python make_pnach.py 192.168.1.50 --real-ps2     # + the cheat-device files

Without --out the patch is written to the current folder.  --real-ps2 also
writes the same patch as codes for a real console's cheat engine (UNTESTED):
SLUS_207.57.cht for Open PS2 Loader, and TW04-CheatDevice.txt for Cheat Device.

Both patches are memory writes -- the ISO is never touched, and deleting the
.pnach undoes everything.

WHAT IT PATCHES

1. The lobby address, an IP literal in two places in the ELF, rewritten in
   place.  The replacement must fit in 15 characters plus a NUL.

2. DNAS.  By default we force the branch at 0x002E1468 so the game's own
   "DNAS never initialised" path runs and sets its pass byte.  The module still
   loads and still fails in the background hunting
   gate1.us.dnas.playstation.org, which costs a few seconds but does not block.

   --strong-dnas instead overwrites the driver at 0x002E1430 with "set the pass
   byte, return", so 0x002E11A0 -- its only caller -- never runs and DNAS never
   starts.  Cleaner, but it has not yet run successfully, so it is not the
   default.

EVERY PATCH USES `word`, NOT `extended`.  See the comment on emit() -- getting
this wrong cost three capture attempts and looked like four different bugs.
"""
import argparse
import ipaddress
import os
import struct
import sys

SERIAL = 'SLUS-20757'
CRC = '64F9781E'
TITLE = 'Tiger Woods PGA Tour 2004 (USA)'

IP_ADDRS = (0x0030FAC0, 0x00311040)     # '159.153.229.231', 16 bytes each
PORT_ADDRS = (0x0030FAD0, 0x00311050)   # '10200', 8 bytes each
IP_FIELD = 16
PORT_FIELD = 8

# Overwrite the DNAS driver's prologue with "done, passed, and return".
#
# THERE ARE TWO BYTES, NOT ONE.  The first version of this set only the pass
# byte and the game hung for ever on "AUTHENTICATING DNAS DATA... PLEASE
# WAIT...".  The screen is not waiting to be told the answer; it is waiting to
# be told there IS one:
#
#   0x002E1590  jr $ra ; lbu $v0, -0x650e($gp)     DNAS_IsDone()
#   0x002E15A0  jr $ra ; lbu $v0, -0x650d($gp)     DNAS_Passed()
#
# and the game polls the first.  `-0x650e` is set to 1 by the three-instruction
# function at 0x002E1580, which the real module calls when it finishes; with
# the driver stubbed out nothing ever called it, so IsDone stayed 0 and the
# dialog sat there.  0x002E11A0 clears both bytes (plus -0x650f and -0x6510)
# when it starts, which is what named them.
#
# So the stub writes both, with the same values their own setters use:
# -0x650e = 1 from 0x002E1588, -0x650d = 1 from 0x002E1484.
#
# Still opt-in.  Setting the two bytes is what the module's own success path
# leaves behind, but that path also calls 0x00294A00(0xBA) on its way through
# (0x002E1474) and this does not.  If that call turns out to matter, the
# symptom would be a dialog that never closes even though the game has moved
# on -- in which case use the default patch, which keeps the module running.
DNAS_DRIVER = 0x002E1430
DNAS_DRIVER_NEW = [
    (0x24030001, 'addiu $v1, $zero, 1'),
    (0xA3839AF2, 'sb    $v1, -0x650e($gp)   -- "done", as 0x002E1588 writes it'),
    (0xA3839AF3, 'sb    $v1, -0x650d($gp)   -- "passed", as 0x002E1484 writes it'),
    (0x03E00008, 'jr    $ra'),
    (0x00000000, 'nop'),
]
# Safe to overwrite five words: every branch inside the driver targets
# 0x002E1450 or later, so nothing jumps into what this replaces.
DNAS_LOAD = 0x002E1468                  # lw $v1, -0x1490($at); superseded
DNAS_LOAD_NEW = 0x00001821              # addu $v1, $zero, $zero


# --- real consoles -----------------------------------------------------------
#
# A PS2 cheat engine (PS2rd, Open PS2 Loader's built-in one, Cheat Device) only
# runs codes once it has hooked the game, and the hook is game-specific: a
# "9" master code naming a regularly called `jal` and the instruction there.
# This one comes from the game's CodeBreaker v1-5 master code, FA7A006E
# 32C1BEF9, which decrypts (CodeBreaker's published v1 scheme) to
# F0100008 001135AF: the ELF's entry point, and a hook at 0x001135AC -- where
# the ELF does hold `jal 0x0011E9A0`, 0x0C047A68.  Every other code is a type-2
# constant 32-bit write of exactly what the .pnach writes.
#
# NONE OF THIS HAS BEEN TRIED ON A REAL CONSOLE.
MASTER_CODE = (0x001135AC, 0x0C047A68)
CHT_NAME = 'SLUS_207.57.cht'                    # OPL looks for <game ID>.cht
CHEATDEVICE_NAME = 'TW04-CheatDevice.txt'
REAL_PS2_TITLE = 'Tiger Woods PGA Tour 2004 (NTSC-U)'


def words(text, field):
    """Pad `text` with NULs to `field` bytes and return little-endian words."""
    raw = text.encode('ascii')
    if len(raw) >= field:
        raise SystemExit('%r needs %d bytes, only %d available'
                         % (text, len(raw) + 1, field))
    raw = raw.ljust(field, b'\0')
    return [struct.unpack_from('<I', raw, i)[0] for i in range(0, field, 4)]


# Use `word`, not `extended`.
#
# `extended` is the Action-Replay-style handler: it treats the top nibble of the
# address as an opcode, and for a plain 0x00xxxxxx address it does NOT write 32
# bits -- it writes the low byte only.  That silently wrecked every patch here:
#
#   * the IP string became '159.153.029.' (one byte per word, then a NUL), which
#     is not a parseable dotted quad, so Lobby_Connect never resolved an address
#     and returned -7 without ever calling connect().  That is why runs 1 and 2
#     showed "CONNECTING TO LOBBY" on screen and zero TCP in the emulator log.
#   * the DNAS patch turned `addiu $sp, $sp, -0x10` into `addiu $sp, $sp, -0xff`,
#     misaligning the stack right before an `sd $ra, 0($sp)`.  That is the boot
#     crash: TLB miss, then pc=0.
#
# `word` is an unconditional memWrite32 and is what we actually want.
def emit(addr, value, note=''):
    line = 'patch=1,EE,%08X,word,%08X' % (addr, value)
    return '%-40s // %s' % (line, note) if note else line


# --- the 13-bit clamp on a leaderboard row's first word -------------------
#
# The generic `+snp` / `+rnk` row reader stores `P` at row+0x00 and then does:
#
#   0x002BCAE8  lw    v1, (s2)          ; the value it just stored
#   0x002BCAEC  slti  v1, v1, 0x2000    ; under 8192?
#   0x002BCAF0  bnel  v1, zero, +4      ; yes -> leave it
#   0x002BCAF8  addiu v0, zero, 0x1FFF
#   0x002BCAFC  sw    v0, (s2)          ; no  -> clamp to 8191
#
# On lists 33, 34 and 35 that word is a DATE -- days since 1 Jan 2003 -- so the
# clamp is also a calendar limit: nothing after 2025-06-05 can be drawn,
# whatever the server sends.  8191 days from a 2003 release is about the shelf
# life someone had in mind, so it looks deliberate rather than accidental.
#
# Raising the two constants moves the ceiling to 2092 and changes nothing else:
# the clamp still happens, it just stops mattering.  Both replacements were
# re-encoded and checked against the words actually in the ELF.
# THERE ARE TWO COPIES of this clamp, one per row message, and they are the
# same five instructions with the same registers:
#
#   0x002BCAEC  `+rnk`  -- the handler that reads A, N and S
#   0x002BCD44  `+snp`  -- the one that reads P, N and S, identified by the
#                          `lw $v0, 0x508($s3)` right after it, which is the
#                          snapshot channel
#
# The leaderboards are fed by `+snp`, so patching only `+rnk` changes nothing
# visible -- which is exactly what happened the first time.
DATE_CLAMPS = (
    (0x002BCAEC, 0x28637FFF, 'slti  $v1, $v1, 0x7FFF   (was 0x2000)  +rnk'),
    (0x002BCAF8, 0x24027FFE, 'addiu $v0, $zero, 0x7FFE (was 0x1FFF)'),
    (0x002BCD44, 0x28637FFF, 'slti  $v1, $v1, 0x7FFF   (was 0x2000)  +snp'),
    (0x002BCD50, 0x24027FFE, 'addiu $v0, $zero, 0x7FFE (was 0x1FFF)'),
)


def build(ip, port, strong=False, comment=None):
    out = [
        'gametitle=%s' % TITLE,
        'comment=%s' % (comment or 'Lobby redirect + DNAS bypass. '
                        'Generated by make_pnach.py.'),
        '',
        '// --- lobby server address: %s -> %s ---' % ('159.153.229.231', ip),
    ]
    for base in IP_ADDRS:
        for n, w in enumerate(words(ip, IP_FIELD)):
            out.append(emit(base + n * 4, w, 'IP string +%d' % (n * 4) if n == 0 else ''))
    if port != 10200:
        out.append('')
        out.append('// --- lobby port: 10200 -> %d ---' % port)
        for base in PORT_ADDRS:
            for n, w in enumerate(words(str(port), PORT_FIELD)):
                out.append(emit(base + n * 4, w))
    if strong:
        out += [
            '',
            '// --- DNAS: stop the driver at 0x002E1430 ever starting the module ---',
        ]
        for n, (word, note) in enumerate(DNAS_DRIVER_NEW):
            out.append(emit(DNAS_DRIVER + n * 4, word, note))
    else:
        out += [
            '',
            '// --- DNAS: force the "not initialised" branch so the check passes ---',
            '// The module still loads and still fails in the background; that costs',
            '// a few seconds on the DNAS screen but does not block the lobby.',
            emit(DNAS_LOAD, DNAS_LOAD_NEW, 'addu $v1, $zero, $zero'),
            '',
            '// Stronger version, stops DNAS running at all -- make_pnach.py --strong-dnas',
        ]
        for n, (word, note) in enumerate(DNAS_DRIVER_NEW):
            out.append('//' + emit(DNAS_DRIVER + n * 4, word, note))
    out += [
        '',
        '// --- leaderboard date ceiling ---',
        '// The tournament leaderboards draw their first column as a date',
        '// counted from 2003, and the row reader clamps that word to 13 bits',
        '// (0x002BCAEC), so they stop dead at 2025-06-05 -- a date that has',
        '// already passed.  Without these two the columns read 6/5/25 on any',
        '// console with a correct clock, so they are not optional.',
    ]
    for addr, word, note in DATE_CLAMPS:
        out.append(emit(addr, word, note))
    out.append('')
    return '\n'.join(out)


def writes(ip, port):
    """[(address, word)]: every write the default patch makes, in order."""
    out = []
    for base in IP_ADDRS:
        out += [(base + n * 4, w) for n, w in enumerate(words(ip, IP_FIELD))]
    if port != 10200:
        for base in PORT_ADDRS:
            out += [(base + n * 4, w)
                    for n, w in enumerate(words(str(port), PORT_FIELD))]
    out.append((DNAS_LOAD, DNAS_LOAD_NEW))
    out += [(addr, word) for addr, word, _note in DATE_CLAMPS]
    return out


def _codes(ip, port):
    """The cheat lines: master code, then one type-2 write per patch word."""
    master = ['Master Code', '9%07X %08X' % MASTER_CODE]
    online = ['TW04 Online - UNTESTED (lobby %s:%d, DNAS, leaderboard dates)'
              % (ip, port)]
    online += ['2%07X %08X' % (addr, word) for addr, word in writes(ip, port)]
    return master, online


def build_cht(ip, port):
    """Open PS2 Loader's <game ID>.cht (PS2rd format).  Every line that is
    not 16 hex digits is read as a cheat NAME, so it carries no comments."""
    master, online = _codes(ip, port)
    return '\n'.join(master + [''] + online) + '\n'


def build_cheatdevice(ip, port):
    """Cheat Device's TXT database: the game title in quotes, then cheats."""
    master, online = _codes(ip, port)
    return '\n'.join(['"%s"' % REAL_PS2_TITLE] + master + [''] + online) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('ip', help='where lobbyd is listening, as seen from the emulated PS2')
    ap.add_argument('--port', type=int, default=10200)
    ap.add_argument('--strong-dnas', action='store_true',
                    help='stop the DNAS driver entirely instead of just forcing its result')
    ap.add_argument('--out', default=None,
                    help='PCSX2 cheats directory (default: the current folder)')
    ap.add_argument('--real-ps2', action='store_true',
                    help='also write the UNTESTED real-console cheat files '
                         '(%s, %s)' % (CHT_NAME, CHEATDEVICE_NAME))
    args = ap.parse_args()

    try:
        ipaddress.IPv4Address(args.ip)
    except ipaddress.AddressValueError:
        raise SystemExit('%r is not an IPv4 address; TW04 cannot take a hostname' % args.ip)

    text = build(args.ip, args.port, args.strong_dnas)
    outdir = args.out or os.getcwd()
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, '%s_%s.pnach' % (SERIAL, CRC))
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)
    print(text)
    print('written to %s' % path)
    if args.real_ps2:
        for name, body in ((CHT_NAME, build_cht(args.ip, args.port)),
                           (CHEATDEVICE_NAME,
                            build_cheatdevice(args.ip, args.port))):
            extra = os.path.join(outdir, name)
            with open(extra, 'w', encoding='utf-8', newline='\n') as f:
                f.write(body)
            print('written to %s (untested on a real PS2)' % extra)
    if not args.out:
        print('\nCopy it into <PCSX2>/cheats/ and tick Enable Cheats for the game.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
