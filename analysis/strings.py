"""Printable strings in a file, each tagged with its FILE OFFSET.

usage: strings.py <file> [minlen]

Like the Unix `strings -t x`, but self-contained.  Offsets are into the file,
not addresses: for the TW04 ELF, vaddr = file offset + 0xFFF00 (one PT_LOAD at
0x00100000, file offset 0x100) -- `elfinfo.py` prints the mapping for any ELF.
"""
import re
import sys


def strings(data, minlen=4):
    """Yield (offset, text) for every run of printable ASCII."""
    for m in re.finditer(rb'[\x20-\x7e\t]{%d,}' % minlen, data):
        yield m.start(), m.group().decode('ascii')


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    minlen = int(sys.argv[2]) if len(sys.argv) > 2 else 4
    with open(sys.argv[1], 'rb') as f:
        data = f.read()
    for off, text in strings(data, minlen):
        print('%08x  %s' % (off, text))


if __name__ == '__main__':
    main()
