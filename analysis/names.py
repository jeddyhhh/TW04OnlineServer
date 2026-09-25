"""Recover function names from the debug-label strings the code passes around.

Nearly every Lobby_*/Tourn_*/_*Callback routine in these builds passes its own
name to a trace helper, so the enclosing function of that string reference is
the function the name belongs to.

usage: names.py <elf>
"""
import sys, os, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ee
from xref import load

NAMEISH = re.compile(r'^(Lobby_|Tourn_|_[A-Za-z])[A-Za-z0-9_]{2,}$')


def build(img, consts):
    """Return {func_vaddr: name}."""
    names = {}
    i = 0
    data = img.data
    while True:
        j = data.find(b'\0', i)
        if j < 0:
            break
        try:
            s = data[i:j].decode('ascii')
        except UnicodeDecodeError:
            s = None
        if s and s.startswith('(ERROR) '):
            s = s[len('(ERROR) '):]
        if s and NAMEISH.match(s):
            va = img.base + i
            for ref in consts.get(va, []):
                fs = ee.func_start(img, ref)
                if fs and fs not in names:
                    names[fs] = s
        i = j + 1
        # strings are packed back to back; skip the padding run
        while i < len(data) and data[i] == 0:
            i += 1
    return names


if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    img, consts, calls = load(path)
    names = build(img, consts)
    for fs in sorted(names):
        print('0x%08x  %s' % (fs, names[fs]))
