"""Build the LobbyAPI request map: verb, tags sent, callback, per function.

Everything hangs off one routine -- LobbyApiRequest(pApi, u4CC, pTagBuf,
pCallback) -- so enumerating its call sites and constant-folding the arguments
gives the complete outbound surface of the protocol.

usage: requests_map.py <elf>
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ee
from xref import load
from tagscan import track, ARGS, render
import names as namemod

REQUEST = 0x002bad78          # LobbyApiRequest(pApi, u4CC, pTagBuf, pCallback)
SET_STR = 0x002be400          # TagFieldSetString(pBuf, iLen, pKey, pValue)
SET_NUM = 0x002be0c0          # TagFieldSetNumber(pBuf, iLen, pKey, iValue)
FIND    = 0x002bd958          # TagFieldFind(pBuf, pKey, ...)


def fourcc(v):
    if v is None:
        return '????'
    b = v.to_bytes(4, 'big')
    return b.decode('ascii') if all(0x20 <= c < 0x7f for c in b) else '0x%08x' % v


def args_at(img, site, n=4):
    fs = ee.func_start(img, site)
    if fs is None:
        return None, [None] * n
    reg = track(img, fs, site)
    return fs, [reg.get(ARGS[i]) for i in range(n)]


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    path = sys.argv[1]
    img, consts, calls = load(path)
    fname = namemod.build(img, consts)

    # tags touched, grouped by enclosing function
    sets, reads = {}, {}
    for callee, bucket, valpos in ((SET_STR, sets, 3), (SET_NUM, sets, 3), (FIND, reads, None)):
        for site in calls.get(callee, []):
            fs, a = args_at(img, site)
            if fs is None:
                continue
            key = a[2] if callee != FIND else a[1]
            k = img.cstr(key, 32) if key and img.valid(key) else None
            if not k:
                continue
            if valpos is None:
                bucket.setdefault(fs, []).append(k)
            else:
                v = render(img, a[valpos])
                kind = 's' if callee == SET_STR else 'n'
                bucket.setdefault(fs, []).append('%s=%s%s' % (k, v, '' if kind == 's' else ' (num)'))

    rows = []
    for site in calls.get(REQUEST, []):
        fs, a = args_at(img, site)
        rows.append((fname.get(fs, 'sub_%08x' % (fs or 0)), fs, site,
                     fourcc(a[1]), fname.get(a[3], ('0x%08x' % a[3]) if a[3] else '-')))
    rows.sort()

    print('# LobbyAPI requests in %s' % os.path.basename(path))
    print('# LobbyApiRequest = 0x%08x, %d call sites\n' % (REQUEST, len(rows)))
    for name, fs, site, cc, cb in rows:
        print("%-34s 0x%08x  verb '%s'  -> %s" % (name, fs or 0, cc, cb))
        for t in dict.fromkeys(sets.get(fs, [])):
            print('        send  %s' % t)
        for t in dict.fromkeys(reads.get(fs, [])):
            print('        read  %s' % t)
        print()

    print('\n# functions that parse tags but issue no request (callbacks)\n')
    for fs in sorted(set(reads) - set(r[1] for r in rows)):
        print('%-34s 0x%08x' % (fname.get(fs, 'sub_%08x' % fs), fs))
        print('        read  %s' % ', '.join(dict.fromkeys(reads[fs])))


main()
