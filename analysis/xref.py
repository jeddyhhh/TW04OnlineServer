"""Who points at this address?  usage: xref.py <elf> <hex-vaddr|string> ..."""
import sys, pickle, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ee

CACHE = os.environ.get('TW_CACHE', os.path.join(os.path.dirname(os.path.abspath(__file__)), '_cache'))


def load(path):
    img = ee.Image(path)
    key = hashlib.md5((path + str(len(img.data))).encode()).hexdigest()[:12]
    os.makedirs(CACHE, exist_ok=True)
    cf = os.path.join(CACHE, key + '.pkl')
    if os.path.exists(cf):
        with open(cf, 'rb') as f:
            consts, calls = pickle.load(f)
    else:
        consts = ee.scan_constants(img)
        calls = ee.scan_calls(img)
        with open(cf, 'wb') as f:
            pickle.dump((consts, calls), f)
    return img, consts, calls


def find_string(img, text):
    """Every vaddr whose C string equals `text`."""
    needle = text.encode() + b'\0'
    out, i = [], 0
    while True:
        i = img.data.find(needle, i)
        if i < 0:
            break
        out.append(img.base + i)
        i += 1
    return out


if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    path = sys.argv[1]
    img, consts, calls = load(path)
    for arg in sys.argv[2:]:
        if arg.startswith('0x'):
            targets = [int(arg, 16)]
        else:
            targets = find_string(img, arg)
            if not targets:
                print('%-40s  (string not found)' % arg)
                continue
        for t in targets:
            s = img.cstr(t)
            label = '0x%08x %r' % (t, s if s is not None else '')
            refs = consts.get(t, [])
            cal = calls.get(t, [])
            print('%s' % label)
            for r in refs:
                fs = ee.func_start(img, r)
                print('    ref  @0x%08x   in func 0x%08x' % (r, fs or 0))
            for c in cal:
                print('    call @0x%08x' % c)
            if not refs and not cal:
                print('    (no refs)')
