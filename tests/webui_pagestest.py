"""The player, stats, records and course pages, and the in-game news.

    python tests/webui_pagestest.py

Builds the twrecords sample database (three golfers, a match, tournament rounds,
a hole in one and the real 1025-putt card) plus a golfer whose name is full of
characters that break HTML and URLs, then serves it the way the live site is
served -- behind a base path -- and reads every new page back.  Last, a real
lobby on the same database answers `news NAME=1`, and the news screen has to
carry the operator's text first and the generated digest after it.
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import eacrypt
import tagfield
import twrecords
import twtourney
from lobbyd import HDR, SESSION_KEY, cc, cc2i

WEB = 8097
LOBBY = 10294
BASE = '/TW04Online'
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-pages.db')
NEWS = os.path.join(tempfile.gettempdir(), 'tw04-test-news.txt')
ODD = 'Tom & <Jo>/#1'                  # every character check_name allows


def fetch(path):
    url = 'http://127.0.0.1:%d%s' % (WEB, path)
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')


def wait_port(port):
    for _ in range(100):
        try:
            socket.create_connection(('127.0.0.1', port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.1)


def frame(kind, tags):
    payload = tagfield.encode(tags).encode('latin-1') + b'\0'
    return struct.pack('>III', cc2i(kind), 0, HDR + len(payload)) + payload


LEFTOVER = {}


def read(sock):
    buf = LEFTOVER.pop(sock, b'')
    while len(buf) < HDR:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError('server closed early')
        buf += chunk
    kind, ident, size = struct.unpack('>III', buf[:HDR])
    while len(buf) < size:
        buf += sock.recv(4096)
    if len(buf) > size:
        LEFTOVER[sock] = buf[size:]
    return cc(kind), ident, buf[HDR:size]


def expect(sock, kind):
    for _ in range(40):
        got, ident, body = read(sock)
        if got == kind:
            return ident, body
    raise AssertionError('never saw %r' % kind)


def news_screen():
    """Sign alice in and ask for the news, as the console does."""
    sock = socket.create_connection(('127.0.0.1', LOBBY), timeout=10)
    try:
        sock.sendall(frame('skey', {'SKEY': b'Public Key'}))
        expect(sock, 'skey')
        ct = '~' + eacrypt.encode('password', SESSION_KEY).decode('latin-1')
        sock.sendall(frame('auth', {'NAME': 'alice', 'PASS': ct, 'TOS': '1'}))
        ident, _ = expect(sock, 'auth')
        assert not ident, 'alice could not sign in: %s' % cc(ident)
        sock.sendall(frame('news', {'NAME': '1'}))
        _, body = expect(sock, 'news')
        return body.rstrip(b'\0').decode('latin-1')
    finally:
        sock.close()


def main():
    today = twtourney.today()
    db = twrecords.sample(TEST_DB, today, extra=(ODD,))
    db.add_tourney(ODD, today, 4, {'HOLES': 18, 'STROKES': 72, 'PARS': 18,
                                   'PUTTS': 32, 'GIR': 9, 'FRWY': 7, 'DRVS': 14,
                                   'LDRV': 280, 'LPUT': 12, 'DONE': 1})
    with open(NEWS, 'w', encoding='utf-8') as f:
        f.write('Server maintenance on Friday.\n')

    procs = [
        subprocess.Popen(
            [sys.executable, os.path.join(HERE, 'webui.py'), '--host',
             '127.0.0.1', '--port', str(WEB), '--db', TEST_DB, '--base-path',
             BASE, '--no-secure-cookie', '--logfile', '', '--reports-key',
             'off'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT),
        subprocess.Popen(
            [sys.executable, os.path.join(HERE, 'lobbyd.py'), '--host',
             '127.0.0.1', '--port', str(LOBBY), '--db', TEST_DB, '--logfile',
             '', '--ping', '0', '--buddy-port', '0', '--news', NEWS],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT),
    ]
    fails = []

    def check(path, status, *want, absent=()):
        got, body = fetch(BASE + path)
        missing = [w for w in want if w not in body]
        present = [a for a in absent if a in body]
        print('%-34s %d%s' % (path[:34], got,
                              '' if not (missing or present) else '  <-- here'))
        if got != status:
            fails.append('%s should be %d, got %d' % (path, status, got))
        for w in missing:
            fails.append('%s should contain %r' % (path, w))
        for a in present:
            fails.append('%s must not contain %r' % (path, a))
        return body

    try:
        wait_port(WEB)
        wait_port(LOBBY)
        odd_url = '/player/' + urllib.parse.quote(ODD, safe='')

        # the pages
        check('/player/alice', 200, 'Head to head', 'Won v',
              'href="%s/player/bob"' % BASE, 'Best round', '66',
              'href="%s/course/4"' % BASE)
        check('/player/ALICE', 200, '<h1>alice')
        check(odd_url, 200, 'Tom &amp; &lt;Jo&gt;/#1', absent=('<Jo>',))
        check('/player/nobody', 404, 'Nobody here is called')
        check('/stats', 200, 'Driving distance', 'Greens in regulation',
              'href="%s/player/bob"' % BASE)
        check('/records', 200, 'Longest drive', '390 yd', 'Holes in one',
              'Course records', absent=('1025',))
        check('/courses', 200, 'Penguin Falls', 'href="%s/course/4"' % BASE)
        check('/course/4', 200, 'Course record', 'Best rounds',
              'Tom &amp; &lt;Jo&gt;/#1')
        check('/course/10', 200, 'Nobody has finished a round here')
        check('/course/99', 404)
        check('/course/abc', 404)
        # names on the existing pages now link, once-prefixed, and the odd
        # name is escaped in the link text and encoded in its address
        body = check('/tournaments', 200, 'href="%s%s"' % (BASE, odd_url))
        if 'href="%s%s' % (BASE, BASE) in body:
            fails.append('a link picked up the base path twice')
        check('/', 200, 'href="%s/stats"' % BASE, 'href="%s/records"' % BASE,
              'href="%s/courses"' % BASE)

        # the news screen
        text = news_screen()
        print('---- news screen ----\n%s\n---------------------' % text)
        for want in ('Server maintenance on Friday.', 'TODAY: Test Open',
                     'Won by alice with 66'):
            if want not in text:
                fails.append('the news screen should say %r' % want)
        if text.find('Server maintenance') > text.find('TODAY:'):
            fails.append("the operator's text goes before the digest")
        if any(len(line) > 63 for line in text.splitlines()):
            fails.append('a news line is wider than the 64-column screen')
    finally:
        for p in procs:
            p.terminate()
            p.wait(timeout=5)

    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: player, stats, records and course pages serve behind a base')
    print('    path with every name escaped and linked, and the news screen')
    print('    carries the operator\'s text and then the digest')
    return 0


if __name__ == '__main__':
    sys.exit(main())
