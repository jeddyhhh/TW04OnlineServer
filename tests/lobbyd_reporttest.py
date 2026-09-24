"""REPORT ABUSE reaches the operator's secret page, with the chat attached.

    python tests/lobbyd_reporttest.py

Starts a real lobby and a real web site on one database.  Three consoles sign
in to a room; bob is rude in the room and in private, carol chats innocently,
and alice reports bob.  Then it checks what was stored -- bob's lines and the
private line between the two, never carol's, never the challenge handshake --
and that the web site serves it only at the secret address, uncached and
unindexed, behind a base path, and that "Mark handled" files it.
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
import twdb
from lobbyd import HDR, SESSION_KEY, cc, cc2i

PORT = 10298
WEB = 8098
BASE = '/TW04Online'
KEY = 'test-reports-key-0123456789'
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-report.db')
ROOM = 'Stroke.T.East'
PLAYERS = [('alice', 'alicepass'), ('bob', 'bobpass'), ('carol', 'carolpass')]
RUDE = 'you are <b>terrible</b> & slow'


def frame(kind, tags, ident=0):
    payload = tagfield.encode(tags).encode('latin-1') + b'\0'
    return struct.pack('>III', cc2i(kind), ident, HDR + len(payload)) + payload


# Bytes read past the end of a frame, per socket.  Two frames sent back to
# back -- `RGET` then its `ROST`s -- can arrive in ONE recv, and a reader that
# drops the tail loses the second: an intermittent timeout that only shows up
# when the server is fast enough to coalesce them.
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
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError('server closed early')
        buf += chunk
    if len(buf) > size:
        LEFTOVER[sock] = buf[size:]
    return cc(kind), ident, buf[HDR:size]


def expect(sock, kind):
    for _ in range(40):
        got, ident, body = read(sock)
        if got == kind:
            return ident, body
    raise AssertionError('never saw a %r reply' % kind)


def sign_in(name, password):
    sock = socket.create_connection(('127.0.0.1', PORT), timeout=5)
    sock.sendall(frame('skey', {'SKEY': b'Public Key'}))
    expect(sock, 'skey')
    ct = '~' + eacrypt.encode(password, SESSION_KEY).decode('latin-1')
    sock.sendall(frame('auth', {'NAME': name, 'PASS': ct, 'TOS': '1'}))
    ident, _ = expect(sock, 'auth')
    assert not ident, 'auth for %s failed: %s' % (name, cc(ident))
    sock.sendall(frame('pers', {'PERS': name}))
    expect(sock, 'pers')
    sock.sendall(frame('move', {'NAME': ROOM}))
    expect(sock, 'move')
    return sock


def say(sock, text, to=None, attr=None):
    tags = {'TEXT': text}
    if to:
        tags['PRIV'] = to
    if attr:
        tags['ATTR'] = attr
    sock.sendall(frame('mesg', tags))
    expect(sock, 'mesg')


def fetch(path, data=None):
    """(status, headers, body) -- redirects are not followed."""
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(
        'http://127.0.0.1:%d%s' % (WEB, path),
        data=urllib.parse.urlencode(data).encode() if data else None)
    try:
        with opener.open(req, timeout=5) as r:
            return r.status, r.headers, r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode('utf-8', 'replace')


def wait_port(port):
    for _ in range(80):
        try:
            socket.create_connection(('127.0.0.1', port), timeout=1).close()
            return
        except OSError:
            time.sleep(0.1)


def main():
    for leftover in (TEST_DB, TEST_DB + '-wal', TEST_DB + '-shm'):
        try:
            os.remove(leftover)
        except OSError:
            pass
    setup = twdb.DB(TEST_DB)
    for name, password in PLAYERS:
        setup.create_account(name, password, persona=name)

    procs = [
        subprocess.Popen(
            [sys.executable, os.path.join(HERE, 'lobbyd.py'), '--host',
             '127.0.0.1', '--port', str(PORT), '--logfile', '', '--ping', '0',
             '--db', TEST_DB, '--buddy-port', '0'],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT),
        subprocess.Popen(
            [sys.executable, os.path.join(HERE, 'webui.py'), '--host',
             '127.0.0.1', '--port', str(WEB), '--db', TEST_DB,
             '--base-path', BASE, '--reports-key', KEY, '--no-secure-cookie',
             '--logfile', ''],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT),
    ]
    fails = []
    socks = []
    db = twdb.DB(TEST_DB)
    try:
        wait_port(PORT)
        wait_port(WEB)
        alice, bob, carol = socks[:] = [sign_in(*p) for p in PLAYERS]

        # 1. the chat
        say(bob, RUDE)                                  # room, from bob
        say(carol, 'nice drive')                        # room, not bob
        say(bob, 'quit the game', to='alice')           # private, bob -> alice
        say(bob, 'challenge\nCOUR=5\n', to='alice', attr='3')   # handshake

        # 2. alice reports bob, twice, and herself once
        for pers in ('bob', 'bob', 'alice'):
            alice.sendall(frame('rept', {'PERS': pers, 'PROD': 'tiger-ps2-2004',
                                         'LANG': 'en'}))
            expect(alice, 'rept')
        time.sleep(0.3)

        reports = db.reports()
        print('stored: %d report(s)' % len(reports))
        if len(reports) != 1:
            fails.append('one report expected (a repeat and a self-report are '
                         'not stored), got %d' % len(reports))
        if reports:
            r = reports[0]
            said = [(c['from'], c['via'], c['text']) for c in r['chat']]
            for line in said:
                print('        %-6s %-8s %r' % line)
            if (r['reporter'], r['accused'], r['room']) != ('alice', 'bob', ROOM):
                fails.append('wrong reporter/accused/room: %r'
                             % ((r['reporter'], r['accused'], r['room']),))
            if ('bob', 'room', RUDE) not in said:
                fails.append("bob's room line should be attached")
            if ('bob', 'private', 'quit the game') not in said:
                fails.append('the private line between them should be attached')
            if any(f == 'carol' for f, _, _ in said):
                fails.append("carol's chat has nothing to do with it")
            if any(t.startswith('challenge') for _, _, t in said):
                fails.append('the challenge handshake is not chat')
            if r['account'] != 'bob' or r['against'] != 1:
                fails.append('the page needs the account and a count, got %r'
                             % ((r['account'], r['against']),))

        # 3. the page, only at its address
        url = '%s/reports/%s' % (BASE, KEY)
        status, headers, body = fetch(url)
        print('page:   %d, %d bytes' % (status, len(body)))
        if status != 200:
            fails.append('the reports page should be served, got %d' % status)
        if 'no-store' not in (headers.get('Cache-Control') or ''):
            fails.append('the reports page must not be cached')
        if 'noindex' not in (headers.get('X-Robots-Tag') or ''):
            fails.append('the reports page must not be indexed')
        if RUDE in body or '&lt;b&gt;terrible&lt;/b&gt;' not in body:
            fails.append('chat must be shown escaped')
        action = 'action="%s/reports/%s/handle"' % (BASE, KEY)
        if action not in body:
            fails.append('the form should post to %s once-prefixed' % action)
        for wrong in ('%s/reports/%s' % (BASE, KEY[:-1]), '%s/reports/' % BASE,
                      '%s/reports/x/handle' % BASE):
            status, _, _ = fetch(wrong)
            if status != 404:
                fails.append('%s should be a plain 404, got %d' % (wrong, status))
        for page_path in ('/', '/live', '/leaderboard'):
            _, _, text = fetch(BASE + page_path)
            if KEY in text or '/reports/' in text:
                fails.append('%s must not link to the reports page' % page_path)

        # 4. a forged handle is refused; the real one files it
        fetch('%s/reports/%s/handle' % (BASE, 'guess'),
              {'id': str(reports[0]['id']) if reports else '1'})
        if len(db.reports()) != 1:
            fails.append('a wrong key must not be able to mark a report handled')
        status, headers, _ = fetch('%s/reports/%s/handle' % (BASE, KEY),
                                   {'id': str(reports[0]['id']) if reports else '1'})
        print('handle: %d -> %s' % (status, headers.get('Location')))
        if db.reports() or len(db.reports(handled=True)) != 1:
            fails.append('Mark handled should move the report to handled')
        if not (headers.get('Location') or '').startswith(url):
            fails.append('after Mark handled it should go back to the page')
        _, _, body = fetch(url)
        if '0 open' not in body or 'reopen' not in body:
            fails.append('the page should show none open and one to reopen')
    finally:
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass
        for proc in procs:
            proc.terminate()
            proc.wait(timeout=5)

    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print()
    print('ok: a report stores the chat that matters, and only the secret')
    print('    address shows it -- uncached, unindexed and unlinked')
    return 0


if __name__ == '__main__':
    sys.exit(main())
