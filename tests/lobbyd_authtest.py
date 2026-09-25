"""Closed registration actually refuses.

The account check is the one thing here that fails *open* if it breaks -- a
mistake lets everybody in and nothing looks wrong -- so it gets its own test.

    python tests/lobbyd_authtest.py

An error travels in the frame header's second word, not the body (0x002BB994
copies it into the request record at +0x08, and _AuthCallback tests it first at
0x002875C0).  So the assertion is on the reply's `ident`.
"""
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import eacrypt
import tagfield
import twdb
from lobbyd import HDR, SESSION_KEY, cc, cc2i

PORT = 10296
ACCOUNT, PASSWORD, PERSONA = 'realuser', 'goodpass', 'realuser'
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-auth.db')


def frame(kind, tags, ident=0):
    payload = tagfield.encode(tags).encode('latin-1') + b'\0'
    return struct.pack('>III', cc2i(kind), ident, HDR + len(payload)) + payload


# Bytes read past the end of a frame, per socket -- two frames can arrive in
# one recv, and dropping the tail loses the second.
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
    return cc(kind), ident, tagfield.decode(buf[HDR:size])


def attempt(name, password, persona=None):
    """(auth error code, persona error code or None) for one login."""
    sock = socket.create_connection(('127.0.0.1', PORT), timeout=5)
    try:
        sock.sendall(frame('skey', {'SKEY': b'Public Key'}))
        read(sock)
        ct = '~' + eacrypt.encode(password, SESSION_KEY).decode('latin-1')
        sock.sendall(frame('auth', {'NAME': name, 'PASS': ct, 'TOS': '1'}))
        _, ident, _ = read(sock)
        if ident or not persona:
            return cc(ident), None
        sock.sendall(frame('pers', {'PERS': persona}))
        _, pers_ident, _ = read(sock)
        return cc(ident), cc(pers_ident)
    finally:
        sock.close()


def main():
    for leftover in (TEST_DB, TEST_DB + '-wal', TEST_DB + '-shm'):
        try:
            os.remove(leftover)
        except OSError:
            pass
    twdb.DB(TEST_DB).create_account(ACCOUNT, PASSWORD, persona=PERSONA)

    # No --open: the server must take the database as the only authority.
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, 'lobbyd.py'),
         '--host', '127.0.0.1', '--port', str(PORT), '--logfile', '',
         '--ping', '0', '--backup-keep', '0', '--db', TEST_DB, '--buddy-port', '0'],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    fails = []
    try:
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)

        cases = [
            ('the real account',   (ACCOUNT, PASSWORD, PERSONA), ('0x00000000', '0x00000000')),
            ('a wrong password',   (ACCOUNT, 'nope1234', None),  ('badp', None)),
            ('an unknown account', ('ghost', 'whatever', None),  ('nusr', None)),
            ("someone else's persona",
             (ACCOUNT, PASSWORD, 'somebodyelse'),                ('0x00000000', 'nper')),
        ]
        for label, args, expect in cases:
            got = attempt(*args)
            print('%-24s -> auth %-10s pers %s' % (label, got[0], got[1]))
            if got != expect:
                fails.append('%s: expected %r, got %r' % (label, expect, got))
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: only real credentials get in, and only their own personas')
    return 0


if __name__ == '__main__':
    sys.exit(main())
