"""Exercise lobbyd end to end with a fake client, before involving PCSX2.

This proves the framing, the TagField codec and the PASS decrypt path all line
up with each other.  It does NOT prove they match the real game -- only a
capture from the running client does that.  Run this first so that when the
emulator test fails you know the failure is on the game's side, not ours.

    python tests/lobbyd_selftest.py
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
from lobbyd import HDR, SESSION_KEY, cc2i, cc

PORT = 10299
PASSWORD = 'hunter2'
# A throwaway account database, so the suite never touches a real one.
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-selftest.db')
for _leftover in (TEST_DB, TEST_DB + '-wal', TEST_DB + '-shm'):
    try:
        os.remove(_leftover)
    except OSError:
        pass


def frame(kind, tags, ident=0):
    payload = tagfield.encode(tags).encode('latin-1') + b'\0'
    return struct.pack('>III', cc2i(kind), ident, HDR + len(payload)) + payload


def read_frame(sock, timeout=5.0):
    sock.settimeout(timeout)
    buf = b''
    while len(buf) < HDR:
        chunk = sock.recv(4096)
        if not chunk:
            raise AssertionError('server closed while waiting for a header')
        buf += chunk
    kind, ident, size = struct.unpack('>III', buf[:HDR])
    while len(buf) < size:
        buf += sock.recv(4096)
    return cc(kind), ident, tagfield.decode(buf[HDR:size])


def main():
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, 'lobbyd.py'),
         '--host', '127.0.0.1', '--port', str(PORT),
         '--password', PASSWORD, '--logfile', '',
         '--db', TEST_DB, '--open', '--buddy-port', '0'],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    failures = []
    try:
        sock = None
        for _ in range(50):
            try:
                sock = socket.create_connection(('127.0.0.1', PORT), timeout=1)
                break
            except OSError:
                time.sleep(0.1)
        assert sock, 'lobbyd never came up on port %d' % PORT

        # 1. handshake
        sock.sendall(frame('@dir', {'PROD': 'tiger-ps2-2004', 'VERS': 'PS2/B10'}))
        kind, _, tags = read_frame(sock)
        if kind != '@dir':
            failures.append('expected @dir reply, got %r' % kind)
        print('ok   @dir -> %r' % tags)

        # 2. session key
        sock.sendall(frame('skey', {'SKEY': b'Public Key'}))
        kind, _, tags = read_frame(sock)
        if tags.get('SKEY') != SESSION_KEY:
            failures.append('skey reply carried %r, expected the session key'
                            % (tags.get('SKEY'),))
        print('ok   skey -> %s' % tags.get('SKEY', b'').hex())

        # 3. auth, with PASS enciphered the way the client would
        ct = '~' + eacrypt.encode(PASSWORD, SESSION_KEY).decode('latin-1')
        sock.sendall(frame('auth', {'NAME': 'tester', 'PASS': ct, 'TOS': '1'}))
        kind, _, tags = read_frame(sock)
        if kind != 'auth':
            failures.append('expected auth reply, got %r' % kind)
        print('ok   auth -> %r' % tags)
        sock.close()
    finally:
        proc.terminate()
        out = proc.communicate(timeout=5)[0]

    if 'MATCH' not in out:
        failures.append('server did not report a password MATCH')
    if 'MISMATCH' in out or '!!!' in out:
        failures.append('server logged a problem')

    print('\n--- server log ---')
    print(out.rstrip())
    print('---')
    if failures:
        for f in failures:
            print('FAIL %s' % f)
        return 1
    print('\nall good: framing, TagField and the PASS decrypt agree with each other')
    return 0


if __name__ == '__main__':
    sys.exit(main())
