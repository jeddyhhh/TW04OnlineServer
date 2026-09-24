"""EA Messenger: keys, lists, presence and messages.

    python tests/lobbyd_buddytest.py

The Messenger client logs in with nothing but the `LKEY` its lobby connection
was given at `pers` (section 57), so the key is the identity.  This starts a
real server with `--buddy-port`, signs two consoles into the lobby, follows the
address `news NAME=0` hands out, and logs both in to Messenger.  Then it walks
what the EA Messenger screen does: add a buddy, see them come online, message
them, log in again and find the list kept, block and unblock, see them leave,
remove them -- and checks that a guessed key, a missing one, and a key whose
lobby session has ended are all turned away.

The frame shapes are the ones the first console capture showed (2026-09-23).
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
BUDDY_PORT = 10297
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-buddy.db')
PLAYERS = [('alice', 'alicepass'), ('bob', 'bobpass')]
STAT = 'en="Tiger Woods 2004"\nP=tig4\n'


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


def tags_of(body):
    return tagfield.decode(body.rstrip(b'\0'))


def expect(sock, kind):
    """Read frames until `kind` arrives, ignoring pushes along the way."""
    for _ in range(20):
        got, ident, body = read(sock)
        if got == kind:
            return ident, body
    raise AssertionError('never saw a %r reply' % kind)


def sign_in(name, password):
    """Log in to the lobby; return the socket and the LKEY `pers` issued."""
    sock = socket.create_connection(('127.0.0.1', PORT), timeout=5)
    sock.sendall(frame('skey', {'SKEY': b'Public Key'}))
    expect(sock, 'skey')
    ct = '~' + eacrypt.encode(password, SESSION_KEY).decode('latin-1')
    sock.sendall(frame('auth', {'NAME': name, 'PASS': ct, 'TOS': '1'}))
    ident, _ = expect(sock, 'auth')
    assert not ident, 'auth for %s failed: %s' % (name, cc(ident))
    sock.sendall(frame('pers', {'PERS': name}))
    ident, body = expect(sock, 'pers')
    assert not ident, 'pers for %s failed: %s' % (name, cc(ident))
    return sock, tags_of(body).get('LKEY', '')


def buddy_auth(key):
    """One Messenger login attempt, exactly as captured from a console."""
    sock = socket.create_connection(('127.0.0.1', BUDDY_PORT), timeout=5)
    tags = {'PROD': 'tiger-ps2-2004', 'VERS': '1.0', 'PRES': 'tiger-ps2-2004',
            'USER': '/cso/tiger-ps2-2004'}
    if key is not None:
        tags['LKEY'] = key
    sock.sendall(frame('AUTH', tags))
    ident, _ = expect(sock, 'AUTH')
    return sock, ident


def messenger(key, who):
    """A signed-in Messenger connection that has stated its presence."""
    sock, ident = buddy_auth(key)
    assert not ident, 'Messenger login failed: %s' % cc(ident)
    sock.sendall(frame('PSET', {'SHOW': 'CHAT', 'PROD': '%s is online' % who,
                                'STAT': STAT}))
    ident, _ = expect(sock, 'PSET')
    assert not ident, 'PSET should be acknowledged'
    return sock


def rget(sock, list_, rid):
    """Fetch a list; return [(user, group)].  Presence that follows is left
    in the socket for `presence` to find."""
    sock.sendall(frame('RGET', {'LRSC': 'cso', 'LIST': list_, 'PRES': 'Y',
                                'ID': str(rid)}))
    _, body = expect(sock, 'RGET')
    size = int(tags_of(body).get('SIZE', '0'))
    rows = []
    for _ in range(size):
        _, body = expect(sock, 'ROST')
        t = tags_of(body)
        assert t.get('ID') == str(rid), 'ROST ID should name the list: %r' % t
        rows.append((t.get('USER'), t.get('GROUP', '')))
    return rows


def presence(sock, who, timeout=2.0):
    """The next PGET about `who`, skipping anything else; None if none comes."""
    sock.settimeout(timeout)
    try:
        for _ in range(20):
            kind, _, body = read(sock)
            t = tags_of(body)
            if kind == 'PGET' and t.get('USER') == who:
                return t
    except socket.timeout:
        return None
    finally:
        sock.settimeout(5)
    return None


def buddy_flow(key_a, key_b, fails, socks):
    alice = messenger(key_a, 'alice')
    socks.append(alice)
    rget(alice, 'B', 1)
    rget(alice, 'I', 2)

    # 1. alice adds bob in the wrong case, while bob is offline
    alice.sendall(frame('RADD', {'LRSC': 'cso', 'ID': '101', 'LIST': 'B',
                                 'PRES': 'Y', 'USER': 'BOB', 'GROUP': ''}))
    ident, body = expect(alice, 'RADD')
    t = tags_of(body)
    print('radd:   BOB -> %s %s' % (cc(ident) if ident else 'OK', t))
    if ident or t.get('ID') != '101' or t.get('FUSR') != 'bob':
        fails.append('RADD should echo ID=101 and name the buddy FUSR=bob, '
                     'got %s %r' % (cc(ident) if ident else 'OK', t))

    # 2. nobody by that name
    alice.sendall(frame('RADD', {'ID': '102', 'LIST': 'B', 'USER': 'nobody'}))
    ident, body = expect(alice, 'RADD')
    print('radd:   nobody -> %s' % (cc(ident) if ident else 'OK'))
    if cc(ident) != 'user' or tags_of(body).get('ID') != '102':
        fails.append("a persona that does not exist should be refused with "
                     "'user' and its ID, got %r" % (cc(ident) if ident else 'OK'))

    # 3. bob comes on, and alice is told
    bob = messenger(key_b, 'bob')
    socks.append(bob)
    seen = presence(alice, 'bob')
    print('pget:   alice sees bob as %s' % (seen or {}).get('SHOW'))
    if not seen or seen.get('SHOW') != 'CHAT' or seen.get('PROD') != 'bob is online' \
            or seen.get('STAT') != STAT:
        fails.append("bob's PSET should reach alice verbatim as PGET, got %r"
                     % (seen,))

    # 4. a message, alice -> bob, arrives from alice with the body untouched
    body_in = 'encoded\x7ftext'
    alice.sendall(frame('SEND', {'TYPE': 'C', 'USER': 'bob', 'BODY': body_in}))
    ident, _ = expect(alice, 'SEND')
    _, rbody = expect(bob, 'RECV')
    got = tags_of(rbody)
    print('recv:   bob got %r' % got)
    if ident or got.get('USER') != 'alice' or got.get('BODY') != body_in \
            or got.get('TYPE') != 'C':
        fails.append('a message should arrive as RECV USER=alice TYPE=C with '
                     'the body untouched, got %r' % (got,))

    # 5. the list survives a fresh login, with presence behind it
    alice.close()
    socks.remove(alice)
    alice = messenger(key_a, 'alice')
    socks.append(alice)
    rows = rget(alice, 'B', 1)
    seen = presence(alice, 'bob')
    print('relog:  list %r, bob %s' % (rows, (seen or {}).get('SHOW')))
    if rows != [('bob', '')]:
        fails.append('the buddy list should be kept, got %r' % (rows,))
    if not seen or seen.get('SHOW') != 'CHAT':
        fails.append('a list fetched with PRES=Y should be followed by the '
                     "buddies' presence, got %r" % (seen,))

    # 6. bob blocks alice: bob goes dark to her and she cannot message him
    bob.sendall(frame('RADD', {'LRSC': 'cso', 'ID': '7', 'LIST': 'I',
                               'PRES': 'Y', 'USER': 'alice'}))
    expect(bob, 'RADD')
    seen = presence(alice, 'bob')
    print('block:  alice sees bob as %s' % (seen or {}).get('SHOW'))
    if not seen or seen.get('SHOW') != 'DISC':
        fails.append('being blocked should make bob read as offline, got %r'
                     % (seen,))
    if rget(bob, 'I', 2) != [('alice', '')]:
        fails.append("the block should be on bob's ignore list")
    alice.sendall(frame('SEND', {'TYPE': 'C', 'USER': 'bob', 'BODY': 'hi'}))
    ident, _ = expect(alice, 'SEND')
    print('block:  alice -> bob -> %s' % (cc(ident) if ident else 'delivered'))
    if not ident:
        fails.append('a blocked sender should not be delivered')

    # 7. unblock, then bob leaves: alice is told he is offline
    bob.sendall(frame('RDEL', {'LRSC': 'cso', 'ID': '8', 'LIST': 'I',
                               'USER': 'alice'}))
    ident, body = expect(bob, 'RDEL')
    if ident or tags_of(body).get('ID') != '8':
        fails.append('RDEL should echo its ID')
    seen = presence(alice, 'bob')
    if not seen or seen.get('SHOW') != 'CHAT':
        fails.append('unblocking should make bob visible again, got %r' % (seen,))
    bob.close()
    socks.remove(bob)
    seen = presence(alice, 'bob')
    print('leave:  alice sees bob as %s' % (seen or {}).get('SHOW'))
    if not seen or seen.get('SHOW') != 'DISC':
        fails.append('bob disconnecting should reach alice as DISC, got %r'
                     % (seen,))

    # 8. a message to someone not on Messenger is refused, not dropped
    alice.sendall(frame('SEND', {'TYPE': 'C', 'USER': 'bob', 'BODY': 'hi'}))
    ident, _ = expect(alice, 'SEND')
    if not ident:
        fails.append('a message to an offline player should be refused')

    # 9. and alice takes him off the list
    alice.sendall(frame('RDEL', {'LRSC': 'cso', 'ID': '9', 'LIST': 'B',
                                 'USER': 'bob'}))
    expect(alice, 'RDEL')
    if rget(alice, 'B', 1):
        fails.append('RDEL should take bob off the list')


def start_server():
    return subprocess.Popen(
        [sys.executable, os.path.join(HERE, 'lobbyd.py'),
         '--host', '127.0.0.1', '--port', str(PORT),
         '--buddy-port', str(BUDDY_PORT), '--logfile', '',
         '--ping', '0', '--db', TEST_DB],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)


def wait_up():
    for port in (PORT, BUDDY_PORT):
        for _ in range(80):
            try:
                socket.create_connection(('127.0.0.1', port), timeout=1).close()
                break
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

    procs = [start_server()]
    fails = []
    socks = []
    try:
        wait_up()

        # the lobby issues a real key, different per login
        alice, key_a = sign_in(*PLAYERS[0])
        bob, key_b = sign_in(*PLAYERS[1])
        socks += [alice, bob]
        print('keys:   alice %s..., bob %s...' % (key_a[:8], key_b[:8]))
        for who, key in (('alice', key_a), ('bob', key_b)):
            if len(key) != 32 or ':' in key or key.startswith('lkey-'):
                fails.append('%s should get a 32-char minted key, got %r'
                             % (who, key))
        if key_a == key_b:
            fails.append('two logins must not share a key')

        # `news NAME=0` names the Messenger listener
        alice.sendall(frame('news', {'NAME': '0'}))
        _, body = expect(alice, 'news')
        addr = body.rstrip(b'\0').decode().strip()
        print('addr:   %s' % addr)
        if addr != '127.0.0.1:%d' % BUDDY_PORT:
            fails.append('news NAME=0 should hand out 127.0.0.1:%d, got %r'
                         % (BUDDY_PORT, addr))

        buddy_flow(key_a, key_b, fails, socks)

        # guessed and missing keys are refused with the client's own codes
        for label, key, code in (('the old pattern', 'lkey-alice', 'auth'),
                                 ('a missing key', None, 'miss')):
            sock, ident = buddy_auth(key)
            sock.close()
            print('auth:   %s -> %s' % (label, cc(ident) if ident else 'OK'))
            if cc(ident) != code:
                fails.append('%s should be refused with %r, got %r'
                             % (label, code, cc(ident) if ident else 'OK'))

        # a key dies with the lobby session that was issued it
        bob.close()
        socks.remove(bob)
        for _ in range(40):
            sock, ident = buddy_auth(key_b)
            sock.close()
            if ident:
                break
            time.sleep(0.05)
        print("auth:   bob's key after bob left -> %s"
              % (cc(ident) if ident else 'OK'))
        if cc(ident) != 'auth':
            fails.append('a key should stop working once its lobby session '
                         'ends, got %r' % (cc(ident) if ident else 'OK'))

        # ...but NOT with the server process.  alice is still signed in when
        # the lobby is killed and started again; her console reconnects to
        # Messenger with the key it already holds, and that has to work --
        # refusing it left real consoles with blank, frozen buddy lists.
        procs[0].terminate()
        procs[0].wait(timeout=5)
        procs[0] = start_server()
        wait_up()
        sock, ident = buddy_auth(key_a)
        rows = rget(sock, 'B', 1) if not ident else None
        sock.close()
        print("auth:   alice's key after a server restart -> %s, list %r"
              % (cc(ident) if ident else 'OK', rows))
        if ident:
            fails.append('a key must survive a server restart, got %s'
                         % cc(ident))
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
    print('ok: Messenger keys come from the lobby and die with it; buddy and')
    print('    block lists are kept; presence, messages and blocks reach the')
    print('    right consoles')
    return 0


if __name__ == '__main__':
    sys.exit(main())
