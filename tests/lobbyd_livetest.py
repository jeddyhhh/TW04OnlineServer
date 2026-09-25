"""The live picture reaches the web site.

    python tests/lobbyd_livetest.py

`lobbyd` and `webui` are separate processes and share nothing but the database,
so "who is online" only works if the lobby actually writes it down.  This
starts a real server, signs two consoles in, puts them in a room, and then
looks at the picture from the OTHER side -- through `twdb`, exactly as the web
site does -- before checking it empties again when they disconnect.

It also renders the live page itself, because a picture the site cannot draw is
no better than one it cannot see.
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
import webui
from lobbyd import HDR, SESSION_KEY, cc, cc2i

PORT = 10295
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-live.db')
ROOM = 'Stroke.T.East'
PLAYERS = [('alice', 'alicepass'), ('bob', 'bobpass')]


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
    """Read frames until `kind` arrives, ignoring pushes along the way."""
    for _ in range(20):
        got, ident, body = read(sock)
        if got == kind:
            return ident, body
    raise AssertionError('never saw a %r reply' % kind)


def sign_in(name, password, room=None):
    sock = socket.create_connection(('127.0.0.1', PORT), timeout=5)
    sock.sendall(frame('skey', {'SKEY': b'Public Key'}))
    expect(sock, 'skey')
    ct = '~' + eacrypt.encode(password, SESSION_KEY).decode('latin-1')
    sock.sendall(frame('auth', {'NAME': name, 'PASS': ct, 'TOS': '1'}))
    ident, _ = expect(sock, 'auth')
    assert not ident, 'auth for %s failed: %s' % (name, cc(ident))
    sock.sendall(frame('pers', {'PERS': name}))
    ident, _ = expect(sock, 'pers')
    assert not ident, 'pers for %s failed: %s' % (name, cc(ident))
    if room:
        sock.sendall(frame('move', {'NAME': room}))
        expect(sock, 'move')
    return sock


def settle(db, ready, tries=80):
    """Wait for the presence table to say what it is going to say.

    The server answers the console FIRST and writes the live picture after --
    which is the right way round, since a client should not wait on the web
    site's bookkeeping -- so the table is always a moment behind the reply the
    test already has in its hand.
    """
    for _ in range(tries):
        rows = db.online()
        if ready(rows):
            return rows
        time.sleep(0.05)
    return db.online()


def settle_playing(db, ready, tries=80):
    """The matches in play, once they say what they are going to say."""
    for _ in range(tries):
        rows = db.playing()
        if ready(rows):
            return rows
        time.sleep(0.05)
    return db.playing()


def start_match(challenger, challenged):
    """challenge -> accept -> both `chal`, as two consoles do it."""
    challenger.sendall(frame('mesg', {'TEXT': 'challenge\nCOUR=5\n',
                                      'PRIV': 'bob', 'ATTR': '3'}))
    expect(challenger, 'mesg')
    challenged.sendall(frame('mesg', {'TEXT': 'accept', 'PRIV': 'alice',
                                      'ATTR': '3'}))
    expect(challenged, 'mesg')
    challenger.sendall(frame('chal', {'PERS': 'bob', 'HOST': '1'}))
    expect(challenger, 'chal')
    challenged.sendall(frame('chal', {'PERS': 'alice', 'HOST': '0'}))
    expect(challenged, 'chal')


def names(rows):
    return sorted(r['persona'] for r in rows)


def main():
    for leftover in (TEST_DB, TEST_DB + '-wal', TEST_DB + '-shm'):
        try:
            os.remove(leftover)
        except OSError:
            pass
    setup = twdb.DB(TEST_DB)
    for name, password in PLAYERS:
        setup.create_account(name, password, persona=name)

    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, 'lobbyd.py'),
         '--host', '127.0.0.1', '--port', str(PORT), '--logfile', '',
         '--ping', '0', '--backup-keep', '0', '--db', TEST_DB, '--buddy-port', '0'],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    fails = []
    socks = []
    db = twdb.DB(TEST_DB)
    try:
        for _ in range(60):
            try:
                socket.create_connection(('127.0.0.1', PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)

        # 1. the server says it is up, without anyone on it
        up, age = db.server_is_up()
        print('server: %s, heartbeat %.1fs old, %d online'
              % ('up' if up else 'DOWN', age, len(db.online())))
        if not up:
            fails.append('a running server should report itself up')
        if db.online():
            fails.append('nobody is connected, so nobody should be online')

        # 2. two consoles sign in and join a room
        socks = [sign_in(name, password, ROOM) for name, password in PLAYERS]
        rows = settle(db, lambda rows: len(rows) == 2
                      and all(r['room'] for r in rows))
        here = names(rows)
        print('online: %s' % (', '.join(here) or '(nobody)'))
        if here != ['alice', 'bob']:
            fails.append('expected both players online, got %r' % (here,))
        rooms = {p['persona']: p['room'] for p in rows}
        if set(rooms.values()) != {ROOM}:
            fails.append('both should be in %s, got %r' % (ROOM, rooms))
        where = {p['persona']: p['detail'] for p in rows}
        print('where:  %s' % where)
        if not all('East' in v for v in where.values()):
            fails.append('the room should read as a place, got %r' % (where,))

        # 3. the feed noticed
        feed = db.activity(limit=20)
        kinds = [r['kind'] for r in feed]
        print('feed:   %s' % ', '.join('%s/%s' % (r['kind'], r['text'])
                                       for r in feed[:4]))
        if 'login' not in kinds:
            fails.append('a login should reach the activity feed, got %r'
                         % (kinds,))
        if 'room' not in kinds:
            fails.append('joining a room should reach the feed, got %r'
                         % (kinds,))

        # 4. the web site can draw it
        webui.DB = db
        body = webui.live_strip()
        if 'dot up' not in body:
            fails.append('the live strip should show the server as up')
        if 'alice' not in body:
            fails.append('the live strip should name who is on, got %r' % body)
        print('strip:  %d bytes, names %s'
              % (len(body), ', '.join(n for n in ('alice', 'bob') if n in body)))
        snap = webui.live_snapshot()
        if not snap['up'] or len(snap['online']) != 2:
            fails.append('the snapshot disagrees with the table: %r' % (snap,))

        # 5. one leaves
        socks.pop().close()
        here = names(settle(db, lambda rows: len(rows) == 1))
        print('after a disconnect: %s' % (', '.join(here) or '(nobody)'))
        if here != ['alice']:
            fails.append('a disconnected player should stop being online, '
                         'got %r' % (here,))

        # 6. and the last one
        socks.pop().close()
        here = names(settle(db, lambda rows: not rows))
        print('after both: %s' % (', '.join(here) or '(nobody)'))
        if here:
            fails.append('an empty server should have nobody online, got %r'
                         % (here,))

        # 7. a match that connects: both consoles leave the lobby within a
        #    second of `+ses` (every capture shows it).  They are PLAYING, not
        #    gone -- the match and both players stay on the board.
        alice, bob = [sign_in(n, p, ROOM) for n, p in PLAYERS]
        socks += [alice, bob]
        start_match(alice, bob)
        if len(settle_playing(db, lambda ms: len(ms) == 1)) != 1:
            fails.append('an agreed match should be in play')
        for sock in (alice, bob):
            sock.close()
            socks.remove(sock)
        rows = settle(db, lambda rows: len(rows) == 2 and all(
            r['state'] == 'playing' for r in rows))
        state = {r['persona']: (r['state'], r['detail']) for r in rows}
        print('in a match, disconnected: %s' % state)
        if state != {'alice': ('playing', 'vs bob'), 'bob': ('playing', 'vs alice')}:
            fails.append('two players who left the lobby to play should stay '
                         'listed as playing each other, got %r' % state)
        if len(db.playing()) != 1:
            fails.append('the match should stay in play with both away, got %r'
                         % db.playing())
        snap = webui.live_snapshot()
        if len(snap['playing']) != 1 or len(snap['online']) != 2:
            fails.append('the live page should still show the match and both '
                         'players, got %r' % snap)

        # 8. one comes back to the lobby: the match is over, result or not
        alice = sign_in(*PLAYERS[0], room=ROOM)
        socks.append(alice)
        settle_playing(db, lambda ms: not ms)
        rows = settle(db, lambda rows: names(rows) == ['alice'])
        print('after alice signs back in: %s, %d match(es)'
              % ({r['persona']: r['state'] for r in rows}, len(db.playing())))
        if db.playing():
            fails.append('signing back in should end the match')
        if names(rows) != ['alice']:
            fails.append('bob is away and his match is over, so only alice '
                         'should be listed, got %r' % names(rows))

        # 9. a match that never connects: both stay in the lobby, and the one
        #    that gave up says so with `chal PERS=*` (13:14:01 on 2026-09-23).
        bob = sign_in(*PLAYERS[1], room=ROOM)
        socks.append(bob)
        start_match(alice, bob)
        settle_playing(db, lambda ms: len(ms) == 1)
        bob.sendall(frame('chal', {'PERS': '*'}))
        expect(bob, 'chal')
        left = settle_playing(db, lambda ms: not ms)
        print('after a failed connect: %d match(es)' % len(left))
        if left:
            fails.append('a player back in the lobby (chal PERS=*) means the '
                         'match did not start')

        # 10. and a result ends one too
        start_match(alice, bob)
        ms = settle_playing(db, lambda ms: len(ms) == 1)
        token = ms[0]['auth'] if ms else ''
        alice.sendall(frame('rank', {'AUTH': token, 'REPT': 'alice',
                                     'NAME0': 'alice', 'NAME1': 'bob',
                                     'STROKES0': '72', 'STROKES1': '75',
                                     'HOLES0': '18', 'HOLES1': '18',
                                     'DONE0': '1', 'DONE1': '1'}))
        expect(alice, 'rank')
        if settle_playing(db, lambda ms: not ms):
            fails.append('a result should end the match')
        else:
            print('after the result: no matches in play')
    finally:
        for sock in socks:
            try:
                sock.close()
            except OSError:
                pass
        proc.terminate()
        proc.wait(timeout=5)

    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print()
    print('ok: the lobby publishes who is on it, and the web site can read')
    print('    it back out of the database')
    return 0


if __name__ == '__main__':
    sys.exit(main())
