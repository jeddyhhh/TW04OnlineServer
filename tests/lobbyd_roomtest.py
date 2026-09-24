"""Two fake clients: one creates a room, the other joins.

Regression test for the two membership bugs found on 2026-09-18 (section 16 of
the wire-format notes): the host never sends `move` after `room`, so creating
has to count as joining, and `+usr` used to reach only the connection that
asked for it.  Both clients must end up seeing both names.

    python tests/lobbyd_roomtest.py
"""
import os, socket, struct, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import eacrypt, tagfield
from lobbyd import HDR, SESSION_KEY, cc2i, cc

PORT = 10297
PASSWORD = 'hunter2'
# A throwaway account database, so the suite never touches a real one.
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-roomtest.db')
for _leftover in (TEST_DB, TEST_DB + '-wal', TEST_DB + '-shm'):
    try:
        os.remove(_leftover)
    except OSError:
        pass
ROOM = 'Match.C.hhhh'
LOG = os.path.join(tempfile.gettempdir(), 'room_test_lobbyd.log')


def frame(kind, tags, ident=0):
    payload = tagfield.encode(tags).encode('latin-1') + b'\0'
    return struct.pack('>III', cc2i(kind), ident, HDR + len(payload)) + payload


class Client:
    def __init__(self, name):
        self.name = name
        self.sock = socket.create_connection(('127.0.0.1', PORT), timeout=5)
        self.buf = b''
        self.users = {}          # index -> name, as the +usr pushes leave it
        self.sessions = []       # every +ses record this client was pushed
        self.seen = []

    def send(self, kind, tags, ident=0):
        self.sock.sendall(frame(kind, tags, ident))

    def _parse(self):
        while len(self.buf) >= HDR:
            kind, ident, size = struct.unpack('>III', self.buf[:HDR])
            if len(self.buf) < size:
                break
            tags = tagfield.decode(self.buf[HDR:size])
            self.buf = self.buf[size:]
            k = cc(kind)
            self.seen.append(k)
            if k == '+usr':
                i = int(tags.get('I', '-1'))
                if 'N' in tags:
                    self.users[i] = tags['N']
                else:
                    self.users.pop(i, None)
            elif k == '+ses':
                self.sessions.append(tags)

    def wait(self, kind, seconds=5.0):
        """Read until a frame of this kind arrives (then drain what follows)."""
        end = time.time() + seconds
        while time.time() < end:
            self._parse()
            if kind in self.seen:
                self.drain(0.3)
                self.seen = []
                return True
            self.sock.settimeout(max(0.05, end - time.time()))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                break
            self.buf += chunk
        raise AssertionError('%s never saw a %r (saw %r)' % (self.name, kind, self.seen))

    def drain(self, seconds=0.5):
        end = time.time() + seconds
        while time.time() < end:
            self.sock.settimeout(max(0.02, end - time.time()))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            self.buf += chunk
        self._parse()

    def login(self):
        self.send('@dir', {'PROD': 'tiger-ps2-2004', 'VERS': 'PS2/B10'})
        self.wait('@dir')
        # the real client volunteers its own endpoint before anything else
        self.send('addr', {'ADDR': '192.0.2.100', 'PORT': str(40000 + len(self.name))})
        self.wait('addr')
        self.send('skey', {'SKEY': b'Public Key'})
        self.wait('skey')
        ct = '~' + eacrypt.encode(PASSWORD, SESSION_KEY).decode('latin-1')
        self.send('auth', {'NAME': self.name, 'PASS': ct, 'TOS': '1'})
        self.wait('auth')
        self.send('pers', {'PERS': self.name})
        self.wait('pers')

    def roster(self):
        return sorted(self.users.values())


def main():
    with open(LOG, 'w'):
        pass
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, 'lobbyd.py'),
         '--host', '127.0.0.1', '--port', str(PORT),
         '--password', PASSWORD, '--logfile', LOG, '--ping', '0',
         '--db', TEST_DB, '--open', '--buddy-port', '0'],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    fails = []
    try:
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)

        host = Client('jed2')
        host.login()
        join = Client('ooo')
        join.login()
        host.drain(0.3); join.drain(0.3)
        host.users.clear(); join.users.clear()

        # the host creates a room and never sends `move`, as the real client does
        host.send('room', {'NAME': ROOM, 'DESC': 'Created by jed2', 'MAX': '50'})
        host.wait('room'); join.drain(0.5)
        print('after create:  host sees %-18r joiner sees %r'
              % (host.roster(), join.roster()))
        if host.roster() != ['jed2']:
            fails.append('host should see itself after creating, saw %r' % host.roster())

        # the other client peeks, then joins
        join.send('peek', {'NAME': ROOM})
        join.wait('peek')
        join.send('move', {'NAME': ROOM})
        join.wait('move'); host.drain(0.6)
        print('after join:    host sees %-18r joiner sees %r'
              % (host.roster(), join.roster()))
        if host.roster() != ['jed2', 'ooo']:
            fails.append('host should see both after the join, saw %r' % host.roster())
        if join.roster() != ['jed2', 'ooo']:
            fails.append('joiner should see both, saw %r' % join.roster())

        # challenge -> accept -> both send `chal`.  Exactly one session must be
        # minted, and both consoles must be handed the SAME seed: the first
        # version fired start_session once per `chal` with a fresh random seed
        # each time, which is a desync on the first shot.
        host.send('mesg', {'TEXT': 'challenge\nCOUR=5\nGLFR=0\n',
                           'PRIV': 'ooo', 'ATTR': '3'})
        host.wait('mesg'); join.drain(0.4)
        join.send('mesg', {'TEXT': 'accept', 'PRIV': 'jed2', 'ATTR': '3'})
        join.wait('mesg'); host.drain(0.4)
        host.send('chal', {'PERS': 'ooo', 'HOST': '1'})
        host.wait('chal')
        join.send('chal', {'PERS': 'jed2', 'HOST': '0'})
        join.wait('chal')
        host.drain(0.6); join.drain(0.6)

        for who, cl in (('host', host), ('joiner', join)):
            print('%s +ses: %r' % (who, cl.sessions))
            if len(cl.sessions) != 1:
                fails.append('%s got %d +ses pushes, expected exactly 1'
                             % (who, len(cl.sessions)))
        seeds = {s.get('SEED') for cl in (host, join) for s in cl.sessions}
        if len(seeds) != 1:
            fails.append('the two consoles were given different seeds: %r' % seeds)
        for cl, expect in ((host, 'ooo'), (join, 'jed2')):
            for s in cl.sessions:
                if s.get('FROM') != expect:
                    fails.append('%s was told FROM=%r, expected %r'
                                 % (cl.name, s.get('FROM'), expect))

        # The course and conditions are only ever stated in the challenge, so
        # the server has to catch them there and attach them to the session.
        import twdb
        db = twdb.DB(TEST_DB)
        token = host.sessions[0].get('AUTH') if host.sessions else ''
        ses = db.session(token)
        setup = {}
        if ses:
            import json
            setup = json.loads(ses['setup']) if ses['setup'] else {}
        print('stored setup: %r' % setup)
        if setup.get('COUR') != '5':
            fails.append('the challenge setup was not stored with the session: %r'
                         % setup)

        # The match never connects, and the OTHER player challenges back
        # without either leaving the lobby -- exactly the Steam Deck log of
        # 2026-09-19.  That second acceptance must get its own `+ses`, with a
        # fresh seed and the new challenger as host; it used to get nothing
        # ("already decided -- not re-pushing"), so no retry could ever start.
        join.send('mesg', {'TEXT': 'challenge\nCOUR=3\nGLFR=0\n',
                           'PRIV': 'jed2', 'ATTR': '3'})
        join.wait('mesg'); host.drain(0.4)
        host.send('mesg', {'TEXT': 'accept', 'PRIV': 'ooo', 'ATTR': '3'})
        host.wait('mesg'); join.drain(0.4)
        join.send('chal', {'PERS': 'jed2', 'HOST': '1'})
        join.wait('chal')
        host.send('chal', {'PERS': 'ooo', 'HOST': '0'})
        host.wait('chal')
        host.drain(0.6); join.drain(0.6)
        for who, cl in (('host', host), ('joiner', join)):
            print('%s +ses after the rematch: %d' % (who, len(cl.sessions)))
            if len(cl.sessions) != 2:
                fails.append('%s should get a second +ses for the rematch, got '
                             '%d in all' % (who, len(cl.sessions)))
        second = {cl.name: cl.sessions[-1] for cl in (host, join)
                  if len(cl.sessions) == 2}
        if len(second) == 2:
            seeds = {s.get('SEED') for s in second.values()}
            if len(seeds) != 1 or seeds == {host.sessions[0].get('SEED')}:
                fails.append('the rematch needs ONE new seed for both, got %r'
                             % seeds)
            if {s.get('HOST') for s in second.values()} != {'ooo'}:
                fails.append('the rematch challenger hosts it, got %r'
                             % {s.get('HOST') for s in second.values()})
    finally:
        proc.terminate()
        proc.wait(timeout=5)

    if fails:
        print('\n--- server log (tail) ---')
        print(''.join(open(LOG, encoding='utf-8').readlines()[-80:]))
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: creating joins, membership reaches everyone in the room, and a '
          'challenge\n    mints one session, one seed for both consoles, and keeps '
          'the match setup')
    return 0


if __name__ == '__main__':
    sys.exit(main())
