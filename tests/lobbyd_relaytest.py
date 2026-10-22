"""The UDP relay: no player needs a port forward (twrelay, lobbyd --relay).

    python tests/lobbyd_relaytest.py

Two halves.  First the relay on its own, over real loopback sockets, playing
the two consoles' CommUDP control packets: the host's POKE {5,0} and the
guest's INIT {1,ident}.  Then the whole lobby started with --relay: a
challenge must hand BOTH consoles the relay in `+ses ADDR`, the route must
carry their packets, a result must release it, and a second match from the
same address must be refused while the first is still connecting.

Every player here is 127.0.0.1 -- one public IP for all of them, the hardest
case for a relay that admits by address, and the only loopback address every
OS has.
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
import eacrypt, tagfield, twrelay                       # noqa: E401,E402
from lobbyd import HDR, SESSION_KEY, cc2i, cc           # noqa: E402

PORT = 10293
PASSWORD = 'hunter2'
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-relaytest.db')
for _leftover in (TEST_DB, TEST_DB + '-wal', TEST_DB + '-shm'):
    try:
        os.remove(_leftover)
    except OSError:
        pass
LOG = os.path.join(tempfile.gettempdir(), 'relay_test_lobbyd.log')

POKE = struct.pack('<II', 5, 0)
INIT = struct.pack('<II', 1, 0x172A)
ACK = struct.pack('<II', 2, 0x172A)


def udp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('127.0.0.1', 0))
    s.settimeout(0.3)
    return s


def spare_udp_port():
    s = udp()
    port = s.getsockname()[1]
    s.close()
    return port


def got(sock):
    """The next datagram, or None after a short wait."""
    try:
        return sock.recvfrom(4096)[0]
    except socket.timeout:
        return None


def relay_alone(fails):
    now = [0.0]
    port = spare_udp_port()
    r = twrelay.Relay('127.0.0.1', port, clock=lambda: now[0])
    r.start()
    to = ('127.0.0.1', port)
    host, guest, host2, guest2 = udp(), udp(), udp(), udp()
    try:
        # One public IP for both players: told apart by role, then by port.
        r.register('one', '127.0.0.1', '127.0.0.1')
        try:
            r.register('early', '127.0.0.1', '127.0.0.9')
            fails.append('a second unlearned host from one IP was accepted')
        except ValueError:
            pass
        guest.sendto(INIT, to)
        if got(host) is not None:
            fails.append('a guest INIT was delivered before the host was known')
        host.sendto(b'not a poke', to)          # learns nothing
        host.sendto(POKE, to)                   # from whatever port its NAT chose
        if got(guest) is not None:
            fails.append('a POKE was forwarded to the guest')
        guest.sendto(INIT, to)
        if got(host) != INIT:
            fails.append('the guest INIT did not reach the learned host')
        host.sendto(ACK, to)
        if got(guest) != ACK:
            fails.append('the host ACK did not reach the guest')
        binary = bytes([0, 255, 4, 10, 0, 127])
        guest.sendto(binary, to)
        if got(host) != binary:
            fails.append('data was not forwarded byte for byte')

        # The first match is learned, so a second from the same IP may start,
        # and the two stay apart.
        r.register('two', '127.0.0.1', '127.0.0.1')
        host2.sendto(POKE, to)
        guest2.sendto(INIT, to)
        if got(host2) != INIT:
            fails.append('the second match did not connect')
        if got(host) is not None:
            fails.append('the second match leaked into the first')
        guest.sendto(b'first', to)
        if got(host) != b'first' or got(host2) is not None:
            fails.append('the first match did not stay on its own route')

        stranger = udp()                        # same IP, a port nobody learned
        stranger.sendto(b'hello', to)
        stranger.sendto(POKE, to)
        host.sendto(b'x' * (twrelay.MAX_PACKET + 1), to)
        if got(guest) is not None or got(guest2) is not None:
            fails.append('an unknown source or an oversize datagram got through')
        stranger.close()

        r.release('two')
        host2.sendto(b'after release', to)
        if got(guest2) is not None:
            fails.append('a released route still forwarded')

        now[0] += twrelay.IDLE_TIMEOUT
        r.expire()
        guest.sendto(b'late', to)
        if got(host) is not None or r.sessions:
            fails.append('an idle route was not expired')

        r.register('pending', '127.0.0.1', '127.0.0.1')
        now[0] += twrelay.START_TIMEOUT
        r.expire()
        if r.sessions:
            fails.append('a route nobody used outlived the setup timeout')
    finally:
        r.close()
        for s in (host, guest, host2, guest2):
            s.close()
    print('relay alone: %s' % ('ok' if not fails else '%d failure(s)' % len(fails)))


def frame(kind, tags, ident=0):
    payload = tagfield.encode(tags).encode('latin-1') + b'\0'
    return struct.pack('>III', cc2i(kind), ident, HDR + len(payload)) + payload


class Client:
    def __init__(self, name):
        self.name = name
        self.sock = socket.create_connection(('127.0.0.1', PORT), timeout=5)
        self.buf = b''
        self.frames = []        # (kind, ident, tags), everything received

    def send(self, kind, tags, ident=0):
        self.sock.sendall(frame(kind, tags, ident))

    def drain(self, seconds=0.4):
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
        while len(self.buf) >= HDR:
            kind, ident, size = struct.unpack('>III', self.buf[:HDR])
            if len(self.buf) < size:
                break
            self.frames.append((cc(kind), ident, tagfield.decode(self.buf[HDR:size])))
            self.buf = self.buf[size:]

    def last(self, kind):
        for k, ident, tags in reversed(self.frames):
            if k == kind:
                return ident, tags
        return None, None

    def login(self):
        self.send('@dir', {'PROD': 'tiger-ps2-2004', 'VERS': 'PS2/B10'})
        self.send('addr', {'ADDR': '192.0.2.100', 'PORT': '3658'})
        self.send('skey', {'SKEY': b'Public Key'})
        ct = '~' + eacrypt.encode(PASSWORD, SESSION_KEY).decode('latin-1')
        self.send('auth', {'NAME': self.name, 'PASS': ct, 'TOS': '1'})
        self.drain(0.4)
        self.send('pers', {'PERS': self.name})
        self.drain(0.4)


def agree(host, guest):
    """Challenge, accept, and both `chal`s -- the guest's completes the pair."""
    host.send('mesg', {'TEXT': 'challenge\nCOUR=5\n', 'PRIV': guest.name,
                       'ATTR': '3'})
    host.drain(0.3); guest.drain(0.3)
    guest.send('mesg', {'TEXT': 'accept', 'PRIV': host.name, 'ATTR': '3'})
    guest.drain(0.3); host.drain(0.3)
    host.send('chal', {'PERS': guest.name, 'HOST': '1'})
    host.drain(0.3)
    guest.send('chal', {'PERS': host.name, 'HOST': '0'})
    guest.drain(0.5); host.drain(0.5)


def lobby_with_relay(fails):
    relay_port = spare_udp_port()
    with open(LOG, 'w'):
        pass
    proc = subprocess.Popen(
        [sys.executable, os.path.join(HERE, 'lobbyd.py'),
         '--host', '127.0.0.1', '--port', str(PORT),
         '--password', PASSWORD, '--logfile', LOG, '--ping', '0',
         '--backup-keep', '0', '--db', TEST_DB, '--open', '--buddy-port', '0',
         '--relay', '127.0.0.1', '--relay-bind', '127.0.0.1',
         '--relay-port', str(relay_port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    to = ('127.0.0.1', relay_port)
    clients = []
    try:
        for _ in range(50):
            try:
                socket.create_connection(('127.0.0.1', PORT), timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        a, b, c, d = (Client(n) for n in ('jed2', 'ooo', 'amy', 'bob'))
        clients = [a, b, c, d]
        for cl in clients:
            cl.login()

        agree(a, b)
        ses = {cl.name: cl.last('+ses')[1] for cl in (a, b)}
        print('+ses ADDR: %r' % {n: (t or {}).get('ADDR') for n, t in ses.items()})
        if any((t or {}).get('ADDR') != '127.0.0.1' for t in ses.values()):
            fails.append('both consoles must be given the relay address, got %r'
                         % {n: (t or {}).get('ADDR') for n, t in ses.items()})

        # A second match from the same address while the first host is still
        # unlearned: refused, cleanly, to both of its players.
        agree(c, d)
        ident, _tags = d.last('chal')
        if d.last('+ses')[1] is not None or ident != cc2i('rely'):
            fails.append('the second match should have been refused with '
                         '"rely", got %r' % (cc(ident) if ident else None,))
        _i, revoke = c.last('+msg')
        if not revoke or revoke.get('T') != 'revoke':
            fails.append('the waiting challenger was not told it was off: %r'
                         % (revoke,))

        host, guest = udp(), udp()
        host.sendto(POKE, to)
        guest.sendto(INIT, to)
        if got(host) != INIT:
            fails.append('the lobby-reserved route did not carry the INIT')
        host.sendto(b'shot', to)
        if got(guest) != b'shot':
            fails.append('the lobby-reserved route did not carry data')

        # Now that the first match is learned, the second can try again.
        agree(c, d)
        if (d.last('+ses')[1] or {}).get('ADDR') != '127.0.0.1':
            fails.append('the retried second match was not started')

        # The result releases the route.
        a.send('rank', {'AUTH': ses['jed2'].get('AUTH', ''), 'REPT': 'jed2',
                        'NAME0': 'jed2', 'NAME1': 'ooo'})
        a.drain(0.4)
        host.sendto(b'after the result', to)
        if got(guest) is not None:
            fails.append('a reported match kept its relay route')
        host.close(); guest.close()
    finally:
        for cl in clients:
            cl.sock.close()
        proc.terminate()
        proc.wait(timeout=5)
    print('lobby with --relay: %s' % ('ok' if not fails else 'see failures'))


def main():
    fails = []
    relay_alone(fails)
    lobby_with_relay(fails)
    if fails:
        print('\n--- server log (tail) ---')
        print(''.join(open(LOG, encoding='utf-8').readlines()[-60:]))
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: both endpoints are learned from their own POKE/INIT, matches '
          'behind\n    one IP stay apart, and the lobby hands out the relay and '
          'releases it on a result')
    return 0


if __name__ == '__main__':
    sys.exit(main())
