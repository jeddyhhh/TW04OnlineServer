"""An optional UDP relay for the peer-to-peer leg, so no player needs a port
forward.

    python twrelay.py            # self-test

TW04 plays a match over UDP 3658 directly between the two consoles, and the
lobby only introduces them (`+ses ADDR`).  The game has no NAT traversal of its
own, so without help the match host has to be reachable from the internet.

It does not need to be, because BOTH consoles already send first.  Read off the
game's CommUDP code in DSOCKF.IRX (the IOP module that does all the UDP work;
the EE only asks it to `'gmut' 'conn'` at 0x0027AA50):

  * the host is the LISTENER.  While it waits it sends an 8-byte POKE --
    words {5, 0} -- to the address it was given, once a second
    (CommUDPThreadData 0x0E30..0x0E68 calling CommUDPProcessPoke, 0x08F0),
    and it accepts the first INIT from ANY source, adopting that source as its
    peer (0x106C);
  * the guest is the CONNECTOR.  It sends an 8-byte INIT -- {1, ident}, ident
    a non-zero random word -- once a second until it is answered
    (0x0D88..0x0DB0, CommUDPProcessInit 0x0254), and re-targets its peer to
    the source of any POKE it receives (0x0FCC);
  * after that, every packet must come from exactly the ip:port the console is
    talking to (SockaddrCompare, 0xEE78, compares family, port and address).

So if both are handed the relay's public address, each opens its own NAT
mapping to the relay on its first packet, whatever port its router picked.
The relay learns each endpoint from the packet its role sends -- a POKE is a
host, an INIT a guest -- from the IP address that player's lobby connection
came from, pins it, and forwards everything else unchanged through its one
socket.  POKEs are consumed: they only open the host's mapping.  A guest INIT
that arrives before the host is known is dropped; the guest sends another a
second later.

Players behind one public IP (a household, carrier-grade NAT) are told apart
by role and by the port their NAT chose.  Only one not-yet-learned host and one
not-yet-learned guest may wait per source IP, so a first packet can never be
attributed to the wrong match; a reservation that would break that is refused,
and the players can simply challenge again a few seconds later.

What it is not: cryptographic UDP authentication.  Admission is by source
address; anyone who can spoof a player's address, or send the first POKE/INIT
from that player's own public IP before the player does, is outside these
guarantees.
"""
import socket
import threading
import time

MAX_PACKET = 2048          # bytes per datagram; TW04's are far smaller
MAX_MATCHES = 64
RATE = 1000                # packets per second per participant
START_TIMEOUT = 60.0       # both players must have sent within this
IDLE_TIMEOUT = 120.0       # either one silent this long ends the route
MAX_AGE = 6 * 3600.0

INIT, POKE = 1, 5


def control(data):
    """INIT, POKE or 0 for one datagram.

    CommUDP's control packets are two words, written IOP-native -- little
    endian -- by CommUDPWrite (0x005C).  The byte order on the wire has not
    been confirmed by a capture, so either order is accepted."""
    if len(data) != 8:
        return 0
    zero = data[4:] == b'\0\0\0\0'
    for kind in (int.from_bytes(data[:4], 'little'),
                 int.from_bytes(data[:4], 'big')):
        if kind == POKE and zero:
            return POKE
        if kind == INIT and not zero:
            return INIT
    return 0


class _Peer:
    def __init__(self, session, address, host, now):
        self.session = session
        self.address = address      # the IP its lobby connection came from
        self.host = host
        self.endpoint = None        # (ip, port), once learned
        self.seen = False
        self.last = now
        self.window = now
        self.packets = 0
        self.forwarded = 0

    def other(self):
        return self.session.b if self.session.a is self else self.session.a


class _Session:
    def __init__(self, token, now):
        self.token = token
        self.created = now
        self.a = self.b = None


class Relay:
    """One UDP socket forwarding for every brokered match.  `register` when a
    match is agreed, `release` when its result arrives; `expire` does the rest.
    Thread-safe: the lobby's handler threads call in while `serve` runs."""

    def __init__(self, bind, port, log=None, clock=time.monotonic):
        self.bind, self.port = bind, port
        self.log = log or (lambda direction, text: None)
        self.clock = clock
        self.lock = threading.Lock()
        self.sessions = {}          # token -> _Session
        self.endpoints = {}         # (ip, port) -> _Peer, once learned
        self.sock = None

    def start(self):
        """Bind and serve on a daemon thread.  No address reuse: a second relay,
        or a console on this machine, already holding the port is an error."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((self.bind, self.port))
        except OSError:
            s.close()
            raise
        s.settimeout(1.0)
        self.sock = s
        threading.Thread(target=self.serve, name='tw04-relay',
                         daemon=True).start()
        self.log('***', 'UDP relay listening on %s:%d' % (self.bind, self.port))

    def close(self):
        if self.sock:
            self.sock.close()
        with self.lock:
            for token in list(self.sessions):
                self._release(token)

    def register(self, token, host, guest):
        """Reserve a route: `host` and `guest` are the dotted-quad addresses
        their lobby connections came from.  Raises ValueError when it cannot."""
        with self.lock:
            self._expire()
            if self.sock is None:
                raise ValueError('the relay is not running')
            if token in self.sessions or len(self.sessions) >= MAX_MATCHES:
                raise ValueError('the relay is full')
            for address in (host, guest):
                try:
                    socket.inet_pton(socket.AF_INET, address)
                except (OSError, TypeError):
                    raise ValueError('%r is not an IPv4 address' % (address,))
            if self._waiting(host, True) or self._waiting(guest, False):
                raise ValueError('another match from that address is still '
                                 'connecting')
            now = self.clock()
            s = _Session(token, now)
            s.a = _Peer(s, host, True, now)
            s.b = _Peer(s, guest, False, now)
            self.sessions[token] = s
        self.log('***', '    relay reserved for host %s and guest %s'
                 % (host, guest))

    def _waiting(self, address, host):
        return any(p.endpoint is None and p.host == host
                   and p.address == address
                   for s in self.sessions.values() for p in (s.a, s.b))

    def release(self, token):
        with self.lock:
            self._release(token)

    def _release(self, token):
        s = self.sessions.pop(token, None)
        if s is None:
            return
        for p in (s.a, s.b):
            if p.endpoint is not None:
                self.endpoints.pop(p.endpoint, None)
        self.log('***', '    relay released %s / %s; forwarded %d / %d packets'
                 % (s.a.address, s.b.address, s.a.forwarded, s.b.forwarded))

    def expire(self):
        with self.lock:
            self._expire()

    def _expire(self):
        now = self.clock()
        for token, s in list(self.sessions.items()):
            pending = not (s.a.seen and s.b.seen)
            if ((pending and now - s.created >= START_TIMEOUT)
                    or now - min(s.a.last, s.b.last) >= IDLE_TIMEOUT
                    or now - s.created >= MAX_AGE):
                self._release(token)

    def serve(self):
        s = self.sock
        while True:
            try:
                data, source = s.recvfrom(MAX_PACKET + 1)
            except socket.timeout:
                self.expire()
                continue
            except OSError:
                return              # closed
            try:
                self.forward(data, source)
            except OSError as exc:
                self.log('!!!', '    relay send failed: %s' % exc)

    def forward(self, data, source):
        """Route one datagram.  Returns where it went, or None if dropped."""
        if not data or len(data) > MAX_PACKET:
            return None
        kind = control(data)
        with self.lock:
            self._expire()
            sender = self.endpoints.get(source)
            if sender is None:
                # Learn a mapping only from the packet its role sends first.
                if not kind:
                    return None
                for s in self.sessions.values():
                    for p in (s.a, s.b):
                        if (p.endpoint is None and p.host == (kind == POKE)
                                and p.address == source[0]):
                            sender = p
                if sender is None:
                    return None
                sender.endpoint = source
                self.endpoints[source] = sender
                self.log('***', '    relay learned the %s at %s:%d'
                         % ('host' if sender.host else 'guest', *source))
            now = self.clock()
            if now - sender.window >= 1.0:
                sender.window, sender.packets = now, 0
            sender.packets += 1
            if sender.packets > RATE:
                return None
            sender.seen = True
            sender.last = now
            if sender.host and kind == POKE:
                return None         # its job was to open the host's mapping
            target = sender.other().endpoint
            if target is None:
                return None         # the guest tries again in a second
            sender.forwarded += 1
            first = sender.forwarded == 1
        self.sock.sendto(data, target)
        if first:
            self.log('***', '    relay forwarding %s:%d -> %s:%d'
                     % (source + target))
        return target


# ---------------------------------------------------------------------------

def _selftest():
    fails = []
    now = [0.0]
    r = Relay('127.0.0.1', 0, clock=lambda: now[0])
    r.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    r.sock.bind(('127.0.0.1', 0))
    poke = (5).to_bytes(4, 'little') + bytes(4)
    init = (1).to_bytes(4, 'little') + (0x172A).to_bytes(4, 'little')
    host, guest = ('127.0.0.2', 40001), ('127.0.0.2', 40002)
    r.register('t', '127.0.0.2', '127.0.0.2')
    try:
        r.register('u', '127.0.0.2', '127.0.0.9')
        fails.append('a second unlearned host from one IP was accepted')
    except ValueError:
        pass
    if r.forward(init, guest) is not None:
        fails.append('a guest INIT went somewhere before the host was known')
    if r.forward(poke, host) is not None:
        fails.append('a POKE was forwarded')
    if r.forward(init, guest) != host:
        fails.append('the guest INIT did not reach the learned host')
    if r.forward(b'data', host) != guest:
        fails.append('data did not reach the guest')
    if r.forward(b'x', ('127.0.0.2', 40003)) is not None:
        fails.append('an unknown source port was forwarded')
    now[0] += IDLE_TIMEOUT
    if r.forward(b'late', host) is not None or r.sessions:
        fails.append('an idle route was not released')
    if control(b'\0\0\0\x05\0\0\0\0') != POKE or control(b'1234567') != 0:
        fails.append('control() misread a packet')
    r.sock.close()
    for f in fails:
        print('FAIL %s' % f)
    if not fails:
        print('relay: learns host and guest from POKE/INIT, consumes POKEs, '
              'pins endpoints, expires idle routes')
    return 1 if fails else 0


if __name__ == '__main__':
    raise SystemExit(_selftest())
