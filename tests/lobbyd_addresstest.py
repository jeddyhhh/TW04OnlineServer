"""Which address each console is given for the peer-to-peer leg (TW04).

    python tests/lobbyd_addresstest.py

The TW05 server's tests/address_test.py, for the same rule ported here.

lobbyd.peer_address, in the five cases that matter, without a server: the
answers only depend on what each console reported in `addr` (ONLINE) and
where its lobby connection came from (REACH).
"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
sys.argv = sys.argv[:1]
import lobbyd                                           # noqa: E402


class Args:
    peer_addr = ''


CASES = [
    # (what it is, reported, seen, what a is told for b, what b is told for a)
    ('two real PS2s on different internet connections: their public IPs, '
     'never their private ones',
     {'a': '192.168.1.20', 'b': '192.168.0.7'}, {'a': '1.1.1.1', 'b': '2.2.2.2'},
     '2.2.2.2', '1.1.1.1'),
    ('two real PS2s behind one router, server on the internet: each '
     'other\'s LAN address',
     {'a': '192.168.1.20', 'b': '192.168.1.21'}, {'a': '3.3.3.3', 'b': '3.3.3.3'},
     '192.168.1.21', '192.168.1.20'),
    ('PCSX2 in Sockets mode behind one router: no LAN address to give, so '
     'the public one (the router has to loop it back; TW04 copes)',
     {'a': '192.0.2.100', 'b': '192.0.2.100'}, {'a': '3.3.3.3', 'b': '3.3.3.3'},
     '3.3.3.3', '3.3.3.3'),
    ('PCSX2 with the lobby on the LAN (the rig): each host adapter',
     {'a': '192.0.2.100', 'b': '192.0.2.100'},
     {'a': '192.168.1.50', 'b': '192.168.0.5'},
     '192.168.0.5', '192.168.1.50'),
    ('one real PS2 and one PCSX2 on the same router: the PS2 is reachable '
     'on the LAN, the PCSX2 only through the router',
     {'a': '192.168.1.20', 'b': '192.0.2.100'}, {'a': '3.3.3.3', 'b': '3.3.3.3'},
     '3.3.3.3', '192.168.1.20'),
]


def main():
    lobbyd.ARGS = Args()
    fails = []
    for what, reported, seen, want_ab, want_ba in CASES:
        lobbyd.ONLINE.clear()
        lobbyd.REACH.clear()
        lobbyd.ONLINE.update({p: (addr, '3658') for p, addr in reported.items()})
        lobbyd.REACH.update(seen)
        got = (lobbyd.peer_address('b', 'a')[0], lobbyd.peer_address('a', 'b')[0])
        print('%-15s %-15s  %s' % (got[0], got[1], what))
        if got != (want_ab, want_ba):
            fails.append('%s: expected %s / %s' % (what, want_ab, want_ba))
    Args.peer_addr = '9.9.9.9'
    if lobbyd.peer_address('b', 'a')[0] != '9.9.9.9':
        fails.append('--peer-addr must win over everything')
    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print()
    print('ok: public addresses between networks, LAN addresses within one')
    return 0


if __name__ == '__main__':
    sys.exit(main())
