"""Challenges from EA Messenger, and matches with RANKED GAME off.

    python tests/lobbyd_messengertest.py

Messenger's CHALLENGE works outside any room, so the match type comes from
the setup's MFLG.  A match with RANKED GAME off stays in the history but is
left off the records.  The result itself arrives tab-separated, with a space
inside WHEN.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import lobbyd
import tagfield
import twdb

ANN, BEA = 'Ann', 'Bea'


def result(auth):
    """Ann beats Bea 70 to 74, as the console sends it: tab-separated."""
    line = ('WHEN=2026.10.24 13:48:49\tAUTH=%s\tREPT=%s\tNAME0=%s\tNAME1=%s\t'
            'RANK0=1\tRANK1=1\tQUIT0=0\tQUIT1=0\tDONE0=1\tDONE1=1\t'
            'SCORE0=0\tSCORE1=0\tSTROKES0=70\tSTROKES1=74\tHOLES0=18\tHOLES1=18\t'
            'PUTTS0=30\tPUTTS1=31\tLDRV0=300\tLDRV1=280' % (auth, ANN, ANN, BEA))
    return tagfield.decode(line.encode('latin-1') + b'\0')


def main():
    fails = []

    # The type of a match
    names = [
        ('Match.T.East', 'Match.T.East', {'MFLG': '34'}, 'Match.T.East'),   # a room's name stands
        (None, None, {'MFLG': '33'}, 'Match.B.Buddy'),
        (None, 'Match.T.East', {'MFLG': '34'}, 'Stroke.B.Buddy'),
        ('Stroke.T.East', None, None, 'Stroke.T.East'),                    # no setup: as before
        (None, None, None, 'match'),
    ]
    for a, b, setup, want in names:
        got = lobbyd.session_name(a, b, setup)
        if got != want:
            fails.append('session_name(%r, %r, %r) should be %r, got %r' % (a, b, setup, want, got))

    # WHEN keeps its time
    when = result('x').get('WHEN')
    if when != '2026.10.24 13:48:49':
        fails.append('WHEN should be the date and time, got %r' % when)

    path = os.path.join(tempfile.gettempdir(), 'tw04-test-messenger.db')
    for leftover in (path, path + '-wal', path + '-shm'):
        try:
            os.remove(leftover)
        except OSError:
            pass
    db = twdb.DB(path)
    for name in (ANN, BEA):
        db.create_account(name, 'pass1234')
    # One ranked Stroke Play match from Messenger, one with RANKED GAME off
    db.add_session('a0000000000000001', 'Stroke.B.Buddy', ANN, BEA, 1, setup={'COUR': '5', 'MFLG': '34'})
    db.add_result(result('a0000000000000001'))
    db.add_session('a0000000000000002', 'Stroke.B.Buddy', ANN, BEA, 2, setup={'COUR': '5', 'MFLG': '2'})
    db.add_result(result('a0000000000000002'))

    if len(db.matches(ANN)) != 2:
        fails.append('both matches should be in the history, got %d' % len(db.matches(ANN)))
    if db.record(ANN) != (1, 1, 0, 0):
        fails.append("Ann's record should be (1, 1, 0, 0), got %r" % (db.record(ANN),))
    board = {row['name']: row['played'] for row in db.leaderboard(kind='Stroke')}
    if board != {ANN: 1, BEA: 1}:
        fails.append('the Stroke Play board should count one match each, got %r' % board)

    lobbyd.DB = db
    lobbyd.ARGS = type('A', (), {'probe_stats': False})()
    stub = lobbyd.Handler.__new__(lobbyd.Handler)
    stub.stat_record(ANN)    # reads only the ranked match; must not fail on the other

    print()
    if fails:
        for f in fails:
            print('FAIL', f)
        return 1
    print('PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
