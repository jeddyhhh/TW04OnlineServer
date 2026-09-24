"""The scoring maths, against a real captured round.

    python tests/twdb_statstest.py

The two `rank` submissions below are verbatim from the first completed
two-player round (a Front 9, 2026-09-18).  They are worth keeping because they
carry three traps that synthetic data would not:

1. `SCORE0` and `SCORE1` are both **0**.  Stroke play does not fill them in, so
   anything that decides a winner from SCORE decides every match is a tie.
   STROKES is the real result and fewer is better.
2. One console reported `NAME0=JeddyH2 NAME1=JeddyH2` -- both sides under the
   same name -- while its numbers were correct and in the same order as its
   opponent's.  So the suffix is positional and the names cannot be trusted:
   0 is the host, from the session the server brokered.
3. Both consoles report, so the same match arrives twice and has to be
   deduplicated on the match token.
"""
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import twdb

AUTH = 'deadbeefcafe0001'
HOST, GUEST = 'JeddyH2', 'JeddyH'

COMMON = ('WHEN=2026.9.18 8:24:00\tAUTH=' + AUTH + '\t'
          'RANK0=1\tRANK1=1\tQUIT0=0\tQUIT1=0\tTYPE0=0\tTYPE1=0\t'
          'DONE0=1\tDONE1=1\tSCORE0=0\tSCORE1=0\tCLUB0=5\tCLUB1=5\t'
          'STROKES0=30\tSTROKES1=41\tPUTTS0=14\tPUTTS1=18\tHOLES0=9\tHOLES1=9\t'
          'EAGS0=1\tEAGS1=0\tBIRD0=4\tBIRD1=2\tACES0=0\tACES1=0\t'
          'GIR0=8\tGIR1=6\tLPUT0=31\tLPUT1=3\tDRVS0=7\tDRVS1=7\t'
          'FRWY0=3\tFRWY1=7\tLDRV0=369\tLDRV1=334\tSHTC0=0\tSHTC1=0\t'
          'PARS0=3\tPARS1=3\tSBOG0=1\tSBOG1=2\tDBOG0=0\tDBOG1=0\t'
          'TBOG0=0\tTBOG1=2\tCOMP0=9\tCOMP1=9')

SUBMISSIONS = [
    'REPT=JeddyH2\tNAME0=JeddyH2\tNAME1=JeddyH\t' + COMMON,
    # the same match as the other console saw it -- note both NAMEs are JeddyH2
    'REPT=JeddyH\tNAME0=JeddyH2\tNAME1=JeddyH2\t' + COMMON,
]


def check_columns(db):
    """STREAK and DROP% as 0x00272390 will render them, from a packed record.

    This is the pair the first working leaderboard got wrong: every row read
    "100" under DROP% because the completed count was never sent, and the
    loser's streak read "0" because a losing run was clamped away.

    The fixture's room is "Match.T.LobbyT", so this round counts as match play
    and lands in 14/16/20.  Stroke play is the same three fields shifted down
    one -- 13/15/19 -- and the same renderer reads both.
    """
    import lobbyd
    import twstats

    class Stub(object):
        standing = lobbyd.Handler.standing
        stat_record = lobbyd.Handler.stat_record
    lobbyd.DB = db
    lobbyd.ARGS = type('A', (), {'probe_stats': False})()

    # The derived lines, from the fixture: the host played 9 holes, 14 putts,
    # 8 GIR, 3 of 7 fairways, 1 eagle, 4 birdies.
    row = twstats.unpack(Stub().stat_record(HOST)[:-1])
    derived = {
        twstats.TOTAL_EAGLES: 1, twstats.TOTAL_BIRDIES: 4,
        twstats.TOTAL_GIR: 8, twstats.FAIRWAYS_HIT: 3,
        twstats.GIR_PERCENT: 89,             # 8 of 9 holes
        twstats.PUTTS_PER_HOLE: 156,         # 14 / 9, in hundredths
        twstats.DRIVING_ACCURACY: 43,        # 3 of 7 drives
        twstats.HOLES_PER_EAGLE: 9,          # 9 holes, 1 eagle
        twstats.BIRDIE_AVERAGE: 4,           # 4 birdies over 1 round
        twstats.MATCH_POINTS: 2,             # one win, in a match room
        twstats.STROKE_POINTS: 0,
    }
    out = []
    for index, want in sorted(derived.items()):
        if row[index] != want:
            out.append('%s should be %d, got %d'
                       % (twstats.NAMED.get(index, index), want, row[index]))
    print('derived: GIR %d%%, %.2f putts/hole, %d%% accuracy, %d holes/eagle'
          % (row[twstats.GIR_PERCENT],
             row[twstats.PUTTS_PER_HOLE] / float(twstats.PUTTS_SCALE),
             row[twstats.DRIVING_ACCURACY], row[twstats.HOLES_PER_EAGLE]))

    for who, streak, drop in ((HOST, 'W1', 0), (GUEST, 'L1', 0)):
        row = twstats.unpack(Stub().stat_record(who)[:-1])
        inc = row[twstats.MATCH_INC]
        done = row[twstats.MATCH_DONE]
        run = row[twstats.MATCH_STREAK]
        got_drop = (0 if inc + done == 0 else
                    100 if inc >= inc + done else
                    int(inc / float(inc + done) * 100))
        got_streak = ('W%d' % run) if run > 0 else ('L%d' % -run) if run else '0'
        print('%s: streak %s, drop %d%% (%d incomplete, %d completed)'
              % (who, got_streak, got_drop, inc, done))
        if got_streak != streak:
            out.append('%s streak should draw %s, got %s' % (who, streak, got_streak))
        if got_drop != drop:
            out.append('%s drop%% should be %d, got %d' % (who, drop, got_drop))
    return out


def main():
    path = os.path.join(tempfile.gettempdir(), 'tw04-test-stats.db')
    for leftover in (path, path + '-wal', path + '-shm'):
        try:
            os.remove(leftover)
        except OSError:
            pass

    db = twdb.DB(path)
    db.create_account(HOST, 'pass1234')
    db.create_account(GUEST, 'pass1234')
    db.add_session(AUTH, 'Match.T.LobbyT', HOST, GUEST, 1627551796)
    for line in SUBMISSIONS:
        db.add_result(dict(kv.split('=', 1) for kv in line.split('\t')))

    fails = []
    matches = db.matches()
    print('%d submission(s) -> %d match(es)' % (len(SUBMISSIONS), len(matches)))
    if len(matches) != 1:
        fails.append('both submissions should collapse to one match, got %d'
                     % len(matches))
    else:
        m = matches[0]
        print('winner %s in %r' % (m['winner'], m['room']))
        for p in m['players']:
            print('   %-8s strokes=%-3d holes=%-2d putts=%-3d birdies=%d eagles=%d'
                  % (p['name'], p['strokes'], p['holes'], p['putts'],
                     p['birdies'], p['eagles']))
        if m['winner'] != HOST:
            fails.append('30 strokes beats 41, so %s should win, got %r'
                         % (HOST, m['winner']))
        host = next(p for p in m['players'] if p['name'] == HOST)
        guest = next(p for p in m['players'] if p['name'] == GUEST)
        if (host['strokes'], guest['strokes']) != (30, 41):
            fails.append('columns are mis-assigned: got %d/%d, expected 30/41'
                         % (host['strokes'], guest['strokes']))
        if host['longest'] != 369 or guest['longest'] != 334:
            fails.append('longest drives mis-assigned: %d/%d'
                         % (host['longest'], guest['longest']))

    print('records: %s %s, %s %s' % (HOST, db.record(HOST), GUEST, db.record(GUEST)))
    if db.record(HOST) != (1, 1, 0, 0):
        fails.append('%s should be 1 played / 1 won, got %r' % (HOST, db.record(HOST)))
    if db.record(GUEST) != (1, 0, 1, 0):
        fails.append('%s should be 1 played / 1 lost, got %r' % (GUEST, db.record(GUEST)))

    board = db.leaderboard()
    print('leaderboard: %s' % ', '.join('%s %.2f/hole' % (e['name'], e['per_hole'])
                                        for e in board))
    if [e['name'] for e in board] != [HOST, GUEST]:
        fails.append('leaderboard order wrong: %r' % [e['name'] for e in board])

    # A result for a match this server never brokered must not be scorable.
    db.add_result({'AUTH': 'notasession', 'REPT': HOST, 'STROKES0': '1'})
    if len(db.matches()) != 1:
        fails.append('a result with an unknown token must not become a match')

    # Each list INDEX gets its own board.  The fixture is a match-play room, so
    # it belongs on 13 and must not appear on 14.
    if [e['name'] for e in db.leaderboard(kind='Match')] != [HOST, GUEST]:
        fails.append('the match board should hold both players')
    if db.leaderboard(kind='Stroke'):
        fails.append('a match-room result must not reach the stroke board')
    if not db.leaderboard(since=0):
        fails.append('a since of 0 should keep everything')
    if db.leaderboard(since=time.time() + 60):
        fails.append('nothing was played in the future')

    # The two leaderboard columns the client computes for itself, checked
    # through the same codec the server packs `S` with.  0x00272458 reads
    # exactly six fields off a row and derives DROP% from two of them.
    fails += check_columns(db)

    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: two submissions collapse to one match, scored by strokes, '
          'columns\n    assigned from the session rather than the NAME fields')
    return 0


if __name__ == '__main__':
    sys.exit(main())
