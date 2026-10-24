"""The STATISTICS screen's rankings: one list per statistic.

    python tests/lobbyd_statlisttest.py

Two 18-hole match-play rounds between Ann and Bea, and Cal, who has not
played.  Each list should hold only the players with a value for its
statistic, best first, with the lowest-first statistics sent the way the
client draws them: (1 << width) - P.
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import lobbyd
import twdb
import twstats

ANN, BEA, CAL = 'Ann', 'Bea', 'Cal'


def result(auth, strokes, drives, eagles, reporter):
    """One `rank` submission; side 0 is the host, Ann."""
    line = ('WHEN=2026.10.24 3:00:00\tAUTH=%s\tREPT=%s\tNAME0=%s\tNAME1=%s\t'
            'RANK0=1\tRANK1=1\tQUIT0=0\tQUIT1=0\tTYPE0=0\tTYPE1=0\t'
            'DONE0=1\tDONE1=1\tSCORE0=3\tSCORE1=-3\tCLUB0=5\tCLUB1=5\t'
            'STROKES0=%d\tSTROKES1=%d\tPUTTS0=30\tPUTTS1=31\tHOLES0=18\tHOLES1=18\t'
            'EAGS0=%d\tEAGS1=%d\tBIRD0=4\tBIRD1=2\tACES0=0\tACES1=0\t'
            'GIR0=12\tGIR1=10\tLPUT0=31\tLPUT1=3\tDRVS0=14\tDRVS1=14\t'
            'FRWY0=9\tFRWY1=7\tLDRV0=%d\tLDRV1=%d\tSHTC0=0\tSHTC1=0\t'
            'PARS0=11\tPARS1=11\tSBOG0=1\tSBOG1=2\tDBOG0=0\tDBOG1=0\t'
            'TBOG0=0\tTBOG1=1\tCOMP0=18\tCOMP1=18'
            % ((auth, reporter, ANN, BEA) + strokes + eagles + drives))
    return dict(kv.split('=', 1) for kv in line.split('\t'))


def rows(stub, index):
    label, board = stub.list_rows(index)
    return label, ['%d %s %d' % (rank, row['name'], row['p']) for rank, row in board]


def main():
    path = os.path.join(tempfile.gettempdir(), 'tw04-test-statlist.db')
    for leftover in (path, path + '-wal', path + '-shm'):
        try:
            os.remove(leftover)
        except OSError:
            pass

    db = twdb.DB(path)
    for name in (ANN, BEA, CAL):
        db.create_account(name, 'pass1234')
    # Ann wins both on strokes; the second round has the longer drives and one
    # eagle each, so the eagle list is a tie.
    for auth, strokes, drives, eagles in (('a0000000000000001', (70, 74), (369, 334), (0, 0)),
                                          ('a0000000000000002', (72, 75), (381, 352), (1, 1))):
        db.add_session(auth, 'Match.T.East', ANN, BEA, 1627551796)
        db.add_result(result(auth, strokes, drives, eagles, ANN))

    lobbyd.DB = db
    lobbyd.ARGS = type('A', (), {'probe_stats': False})()
    stub = lobbyd.Handler.__new__(lobbyd.Handler)

    best = {who: twstats.unpack(stub.stat_record(who)[:-1])[twstats.BEST_ROUND] for who in (ANN, BEA)}
    width = twstats.FIELDS[twstats.BEST_ROUND][0]
    want = {
        4: ['1 Ann 381', '2 Bea 352'],                                       # longest drive
        9: ['1 Ann 1', '1 Bea 1'],                                           # eagles, tied
        18: ['1 Ann 2'],                                                     # match wins; Bea has none
        19: ['1 Bea 2'],                                                     # match losses
        29: ['1 Ann %d' % ((1 << width) - 70), '2 Bea %d' % ((1 << width) - 74)],  # best round, lowest first
        0: ['1 Ann 4'],                                                      # rank points
        30: [],                                                              # field 40: nobody
    }

    fails = []
    print('best rounds: %s %d, %s %d' % (ANN, best[ANN], BEA, best[BEA]))
    if best[ANN] != 70 or best[BEA] != 74:
        fails.append('best rounds should be 70 and 74, got %r' % best)
    for index, expected in sorted(want.items()):
        label, got = rows(stub, index)
        print('list %2d (%s): %s' % (index, label, got or '(empty)'))
        if got != expected:
            fails.append('list %d should be %r, got %r' % (index, expected, got))
        if any(CAL in r for r in got):
            fails.append('list %d shows %s, who has not played' % (index, CAL))

    # The fixed boards keep their own lists.
    if 13 in lobbyd.Handler.STAT_LISTS or 14 in lobbyd.Handler.STAT_LISTS or 32 in lobbyd.Handler.STAT_LISTS:
        fails.append('13, 14 and 32 have boards of their own')

    print()
    if fails:
        for f in fails:
            print('FAIL', f)
        return 1
    print('PASS')
    return 0


if __name__ == '__main__':
    sys.exit(main())
