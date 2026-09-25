"""Tournament money and the server totals, against a scratch database.

    python tests/twdb_tourneytest.py

Three rules, each of which the site once got wrong:

1. **Ties share.**  Two players on the same score share the place and split
   the prizes for the places they cover, as the Tour does -- whoever happened
   to post first used to take all of 1st.
2. **An open day has no winner.**  Today's event counts towards the events
   a player has entered, but not towards earnings, wins, best finish or the
   winners lists until the day is over.
3. **Every match counts.**  The Server Stats totals and a player's record used
   to read only the newest few hundred matches, so both stopped growing.
4. **MY RESUME carries the tournaments.**  The console's stats record used to
   be built from head-to-head matches alone, so a tournament player's resume
   read all zeros.  Tiger Status climbs with online points.
5. **One backup a day.**  The daily copy is made once, opens as a database,
   and only the newest few are kept.
"""
import datetime
import os
import sqlite3
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import twdb
import twrecords
import twstats
import twtourney

TODAY = twtourney.today()
PURSE = 1000000


def card(strokes):
    # Enough of a real card for the player pages to count it as finished.
    return {'HOLES': 18, 'STROKES': strokes, 'PUTTS': 30, 'PARS': 18,
            'DONE': 1, 'QUIT': 0}


def check(cond, what):
    if not cond:
        sys.exit('FAIL: ' + what)


def ties_and_open_days(db):
    yesterday = TODAY - 1
    db.add_events([{'day': d, 'name': 'Test Open', 'course': 4,
                    'purse': PURSE} for d in (yesterday, TODAY)])
    # Yesterday: alice and bob tie for 1st, carol is 3rd -- not 2nd.
    for who, s in (('alice', 62), ('bob', 62), ('carol', 65)):
        db.add_tourney(who, yesterday, 4, card(s))
    board = db.tourney_day(yesterday)
    check([(r['name'], r['place'], r['tied']) for r in board] ==
          [('alice', 1, 2), ('bob', 1, 2), ('carol', 3, 1)],
          'tied scores share a place: %r' % [(r['name'], r['place'], r['tied'])
                                             for r in board])
    check(db.tourney_place('bob', yesterday) == (1, 3), 'bob is 1st of 3')

    # Today: only dave has played, so he leads but has not won anything.
    db.add_tourney('dave', TODAY, 4, card(70))

    rows = {r['name']: r for r in
            db.tourney_standings(yesterday, TODAY, twtourney.payout)}
    split = (twtourney.payout(PURSE, 1) + twtourney.payout(PURSE, 2)) // 2
    check(rows['alice']['earned'] == rows['bob']['earned'] == split,
          'a tie for 1st splits 1st and 2nd: %r, %r, want %d'
          % (rows['alice']['earned'], rows['bob']['earned'], split))
    check(rows['carol']['earned'] == twtourney.payout(PURSE, 3),
          'the next score is paid as 3rd')
    check(rows['alice']['wins'] == rows['bob']['wins'] == 1,
          'a tie for 1st is a win for both')
    check(rows['dave']['rounds'] == 1 and rows['dave']['earned'] == 0,
          "today's leader has entered, but is paid nothing yet: %r"
          % rows['dave'])
    check(rows['dave']['wins'] == 0 and rows['dave']['best'] is None,
          "today's leader has not won yet: %r" % rows['dave'])

    recent = db.tourney_recent()
    check([r['day'] for r in recent] == [yesterday],
          'recent winners leave out the open day: %r'
          % [r['day'] for r in recent])
    check([w['name'] for w in recent[0]['winners']] == ['alice', 'bob'],
          'both co-winners are listed')

    wins = twrecords.tourney_wins(twrecords.rounds(db))
    check(sorted(wins) == ['alice', 'bob'],
          'player pages count co-winners and not today: %r' % sorted(wins))

    # MY RESUME, as the console gets it.
    c = db.tourney_career('alice', twtourney.payout)
    check((c['entered'], c['won'], c['top10'], c['top25'], c['earned']) ==
          (1, 1, 1, 1, split) and c['rank'] in (1, 2),
          "alice's career: %r" % c)
    c = db.tourney_career('dave', twtourney.payout)
    check((c['entered'], c['won'], c['earned'], c['rank']) == (1, 0, 0, 0),
          "today's entrant has entered, and no more: %r" % c)
    import lobbyd

    class Stub(object):
        standing = lobbyd.Handler.standing
        stat_record = lobbyd.Handler.stat_record
    lobbyd.DB = db
    lobbyd.ARGS = type('A', (), {'probe_stats': False})()
    row = twstats.unpack(Stub().stat_record('carol')[:-1])
    want = {twstats.EVENTS_ENTERED: 1, twstats.EVENTS_WON: 0,
            twstats.TOP10: 1, twstats.TOP25: 1,
            twstats.TOTAL_EARNINGS: twtourney.payout(PURSE, 3)
            // twstats.EARNINGS_SCALE,
            twstats.BEST_ROUND: 65, twstats.SCORING_AVERAGE: 65}
    got = {k: row[k] for k in want}
    check(got == want, "carol's resume, tournament rounds only: %r, want %r"
          % (got, want))
    # EARNINGS RANK comes from `myrnk`: word 10 of RNKRS.  carol is 3rd.
    import struct
    Stub.rank_record = lobbyd.Handler.rank_record
    Stub.RNKRS_BYTES = lobbyd.Handler.RNKRS_BYTES
    Stub.RNKRS_EARNINGS_RANK = lobbyd.Handler.RNKRS_EARNINGS_RANK
    blob = Stub().rank_record('carol')
    words = struct.unpack('<36I', blob)
    check(len(blob) == 144 and words[10] == 3 and sum(words) == 3,
          "carol's RNKRS should hold rank 3 in word 10 only: %r" % (words,))


def tiger_and_backups(db, folder):
    steps = [(p, twstats.tiger_status(p)) for p in (0, 49, 50, 100, 199, 200,
                                                     499, 500, 5000)]
    check(steps == [(0, 0), (49, 0), (50, 1), (100, 2), (199, 2), (200, 3),
                    (499, 3), (500, 4), (5000, 4)],
          'Tiger Status gains a letter at 50, 100, 200 and 500: %r' % steps)

    first = datetime.date(2026, 1, 1)
    made = [db.backup(folder, keep=3, day=first + datetime.timedelta(days=n))
            for n in range(5)]
    check(all(made), 'a copy each new day: %r' % made)
    check(db.backup(folder, keep=3, day=first + datetime.timedelta(days=4))
          is None, "a second copy the same day is skipped")
    left = sorted(os.listdir(folder))
    check(left == ['tw04-2026-01-03.db', 'tw04-2026-01-04.db',
                   'tw04-2026-01-05.db'], 'only the newest 3 kept: %r' % left)
    copy = sqlite3.connect(os.path.join(folder, left[-1]))
    try:
        n = copy.execute('SELECT COUNT(*) FROM tourney').fetchone()[0]
    finally:
        copy.close()
    check(n == db.one('SELECT COUNT(*) AS n FROM tourney')['n'],
          'the copy holds the same rounds')


def every_match(db):
    n = 620                              # more than the old cap of 500
    for i in range(n):
        auth = 'm%04d' % i
        db.add_session(auth, 'Stroke.T.Test', 'erin', 'finn', i)
        db.add_result({'AUTH': auth, 'REPT': 'erin',
                       'DONE0': '1', 'DONE1': '1', 'QUIT0': '0', 'QUIT1': '0',
                       'HOLES0': '18', 'HOLES1': '18',
                       'STROKES0': '70', 'STROKES1': '72'})
    st = db.stats()
    check(st['matches'] == n, 'every match is counted: %d of %d'
          % (st['matches'], n))
    check(db.record('erin')[:2] == (n, n),
          "a player's record reads every match: %r" % (db.record('erin'),))
    check(db.leaderboard()[0]['played'] == n, 'the leaderboard reads them all')

    # And the cache notices a new one.
    db.add_session('late', 'Stroke.T.Test', 'erin', 'finn', 1)
    db.add_result({'AUTH': 'late', 'REPT': 'erin', 'DONE0': '1', 'DONE1': '1',
                   'HOLES0': '18', 'HOLES1': '18',
                   'STROKES0': '75', 'STROKES1': '71'})
    check(db.stats()['matches'] == n + 1, 'a new match shows up at once')
    check(len(db.matches('finn', limit=3)) == 3, 'limit still limits')


def main():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        db = twdb.DB(os.path.join(d, 'tw04.db'))
        try:
            ties_and_open_days(db)
            tiger_and_backups(db, os.path.join(d, 'backups'))
            every_match(db)
        finally:
            db.conn.close()
    print('ok: tied scores share places and prize money, an open day has no\n'
          '    winner yet, every match counts towards the totals, and MY\n'
          '    RESUME carries tournament rounds and money, and the daily\n'
          '    backup keeps the newest copies')


if __name__ == '__main__':
    main()
