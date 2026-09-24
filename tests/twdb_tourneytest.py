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
"""
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import twdb
import twrecords
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
            every_match(db)
        finally:
            db.conn.close()
    print('ok: tied scores share places and prize money, an open day has no\n'
          '    winner yet, and every match counts towards the totals')


if __name__ == '__main__':
    main()
