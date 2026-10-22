"""The four-day events (twtourney.MAJORS), against a scratch database.

    python tests/twdb_majorstest.py

A major is four ordinary daily events on one course.  What makes it one event
is the server adding them up, and each rule here is one a one-day event never
needed:

1. **The board is the running total.**  Each day's board is the sum of each
   player's round of every day so far (the first one recorded), and a player
   who misses a day is off it -- including on the console's daily leaderboard.
   The weekend events and the one-round-a-day rule: tests/twdb_weekendtest.py.
2. **It is decided once.**  Nothing is paid, and nobody wins, until the last
   day is over; then the purse is paid on the 72-hole total.
3. **It is entered once.**  Four rounds are one event on MY RESUME and the
   money lists.
4. **Old calendars gain majors safely.**  A calendar stored before majors
   existed gets them only where the event has not started and nobody has
   played a round of it -- and an old database file opens and upgrades.
"""
import datetime
import os
import shutil
import sqlite3
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root
sys.path.insert(0, HERE)
import twdb
import twrecords
import twtourney

# The 2026 US Major: Thursday 18 to Sunday 21 June.
FIRST = twtourney.to_day(datetime.date(2026, 6, 18))
LAST = FIRST + twtourney.MAJOR_DAYS - 1
PURSE = 15000000


def card(strokes):
    return {'HOLES': 18, 'STROKES': strokes, 'PUTTS': 30, 'PARS': 18,
            'DONE': 1, 'QUIT': 0}


def check(cond, what):
    if not cond:
        sys.exit('FAIL: ' + what)


def on(day):
    """Pretend today is `day` -- every module asks twtourney.today()."""
    twtourney.today = lambda: day


# alice plays every day; bob too, worse; carol leads day 1 and misses day 2.
PLAY = {'alice': (70, 70, 70, 70), 'bob': (72, 72, 72, 72),
        'carol': (66, None, 66, 66)}


def play(db, upto):
    for n in range(upto):
        for who, rounds in sorted(PLAY.items()):
            if rounds[n] is not None:
                db.add_tourney(who, FIRST + n, 0, card(rounds[n]))


def running_board(db):
    db.add_events(twtourney.majors_between(FIRST, LAST))
    on(FIRST + 1)
    play(db, 2)
    first = [(r['name'], r['strokes'], r['rounds']) for r in db.tourney_board(FIRST)]
    check(first == [('carol', 66, 1), ('alice', 70, 1), ('bob', 72, 1)],
          'round 1 is an ordinary board: %r' % first)
    second = db.tourney_board(FIRST + 1)
    got = [(r['name'], r['strokes'], r['by_round'], r['place']) for r in second]
    check(got == [('alice', 140, [70, 70], 1), ('bob', 144, [72, 72], 2)],
          'round 2 is the running total, and carol missed it: %r' % got)
    # These cards imply par 70 (twtourney.card_par), so 140 is level over two.
    check(second[0]['par'] == 2 * db.course_par(0) == 140
          and twtourney.row_to_par(second[0]) == 'E'
          and twtourney.row_to_par(second[1]) == '+4',
          'par on a running board covers every round: %r'
          % [(r['par'], twtourney.row_to_par(r)) for r in second])
    check(db.tourney_place('carol', FIRST + 1)[0] == 0,
          'a missed round has no place')
    check(db.tourney_standings(FIRST, LAST, twtourney.payout,
                               open_day=FIRST + 1)[0]['earned'] == 0,
          'nothing is paid while the event is being played')


def decided_once(db):
    play_rest = {who: rounds for who, rounds in PLAY.items()}
    for n in (2, 3):
        for who, rounds in sorted(play_rest.items()):
            db.add_tourney(who, FIRST + n, 0, card(rounds[n]))
    on(LAST)                     # the last day is still open
    open_ = {r['name']: r for r in db.tourney_standings(
        FIRST, LAST, twtourney.payout)}
    check(all(r['earned'] == 0 and r['wins'] == 0 for r in open_.values()),
          'the last day pays nothing until it is over')
    on(LAST + 1)
    final = [(r['name'], r['strokes'], r['place']) for r in db.tourney_board(LAST)]
    check(final == [('alice', 280, 1), ('bob', 288, 2)],
          'the 72-hole board leaves carol off: %r' % final)
    table = {r['name']: r for r in db.tourney_standings(
        FIRST, LAST, twtourney.payout)}
    check(table['alice']['earned'] == twtourney.payout(PURSE, 1)
          and table['bob']['earned'] == twtourney.payout(PURSE, 2)
          and table['carol']['earned'] == 0,
          'the purse is paid once, on the total: %r'
          % {k: v['earned'] for k, v in table.items()})
    check((table['alice']['events'], table['alice']['rounds'],
           table['alice']['wins']) == (1, 4, 1),
          'four rounds are one event and one win: %r' % table['alice'])
    check((table['carol']['events'], table['carol']['wins']) == (1, 0),
          'carol entered once and won nothing')
    career = db.tourney_career('alice', twtourney.payout)
    check((career['entered'], career['won'], career['earned']) ==
          (1, 1, twtourney.payout(PURSE, 1)), 'MY RESUME: %r' % career)
    recent = db.tourney_recent()
    check([(r['day'], r['winner']['name']) for r in recent] == [(LAST, 'alice')],
          'only the last day has a winner: %r'
          % [(r['day'], r['winner']['name']) for r in recent])
    wins = twrecords.tourney_wins(twrecords.rounds(db))
    check(sorted(wins) == ['alice'] and wins['alice'][0]['day'] == LAST,
          "carol's day-one 66 is not a win: %r" % dict(wins))


def news(db):
    mid = twrecords.news(db, today=FIRST + 1).replace('\n  ', ' ')
    check('Leader: alice 140' in mid and 'after 2 rounds, 2 in the field' in mid,
          'the news leads with the running total: %r' % mid)
    check('Led by carol 66' in mid, "yesterday's leader, not a winner: %r" % mid)
    after = twrecords.news(db, today=LAST + 1).replace('\n  ', ' ')
    check('Won by alice 280' in after, 'the last day names its winner: %r' % after)


def lobby(db):
    """The console's daily board, its winners list and the round receipt."""
    import lobbyd
    lobbyd.DB = db
    lobbyd.log = lobbyd.note = lambda *a, **k: None
    lobbyd.publish_live = lambda: None

    class Stub(object):
        SEASON_DAYS = lobbyd.Handler.SEASON_DAYS
        DAILY_BASE = lobbyd.Handler.DAILY_BASE
        WEEKLY_BASE = lobbyd.Handler.WEEKLY_BASE
        LIST_WEEK_GOLFERS = lobbyd.Handler.LIST_WEEK_GOLFERS
        LIST_TOURNEY_WINNERS = lobbyd.Handler.LIST_TOURNEY_WINNERS
        LISTS = lobbyd.Handler.LISTS
        TOURNEY_KEYS = {}
        list_rows = lobbyd.Handler.list_rows
        event_winners = lobbyd.Handler.event_winners
        weekly_winners = lobbyd.Handler.weekly_winners
        week_earnings = lobbyd.Handler.week_earnings
        on_5d0tr = lobbyd.Handler.on_5d0tr
        persona = 'alice'
        sent = None

        def send(self, kind, ident, tags=None, raw=None):
            self.sent = raw
    stub = Stub()
    on(LAST + 1)
    index = stub.DAILY_BASE + (FIRST + 2) - (LAST + 1 - stub.SEASON_DAYS)
    _what, rows = stub.list_rows(index)
    check([(rank, r['name'], r['strokes']) for rank, r in rows] ==
          [(1, 'alice', 210), (2, 'bob', 216)],
          'the daily board after round 3 is the total: %r'
          % [(rank, r['name'], r['strokes']) for rank, r in rows])
    check(rows[0][1]['p'] > rows[1][1]['p'], 'the leader sorts first')
    winners = [(r['name'], r['day']) for r in stub.event_winners()]
    check(winners == [('alice', LAST)],
          'TOURNAMENT WINNERS lists the event once: %r' % winners)

    # A round reported on a major day: a fresh player on day 2, then dana's
    # day 3 after missing nothing -- and carol, who missed day 2.
    on(FIRST + 2)
    key = b'K' * 16

    def report(who, strokes):
        stub.persona = who
        stub.TOURNEY_KEYS[who] = (FIRST + 2, key)
        f = dict.fromkeys(twtourney.ROUND_FIELDS, 0)
        f.update(DONE=1, HOLES=18, STROKES=strokes, PARS=18, PUTTS=30)
        blob = struct.pack('<23I', *[f[k] for k in twtourney.ROUND_FIELDS])
        blob += key + struct.pack('<HBB', FIRST + 2, 0, 0) + bytes(16)
        stub.on_5d0tr(0, {'PERS': who, 'DATA': blob.hex()})
        return stub.sent.decode('ascii')
    msg = report('carol', 64)
    check(msg.startswith('Round 3 of 4: 64 is recorded') and
          'missed round' in msg, 'carol is told she is off the board: %r' % msg)
    msg = report('alice', 75)
    check(msg.startswith('Round 3 of 4: 75 is recorded, but your first round of'
                         ' 70 counts')
          and 'Total 210' in msg and '1st of 2' in msg,
          'alice is told her total and place: %r' % msg)


def calendar(folder):
    """Majors on a calendar drawn before they existed, and an old file."""
    path = os.path.join(folder, 'old.db')
    # An events table from before the `series` column.
    conn = sqlite3.connect(path)
    conn.execute('CREATE TABLE events (day INTEGER PRIMARY KEY, name TEXT NOT'
                 ' NULL, course INTEGER NOT NULL DEFAULT 0, purse INTEGER NOT'
                 ' NULL DEFAULT 0, created REAL NOT NULL, conditions TEXT NOT'
                 " NULL DEFAULT '')")
    june = twtourney.month_days(2026, 6)[0]
    conn.executemany('INSERT INTO events VALUES (?, ?, 3, 1000000, 0, ?)',
                     [(d, 'Old %d' % d, '') for d in range(june, june + 30)])
    conn.commit()
    conn.close()
    db = twdb.DB(path)
    try:
        check(db.event(FIRST)['series'] is None, 'an old day is a one-day event')
        majors = twtourney.majors_between(june, june + 29)
        check(db.place_series(majors, FIRST + 1) == [],
              'an event that has started is not placed')
        db.add_tourney('zed', FIRST + 3, 3, card(70))
        check(db.place_series(majors, FIRST) == [],
              'an event with a round on any day is not placed')
        db.run('DELETE FROM tourney')
        check(db.place_series(majors, FIRST) == [FIRST],
              'an untouched event is placed whole')
        ev = [db.event(d) for d in range(FIRST, LAST + 1)]
        check([(e['name'], e['series'], e['purse'], e['course']) for e in ev] ==
              [('US Major Championship R%d' % n, FIRST, PURSE, 20)
               for n in range(1, 5)], 'placed: %r' % ev)
        check(db.event(FIRST - 1)['name'] == 'Old %d' % (FIRST - 1),
              'the days around it are left alone')
        check(db.place_series(majors, FIRST) == [], 'placing again does nothing')
        twtourney.today = lambda: FIRST
        entry = twtourney.entries_for([db.event(FIRST)])[0]
        check(entry[1][twtourney.ICON_OFFSET] == twtourney.MAJOR_ICON,
              'a stored major day draws the star')
    finally:
        db.conn.close()


def main():
    real_today = twtourney.today
    d = tempfile.mkdtemp()
    db = twdb.DB(os.path.join(d, 'tw04.db'))
    try:
        running_board(db)
        decided_once(db)
        news(db)
        lobby(db)
        calendar(d)
    finally:
        twtourney.today = real_today
        db.conn.close()
        shutil.rmtree(d, ignore_errors=True)
    print('ok: a major\'s board is the running total and drops a missed round;\n'
          '    it is paid and won once, on the last day, and entered once; the\n'
          '    console board, winners list, receipt and news agree; and an old\n'
          '    calendar gains majors only where nobody has played')


if __name__ == '__main__':
    main()
