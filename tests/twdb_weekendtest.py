"""The three-round weekend events and one round a day, against a scratch
database.

    python tests/twdb_weekendtest.py

Every weekend outside a major is Friday's event played Friday to Sunday
(twtourney.weekend_rounds).  What is checked here:

1. **One start a day.**  On a day of a multi-day event, a second `esr2t` is
   refused with the same empty list as a day with no event; a one-day event
   still lets a player start as often as they like.
2. **The first round stands.**  An unfinished round of a multi-day event is not
   recorded (the player is out), and a second card for a day does not replace
   the first.
3. **It is a three-round event.**  The receipt counts "of 3", the board is the
   54-hole total, and the purse is paid once, on Sunday.
4. **Old calendars gain weekends safely.**  lobbyd.schedule_weekends turns a
   stored Friday into the weekend, whole, only where nobody has played.
"""
import datetime
import os
import shutil
import struct
import sys
import tempfile
import types

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root
sys.path.insert(0, HERE)

import twdb
import twtourney

# 2026-10-23 to 25: an ordinary weekend.
FRIDAY = twtourney.to_day(datetime.date(2026, 10, 23))


def check(cond, what):
    if not cond:
        sys.exit('FAIL: ' + what)


def on(day):
    """Pretend today is `day` -- every module asks twtourney.today()."""
    twtourney.today = lambda: day


def stub_lobby(db):
    import lobbyd
    lobbyd.DB = db
    lobbyd.ARGS = types.SimpleNamespace(probe_tourney=False, probe_icons=False,
                                        probe_conditions=False)
    lobbyd.log = lobbyd.note = lambda *a, **k: None
    lobbyd.publish_live = lambda: None

    class Stub(object):
        TOURNEY_KEYS = {}
        on_esr2t = lobbyd.Handler.on_esr2t
        on_5d0tr = lobbyd.Handler.on_5d0tr
        tourney_entry = lobbyd.Handler.tourney_entry
        persona = 'alice'
        sent = None

        def send(self, kind, ident, tags=None, raw=None):
            self.sent = raw if raw is not None else tags
    return lobbyd, Stub()


def start(stub, who):
    stub.persona = who
    stub.on_esr2t(0, {'PERS': who})
    return stub.sent


def report(stub, who, day, strokes, holes=18, quit=0):
    key = stub.TOURNEY_KEYS[who][1]
    f = dict.fromkeys(twtourney.ROUND_FIELDS, 0)
    f.update(DONE=int(not quit), QUIT=quit, HOLES=holes, STROKES=strokes,
             PARS=holes, PUTTS=2 * holes)
    blob = struct.pack('<23I', *[f[k] for k in twtourney.ROUND_FIELDS])
    blob += key + struct.pack('<HBB', day, 0, 0) + bytes(16)
    stub.persona = who
    stub.on_5d0tr(0, {'PERS': who, 'DATA': blob.hex()})
    return stub.sent.decode('ascii')


def weekend(db):
    db.add_events(twtourney.generate_month(2026, 10))
    lobbyd, stub = stub_lobby(db)
    friday = db.event(FRIDAY)
    check(friday['series'] == FRIDAY and friday['name'].endswith(' R1'),
          'Friday is round 1 of the weekend: %r' % friday)
    check(db.event(FRIDAY - 1)['series'] is None, 'Thursday is a one-day event')

    # A one-day event: start as often as you like.
    on(FRIDAY - 1)
    for _ in range(2):
        check(start(stub, 'alice')['DATA'] != '', 'a one-day event can be replayed')

    # Friday: alice plays 70; a second start is refused.  bob quits.
    on(FRIDAY)
    check(start(stub, 'alice')['DATA'] != '', 'the first start of the day is let in')
    msg = report(stub, 'alice', FRIDAY, 70)
    check(msg.startswith('Round 1 of 3: 70 is recorded. That is your round for'
                         ' today'), 'the receipt counts three rounds: %r' % msg)
    refused = start(stub, 'alice')
    check(refused['DATA'] == '' and refused['TKEY'] == bytes(16),
          'a second start of the day is refused: %r' % refused)
    start(stub, 'bob')
    msg = report(stub, 'bob', FRIDAY, 20, holes=4, quit=1)
    check('out of this event' in msg, 'an unfinished round is told it is out: %r'
          % msg)
    check(db.tourney_day(FRIDAY, limit=10) and
          [r['name'] for r in db.tourney_day(FRIDAY, limit=10)] == ['alice'],
          'the unfinished round is not on the board')
    check(start(stub, 'bob')['DATA'] == '', 'quitting does not give a retry')
    # A second card for the day (a key from before this rule, say) does not
    # replace the first.
    stub.TOURNEY_KEYS['alice'] = (FRIDAY, b'L' * 16)
    msg = report(stub, 'alice', FRIDAY, 65)
    check('your first round of 70 counts' in msg, 'the first round stands: %r' % msg)

    # Saturday and Sunday.
    for n, strokes in ((1, 71), (2, 72)):
        on(FRIDAY + n)
        start(stub, 'alice')
        msg = report(stub, 'alice', FRIDAY + n, strokes)
    check(msg.startswith('Round 3 of 3: 72 is recorded.')
          and 'tomorrow' not in msg, 'the last round says nothing about tomorrow: %r'
          % msg)
    on(FRIDAY + 3)
    board = db.tourney_board(FRIDAY + 2)
    check([(r['name'], r['strokes'], r['by_round']) for r in board] ==
          [('alice', 213, [70, 71, 72])], 'the 54-hole board: %r' % board)
    on(FRIDAY + 2)                       # Sunday still open: nothing paid
    open_ = {r['name']: r for r in db.tourney_standings(
        FRIDAY, FRIDAY + 2, twtourney.payout)}
    check(open_['alice']['earned'] == 0, 'nothing is paid before Sunday is over')
    on(FRIDAY + 3)
    only = {r['name']: r for r in db.tourney_standings(
        FRIDAY, FRIDAY + 2, twtourney.payout)}
    check((only['alice']['earned'], only['alice']['events'], only['alice']['wins'])
          == (twtourney.payout(friday['purse'], 1), 1, 1),
          'three rounds are one event, won and paid once: %r' % only['alice'])


def stored_calendar(folder):
    """A calendar drawn before weekend events existed."""
    db = twdb.DB(os.path.join(folder, 'old.db'))
    try:
        lobbyd, _stub = stub_lobby(db)
        plain = [dict(e, series=None, name='Plain %d' % e['day'], purse=2000000)
                 for e in twtourney.draw_month(2026, 10)]
        db.add_events(plain)
        on(FRIDAY + 1)                         # this weekend has started
        check(lobbyd.schedule_weekends() == [], 'a started weekend is left alone')
        on(FRIDAY)
        db.add_tourney('zed', FRIDAY + 2, 3, {'HOLES': 18, 'STROKES': 70,
                                             'PARS': 18, 'DONE': 1, 'QUIT': 0})
        check(FRIDAY not in lobbyd.schedule_weekends(),
              'a weekend with a round on it is left alone')
        db.run('DELETE FROM tourney')
        db.run("UPDATE events SET series = 0, name = 'Plain ' || day"
               ' WHERE day >= ?', (FRIDAY,))
        check(FRIDAY in lobbyd.schedule_weekends(), 'an untouched weekend is placed')
        got = [(e['name'], e['series'], e['purse']) for e in
               (db.event(FRIDAY + n) for n in range(3))]
        check(got == [('Plain %d R%d' % (FRIDAY, n), FRIDAY, 3000000)
                      for n in (1, 2, 3)],
              "the weekend is the stored Friday's, at 1.5x: %r" % got)
        check(db.event(FRIDAY + 3)['series'] is None, 'Monday is left alone')
        check(lobbyd.schedule_weekends() == [], 'placing again does nothing')
    finally:
        db.conn.close()


def main():
    real_today = twtourney.today
    d = tempfile.mkdtemp()
    db = twdb.DB(os.path.join(d, 'tw04.db'))
    try:
        weekend(db)
        stored_calendar(d)
    finally:
        twtourney.today = real_today
        db.conn.close()
        shutil.rmtree(d, ignore_errors=True)
    print('ok: a weekend is three rounds of Friday\'s event, one start a day,\n'
          '    an unfinished round puts a player out and a second card does not\n'
          '    replace the first; it is paid and won once, on Sunday; and an old\n'
          '    calendar gains weekends only where nobody has played')


if __name__ == '__main__':
    main()
