"""`twdb.py --reset-stats`: everything played goes, the accounts stay (TW04).

    python tests/twdb_resettest.py

The TW05 server's tests/reset_test.py for the same command here.  A database
with rounds, a match, a calendar, a golfer, a buddy and an abuse report is
reset through the real command line.  The
accounts, personas, golfer, buddy and report must survive; everything else
must be empty; a copy must have been saved first; and the calendar must move
on a generation, so the lobby deals a NEW one -- while generation 0 still
draws exactly the calendar every existing database has.  A lobby whose
heartbeat is fresh must be refused.
"""
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
SERVER = HERE
import twdb                                             # noqa: E402
import twrecords                                        # noqa: E402
import twstats                                          # noqa: E402
import twtourney                                        # noqa: E402

KEEP = ('accounts', 'personas', 'golfers', 'buddies', 'reports')
WIPE = ('results', 'sessions', 'tourney', 'events', 'daily_peak', 'live')


def count(path, table):
    db = twdb.DB(path)
    return db.one('SELECT COUNT(*) AS n FROM %s' % table)['n']


def reset(path, *extra):
    return subprocess.run([sys.executable, os.path.join(SERVER, 'twdb.py'),
                           '--db', path, '--reset-stats'] + list(extra),
                          capture_output=True, text=True, input='')


def main():
    tmp = tempfile.mkdtemp(prefix='tw04reset')
    path = os.path.join(tmp, 'tw04.db')
    fails = []
    try:
        db = twrecords.sample(path)
        year, month = twtourney.month_of(twtourney.today())
        db.add_events(twtourney.generate_month(year, month, twstats.COURSES))
        db.set_golfer('alice', b'\x80golfer')
        db.add_buddy('alice', 'bob')
        db.add_report('alice', 'bob')
        db.note_online(2)
        before = {t: count(path, t) for t in KEEP + WIPE}
        print('before: %s' % before)

        # 1. a running lobby is refused, and nothing changes
        db.set_live('heartbeat', int(time.time()))
        r = reset(path, '--yes')
        if r.returncode == 0 or count(path, 'tourney') != before['tourney']:
            fails.append('a fresh heartbeat must stop the reset: %r' % r.stdout)
        db.set_live('heartbeat', 0)            # what a clean stop leaves

        # 2. without --yes, anything but RESET leaves it alone
        r = reset(path)
        if r.returncode == 0 or count(path, 'results') != before['results']:
            fails.append('no RESET typed, so nothing may change')

        # 3. the reset itself
        r = reset(path, '--yes')
        print(r.stdout.strip())
        if r.returncode != 0:
            fails.append('the reset failed: %s %s' % (r.stdout, r.stderr))
        after = {t: count(path, t) for t in KEEP + WIPE}
        print('after:  %s' % after)
        for t in KEEP:
            if after[t] != before[t] or not before[t]:
                fails.append('%s must survive the reset (%d -> %d)'
                             % (t, before[t], after[t]))
        for t in WIPE:
            if after[t]:
                fails.append('%s must be empty after the reset, has %d'
                             % (t, after[t]))
        copies = glob.glob(os.path.join(tmp, 'before-reset-*.db'))
        if len(copies) != 1 or count(copies[0], 'tourney') != before['tourney']:
            fails.append('a full copy must be saved before the reset: %r'
                         % copies)
        db = twdb.DB(path)
        if db.calendar_epoch() != 1:
            fails.append('the calendar should be on generation 1, is %d'
                         % db.calendar_epoch())
        if not db.verify('alice', 'password'):
            fails.append('alice must still be able to sign in')

        # 4. a new calendar for generation 1; generation 0 is untouched
        g0 = [e['course'] for e in twtourney.generate_month(
            year, month, twstats.COURSES)]
        g0b = [e['course'] for e in twtourney.generate_month(
            year, month, twstats.COURSES, 0)]
        g1 = [e['course'] for e in twtourney.generate_month(
            year, month, twstats.COURSES, db.calendar_epoch())]
        if g0 != g0b:
            fails.append('generation 0 must be the calendar it always was')
        if sum(a == b for a, b in zip(g0, g1)) > len(g0) // 2:
            fails.append('generation 1 should be a different calendar')
        again = reset(path, '--yes')
        if again.returncode != 0 or twdb.DB(path).calendar_epoch() != 2:
            fails.append('a second reset should move on to generation 2')

        # 5. --reset-calendar on its own: a fresh database with this month and
        #    next generated, a round played on a FUTURE day, and the usual
        #    rounds today and in the past
        cal = os.path.join(tmp, 'calendar.db')
        db = twrecords.sample(cal)
        today = twtourney.today()
        y, m = twtourney.month_of(today)
        ny, nm = (y + 1, 1) if m == 12 else (y, m + 1)
        for yy, mm in ((y, m), (ny, nm)):
            db.add_events(twtourney.generate_month(yy, mm, twstats.COURSES))
        future = today + 3
        db.add_tourney('alice', future, 4, {'HOLES': 18, 'STROKES': 70,
                                           'DONE': 1, 'QUIT': 0})
        old = {r['day']: (r['course'], r['name'])
               for r in db.query('SELECT day, course, name FROM events')}
        rounds = count(cal, 'tourney')
        r = subprocess.run([sys.executable, os.path.join(SERVER, 'twdb.py'),
                            '--db', cal, '--reset-calendar', '--yes'],
                           capture_output=True, text=True, input='')
        print(r.stdout.strip().splitlines()[-1] if r.stdout else r.stderr)
        db = twdb.DB(cal)
        left = {r['day'] for r in db.query('SELECT day FROM events')}
        should_stay = {d for d in old if d <= today or d == future}
        if r.returncode != 0 or left != should_stay:
            fails.append('--reset-calendar should keep today, the past and '
                         'played days only: kept %d of %d'
                         % (len(left), len(should_stay)))
        epoch = db.calendar_epoch()
        if epoch in (0, 1) or count(cal, 'tourney') != rounds or \
                count(cal, 'accounts') != 3:
            fails.append('a random generation, and nothing else touched '
                         '(epoch %d)' % epoch)
        if not glob.glob(os.path.join(tmp, 'before-calendar-*.db')):
            fails.append('--reset-calendar must save a copy first')
        # what the lobby does next (ensure_season): fill the short months
        # from the new generation, adding only the missing days
        for yy, mm in ((y, m), (ny, nm)):
            db.add_events(twtourney.generate_month(yy, mm, twstats.COURSES,
                                                   epoch))
        new = {r['day']: (r['course'], r['name'])
               for r in db.query('SELECT day, course, name FROM events')}
        if set(new) != set(old):
            fails.append('the lobby should refill every cleared day')
        if any(new[d] != old[d] for d in should_stay):
            fails.append('kept days must not change when the lobby refills')
        redrawn = [d for d in old if d not in should_stay]
        if sum(new[d][0] == old[d][0] for d in redrawn) > len(redrawn) // 2:
            fails.append('the cleared days should be a new draw')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for f in fails:
        print('FAIL %s' % f)
    if not fails:
        print('ok: a reset keeps accounts, personas, golfers, buddies and '
              'reports,\n    wipes play, saves a copy first, refuses a '
              'running lobby, and\n    deals a new calendar; --reset-calendar '
              'redraws only the days to come')
    return 1 if fails else 0


if __name__ == '__main__':
    sys.exit(main())
