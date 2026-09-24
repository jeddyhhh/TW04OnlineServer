"""Event pages, head to head, achievements, the activity chart and the admin
page.

    python tests/webui_featurestest.py

Serves the twrecords sample database behind a base path, as the live site is,
with a lobby on the same database, then:

- reads every new page back, and checks the links to them from the old ones;
- works the admin page the way the operator would -- a password reset that
  really changes the password, a ban, a rename that carries a player's results
  with them, and news that the console then shows -- and checks that a wrong
  key gets nothing but a 404.
"""
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))    # the repository root, where the server is
sys.path.insert(0, HERE)
import twdb
import twrecords
import twtourney
from webui_pagestest import news_screen, wait_port
import webui_pagestest

WEB = 8096
LOBBY = 10295
BASE = '/TW04Online'
KEY = 'test-admin-key'
TEST_DB = os.path.join(tempfile.gettempdir(), 'tw04-test-features.db')
NEWS = os.path.join(tempfile.gettempdir(), 'tw04-test-features-news.txt')


def request(path, form=None):
    url = 'http://127.0.0.1:%d%s%s' % (WEB, BASE, path)
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    try:
        with urllib.request.urlopen(url, data=data, timeout=10) as r:
            return r.status, r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')


def achievement_rules(today):
    """The five achievements, on made-up rounds: only a FINISHED day's win
    counts, and every course needs a win of either kind."""
    def r(kind, when, course, strokes=70, day=None, **kw):
        base = {'persona': 'ann', 'kind': kind, 'when': when, 'day': day,
                'course': course, 'holes': 18, 'strokes': strokes,
                'eagles': 0, 'aces': 0, 'result': None, 'opponent': ''}
        base.update(kw)
        return base
    courses = list(twtourney.TOURNEY_COURSES)
    rs = [r('stroke', 1, courses[0], eagles=1, result='W', opponent='x'),
          r('stroke', 2, courses[1], strokes=59, result='W', opponent='x')]
    # tournament wins on the other courses, the last one today (still open)
    for n, c in enumerate(courses[2:]):
        day = today - (len(courses) - 3) + n      # the last one is today
        rs.append(r('tourney', 10 + n, c, day=day))
    got = {a['key']: a for a in twrecords.achievements(rs, 'ann', open_day=today)}
    fails = []
    if not got['eagle']['when'] or got['ace']['when']:
        fails.append('eagle earned, ace not: %r' % got)
    if got['sub60']['when'] != 2:
        fails.append('a 59 is under 60')
    if not got['wins5']['when']:
        fails.append('five finished tournament wins earn Five-time winner')
    if got['every']['when'] or got['every']['progress'] != '%d of %d courses' % (
            len(courses) - 1, len(courses)):
        fails.append("today's open event must not complete the set: %r"
                     % got['every'])
    rs.append(r('match', 99, courses[-1], result='W', opponent='x'))
    got = {a['key']: a for a in twrecords.achievements(rs, 'ann', open_day=today)}
    if got['every']['when'] != 99:
        fails.append('a match win on the last course completes the set')
    return fails


def main():
    today = twtourney.today()
    iso = lambda d: twtourney.from_day(d).isoformat()             # noqa: E731
    db = twrecords.sample(TEST_DB, today)
    db.add_events([{'day': today - 1, 'name': 'Yesterday Invitational',
                    'course': 4, 'purse': 2000000},
                   {'day': today + 3, 'name': 'Future Classic', 'course': 9,
                    'purse': 3000000}])
    with open(NEWS, 'w', encoding='utf-8') as f:
        f.write('Old news.\n')

    procs = [
        subprocess.Popen(
            [sys.executable, os.path.join(HERE, 'webui.py'), '--host',
             '127.0.0.1', '--port', str(WEB), '--db', TEST_DB, '--base-path',
             BASE, '--no-secure-cookie', '--logfile', '', '--reports-key',
             'off', '--admin-key', KEY, '--news', NEWS],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT),
        subprocess.Popen(
            [sys.executable, os.path.join(HERE, 'lobbyd.py'), '--host',
             '127.0.0.1', '--port', str(LOBBY), '--db', TEST_DB, '--logfile',
             '', '--ping', '0', '--buddy-port', '0', '--news', NEWS,
             '--no-auto-news'],
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT),
    ]
    fails = achievement_rules(today)

    def check(path, status, *want, absent=(), form=None):
        got, body = request(path, form)
        missing = [w for w in want if w not in body]
        present = [a for a in absent if a in body]
        print('%-5s %-40s %d%s' % ('POST' if form is not None else 'GET',
                                   path[:40], got,
                                   '' if not (missing or present) else '  <-- here'))
        if got != status:
            fails.append('%s should be %d, got %d' % (path, status, got))
        fails.extend('%s should contain %r' % (path, w) for w in missing)
        fails.extend('%s must not contain %r' % (path, a) for a in present)
        return body

    try:
        wait_port(WEB)
        wait_port(LOBBY)

        # -- event pages ------------------------------------------------------
        # Yesterday: alice 66 beat bob 71, so 18% and 10.9% of $2,000,000.
        check('/event/' + iso(today - 1), 200, 'Yesterday Invitational',
              'Final leaderboard', 'href="%s/player/alice"' % BASE,
              '$360,000', '$218,000', 'final')
        check('/event/' + iso(today), 200, 'Test Open', 'closes in',
              'Still open', '$180,000')         # bob leads today, on 68
        check('/event/' + iso(today + 3), 200, 'Future Classic',
              'not played yet', absent=('<th>Pos</th>',))
        check('/event/2001-01-01', 404, 'There was no event')
        check('/event/yesterday', 404, 'not a date')

        # -- head to head -----------------------------------------------------
        # The sample match: alice 69 beat bob 73 in stroke play.
        check('/h2h/alice/bob', 200, 'Last meetings', 'alice won',
              'Stroke play 1&ndash;0&ndash;0',
              'href="%s/h2h/bob/alice"' % BASE)
        check('/h2h/BOB/Alice', 200, 'alice won')    # names match any case
        check('/h2h/alice/carol', 200, 'have not finished a match')
        check('/h2h/alice/nobody', 404, 'Nobody here is called')
        check('/h2h/alice', 404)

        # -- links and the rest -----------------------------------------------
        check('/player/alice', 200, 'Achievements',
              'href="%s/h2h/alice/bob"' % BASE,
              'href="%s/event/%s"' % (BASE, iso(today - 1)))
        check('/player/carol', 200, 'Hole in one', 'Earned')
        check('/tournaments', 200, 'closes in',
              'href="%s/event/%s"' % (BASE, iso(today)),
              'href="%s/event/%s"' % (BASE, iso(today - 1)))
        check('/stats', 200, 'The last 30 days', 'Most players online')

        # -- the admin page ---------------------------------------------------
        check('/admin/wrong', 404, absent=('Account or persona',))
        check('/admin/' + KEY + '?q=bo', 200, 'Accounts', '>bob<',
              'Ban account', absent=('>carol<',))
        acct = db.account('bob')

        body = check('/admin/%s/password' % KEY, 200, 'password is now',
                     form={'id': acct['id'], 'password': 'newpass9', 'q': 'bob'})
        if not db.verify('bob', 'newpass9'):
            fails.append('the password reset did not take')
        body = check('/admin/%s/password' % KEY, 200, 'password is now',
                     form={'id': acct['id'], 'password': '', 'q': 'bob'})
        made = body.split('password is now ')[1].split(' ')[0]
        if not db.verify('bob', made):
            fails.append('the made-up password %r does not work' % made)
        check('/admin/%s/password' % KEY, 200, 'password must be',
              form={'id': acct['id'], 'password': 'abc', 'q': 'bob'})

        check('/admin/%s/ban' % KEY, 200, 'banned bob', 'Lift ban',
              form={'id': acct['id'], 'ban': '1', 'q': 'bob'})
        try:
            db.verify('bob', made)
            fails.append('a banned account can still sign in')
        except twdb.Error:
            pass
        check('/admin/%s/ban' % KEY, 200, 'lifted the ban',
              form={'id': acct['id'], 'ban': '0', 'q': 'bob'})

        check('/admin/%s/rename' % KEY, 200, 'already taken',
              form={'persona': 'bob', 'name': 'alice', 'q': 'bob'})
        check('/admin/%s/rename' % KEY, 200, 'renamed bob to robert',
              form={'persona': 'bob', 'name': 'robert', 'q': 'bob'})
        check('/player/robert', 200, 'Test Open', 'robert')
        check('/player/bob', 404)
        check('/h2h/alice/robert', 200, 'alice won')
        if db.one("SELECT COUNT(*) AS n FROM tourney WHERE persona = 'bob'")['n']:
            fails.append("bob's tournament rounds did not follow the rename")

        check('/admin/%s/news' % KEY, 200, 'plain ASCII',
              form={'news': 'Café night', 'q': ''})
        check('/admin/wrong/news', 404, form={'news': 'hijack', 'q': ''})
        check('/admin/%s/news' % KEY, 200, 'news saved',
              form={'news': 'Hello from the admin page.\r\nSecond line.',
                    'q': ''})
        with open(NEWS, encoding='utf-8') as f:
            saved = f.read()
        if saved != 'Hello from the admin page.\nSecond line.':
            fails.append('the news file holds %r' % saved)

        # The console sees it, and the lobby has started today's peak (the
        # news login picks no persona, so the count itself can be 0).
        webui_pagestest.LOBBY = LOBBY
        text = news_screen()
        if 'Hello from the admin page.' not in text:
            fails.append('the news screen says %r' % text)
        peak = db.one('SELECT peak FROM daily_peak WHERE day = ?', (today,))
        if peak is None:
            fails.append("the lobby did not record today's peak")
    finally:
        for p in procs:
            p.terminate()
            p.wait(timeout=5)
        db.conn.close()

    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: event, head-to-head and stats pages serve and are linked;'
          '\n    the admin page resets, bans, renames and edits the news, and'
          '\n    a wrong key is a 404')
    return 0


if __name__ == '__main__':
    sys.exit(main())
