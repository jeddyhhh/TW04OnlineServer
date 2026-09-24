"""The sign-up site for the TW04 master server.  Standard library only.

    python tools/webui.py --port 8080

Serves three pages from `http.server`: register, sign in, and a profile page
where an account's personas and match history live.  No framework, no template
engine, no static files -- one process next to `lobbyd`, sharing its sqlite
file.

Accounts made here are what the console's login screen accepts: the account
name and password go in at `auth`, and the personas this page manages are the
list the game offers on the SELECT ACCOUNT screen.
"""
import argparse
import html
import http.cookies
import http.server
import json
import os
import re
import secrets
import socket
import socketserver
import sys
import threading
import time
import urllib.parse

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twdb
import twlog
import twrecords
import twstats
import twtourney

# The patch builder is OPTIONAL.  It is only needed for the download on the
# front page, and a deployment is a folder of files somebody copies by hand --
# so a missing one must cost the feature that needs it and nothing else.  As a
# hard import this took the entire web site off the air, and what the operator
# saw was the reverse proxy's own 503 rather than anything this program had a
# chance to say.
try:
    import make_pnach
except ImportError as _exc:                            # noqa: N816
    make_pnach = None
    MAKE_PNACH_WHY = str(_exc)

DB = None
# One line per request, capped -- see twlog.  stdout only until main() runs.
LOG = twlog.Log(echo=True)
DEFAULT_LOG = os.path.join(os.path.dirname(os.path.dirname(twdb.DEFAULT_DB)),
                           'logs', 'webui.log')
BASE = ''                     # mounted under this path, e.g. '/TW04Online'
TRUST_PROXY = False           # read X-Forwarded-For?  Only behind one.
SECURE_COOKIE = False         # add `Secure`; on when there is TLS in front

# What to tell a visitor to point their game at.  The patch writes a DOTTED
# QUAD into a 16-byte field in the ELF -- the game cannot resolve a name -- so
# whatever is set here has to end up as an IPv4 address.  Empty means "work it
# out from the address this request arrived at", which is right whenever the
# lobby and the web site are the same machine, and wrong otherwise; that is
# what --advertise is for.
ADVERTISE = ''
LOBBY_PORT = 10200

# The operator's abuse-reports page lives at /reports/<REPORTS_KEY> and nowhere
# else: no link to it, no login, and any other path under /reports is an
# ordinary 404, so its existence is not advertised.  The key is made once and
# kept beside the database (see `reports_key`).  Empty switches the page off.
REPORTS_KEY = ''
_ENDPOINT = [0.0, None]       # (when it was resolved, (ip, port)) -- see below
ENDPOINT_TTL = 300


SESSIONS = {}                 # token -> {'account': id, 'csrf': str, 'seen': ts}
SESSION_LOCK = threading.Lock()
SESSION_MAX_AGE = 12 * 3600
ATTEMPTS = {}                 # client ip -> [count, first attempt]
MAX_ATTEMPTS = 10
ATTEMPT_WINDOW = 300

CSS = """
/* A golf palette: fairway green, bunker sand, scorecard cream.  Dark, because
   the console it belongs to is usually the brightest thing in the room. */
:root {
  --turf:#0c1a12; --turf-2:#112417; --line:#1e3a27; --line-2:#2a5236;
  --ink:#e8efe6; --mute:#8fa894; --gold:#c9a227; --flag:#c0392b;
  color-scheme: dark;
}
* { box-sizing:border-box; }
body { margin:0; background:var(--turf); color:var(--ink);
       font:16px/1.6 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif; }

/* header */
.top { border-bottom:1px solid var(--line);
       background:linear-gradient(180deg,#123320,#0d1c13); }
.top .wrap { display:flex; align-items:center; gap:1rem; flex-wrap:wrap;
             padding:1.1rem 1rem; }
.brand { font-size:1.05rem; font-weight:700; letter-spacing:.14em;
         text-transform:uppercase; margin:0; }
.brand span { color:var(--gold); }
.brand small { display:block; font-size:.7rem; letter-spacing:.18em;
               color:var(--mute); font-weight:600; margin-top:.15rem; }
nav { margin-left:auto; display:flex; gap:1.2rem; flex-wrap:wrap;
      font-size:.82rem; letter-spacing:.1em; text-transform:uppercase; }
nav a { color:var(--mute); text-decoration:none; padding-bottom:.2rem;
        border-bottom:2px solid transparent; }
nav a:hover { color:var(--ink); border-bottom-color:var(--gold); }

.wrap { max-width:56rem; margin:0 auto; padding:0 1rem; }
main.wrap { padding-top:2rem; padding-bottom:1rem; }

h1 { font-size:1.6rem; margin:0 0 .3rem; letter-spacing:.01em; }
h2 { font-size:.78rem; margin:0 0 1rem; color:var(--gold); font-weight:700;
     text-transform:uppercase; letter-spacing:.16em; }
h3 { font-size:.95rem; margin:1.6rem 0 .5rem; color:var(--mute); }
.sub { color:var(--mute); margin:0 0 1.8rem; }

.card { background:var(--turf-2); border:1px solid var(--line);
        border-radius:12px; padding:1.4rem; margin-bottom:1.1rem; }
.cols { display:grid; gap:1.1rem; grid-template-columns:repeat(auto-fit,minmax(17rem,1fr)); }

/* the scorecard-style tables */
table { width:100%; border-collapse:collapse; font-size:.9rem; }
caption { text-align:left; color:var(--mute); font-size:.8rem;
          padding-bottom:.5rem; }
th { text-align:left; padding:.4rem .4rem; color:var(--mute); font-weight:600;
     font-size:.72rem; text-transform:uppercase; letter-spacing:.1em;
     border-bottom:1px solid var(--line-2); }
td { padding:.5rem .4rem; border-bottom:1px solid var(--line); }
tbody tr:last-child td { border-bottom:0; }
tbody tr:hover td { background:#16291c; }
td.num, th.num { text-align:right; font-variant-numeric:tabular-nums; }
tr.me td { background:#16291c; }
tr.me td:first-child { box-shadow:inset 3px 0 0 var(--gold); }
.rank { color:var(--mute); font-variant-numeric:tabular-nums; }
.rank-1 { color:var(--gold); font-weight:700; }
.under { color:#6fcf97; } .over { color:#e08b7c; }

/* the stats board */
.figures { display:grid; gap:.8rem;
           grid-template-columns:repeat(auto-fit,minmax(8.5rem,1fr)); }
.figure { background:#0f2115; border:1px solid var(--line);
          border-radius:10px; padding:.8rem .9rem; }
.figure b { display:block; font-size:1.5rem; line-height:1.1;
            font-variant-numeric:tabular-nums; }
.figure span { display:block; font-size:.7rem; color:var(--mute);
               text-transform:uppercase; letter-spacing:.1em; margin-top:.25rem; }

/* forms */
label { display:block; font-size:.78rem; color:var(--mute); margin:.8rem 0 .25rem;
        text-transform:uppercase; letter-spacing:.08em; }
input[type=text], input[type=password], input[type=email], select {
  width:100%; padding:.6rem .75rem; border-radius:8px;
  border:1px solid var(--line-2); background:#0a1710; color:var(--ink);
  font-size:1rem; }
input:focus, select:focus { outline:2px solid var(--gold); outline-offset:1px; }
button { margin-top:1.2rem; padding:.6rem 1.3rem; border:0; border-radius:8px;
         background:var(--gold); color:#20180a; font-size:.9rem; font-weight:700;
         letter-spacing:.06em; text-transform:uppercase; cursor:pointer; }
button:hover { filter:brightness(1.12); }
button.quiet { background:var(--line-2); color:var(--ink); }
.row { display:flex; gap:1rem; flex-wrap:wrap; }
.row > * { flex:1 1 12rem; }

.msg { padding:.8rem 1rem; border-radius:8px; margin:1.5rem 0 0; font-size:.9rem; }
.err { background:#2e1418; border:1px solid #6d2b34; color:#ffc9d0; }
.ok  { background:#10281a; border:1px solid #2c6238; color:#b9f0ca; }

.pill { display:inline-block; background:#16311f; border:1px solid var(--line-2);
        border-radius:999px; padding:.2rem .8rem; margin:0 .35rem .35rem 0;
        font-size:.85rem; }
a { color:#8fd0a3; }
.foot { color:#5f7566; font-size:.8rem; }
footer { border-top:1px solid var(--line); margin-top:2rem; padding:1.5rem 0 2.5rem; }
form.inline { display:inline; }
form.inline button { margin:0; padding:.2rem .7rem; font-size:.72rem; }

/* the patch download and the step lists */
a.dl { display:inline-block; background:var(--gold); color:#20180a;
       text-decoration:none; border-radius:8px; padding:.55rem 1.2rem;
       font-size:.85rem; font-weight:700; letter-spacing:.05em; }
a.dl:hover { filter:brightness(1.12); }
ol.steps { margin:.2rem 0 1.4rem; padding-left:1.3rem; font-size:.9rem;
           color:#c3d3c4; }
ol.steps li { margin:.45rem 0; }
ol.steps code, p code, .foot code { background:#0a1710; border:1px solid var(--line-2);
       border-radius:5px; padding:.05rem .35rem; font-size:.85em; }

/* the live strip and the live page */
.strip { border-bottom:1px solid var(--line); background:#0a1710;
         font-size:.78rem; letter-spacing:.08em; text-transform:uppercase;
         color:var(--mute); }
.strip .wrap { display:flex; gap:1.2rem; flex-wrap:wrap; align-items:center;
               padding:.55rem 1rem; }
.strip a { color:var(--mute); text-decoration:none; margin-left:auto; }
.strip a:hover { color:var(--gold); }
.dot { display:inline-block; width:.55rem; height:.55rem; border-radius:50%;
       margin-right:.45rem; vertical-align:baseline; background:var(--mute); }
.dot.up { background:#4ec07a; box-shadow:0 0 0 3px rgba(78,192,122,.18); }
.dot.down { background:var(--flag); box-shadow:0 0 0 3px rgba(192,57,43,.18); }
.dot.warm { background:var(--gold); }
.feed { list-style:none; margin:0; padding:0; font-size:.9rem; }
.feed li { display:flex; gap:.8rem; padding:.45rem 0;
           border-bottom:1px solid var(--line); }
.feed li:last-child { border-bottom:0; }
.feed time { color:#5f7566; font-size:.78rem; white-space:nowrap;
             min-width:5.5rem; font-variant-numeric:tabular-nums; }
.feed .k { color:var(--gold); font-size:.68rem; letter-spacing:.12em;
           text-transform:uppercase; min-width:5rem; }
.tag { display:inline-block; font-size:.68rem; letter-spacing:.1em;
       text-transform:uppercase; border-radius:999px; padding:.05rem .6rem;
       border:1px solid var(--line-2); color:var(--mute); }
.tag.playing { border-color:#2c6238; color:#8ce0a6; }
.tag.bad { border-color:#7a3b32; color:#f0a393; }
/* a player's or a course's name, linking to its page */
a.pl { color:inherit; text-decoration:none; border-bottom:1px dotted var(--line-2); }
a.pl:hover { color:var(--gold); border-bottom-color:var(--gold); }
.statgrid { display:grid; gap:1.1rem;
            grid-template-columns:repeat(auto-fit,minmax(19rem,1fr)); }
.statgrid .card { margin:0; }
.statgrid table { font-size:.86rem; }
.scroll { overflow-x:auto; }
.show-sm { display:none; }
@media (max-width:560px) { .hide-sm { display:none; } .show-sm { display:block; } }
.conds { color:var(--mute); font-size:.85rem; }
/* an event's prize money: hidden under its schedule row until the event's
   name is clicked (a #pay-<day> link), so it needs no script */
tr.payout { display:none; scroll-margin-top:5rem; }
tr.payout:target { display:table-row; }
/* one padding for the outer cell whether hovered or not -- a hover rule that
   out-ranked the inner cells' padding made the table jump */
tr.payout > td, tbody tr.payout:hover > td { background:#0f1f15; padding:.8rem 1rem; }
tr.payout table { max-width:24rem; font-size:.85rem; }
tr.payout table td { padding:.3rem .4rem; }
tr.payout caption a { float:right; }
.conds b { color:var(--ink); font-weight:600; }
.chat { list-style:none; margin:.8rem 0 0; padding:0; font-size:.86rem; }
.chat li { padding:.3rem 0; border-bottom:1px solid var(--line); display:flex;
           gap:.7rem; align-items:baseline; }
.chat li:last-child { border-bottom:0; }
.chat time { color:#5f7566; font-size:.76rem; white-space:nowrap;
             font-variant-numeric:tabular-nums; }
.chat .who { color:var(--gold); white-space:nowrap; }
.chat .said { word-break:break-word; }
"""



def u(path='/'):
    """A path with the mount prefix on it.

    `page()` rewrites the links inside the HTML, but a redirect is a Location
    HEADER and never passes through it -- so redirects have to ask for the
    prefix themselves or they send the browser out of the mount point.
    """
    return (BASE + path) if path.startswith('/') else path


def _topar(text):
    """Colour a score relative to par, the way a leaderboard does."""
    cls = 'under' if text.startswith('-') else 'over' if text.startswith('+') else ''
    return '<span class="%s">%s</span>' % (cls, text) if cls else text


def plink(name):
    """A player's name, linking to their page."""
    return '<a class="pl" href="/player/%s">%s</a>' % (
        urllib.parse.quote(name, safe=''), html.escape(name))


def clink(course):
    """A course's name, linking to its page."""
    if course is None:
        return '<span class="foot">unknown course</span>'
    return '<a class="pl" href="/course/%d">%s</a>' % (
        course, html.escape(twrecords.course_name(course)))


def conditions_line(conditions):
    """Every tournament setting on one line -- 'Tees Black · Rough Long ...'
    -- so nobody has to know what the game's defaults are."""
    return '<span class="conds">%s</span>' % ' &middot; '.join(
        '%s <b>%s</b>' % (label, html.escape(option))
        for label, option, _default in twtourney.condition_items(conditions))


def conditions_cells(conditions, cls='hide-sm'):
    """The same settings as four table cells, Tees / Rough / Fairways /
    Greens, for the schedule."""
    return ''.join('<td class="%s">%s</td>' % (cls, html.escape(option))
                   for _label, option, _default in
                   twtourney.condition_items(conditions))


def _date(t):
    return time.strftime('%d %b %Y', time.localtime(t)) if t else ''


def _kind(r):
    """What sort of round this was, for a table cell."""
    if r['kind'] == 'tourney':
        return html.escape(r['event'] or 'Tournament')
    return 'Match play' if r['kind'] == 'match' else 'Stroke play'


def _result(r):
    if r['result']:
        verdict = {'W': 'Won', 'L': 'Lost', 'T': 'Tied'}[r['result']]
        return '%s v %s' % (verdict, plink(r['opponent'])) if r['opponent'] \
            else verdict
    if r['place']:
        return '%s of %d' % (_ordinal(r['place']), r['field'])
    return ''


def _score(r):
    """Strokes, and to par where the round was a full eighteen."""
    if r['strokes'] is None:
        return '&ndash;'
    if r['to_par'] is None:
        return '%d <span class="foot">(%d holes)</span>' % (r['strokes'],
                                                           r['holes'])
    return '%d %s' % (r['strokes'], _topar(twrecords.fmt_par(r['to_par'])))


def _rounds_table(rs, who=True, course=True):
    """Date, (player,) type, (course,) score, result."""
    if not rs:
        return '<p class="foot" style="margin:0">No rounds yet.</p>'
    head = ('<th>Date</th>%s<th>Round</th>%s'
            '<th class="num">Score</th><th>Result</th>'
            % ('<th>Golfer</th>' if who else '',
               '<th>Course</th>' if course else ''))
    rows = ''.join(
        '<tr><td>%s</td>%s<td>%s</td>%s<td class="num">%s</td>'
        '<td>%s</td></tr>'
        % (_date(r['when']), '<td>%s</td>' % plink(r['persona']) if who else '',
           _kind(r), '<td>%s</td>' % clink(r['course']) if course else '',
           _score(r), _result(r))
        for r in rs)
    return ('<table><thead><tr>%s</tr></thead><tbody>%s</tbody></table>'
            % (head, rows))


def _ordinal(n):
    """1 -> '1st'.  Same wording the game uses when it confirms a round."""
    if not n or n < 1:
        return '&ndash;'
    if 10 <= n % 100 <= 20:
        return '%dth' % n
    return '%d%s' % (n, {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th'))


_LINK = re.compile(r'((?:href|action)=")(/[^"]*)"')


def _prefix_links(text):
    """Push every absolute link onto the mount point.

    Done once, on the finished page, rather than at each link: the pages are
    %-formatted templates, so threading a prefix through each href would mean
    renumbering every substitution tuple -- a lot of edits and an easy place to
    put a link in the wrong argument slot.  One rewrite at the end cannot miss
    one, and there is nothing else in these pages that looks like a link.
    """
    if not BASE:
        return text
    return _LINK.sub(lambda m: '%s%s%s"' % (m.group(1), BASE, m.group(2)), text)


NAV = (('/', 'Home'), ('/live', 'Live'), ('/leaderboard', 'Leaderboard'),
       ('/tournaments', 'Tournaments'), ('/stats', 'Stats'),
       ('/records', 'Records'), ('/courses', 'Courses'))

# Shown only once there is an account to go to.  Offering it to a visitor who
# is not signed in would be a link that bounces them straight back here.
NAV_ACCOUNT = ('/account', 'Account')

# How often the live page reloads itself.  Short enough to feel live, long
# enough that a browser left open on it is not a load worth thinking about.
LIVE_REFRESH = 20


def _ago(seconds):
    """A duration as a person says it: "just now", "4m", "2h 10m"."""
    seconds = int(max(0, seconds))
    if seconds < 45:
        return 'just now'
    if seconds < 3600:
        return '%dm' % (seconds // 60)
    if seconds < 24 * 3600:
        hours, rest = divmod(seconds, 3600)
        return '%dh %dm' % (hours, rest // 60) if rest >= 60 else '%dh' % hours
    days, rest = divmod(seconds, 24 * 3600)
    return '%dd %dh' % (days, rest // 3600) if rest >= 3600 else '%dd' % days


def _span(seconds):
    """A length of time, for something that has been going on rather than
    something that just happened -- "up just now" reads like nonsense."""
    return 'less than a minute' if seconds < 60 else _ago(seconds)


def live_snapshot():
    """What the master server is doing this second, or None if it is not up.

    `lobbyd` mirrors its own state into the database -- see the LIVE PICTURE
    section there -- because the two are separate processes and this one cannot
    see the other's memory.  A row is only as true as its heartbeat, so a
    server that was killed reads as down here rather than as permanently busy.
    """
    try:
        up, age = DB.server_is_up()
        return {
            'up': up,
            'age': age,
            'online': DB.online() if up else [],
            'playing': DB.playing() if up else [],
            'started': (lambda v: float(v) if v else None)(DB.get_live('started')[0]),
        }
    except Exception:                                  # noqa: BLE001
        return None


def live_strip():
    """One line under the nav, on every page: is the server up, who is on it.

    The single question a visitor arrives with is "can I play right now?", and
    it should not take a click to answer.
    """
    snap = live_snapshot()
    if snap is None:
        return ''
    if not snap['up']:
        return ('<div class="strip"><div class="wrap">'
                '<span><span class="dot down"></span>Master server offline'
                '</span><a href="/live">Live &rarr;</a></div></div>')
    n, games = len(snap['online']), len(snap['playing'])
    who = ', '.join(html.escape(p['persona']) for p in snap['online'][:4])
    if n > 4:
        who += ' and %d more' % (n - 4)
    bits = ['<span><span class="dot up"></span>Master server online</span>',
            '<span>%s</span>' % ('Nobody in the lobby' if not n else
                                 '%d online &middot; %s' % (n, who))]
    if games:
        bits.append('<span>%d match%s in play</span>'
                    % (games, '' if games == 1 else 'es'))
    bits.append('<a href="/live">Live &rarr;</a>')
    return '<div class="strip"><div class="wrap">%s</div></div>' % ''.join(bits)


def lobby_endpoint(host_header=''):
    """(ipv4, port) for the master server, as a visitor must type it.

    The port is whatever `lobbyd` published when it started, so the download
    cannot drift from the server it is for.  The address is `--advertise` when
    given, and otherwise the hostname this request came in on -- which is the
    right answer when the site and the lobby are the same box, and is the only
    thing the site can know when they are not.

    Resolved at most once every ENDPOINT_TTL seconds.  A DNS lookup per page
    load would be absurd, and the answer changes about as often as the server
    moves.
    """
    when, cached = _ENDPOINT
    if cached and time.time() - when < ENDPOINT_TTL:
        return cached

    port = LOBBY_PORT
    try:
        published, _at = DB.get_live('port')
        if published:
            port = int(published)
    except (TypeError, ValueError, AttributeError):
        pass

    name = ADVERTISE or (host_header or '').split(',')[0].strip()
    name = name.rsplit(':', 1)[0] if name.count(':') == 1 else name
    name = name.strip('[]') or socket.gethostname()
    try:
        ip = socket.gethostbyname(name)
    except OSError:
        ip = ''
    # A loopback answer is kept rather than rejected: it is what a local test
    # should get, and an operator running this for real has --advertise.
    _ENDPOINT[:] = [time.time(), (ip, port)]
    return ip, port


# The filename PCSX2 matches against the disc, kept here as well so the route
# still exists -- and still explains itself -- when the builder is missing.
PNACH_NAME = 'SLUS-20757_64F9781E.pnach'


def pnach_name():
    if make_pnach is None:
        return PNACH_NAME
    return '%s_%s.pnach' % (make_pnach.SERIAL, make_pnach.CRC)


def _figure(value, label):
    return '<div class="figure"><b>%s</b><span>%s</span></div>' % (value, label)


def stats_board():
    """The server at a glance, on the foot of every page.

    Deliberately a handful of numbers rather than a report: the point is that a
    visitor can see the place is alive and being played on, which two dozen
    figures would obscure rather than show.
    """
    try:
        st = DB.stats()
    except Exception:                                  # noqa: BLE001
        return ''                                      # never break a page

    figures = [
        _figure(st['accounts'], 'Accounts'),
        _figure(st['personas'], 'Golfers'),
        _figure(st['recent'], 'Active this week'),
        _figure(st['matches'], 'Matches'),
        _figure(st['rounds'], 'Tournament rounds'),
        _figure(st['events'], 'Events scheduled'),
    ]
    if st['holes']:
        figures.append(_figure('{:,}'.format(st['holes']), 'Holes played'))
    # The live half, in the same row: what the place is doing now, beside what
    # it has ever done.
    figures.insert(0, _figure(
        '<span class="dot %s"></span>%s' % ('up' if st['up'] else 'down',
                                            st['online'] if st['up'] else '0'),
        'Online now'))
    if st['peak_online']:
        figures.append(_figure(st['peak_online'], 'Most at once'))

    notes = []
    if st['lobby_uptime']:
        notes.append('Lobby up <strong>%s</strong>' % _span(st['lobby_uptime']))
    elif not st['up']:
        notes.append('Lobby <strong>offline</strong>')
    if st['best_round']:
        notes.append('Best round <strong>%d</strong>' % st['best_round'])
    if st['longest_drive']:
        notes.append('Longest drive <strong>%d yd</strong>' % st['longest_drive'])
    if st['longest_putt']:
        notes.append('Longest putt <strong>%d ft</strong>' % st['longest_putt'])
    if st['eagles']:
        notes.append('<strong>%d</strong> eagle%s' % (st['eagles'],
                                                      '' if st['eagles'] == 1 else 's'))
    if st['aces']:
        notes.append('<strong>%d</strong> hole%s in one'
                     % (st['aces'], '' if st['aces'] == 1 else 's'))
    if st['top_course']:
        course, n = st['top_course']
        notes.append('Most played <strong>%s</strong> (%d)'
                     % (html.escape(twstats.course_name(course)), n))
    if st['since']:
        notes.append('Online since %s'
                     % time.strftime('%d %b %Y', time.localtime(st['since'])))

    return ('<h2>Server stats</h2><div class="figures">%s</div>%s'
            % (''.join(figures),
               '<p class="foot" style="margin-top:1.1rem">%s</p>'
               % ' &middot; '.join(notes) if notes else ''))


# Headers for the reports page: never cached, never indexed, and never leak
# its address to another site in a Referer.
PRIVATE = (('Cache-Control', 'no-store'),
           ('X-Robots-Tag', 'noindex, nofollow'),
           ('Referrer-Policy', 'no-referrer'))


def reports_key(db_path, given=''):
    """The secret in the reports page's address.

    `--reports-key` wins; otherwise it is read from `reports.key` beside the
    database, and made there the first time.  Beside the database rather than
    beside this file, so a deployment copied over the top of an old one keeps
    the same address.
    """
    if given:
        return given
    path = os.path.join(os.path.dirname(os.path.abspath(db_path)), 'reports.key')
    try:
        with open(path, encoding='ascii') as f:
            key = f.read().strip()
        if key:
            return key
    except OSError:
        pass
    key = secrets.token_urlsafe(24)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='ascii') as f:
        f.write(key + '\n')
    return key


def page(title, body, message=None, kind='err', stats=True, refresh=0,
         signed_in=False):
    body = _prefix_links(body)
    banner = ('<div class="msg %s">%s</div>' % (kind, html.escape(message))
              if message else '')
    links = (NAV + (NAV_ACCOUNT,)) if signed_in else NAV
    nav = ''.join('<a href="%s">%s</a>' % (u(href), text) for href, text in links)
    board = _prefix_links(stats_board()) if stats else ''
    strip = _prefix_links(live_strip())
    meta = ('<meta http-equiv="refresh" content="%d">' % refresh) if refresh else ''
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">%s
<title>%s</title><style>%s</style></head><body>
<header class="top"><div class="wrap">
<p class="brand">Tiger Woods <span>PGA Tour 2004</span><small>Online &mdash; community master server</small></p>
<nav>%s</nav></div></header>%s
<main class="wrap">%s%s</main>
<footer><div class="wrap">%s
<p class="foot" style="margin-top:1.4rem">Tiger Woods PGA Tour 2004 is a
trademark of its owners. This is a fan-run server and is not affiliated with
them.</p></div></footer>
</body></html>""" % (meta, html.escape(title), CSS, nav, strip, banner, body,
                     board)
            ).encode('utf-8')


def new_session(account_id):
    token = secrets.token_urlsafe(24)
    with SESSION_LOCK:
        now = time.time()
        for old, data in list(SESSIONS.items()):
            if now - data['seen'] > SESSION_MAX_AGE:
                del SESSIONS[old]
        SESSIONS[token] = {'account': account_id, 'csrf': secrets.token_urlsafe(16),
                           'seen': now}
    return token


def get_session(token):
    with SESSION_LOCK:
        data = SESSIONS.get(token)
        if not data:
            return None
        if time.time() - data['seen'] > SESSION_MAX_AGE:
            del SESSIONS[token]
            return None
        data['seen'] = time.time()
        return dict(data)


def throttled(ip):
    """True when this address has failed too often lately."""
    count, first = ATTEMPTS.get(ip, (0, 0.0))
    if time.time() - first > ATTEMPT_WINDOW:
        ATTEMPTS.pop(ip, None)
        return False
    return count >= MAX_ATTEMPTS


def note_failure(ip):
    count, first = ATTEMPTS.get(ip, (0, time.time()))
    ATTEMPTS[ip] = (count + 1, first)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = 'tw04-webui'
    protocol_version = 'HTTP/1.1'

    def log_message(self, fmt, *args):
        LOG.write('%s %s %s' % (time.strftime('%H:%M:%S'), self.peer(),
                                fmt % args))

    # -- plumbing ----------------------------------------------------------
    def reply(self, body, status=200, cookie=None, location=None,
              ctype='text/html; charset=utf-8', disposition=None, headers=()):
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        if location:
            self.send_header('Location', location)
        if disposition:
            self.send_header('Content-Disposition', disposition)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'same-origin')
        if cookie is not None:
            self.send_header('Set-Cookie', cookie)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, where, cookie=None):
        self.reply(b'', status=303, cookie=cookie, location=where)

    def form(self):
        length = int(self.headers.get('Content-Length') or 0)
        if length > 64 * 1024:
            return {}
        raw = self.rfile.read(length).decode('utf-8', 'replace')
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

    def session(self):
        raw = self.headers.get('Cookie')
        if not raw:
            return None, None
        jar = http.cookies.SimpleCookie(raw)
        token = jar['tw04'].value if 'tw04' in jar else None
        return token, (get_session(token) if token else None)

    def route(self):
        """The path with the mount prefix removed, or None if it is outside it.

        `/TW04Online` and `/TW04Online/` both mean the front page.
        """
        path = urllib.parse.urlparse(self.path).path
        if not BASE:
            return path
        if path == BASE:
            return '/'
        if path.startswith(BASE + '/'):
            return path[len(BASE):]
        return None

    def peer(self):
        """The client's address, which behind a proxy is not the socket's.

        Without this every request comes from 127.0.0.1 and the login throttle
        becomes one shared bucket: a handful of wrong passwords from anyone
        locks out everyone.  X-Forwarded-For is trivially forged, though, so it
        is only believed when the operator says there is a proxy in front.
        """
        if TRUST_PROXY:
            fwd = self.headers.get('X-Forwarded-For')
            if fwd:
                return fwd.split(',')[0].strip()
        return self.client_address[0]

    def cookie_for(self, token):
        # Scoped to the mount point: a cookie for /TW04Online must not be sent
        # to the rest of the site sharing this hostname.  `Secure` keeps it off
        # plain HTTP entirely -- without it, one http:// link is enough to put
        # a live session token on the wire in clear.
        return ('tw04=%s; Path=%s; HttpOnly; SameSite=Lax%s; Max-Age=%d'
                % (token, BASE or '/', '; Secure' if SECURE_COOKIE else '',
                   SESSION_MAX_AGE))

    # -- pages -------------------------------------------------------------
    def do_GET(self):
        path = self.route()
        if path is None:
            return self.reply(page('Not found', '<h1>Not found</h1>'), status=404)
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        note = (query.get('m') or [None])[0]
        _, session = self.session()

        if path == '/':
            return self.reply(self.front(note, session=session))
        if path == '/account':
            if not session:
                return self.redirect(u('/'))
            return self.reply(self.profile(session, note))
        if path == '/' + pnach_name():
            # `?dnas=skip` used to serve the --strong-dnas build.  It hangs the
            # game on PLEASE WAIT -- see notes section 55 -- so the parameter
            # is now ignored rather than removed, because the old link is in
            # people's history and a working patch is a better answer than a
            # 404.
            body = self.pnach()
            if body is None:
                why = ('<code>make_pnach.py</code> is not installed beside '
                       '<code>webui.py</code> on this server.'
                       if make_pnach is None else
                       'This server does not know its own public address, so '
                       'it cannot build a patch that points at itself. The '
                       'operator needs to start it with '
                       '<code>--advertise</code>.')
                return self.reply(page(
                    'Patch', '<div class="card"><h2>Patch</h2>'
                    '<p class="sub" style="margin:0">%s</p></div>' % why),
                    status=503)
            return self.reply(body, ctype='text/plain; charset=utf-8',
                              disposition='attachment; filename="%s"'
                                          % pnach_name())
        if path == '/live':
            return self.reply(self.live(session))
        if path == '/live.json':
            return self.reply(self.live_json(), ctype='application/json')
        if path == '/leaderboard':
            return self.reply(self.leaderboard(session))
        if path == '/stats':
            return self.reply(self.stats_page(session))
        if path == '/records':
            return self.reply(self.records_page(session))
        if path == '/courses':
            return self.reply(self.courses_page(session))
        if path.startswith('/course/'):
            return self.course_page(path[len('/course/'):], session)
        if path.startswith('/player/'):
            return self.player_page(
                urllib.parse.unquote(path[len('/player/'):]), session)
        if path == '/tournaments':
            return self.reply(self.tournaments(session))
        if path.startswith('/reports/'):
            if not self.reports_allowed(path[len('/reports/'):]):
                return self.reply(page('Not found', '<h1>Not found</h1>'),
                                  status=404)
            return self.reply(self.reports_page(note), headers=PRIVATE)
        if path == '/logout':
            token, _ = self.session()
            with SESSION_LOCK:
                SESSIONS.pop(token, None)
            return self.redirect(u('/'), cookie='tw04=; Path=%s; Max-Age=0' % (BASE or '/'))
        self.reply(page('Not found', '<h1>Not found</h1>'), status=404)

    def do_POST(self):
        path = self.route()
        if path is None:
            return self.reply(page('Not found', '<h1>Not found</h1>'), status=404)
        fields = self.form()
        token, session = self.session()

        if path.startswith('/reports/') and path.endswith('/handle'):
            # The key in the path is the credential AND the CSRF token: a
            # third-party page cannot build this form without knowing it.
            key = path[len('/reports/'):-len('/handle')]
            if not self.reports_allowed(key):
                return self.reply(page('Not found', '<h1>Not found</h1>'),
                                  status=404)
            return self.do_report_handled(key, fields)

        if path in ('/register', '/login'):
            if throttled(self.peer()):
                return self.reply(self.front('too many attempts -- wait a few '
                                             'minutes and try again'), status=429)
            return (self.do_register(fields) if path == '/register'
                    else self.do_login(fields))

        if not session:
            return self.redirect(u('/'))
        if not secrets.compare_digest(fields.get('csrf', ''), session['csrf']):
            return self.reply(self.profile(session, 'that form expired -- '
                                           'please try again'), status=400)

        actions = {
            '/persona/add': self.do_add_persona,
            '/persona/drop': self.do_drop_persona,
            '/profile': self.do_profile,
            '/password': self.do_password,
        }
        action = actions.get(path)
        if not action:
            return self.reply(page('Not found', '<h1>Not found</h1>'), status=404)
        try:
            note = action(session, fields)
        except twdb.Error as exc:
            return self.reply(self.profile(session, str(exc)))
        return self.reply(self.profile(session, note, kind='ok'))

    # -- actions -----------------------------------------------------------
    def do_register(self, fields):
        try:
            if fields.get('password') != fields.get('password2'):
                raise twdb.Error('the two passwords do not match')
            account_id = DB.create_account(
                fields.get('account', ''), fields.get('password', ''),
                mail=fields.get('mail', '')[:120],
                gend=fields.get('gend', 'M')[:1] or 'M',
                born=(fields.get('born', '') or '19700101').replace('-', '')[:8],
                persona=fields.get('persona') or fields.get('account', ''))
        except twdb.Error as exc:
            note_failure(self.peer())
            return self.reply(self.front(str(exc), fields))
        return self.redirect(u('/account'), cookie=self.cookie_for(new_session(account_id)))

    def do_login(self, fields):
        try:
            row = DB.verify(fields.get('account', ''), fields.get('password', ''))
        except twdb.Error as exc:
            return self.reply(self.front(str(exc), fields))
        if not row:
            note_failure(self.peer())
            return self.reply(self.front('no account by that name, or the wrong '
                                         'password', fields))
        return self.redirect(u('/account'), cookie=self.cookie_for(new_session(row['id'])))

    def do_add_persona(self, session, fields):
        name = fields.get('persona', '')
        DB.add_persona(session['account'], name)
        return 'added the persona %s' % name

    def do_drop_persona(self, session, fields):
        name = fields.get('persona', '')
        DB.drop_persona(session['account'], name)
        return 'removed the persona %s' % name

    def do_profile(self, session, fields):
        DB.set_profile(session['account'], mail=fields.get('mail', '')[:120],
                       gend=(fields.get('gend') or 'M')[:1],
                       born=(fields.get('born', '') or '19700101').replace('-', '')[:8],
                       spam='spam' in fields)
        return 'profile saved'

    def do_password(self, session, fields):
        row = DB.one('SELECT name FROM accounts WHERE id = ?', (session['account'],))
        if not DB.verify(row['name'], fields.get('current', '')):
            raise twdb.Error('your current password is not right')
        if fields.get('password') != fields.get('password2'):
            raise twdb.Error('the two new passwords do not match')
        DB.set_password(session['account'], fields.get('password', ''))
        return 'password changed'

    # -- rendering ---------------------------------------------------------
    def front(self, note=None, fields=None, session=None):
        """The front page, which is the same page whether or not you are on it.

        Someone who has just signed up wants the connection instructions next,
        and they are here -- so a signed-in visitor gets the same page with the
        two forms replaced by a line saying who they are.
        """
        got = fields or {}
        keep = lambda k: html.escape(got.get(k, ''), quote=True)   # noqa: E731
        if session:
            who = ''
            try:
                row = DB.one('SELECT name FROM accounts WHERE id = ?',
                             (session['account'],))
                who = row['name'] if row else ''
            except Exception:                          # noqa: BLE001
                who = ''
            body = ('<div class="card"><h2>Signed in</h2>'
                    '<p class="sub" style="margin:0">You are signed in%s. '
                    '<a href="/account">Manage your account</a> to add a '
                    'persona or change your password &mdash; or read on for '
                    'how to connect.</p></div>'
                    % (' as <strong>%s</strong>' % html.escape(who)
                       if who else ''))
            return page('Home',
                        self.today_card() + body + self.connect_card()
                        + self.disc_card(), note, signed_in=True)
        body = """
<div class="card">
<h2>Sign in</h2>
<form method="post" action="/login">
  <div class="row">
    <div><label>Account name</label>
      <input type="text" name="account" required autocomplete="username"></div>
    <div><label>Password</label>
      <input type="password" name="password" required
             autocomplete="current-password"></div>
  </div>
  <button type="submit" class="quiet">Sign in</button>
</form>
</div>

<div class="card">
<h2>Create an account</h2>
<p class="sub" style="margin:-.4rem 0 1rem">This is the account you sign in with
on the console.</p>
<form method="post" action="/register">
  <div class="row">
    <div><label>Account name</label>
      <input type="text" name="account" maxlength="%d" value="%s" required
             autocomplete="username"></div>
    <div><label>First persona <span class="foot">(the name other
      players see)</span></label>
      <input type="text" name="persona" maxlength="%d" value="%s"></div>
  </div>
  <div class="row">
    <div><label>Password (%d&ndash;%d characters)</label>
      <input type="password" name="password" required
             autocomplete="new-password"></div>
    <div><label>Repeat password</label>
      <input type="password" name="password2" required
             autocomplete="new-password"></div>
  </div>
  <div class="row">
    <div><label>Email (optional)</label>
      <input type="email" name="mail" value="%s"></div>
    <div><label>Gender</label><select name="gend">
      <option value="M">Male</option><option value="F">Female</option>
    </select></div>
  </div>
  <button type="submit">Create account</button>
</form>
</div>
""" % (twdb.MAX_NAME, keep('account'), twdb.MAX_NAME, keep('persona'),
       twdb.MIN_PASSWORD, twdb.MAX_PASSWORD, keep('mail'))
        return page('Sign in',
                    self.today_card() + body + self.connect_card()
                    + self.disc_card(), note)

    def today_card(self):
        """Today's event, above the fold.  It is the one thing on this site
        that changes every day, so it earns the top of the page."""
        day = twtourney.today()
        event = DB.event(day)
        if not event:
            return ''
        board = DB.tourney_day(day, limit=3)
        played = ''
        if board:
            rows = ''.join(
                '<tr><td class="rank%s">%d</td><td>%s</td>'
                '<td class="num">%d</td><td class="num %s">%s</td></tr>'
                % (' rank-1' if n == 1 else '', n, plink(r['name']),
                   r['strokes'],
                   'under' if twtourney.to_par(
                       r['fields'], r['par']).startswith('-') else 'over',
                   twtourney.to_par(r['fields'], r['par']))
                for n, r in enumerate(board, 1))
            played = ('<table style="margin-top:1rem"><caption>Leading today'
                      '</caption><tbody>%s</tbody></table>' % rows)
        else:
            played = ('<p class="foot" style="margin-top:1rem">Nobody has '
                      'posted a score yet today.</p>')
        return ('<div class="card"><h2>Today&rsquo;s event</h2>'
                '<h1 style="margin:0 0 .2rem">%s</h1>'
                '<p class="sub" style="margin:0">%s &middot; %s &middot; '
                '%s</p><p style="margin:.5rem 0 0">%s</p>%s</div>'
                % (html.escape(event['name']),
                   html.escape(twstats.course_name(event['course'])),
                   twtourney.money(event['purse']),
                   twtourney.from_day(day).strftime('%A %d %B %Y'),
                   conditions_line(event.get('conditions')), played))

    def connect_card(self):
        """How to get the game talking to this server, with the patch to do it.

        This is the single thing a visitor cannot work out for themselves: the
        lobby address is an IP literal compiled into the disc, so there is no
        setting anywhere in the game that points it here.  Everything else on
        the site is optional reading; this is not.
        """
        ip, port = lobby_endpoint(self.headers.get('Host', ''))
        where = ('<code>%s</code> port <code>%d</code>' % (html.escape(ip), port)
                 if ip else 'this server')
        unresolved = '' if ip else (
            '<p class="msg err" style="margin:1rem 0 0">This site cannot work '
            'out its own public address, so the patch below may point at the '
            'wrong place. The server operator should start it with '
            '<code>--advertise</code>.</p>')
        if make_pnach is None:
            download = (
                '<p class="msg err" style="margin:0 0 1.2rem">The patch cannot '
                'be built on this server, so there is nothing to download yet '
                '&mdash; <code>make_pnach.py</code> is missing beside '
                '<code>webui.py</code>. Everything below still applies; ask '
                'whoever runs the server for the file.</p>')
        else:
            download = (
                '<p><a class="dl" href="/%s">Download %s</a></p>'
                '<p class="foot">If the DNAS screen takes a long time &mdash; '
                'half a minute or more, which is common on Linux and the Steam '
                'Deck &mdash; that is a name lookup timing out, not the patch. '
                'Setting <strong>DNS1</strong> in step 2 below to a real '
                'resolver fixes it.</p>' % (pnach_name(), pnach_name()))
        return """
<div class="card">
<h2>Connect from PCSX2</h2>
<p class="sub" style="margin:-.4rem 0 1.2rem">The lobby address is compiled
into the disc, so the game has to be patched to reach %s. Nothing is written to
your ISO &mdash; deleting the file below puts everything back.</p>

%s

<h3>1. Install the patch</h3>
<ol class="steps">
<li>Put the downloaded file in your PCSX2 <code>cheats</code> folder.
  In PCSX2 that is <em>Settings &rarr; Folders</em>, or
  <code>&lt;PCSX2&gt;/cheats</code> next to the executable. Keep the filename
  exactly as it downloaded &mdash; PCSX2 matches it against the disc's serial
  and CRC.</li>
<li>Right-click the game in your list &rarr; <em>Properties</em> &rarr;
  <em>Patches</em>, and tick <strong>Enable Cheats</strong>. Doing it per game
  leaves the rest of your library alone.</li>
<li>Start the game. The PCSX2 console should report the patches as active. The
  patch applies at boot, so a game already running is still using EA's old
  address.</li>
</ol>

<h3>2. Turn the network on</h3>
<ol class="steps">
<li><em>Settings &rarr; Network &amp; HDD</em>: tick
  <strong>Enable Network (DEV9)</strong>.</li>
<li>Set the Ethernet device mode to <strong>Sockets</strong> unless you know
  you want PCAP. Sockets needs no drivers and no administrator rights.</li>
<li><strong>Ethernet Device</strong>: on <strong>Linux and the Steam
  Deck</strong>, leave it on <strong>Auto</strong>. Picking your adapter by name
  (<code>wlan0</code>, say) still gets you into the lobby, but head-to-head
  matches then never start. On Windows, choose the adapter you connect to the
  internet with.</li>
<li>Set <strong>DNS1</strong> to a real resolver &mdash; your router, or
  <code>1.1.1.1</code>. Leaving it on Auto is the usual cause of a long wait
  at the DNAS and lobby screens.</li>
</ol>

<h3>3. Sign up, then sign in</h3>
<ol class="steps">
<li>Create an account at the top of this page. The <strong>account name</strong>
  and <strong>password</strong> are what you type on the console; the
  <strong>persona</strong> is the name other players see. An account can hold
  up to four personas, and you can add more once you are signed in here.</li>
<li>Passwords are %d&ndash;%d characters. The console's keyboard is limited, so
  something short and plain travels better.</li>
<li><strong>First time only:</strong> the game needs a PlayStation&nbsp;2
  network configuration on the memory card. If there is none, it says so when
  you choose <em>ONLINE</em> and offers to create one with the network
  configurator on the game disc. Don't change anything there &mdash; just save
  the default settings to the memory card. You won't be asked again.</li>
<li>On the console choose <em>ONLINE</em> from the main menu, let it pass the
  DNAS screen, then enter the same account name and password. Pick your persona
  on the SELECT ACCOUNT screen.</li>
<li>You are in the lobby. Stroke play and match play are head to head against
  another player; the daily tournament is against everyone else's score for
  that day. All three feed the leaderboards on this site.</li>
</ol>

<h3>If it will not connect</h3>
<p class="foot">Check the <a href="/live">live page</a> first &mdash; if the
master server is offline, nothing will connect. Otherwise the usual causes are
Enable Cheats left off, the patch file renamed, DEV9 not enabled, or the game
started before the patch was installed. For head-to-head play the two consoles
talk <strong>directly</strong> to each other over UDP once the server has
introduced them, so both need to be reachable from one another &mdash; a Wi-Fi
network with client isolation turned on will let you into the lobby and then
fail to start the match.  On Linux or a Steam Deck, the same symptom comes from
the Ethernet Device being set to an adapter by name instead of Auto.</p>
%s
</div>""" % (where, download, twdb.MIN_PASSWORD, twdb.MAX_PASSWORD, unresolved)

    def disc_card(self):
        """Exactly which release the patch is for, and how to check yours.

        PCSX2 matches a .pnach to a game by SERIAL and CRC -- they are the
        filename -- so a disc that reports anything else will silently not be
        patched, and the game will quietly dial EA's dead address instead.
        Every address in the patch is an offset into this one build, so this is
        not a detail a visitor can approximate.
        """
        return """
<div class="card">
<h2>The disc you need</h2>
<p class="sub" style="margin:-.4rem 0 1.2rem">The patch is a list of addresses
inside one specific build of the game, so it will not apply to any other
release. PCSX2 shows the serial and CRC of whatever you have in its game
list.</p>

<table><tbody>
<tr><td>Title</td><td><strong>Tiger Woods PGA Tour 2004</strong></td></tr>
<tr><td>Platform</td><td>PlayStation 2</td></tr>
<tr><td>Region</td><td>USA &mdash; NTSC-U/C</td></tr>
<tr><td>Serial</td><td><code>%s</code></td></tr>
<tr><td>CRC</td><td><code>%s</code></td></tr>
</tbody></table>

<p class="foot">Dump your own disc &mdash; a PS2 game you own reads on most PC
DVD drives, and PCSX2 documents the process. You will also need a PS2 BIOS
image, which has to come from a console you own; PCSX2 cannot run without one
and none is distributed here.</p>
</div>""" % (make_pnach.SERIAL if make_pnach else 'SLUS-20757',
             make_pnach.CRC if make_pnach else '64F9781E')

    def pnach(self, strong=False):
        """The patch itself, built for THIS server rather than shipped as a
        fixed file, so the address in it cannot be stale.

        `strong` is never passed from the site.  The --strong-dnas build is
        kept in make_pnach for anyone working on it with a debugger, but it is
        not something to hand a visitor: it stops the game dead on the DNAS
        screen.
        """
        if make_pnach is None:
            return None
        ip, port = lobby_endpoint(self.headers.get('Host', ''))
        if not ip:
            return None
        return make_pnach.build(
            ip, port, strong,
            comment='Master server -> %s:%d.  %sDownloaded from this '
                    'server\'s web site.'
                    % (ip, port, 'DNAS driver stopped.  ' if strong else '')
        ).encode('utf-8')

    # -- the live page ------------------------------------------------------
    FEED_WORDS = {
        'login': 'arrived', 'logout': 'left', 'room': 'lobby',
        'match': 'tee off', 'result': 'result', 'round': 'round',
        'signup': 'new player', 'calendar': 'calendar', 'server': 'server',
    }

    def live(self, session):
        """Who is on the server right now, and what has just happened.

        The page reloads itself rather than polling with script: it is a few
        kilobytes, there is nothing on it to lose across a reload, and a meta
        refresh works with script switched off.
        """
        snap = live_snapshot()
        if snap is None:
            return page('Live', '<div class="card"><h2>Live</h2>'
                                '<p class="sub" style="margin:0">The server '
                                'status is not available.</p></div>',
                        signed_in=bool(session))

        if not snap['up']:
            last = ('last heard from %s ago' % _ago(snap['age'])
                    if snap['age'] else 'it has not checked in')
            card = ('<div class="card"><h2>Master server</h2>'
                    '<h1 style="margin:0"><span class="dot down"></span>'
                    'Offline</h1>'
                    '<p class="sub" style="margin:.4rem 0 0">The lobby is not '
                    'answering &mdash; %s. The web site keeps working; the '
                    'game will not connect until it is back.</p></div>' % last)
            return page('Live', card + self.feed_card(),
                        refresh=LIVE_REFRESH, signed_in=bool(session))

        cards = []
        uptime = ('up %s' % _span(time.time() - snap['started'])
                  if snap['started'] else 'up')
        games = len(snap['playing'])
        cards.append(
            '<div class="card"><h2>Master server</h2>'
            '<h1 style="margin:0"><span class="dot up"></span>Online</h1>'
            '<p class="sub" style="margin:.4rem 0 0">%s &middot; last check-in '
            '%s &middot; %d in the lobby &middot; %d match%s in play</p></div>'
            % (uptime, _ago(snap['age']), len(snap['online']), games,
               '' if games == 1 else 'es'))

        if snap['online']:
            rows = []
            now = time.time()
            for player in snap['online']:
                tag = ('<span class="tag playing">playing</span>'
                       if player['state'] == 'playing' else '')
                rows.append('<tr><td><strong>%s</strong> %s</td><td>%s</td>'
                            '<td class="num">%s</td></tr>'
                            % (plink(player['persona']), tag,
                               html.escape(player['detail']
                                           or 'choosing a lobby'),
                               _ago(now - player['since'])))
            cards.append('<div class="card"><h2>In the lobby</h2>'
                         '<table><thead><tr><th>Player</th><th>Where</th>'
                         '<th class="num">Here for</th></tr></thead><tbody>'
                         + ''.join(rows) + '</tbody></table></div>')
        else:
            cards.append('<div class="card"><h2>In the lobby</h2>'
                         '<p class="sub" style="margin:0">Nobody is online at '
                         'the moment &mdash; the server is up and waiting.'
                         '</p></div>')

        if snap['playing']:
            rows = []
            now = time.time()
            for game in snap['playing']:
                course = (twstats.course_name(game['course'])
                          if game['course'] >= 0 else '')
                rows.append('<tr><td><strong>%s</strong> v <strong>%s</strong>'
                            '</td><td>%s</td><td>%s</td><td class="num">%s</td>'
                            '</tr>'
                            % (plink(game['host']),
                               plink(game['guest']),
                               html.escape(game['kind'] or ''),
                               html.escape(course) or '&mdash;',
                               _ago(now - game['started'])))
            cards.append('<div class="card"><h2>Matches in play</h2>'
                         '<table><thead><tr><th>Players</th><th>Type</th>'
                         '<th>Course</th><th class="num">Running</th></tr>'
                         '</thead><tbody>' + ''.join(rows)
                         + '</tbody></table></div>')

        return page('Live', ''.join(cards) + self.feed_card(),
                    refresh=LIVE_REFRESH, signed_in=bool(session))

    def feed_card(self, limit=25):
        """The last few things that happened, newest first."""
        try:
            rows = DB.activity(limit=limit)
        except Exception:                              # noqa: BLE001
            return ''
        if not rows:
            return ('<div class="card"><h2>Activity</h2><p class="sub" '
                    'style="margin:0">Nothing has happened yet.</p></div>')
        now = time.time()
        items = []
        for row in rows:
            when = _ago(now - row['at'])
            items.append('<li><time>%s</time><span class="k">%s</span>'
                         '<span>%s</span></li>'
                         % (when if when == 'just now' else when + ' ago',
                            html.escape(self.FEED_WORDS.get(row['kind'],
                                                            row['kind'])),
                            html.escape(row['text'])))
        return ('<div class="card"><h2>Activity</h2><ul class="feed">%s</ul>'
                '</div>' % ''.join(items))

    def live_json(self):
        """The same picture as data, for anyone who would rather poll it.

        Nothing in here that is not already drawn on the page -- names, rooms
        and counts.  No addresses and no account names.
        """
        snap = live_snapshot() or {'up': False, 'online': [], 'playing': [],
                                   'age': 0, 'started': None}
        out = {
            'up': bool(snap['up']),
            'checked_in': round(snap['age'], 1),
            'started': snap['started'],
            'online': [{'persona': p['persona'], 'state': p['state'],
                        'where': p['detail'], 'since': p['since']}
                       for p in snap['online']],
            'playing': [{'host': g['host'], 'guest': g['guest'],
                         'kind': g['kind'], 'course': g['course'],
                         'course_name': (twstats.course_name(g['course'])
                                         if g['course'] >= 0 else ''),
                         'started': g['started']}
                        for g in snap['playing']],
        }
        try:
            out['activity'] = [{'at': r['at'], 'kind': r['kind'],
                                'text': r['text']} for r in DB.activity(25)]
        except Exception:                              # noqa: BLE001
            out['activity'] = []
        return json.dumps(out, indent=1).encode('utf-8')

    def leaderboard(self, session):
        """Everyone who has finished a match, best first.

        Strokes per hole rather than total strokes: a Front 9 is nine holes and
        a full round is eighteen, so the totals are not comparable.
        """
        esc = lambda v: html.escape(str(v or ''), quote=True)       # noqa: E731
        rows = []
        for n, e in enumerate(DB.leaderboard(), 1):
            rows.append(
                '<tr><td class="rank%s">%d</td><td><strong>%s</strong></td>'
                '<td class="num">%d&ndash;%d&ndash;%d</td><td class="num">%.2f</td>'
                '<td class="num">%d</td><td class="num">%d</td>'
                '<td class="num">%d</td><td class="num">%d</td></tr>'
                % (' rank-1' if n == 1 else '', n, plink(e['name']),
                   e['won'], e['lost'], e['tied'], e['per_hole'],
                   e['birdies'], e['eagles'], e['aces'], e['longest']))
        table = ('<table><thead><tr><th>#</th><th>Golfer</th>'
                 '<th class="num">W&ndash;L&ndash;T</th>'
                 '<th class="num">Str/hole</th><th class="num">Birdies</th>'
                 '<th class="num">Eagles</th><th class="num">Aces</th>'
                 '<th class="num">Longest</th></tr></thead><tbody>'
                 + ''.join(rows) + '</tbody></table>') if rows else (
            '<p class="foot" style="margin:0">Nobody has finished a match yet.</p>')
        body = ('<h1>Leaderboard</h1><p class="sub">Head to head, ranked by '
                'matches won and then by strokes per hole &mdash; a Front 9 and '
                'a full round are not comparable any other way.</p>'
                '<div class="card scroll"><h2>Match and stroke play</h2>%s</div>'
                % table)
        return page('Leaderboard', body, signed_in=bool(session))

    def tourney_record(self, names):
        """This account's personas on the season money list, and their last
        round.  Only the personas that have actually entered something -- a
        table of zeroes says less than a sentence does."""
        esc = lambda v: html.escape(str(v or ''), quote=True)       # noqa: E731
        today = twtourney.today()
        mine = {r['name']: r for r in
                DB.tourney_standings(today - 365, today, twtourney.payout)
                if r['name'] in set(names)}
        if not mine:
            return ('<p class="sub" style="margin:0">No tournament rounds yet. '
                    "Pick ONLINE TOURNAMENTS on the console and play the day's "
                    'event &mdash; <a href="/tournaments">see the schedule</a>.</p>')
        rows = []
        for who in names:
            r = mine.get(who)
            if not r:
                continue
            last = DB.query('SELECT day FROM tourney WHERE persona = ?'
                            ' ORDER BY day DESC LIMIT 1', (who,))
            when = (twtourney.from_day(last[0]['day']).strftime('%d %b %Y')
                    if last else '&ndash;')
            rows.append('<tr><td><strong>%s</strong></td><td>%s</td><td>%d</td>'
                        '<td>%d</td><td>%s</td><td>%s</td></tr>'
                        % (esc(who), twtourney.money(r['earned']), r['rounds'],
                           r['wins'], _ordinal(r['best']), when))
        table = ('<table><tr><th>Persona</th><th>Earnings</th><th>Events</th>'
                 '<th>Wins</th><th>Best</th><th>Last played</th></tr>'
                 + ''.join(rows) + '</table>')

        # And the rounds themselves, which is where the event and the course
        # actually belong.
        played = []
        for who in names:
            for r in DB.tourney_rounds(who, 10):
                played.append((r['day'], who, r))
        played.sort(key=lambda t: -t[0])
        if played:
            lines = []
            for _day, who, r in played[:12]:
                lines.append(
                    '<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                    '<td>%d</td><td>%s</td><td>%s of %d</td></tr>'
                    % (twtourney.from_day(r['day']).strftime('%d %b %Y'),
                       esc(who),
                       esc(r['event']) if r['named']
                       else '<span class="sub">unrecorded</span>',
                       esc(twstats.course_name(r['course'])), r['strokes'],
                       twtourney.to_par(r['fields'], r['par']),
                       _ordinal(r['place']), r['entrants']))
            table += ('<h2>Rounds</h2><table><tr><th>Date</th><th>Persona</th>'
                      '<th>Event</th><th>Course</th><th>Score</th>'
                      '<th>To par</th><th>Finish</th></tr>'
                      + ''.join(lines) + '</table>')
        return table

    def tournaments(self, session):
        """The calendar, the money list and the recent winners.

        Everything here is read from the same tables the game reads, with the
        same payout function -- so a figure on this page and the figure on the
        console's WEEKLY MONEY LEADERS board cannot drift apart.
        """
        esc = lambda v: html.escape(str(v or ''), quote=True)       # noqa: E731
        today = twtourney.today()
        cards = []

        # --- today, and what is coming -------------------------------------
        rows = []
        for e in DB.events(today, 15):
            course = twstats.course_name(e['course'])
            when = twtourney.from_day(e['day'])
            # All four settings, always: in their own columns on a wide
            # screen, and as a line under the event's name on a phone.
            rows.append('<tr%s><td>%s</td><td><a class="pl" href="#pay-%d">'
                        '<strong>%s</strong></a>'
                        '<div class="show-sm">%s</div></td>'
                        '<td>%s</td>%s<td class="num">%s</td></tr>'
                        % (' class="me"' if e['day'] == today else '',
                           when.strftime('%a %d %b'), e['day'], esc(e['name']),
                           conditions_line(e.get('conditions')),
                           esc(course), conditions_cells(e.get('conditions')),
                           twtourney.money(e['purse'])))
            # The Tour-style split of this event's purse, top ten only --
            # the same `payout` the money list and the console use.
            rows.append('<tr class="payout" id="pay-%d"><td colspan="8">'
                        '<table><caption>%s prize money '
                        '<a href="#schedule">Close</a></caption>'
                        '<thead><tr><th>Place</th><th class="num">Share</th>'
                        '<th class="num">Prize</th></tr></thead><tbody>%s'
                        '</tbody></table></td></tr>'
                        % (e['day'], esc(e['name']), ''.join(
                            '<tr><td>%s</td><td class="num">%s%%</td>'
                            '<td class="num">%s</td></tr>'
                            % (_ordinal(n), ('%.2f' % (share * 100))
                               .rstrip('0').rstrip('.'),
                               twtourney.money(twtourney.payout(e['purse'], n)))
                            for n, share in enumerate(twtourney.PAYOUT, 1))))
        cards.append('<h2 id="schedule">Schedule</h2>' + (
            '<p class="foot" style="margin:-.4rem 0 .8rem">Click an event to '
            'see how its purse is paid out.</p>' if rows else '') + (
            '<table><thead><tr><th>Date</th><th>Event</th><th>Course</th>'
            '<th class="hide-sm">Tees</th><th class="hide-sm">Rough</th>'
            '<th class="hide-sm">Fairways</th><th class="hide-sm">Greens</th>'
            '<th class="num">Purse</th></tr></thead><tbody>'
            + ''.join(rows) + '</tbody></table>' if rows else
            '<p class="foot" style="margin:0">No events scheduled.</p>'))

        # --- the season money list -----------------------------------------
        season = DB.tourney_standings(today - 365, today, twtourney.payout)
        rows = []
        for n, r in enumerate(season, 1):
            rows.append('<tr><td class="rank%s">%d</td>'
                        '<td><strong>%s</strong></td><td class="num">%s</td>'
                        '<td class="num">%d</td><td class="num">%d</td>'
                        '<td class="num">%s</td></tr>'
                        % (' rank-1' if n == 1 else '', n, plink(r['name']),
                           twtourney.money(r['earned']), r['rounds'], r['wins'],
                           _ordinal(r['best']) if r['best'] else '&ndash;'))
        cards.append('<h2>Money list</h2>' + (
            '<table><thead><tr><th>#</th><th>Golfer</th>'
            '<th class="num">Earnings</th><th class="num">Events</th>'
            '<th class="num">Wins</th><th class="num">Best</th></tr></thead>'
            '<tbody>' + ''.join(rows) + '</tbody></table>' if rows else
            '<p class="foot" style="margin:0">Nobody has played an event yet.</p>'))

        # --- who won what --------------------------------------------------
        rows = []
        for r in DB.tourney_recent(20):
            e, w = r['event'], r['winner']
            # The name the ROUND recorded, not the one the calendar shows now:
            # the calendar is generated, and a round played before that column
            # existed would otherwise be labelled with whatever event that day
            # happens to be today.
            name = w.get('event') or ''
            rows.append('<tr><td>%s</td><td>%s</td><td>%s</td>'
                        '<td><strong>%s</strong></td><td class="num">%d</td>'
                        '<td class="num">%s</td></tr>'
                        % (twtourney.from_day(r['day']).strftime('%d %b %Y'),
                           esc(name) if name else '<span class="foot">unrecorded</span>',
                           esc(twstats.course_name(w['course'])), plink(w['name']),
                           w['strokes'],
                           _topar(twtourney.to_par(w['fields'], w['par']))))
        if rows:
            cards.append('<h2>Recent winners</h2><table><thead><tr><th>Date</th>'
                         '<th>Event</th><th>Course</th><th>Winner</th>'
                         '<th class="num">Score</th><th class="num">To par</th>'
                         '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table>')

        # Today's event leads this page as well as the front one.  It is the
        # single thing on the site that changes every day, and someone who
        # came straight here for the tournaments should not have to go back to
        # the home page to see what is on right now.
        body = ('<h1>Tournaments</h1><p class="sub">One event a day, the same '
                'course and conditions for everyone, scored on the server.</p>'
                '%s%s'
                % (self.today_card(),
                   ''.join('<div class="card">%s</div>' % c for c in cards)))
        return page('Tournaments', body, signed_in=bool(session))

    # -- players, stats, records and courses ---------------------------------
    # All of it comes from twrecords.rounds(): one list of every finished round,
    # head to head and tournament alike, with impossible numbers already
    # thrown out.  The in-game news is built from the same list, so the two can
    # never disagree about who holds a record.

    def not_found(self, title, text, session):
        return self.reply(page(title, '<div class="card"><h2>%s</h2>'
                                      '<p class="sub" style="margin:0">%s</p>'
                                      '</div>' % (html.escape(title), text),
                               signed_in=bool(session)), status=404)

    def player_page(self, name, session):
        rs = twrecords.rounds(DB)
        p = twrecords.player(rs, name)
        if p is None:
            known = DB.persona(name)
            if not known:
                return self.not_found('Golfer', 'Nobody here is called '
                                      '<strong>%s</strong>.' % html.escape(name),
                                      session)
            return self.reply(page(known['name'], (
                '<h1>%s</h1><div class="card"><p class="sub" style="margin:0">'
                'Has not finished a round yet.</p></div>'
                % html.escape(known['name'])), signed_in=bool(session)))
        name = p['name']
        online = any(o['persona'] == name for o in (live_snapshot() or {})
                     .get('online', []))
        best = p['best']
        figs = [_figure(p['rounds'], 'Rounds'),
                _figure('%d&ndash;%d&ndash;%d' % (p['won'], p['lost'], p['tied']),
                        'Match record'),
                _figure(p['tourney_wins'], 'Tournament wins')]
        if best:
            figs.append(_figure('%d <small>%s</small>' % (
                best['strokes'], twrecords.fmt_par(best['to_par'])), 'Best round'))
        if p['scoring'] is not None:
            figs.append(_figure('%.1f' % p['scoring'], 'Scoring average'))
        if p['longest']:
            figs.append(_figure('%d yd' % p['longest'], 'Longest drive'))

        # Where they stand on each stat table, if they qualify for it.
        standing = {}
        for cat, rows in twrecords.leaders(rs, top=10000):
            for n, (who, _v, _c) in enumerate(rows, 1):
                if who == name:
                    standing[cat[0]] = (n, len(rows))
        stat_rows = []
        for cat in twrecords.CATEGORIES:
            key, title, field, _better, how, _counted, note = cat
            value = p[field]
            if value is None or (field == 'eagles' and not value):
                continue
            rank = standing.get(key)
            stat_rows.append(
                '<tr><td>%s <span class="foot">%s</span></td>'
                '<td class="num">%s</td><td class="num foot">%s</td></tr>'
                % (html.escape(title), html.escape(note),
                   twrecords.fmt(value, how),
                   '%s of %d' % (_ordinal(rank[0]), rank[1]) if rank else ''))
        if p['aces']:
            stat_rows.append('<tr><td>Holes in one</td><td class="num">%d</td>'
                             '<td></td></tr>' % p['aces'])
        if p['longest_putt']:
            stat_rows.append('<tr><td>Longest putt holed</td>'
                             '<td class="num">%d ft</td><td></td></tr>'
                             % p['longest_putt'])

        h2h = ''.join(
            '<tr><td>%s</td><td class="num">%d</td><td class="num">%d&ndash;%d'
            '&ndash;%d</td><td class="num">%s</td></tr>'
            % (plink(e['opponent']), e['W'] + e['L'] + e['T'], e['W'], e['L'],
               e['T'], _date(e['last']))
            for e in p['head_to_head'])

        sub_bits = ['Playing since %s' % _date(p['first'])]
        if p['favourite']:
            course, n = p['favourite']
            sub_bits.append('most often at %s (%d)' % (clink(course), n))
        body = ('<h1>%s%s</h1><p class="sub">%s</p>'
                '<div class="card"><h2>Career</h2><div class="figures">%s</div>'
                '</div>'
                % (html.escape(name),
                   ' <span class="tag playing">online now</span>' if online else '',
                   ' &middot; '.join(sub_bits), ''.join(figs)))
        body += ('<div class="card"><h2>Tour stats</h2><table><thead><tr>'
                 '<th>Stat</th><th class="num">Value</th><th class="num">Rank'
                 '</th></tr></thead><tbody>%s</tbody></table><p class="foot" '
                 'style="margin:.8rem 0 0">Ranks count players with at least %d '
                 'rounds.  <a class="pl" href="/stats">All stat leaders</a></p>'
                 '</div>' % (''.join(stat_rows), twrecords.MIN_ROUNDS))
        if h2h:
            body += ('<div class="card"><h2>Head to head</h2><table><thead><tr>'
                     '<th>Opponent</th><th class="num">Played</th>'
                     '<th class="num">W&ndash;L&ndash;T</th>'
                     '<th class="num">Last played</th></tr></thead><tbody>%s'
                     '</tbody></table></div>' % h2h)
        body += ('<div class="card"><h2>Recent rounds</h2>%s</div>'
                 % _rounds_table(p['recent'], who=False))
        return self.reply(page(name, body, signed_in=bool(session)))

    def stats_page(self, session):
        rs = twrecords.rounds(DB)
        cards = []
        for cat, rows in twrecords.leaders(rs):
            _key, title, _field, _better, how, counted, note = cat
            if rows:
                table = ('<table><tbody>%s</tbody></table>' % ''.join(
                    '<tr><td class="rank%s">%d</td><td>%s</td>'
                    '<td class="num">%s</td><td class="num foot">%d rd%s</td>'
                    '</tr>' % (' rank-1' if n == 1 else '', n, plink(who),
                               twrecords.fmt(value, how), c,
                               '' if c == 1 else 's')
                    for n, (who, value, c) in enumerate(rows, 1)))
            elif counted:
                table = ('<p class="foot" style="margin:0">Nobody has played '
                         '%d rounds yet.</p>' % twrecords.MIN_ROUNDS)
            else:
                table = '<p class="foot" style="margin:0">None yet.</p>'
            cards.append('<div class="card"><h2>%s</h2><p class="foot" '
                         'style="margin:-.6rem 0 .6rem">%s</p>%s</div>'
                         % (html.escape(title), html.escape(note), table))
        body = ('<h1>Tour stats</h1><p class="sub">Every finished round on this '
                'server, head to head and tournament.  Averages need at least %d '
                'rounds to qualify; scoring counts 18-hole rounds only, and the '
                'rest are per 18 holes so a Front 9 counts for half.</p>'
                '<div class="statgrid">%s</div>'
                % (twrecords.MIN_ROUNDS, ''.join(cards)))
        return page('Stats', body, signed_in=bool(session))

    def records_page(self, session):
        rs = twrecords.rounds(DB)
        rec, aces = twrecords.records(rs)
        rows = ''.join(
            '<tr><td>%s</td><td><strong>%s</strong></td><td>%s</td><td>%s</td>'
            '<td class="num">%s</td></tr>'
            % (html.escape(title), html.escape(show), plink(r['persona']),
               clink(r['course']), _date(r['when']))
            for _key, title, r, show in rec if r)
        body = ('<h1>Records</h1><p class="sub">The best anyone has done on this '
                'server.  A tie goes to whoever did it first.</p>'
                '<div class="card"><h2>Server records</h2>%s</div>'
                % ('<table><thead><tr><th>Record</th><th></th><th>Golfer</th>'
                   '<th>Course</th><th class="num">Date</th></tr></thead>'
                   '<tbody>%s</tbody></table>' % rows if rows else
                   '<p class="foot" style="margin:0">No rounds finished yet.</p>'))
        course_rows = ''.join(
            '<tr><td>%s</td><td class="num">%s</td><td>%s</td>'
            '<td class="num">%s</td></tr>'
            % (clink(c['course']), _score(c['record']),
               plink(c['record']['persona']), _date(c['record']['when']))
            for c in sorted(twrecords.courses(rs), key=lambda c: c['name'])
            if c['record'])
        if course_rows:
            body += ('<div class="card"><h2>Course records</h2><table><thead>'
                     '<tr><th>Course</th><th class="num">Score</th>'
                     '<th>Golfer</th><th class="num">Date</th></tr></thead>'
                     '<tbody>%s</tbody></table></div>' % course_rows)
        if aces:
            body += ('<div class="card"><h2>Holes in one</h2><table><thead><tr>'
                     '<th>Golfer</th><th>Course</th><th>Round</th>'
                     '<th class="num">Date</th></tr></thead><tbody>%s</tbody>'
                     '</table></div>' % ''.join(
                         '<tr><td>%s</td><td>%s</td><td>%s</td>'
                         '<td class="num">%s</td></tr>'
                         % (plink(r['persona']), clink(r['course']), _kind(r),
                            _date(r['when']))
                         for r in reversed(aces)))
        return page('Records', body, signed_in=bool(session))

    def courses_page(self, session):
        rs = twrecords.rounds(DB)
        cs = twrecords.courses(rs)
        rows = ''.join(
            '<tr><td>%s</td><td class="num">%s</td><td class="num">%d</td>'
            '<td class="num hide-sm">%d</td><td class="num hide-sm">%s</td>'
            '<td class="num">%s</td><td>%s</td></tr>'
            % (clink(c['course']), c['par'] or '&ndash;', c['rounds'],
               c['players'], twrecords.fmt(c['scoring'], '%.1f'),
               _topar(twrecords.fmt(c['to_par'], 'par'))
               if c['to_par'] is not None else '&ndash;',
               '%s by %s' % (_score(c['record']), plink(c['record']['persona']))
               if c['record'] else '')
            for c in cs)
        body = ('<h1>Courses</h1><p class="sub">Every course that has been '
                'played here, hardest first by average score against par.  '
                'Par is learnt from the scorecards themselves.</p>'
                '<div class="card scroll">%s</div>'
                % ('<table><thead><tr><th>Course</th><th class="num">Par</th>'
                   '<th class="num">Rounds</th><th class="num hide-sm">Golfers'
                   '</th><th class="num hide-sm">Average</th>'
                   '<th class="num">To par</th>'
                   '<th>Course record</th></tr></thead><tbody>%s</tbody></table>'
                   % rows if rows else
                   '<p class="foot" style="margin:0">No rounds finished yet.</p>'))
        return page('Courses', body, signed_in=bool(session))

    def course_page(self, index, session):
        try:
            index = int(index)
        except ValueError:
            return self.not_found('Course', 'There is no such course.', session)
        rs = twrecords.rounds(DB)
        c = twrecords.course(rs, index)
        if c is None:
            if 0 <= index < len(twstats.COURSES):
                return self.reply(page(twrecords.course_name(index), (
                    '<h1>%s</h1><div class="card"><p class="sub" '
                    'style="margin:0">Nobody has finished a round here yet.</p>'
                    '</div>' % html.escape(twrecords.course_name(index))),
                    signed_in=bool(session)))
            return self.not_found('Course', 'There is no such course.', session)
        figs = [_figure(c['par'] or '&ndash;', 'Par'),
                _figure(c['rounds'], 'Rounds'),
                _figure(c['players'], 'Golfers')]
        if c['scoring'] is not None:
            figs.append(_figure('%.1f' % c['scoring'], 'Scoring average'))
        if c['to_par'] is not None:
            figs.append(_figure(_topar(twrecords.fmt(c['to_par'], 'par')),
                                'Average to par'))
        if c['gir_pct'] is not None:
            figs.append(_figure('%.0f%%' % c['gir_pct'], 'Greens hit'))
        if c['putts18'] is not None:
            figs.append(_figure('%.1f' % c['putts18'], 'Putts per 18'))
        if c['birdies18'] is not None:
            figs.append(_figure('%.1f' % c['birdies18'], 'Birdies per 18'))
        rec = c['best']
        body = ('<h1>%s</h1><p class="sub">%s</p><div class="card"><h2>The course'
                '</h2><div class="figures">%s</div></div>'
                % (html.escape(c['name']),
                   'Course record <strong>%s</strong> by %s, %s'
                   % (_score(rec), plink(rec['persona']), _date(rec['when']))
                   if rec else 'No full round yet, so no course record.',
                   ''.join(figs)))
        if c['top']:
            body += ('<div class="card"><h2>Best rounds</h2><table><thead><tr>'
                     '<th>#</th><th>Golfer</th><th class="num">Score</th>'
                     '<th>Round</th><th class="num">Date</th></tr></thead>'
                     '<tbody>%s</tbody></table></div>' % ''.join(
                         '<tr><td class="rank%s">%d</td><td>%s</td>'
                         '<td class="num">%s</td><td>%s</td>'
                         '<td class="num">%s</td></tr>'
                         % (' rank-1' if n == 1 else '', n, plink(r['persona']),
                            _score(r), _kind(r), _date(r['when']))
                         for n, r in enumerate(c['top'], 1)))
        body += ('<div class="card"><h2>Recent rounds</h2>%s</div>'
                 % _rounds_table(c['recent'], course=False))
        return self.reply(page(c['name'], body, signed_in=bool(session)))

    # -- the operator's abuse reports ---------------------------------------
    @staticmethod
    def reports_allowed(key):
        return bool(REPORTS_KEY) and secrets.compare_digest(
            key.encode('utf-8'), REPORTS_KEY.encode('utf-8'))

    def do_report_handled(self, key, fields):
        try:
            rid = int(fields.get('id', ''))
        except ValueError:
            return self.redirect(u('/reports/%s' % key))
        reopen = fields.get('action') == 'reopen'
        DB.set_report_handled(rid, not reopen)
        return self.redirect(u('/reports/%s?m=%s' % (key, urllib.parse.quote(
            'report #%d %s' % (rid, 'reopened' if reopen else 'marked handled')))))

    def reports_page(self, note=None):
        """Every REPORT ABUSE from the game, with the chat attached to it.

        Open reports in full; handled ones as a short list underneath, in
        case one needs reopening.  Acting on a report is done from the shell
        (`twdb.py --disable ACCOUNT`) -- this page only reads and files.
        """
        # Bare path: page() puts the mount point on every action= itself.
        action = '/reports/%s/handle' % REPORTS_KEY
        open_ = DB.reports(handled=False)
        done = DB.reports(handled=True, limit=30)

        def when(t):
            return time.strftime('%d %b %H:%M', time.localtime(t))

        def who(r):
            if not r['account']:
                return ('<strong>%s</strong> <span class="tag bad">no such '
                        'persona now</span>' % html.escape(r['accused']))
            flag = ('<span class="tag bad">disabled</span>'
                    if r['disabled'] else '')
            return ('<strong>%s</strong> (account %s) %s'
                    % (html.escape(r['accused']), html.escape(r['account']),
                       flag))

        cards = ['<div class="card"><h2>Abuse reports</h2>'
                 '<h1 style="margin:0">%d open</h1>'
                 '<p class="sub" style="margin:.4rem 0 0">Filed with REPORT '
                 'ABUSE in the game. The chat is what this server relayed in '
                 'the hour before: what the reported player said in rooms, and '
                 'private or EA Messenger lines between the two. To act on one, '
                 'on the server: <code>python3 twdb.py --disable ACCOUNT</code>.'
                 ' This page is not linked from anywhere &mdash; keep its '
                 'address to yourself.</p></div>' % len(open_)]

        for r in open_:
            lines = ''.join(
                '<li><time>%s</time><span class="tag">%s</span>'
                '<span class="who">%s%s</span><span class="said">%s</span></li>'
                % (time.strftime('%H:%M:%S', time.localtime(c.get('at', 0))),
                   html.escape(c.get('via', '')),
                   html.escape(c.get('from', '')),
                   (' &rarr; %s' % html.escape(c['to'])) if c.get('to') else '',
                   html.escape(c.get('text', '')))
                for c in r['chat'])
            chat = ('<ul class="chat">%s</ul>' % lines if lines else
                    '<p class="sub" style="margin:.8rem 0 0">No chat from them '
                    'was relayed in the hour before this report.</p>')
            cards.append(
                '<div class="card"><h2>#%d &middot; %s</h2>'
                '<p style="margin:0">%s reported by <strong>%s</strong>%s'
                ' &middot; %d report%s name them</p>%s'
                '<form method="post" action="%s" class="inline">'
                '<input type="hidden" name="id" value="%d">'
                '<button type="submit" style="margin-top:1rem">Mark handled'
                '</button></form></div>'
                % (r['id'], when(r['at']), who(r), html.escape(r['reporter']),
                   (' in %s' % html.escape(r['room'])) if r['room'] else '',
                   r['against'], '' if r['against'] == 1 else 's', chat,
                   action, r['id']))

        if done:
            rows = ''.join(
                '<tr><td>#%d</td><td>%s</td><td>%s &rarr; <strong>%s</strong>'
                '</td><td class="num">%d</td><td><form method="post" '
                'action="%s" class="inline"><input type="hidden" name="id" '
                'value="%d"><input type="hidden" name="action" value="reopen">'
                '<button class="quiet" type="submit">reopen</button></form>'
                '</td></tr>'
                % (r['id'], when(r['at']), html.escape(r['reporter']),
                   html.escape(r['accused']), len(r['chat']), action, r['id'])
                for r in done)
            cards.append('<div class="card"><h2>Handled</h2><table><thead><tr>'
                         '<th></th><th>Filed</th><th>Report</th>'
                         '<th class="num">Chat lines</th><th></th></tr></thead>'
                         '<tbody>%s</tbody></table></div>' % rows)
        return page('Reports', ''.join(cards), message=note, kind='ok',
                    stats=False)

    def profile(self, session, note=None, kind='err'):
        account = DB.one('SELECT * FROM accounts WHERE id = ?',
                         (session['account'],))
        personas = DB.personas(account['id'])
        csrf = html.escape(session['csrf'], quote=True)
        esc = lambda v: html.escape(str(v or ''), quote=True)       # noqa: E731

        chips = []
        for name in personas:
            played, won, lost, tied = DB.record(name)
            drop = ('<form class="inline" method="post" action="/persona/drop">'
                    '<input type="hidden" name="csrf" value="%s">'
                    '<input type="hidden" name="persona" value="%s">'
                    '<button class="quiet" type="submit">remove</button></form>'
                    % (csrf, esc(name))) if len(personas) > 1 else ''
            chips.append('<tr><td><strong>%s</strong> <a class="pl" '
                         'href="/player/%s" style="font-size:.8rem">'
                         'public page</a></td><td>%d played</td>'
                         '<td>%d&ndash;%d&ndash;%d</td>'
                         '<td style="text-align:right">%s</td></tr>'
                         % (esc(name), urllib.parse.quote(name, safe=''),
                            played, won, lost, tied, drop))

        rows = []
        for name in personas:
            for m in DB.matches(name, 10):
                mine = next(p for p in m['players'] if p['name'] == name)
                them = next(p for p in m['players'] if p['name'] != name)
                verdict = ('tie' if m['winner'] is None else
                           'won' if m['winner'] == name else 'lost')
                setup = m.get('setup') or {}
                course = twstats.course_name(setup.get('COUR'))
                mode = ('Match' if m['room'].startswith('Match')
                        else 'Stroke' if m['room'].startswith('Stroke') else '')
                extra = []
                if setup.get('SHOT'):
                    extra.append('%s s clock' % esc(setup['SHOT']))
                # CFLG is one-hot per setting; four of its five groups are
                # named.  The fifth is not a condition -- it moves on its own --
                # so it is left out rather than shown as a number nobody can
                # read.  MFLG is still unknown and stays raw.
                for label, index in sorted(twstats.conditions(
                        setup.get('CFLG')).items()):
                    extra.append('%s %d' % (esc(label), index))
                if setup.get('MFLG'):
                    extra.append('MFLG=%s' % esc(setup['MFLG']))
                rows.append(
                    '<tr><td>%s</td><td>%s</td><td>%s</td><td>%d&ndash;%d</td>'
                    '<td>%s</td><td>%s</td><td>%d</td><td>%s</td></tr>'
                    % (esc(name), plink(them['name']), verdict,
                       mine['strokes'], them['strokes'],
                       esc(course) or '&mdash;', mode, mine['holes'],
                       time.strftime('%Y-%m-%d %H:%M',
                                     time.localtime(m['received']))))
                if extra:
                    rows.append('<tr><td></td><td colspan="7" class="sub" '
                                'style="margin:0;font-size:.8rem">%s</td></tr>'
                                % ' &middot; '.join(extra))
        history = ('<table><tr><th>Persona</th><th>Opponent</th><th></th>'
                   '<th>Strokes</th><th>Course</th><th>Mode</th><th>Holes</th>'
                   '<th>Played</th></tr>'
                   + ''.join(rows) + '</table>') if rows else (
            '<p class="sub" style="margin:0">No matches reported yet.</p>')

        add = ''
        if len(personas) < twdb.MAX_PERSONAS:
            add = """
<form method="post" action="/persona/add">
  <input type="hidden" name="csrf" value="%s">
  <label>Add a persona (%d of %d used)</label>
  <input type="text" name="persona" maxlength="%d" required>
  <button type="submit">Add persona</button>
</form>""" % (csrf, len(personas), twdb.MAX_PERSONAS, twdb.MAX_NAME)
        else:
            add = ('<p class="sub" style="margin:.5rem 0 0">All %d slots are in '
                   'use &mdash; the game only reads four from the login reply.</p>'
                   % twdb.MAX_PERSONAS)

        born = esc(account['born'])
        born_value = ('%s-%s-%s' % (born[:4], born[4:6], born[6:8])
                      if len(born) == 8 and born.isdigit() else '')
        body = """
<h1>%s</h1>
<p class="sub">Signed in &mdash; <a href="/leaderboard">leaderboard</a>
 &middot; <a href="/tournaments">tournaments</a>
 &middot; <a href="/logout">sign out</a></p>

<div class="card">
<h2>Personas</h2>
<table>%s</table>
%s
</div>

<div class="card">
<h2>Profile</h2>
<form method="post" action="/profile">
  <input type="hidden" name="csrf" value="%s">
  <div class="row">
    <div><label>Email</label><input type="email" name="mail" value="%s"></div>
    <div><label>Gender</label><select name="gend">
      <option value="M"%s>Male</option><option value="F"%s>Female</option>
    </select></div>
    <div><label>Date of birth</label>
      <input type="text" name="born" placeholder="YYYY-MM-DD" value="%s"></div>
  </div>
  <label><input type="checkbox" name="spam" %s style="width:auto"> Happy to
    receive news</label>
  <button type="submit">Save profile</button>
</form>
</div>

<div class="card">
<h2>Password</h2>
<form method="post" action="/password">
  <input type="hidden" name="csrf" value="%s">
  <div class="row">
    <div><label>Current password</label>
      <input type="password" name="current" required></div>
    <div><label>New password</label>
      <input type="password" name="password" required></div>
    <div><label>Repeat new password</label>
      <input type="password" name="password2" required></div>
  </div>
  <button type="submit">Change password</button>
</form>
</div>

<div class="card">
<h2>Tournaments</h2>
%s
</div>

<div class="card">
<h2>Recent matches</h2>
%s
</div>
""" % (esc(account['name']), ''.join(chips), add, csrf, esc(account['mail']),
       ' selected' if account['gend'] != 'F' else '',
       ' selected' if account['gend'] == 'F' else '',
       born_value, 'checked' if account['spam'] else '', csrf,
       self.tourney_record(personas), history)
        return page(esc(account['name']), body, note, kind, signed_in=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main(argv=None):
    global DB, BASE, TRUST_PROXY, SECURE_COOKIE, ADVERTISE, LOBBY_PORT
    global REPORTS_KEY, LOG
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db', default=twdb.DEFAULT_DB)
    ap.add_argument('--host', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=8080)
    ap.add_argument('--base-path', default='',
                    help='mount the site under a path, e.g. /TW04Online, when '
                         'it sits behind a reverse proxy that is not giving it '
                         'a hostname of its own')
    ap.add_argument('--no-secure-cookie', dest='secure_cookie',
                    action='store_false',
                    help='do not mark the session cookie Secure.  Only for '
                         'testing over plain HTTP; it is on by default because '
                         'anything public should be behind TLS')
    ap.add_argument('--advertise', default='',
                    help='the address players should point their game at, as a '
                         'name or an IPv4 address.  Only needed when the lobby '
                         'is not on the same host as this site, or when this '
                         'host cannot resolve its own public name -- otherwise '
                         'the address the request arrived at is used')
    ap.add_argument('--lobby-port', type=int, default=10200,
                    help='the port to put in the downloadable patch when '
                         'lobbyd has not published one (default 10200)')
    ap.add_argument('--trust-proxy', action='store_true',
                    help='take the client address from X-Forwarded-For.  Only '
                         'with a reverse proxy in front: the header is forged '
                         'trivially, and the login throttle depends on it')
    ap.add_argument('--reports-key', default='',
                    help='the secret in the abuse-reports page address, '
                         '/reports/<key>.  Default: made once and kept in '
                         'reports.key beside the database.  "off" disables '
                         'the page')
    ap.add_argument('--logfile', default=DEFAULT_LOG,
                    help='the request log (default logs/webui.log beside '
                         'data/).  Empty for none')
    ap.add_argument('--log-max-mb', type=float, default=twlog.DEFAULT_MAX_MB,
                    help='roll the log over at this size (default %d MB)'
                         % twlog.DEFAULT_MAX_MB)
    ap.add_argument('--log-keep', type=int, default=twlog.DEFAULT_KEEP,
                    help='rolled-over copies to keep (default %d)'
                         % twlog.DEFAULT_KEEP)
    ap.add_argument('--quiet', action='store_true',
                    help='log requests to the file only, not the console too')
    args = ap.parse_args(argv)

    LOG = twlog.Log(args.logfile, max_bytes=args.log_max_mb * (1 << 20),
                    keep=args.log_keep, echo=not args.quiet)
    say = LOG.write         # startup lines go to the log as well

    BASE = '/' + args.base_path.strip('/') if args.base_path.strip('/') else ''
    TRUST_PROXY = args.trust_proxy
    SECURE_COOKIE = args.secure_cookie
    ADVERTISE = args.advertise
    LOBBY_PORT = args.lobby_port
    DB = twdb.DB(args.db)
    say('database %s -- %d accounts' % (DB.path, DB.count_accounts()))
    if args.reports_key != 'off':
        REPORTS_KEY = reports_key(DB.path, args.reports_key)
        say('abuse reports (%d open) -- private, do not share this address:'
              % DB.count_open_reports())
        say('    %s/reports/%s' % (BASE, REPORTS_KEY))
    say('lobbyd must be given this SAME path; it prints the one it opened.')
    say('sign-up site on http://%s:%d%s/'
          % ('localhost' if args.host in ('0.0.0.0', '') else args.host,
             args.port, BASE))
    if BASE and not TRUST_PROXY:
        say('!! mounted under %s but --trust-proxy is off, so every request'
              % BASE)
        say('   looks like it came from the proxy and the login throttle is')
        say('   one shared bucket shared by everybody')
    if make_pnach is None:
        say('!! make_pnach.py is not beside webui.py (%s), so the patch'
              % MAKE_PNACH_WHY)
        say('   download is switched off.  The rest of the site is fine.')
    ip, lport = lobby_endpoint(ADVERTISE)
    if ip:
        say('the downloadable patch will point the game at %s:%d' % (ip, lport))
    else:
        say('!! cannot resolve this host\'s own address, so the patch')
        say('   download is disabled -- pass --advertise <host-or-ip>')
    say('(plain HTTP -- put it behind a reverse proxy with TLS before it faces '
          'the internet)')
    with Server((args.host, args.port), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            say('stopped')
    return 0


if __name__ == '__main__':
    sys.exit(main())
