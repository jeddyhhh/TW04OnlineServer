"""Every round anyone has played, and what can be said about them.

    python tools/twrecords.py            # self-test

Head-to-head matches (`results`, resolved through `twdb.matches`) and
tournament rounds (`tourney`) are recorded in different shapes by different
code paths.  `rounds()` folds both into one list of plain dicts, one per player
per round, and everything else here -- a player's page, the stat leaders, the
records, the course pages, the in-game news -- is a function of that list.  One
list, so the web site and the news screen cannot disagree about who holds a
record.

WHAT COUNTS

Only rounds a player finished: `DONE` set, `QUIT` clear, some holes played.
Scoring figures (averages, low rounds, course records) use 18-hole rounds only
-- a Front 9 is not comparable with a full round.  Per-hole figures (greens,
fairways, putts, birdies) use every finished hole, scaled to 18.

WHAT IS NOT BELIEVED

The console reports what it reports.  One real tournament card came in with
`PUTTS=1025` for eighteen holes, so every number is range-checked and anything
impossible becomes None -- left out of averages and records, never shown as a
record.  `clean()` holds the limits.
"""
import collections
import json
import textwrap
import time

import twstats
import twtourney

MIN_ROUNDS = 3              # before an average goes on a leaderboard
WEEK = 7 * 24 * 3600
NEWS_WIDTH = 60             # the news screen wraps at 64 (0x00272ED0)
NEWS_RECORDS = ('low', 'drive', 'putt')     # which records make the news
NEWS_MAX_RECORDS = 6


# ---------------------------------------------------------------------------
# rounds

def _int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def clean(r):
    """Replace anything impossible with None, in place.  Returns `r`."""
    holes = r['holes']

    def within(key, low, high):
        v = r.get(key)
        if v is not None and not (low <= v <= high):
            r[key] = None

    within('strokes', holes, holes * 12)
    within('putts', 1, holes * 6)          # 0 is "not reported", not a record
    within('gir', 0, holes)
    within('drives', 0, holes)
    if r['drives'] is None or r.get('fairways') is not None and \
            r['fairways'] > r['drives']:
        r['fairways'] = None
    within('longest', 1, 450)              # yards
    within('longest_putt', 1, 150)         # feet
    for key in ('eagles', 'birdies', 'aces', 'pars', 'bogeys', 'doubles',
                'triples'):
        within(key, 0, holes)
    return r


def _from_fields(f, suffix=''):
    g = lambda k: _int(f.get(k + suffix))                  # noqa: E731
    return {'holes': g('HOLES'), 'strokes': g('STROKES'), 'putts': g('PUTTS'),
            'gir': g('GIR'), 'fairways': g('FRWY'), 'drives': g('DRVS'),
            'longest': g('LDRV'), 'longest_putt': g('LPUT'),
            'eagles': g('EAGS'), 'birdies': g('BIRD'), 'aces': g('ACES'),
            'pars': g('PARS'), 'bogeys': g('SBOG'), 'doubles': g('DBOG'),
            'triples': g('TBOG'), 'done': g('DONE'), 'quit': g('QUIT')}


def _card(r):
    """A round back in the scorecard shape twtourney's par code reads."""
    return {'HOLES': r['holes'], 'STROKES': r['strokes'] or 0,
            'ACES': r['aces'] or 0, 'EAGS': r['eagles'] or 0,
            'BIRD': r['birdies'] or 0, 'PARS': r['pars'] or 0,
            'SBOG': r['bogeys'] or 0, 'DBOG': r['doubles'] or 0,
            'TBOG': r['triples'] or 0}


def rounds(db):
    """Every finished round, oldest first, each a dict with `persona`, `kind`
    ('match', 'stroke' or 'tourney'), `when`, `course`, the stat fields,
    `par` and `to_par` (18-hole rounds only), and for head-to-head rounds
    `opponent` and `result` ('W', 'L' or 'T')."""
    out = []
    for m in db.matches(limit=100000):
        setup = m.get('setup') or {}
        course = _int(setup['COUR']) if str(setup.get('COUR', '')).isdigit() \
            else None
        kind = 'match' if (m['room'] or '').startswith('Match') else 'stroke'
        names = [p['name'] for p in m['players']]
        for p in m['players']:
            r = {'persona': p['name'], 'kind': kind,
                 'when': m['received'] or m['when'] or 0, 'day': None,
                 'course': course, 'event': '', 'auth': m['auth'],
                 'holes': p['holes'], 'strokes': p['strokes'],
                 'putts': p['putts'], 'gir': p['gir'],
                 'fairways': p['fairways'], 'drives': p['drives'],
                 'longest': p['longest'], 'longest_putt': p['longest_putt'],
                 'eagles': p['eagles'], 'birdies': p['birdies'],
                 'aces': p['aces'], 'pars': p['pars'], 'bogeys': p['bogeys'],
                 'doubles': p.get('doubles', 0), 'triples': p.get('triples', 0),
                 'done': p['done'], 'quit': p['quit']}
            other = [n for n in names if n != p['name']]
            r['opponent'] = other[0] if other else ''
            r['result'] = ('T' if m['winner'] is None else
                           'W' if m['winner'] == p['name'] else 'L')
            out.append(r)
    for row in db.query('SELECT persona, day, course, event, fields, received'
                        ' FROM tourney'):
        try:
            f = json.loads(row['fields'])
        except ValueError:
            continue
        r = _from_fields(f)
        r.update({'persona': row['persona'], 'kind': 'tourney',
                  'when': row['received'] or 0, 'day': row['day'],
                  'course': row['course'], 'event': row['event'] or '',
                  'auth': '', 'opponent': '', 'result': None})
        if not r['event']:
            listed = db.event(row['day'])
            r['event'] = listed['name'] if listed else ''
        out.append(r)

    done = [clean(r) for r in out
            if r['done'] and not r['quit'] and r['holes'] > 0]

    # Par per course: what the database has learnt, tightened by any 18-hole
    # card here that bounds it lower.  Every bound errs high, so the minimum
    # is the best estimate (twtourney.card_par).
    pars = dict(db.course_pars())
    for r in done:
        if r['course'] is not None and r['holes'] == 18 and r['strokes']:
            bound = twtourney.card_par(_card(r))
            if bound:
                pars[r['course']] = min(pars.get(r['course'], bound), bound)
    for r in done:
        full = r['holes'] == 18 and r['strokes'] is not None
        r['par'] = (pars.get(r['course'], twtourney.DEFAULT_PAR)
                    if full else None)
        r['to_par'] = r['strokes'] - r['par'] if full else None

    # A tournament round's finishing place in its day's field, ordered as the
    # tournament board orders it: strokes, then whoever reported first.
    days = collections.defaultdict(list)
    for r in done:
        r['place'] = r['field'] = None
        if r['kind'] == 'tourney' and r['strokes'] is not None:
            days[r['day']].append(r)
    for field in days.values():
        field.sort(key=lambda r: (r['strokes'], r['when']))
        for n, r in enumerate(field, 1):
            r['place'], r['field'] = n, len(field)

    done.sort(key=lambda r: r['when'])
    return done


def course_name(course):
    return twstats.course_name(course) if course is not None else 'Unknown course'


def fmt_par(n):
    if n is None:
        return ''
    return 'E' if n == 0 else '%+d' % n


# ---------------------------------------------------------------------------
# aggregates

def _agg(rs):
    """Totals and rates over a list of rounds.  Rates are None when there is
    nothing to rate."""
    full = [r for r in rs if r['holes'] == 18 and r['strokes'] is not None]
    holes = sum(r['holes'] for r in rs)

    def per18(key):
        good = [r for r in rs if r.get(key) is not None]
        h = sum(r['holes'] for r in good)
        return sum(r[key] for r in good) * 18.0 / h if h else None

    def pct(num, den):
        good = [r for r in rs if r.get(num) is not None
                and r.get(den if den != 'holes' else num) is not None]
        d = sum(r[den] for r in good)
        return 100.0 * sum(r[num] for r in good) / d if d else None

    drives = [r['longest'] for r in rs if r['longest'] is not None]
    return {
        'rounds': len(rs), 'full': len(full), 'holes': holes,
        'scoring': (sum(r['strokes'] for r in full) / float(len(full))
                    if full else None),
        'to_par': (sum(r['to_par'] for r in full) / float(len(full))
                   if full else None),
        'putts18': per18('putts'),
        'birdies18': per18('birdies'),
        'gir_pct': pct('gir', 'holes'),
        'fir_pct': pct('fairways', 'drives'),
        'drive_avg': sum(drives) / float(len(drives)) if drives else None,
        'longest': max(drives) if drives else None,
        'longest_putt': max([r['longest_putt'] for r in rs
                             if r['longest_putt'] is not None] or [None],
                            key=lambda v: -1 if v is None else v),
        'eagles': sum(r['eagles'] or 0 for r in rs),
        'birdies': sum(r['birdies'] or 0 for r in rs),
        'aces': sum(r['aces'] or 0 for r in rs),
        'best': min(full, key=lambda r: (r['strokes'], r['when'])) if full else None,
        'best_par': min(full, key=lambda r: (r['to_par'], r['when'])) if full else None,
    }


def tourney_wins(rs):
    """{persona: [winning round, ...]}.  A day's winner is its lowest round;
    a tie goes to whoever reported first, as on the tournament board."""
    days = collections.defaultdict(list)
    for r in rs:
        if r['kind'] == 'tourney' and r['strokes'] is not None:
            days[r['day']].append(r)
    wins = collections.defaultdict(list)
    for day, field in days.items():
        best = min(field, key=lambda r: (r['strokes'], r['when']))
        wins[best['persona']].append(best)
    return wins


def player(rs, name):
    """Everything the player page shows, or None if they have no rounds."""
    mine = [r for r in rs if r['persona'].lower() == name.lower()]
    if not mine:
        return None
    name = mine[0]['persona']
    a = _agg(mine)
    h2h = {}
    for r in mine:
        if r['result'] is None:
            continue
        e = h2h.setdefault(r['opponent'], {'opponent': r['opponent'],
                                           'W': 0, 'L': 0, 'T': 0,
                                           'last': 0})
        e[r['result']] += 1
        e['last'] = max(e['last'], r['when'])
    courses = collections.Counter(r['course'] for r in mine
                                  if r['course'] is not None)
    a.update({
        'name': name,
        'won': sum(1 for r in mine if r['result'] == 'W'),
        'lost': sum(1 for r in mine if r['result'] == 'L'),
        'tied': sum(1 for r in mine if r['result'] == 'T'),
        'tourney_rounds': sum(1 for r in mine if r['kind'] == 'tourney'),
        'tourney_wins': len(tourney_wins(rs).get(name, [])),
        'favourite': courses.most_common(1)[0] if courses else None,
        'head_to_head': sorted(h2h.values(),
                               key=lambda e: (-(e['W'] + e['L'] + e['T']),
                                              e['opponent'].lower())),
        'recent': list(reversed(mine))[:10],
        'first': mine[0]['when'], 'latest': mine[-1]['when'],
    })
    return a


# name, heading, the aggregate key, 'low' or 'high' is better, format, minimum
# rounds (counted as 18-hole rounds for scoring, any finished round otherwise),
# and a short note on how it is worked out.
CATEGORIES = [
    ('to_par', 'Scoring (to par)', 'to_par', 'low', 'par', 'full',
     'average score against the course\'s par, 18-hole rounds'),
    ('scoring', 'Scoring average', 'scoring', 'low', '%.1f', 'full',
     'strokes per 18-hole round'),
    ('drive_avg', 'Driving distance', 'drive_avg', 'high', '%.0f yd', 'rounds',
     'average of each round\'s longest drive'),
    ('fir_pct', 'Driving accuracy', 'fir_pct', 'high', '%.1f%%', 'rounds',
     'fairways hit from the tee'),
    ('gir_pct', 'Greens in regulation', 'gir_pct', 'high', '%.1f%%', 'rounds',
     'greens reached in par minus two'),
    ('putts18', 'Putting', 'putts18', 'low', '%.1f', 'rounds',
     'putts per 18 holes'),
    ('birdies18', 'Birdies', 'birdies18', 'high', '%.2f', 'rounds',
     'birdies per 18 holes'),
    ('eagles', 'Eagles', 'eagles', 'high', '%d', None, 'total, any round'),
    ('rounds', 'Rounds played', 'rounds', 'high', '%d', None,
     'finished rounds, head to head and tournament'),
]


def fmt(value, how):
    if value is None:
        return '&ndash;'
    if how == 'par':
        return fmt_par(int(round(value))) if abs(value - round(value)) < .05 \
            else '%+.1f' % value
    return how % value


def leaders(rs, top=10, min_rounds=MIN_ROUNDS):
    """[(category, [(persona, value, rounds counted), ...]), ...]."""
    by = collections.defaultdict(list)
    for r in rs:
        by[r['persona']].append(r)
    aggs = {name: _agg(mine) for name, mine in by.items()}
    out = []
    for cat in CATEGORIES:
        key, _title, field, better, _fmt, counted, _note = cat
        rows = []
        for name, a in aggs.items():
            if a[field] is None:
                continue
            n = a[counted] if counted else a['rounds']
            if counted and n < min_rounds:
                continue
            if field in ('eagles',) and not a[field]:
                continue
            rows.append((name, a[field], n))
        rows.sort(key=lambda t: ((t[1] if better == 'low' else -t[1]),
                                 -t[2], t[0].lower()))
        out.append((cat, rows[:top]))
    return out


# name, heading, how to pick the holder from the eligible rounds, eligibility,
# how to show it.
def records(rs):
    """[(key, title, round or None, display), ...] plus the list of aces."""
    full = [r for r in rs if r['holes'] == 18 and r['strokes'] is not None]

    def best(pool, key, low=True):
        pool = [r for r in pool if r.get(key) is not None
                and (r[key] > 0 or low)]
        if not pool:
            return None
        return min(pool, key=lambda r: ((r[key] if low else -r[key]),
                                        r['when']))

    rec = []

    def add(key, title, r, show):
        rec.append((key, title, r, show(r) if r else ''))

    add('low', 'Lowest round', best(full, 'strokes'),
        lambda r: '%d (%s)' % (r['strokes'], fmt_par(r['to_par'])))
    add('par', 'Lowest to par', best(full, 'to_par'),
        lambda r: '%s (%d)' % (fmt_par(r['to_par']), r['strokes']))
    add('drive', 'Longest drive', best(rs, 'longest', low=False),
        lambda r: '%d yd' % r['longest'])
    add('putt', 'Longest putt holed', best(rs, 'longest_putt', low=False),
        lambda r: '%d ft' % r['longest_putt'])
    add('birdies', 'Most birdies in a round', best(full, 'birdies', low=False),
        lambda r: '%d' % r['birdies'])
    add('eagles', 'Most eagles in a round', best(full, 'eagles', low=False),
        lambda r: '%d' % r['eagles'])
    add('putts', 'Fewest putts in a round', best(full, 'putts'),
        lambda r: '%d' % r['putts'])
    add('gir', 'Most greens in regulation', best(full, 'gir', low=False),
        lambda r: '%d of 18' % r['gir'])
    aces = [r for r in rs if r['aces']]
    return rec, aces


def courses(rs):
    """One row per course played, hardest first (highest average to par)."""
    by = collections.defaultdict(list)
    for r in rs:
        if r['course'] is not None:
            by[r['course']].append(r)
    out = []
    for course, mine in by.items():
        a = _agg(mine)
        full = [r for r in mine if r['holes'] == 18 and r['strokes'] is not None]
        a.update({'course': course, 'name': course_name(course),
                  'players': len({r['persona'] for r in mine}),
                  'par': full[0]['par'] if full else None,
                  'record': a['best']})
        out.append(a)
    out.sort(key=lambda a: (a['to_par'] is None,
                            -(a['to_par'] or 0), a['name']))
    return out


def course(rs, index):
    mine = [r for r in rs if r['course'] == index]
    if not mine:
        return None
    a = _agg(mine)
    full = [r for r in mine if r['holes'] == 18 and r['strokes'] is not None]
    a.update({'course': index, 'name': course_name(index),
              'players': len({r['persona'] for r in mine}),
              'par': full[0]['par'] if full else None,
              'top': sorted(full, key=lambda r: (r['strokes'], r['when']))[:10],
              'recent': list(reversed(mine))[:10]})
    return a


# ---------------------------------------------------------------------------
# the in-game news

def _money(n):
    return '${:,}'.format(int(n)) if n else ''


def news(db, now=None, today=None):
    """The generated half of the news screen, as text: today's event and who
    leads it, yesterday's winner, records set in the last week, and the week's
    busiest player.  Sections with nothing to say are left out, so a quiet
    server produces a short page rather than a page of zeros."""
    now = now or time.time()
    today = twtourney.today() if today is None else today
    rs = rounds(db)
    sections = []

    event = db.event(today)
    if event:
        lines = ["TODAY: %s" % event['name'],
                 '%s%s' % (course_name(event['course']),
                           ', purse %s' % _money(event['purse'])
                           if event['purse'] else ''),
                 twtourney.describe_conditions(event.get('conditions'))]
        board = [r for r in rs if r['kind'] == 'tourney' and r['day'] == today
                 and r['strokes'] is not None]
        if board:
            lead = min(board, key=lambda r: (r['strokes'], r['when']))
            lines.append('Leader: %s %d (%s), %d in the field'
                         % (lead['persona'], lead['strokes'],
                            fmt_par(lead['to_par']), len(board)))
        else:
            lines.append('Nobody has posted a score yet.')
        sections.append(lines)

    past = [r for r in rs if r['kind'] == 'tourney' and r['day'] == today - 1
            and r['strokes'] is not None]
    if past:
        win = min(past, key=lambda r: (r['strokes'], r['when']))
        sections.append(['YESTERDAY: %s' % (win['event'] or 'the daily event'),
                         'Won by %s with %d (%s)'
                         % (win['persona'], win['strokes'],
                            fmt_par(win['to_par']))])

    # Only the headline records.  On a young server EVERY record is new this
    # week, and "fewest putts: 30" is not news.
    fresh = []
    rec, aces = records(rs)
    for key, title, r, show in rec:
        if key in NEWS_RECORDS and r and now - r['when'] < WEEK:
            fresh.append('%s: %s, %s' % (title, r['persona'], show))
    for c in courses(rs):
        r = c['record']
        if r and now - r['when'] < WEEK:
            fresh.append('Course record, %s: %s %d'
                         % (c['name'], r['persona'], r['strokes']))
    for r in aces:
        if now - r['when'] < WEEK:
            fresh.append('Hole in one: %s at %s'
                         % (r['persona'], course_name(r['course'])))
    if fresh:
        sections.append(['NEW RECORDS THIS WEEK'] + fresh[:NEWS_MAX_RECORDS])

    week = [r for r in rs if now - r['when'] < WEEK]
    if week:
        busy = collections.Counter(r['persona'] for r in week).most_common(1)[0]
        lines = ['THIS WEEK: %d round%s played'
                 % (len(week), '' if len(week) == 1 else 's'),
                 'Most active: %s (%d)' % busy]
        full = [r for r in week if r['to_par'] is not None]
        if full:
            b = min(full, key=lambda r: (r['to_par'], r['when']))
            lines.append('Best round: %s %d (%s) at %s'
                         % (b['persona'], b['strokes'], fmt_par(b['to_par']),
                            course_name(b['course'])))
        sections.append(lines)

    out = []
    for lines in sections:
        for line in lines:
            out.extend(textwrap.wrap(line, NEWS_WIDTH,
                                     subsequent_indent='  ') or [''])
        out.append('')
    return '\n'.join(out).rstrip('\n')


# ---------------------------------------------------------------------------

def sample(path, today=None, extra=()):
    """A fresh database at `path` with a known set of rounds, for the tests
    here and in webui_pagestest: three golfers, a head-to-head match, three
    days of tournament rounds, a hole in one, and the real card that came in
    with 1025 putts.  `extra` names more personas (with no rounds).  Returns
    the open twdb.DB."""
    import os
    import twdb

    for leftover in (path, path + '-wal', path + '-shm'):
        try:
            os.remove(leftover)
        except OSError:
            pass
    db = twdb.DB(path)
    for name in ('alice', 'bob', 'carol') + tuple(extra):
        db.create_account(name, 'password', persona=name)
    today = twtourney.today() if today is None else today

    def card(strokes, **kw):
        # A consistent par-72 card: the hole counts add up to 18 and to the
        # strokes, so the par code learns 72 rather than something skewed.
        bird, bog = max(0, 72 - strokes), max(0, strokes - 72)
        f = {'HOLES': 18, 'STROKES': strokes, 'PUTTS': 30, 'GIR': 10,
             'FRWY': 8, 'DRVS': 14, 'LDRV': 300, 'LPUT': 20, 'EAGS': 0,
             'BIRD': bird, 'ACES': 0, 'PARS': 18 - bird - bog, 'SBOG': bog,
             'DBOG': 0, 'TBOG': 0, 'DONE': 1, 'QUIT': 0}
        f.update(kw)
        return f

    db.add_events([{'day': today, 'name': 'Test Open', 'course': 4,
                    'purse': 1000000}])
    db.add_tourney('alice', today, 4, card(70))
    db.add_tourney('bob', today, 4, card(68, LDRV=390))
    db.add_tourney('carol', today, 4, card(75, PUTTS=1025))  # the real bad card
    db.add_tourney('alice', today - 1, 4, card(66, LPUT=48))
    db.add_tourney('bob', today - 1, 4, card(71))
    db.add_tourney('carol', today - 2, 9, card(72, ACES=1, PARS=17))
    # a head-to-head match: a session plus both consoles' report
    db.add_session('tok1', 'Stroke.T.East', 'alice', 'bob', 1,
                   setup={'COUR': '4'})
    f = {}
    for side, c in (('0', card(69)), ('1', card(73))):
        f.update({k + side: v for k, v in c.items()})
    f['AUTH'] = 'tok1'
    db.add_result(f)
    return db


def _selftest():
    import os
    import tempfile

    fails = []
    today = twtourney.today()
    now = time.time()
    db = sample(os.path.join(tempfile.gettempdir(), 'tw04-test-records.db'),
                today)

    rs = rounds(db)
    print('rounds: %d' % len(rs))
    bad = [r for r in rs if r['persona'] == 'carol' and r['day'] == today][0]
    if bad['putts'] is not None:
        fails.append('1025 putts must be thrown out, got %r' % bad['putts'])

    p = player(rs, 'ALICE')
    print('alice: %d rounds, W%d L%d, best %d, putts/18 %.1f'
          % (p['rounds'], p['won'], p['lost'], p['best']['strokes'],
             p['putts18']))
    if (p['name'], p['rounds'], p['won'], p['lost']) != ('alice', 3, 1, 0):
        fails.append('alice: 3 rounds, one match won, got %r'
                     % ((p['name'], p['rounds'], p['won'], p['lost']),))
    if p['best']['strokes'] != 66 or p['tourney_wins'] != 1:
        fails.append('alice: best 66 and yesterday\'s win, got %r'
                     % ((p['best']['strokes'], p['tourney_wins']),))
    if p['head_to_head'][0]['opponent'] != 'bob':
        fails.append('alice has played bob')

    lead = dict((cat[0], rows) for cat, rows in leaders(rs, min_rounds=1))
    if lead['drive_avg'][0][0] != 'bob':
        fails.append('bob drives furthest on average')
    if any(n == 'carol' and v > 40 for n, v, _ in lead['putts18']):
        fails.append('the bad card must not reach the putting table')

    rec, aces = records(rs)
    rec = {k: (r['persona'] if r else None, show) for k, _t, r, show in rec}
    print('records: %r' % rec)
    if rec['low'][0] != 'alice' or rec['drive'][0] != 'bob' \
            or rec['putt'][0] != 'alice':
        fails.append('record holders wrong: %r' % rec)
    if [r['persona'] for r in aces] != ['carol']:
        fails.append('carol has the only ace')

    cs = courses(rs)
    if [c['course'] for c in cs][:1] and cs[0]['record'] is None:
        fails.append('a course played in full has a record')

    text = news(db, now=now, today=today)
    print('---- news ----\n%s\n--------------' % text)
    for want in ('TODAY: Test Open', 'Leader: bob 68 (-4)', 'YESTERDAY',
                 'Won by alice with 66 (-6)', 'Most active',
                 'Hole in one: carol'):
        if want not in text:
            fails.append('news should say %r' % want)
    if 'Fewest putts' in text:
        fails.append('minor records do not make the news')
    if any(len(line) > NEWS_WIDTH for line in text.splitlines()):
        fails.append('a news line is wider than the screen')

    if fails:
        for f in fails:
            print('FAIL %s' % f)
        return 1
    print('\nok: both kinds of round fold into one list, impossible numbers are')
    print('    dropped, and pages, leaders, records and news agree on it')
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(_selftest())
