"""The TW04 master server's database.  sqlite3 from the standard library.

One file, no server process, no dependencies.  `lobbyd` and the web front end
both open it; sqlite's own locking keeps them honest, and WAL mode means a
reader never blocks the writer.

    python tools/twdb.py --create-account jed --password x
    python tools/twdb.py --list

The default path is <project>/data/tw04.db, anchored to this file rather than
to the working directory, so every tool opens the same one wherever it is run
from.

THE SHAPE OF AN EA ACCOUNT

The client's login is two steps and the database mirrors them exactly:

    auth NAME=<account> PASS=<enciphered>   ->  PERSONAS=<comma-separated>
    pers PERS=<one of those>

So an **account** is the credential and a **persona** is the name other players
see.  `_AuthCallback` (0x00287590) parses `PERSONAS` with a ',' separator into
four 32-byte slots, so an account may hold at most four and each is at most 31
characters.

A persona also owns a **golfer** -- the Create-A-Player blob the client uploads
with `cusr whomi` and the opponent fetches with `user`.  That is what makes your
player follow you between consoles, so it belongs here rather than in memory.
"""
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import sys
import threading
import time

if __package__ in (None, ''):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import twtourney

# The default is anchored to THIS FILE, not to the working directory.  `lobbyd`
# and `webui` must agree on one database, and a relative default does not make
# them agree -- it makes them agree only when they happen to be started from the
# same folder.  Running the server once from `tools/` split them into
# `tools/data/tw04.db` and `data/tw04.db`, and the symptom was an account that
# existed on the web site and did not exist at the login screen.
#
# Inside the project the modules live in `tools/` and the data belongs one level
# up, beside it.  A deployment folder is flat, and there the data belongs in
# that same directory -- otherwise copying the folder to a server would leave
# its database behind in the parent.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE) if os.path.basename(_HERE) == 'tools' else _HERE
DEFAULT_DB = os.path.join(_ROOT, 'data', 'tw04.db')

MAX_PERSONAS = 4          # four 32-byte slots at 0x002875E8
MAX_NAME = 31             # 32-byte field, NUL terminated
MIN_PASSWORD = 4          # "Passwords should be 4-16 characters long."
MAX_PASSWORD = 16         # -- 0x00312BF0, the client's own validation

PBKDF2_ROUNDS = 200_000

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id        INTEGER PRIMARY KEY,
    name      TEXT NOT NULL COLLATE NOCASE UNIQUE,
    salt      BLOB NOT NULL,
    hash      BLOB NOT NULL,
    mail      TEXT NOT NULL DEFAULT '',
    gend      TEXT NOT NULL DEFAULT 'M',
    born      TEXT NOT NULL DEFAULT '19700101',
    spam      INTEGER NOT NULL DEFAULT 0,
    disabled  INTEGER NOT NULL DEFAULT 0,
    created   REAL NOT NULL,
    last_seen REAL
);

CREATE TABLE IF NOT EXISTS personas (
    id         INTEGER PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name       TEXT NOT NULL COLLATE NOCASE UNIQUE,
    created    REAL NOT NULL,
    last_seen  REAL
);
CREATE INDEX IF NOT EXISTS personas_account ON personas(account_id);

-- The Create-A-Player record, uploaded by `cusr whomi` and served to the
-- opponent by `user`.  One per persona, replaced wholesale.
CREATE TABLE IF NOT EXISTS golfers (
    persona_id INTEGER PRIMARY KEY REFERENCES personas(id) ON DELETE CASCADE,
    crpin      BLOB NOT NULL,
    updated    REAL NOT NULL
);

-- A match the server brokered, keyed by the token it minted for `+ses` AUTH.
-- Results arrive long afterwards -- in the first real round, twenty-two minutes
-- later, with both consoles having disconnected and logged in again -- so the
-- pairing cannot live in memory.
CREATE TABLE IF NOT EXISTS sessions (
    auth    TEXT PRIMARY KEY,
    room    TEXT NOT NULL DEFAULT '',
    host    TEXT NOT NULL,
    guest   TEXT NOT NULL,
    seed    INTEGER NOT NULL DEFAULT 0,
    started REAL NOT NULL,
    -- The match settings, as JSON.  They are not in the `rank` result at all;
    -- they arrive earlier, in the challenge that set the match up, so they have
    -- to be captured there and kept.
    setup   TEXT NOT NULL DEFAULT ''
);

-- A `rank` submission, exactly as it arrived.  Both consoles report the same
-- match, so a match is the (auth, when) pair and there are normally two rows.
CREATE TABLE IF NOT EXISTS results (
    id        INTEGER PRIMARY KEY,
    auth      TEXT NOT NULL DEFAULT '',
    played    TEXT NOT NULL DEFAULT '',
    reporter  TEXT NOT NULL DEFAULT '',
    fields    TEXT NOT NULL,
    received  REAL NOT NULL
);
-- The tournament calendar: one event a day, generated a month at a time and
-- then left alone.  It is stored rather than recomputed because results point
-- at it -- a round recorded at Torrey Pines has to stay a round at Torrey
-- Pines even if the generator is changed afterwards.
CREATE TABLE IF NOT EXISTS events (
    day     INTEGER PRIMARY KEY,
    name    TEXT NOT NULL,
    course  INTEGER NOT NULL DEFAULT 0,
    purse   INTEGER NOT NULL DEFAULT 0,
    created REAL NOT NULL
);

-- A tournament round, one per player per event day.  Unlike a head-to-head
-- `rank`, this arrives on its own and is authenticated by the TKEY the server
-- handed out when it let the player start.
CREATE TABLE IF NOT EXISTS tourney (
    id       INTEGER PRIMARY KEY,
    persona  TEXT NOT NULL,
    day      INTEGER NOT NULL,
    course   INTEGER NOT NULL DEFAULT 0,
    strokes  INTEGER NOT NULL DEFAULT 0,
    fields   TEXT NOT NULL,
    received REAL NOT NULL,
    UNIQUE(persona, day)
);
CREATE INDEX IF NOT EXISTS tourney_day ON tourney(day);

-- What each course's par is believed to be.  Nothing on the wire ever states
-- it, so it is learnt from the scorecards themselves -- see
-- `twtourney.card_par` for why the smallest bound wins and `bound` for how
-- many cards have voted.
CREATE TABLE IF NOT EXISTS course_par (
    course  INTEGER PRIMARY KEY,
    par     INTEGER NOT NULL,
    cards   INTEGER NOT NULL DEFAULT 0,
    at      REAL NOT NULL DEFAULT 0
);

-- WHO IS ON THE SERVER RIGHT NOW.
--
-- `lobbyd` holds this in memory -- ONLINE, WHERE, SESSIONS -- and the web site
-- is a separate process that cannot see any of it.  Mirroring it into the
-- database is what lets the site show a live picture without the two talking
-- to each other directly.  Rows are the truth only as far as `seen`: a lobbyd
-- that is killed cannot tidy up after itself, so a reader must treat anything
-- older than `PRESENCE_STALE` as gone.
CREATE TABLE IF NOT EXISTS presence (
    persona TEXT PRIMARY KEY,
    room    TEXT NOT NULL DEFAULT '',
    state   TEXT NOT NULL DEFAULT 'lobby',
    detail  TEXT NOT NULL DEFAULT '',
    since   REAL NOT NULL,
    seen    REAL NOT NULL
);

-- A match currently being played, from the moment the server hands out a
-- session to the moment a result comes back for it.
CREATE TABLE IF NOT EXISTS playing (
    auth    TEXT PRIMARY KEY,
    room    TEXT NOT NULL DEFAULT '',
    host    TEXT NOT NULL DEFAULT '',
    guest   TEXT NOT NULL DEFAULT '',
    kind    TEXT NOT NULL DEFAULT '',
    course  INTEGER NOT NULL DEFAULT -1,
    started REAL NOT NULL,
    seen    REAL NOT NULL
);

-- A short rolling history of things that happened, for a live feed.  Trimmed
-- on write so it cannot grow without bound.
CREATE TABLE IF NOT EXISTS activity (
    id   INTEGER PRIMARY KEY,
    at   REAL NOT NULL,
    kind TEXT NOT NULL,
    who  TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS activity_at ON activity(at);

-- EA Messenger lists: `B` is a persona's buddy list, `I` its ignore (block)
-- list -- the two values of `LIST` in `RGET`/`RADD`/`RDEL`.  Keyed by persona
-- id so dropping a persona takes it off everybody's lists with it.
CREATE TABLE IF NOT EXISTS buddies (
    owner_id INTEGER NOT NULL REFERENCES personas(id) ON DELETE CASCADE,
    buddy_id INTEGER NOT NULL REFERENCES personas(id) ON DELETE CASCADE,
    list     TEXT NOT NULL,
    grp      TEXT NOT NULL DEFAULT '',
    added    REAL NOT NULL,
    PRIMARY KEY (owner_id, buddy_id, list)
);
CREATE INDEX IF NOT EXISTS buddies_buddy ON buddies(buddy_id, list);

-- EA Messenger login keys, one live key per persona, minted at `pers`.  Kept
-- here rather than only in lobbyd's memory because a console keeps its
-- Messenger session across a lobby RESTART and reconnects with the key it
-- already holds -- and a restarted lobbyd that has forgotten it refuses the
-- login, which leaves the game's buddy list as blank "offline" rows that
-- freeze the emulator when removed (2026-09-23).
CREATE TABLE IF NOT EXISTS lkeys (
    key     TEXT PRIMARY KEY,
    persona TEXT NOT NULL COLLATE NOCASE UNIQUE,
    issued  REAL NOT NULL
);

-- REPORT ABUSE, from the player menu.  The request (`rept PERS PROD LANG`,
-- 0x00275430) names only who is being reported; the game tells the reporter
-- "a copy of the chat log will be sent", so the server attaches what it
-- relayed itself -- `chat` is a JSON list of {at, from, to, via, text}.
-- `handled` is set from the reports page.  Names are stored as text, not ids,
-- so a report outlives the persona it is about.
CREATE TABLE IF NOT EXISTS reports (
    id       INTEGER PRIMARY KEY,
    at       REAL NOT NULL,
    reporter TEXT NOT NULL,
    accused  TEXT NOT NULL,
    room     TEXT NOT NULL DEFAULT '',
    chat     TEXT NOT NULL DEFAULT '[]',
    handled  REAL
);
CREATE INDEX IF NOT EXISTS reports_accused ON reports(accused);

-- One-line facts the server keeps current: its heartbeat, its uptime, the
-- rooms it is offering.  A key/value table rather than columns because what is
-- worth publishing changes more often than the schema should.
CREATE TABLE IF NOT EXISTS live (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    at    REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS results_auth ON results(auth);
CREATE INDEX IF NOT EXISTS results_reporter ON results(reporter);
"""


def _col(row, name, default=None):
    """A column that may not exist yet.

    sqlite3.Row raises IndexError for a name it does not have, which killed a
    whole connection thread when a database written by an older build was
    opened by a newer one.  Migrations should prevent that, but a stale process
    holding an old connection can still hit it, so reads degrade rather than
    throw.
    """
    try:
        value = row[name]
    except (IndexError, KeyError):
        return default
    return default if value is None else value


def _int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _winner(players):
    """The winning name, or None for a tie.

    SCORE is 0 for both sides in every stroke-play result captured so far, so
    STROKES decides and fewer is better.  SCORE is kept as the tie-break for
    match play, where it is the holes-up figure and more is better.
    """
    a, b = players
    if a['strokes'] != b['strokes'] and (a['strokes'] or b['strokes']):
        return a['name'] if a['strokes'] < b['strokes'] else b['name']
    if a['score'] != b['score']:
        return a['name'] if a['score'] > b['score'] else b['name']
    return None


class Error(Exception):
    """Something the caller should show a person, not a stack trace."""


def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt,
                                 PBKDF2_ROUNDS)
    return salt, digest


def check_name(name, what='name'):
    name = (name or '').strip()
    if not name:
        raise Error('a %s is required' % what)
    if len(name) > MAX_NAME:
        raise Error('%s must be %d characters or fewer' % (what, MAX_NAME))
    # ',' separates PERSONAS on the wire and the rest confuse the TagField codec.
    bad = set(name) & set(',="%:\n\r\t')
    if bad:
        raise Error('%s cannot contain %s' % (what, ' '.join(sorted(bad))))
    if not all(32 <= ord(c) < 127 for c in name):
        raise Error('%s must be plain ASCII -- the PS2 cannot display anything else'
                    % what)
    return name


def check_password(password):
    if not MIN_PASSWORD <= len(password or '') <= MAX_PASSWORD:
        # The client enforces this itself at 0x00312BF0, so anything outside it
        # could never be typed at the console.
        raise Error('password must be %d-%d characters'
                    % (MIN_PASSWORD, MAX_PASSWORD))
    return password


class DB:
    def __init__(self, path):
        self.path = os.path.abspath(path)
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.executescript(SCHEMA)
            self._migrate()
            self.conn.commit()

    # Columns added to a table that already existed.  `CREATE TABLE IF NOT
    # EXISTS` creates a missing table but will not add a missing column, so a
    # database made by an older build keeps its old shape and the first query
    # that names the new column fails.  Adding them here means an existing file
    # can simply be dropped in.
    MIGRATIONS = [
        ('sessions', 'setup', "TEXT NOT NULL DEFAULT ''"),
        # A round records the event it was played in, by name, at the time it
        # is reported.  The calendar is generated and could be regenerated
        # differently; a result should say what it actually was, not what the
        # current calendar says that day is now.  Rows written before this
        # column existed fall back to the calendar.
        ('tourney', 'event', "TEXT NOT NULL DEFAULT ''"),
        # The par the card implies, cached so a course's par is one GROUP BY
        # rather than a JSON parse per row.  0 means "this card cannot say".
        ('tourney', 'par', 'INTEGER NOT NULL DEFAULT 0'),
    ]

    def _migrate(self):
        added = set()
        for table, column, decl in self.MIGRATIONS:
            info = self.conn.execute('PRAGMA table_info(%s)' % table).fetchall()
            if not info:
                continue                      # the table is new; SCHEMA made it
            if column not in {row['name'] for row in info}:
                self.conn.execute('ALTER TABLE %s ADD COLUMN %s %s'
                                  % (table, column, decl))
                added.add((table, column))
        if ('tourney', 'par') in added:
            self._backfill_par()

    def _backfill_par(self):
        """Work out `tourney.par` for rows written before the column existed.

        An ALTER only fills the default, and 0 there means "this card cannot
        name a par" -- which is indistinguishable from "nobody has looked yet".
        So look now, once, rather than leaving every existing course with no
        evidence behind it.
        """
        rows = self.conn.execute('SELECT id, fields FROM tourney').fetchall()
        for row in rows:
            try:
                par = twtourney.card_par(json.loads(row['fields'])) or 0
            except (ValueError, TypeError):
                par = 0
            self.conn.execute('UPDATE tourney SET par = ? WHERE id = ?',
                              (par, row['id']))
        self.conn.commit()

    # -- plumbing ----------------------------------------------------------
    def query(self, sql, args=()):
        with self.lock:
            return self.conn.execute(sql, args).fetchall()

    def one(self, sql, args=()):
        rows = self.query(sql, args)
        return rows[0] if rows else None

    def run(self, sql, args=()):
        with self.lock:
            cur = self.conn.execute(sql, args)
            self.conn.commit()
            return cur

    def run_many(self, sql, rows):
        """One transaction for the lot -- a month of events is all or nothing,
        which is what lets `month_generated` decide from a count."""
        with self.lock:
            self.conn.executemany(sql, rows)
            self.conn.commit()

    # -- accounts ----------------------------------------------------------
    def create_account(self, name, password, mail='', gend='M',
                       born='19700101', spam=0, persona=None):
        name = check_name(name, 'account name')
        check_password(password)
        persona = check_name(persona or name, 'persona')
        if self.one('SELECT 1 FROM accounts WHERE name = ?', (name,)):
            raise Error('the account %r already exists' % name)
        if self.one('SELECT 1 FROM personas WHERE name = ?', (persona,)):
            raise Error('the persona %r is already taken' % persona)
        salt, digest = hash_password(password)
        cur = self.run(
            'INSERT INTO accounts (name, salt, hash, mail, gend, born, spam,'
            ' created) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (name, salt, digest, mail, gend, born, int(bool(spam)), time.time()))
        self.run('INSERT INTO personas (account_id, name, created)'
                 ' VALUES (?, ?, ?)', (cur.lastrowid, persona, time.time()))
        return cur.lastrowid

    def account(self, name):
        return self.one('SELECT * FROM accounts WHERE name = ?', (name,))

    def verify(self, name, password):
        """The account row for these credentials, or None.

        Always does the full derivation, so a missing account and a wrong
        password take the same time and cannot be told apart by timing.
        """
        row = self.account(name)
        salt = row['salt'] if row else b'\0' * 16
        expect = row['hash'] if row else b'\0' * 32
        _, digest = hash_password(password or '', salt)
        if not hmac.compare_digest(digest, expect) or row is None:
            return None
        if row['disabled']:
            raise Error('that account is disabled')
        self.run('UPDATE accounts SET last_seen = ? WHERE id = ?',
                 (time.time(), row['id']))
        return row

    def set_password(self, account_id, password):
        check_password(password)
        salt, digest = hash_password(password)
        self.run('UPDATE accounts SET salt = ?, hash = ? WHERE id = ?',
                 (salt, digest, account_id))

    def set_profile(self, account_id, mail=None, gend=None, born=None, spam=None):
        sets, args = [], []
        for column, value in (('mail', mail), ('gend', gend), ('born', born)):
            if value is not None:
                sets.append('%s = ?' % column)
                args.append(value)
        if spam is not None:
            sets.append('spam = ?')
            args.append(int(bool(spam)))
        if not sets:
            return
        args.append(account_id)
        self.run('UPDATE accounts SET %s WHERE id = ?' % ', '.join(sets), args)

    # -- personas ----------------------------------------------------------
    def personas(self, account_id):
        return [r['name'] for r in self.query(
            'SELECT name FROM personas WHERE account_id = ? ORDER BY id',
            (account_id,))]

    def add_persona(self, account_id, name):
        name = check_name(name, 'persona')
        existing = self.personas(account_id)
        if len(existing) >= MAX_PERSONAS:
            raise Error('an account can hold %d personas; the game only reads '
                        'that many from the login reply' % MAX_PERSONAS)
        if self.one('SELECT 1 FROM personas WHERE name = ?', (name,)):
            raise Error('the persona %r is already taken' % name)
        self.run('INSERT INTO personas (account_id, name, created)'
                 ' VALUES (?, ?, ?)', (account_id, name, time.time()))

    def drop_persona(self, account_id, name):
        if len(self.personas(account_id)) <= 1:
            raise Error('an account needs at least one persona')
        self.run('DELETE FROM personas WHERE account_id = ? AND name = ?',
                 (account_id, name))

    def persona(self, name):
        return self.one('SELECT * FROM personas WHERE name = ?', (name,))

    def owns_persona(self, account_id, name):
        return bool(self.one(
            'SELECT 1 FROM personas WHERE account_id = ? AND name = ?',
            (account_id, name)))

    def seen_persona(self, name):
        self.run('UPDATE personas SET last_seen = ? WHERE name = ?',
                 (time.time(), name))

    # -- EA Messenger login keys ------------------------------------------
    # How long a key is honoured if nothing retires it first.  A lobby that is
    # restarted cannot retire the keys of the sessions it lost, so without an
    # age limit those would stay valid for ever.
    LKEY_TTL = 12 * 3600

    def issue_lkey(self, persona):
        """A fresh key for `persona`, replacing any older one."""
        key = secrets.token_hex(16)
        self.run('INSERT INTO lkeys (key, persona, issued) VALUES (?, ?, ?)'
                 ' ON CONFLICT (persona) DO UPDATE SET key = excluded.key,'
                 ' issued = excluded.issued', (key, persona, time.time()))
        return key

    def lkey_persona(self, key):
        """The persona `key` was issued to, or None if it is unknown,
        superseded or older than LKEY_TTL."""
        if not key:
            return None
        row = self.one('SELECT persona FROM lkeys WHERE key = ? AND issued > ?',
                       (key, time.time() - self.LKEY_TTL))
        return row['persona'] if row else None

    def retire_lkey(self, key):
        if key:
            self.run('DELETE FROM lkeys WHERE key = ?', (key,))

    # -- abuse reports -----------------------------------------------------
    def add_report(self, reporter, accused, room='', chat=()):
        cur = self.run('INSERT INTO reports (at, reporter, accused, room, chat)'
                       ' VALUES (?, ?, ?, ?, ?)',
                       (time.time(), reporter, accused, room or '',
                        json.dumps(list(chat))))
        return cur.lastrowid

    def reports(self, handled=False, limit=100):
        """Open reports (or handled ones), newest first, each with the
        reported persona's account and how many reports name that persona."""
        rows = self.query(
            'SELECT r.*, a.name AS account, a.disabled AS disabled,'
            ' (SELECT COUNT(*) FROM reports x WHERE x.accused = r.accused'
            '  COLLATE NOCASE) AS against'
            ' FROM reports r'
            ' LEFT JOIN personas p ON p.name = r.accused'
            ' LEFT JOIN accounts a ON a.id = p.account_id'
            ' WHERE (r.handled IS NOT NULL) = ?'
            ' ORDER BY r.at DESC LIMIT ?', (1 if handled else 0, limit))
        out = []
        for row in rows:
            item = dict(row)
            try:
                item['chat'] = json.loads(row['chat'] or '[]')
            except ValueError:
                item['chat'] = []
            out.append(item)
        return out

    def set_report_handled(self, report_id, handled=True):
        self.run('UPDATE reports SET handled = ? WHERE id = ?',
                 (time.time() if handled else None, report_id))

    def count_open_reports(self):
        return self.one('SELECT COUNT(*) AS n FROM reports'
                        ' WHERE handled IS NULL')['n']

    # -- EA Messenger lists ------------------------------------------------
    # The client caps a buddy list at 25 ("the maximum of 25 buddies has been
    # reached"); the server holds the same line so a modified client cannot
    # grow one without bound.
    MAX_BUDDIES = 25

    def buddy_list(self, owner, list_='B'):
        """[(name, group)] on `owner`'s list, in the order they were added."""
        return [(r['name'], r['grp']) for r in self.query(
            'SELECT b.name, l.grp FROM buddies l'
            ' JOIN personas o ON o.id = l.owner_id'
            ' JOIN personas b ON b.id = l.buddy_id'
            ' WHERE o.name = ? AND l.list = ? ORDER BY l.added, b.name',
            (owner, list_))]

    def add_buddy(self, owner, buddy, list_='B', group=''):
        """Put `buddy` on `owner`'s list.  Returns the buddy's name as stored,
        which is what the client is told to call it (`FUSR`)."""
        o, b = self.persona(owner), self.persona(buddy)
        if not o or not b:
            raise Error('no persona called %r' % (buddy if o else owner))
        if o['id'] == b['id']:
            raise Error("you can't add yourself")
        on = self.one('SELECT 1 FROM buddies WHERE owner_id = ? AND buddy_id = ?'
                      ' AND list = ?', (o['id'], b['id'], list_))
        if not on and len(self.buddy_list(owner, list_)) >= self.MAX_BUDDIES:
            raise Error('the list is full')
        self.run('INSERT INTO buddies (owner_id, buddy_id, list, grp, added)'
                 ' VALUES (?, ?, ?, ?, ?)'
                 ' ON CONFLICT (owner_id, buddy_id, list)'
                 ' DO UPDATE SET grp = excluded.grp',
                 (o['id'], b['id'], list_, group or '', time.time()))
        return b['name']

    def drop_buddy(self, owner, buddy, list_='B'):
        self.run('DELETE FROM buddies WHERE list = ?'
                 ' AND owner_id = (SELECT id FROM personas WHERE name = ?)'
                 ' AND buddy_id = (SELECT id FROM personas WHERE name = ?)',
                 (list_, owner, buddy))

    def watchers(self, buddy):
        """Everyone with `buddy` on their buddy list -- who hears its presence."""
        return [r['name'] for r in self.query(
            'SELECT o.name FROM buddies l'
            ' JOIN personas o ON o.id = l.owner_id'
            ' JOIN personas b ON b.id = l.buddy_id'
            " WHERE b.name = ? AND l.list = 'B'", (buddy,))]

    def blocks(self, owner, other):
        """True when `owner` has `other` on their ignore list."""
        return bool(self.one(
            'SELECT 1 FROM buddies l'
            ' JOIN personas o ON o.id = l.owner_id'
            ' JOIN personas b ON b.id = l.buddy_id'
            " WHERE o.name = ? AND b.name = ? AND l.list = 'I'",
            (owner, other)))

    # -- golfers -----------------------------------------------------------
    def set_golfer(self, persona_name, blob):
        row = self.persona(persona_name)
        if not row:
            return False
        self.run('INSERT INTO golfers (persona_id, crpin, updated)'
                 ' VALUES (?, ?, ?) ON CONFLICT(persona_id) DO UPDATE SET'
                 ' crpin = excluded.crpin, updated = excluded.updated',
                 (row['id'], blob, time.time()))
        return True

    def golfer(self, persona_name):
        row = self.one(
            'SELECT g.crpin FROM golfers g JOIN personas p ON p.id = g.persona_id'
            ' WHERE p.name = ?', (persona_name,))
        return row['crpin'] if row else None

    # -- results -----------------------------------------------------------
    # -- sessions ----------------------------------------------------------
    def add_session(self, auth, room, host, guest, seed, setup=None):
        self.run('INSERT OR REPLACE INTO sessions'
                 ' (auth, room, host, guest, seed, started, setup)'
                 ' VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (auth, room, host, guest, int(seed), time.time(),
                  json.dumps(setup, sort_keys=True) if setup else ''))

    def session(self, auth):
        return self.one('SELECT * FROM sessions WHERE auth = ?', (auth,))

    # -- results -----------------------------------------------------------
    def add_result(self, fields):
        self.run('INSERT INTO results (auth, played, reporter, fields, received)'
                 ' VALUES (?, ?, ?, ?, ?)',
                 (fields.get('AUTH', ''), fields.get('WHEN', ''),
                  fields.get('REPT', ''), json.dumps(fields, sort_keys=True),
                  time.time()))

    def count_accounts(self):
        return self.one('SELECT COUNT(*) AS n FROM accounts')['n']

    def results_for(self, persona, limit=25):
        return self.query(
            'SELECT * FROM results WHERE reporter = ? ORDER BY id DESC LIMIT ?',
            (persona, limit))

    def matches(self, persona=None, limit=200):
        """One row per match, resolved against the session that brokered it.

        Both consoles report the same match, so the raw `results` table holds it
        twice.  Deduplicating on AUTH is only possible because the token is
        unique per session -- it used to be the constant 'tw04-local', which
        made every match in the database look like the same one.

        Which column is whose comes from the SESSION, not from the NAME0/NAME1
        fields.  In the first real round one console reported
        `NAME0=JeddyH2 NAME1=JeddyH2` -- both sides the same name -- while its
        numbers were correct and in the same order as its opponent's.  So the
        suffix is positional: **0 is the host**, 1 is the guest, in both
        submissions.
        """
        # THE FIRST REPORT FOR A TOKEN IS THE ONE THAT COUNTS.  Both consoles
        # report the same match, so there are normally two rows and either
        # would do -- but nothing stops a console sending a third, later, with
        # better numbers.  Taking the newest row let a player who had lost
        # resubmit and flip the result; taking the earliest does not.
        seen, out = set(), []
        for row in self.query(
                'SELECT * FROM results WHERE id IN'
                ' (SELECT MIN(id) FROM results GROUP BY auth)'
                ' ORDER BY id DESC LIMIT ?', (limit * 2,)):
            if row['auth'] in seen:
                continue
            ses = self.session(row['auth'])
            if not ses:
                continue          # a result for a match we did not broker
            if persona and persona not in (ses['host'], ses['guest']):
                continue
            seen.add(row['auth'])
            f = json.loads(row['fields'])
            raw_setup = _col(ses, 'setup', '')
            try:
                setup = json.loads(raw_setup) if raw_setup else {}
            except ValueError:
                setup = {}
            match = {'auth': row['auth'], 'room': ses['room'],
                     'when': row['played'], 'received': row['received'],
                     'host': ses['host'], 'guest': ses['guest'],
                     'setup': setup, 'players': []}
            for side, who in (('0', ses['host']), ('1', ses['guest'])):
                match['players'].append({
                    'name': who,
                    'strokes': _int(f.get('STROKES' + side)),
                    'score': _int(f.get('SCORE' + side)),
                    'holes': _int(f.get('HOLES' + side)),
                    'putts': _int(f.get('PUTTS' + side)),
                    'gir': _int(f.get('GIR' + side)),
                    'fairways': _int(f.get('FRWY' + side)),
                    'drives': _int(f.get('DRVS' + side)),
                    'longest': _int(f.get('LDRV' + side)),
                    'longest_putt': _int(f.get('LPUT' + side)),
                    'eagles': _int(f.get('EAGS' + side)),
                    'birdies': _int(f.get('BIRD' + side)),
                    'aces': _int(f.get('ACES' + side)),
                    'pars': _int(f.get('PARS' + side)),
                    'bogeys': _int(f.get('SBOG' + side)),
                    'doubles': _int(f.get('DBOG' + side)),
                    'triples': _int(f.get('TBOG' + side)),
                    'shotclock': _int(f.get('SHTC' + side)),
                    'done': _int(f.get('DONE' + side)),
                    'quit': _int(f.get('QUIT' + side)),
                    'completed': _int(f.get('COMP' + side)),
                })
            match['winner'] = _winner(match['players'])
            out.append(match)
            if len(out) >= limit:
                break
        return out

    def record(self, persona):
        """(played, won, lost, tied) over the matches this persona finished."""
        played = won = lost = tied = 0
        for m in self.matches(persona):
            mine = next(p for p in m['players'] if p['name'] == persona)
            if not mine['done'] or mine['quit']:
                continue
            played += 1
            if m['winner'] is None:
                tied += 1
            elif m['winner'] == persona:
                won += 1
            else:
                lost += 1
        return played, won, lost, tied

    def events(self, start, count):
        """The stored events covering [start, start+count), day order."""
        rows = self.query('SELECT * FROM events WHERE day >= ? AND day < ?'
                          ' ORDER BY day ASC', (start, start + count))
        return [{'day': r['day'], 'name': r['name'], 'course': r['course'],
                 'purse': r['purse']} for r in rows]

    def event(self, day):
        rows = self.events(day, 1)
        return rows[0] if rows else None

    def month_generated(self, first, length):
        """Has this month been written yet?  One row is enough to say yes --
        a month is inserted in a single transaction, so it is all or nothing."""
        row = self.one('SELECT COUNT(*) AS n FROM events'
                       ' WHERE day >= ? AND day < ?', (first, first + length))
        return bool(row) and row['n'] >= length

    def add_events(self, events):
        """Store a generated month.  Existing days are left alone, so this can
        never rewrite an event somebody has already played."""
        now = time.time()
        self.run_many(
            'INSERT OR IGNORE INTO events (day, name, course, purse, created)'
            ' VALUES (?, ?, ?, ?, ?)',
            [(e['day'], e['name'], e['course'], e['purse'], now)
             for e in events])

    def events_with_course(self, courses, from_day=0):
        """Scheduled events on a course from `courses`, on or after a day."""
        if not courses:
            return []
        marks = ','.join('?' * len(courses))
        rows = self.query('SELECT * FROM events WHERE day >= ? AND course IN (%s)'
                          ' ORDER BY day ASC' % marks,
                          (from_day,) + tuple(courses))
        return [{'day': r['day'], 'name': r['name'], 'course': r['course'],
                 'purse': r['purse']} for r in rows]

    def replace_event(self, day, name, course):
        """Change one scheduled event, keeping its purse."""
        self.run('UPDATE events SET name = ?, course = ? WHERE day = ?',
                 (name, course, day))

    def add_tourney(self, persona, day, course, fields, event=''):
        """Record a tournament round.  One per player per day -- a second
        report for the same day replaces the first, which is what happens when
        a player replays an event."""
        par = twtourney.card_par(fields) or 0
        self.run('INSERT INTO tourney (persona, day, course, strokes, event,'
                 ' par, fields, received) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
                 ' ON CONFLICT(persona, day) DO UPDATE SET'
                 ' course=excluded.course, strokes=excluded.strokes,'
                 ' event=excluded.event, par=excluded.par,'
                 ' fields=excluded.fields, received=excluded.received',
                 (persona, day, course, fields.get('STROKES', 0), event, par,
                  json.dumps(fields), time.time()))
        if par:
            self.note_par(course, par)

    # -- what a course is worth --------------------------------------------
    def note_par(self, course, bound):
        """Fold one card's bound into the stored par for a course.

        Smaller wins.  Every bound a scorecard gives is an over-estimate or
        exact, never an under-estimate, so the running minimum walks down onto
        the real figure and stays there.
        """
        row = self.one('SELECT par, cards FROM course_par WHERE course = ?',
                       (course,))
        if row is None:
            self.run('INSERT INTO course_par (course, par, cards, at)'
                     ' VALUES (?, ?, 1, ?)', (course, bound, time.time()))
            return bound
        par = min(row['par'], bound)
        self.run('UPDATE course_par SET par = ?, cards = cards + 1, at = ?'
                 ' WHERE course = ?', (par, time.time(), course))
        return par

    def course_pars(self):
        """{course index: par} for every course anything is known about.

        The stored table is authoritative; the tourney rows are consulted too
        so a database whose `course_par` was never written -- one migrated in,
        or one where a round was recorded by an older build -- still answers.
        """
        out = {}
        for r in self.query('SELECT course, MIN(par) AS par FROM tourney'
                            ' WHERE par > 0 GROUP BY course'):
            out[r['course']] = r['par']
        for r in self.query('SELECT course, par FROM course_par'):
            best = out.get(r['course'])
            out[r['course']] = r['par'] if best is None else min(best, r['par'])
        return out

    def course_par(self, course):
        """The par to score a round on `course` against."""
        return self.course_pars().get(course, twtourney.DEFAULT_PAR)

    def tourney_rounds(self, persona, limit=20):
        """One player's tournament rounds, newest first, with the event.

        The name comes from the round when it has one and from the calendar
        otherwise, so rows recorded before that column existed still read
        sensibly -- `named` says which, because a regenerated calendar may not
        agree with what the player actually saw.  The COURSE is always the
        round's own: that is what was played, whatever the calendar says now.
        """
        rows = self.query('SELECT * FROM tourney WHERE persona = ?'
                          ' ORDER BY day DESC LIMIT ?', (persona, limit))
        pars = self.course_pars()
        out = []
        for r in rows:
            event = _col(r, 'event', '')
            listed = self.event(r['day'])
            place, entrants = self.tourney_place(persona, r['day'])
            out.append({'day': r['day'], 'course': r['course'],
                        'strokes': r['strokes'],
                        'par': pars.get(r['course'], twtourney.DEFAULT_PAR),
                        'event': event or (listed['name'] if listed else ''),
                        'named': bool(event),
                        'fields': json.loads(r['fields']),
                        'place': place, 'entrants': entrants})
        return out

    def tourney_day(self, day, limit=50):
        """The leaderboard for one event day, best score first.

        Every row carries the same `par` -- the COURSE's, not its own card's.
        One board must be scored against one par or the to-par column comes
        out in a different order from the strokes it was sorted by.
        """
        rows = self.query('SELECT * FROM tourney WHERE day = ?'
                          ' ORDER BY strokes ASC, received ASC LIMIT ?',
                          (day, limit))
        pars = self.course_pars() if rows else {}
        return [{'name': r['persona'], 'strokes': r['strokes'],
                 'course': r['course'], 'event': _col(r, 'event', ''),
                 'par': pars.get(r['course'], twtourney.DEFAULT_PAR),
                 'fields': json.loads(r['fields'])}
                for r in rows]

    def tourney_standings(self, first, last, payout=None):
        """Every player over a range of event days, richest first.

        `payout(purse, place)` is passed in rather than imported so the money
        rule lives in one place -- twtourney -- and both the game server and the
        web site get the same answer from the same code.

        A placing only means something inside its own event and each event has
        its own purse, so this has to walk a day at a time; there is no way to
        total it with one query.
        """
        table = {}
        for day in range(first, last + 1):
            board = self.tourney_day(day, limit=1000)
            if not board:
                continue
            event = self.event(day)
            purse = event['purse'] if event else 0
            for place, row in enumerate(board, 1):
                e = table.setdefault(row['name'], {
                    'name': row['name'], 'rounds': 0, 'earned': 0,
                    'wins': 0, 'best': None, 'strokes': 0})
                e['rounds'] += 1
                e['strokes'] += row['strokes']
                e['wins'] += (place == 1)
                e['best'] = place if e['best'] is None else min(e['best'], place)
                if payout:
                    e['earned'] += payout(purse, place)
        return sorted(table.values(), key=lambda r: (-r['earned'], r['strokes']))

    def tourney_recent(self, limit=20):
        """The most recent finished events, newest first, with their winner."""
        rows = self.query('SELECT day, MIN(strokes) AS best FROM tourney'
                          ' GROUP BY day ORDER BY day DESC LIMIT ?', (limit,))
        out = []
        for r in rows:
            board = self.tourney_day(r['day'], limit=1)
            event = self.event(r['day'])
            if board:
                out.append({'day': r['day'], 'event': event, 'winner': board[0]})
        return out

    # -- the live picture ---------------------------------------------------
    #
    # Everything below is written by `lobbyd` and read by `webui`.  The two are
    # separate processes, so a row is only as true as its timestamp: a server
    # that is killed leaves its last state behind exactly as it was.  Readers
    # must therefore age rows out, which is what PRESENCE_STALE is for, and
    # writers must refresh them, which is what the keepalive does.

    PRESENCE_STALE = 150         # seconds; the keepalive runs well inside this

    def set_live(self, key, value):
        """Publish one fact about the running server."""
        self.run('INSERT INTO live (key, value, at) VALUES (?, ?, ?)'
                 ' ON CONFLICT(key) DO UPDATE SET'
                 ' value=excluded.value, at=excluded.at',
                 (key, str(value), time.time()))

    def get_live(self, key, default=None):
        row = self.one('SELECT value, at FROM live WHERE key = ?', (key,))
        if row is None:
            return default, 0.0
        return row['value'], row['at']

    def live_all(self):
        return {r['key']: (r['value'], r['at'])
                for r in self.query('SELECT key, value, at FROM live')}

    def server_is_up(self, stale=None):
        """Has the master server touched its heartbeat recently?"""
        _value, at = self.get_live('heartbeat')
        if not at:
            return False, 0.0
        age = time.time() - at
        return age <= (stale or self.PRESENCE_STALE), age

    def set_presence(self, persona, room=None, state=None, detail=None):
        """Mark a player present, keeping `since` across updates.

        `since` is when they arrived, and it must survive a room change or the
        site would report everyone as having just walked in.
        """
        now = time.time()
        row = self.one('SELECT * FROM presence WHERE persona = ?', (persona,))
        if row is None:
            self.run('INSERT INTO presence (persona, room, state, detail,'
                     ' since, seen) VALUES (?, ?, ?, ?, ?, ?)',
                     (persona, room or '', state or 'lobby', detail or '',
                      now, now))
            return
        self.run('UPDATE presence SET room = ?, state = ?, detail = ?, seen = ?'
                 ' WHERE persona = ?',
                 (row['room'] if room is None else room,
                  row['state'] if state is None else state,
                  row['detail'] if detail is None else detail,
                  now, persona))

    def touch_presence(self, personas):
        """One `seen` sweep for everyone still connected."""
        now = time.time()
        self.run_many('UPDATE presence SET seen = ? WHERE persona = ?',
                      [(now, p) for p in personas])

    def clear_presence(self, persona):
        self.run('DELETE FROM presence WHERE persona = ?', (persona,))

    def keep_presence(self, personas):
        """Everyone not named here has gone.

        The writer publishes the whole picture each time rather than tracking
        arrivals and departures one by one, so the table has to be trimmed to
        match or a player who left at a moment nobody handled stays online for
        ever.
        """
        if not personas:
            self.run('DELETE FROM presence')
            return
        marks = ','.join('?' * len(personas))
        self.run('DELETE FROM presence WHERE persona NOT IN (%s)' % marks,
                 tuple(personas))

    def clear_all_presence(self):
        """Start of day.  A server that crashed left its players "online"."""
        self.run('DELETE FROM presence')
        self.run('DELETE FROM playing')

    def online(self, stale=None):
        """Everyone present, longest-standing first, ghosts dropped."""
        cutoff = time.time() - (stale or self.PRESENCE_STALE)
        return [dict(r) for r in
                self.query('SELECT * FROM presence WHERE seen >= ?'
                           ' ORDER BY since ASC', (cutoff,))]

    def start_playing(self, auth, room, host, guest, kind='', course=-1):
        now = time.time()
        self.run('INSERT INTO playing (auth, room, host, guest, kind, course,'
                 ' started, seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
                 ' ON CONFLICT(auth) DO UPDATE SET seen=excluded.seen',
                 (auth, room, host, guest, kind, course, now, now))

    def stop_playing(self, auth):
        self.run('DELETE FROM playing WHERE auth = ?', (auth,))

    # No round of golf takes this long.  A match with no result after it was
    # abandoned somewhere nobody told us about -- both consoles switched off,
    # say -- and stops being shown.
    MATCH_MAX_AGE = 3 * 3600

    def playing(self):
        """Matches under way, from the introduction (`+ses`) until something
        says they are over: a result, a player back in the lobby (see
        `end_playing_for`), or MATCH_MAX_AGE.

        NOT tied to presence.  The moment the two consoles connect to each
        other they leave the lobby (both disconnect within a second of `+ses`
        in every capture), so "nobody in it is connected" is precisely what a
        match in play looks like -- the old rule hid every match the instant
        it started."""
        cutoff = time.time() - self.MATCH_MAX_AGE
        return [dict(r) for r in
                self.query('SELECT * FROM playing WHERE started >= ?'
                           ' ORDER BY started ASC', (cutoff,))]

    def end_playing_for(self, persona):
        """Close any match `persona` is in.  Returns how many were open."""
        cur = self.run('DELETE FROM playing WHERE host = ? COLLATE NOCASE'
                       ' OR guest = ? COLLATE NOCASE', (persona, persona))
        return cur.rowcount

    def drop_old_playing(self):
        self.run('DELETE FROM playing WHERE started < ?',
                 (time.time() - self.MATCH_MAX_AGE,))

    MAX_ACTIVITY = 400

    def note(self, kind, text, who=''):
        """Add a line to the live feed, and keep it short."""
        self.run('INSERT INTO activity (at, kind, who, text)'
                 ' VALUES (?, ?, ?, ?)', (time.time(), kind, who, text))
        self.run('DELETE FROM activity WHERE id NOT IN'
                 ' (SELECT id FROM activity ORDER BY id DESC LIMIT ?)',
                 (self.MAX_ACTIVITY,))

    def activity(self, limit=30, kinds=None):
        if kinds:
            marks = ','.join('?' * len(kinds))
            return [dict(r) for r in self.query(
                'SELECT * FROM activity WHERE kind IN (%s)'
                ' ORDER BY id DESC LIMIT ?' % marks, tuple(kinds) + (limit,))]
        return [dict(r) for r in self.query(
            'SELECT * FROM activity ORDER BY id DESC LIMIT ?', (limit,))]

    def stats(self):
        """Everything worth putting on a status board, in one pass.

        Read-only and cheap enough to render on every page load: the tables
        here are small, and a server with a thousand rounds on it still answers
        in a few milliseconds.
        """
        now = time.time()
        one = lambda sql, args=(): (self.one(sql, args) or {'n': 0})['n']  # noqa: E731

        out = {
            'accounts': one('SELECT COUNT(*) AS n FROM accounts'),
            'personas': one('SELECT COUNT(*) AS n FROM personas'),
            'golfers': one('SELECT COUNT(*) AS n FROM golfers'),
            'sessions': one('SELECT COUNT(*) AS n FROM sessions'),
            'rounds': one('SELECT COUNT(*) AS n FROM tourney'),
            'events': one('SELECT COUNT(*) AS n FROM events'),
        }

        # Signed in lately.  `personas.last_seen` is stamped when the console
        # picks a persona, so this is "played recently" rather than "connected
        # right now" -- the lobby's live list is in another process.
        out['recent'] = one(
            'SELECT COUNT(*) AS n FROM personas WHERE last_seen > ?',
            (now - 7 * 24 * 3600,))
        row = self.one('SELECT MAX(last_seen) AS n FROM personas')
        out['last_seen'] = row['n'] if row else None

        # Head-to-head totals, from the matches that actually resolved.
        totals = dict.fromkeys(('matches', 'holes', 'strokes', 'birdies',
                                'eagles', 'aces'), 0)
        best_round = longest_drive = longest_putt = 0
        for m in self.matches(limit=500):
            totals['matches'] += 1
            for pl in m['players']:
                if not pl['done'] or pl['quit']:
                    continue
                for k in ('holes', 'strokes', 'birdies', 'eagles', 'aces'):
                    totals[k] += pl[k]
                longest_drive = max(longest_drive, pl['longest'])
                longest_putt = max(longest_putt, pl['longest_putt'])
                if pl['strokes'] and pl['holes'] == 18:
                    best_round = (pl['strokes'] if not best_round
                                  else min(best_round, pl['strokes']))
        out.update(totals)
        out['longest_drive'] = longest_drive
        out['longest_putt'] = longest_putt

        # Tournament totals, and the best round anywhere.
        for r in self.query('SELECT strokes, fields FROM tourney'):
            f = json.loads(r['fields'])
            if f.get('HOLES') == 18 and r['strokes']:
                best_round = (r['strokes'] if not best_round
                              else min(best_round, r['strokes']))
            longest_drive = max(longest_drive, f.get('LDRV', 0))
            longest_putt = max(longest_putt, f.get('LPUT', 0))
            # Tournament rounds count towards the totals too.  Leaving them out
            # meant a server that only ever played tournaments reported no
            # eagles and no holes at all.
            out['holes'] += f.get('HOLES', 0)
            out['strokes'] += r['strokes']
            out['birdies'] += f.get('BIRD', 0)
            out['eagles'] += f.get('EAGS', 0)
            out['aces'] += f.get('ACES', 0)
        out['best_round'] = best_round
        out['longest_drive'] = longest_drive
        out['longest_putt'] = longest_putt

        row = self.one('SELECT course, COUNT(*) AS n FROM tourney'
                       ' GROUP BY course ORDER BY n DESC LIMIT 1')
        out['top_course'] = (row['course'], row['n']) if row else None
        row = self.one('SELECT MIN(created) AS n FROM accounts')
        out['since'] = row['n'] if row and row['n'] else None

        # The live half: what the lobby is doing this second, as opposed to
        # what it has ever done.
        up, age = self.server_is_up()
        here = self.online()
        out['up'] = up
        out['heartbeat_age'] = age
        out['online'] = len(here) if up else 0
        out['in_game'] = len(self.playing()) if up else 0
        started, _at = self.get_live('started')
        out['lobby_started'] = float(started) if started else None
        out['lobby_uptime'] = (now - float(started)) if started and up else None
        peak, _at = self.get_live('peak_online')
        out['peak_online'] = int(peak) if peak else 0
        out['course_pars'] = self.course_pars()
        return out

    def tourney_place(self, persona, day):
        """(place, entrants) for a persona on a day, or (0, n) if absent."""
        board = self.tourney_day(day, limit=1000)
        for n, row in enumerate(board, 1):
            if row['name'] == persona:
                return n, len(board)
        return 0, len(board)

    def leaderboard(self, limit=50, kind=None, since=None):
        """Every persona that has finished a match, best first.

        `kind` keeps only one game type -- rooms are named "<type>.<id>.<name>"
        and the type is literally "Match" or "Stroke", so the room a match was
        brokered in is what decides which board it belongs on.

        `since` is an epoch cutoff against the time the RESULT ARRIVED, not the
        `WHEN` the console reported: the client's clock is whatever the console
        is set to and two consoles in one match rarely agree, while the receipt
        time is the server's own.
        """
        table = {}
        for m in self.matches(limit=500):
            if kind and not (m['room'] or '').startswith(kind):
                continue
            if since is not None and (m['received'] or 0) < since:
                continue
            for p in m['players']:
                if not p['done'] or p['quit']:
                    continue
                e = table.setdefault(p['name'], {
                    'name': p['name'], 'played': 0, 'won': 0, 'lost': 0,
                    'tied': 0, 'strokes': 0, 'holes': 0, 'putts': 0,
                    'birdies': 0, 'eagles': 0, 'aces': 0, 'longest': 0})
                e['played'] += 1
                if m['winner'] is None:
                    e['tied'] += 1
                elif m['winner'] == p['name']:
                    e['won'] += 1
                else:
                    e['lost'] += 1
                for k in ('strokes', 'holes', 'putts', 'birdies', 'eagles', 'aces'):
                    e[k] += p[k]
                e['longest'] = max(e['longest'], p['longest'])
        rows = list(table.values())
        for e in rows:
            # Strokes per hole is the only cross-comparable number here: rounds
            # differ in length (a Front 9 is nine holes, not eighteen).
            e['per_hole'] = (e['strokes'] / e['holes']) if e['holes'] else 0.0
        rows.sort(key=lambda e: (-e['won'], e['per_hole'] or 999))
        return rows[:limit]


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--db', default=DEFAULT_DB)
    ap.add_argument('--create-account', metavar='NAME')
    ap.add_argument('--password')
    ap.add_argument('--persona', help='first persona (default: the account name)')
    ap.add_argument('--mail', default='')
    ap.add_argument('--add-persona', nargs=2, metavar=('ACCOUNT', 'PERSONA'))
    ap.add_argument('--set-password', nargs=2, metavar=('ACCOUNT', 'PASSWORD'))
    ap.add_argument('--disable', metavar='ACCOUNT')
    ap.add_argument('--enable', metavar='ACCOUNT')
    ap.add_argument('--list', action='store_true')
    args = ap.parse_args()

    db = DB(args.db)
    try:
        if args.create_account:
            if not args.password:
                raise Error('--create-account needs --password')
            db.create_account(args.create_account, args.password, mail=args.mail,
                              persona=args.persona)
            print('created %r with persona %r'
                  % (args.create_account, args.persona or args.create_account))
        if args.add_persona:
            account, persona = args.add_persona
            row = db.account(account)
            if not row:
                raise Error('no such account %r' % account)
            db.add_persona(row['id'], persona)
            print('added persona %r to %r' % (persona, account))
        if args.set_password:
            account, password = args.set_password
            row = db.account(account)
            if not row:
                raise Error('no such account %r' % account)
            db.set_password(row['id'], password)
            print('password changed for %r' % account)
        for flag, value in ((args.disable, 1), (args.enable, 0)):
            if flag:
                db.run('UPDATE accounts SET disabled = ? WHERE name = ?',
                       (value, flag))
                print('%s %r' % ('disabled' if value else 'enabled', flag))
        if args.list or not any((args.create_account, args.add_persona,
                                 args.set_password, args.disable, args.enable)):
            rows = db.query('SELECT * FROM accounts ORDER BY id')
            if not rows:
                print('no accounts yet in %s' % args.db)
            for row in rows:
                print('%-20s %-28s %s%s'
                      % (row['name'], ', '.join(db.personas(row['id'])),
                         row['mail'], '  [disabled]' if row['disabled'] else ''))
    except Error as exc:
        print('error: %s' % exc)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
