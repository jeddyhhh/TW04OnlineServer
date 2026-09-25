"""The TW04 master server: lobby, rooms, matchmaking and results.

    python lobbyd.py

Two consoles can log in, see each other, create and join rooms, chat, challenge
each other, get handed each other's address for the peer-to-peer game, and
report the round afterwards.  Accounts live in twdb.py, shared with the
sign-up site in webui.py.

It began as a measuring instrument and can still log every frame in both raw
and decoded form (-v), which is how the protocol was worked out.  Replies that
are still guesses say so in the handler that sends them.

PASSWORDS ARE NOT LOGGED.  Neither the plaintext nor the ciphertext -- with the
session key being a fixed constant below, one is as good as the other.
--log-passwords turns that off for working on the cipher; it writes real
credentials into a plain file, so use it against accounts you own and delete
the log afterwards.
"""
import argparse
import binascii
import collections
import json
import os
import random
import re
import secrets
import socket
import socketserver
import struct
import sys
import threading
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import eacrypt
import tagfield
import twdb
import twlog
import twrecords
import twstats
import twtourney

HDR = 12

# The one log -- see twlog.  Until main() opens it, lines only go to stdout.
LOG = twlog.Log(echo=True)
# Beside data/, like the database: logs/lobbyd.log in the project, or in the
# folder a deployment was copied to.
DEFAULT_LOG = os.path.join(os.path.dirname(os.path.dirname(twdb.DEFAULT_DB)),
                           'logs', 'lobbyd.log')

# Optional hint written by tools/setup_pcsx2.py; only the pcsx2 path is trusted
# from it, because the endpoint is read from the .pnach itself below.
# Only in the development project, where this file sits in tools/ beside
# notes/; a deployed or cloned copy has no such file and must not go looking
# outside its own folder for one.
_MOD_DIR = os.path.dirname(os.path.abspath(__file__))
RIG = (os.path.join(os.path.dirname(_MOD_DIR), 'notes', 'rig.json')
       if os.path.basename(_MOD_DIR) == 'tools' else None)


PNACH_IP = 0x0030FAC0        # the lobby address string in the TW04 ELF
PNACH_PORT = 0x0030FAD0      # the lobby port string


def rig_config():
    """Where the game will actually dial.

    Read straight out of the installed .pnach -- the same file PCSX2 loads --
    rather than trusting a side-car record, which can go stale the moment the
    patch is regenerated with different options.  That exact staleness caused a
    port mismatch in both directions on 2026-09-17.
    """
    cfg = {}
    try:
        if RIG:
            with open(RIG, encoding='utf-8') as f:
                cfg = json.load(f)
    except Exception:                                  # noqa: BLE001 - optional
        pass

    # Only on a machine that is also running the game: rig.json (written by
    # tools/setup_pcsx2.py) or TW_PCSX2 names the PCSX2 folder.  A standalone
    # server has neither, and simply uses --port.
    pcsx2 = cfg.get('pcsx2') or os.environ.get('TW_PCSX2')
    if not pcsx2:
        return cfg
    pnach = os.path.join(pcsx2, 'cheats', 'SLUS-20757_64F9781E.pnach')
    try:
        with open(pnach, encoding='utf-8') as f:
            text = f.read()
    except OSError:
        return cfg

    words = {int(a, 16): int(v, 16) for a, v in
             re.findall(r'^patch=1,EE,([0-9A-Fa-f]{8}),word,([0-9A-Fa-f]{8})',
                        text, re.M)}

    def string_at(base, nwords):
        raw = b''.join(words.get(base + 4 * i, 0).to_bytes(4, 'little')
                       for i in range(nwords))
        return raw.split(b'\0')[0].decode('latin-1')

    ip = string_at(PNACH_IP, 4)
    # No port patch means the game keeps its built-in 10200.
    port = string_at(PNACH_PORT, 2) or '10200'
    if ip:
        cfg = dict(cfg, ip=ip, port=int(port), source=pnach)
    return cfg


ARGS = None
DB = None
# The day the --probe-conditions layout counts from: the server's today when it
# started, so the layout cannot slide under a session that runs past midnight.
PROBE_ANCHOR = None

# Error codes travel in the frame header's SECOND word -- what we have been
# calling `ident` -- not in the body.  0x002BB994 copies it straight into the
# request record at +0x08, and every callback tests that word first:
# _AuthCallback bails at 0x002875C0, _ChalCallback at 0x002894B4.  Zero means
# success, which is why echoing the request's ident has always read as OK.
#
# _RegisterCallback knows `dupl`, `tooy` and `pmal` by name (0x00287818
# onwards).  The rest are ours: _AuthCallback has no table and simply formats
# whatever code it is given into a dialog, so a readable 4CC is the friendliest
# thing to send.
ERR_DUPLICATE = 'dupl'      # 0x00287818 -- that account name is taken
ERR_NO_USER = 'nusr'        # no account by that name
ERR_BAD_PASSWORD = 'badp'   # wrong password
ERR_DISABLED = 'bann'       # account disabled
ERR_NO_PERSONA = 'nper'     # that persona is not on this account

# persona -> (addr, port) for everyone currently logged in.  The real lobby
# clearly keeps this: `sele` subscribes to ROOMS/GAMES/USERS/RANKS/MESGS, which
# only means anything if the server pushes those lists back.
ONLINE = {}

# Rooms the clients have created via `Lobby_CreateRoom`, and every live
# connection, so a created room can be pushed to everyone rather than just its
# author.
CREATED = []
MAX_CREATED_ROOMS = 64          # player-made rooms kept; see on_room
CONNS = set()

# persona -> the room it is currently in, from `move`.
WHERE = {}

# persona -> the opponent it just agreed a match with, from `chal`.
MATCHED = {}

# frozenset({a, b}) -> the match settings from the challenge that set it up.
#
# `rank` carries no course and no conditions -- those are only ever stated in
# the challenge, several minutes earlier.  Catch them there or lose them.
PENDING_SETUP = {}

# frozenset({a, b}) -> the session already pushed to that pair.
#
# `start_session` MUST be idempotent.  Both clients send `chal` when a challenge
# is accepted, and either one can complete the pair, so the naive version fired
# twice and minted a fresh random SEED each time -- two `+ses` pushes per client
# carrying DIFFERENT seeds:
#
#   14:51:18 SESSION 'Match.C.hhhhh': host=jed2 vs ooo, seed=242048934
#   14:51:18 SESSION 'Match.C.hhhhh': host=jed2 vs ooo, seed=1748185401
#
# Whichever each console ended up keeping was a coin flip, and two consoles
# playing the same hole off different seeds is a desync waiting for the first
# shot.  Deciding the session once and replaying the same record is the fix.
SESSIONS = {}

# persona -> the host-side source address of that persona's lobby connection.
# Needed because what the client reports in `addr` is its own view of itself,
# which under the Sockets backend is 192.0.2.100 for every instance.  The source
# address of its TCP connection, by contrast, is the host NIC its emulator is
# bound to -- which is exactly what the other console has to dial.
REACH = {}

# EA Messenger login keys live in the database (`twdb` `lkeys`), one per
# persona, minted at `pers`.
#
# The Messenger client logs in with nothing but this key: `_PersCallback`
# (0x00287BB0) keeps the `LKEY` from the `pers` reply and the buddy connect call
# (0x002C2B60) sends it as `AUTH LKEY=` with the fixed `USER=/cso/tiger-ps2-2004`.
# So the key IS the identity on that connection, and has to be unguessable --
# the old `lkey-<persona>` let anyone who could type claim anyone.
#
# NOT in memory: a console keeps its Messenger session across a lobbyd
# RESTART and reconnects with the key it already holds.  A restarted process
# that had forgotten it refused the login, and the game answered by showing
# its buddy list as blank "offline" rows that froze the emulator when removed.

# The chat this server has relayed recently -- lobby room chat, lobby private
# chat and EA Messenger messages -- so that REPORT ABUSE can attach it.  The
# game promises the reporter "a copy of the chat log will be sent to customer
# service", but the `rept` request itself carries nothing but the name
# (0x00275430), so the only copy there is is ours.  Memory only, and bounded:
# nothing is written anywhere unless somebody files a report.
CHATLOG = collections.deque(maxlen=2000)
REPORT_WINDOW = 3600            # seconds of chat attached to a report
REPORT_LINES = 60               # at most this many lines of it
REPORT_REPEAT = 600             # one report per reporter per accused per this

# (reporter, accused) -> when they last reported them, to stop a flood.
REPORTED = {}


def record_chat(frm, text, to='', room='', via='room'):
    CHATLOG.append({'at': time.time(), 'from': frm or '', 'to': to or '',
                    'room': room or '', 'via': via, 'text': text})


def chat_for_report(reporter, accused, now=None):
    """What goes into a report: everything the accused said in a room, and
    every private or Messenger line between the two, within the window."""
    now = now or time.time()
    lo = accused.lower()
    pair = {reporter.lower(), lo}
    keep = []
    for line in CHATLOG:
        if now - line['at'] > REPORT_WINDOW:
            continue
        frm, to = line['from'].lower(), line['to'].lower()
        if line['via'] == 'room' and frm == lo:
            keep.append(line)
        elif line['via'] != 'room' and {frm, to} == pair:
            keep.append(line)
    return keep[-REPORT_LINES:]


# Live EA Messenger connections, for the keepalive.
BUDDY_CONNS = set()

# persona -> its signed-in EA Messenger connection: who can be told about,
# and who can be sent a message.
MESSENGER = {}

# PCSX2's Sockets DEV9 backend runs a userspace stack behind a virtual DHCP
# server that hands out 192.0.2.100/24 -- the same address to EVERY instance.
# So a peer that reports 192.0.2.100 is reporting an address that, from the
# other console, means "me".  Sending that on in `+ses` tells each client to
# connect to itself.
PCSX2_VIRTUAL = '192.0.2.'


def dotted_quad(addr):
    """An address the GAME can use, or None.

    TW04 has no IPv6 anywhere.  The lobby address is a 15-character field in
    the ELF parsed with `%d.%d.%d.%d` (0x00310FD0), and the peer address in
    `+ses ADDR` travels the same way, so anything that is not a dotted quad is
    not representable at all.

    A connection accepted on a dual-stack socket reports an IPv4 peer as
    `::ffff:192.0.2.1`.  That is an IPv4 address wearing a v6 hat and unwraps
    cleanly.  A genuine IPv6 address does not, and returns None rather than
    something that would reach the console as garbage and be parsed as a
    number anyway.
    """
    if not addr:
        return None
    if addr.startswith('::ffff:') and addr.count('.') == 3:
        return addr[len('::ffff:'):]
    if ':' in addr:
        return None
    return addr


def peer_address(peer):
    """The address to hand the OTHER player for the peer-to-peer leg."""
    addr, port = ONLINE.get(peer) or ('', '')
    # A client that never got through `addr` leaves (None, None) here, and an
    # unguarded .startswith() on that killed the handler thread mid-session --
    # the session was minted, nothing was pushed, and the connection just died.
    addr, port = addr or '', port or ''
    if ARGS.peer_addr:
        return ARGS.peer_addr, port
    if addr.startswith(PCSX2_VIRTUAL):
        # Substitute the address that console's own traffic comes from, i.e.
        # the host NIC its emulator is bound to.  Confirmed working: the client
        # built "192.168.1.50:3658:3658" at 0x0036D8C0 out of this and went
        # in-game.  Two instances on the SAME host address then collide on UDP
        # 3658, the game's fixed peer-to-peer port, so they need different
        # adapters, and this picks each one up automatically.
        return REACH.get(peer, addr), port
    return addr, port


# ---------------------------------------------------------------------------
# The 60-second idle disconnect, and how to stop it
#
# Read out of LobbyApiUpdate (0x002BB830, epilogue at 0x002BD0DC):
#
#   0x002BB86C  s6 = NetTick()                      ; milliseconds
#   0x002BB88C  v0 = [api+0x14]                     ; tick of the last update
#   0x002BB894  v1 = now - v0
#   0x002BB898  if v1 >= 5001:                      ; a stall (load screen, a
#   0x002BB8A8      [api+0x10] += v1                ; modal dialog) is forgiven
#   0x002BB8AC  v0 = [api+0x10]                     ; the idle DEADLINE
#   0x002BB8B0  if v0 - now < 0:
#   0x002BB8C8      Disconnect(api, 'time', 0x800)  ; <-- this is the dropout
#
# and, in the receive loop:
#
#   0x002BD084  v0 = 0xEA60                         ; 60000 ms
#   0x002BB914  v0 += now
#   0x002BB924  [api+0x10] = v0                     ; in the BNE's delay slot,
#                                                   ; so EVERY inbound frame
#                                                   ; refreshes the deadline
#
# So the cure is to make sure the client hears something inside every 60 s
# window.  The client already has a verb for exactly that: at 0x002BB920 an
# inbound `~png` is intercepted before the normal dispatch and echoed straight
# back with a TIME field (0x002BB958) -- a server-initiated keepalive.  The
# client also has its own 30 s outbound ping (`_SendPing`, 0x002BB7F8,
# rescheduled with +0x7530 at 0x002BD0AC) but only runs it when [api+0x18] is
# non-zero, which it is not on this path -- hence the silence.
PING = threading.Event()
CALENDAR = threading.Event()


def ensure_season():
    """Generate the months the SERVER thinks exist, and no others.

    Deliberately not driven by requests.  `START` on a `mg5ri` is whatever the
    console's clock says, and a console's clock is the player's to set -- so
    generating on demand let anyone mint next year's calendar by winding their
    PS2 forward, and then enter those events.  Generation is the server's
    decision, taken on the server's clock.

    A month outside the horizon simply has no events, and the calendar draws
    empty cells for it.
    """
    made = []
    year, month = twtourney.month_of(twtourney.today())
    for _ in range(ARGS.months + 1):
        first, length = twtourney.month_days(year, month)
        if not DB.month_generated(first, length):
            DB.add_events(twtourney.generate_month(year, month, twstats.COURSES))
            made.append('%04d-%02d' % (year, month))
        year, month = year + (month == 12), month % 12 + 1
    if made:
        log('***', 'tournament calendar generated for %s' % ', '.join(made))
        note('calendar', 'the tournament calendar was drawn up for %s'
             % ', '.join(made))
    repair_calendar()
    reprice_calendar()
    return made


def repair_calendar():
    """Replace scheduled events on a course that cannot be played.

    The rotation is a list that can be wrong -- Skillz was in it, and is the
    skills-challenge venue rather than a golf course.  Months are generated
    once and kept, so correcting the list does not correct a calendar already
    written; this does.

    Only days from today onward, and only the offending day.  Regenerating the
    month would be simpler and would rewrite events people have already played
    or looked at, and results point at them by name.
    """
    bad = DB.events_with_course(twtourney.UNPLAYABLE_COURSES, twtourney.today())
    for event in bad:
        fixed = twtourney.replace_course(event['day'], twstats.COURSES)
        DB.replace_event(event['day'], fixed['name'], fixed['course'])
        log('!!!', 'rescheduled %s: %s was not playable, now %s'
            % (twtourney.from_day(event['day']),
               twstats.course_name(event['course']),
               twstats.course_name(fixed['course'])))
    return bad


def reprice_calendar():
    """Bring stored events up to the current rules: conditions (tees, rough,
    fairways, greens) and a purse from the course and those conditions --
    twtourney.event_conditions and event_purse.

    Months are generated once and kept, so a new rule reaches a calendar that
    already exists only through here.  From today onward, and never on a day
    somebody has played (twdb.refresh_events).  An event that already has
    conditions keeps them; one that has none gets its day's draw -- except
    TODAY's, which keeps the game's defaults, because it may already be being
    played on them.  Idempotent: once the calendar agrees, it changes nothing
    and says nothing."""
    today = twtourney.today()

    def plan(event):
        conditions = event['conditions']
        if not conditions and event['day'] > today:
            conditions = twtourney.event_conditions(event['day'])
        return conditions, twtourney.event_purse(event['course'], conditions)

    changed = DB.refresh_events(today, plan)
    for event, conditions, purse in changed[:5]:
        log('***', 'updated %s at %s: %s, $%s -> $%s'
            % (twtourney.from_day(event['day']),
               twstats.course_name(event['course']),
               twtourney.describe_conditions(conditions),
               format(event['purse'], ','), format(purse, ',')))
    if len(changed) > 5:
        log('***', '... and %d more upcoming events updated' % (len(changed) - 5))
    if changed:
        note('calendar', 'upcoming tournaments now have course conditions, and '
             'purses to match (%d events updated)' % len(changed))
    return changed


def backup_tick():
    """A copy of the database once a day, in --backup-dir, keeping
    --backup-keep of them.  Checked hourly, and once at startup, so a server
    restarted every day still makes its copy."""
    while True:
        try:
            made = DB.backup(ARGS.backup_dir, ARGS.backup_keep)
            if made:
                log('***', 'backed up the database to %s' % made)
        except Exception as exc:                       # noqa: BLE001 - a tick
            log('!!!', 'database backup failed: %s' % exc)  # must never die
        if CALENDAR.wait(3600):
            return


def calendar_tick():
    """Roll the calendar forward on the server's clock.

    Long period on purpose: the only thing this has to catch is the turn of a
    month, and it already runs once at startup.  Checking every few minutes
    means a server left running through midnight on the 31st has the new month
    before anyone can ask for it.
    """
    while not CALENDAR.wait(ARGS.calendar_tick):
        try:
            ensure_season()
        except Exception as exc:                       # noqa: BLE001 - a tick
            log('!!!', 'calendar tick failed: %s' % exc)   # must never die


def keepalive():
    '''Push `~png` to every live connection well inside the client's 60 s
    deadline.  Any inbound frame would do, but `~png` is the one the client
    answers, so the log shows both halves and proves it is being pumped.'''
    while not PING.wait(ARGS.ping):
        for h in list(CONNS):
            try:
                h.send('~png', 0, {})
            except OSError:
                CONNS.discard(h)


# The rooms offered on the GAME LOBBIES screen.  A room is `<type>.<id>.<name>`
# and only the TYPE is ever read back -- `match['room'].startswith('Match')` is
# what decides which leaderboard a result belongs on -- so the name is free to
# change without touching anything already recorded.  The ids were TIGERC,
# which spelled something but told a player nothing.
# THE IDS ARE NOT OURS TO CHOOSE.  The client has ten prefixes compiled in, as
# a pointer table at 0x00303820:
#
#     Stroke.T.  Stroke.I.  Stroke.G.  Stroke.E.  Stroke.R.
#     Match.T.   Match.I.   Match.G.   Match.E.   Match.R.
#
# Five per type, and no `C` -- which is why a sixth room was pushed every time
# and never appeared on the GAME LOBBIES screen.  Adding more is not possible
# from this side; the letters are the set.
#
# `Match.T.East1` and `Stroke.T.East1` are also in the image, at 0x00311080, as
# EA's own defaults.  So "East" is their name for the T room, not an invention.
ROOMS = (
    ('T', 'East'),
    ('I', 'West'),
    ('G', 'Beginner'),
    ('E', 'Advanced'),
    ('R', 'Open'),
)


def default_rooms():
    """Every room, in both game types.  Match play and stroke play get the same
    set because the client picks the type first and then the room."""
    return ['%s.%s.%s' % (kind, ident, name)
            for kind in ('Match', 'Stroke')
            for ident, name in ROOMS]


def broadcast_rooms():
    for h in list(CONNS):
        try:
            h.push_rooms()
        except OSError:
            CONNS.discard(h)


def push_to(persona, kind, tags):
    """Send one frame to one persona's connection."""
    for h in list(CONNS):
        if h.persona == persona:
            try:
                h.send(kind, 0, tags)
                return True
            except OSError:
                CONNS.discard(h)
            return False
    log('!!!', '    %r is not connected' % persona)
    return False


def start_session(a, b):
    """Push `+ses` to both halves of an agreed match.

    `+ses` is the match-start push.  Its handler is inline in the connection
    layer at 0x002BBEF4 (reached from the `bne` at 0x002BBEF0) and it stashes
    thirteen fields on the API handle before calling the lobby's slot-4
    callback:

        NAME  api+0x200  32   SELF  api+0x220  32   HOST  api+0x240  32
        OPPO  api+0x260  32   P1..P4 api+0x280.. 16 each
        ADDR  api+0x2C0  parsed as a dotted quad by 0x002BF270
        FROM  api+0x2C4  SEED  api+0x2C8  WHEN  api+0x2CC  AUTH  api+0x2D0  64

    then sets `api+0x08 |= 0x200` and calls `[api+0x538]` -- registered as
    0x00273470 by Lobby_Init at 0x0027483C -- with a record whose kind is
    'play'.  That callback re-reads **FROM** and **ADDR** as 32-byte strings
    and strcpy's them into a peer record at +0x20 and +0x40 (0x0028B210,
    0x0028B260), then sets bit 0x10 of the challenge state word at gp-0x66F8.

    So the two fields that actually matter are `FROM` (the peer's name) and
    `ADDR` (the peer's dotted-quad address).  There is no PORT here; the P2P
    port is the one each client volunteered in its own `addr` request.

    `WHEN` is read by 0x002BFD80, which tests for a leading '$' -- it is a
    binary field, not a number.  The rest are best-guess and the client will
    say if they are wrong.
    """
    ma, mb = MATCHED.get(a), MATCHED.get(b)
    if not (ma and mb):
        return

    pair = frozenset((a, b))
    session = SESSIONS.get(pair)
    if session is None:
        host = a if ma['host'] else b
        other = b if host == a else a
        name = WHERE.get(a) or WHERE.get(b) or 'match'
        session = {
            'host': host,
            'other': other,
            'seed': random.randrange(1, 0x7FFFFFFF),
            'when': struct.pack('>Q', int(time.time())),
            'name': name,
            # A token unique to THIS match.  The client hands it straight back
            # in the `rank` result (AUTH), which is the only thing tying a
            # result to a pairing the server actually brokered -- and the only
            # way to know which of the two numbered columns is whose.  It used
            # to be the constant 'tw04-local', so every match in the database
            # looked like the same one.
            'auth': secrets.token_hex(8),
        }
        SESSIONS[pair] = session
        # Results turn up long after both consoles have disconnected, so the
        # pairing has to outlive this process's memory of it.
        # pop, not get: a stale setup from an abandoned challenge must not
        # attach itself to a later match between the same two players.
        setup = PENDING_SETUP.pop(pair, None)
        DB.add_session(session['auth'], name, host, other, session['seed'],
                       setup=setup)
        log('***', '    SESSION %r: host=%s vs %s, seed=%d'
            % (session['name'], session['host'], session['other'], session['seed']))
        # Tell the web site a match is under way.  The course is only ever
        # stated in the challenge, which is what `setup` is -- there is
        # nothing in `+ses` that names it.
        try:
            course = int((setup or {}).get('COUR', -1))
        except (TypeError, ValueError):
            course = -1
        try:
            DB.start_playing(session['auth'], name, host, other,
                             kind=name.split('.')[0], course=course)
        except Exception as exc:                        # noqa: BLE001
            log('!!!', '    could not record the match as live: %s' % exc)
        note('match', '%s and %s teed off in %s'
             % (host, other, room_label(name) or name), who=host)
        publish_live()
    else:
        log('***', '    session for %s/%s already decided (seed=%d) -- not '
            're-pushing' % (a, b, session['seed']))
        return

    host, other = session['host'], session['other']
    seed, when, name = session['seed'], session['when'], session['name']
    log('***', '    match token %s' % session['auth'])
    # Both consoles resolving to the SAME address means they are behind one
    # NAT and the server is on the far side of it.  The game does no hole
    # punching: it dials the literal address it is handed, so each console
    # ends up sending to its own public IP and the router has to hairpin it
    # back.  Plenty do not, and the symptom is a match that is agreed in the
    # lobby and then never starts -- with nothing in this log to say why.
    ends = {p: peer_address(p)[0] for p in (a, b)}
    if ends[a] and ends[a] == ends[b]:
        log('!!!', '    %s and %s both resolve to %s -- they are behind the '
                   'same NAT as far as this server can see, so the peer-to-'
                   'peer leg needs the router to hairpin.  If the match never '
                   'starts, that is why; run the lobby on their LAN or use '
                   '--peer-addr.' % (a, b, ends[a]))

    for me, peer in ((a, b), (b, a)):
        addr, port = peer_address(peer)
        if not addr:
            log('!!!', '    no endpoint known for %s -- +ses will be useless' % peer)
        push_to(me, '+ses', {
            'NAME': name,
            'SELF': me,
            'HOST': host,
            'OPPO': peer,
            'P1': host,
            'P2': other,
            'FROM': peer,
            'ADDR': addr or '0.0.0.0',
            'SEED': str(seed),
            'WHEN': when,
            'AUTH': session['auth'],
        })
        log('***', '    +ses to %s: peer %s at %s:%s' % (me, peer, addr, port))


def broadcast_users(room):
    '''Re-push the occupant list of `room` to everyone who is in it.

    `push_users` on its own only ever reaches the connection that asked, which
    is right for `peek` (the browser asking about a room you are not in) and
    wrong for everything else: the host of a room never sends `move`, so it
    never asked, so its own PLAYER column stayed empty while the joiner could
    see itself.  Membership changes have to reach every member.
    '''
    if not room:
        return
    here = Handler.occupants(room)
    for h in list(CONNS):
        if h.persona and WHERE.get(h.persona) == room:
            try:
                h.push_users(here)
            except OSError:
                CONNS.discard(h)


# ---------------------------------------------------------------------------
# THE LIVE PICTURE
#
# Everything this server knows about who is on it lives in module globals --
# ONLINE, WHERE, SESSIONS -- and the web site is a different process that
# cannot see a single one of them.  So the picture is mirrored into the
# database, which both already open, and the site reads it from there.
#
# It is written whole rather than incrementally.  Incremental updates have to
# be right at every one of a dozen call sites and are wrong the moment one is
# missed; recomputing the lot from the globals is right whenever it runs, and
# it runs after anything that could have changed them.  The tables are tiny.
#
# Nothing here may raise.  A web site that cannot be updated is a cosmetic
# problem; a lobby connection that dies because of one is not.

PEAK_ONLINE = [0]


def room_label(room):
    """`Match.T.East` -> `East (match play)`, for people rather than parsers."""
    if not room:
        return ''
    parts = room.split('.')
    if len(parts) != 3:
        return room
    kind, _ident, name = parts
    return '%s (%s play)' % (name, kind.lower())


def live_state(persona):
    """(state, detail) for one player: what they are doing, in two words."""
    for pair in SESSIONS:
        if persona in pair:
            other = next(iter(pair - {persona}), '')
            return 'playing', 'vs %s' % other
    if MATCHED.get(persona):
        return 'matched', 'vs %s' % (MATCHED[persona].get('opp') or '')
    return 'lobby', room_label(WHERE.get(persona, ''))


def publish_live():
    """Mirror ONLINE / WHERE / SESSIONS into the database for the web site.

    Plus everyone in a match still in play.  Two consoles that have connected
    to each other leave the lobby -- that is what starting a match looks like
    from here -- but they are still on the server as far as anyone reading
    the site is concerned, so they stay listed as playing until the match is
    over (see `end_matches` and twdb.playing).
    """
    if DB is None:
        return
    try:
        here = sorted(ONLINE)
        for persona in here:
            state, detail = live_state(persona)
            DB.set_presence(persona, room=WHERE.get(persona, ''),
                            state=state, detail=detail)
        DB.drop_old_playing()
        away = {}
        for m in DB.playing():
            for me, opp in ((m['host'], m['guest']), (m['guest'], m['host'])):
                if me not in ONLINE:
                    away[me] = (opp, m['room'])
        for persona, (opp, room) in sorted(away.items()):
            DB.set_presence(persona, room=room, state='playing',
                            detail='vs %s' % opp)
        shown = here + sorted(away)
        DB.keep_presence(shown)
        DB.touch_presence(shown)
        if len(shown) > PEAK_ONLINE[0]:
            PEAK_ONLINE[0] = len(shown)
            DB.set_live('peak_online', PEAK_ONLINE[0])
        DB.set_live('online', len(shown))
        DB.note_online(len(shown))          # today's peak, for the stats chart
        DB.set_live('heartbeat', int(time.time()))
    except Exception as exc:                            # noqa: BLE001
        log('!!!', '    could not publish the live picture: %s' % exc)


def end_matches(persona, why):
    """`persona` is back in the lobby, so any match they were in is over --
    with a result or without one.  Never fatal."""
    if DB is None or not persona:
        return
    try:
        n = DB.end_playing_for(persona)
    except Exception as exc:                            # noqa: BLE001
        log('!!!', '    could not close %s\'s match: %s' % (persona, exc))
        return
    if n:
        log('***', '    %s %s -- their match is no longer in play'
            % (persona, why))
        publish_live()


def note(kind, text, who=''):
    """One line for the web site's activity feed.  Never fatal."""
    if DB is None:
        return
    try:
        DB.note(kind, text, who=who)
    except Exception as exc:                            # noqa: BLE001
        log('!!!', '    could not record activity: %s' % exc)


def heartbeat():
    """Keep the live picture fresh even when nothing is happening.

    Separate from `keepalive` because that one is switched off by `--ping 0`,
    and a server with no clients on it still needs to be saying that it is up.
    """
    while not PING.wait(HEARTBEAT_SECONDS):
        publish_live()


HEARTBEAT_SECONDS = 30


# persona -> the CRPIN blob its client uploaded via `cusr whomi`.  That is the
# Create-A-Player record; the other player's client asks for it with `user`.
CRPIN = {}

# The 16 bytes we hand the client in SKEY.  The server chooses them, which is
# what lets it decrypt PASS.
#
# THE FIRST BYTE MUST NOT BE ZERO.  LobbyApiRequest decides which password path
# to take with `lb $v1, 0x24($s1); bnez $v1, ...` at 0x002BAE88 -- and handle
# +0x24 is the key buffer itself, so the test is literally "is byte 0 of the key
# non-zero", not "did a key arrive".  A key starting 00 makes the client fall
# back to the public-key path and send PASS as raw $hex instead of the ~-prefixed
# symmetric form.  Cost one capture run to find.
SESSION_KEY = bytes.fromhex('a1b2c3d4e5f60718293a4b5c6d7e8f90')
assert SESSION_KEY[0] != 0, 'first byte of the session key must be non-zero'
assert len(SESSION_KEY) == 16


def cc(value):
    b = value.to_bytes(4, 'big')
    return b.decode('ascii') if all(0x20 <= c < 0x7F for c in b) else '0x%08x' % value


def cc2i(text):
    return int.from_bytes(text.encode('ascii'), 'big')


def log(direction, text):
    LOG.write('%s %s %s' % (time.strftime('%H:%M:%S'), direction, text))


def log_exception(where):
    """A traceback, into the log rather than onto stderr -- under tw04.sh
    stderr goes to a file handle that a rollover leaves pointing at the old
    copy, and a crash is exactly what should be in the live log."""
    log('!!!', 'exception in %s:\n%s' % (where, traceback.format_exc().rstrip()))


# Fields whose value must never reach the log.  `PASS` is the obvious one, and
# the CIPHERTEXT is just as sensitive as the plaintext here: the session key is
# a fixed constant a few lines up, so anyone holding a log can decrypt it.
SECRET_FIELDS = ('PASS',)
SECRET_RE = re.compile(r'^(PASS=).*$', re.M)


def redact(text):
    """Blank the value of every secret field in a decoded frame body."""
    if ARGS and ARGS.log_passwords:
        return text
    return SECRET_RE.sub(lambda m: '%s<redacted>' % m.group(1), text)


def redacted_tags(tags):
    """The decoded fields, with secret values replaced by their length."""
    if ARGS and ARGS.log_passwords:
        return tags
    return {k: ('<redacted, %d chars>' % len(v) if k in SECRET_FIELDS else v)
            for k, v in tags.items()}


def has_secret(tags):
    return any(k in tags for k in SECRET_FIELDS)


def hexdump(data, indent='        '):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        text = ''.join(chr(c) if 0x20 <= c < 0x7F else '.' for c in chunk)
        out.append('%s%04x  %-47s  %s'
                   % (indent, off, binascii.hexlify(chunk, ' ').decode(), text))
    return '\n'.join(out)


def _row_points(row):
    """The number in a leaderboard row's points column.

    A head-to-head row scores two for a win and one for a tie; a tournament row
    has no wins at all, only a round, so its number is the score.  The column is
    the same column, so this is where the two shapes have to meet.
    """
    if 'won' in row:
        return row['won'] * 2 + row['tied']
    return row.get('strokes', 0)


def _ordinal(n):
    """1 -> '1st'.  This goes on screen, so it should read like English."""
    if n <= 0:
        return 'unplaced'
    if 10 <= n % 100 <= 20:
        return '%dth' % n
    return '%d%s' % (n, {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th'))


def _pct(part, whole):
    """`part` as a whole percent of `whole`, clamped to the 7 bits it goes into."""
    if not whole:
        return 0
    return min(127, int(round(part * 100.0 / whole)))


class Handler(socketserver.BaseRequestHandler):

    # Direction markers for the frame log.  BuddyHandler overrides them so the
    # two servers' frames can be told apart in one log -- and so a grep for
    # `<-- auth` keeps meaning the lobby.
    IN, OUT = '<--', '-->'

    def who(self):
        """This connection, for the log: `host:port`, either family."""
        host, port = self.client_address[0], self.client_address[1]
        return '[%s]:%d' % (host, port) if ':' in host else '%s:%d' % (host, port)

    def setup(self):
        self.buf = b''
        # the keepalive thread writes to this socket too
        self.wlock = threading.Lock()
        # highest +usr index this connection has been sent, so a shrinking
        # room can have the tail entries explicitly removed
        self.usr_high = 0
        self.peer = (None, None)
        self.account = None
        self.account_id = None
        self.persona = None
        self.lkey = None
        CONNS.add(self)
        # `client_address` is a 4-tuple on an IPv6 socket -- host, port,
        # flowinfo, scope -- so the pair has to be taken explicitly.  Formatting
        # the whole tuple raised in `setup()` and killed the connection before
        # it had done anything.
        log('***', 'connect from %s' % self.who())

    def finish(self):
        CONNS.discard(self)
        # A clean lobby logout retires the key.  A restart does not get here,
        # which is the point: the key outlives the process, not the session.
        try:
            DB.retire_lkey(self.lkey)
        except Exception as exc:                        # noqa: BLE001
            log('!!!', '    could not retire the Messenger key: %s' % exc)
        if self.persona:
            ONLINE.pop(self.persona, None)
            was = WHERE.pop(self.persona, None)
            opp = (MATCHED.pop(self.persona, None) or {}).get('opp')
            SESSIONS.pop(frozenset((self.persona, opp)), None)
            REACH.pop(self.persona, None)
            if was:
                broadcast_users(was)
            log('***', 'persona %r left; online now: %s'
                % (self.persona, ', '.join(sorted(ONLINE)) or '(nobody)'))
            note('logout', '%s went offline' % self.persona, who=self.persona)
            publish_live()
        log('***', 'disconnect %s' % self.who())

    def send(self, kind, ident=0, tags=None, raw=None):
        payload = raw if raw is not None else (tagfield.encode(tags or {}).encode('latin-1'))
        payload += b'\0'
        frame = struct.pack('>III', cc2i(kind), ident, HDR + len(payload)) + payload
        log(self.OUT, "%s/%s size=%d  %s"
            % (kind, cc(ident), len(frame), payload[:-1].decode('latin-1', 'replace')))
        if ARGS.verbose:
            log('   ', '\n' + hexdump(frame))
        with self.wlock:
            self.request.sendall(frame)

    def handle(self):
        while True:
            try:
                chunk = self.request.recv(4096)
            except OSError:
                return
            if not chunk:
                return
            self.buf += chunk
            while len(self.buf) >= HDR:
                kind, ident, size = struct.unpack('>III', self.buf[:HDR])
                if size < HDR or size > 0x10000:
                    log('!!!', 'implausible size %d -- framing is wrong, raw follows:' % size)
                    log('   ', '\n' + hexdump(self.buf[:64]))
                    return
                if len(self.buf) < size:
                    break
                frame, self.buf = self.buf[:size], self.buf[size:]
                self.dispatch(kind, ident, frame[HDR:])

    def dispatch(self, kind, ident, payload):
        name = cc(kind)
        body = payload.rstrip(b'\0')
        tags = tagfield.decode(body)
        log(self.IN, '%s/%s size=%d  %s'
            % (name, cc(ident), HDR + len(payload),
               redact(body.decode('latin-1', 'replace'))))
        for key, value in redacted_tags(tags).items():
            log('   ', '    %-8s %r' % (key, value))
        if ARGS.verbose:
            if has_secret(tags) and not ARGS.log_passwords:
                log('   ', '        (hexdump suppressed -- this frame carries a '
                           'password; --log-passwords to see it)')
            else:
                log('   ', '\n' + hexdump(
                    struct.pack('>III', kind, ident, HDR + len(payload)) + payload))

        handler = getattr(self, self.PREFIX + name.strip('@~+').lower(), None)
        if handler:
            handler(ident, tags)
        else:
            self.unhandled(name, ident, tags)

    PREFIX = 'on_'

    def unhandled(self, name, ident, tags):
        # Silence is the one reply that is definitely wrong: an unanswered
        # request leaves the client idle and it drops the session after 60s.
        # A bare OK at least keeps it alive and lets the next request tell
        # us what it wanted.
        log('!!!', '    no handler for %r -- answering bare OK' % name)
        self.send(name, ident, {'~~': 'OK'})

    # ---- handshake -------------------------------------------------------

    def on_dir(self, ident, tags):
        """'@dir'.  A real server answers with a directory of lobby servers;
        we point the client back at ourselves."""
        host, port = self.request.getsockname()
        self.send('@dir', ident, {
            '~~': 'OK',
            'NAME': 'tw04-local',
            'ADDR': host,
            'PORT': str(port),
            'COUNT': '1',
        })

    def on_png(self, ident, tags):
        '''The client's half of the keepalive.  `~png` is intercepted at
        0x002BB910, before the normal dispatch, and bounced straight back with
        TIME=<the last measured round trip> -- so this is a reply, not a
        request.  Answering it would start a loop.'''
        pass

    def on_addr(self, ident, tags):
        """The client volunteers its own endpoint -- 'ADDR=192.0.2.100 PORT=58375'.

        That is the PS2's DHCP address and the port it will listen on, i.e. what
        the lobby has to hand the other player when a match starts.  Remember it
        and acknowledge.
        """
        self.peer = (tags.get('ADDR'), tags.get('PORT'))
        log('***', '    peer endpoint for P2P: %s:%s' % self.peer)
        self.send('addr', ident, {'~~': 'OK', 'ADDR': tags.get('ADDR', ''),
                                  'PORT': tags.get('PORT', '')})

    def on_skey(self, ident, tags):
        """The client asked for a session key; hand it ours."""
        self.send('skey', ident, {'~~': 'OK', 'SKEY': SESSION_KEY})

    def on_sele(self, ident, tags):
        """'sele' subscribes to notification channels:
        ROOMS=1 GAMES=1 USERS=1 RANKS=1 MESGS=1.  Echo them back as granted,
        then push the room list -- that is what the subscription is FOR."""
        granted = {k: v for k, v in tags.items() if k != '~~'}
        self.send('sele', ident, dict({'~~': 'OK'}, **granted))
        if tags.get('ROOMS') == '1':
            self.push_rooms()

    # ---- unsolicited pushes ----------------------------------------------
    #
    # The client never asks for the room list; the server volunteers it. The
    # inbound dispatcher at 0x002BB830 recognises a family of '+' verbs --
    # +ses +msg +who +rom +pop +usr +rnk +snp -- each gated on the matching
    # channel having been subscribed via `sele` (it checks [conn+0x310 + chan*4]
    # before parsing).
    #
    # +rom is one room, read at 0x002BC310 into a 0x68-byte record:
    #     I  room id, GetNumber, default -1; a negative id is discarded
    #     N  room name, GetString 0x20 -> record+0x1C; ABSENT MEANS "REMOVE"
    #     H  GetString 0x20 -> record+0x3C
    #     F  default -1 -> record+0x08
    #     A  -> record+0x64
    #     T  number
    # Only I and N are needed to create an entry; the rest have defaults.
    #
    # This is the fix for the empty room list that makes Lobby_JoinRoom return
    # -10 ("Invalid name.") when it cannot find the room it asked for.

    def push_rooms(self):
        for i, room in enumerate(list(ARGS.rooms) + CREATED):
            self.send('+rom', 0, {'I': str(i), 'N': room, 'H': self.persona or '',
                                  'F': '0', 'A': '0', 'T': '0'})
        allrooms = list(ARGS.rooms) + CREATED
        log('***', '    pushed %d room(s): %s'
            % (len(allrooms), ', '.join(allrooms)))

    # ---- the measurement -------------------------------------------------

    def fail(self, verb, code, why):
        """Answer a request with an error 4CC in the header's second word."""
        log('!!!', '    %s refused: %s (%s)' % (verb, why, code))
        self.send(verb, cc2i(code), {'~~': 'ERR', 'MESG': why})

    def on_auth(self, ident, tags):
        """Log in.  _AuthCallback (0x00287590) reads PERSONAS as a
        comma-separated list of up to four 32-byte names (0x002875E8), plus
        MAIL / GEND / BORN / SPAM for the profile screen."""
        name = tags.get('NAME') or ''
        plain = self.check_password('auth', tags)
        if plain is None:
            return self.fail('auth', ERR_BAD_PASSWORD, 'password unreadable')

        try:
            row = DB.verify(name, plain)
        except twdb.Error as exc:
            return self.fail('auth', ERR_DISABLED, str(exc))

        if row is None:
            if not ARGS.open:
                known = DB.account(name) is not None
                return self.fail('auth',
                                 ERR_BAD_PASSWORD if known else ERR_NO_USER,
                                 'wrong password' if known else
                                 'no account %r -- make one on the web site' % name)
            # Open mode: first login creates the account.  Convenient for a
            # LAN game, wrong for anything facing the internet.
            try:
                DB.create_account(name, plain)
            except twdb.Error as exc:
                return self.fail('auth', ERR_DUPLICATE, str(exc))
            log('***', '    --open: created account %r on first login' % name)
            row = DB.verify(name, plain)

        self.account = row['name']
        self.account_id = row['id']
        personas = DB.personas(row['id'])
        log('***', '    %r signed in; personas: %s'
            % (self.account, ', '.join(personas)))
        self.send('auth', ident, {
            '~~': 'OK',
            'PERSONAS': ','.join(personas[:twdb.MAX_PERSONAS]),
            'MAIL': row['mail'] or '',
            'GEND': row['gend'] or 'M',
            'BORN': row['born'] or '19700101',
            'SPAM': str(row['spam'] or 0),
        })

    def on_acct(self, ident, tags):
        """Create an account from the console.  _RegisterCallback (0x002877E0)
        recognises `dupl` for a name already taken, `tooy` for under age and
        `pmal` for a bad parent/guardian address."""
        name = tags.get('NAME') or ''
        plain = self.check_password('acct', tags)
        if plain is None:
            return self.fail('acct', ERR_BAD_PASSWORD, 'password unreadable')
        try:
            DB.create_account(name, plain, mail=tags.get('MAIL', ''),
                              gend=tags.get('GEND', 'M'),
                              born=tags.get('BORN', '19700101'),
                              spam=tags.get('SPAM', '0') not in ('', '0'))
        except twdb.Error as exc:
            code = ERR_DUPLICATE if 'already' in str(exc) else ERR_BAD_PASSWORD
            return self.fail('acct', code, str(exc))
        log('***', '    created account %r from the console' % name)
        note('signup', '%s signed up' % name, who=name)
        self.send('acct', ident, {'~~': 'OK', 'OPTS': '0', 'AGE': '21'})

    def on_pass(self, ident, tags):
        self.check_password('pass', tags)
        self.send('pass', ident, {'~~': 'OK'})

    def check_password(self, verb, tags):
        """Decrypt PASS and return the plaintext, or None if it did not arrive
        in a form we can read.  The running commentary is the point: this is
        also the regression test for eacrypt.py against the real client."""
        raw = tags.get('PASS')
        if raw is None:
            log('!!!', '%s carried no PASS field' % verb)
            return None
        if isinstance(raw, bytes):
            log('!!!', '    PASS arrived as a BINARY field ($%s), not a ~-string.'
                       % raw.hex())
            log('!!!', '    That is the public-key path at 0x002BE948, taken when '
                       'byte 0 of the session key is zero.')
            log('!!!', '    %s' % ('MASK is present, which confirms it.'
                                   if 'MASK' in tags else
                                   'Expected MASK alongside it, though.'))
            return None
        if ARGS.log_passwords:
            log('   ', '    PASS ciphertext %r (%d chars)' % (raw, len(raw)))
        else:
            log('   ', '    PASS arrived, %d chars' % len(raw))
        if not raw.startswith('~'):
            log('!!!', '    PASS is not ~-prefixed: the client took the public-key '
                       'path, so no usable session key reached it')
            return None
        try:
            plain = eacrypt.decode(raw, SESSION_KEY).decode('latin-1')
        except Exception as exc:                       # noqa: BLE001 - diagnostic
            log('!!!', '    decrypt raised %r' % (exc,))
            return None
        if ARGS.log_passwords:
            log('   ', '    PASS decrypted  %r' % plain)
        else:
            log('   ', '    PASS decrypted, %d chars' % len(plain))
        if ARGS.password is None:
            pass
        elif plain == ARGS.password:
            log('***', '    MATCH -- decrypted PASS equals the expected password; '
                       'eacrypt.py inverts what the client sent')
            expect = '~' + eacrypt.encode(ARGS.password, SESSION_KEY).decode('latin-1')
            log('   ', '    predicted ciphertext %s' % ('identical' if expect == raw
                                                        else 'DIFFERS'))
        else:
            log('!!!', '    MISMATCH -- the decrypted PASS is not the expected '
                       'password (%d chars vs %d)' % (len(plain), len(ARGS.password)))
            log('!!!', '    --log-passwords prints both, and the ciphertext to '
                       'work back from')
        return plain

    # ---- everything else -------------------------------------------------

    def on_chal(self, ident, tags):
        """Two different requests share this verb.

        `chal PERS=*` with no HOST is the subscribe-to-challenges call the
        client makes right after `auth`; its callback ignores the reply.

        `chal PERS=<opponent> HOST=<0|1>` is `_SendChalMessage` (0x00289AF0),
        sent by BOTH clients the moment a challenge is accepted -- the
        challenger with HOST=1, the accepter with HOST=0.  Its callback is
        _ChalCallback (0x00289470), and **MODE is a four-character word, not a
        number**:

            0x002894C8  MODE == "play"  -> proceed
            0x002894DC  MODE == "chal"  -> proceed (standby)
            0x002894F0  MODE == "idle"  -> "Challenge was cancelled"
                        anything else   -> "Couldn't issue challenge to
                                            opponent"

        `MODE=0` fell into that last case, which is the error both clients
        showed.  The error 4CCs the reply can carry instead are read at
        0x002894B4 and each has its own dialog:

            nrom / uusr  "Your opponent has left the room"
            igno         "Your opponent is not accepting challenges"
            ingm         "Your opponent is in a game"
            paut / maut   not authorized to issue challenges
        """
        who = tags.get('PERS', '')
        host = tags.get('HOST')
        if host is None:
            self.send('chal', ident, {'~~': 'OK'})
            # The console sends this whenever it is (back) in the lobby -- after
            # `auth`, and 30 s after a `+ses` whose peer connection failed
            # (13:14:01 on 2026-09-23, the Steam Deck attempts too).  A player
            # still connected who says it is not playing anyone.  At login the
            # persona is not chosen yet, and `pers` closes the match instead.
            end_matches(self.persona, 'is back in the lobby')
            return

        # A real match request.  Both clients send one; the pair is complete
        # when each has named the other, and that is when the match can start.
        MATCHED[self.persona] = {'opp': who, 'host': host == '1'}
        log('***', '    MATCH %s (host=%s, %s:%s) vs %s (%s:%s)'
            % (self.persona, host, self.peer[0], self.peer[1], who,
               *ONLINE.get(who, ('?', '?'))))
        self.send('chal', ident, {'~~': 'OK', 'MODE': 'play'})

        theirs = MATCHED.get(who)
        if theirs and theirs['opp'] == self.persona:
            start_session(self.persona, who)

    # `onln` and `cusr myrnk` are the two ranking requests, both sent by
    # 0x00277060 / 0x00277130 and both rate-limited by the client to one every
    # N seconds (the float compare at 0x002770BC).  Their callbacks write into
    # the one global online context at [gp-0x6714]:
    #
    #   0x002741E0  onln   S -> ctx+0x7C, 128 bytes, a STRING (0x002BF5F0)
    #                      R -> ctx+0xFC,  an integer
    #                      P -> ctx+0x100, an integer
    #   0x002742B0  myrnk  RNKRS -> ctx+0x104, 144 bytes, BINARY -- 0x002BF7F0
    #                      refuses anything that does not start with '$'
    #
    # both then post UI message 0xD4 (0x00294A00), which is what makes the
    # profile screen redraw.  `R` and `P` line up with the ONLINE RANK and
    # ONLINE POINTS lines on that screen; `S` is 128 bytes and unidentified.
    RNKRS_BYTES = 0x90
    # RNKRS is 36 little-endian words, read by 0x00276CE0(key), which maps a
    # key to a word with the switch at 0x00277220.  MY RESUME's EARNINGS RANK
    # line is 0x002A0E08: key 0x1F -> word 10, drawn "%d", or "N/A" when <= 0.
    # (Found from the ELF on 2026-09-25, after field 38 of `S` was tried and
    # the line stayed N/A.)  The other 35 words are still unknown -- zeros.
    RNKRS_EARNINGS_RANK = 10

    def rank_record(self, persona):
        """RNKRS for `myrnk`: 144 bytes, with what is known filled in."""
        words = [0] * (self.RNKRS_BYTES // 4)
        if persona:
            words[self.RNKRS_EARNINGS_RANK] = DB.tourney_career(
                persona, twtourney.payout)['rank']
        return struct.pack('<%dI' % len(words), *words)

    def stat_record(self, persona):
        """The packed `S` statistics blob for a persona.

        56 bit-fields, high-bit escaped, terminated with a marker -- see
        twstats.py.  The index of each one was read straight off the MY
        RESUME screen with --probe-stats, so the mapping is observed rather
        than inferred.

        Match play and stroke play are told apart by the room the match was
        played in: rooms are named "<type>.<id>.<name>" and the type is
        literally "Match" or "Stroke" -- the game names its own rooms that way.

        EVERY RATIO IS OURS TO WORK OUT.  The client does no arithmetic: under
        --probe-stats "HOLES PER EAGLE" read back 44 and "DRIVING ACCURACY %"
        read back 46, their own indices, so each of those lines is a plain
        stored field.  Only one is fixed point -- PUTTS PER HOLE is in
        hundredths, which is why 43 drew as "0.43" while the rest drew whole.
        """
        if ARGS.probe_stats:
            # Every field carries its own index; read the mapping off screen.
            return twstats.probe()

        by_kind = {'Match': [], 'Stroke': []}
        # Running totals over the rounds this persona actually finished.
        total = dict.fromkeys(('aces', 'eagles', 'birdies', 'gir', 'fairways',
                               'drives', 'putts', 'holes', 'strokes'), 0)
        longest_drive = longest_putt = 0
        best = None
        rounds_played = 0
        for match in DB.matches(persona):
            mine = next(p for p in match['players'] if p['name'] == persona)
            kind = 'Match' if match['room'].startswith('Match') else 'Stroke'
            by_kind[kind].append((match, mine))
            if mine['done'] and not mine['quit']:
                for k in total:
                    total[k] += mine[k]
                longest_drive = max(longest_drive, mine['longest'])
                longest_putt = max(longest_putt, mine['longest_putt'])
                if mine['strokes']:
                    rounds_played += 1
                    best = (mine['strokes'] if best is None
                            else min(best, mine['strokes']))

        # Tournament rounds are golf too: the best round of each day this
        # persona entered (the `tourney` table), with impossible numbers
        # thrown out the way the web site's pages throw them out.  Leaving
        # them out made MY RESUME read all zeros for a player who had only
        # played tournaments (2026-09-25).
        for row in DB.query('SELECT fields FROM tourney WHERE persona = ?',
                            (persona,)):
            try:
                card = twrecords.clean(twrecords._from_fields(
                    json.loads(row['fields'])))
            except (ValueError, TypeError, KeyError):
                continue
            if not card['done'] or card['quit'] or not card['holes']:
                continue
            for k in total:
                total[k] += card[k] or 0
            longest_drive = max(longest_drive, card['longest'] or 0)
            longest_putt = max(longest_putt, card['longest_putt'] or 0)
            if card['strokes']:
                rounds_played += 1
                best = (card['strokes'] if best is None
                        else min(best, card['strokes']))

        career = DB.tourney_career(persona, twtourney.payout)
        points = self.standing(persona)[1]
        values = {
            twstats.POINTS: points,
            twstats.TIGER_STATUS: twstats.tiger_status(points),
            twstats.EVENTS_ENTERED: career['entered'],
            twstats.EVENTS_WON: career['won'],
            twstats.TOP10: career['top10'],
            twstats.TOP25: career['top25'],
            twstats.TOTAL_EARNINGS: career['earned'] // twstats.EARNINGS_SCALE,
            twstats.HOLES_IN_ONE: total['aces'],
            twstats.TOTAL_EAGLES: total['eagles'],
            twstats.TOTAL_BIRDIES: total['birdies'],
            twstats.TOTAL_GIR: total['gir'],
            twstats.FAIRWAYS_HIT: total['fairways'],
            twstats.LONGEST_DRIVE: longest_drive,
            twstats.LONGEST_PUTT: longest_putt,
        }
        if best is not None:
            values[twstats.BEST_ROUND] = best
            values[twstats.SCORING_AVERAGE] = int(round(
                total['strokes'] / float(rounds_played)))

        # The derived lines.  Each is guarded by its own denominator, because a
        # persona with no finished rounds has zeros everywhere and the client
        # would happily draw whatever a division by zero produced.
        if total['holes']:
            values[twstats.GIR_PERCENT] = _pct(total['gir'], total['holes'])
            values[twstats.PUTTS_PER_HOLE] = int(round(
                total['putts'] * twstats.PUTTS_SCALE / float(total['holes'])))
        if total['drives']:
            values[twstats.DRIVING_ACCURACY] = _pct(total['fairways'],
                                                    total['drives'])
        if total['eagles']:
            values[twstats.HOLES_PER_EAGLE] = int(round(
                total['holes'] / float(total['eagles'])))
        if rounds_played:
            values[twstats.BIRDIE_AVERAGE] = int(round(
                total['birdies'] / float(rounds_played)))

        for kind, fields in (
                ('Match', (twstats.MATCH_WIN, twstats.MATCH_LOSS,
                           twstats.MATCH_TIE, twstats.MATCH_STREAK,
                           twstats.MATCH_INC, twstats.MATCH_DONE,
                           twstats.MATCH_POINTS)),
                ('Stroke', (twstats.STROKE_WIN, twstats.STROKE_LOSS,
                            twstats.STROKE_TIE, twstats.STROKE_STREAK,
                            twstats.STROKE_INC, twstats.STROKE_DONE,
                            twstats.STROKE_POINTS))):
            win_f, loss_f, tie_f, streak_f, inc_f, done_f, points_f = fields
            won = lost = tied = incomplete = run = 0
            for match, mine in by_kind[kind]:
                if not mine['done'] or mine['quit']:
                    incomplete += 1
                    continue
                if match['winner'] is None:
                    tied += 1
                    run = 0
                elif match['winner'] == persona:
                    won += 1
                    run = run + 1 if run >= 0 else 1
                else:
                    lost += 1
                    run = run - 1 if run <= 0 else -1
            # The streak is SIGNED, so send the losing ones too.  The second
            # word of a field's descriptor is the sign flag, not a default:
            # 0x00273930 floods the value's top bit up to bit 31, and only
            # fields 13 and 14 have it set.  0x002A1048 then reads the result
            # with `blez` -- positive draws "W<n>", negative negates it and
            # draws "L<n>", and zero prints a bare "0", which is what the
            # loser's row showed while this clamped at zero.
            #
            # DROP% is computed from the pair (incomplete, completed), so the
            # completed count has to be sent or every finisher reads 100%:
            # 0x002724BC takes the "all dropped" branch whenever `done` is 0.
            # Points are kept per mode as well as overall -- the STATISTICS
            # screen has a "Stroke Points" and a "Match Points" line, fields 5
            # and 4, beside the single "Rank Points" in field 1.  Same scheme
            # as the leaderboard: two for a win, one for a tie.
            values.update({win_f: won, loss_f: lost, tie_f: tied,
                           inc_f: incomplete, done_f: won + lost + tied,
                           streak_f: run, points_f: won * 2 + tied})
        return twstats.pack(values)

    def standing(self, persona):
        """(rank, points) for a persona, from the results we have stored.

        The points scheme is ours -- EA's is not recoverable from the client,
        which only ever displays the number the server sends.  Two for a win,
        one for a tie is the obvious choice and is easy to change here.
        """
        board = DB.leaderboard()
        points = 0
        rank = 0
        for n, row in enumerate(board, 1):
            if row['name'] == persona:
                rank = n
                points = row['won'] * 2 + row['tied']
                break
        return rank, points

    def on_onln(self, ident, tags):
        """`onln PERS=<name>` -- this player's own standing.

        Sent by 0x00277060 with the global online context as the callback's
        user pointer, so the three fields land in one struct and drive the
        ONLINE RANK / ONLINE POINTS lines on the profile screen.
        """
        who = tags.get('PERS') or self.persona or ''
        rank, _points = self.standing(who)
        _played, won, lost, tied = DB.record(who) if who else (0, 0, 0, 0)
        # `R` is the rank and `P` is the PING -- 0x0028A214 and 0x0028A254 feed
        # them to the RANK and PNG tags of the challenge blob.  Online points
        # are not here at all; they are statistic 1 inside `S`.
        blob = self.stat_record(who) if who else twstats.pack({})
        log('***', '    %s standing: rank=%d record=%d-%d-%d, S is %d bytes'
            % (who or '?', rank, won, lost, tied, len(blob)))
        self.send('onln', ident, {'~~': 'OK', 'S': blob.decode('latin-1'),
                                  'R': str(rank), 'P': '0'})

    # `cusr` is a generic "run a server command" envelope; CMD names the command.
    # Replies below are guesses except where a reader is known.
    CUSR = {
        # 'myrnk' is answered above -- RNKRS is a binary field, not a number.
        'whomi': {},
        # 'lts5d' is answered above -- atoi over the body, and a DAY NUMBER.
        # 'ufpvt' is answered above -- its reply is plain text, not a TagField.
        # 'mg5ri' and 'qdb@w' are answered above -- their replies are hex,
        # not TagFields.  See twtourney.py.
        # '5d0tr' is answered above -- its reply is shown to the player as text.
        # _TourneyStartCallback (0x002DE160) reads TKEY and DATA
        # 'esr2t' is answered above -- TKEY is binary and DATA is a hex list.
    }

    # The two tournament lists.  `mg5ri` is the calendar and `qdb@w` the daily
    # results; both are asked for with START and NUM, and
    # Tourn_GetTodaysTourneyInfoFromServer is the same `mg5ri` with START=-1
    # and NUM=1 (0x002DF49C).
    # cmd -> how many data bytes an entry carries.  The two parsers are not the
    # same width: 0x002DDE20 reads 0x10 for the calendar, 0x002DE000 reads 0x0C
    # for the results.  Sending 16 to the results list desynchronises it, which
    # is measurable -- the live client took 30 entries on one and 0 on the other
    # from the same body.
    TOURNEY_LISTS = {'mg5ri': twtourney.DATA_BYTES,
                     'qdb@w': twtourney.RESULT_BYTES}

    # The client's array holds 105 entries, but one reply is one frame, and the
    # request side of this exchange is built in an 0x800 buffer (0x002DF1EC).
    # A probe entry costs 41 characters, so 32 keeps a reply near 1300 and well
    # inside anything that size.  If the client turns out to ask for more and
    # to cope with it, raise this -- the ceiling is twtourney.MAX_ENTRIES.
    TOURNEY_PAGE = 32

    def tourney_body(self, tags, width=twtourney.DATA_BYTES):
        """The hex list these two commands answer with -- NOT a TagField.

        `COUNT=0` had been going back here, and the hex reader does not reject
        it: 'C' and 'O' are both above '0', so it decodes them as a count of
        192, more entries than the 105-entry array holds, and 0x002DDD70 throws
        the whole reply away.  An empty list is the two characters "00".

        `START` IS A DATE.  Showing September 2026 the calendar asked for
        `START=46266 NUM=30`, and day 46266 counted from 1899-12-30 is
        2026-09-01 -- so it wants one month, by day number, not a page of rows.
        `START=-1 NUM=1` is the separate "today" call.
        """
        try:
            start = int(tags.get('START') or 0)
            count = int(tags.get('NUM') or 0)
        except ValueError:
            start, count = 0, 0
        if start < 0:                    # "today", asked for as START=-1 NUM=1
            start = twtourney.today()
        count = max(0, min(count, twtourney.MAX_ENTRIES, self.TOURNEY_PAGE))
        if not ARGS.probe_tourney and width != twtourney.DATA_BYTES:
            entries = self.tourney_results(start, count)
            body = (twtourney.encode_list(entries, width) if entries
                    else twtourney.EMPTY)
            return body, len(entries), start
        if width == twtourney.DATA_BYTES:
            # The calendar's day offset is known, so put the day where the
            # client looks for it -- the cells can then light up and a day can
            # be opened -- and let every other byte name itself.
            #
            # A real event a day, unless a mapping probe is on.
            # Read only.  Which months exist is decided by `ensure_season` on
            # the server's clock, never by what a console asks for.
            if ARGS.probe_icons:
                entries = twtourney.probe_icons(count, start, twstats.COURSES)
            elif ARGS.probe_conditions:
                entries = twtourney.probe_conditions(count, start, PROBE_ANCHOR)
            elif ARGS.probe_tourney:
                entries = twtourney.probe_bytes(count, start)
            else:
                entries = twtourney.entries_for(DB.events(start, count))
        else:
            # The results list.  Its day offset IS known now (data offset 4,
            # from 0x002DF0EC), so the probe can make entries the dialog will
            # actually find, and let the other bytes name themselves.
            entries = twtourney.probe_results(count, start)
        return twtourney.encode_list(entries, width), len(entries), start

    # The 16-byte key each player was handed when they started an event, by
    # persona.  `5d0tr` signs its results with it, so it has to outlive the
    # `esr2t` that issued it.
    TOURNEY_KEYS = {}

    def on_esr2t(self, ident, tags):
        """`_GetStartPermissionFromServer` -- may this player start today's event?

        The callback `0x002DE160` wants two things, and refuses with "The server
        is temporarily unavailable" if it cannot get them:

            0x002DE1AC  TKEY -> [gp-0x6520], 16 bytes, BINARY ('$' + hex)
            0x002DE1CC  DATA -> a string, up to 0x400
            0x002DE1F4  0x002DDCC0(DATA, 0x003EEAA0)   <- THE SAME LIST PARSER
            0x002DE1FC  if it returned 0: refuse

        So `DATA` is a tournament list in the hex format, not a description of
        one, and the buffer it lands in is a single 0x30-byte entry -- so it
        holds exactly one event, the one being started.

        `TKEY` is the key that `5d0tr` signs its round results with: the same
        `[gp-0x6520]` that `0x002DF6F0` derives the 0x200-byte blob's key from.
        Nothing verifies it yet, but it is kept so that it can be.
        """
        who = tags.get('PERS') or self.persona or ''
        # The server's today, never the console's.  This is the gate on which
        # event can be played at all: the calendar is only a list.
        day = twtourney.today()
        if DB.event(day) is None and not (ARGS.probe_tourney or ARGS.probe_icons
                                          or ARGS.probe_conditions):
            log('!!!', '    esr2t: no event generated for %s, refusing'
                % twtourney.from_day(day))
            return self.send('cusr', ident, {'~~': 'OK', 'CMD': 'esr2t',
                                             'TKEY': bytes(16), 'DATA': ''})
        name, data = self.tourney_entry(day)
        key = secrets.token_bytes(16)
        self.TOURNEY_KEYS[who] = (day, key)
        log('***', '    esr2t %s starts %r on %s, key %s'
            % (who or '?', name, twtourney.from_day(day), key.hex()))
        self.send('cusr', ident, {'~~': 'OK', 'CMD': 'esr2t',
                                  'TKEY': key,
                                  'DATA': twtourney.encode_list([(name, data)])})

    def tourney_results(self, start, count):
        """The finished days in this range, as THIS player saw them.

        A result entry is the day from one point of view -- the winner's name,
        the winner's score, and the viewer's own score and finish -- so it is
        built per request, not per player.

        Only days this persona actually played are sent.  With no entry the
        dialog draws "Not available" on all four lines, which is the truth for
        a day they were not in; inventing a finish for them would draw "1st
        Place" instead.
        """
        me = self.persona or ''
        out = []
        for day in range(start, start + count):
            board = DB.tourney_day(day, limit=1000)
            mine = next((row for row in board if row['name'] == me), None)
            if not mine:
                continue
            out.append(twtourney.make_result(
                board[0]['name'], day,
                winner_score=board[0]['strokes'],
                your_score=mine['strokes'],
                place=mine['place']))
        return out

    def tourney_entry(self, day):
        """The one event on `day`, in whatever mode the server is running.

        This has to agree with what the calendar served, or a player would
        start one event and be shown another.  Both go through twtourney, and
        both are a pure function of the day, so they cannot drift.
        """
        if ARGS.probe_icons:
            return twtourney.probe_icons(1, day, twstats.COURSES)[0]
        if ARGS.probe_conditions:
            return twtourney.probe_conditions(1, day, PROBE_ANCHOR)[0]
        if ARGS.probe_tourney:
            return twtourney.probe_bytes(1, day, after=day - 1)[0]
        event = DB.event(day)
        if event is None:                 # a day outside any generated month
            return twtourney.make_entry('No Event', day)
        return twtourney.entries_for([event])[0]

    def on_5d0tr(self, ident, tags):
        """`Tourn_ReportRoundResults` -- a finished tournament round.

        `DATA` is NOT encrypted.  `0x002DF6F0` runs the buffer through
        0x002C44A0 / 0x002C4570, which reads like a cipher in the disassembly,
        but the captured bytes are a plain little-endian struct: 23 u32 in the
        same field order as a head-to-head `rank`, then the 16-byte TKEY this
        server issued, then the event's day and course.  Those calls serialise;
        they do not encrypt.

        So the anti-cheat is an ECHO.  A report is authentic if the key inside
        it is the key this server handed that player when it let them start,
        which also ties the score to one event on one day.

        `_RoundResultsCallback` (0x002DE390) shows the reply BODY to the player
        verbatim (0x0028B880), so the reply is a human-readable line, not a
        TagField -- which is why the last one drew "OK CMD=5d0tr" on screen.
        """
        who = tags.get('PERS') or self.persona or ''
        try:
            fields, key, day, course, _tail = twtourney.parse_round(
                tags.get('DATA') or '')
        except (ValueError, TypeError) as exc:
            log('!!!', '    5d0tr from %s is unreadable: %s' % (who or '?', exc))
            return self.send('cusr', ident,
                             raw=b'That round could not be read.')

        issued_day, issued_key = self.TOURNEY_KEYS.get(who, (None, None))
        if issued_key is None or key != issued_key:
            # Not necessarily cheating -- a restarted server forgets its keys.
            log('!!!', '    5d0tr from %s has key %s, expected %s'
                % (who or '?', key.hex(),
                   issued_key.hex() if issued_key else '(none issued)'))
            return self.send('cusr', ident, raw=(
                b'This round was not started on this server, so it cannot be '
                b'recorded.'))
        if not twtourney.round_is_consistent(fields):
            log('!!!', '    5d0tr from %s does not add up: %r' % (who, fields))
            return self.send('cusr', ident,
                             raw=b'That scorecard does not add up.')

        # File it against the day the KEY was issued for, and the course the
        # server generated -- not the day and course in the report.  Those come
        # from the console, which is where a wound-forward clock would show up:
        # without this, a player could enter today's event and have the result
        # recorded against any date they liked.
        event = DB.event(issued_day)
        # Only a player's lowest round of the day counts; a worse replay is
        # acknowledged but leaves the standing score alone.
        best = DB.add_tourney(who, issued_day,
                              event['course'] if event else course, fields,
                              event=event['name'] if event else '')
        kept = (' (best of the day %d stands)' % best
                if best != fields['STROKES'] else '')
        place, entrants = DB.tourney_place(who, issued_day)
        log('***', '    %s scored %d over %d holes on %s%s -- %s of %d'
            % (who, fields['STROKES'], fields['HOLES'],
               twtourney.from_day(issued_day), kept, _ordinal(place), entrants))
        note('round', '%s posted %d at %s%s%s -- %s of %d'
             % (who, fields['STROKES'],
                twstats.course_name(event['course'] if event else course),
                (' in the %s' % event['name']) if event and event['name'] else '',
                kept, _ordinal(place), entrants), who=who)
        publish_live()
        if issued_day != day:
            log('!!!', '    %s started %s but reported %s -- recorded against '
                       'the day it started'
                % (who, twtourney.from_day(issued_day),
                   twtourney.from_day(day)))
        if best != fields['STROKES']:
            message = ('Your round of %d is recorded, but your best of %d '
                       'still counts.%sYou are %s of %d.' % (
                           fields['STROKES'], best, chr(10), _ordinal(place),
                           entrants))
        else:
            message = 'Your round of %d is recorded.%sYou are %s of %d.' % (
                fields['STROKES'], chr(10), _ordinal(place), entrants)
        self.send('cusr', ident, raw=message.encode('ascii'))

    def on_cusr(self, ident, tags):
        cmd = tags.get('CMD', '')
        if cmd == 'lts5d':
            # `Tourn_GetTodaysDateFromServer`.  NOT a TagField, and not a date
            # either: `_TodaysDateCallback` (0x002DE2E0) runs
            #
            #   0x002DE308  atoi(body)
            #   0x002DE310  [gp-0x6544] = that, as a short
            #
            # and `[gp-0x6544]` is THE CURRENT DAY -- the same day number the
            # calendar uses.  0x00265640 then splits it into year/month/day,
            # which is how the client knows what "today" is at all.
            #
            # The old reply was a TagField carrying `DATA=20260919`, and atoi
            # over a body starting "OK" is zero.  Everything downstream is
            # gated on that day being sensible: 0x002DEEF0 and 0x002DEF30 both
            # bail on `day <= 0`, so the DAILY LEADERBOARDS and WEEKLY MONEY
            # LEADERS screens resolved their list index to -1 and never sent a
            # request at all.  Confirmed live -- [gp-0x6544] read 0.
            body = str(twtourney.today())
            log('***', '    lts5d -> %s (%s)'
                % (body, twtourney.from_day(twtourney.today())))
            return self.send('cusr', ident, raw=body.encode('ascii'))
        if cmd == 'esr2t':
            return self.on_esr2t(ident, tags)
        if cmd == '5d0tr':
            return self.on_5d0tr(ident, tags)
        if cmd in self.TOURNEY_LISTS:
            body, n, first = self.tourney_body(tags, self.TOURNEY_LISTS[cmd])
            # Name the days the ENTRIES cover, not a range derived from how
            # many there are -- the calendar is one a day, but results are only
            # the days this player actually entered, so counting days from the
            # entry count reports the wrong dates entirely.
            days = twtourney.list_days(body,
                                       self.TOURNEY_LISTS[cmd]) if n else []
            log('***', '    %s %s (START=%s NUM=%s) -> %d entr%s, %d chars'
                % (cmd,
                   ('%s..%s' % (twtourney.from_day(min(days)),
                                twtourney.from_day(max(days)))
                    if len(days) > 1 else
                    str(twtourney.from_day(days[0])) if days else 'nothing'),
                   tags.get('START', '-'), tags.get('NUM', '-'), n,
                   'y' if n == 1 else 'ies', len(body)))
            self.send('cusr', ident, raw=body.encode('ascii'))
            return
        if cmd == 'ufpvt':
            # NOT a TagField.  _GetUserPrivateData's callback (0x002DE7A0) runs
            #
            #   sscanf(body, "%d %d %d %d %d %d", ...)
            #
            # straight over the reply body, and on an error reply it sets four
            # globals to -1 -- which is what draws "Data unavailable at this
            # time" on the leaderboard (0x002723D0 tests [gp-0x773C] >= 0).
            #
            # ALL SIX ARE NOW NAMED.  `0x002DE7C0` hands sscanf its six
            # destinations in EE argument order, and the readers say what each
            # one is for:
            #
            #   1  [gp-0x6542]  short  the FIRST day of the season
            #   2  [gp-0x6540]  short  the LAST day
            #   3  [gp-0x7748]  int    the daily leaderboards' base list index
            #   4  [gp-0x7744]  int    the weekly money leaders' base index
            #   5  [gp-0x7740]  int    the highest list index that exists
            #   6  [gp-0x6538]  int    a bitmask of optional features
            #
            # 0x002DEEC0 answers "is day D in season?" with `S1 <= D <= S2`,
            # and 0x002DEF30 turns a day into a weekly index by dividing the
            # offset from S1 by seven (the 0x92492493 multiply at 0x002DEF64).
            # 0x002DEEF0 does the same for a day without the division.
            #
            # Both were zero, so every day failed `D <= S2` and the DAILY
            # LEADERBOARDS screen never asked the server for anything -- it had
            # already decided today was out of season.
            # NOT a row count.  Trapped live at 0x00276DD0: the front end asks
            # for INDEX=14 with RANGE=25, and the gate is
            #
            #   0x00276DF4  if [gp-0x773C] < INDEX: return
            #
            # so the number has to be at least as large as the highest list
            # index any screen asks for -- it is a "how many lists exist", not
            # "how many rows".  Sending the player count (2) rejected every
            # request before it reached the socket, which is why `snap` was
            # never seen.
            first = twtourney.today() - self.SEASON_DAYS
            last = twtourney.today() + self.SEASON_DAYS
            body = '%d %d %d %d %d %d' % (
                first, last, self.DAILY_BASE, self.WEEKLY_BASE,
                self.MAX_LIST_INDEX, self.FEATURE_BITS)
            log('***', '    ufpvt season %s..%s, daily lists from %d, weekly '
                       'from %d, ceiling %d'
                % (twtourney.from_day(first), twtourney.from_day(last),
                   self.DAILY_BASE, self.WEEKLY_BASE, self.MAX_LIST_INDEX))
            log('***', '    ufpvt -> %r (%d ranked player(s) available)'
                % (body, len(DB.leaderboard())))
            self.send('cusr', ident, raw=body.encode('ascii'))
            # The count is only a promise.  The rows cannot be pushed here --
            # `+snp` delivers to whatever channel the last `snap` REPLY named,
            # and no `snap` has been answered yet, so they would go to channel 0
            # and be thrown away.  They are sent from on_snap instead.
            return
        if cmd == 'myrnk':
            # 144 bytes of ranking record -- see rank_record.  It must be a
            # `$`-prefixed binary field: 0x002BF7F0 returns -1 for anything
            # else, which is why the old `RNKRS=0` was refused.
            who = tags.get('PERS') or self.persona or ''
            blob = self.rank_record(who)
            self.send('cusr', ident, {'~~': 'OK', 'CMD': cmd, 'RNKRS': blob})
            log('***', '    myrnk -> earnings rank %d for %s'
                % (struct.unpack_from('<I', blob,
                                      4 * self.RNKRS_EARNINGS_RANK)[0],
                   who or '?'))
            return
        if cmd == 'whomi' and 'CRPIN' in tags:
            blob = tags['CRPIN']
            if isinstance(blob, str):
                blob = blob.encode('latin-1')
            who = self.persona or self.account
            CRPIN[who] = blob
            stored = DB.set_golfer(who, blob)
            log('***', '    stored the golfer for %s, %d bytes%s'
                % (who, len(blob), '' if stored else ' (in memory only -- no '
                   'such persona in the database)'))
        extra = self.CUSR.get(cmd)
        if extra is None:
            log('!!!', '    unknown cusr CMD %r -- replying bare OK' % cmd)
            extra = {}
        self.send('cusr', ident, dict({'~~': 'OK', 'CMD': cmd}, **extra))

    # The news buffer is 0x1388 bytes (0x00287314) and 0x00272D80 word-wraps it
    # into 64-character lines, so anything much past this is simply not read.
    # The box on screen is narrower than 64, so the text is wrapped here first
    # (twrecords.NEWS_WIDTH).  Whoever reads this is already signed in, so the
    # default has no sign-up instructions.
    NEWS_MAX = 0x1388 - 1
    NEWS_DEFAULT = "Welcome back to Tiger Woods PGA Tour 2004 online."

    def news_text(self):
        """Whatever is in the news file right now, or the built-in message.

        Read per request rather than cached, so the file can be edited while
        the server is running and the next player to look sees the change.
        """
        if ARGS.news:
            try:
                with open(ARGS.news, encoding='utf-8') as f:
                    return f.read()
            except OSError:
                pass
        return self.NEWS_DEFAULT

    def buddy_address(self):
        """The `host:port` to hand out for EA Messenger, or None.

        `--buddy-addr` wins when given.  Otherwise, with our own Messenger
        listener running, it is the address this console reached the LOBBY on
        -- the same reasoning as `@dir`, and right on any host that holds its
        public address directly.  Behind NAT, pass `--buddy-addr` instead.

        Always with the port: the non-LKEY connect path returns early at
        0x00286268 when the port half is empty.
        """
        if ARGS.buddy_addr:
            return ARGS.buddy_addr
        if not ARGS.buddy_port:
            return None
        host = dotted_quad(self.request.getsockname()[0])
        return '%s:%d' % (host, ARGS.buddy_port) if host else None

    def on_news(self, ident, tags):
        """`news` is TWO requests wearing one verb, told apart by NAME.

        `NAME=0` is `Lobby_GetBuddyServerAddr` (0x00287F60), fired from
        _AuthCallback at 0x00287770 the moment a login succeeds.  Its callback
        (0x002873D0) takes the **first line** of the body, splits it on the
        first ':' (0x00121FB0 against the literal ":" at 0x003113B0), and hands
        the two halves to 0x00286110 and 0x00286120 -- host and port.  So the
        whole reply is one line, `host:port`, naming the EA Messenger server.
        An empty body is checked for and ignored (0x002873EC), which is the
        right answer while we do not run one.

        `NAME=1` is `Lobby_GetNews` (0x00287ED0).  Its callback (0x002872E0)
        does not parse the body at all -- it `strcpy`s the whole thing into a
        5000-byte buffer at 0x003B5A44 and passes it to 0x00272D80, which
        word-wraps it at 64 characters.  So the reply body **is** the news
        text, verbatim, with no OK and no tags: anything we put in the usual
        `~~` slot would be printed as the first line of the news.
        """
        which = tags.get('NAME', '0')
        if which == '0':
            addr = self.buddy_address()
            body = ('%s\n' % addr) if addr else ''
            log('***', '    buddy server address requested -> %r'
                % (addr or '(none configured)'))
        else:
            # 0x00272D80 does not print the buffer -- it walks it as a LIST,
            # asking 0x00272E50 how many items there are and pulling each into
            # a 0x40-byte slot with 0x00272ED0.  A body with no newline at all
            # produced an empty screen, so normalise: CRLF and CR become LF,
            # and the text always ends with one.
            text = self.news_text()
            if not ARGS.no_auto_news:
                # The operator's text first -- maintenance notices matter more
                # than who leads today -- then the digest, built from the same
                # rounds the web site's pages use (twrecords.news).
                try:
                    digest = twrecords.news(DB)
                except Exception:                       # noqa: BLE001
                    log_exception('the news digest')
                    digest = ''
                if digest:
                    text = text.rstrip('\n') + '\n\n' + digest
            text = twrecords.wrap_news(text)
            text = text.rstrip('\n') + '\n'
            body = text[:self.NEWS_MAX]
            log('***', '    news requested (NAME=%s) -> %d chars, %d line(s)'
                % (which, len(body), body.count('\n')))
        self.send('news', ident, raw=body.encode('latin-1', 'replace'))

    # ---- rooms and matchmaking -------------------------------------------
    # None of these reply shapes are established; they are the minimum that
    # keeps the client moving so the log can show what it asks for next.

    # The lists a `snap` can ask for, by the INDEX the client sends.  A row is
    # rendered by 0x00272390, and 14 and 13 are the two it has hard-wired
    # branches for (0x0027243C, 0x0027250C) -- they pick the stroke or the match
    # triple of stat fields.  Every other list, 32 among them, takes the generic
    # path at 0x002725E0, where the columns come from a table at 0x003B6DD4 that
    # the screen fills in when it opens.
    LISTS = {
        14: ('Stroke', None),          # STROKE PLAY LEADERBOARD
        13: ('Match', None),           # MATCH PLAY LEADERBOARD
        32: (None, 7 * 86400),         # GOLFER OF THE WEEK
    }

    # Two more type 2 lists, both drawn with a date in the first column.
    # Which is which was not clear from the wire -- the screens ask for them in
    # whatever order they are tabbed through -- so if they turn out to be the
    # wrong way round, swap these two numbers and nothing else.
    # Measured: 33 drew what was served as event winners under the TOURNAMENT
    # WINNERS heading, and 35 drew the weekly money under GOLFERS OF THE WEEK.
    LIST_WEEK_GOLFERS = 35          # GOLFERS OF THE WEEK, a week per row
    LIST_TOURNEY_WINNERS = 33       # TOURNAMENT WINNERS, an event per row

    def weekly_winners(self):
        """Whoever earned most in each week of the season, newest week first."""
        first = twtourney.today() - self.SEASON_DAYS
        monday = first - (first % 7)
        out = []
        while monday <= twtourney.today():
            week = self.week_earnings(monday)
            if week:
                best = week[0]
                out.append({'name': best['name'], 'day': monday,
                            'strokes': best['rounds'],
                            'text': twtourney.money(best['earned'])})
            monday += 7
        out.reverse()
        return out

    def event_winners(self):
        """Whoever won each FINISHED event, newest first -- today's is still
        being played.  Players tied for 1st are all winners, one row each."""
        out = []
        for day in range(twtourney.today() - self.SEASON_DAYS,
                         twtourney.today()):
            for row in DB.tourney_day(day, limit=1000):
                if row['place'] != 1:
                    break
                out.append({'name': row['name'], 'day': day,
                            'strokes': row['strokes'],
                            'text': twtourney.to_par(row['fields'],
                                                     row['par'])})
        out.reverse()
        return out

    def week_earnings(self, monday):
        """Seven days of prize money, richest first.

        The column is headed EARNINGS, so it is money -- a share of each day's
        purse by where the player finished that day.  It has to be worked out a
        day at a time, because a placing only means anything within its own
        event, and the purse differs from day to day.
        """
        rows = DB.tourney_standings(monday, monday + 6, twtourney.payout)
        for row in rows:
            row['text'] = twtourney.money(row['earned'])
            row['strokes'] = row['rounds']
            # Richest first, so the sort key is the money -- scaled down to
            # stay a small number, since only the order matters.
            row['p'] = row['earned'] // 10000
        return rows

    def list_rows(self, index):
        """(what this list is, [(rank, row)]) for a `snap` INDEX.

        Three kinds of list share one request.  13, 14 and 32 are fixed -- the
        match board, the stroke board and golfer of the week.  The tournament
        boards are not: their index is worked out from the DATE, off the season
        start this server itself declared in `ufpvt` (on_cusr), so the
        same arithmetic has to be done here in reverse.
        """
        first = twtourney.today() - self.SEASON_DAYS
        span = 2 * self.SEASON_DAYS

        if self.DAILY_BASE <= index <= self.DAILY_BASE + span:
            day = first + (index - self.DAILY_BASE)
            rows = DB.tourney_day(day)
            for row in rows:
                # The daily board has RANK, PLAYER NAME and ONE free column,
                # and no numeric column of its own -- so the result has to go
                # in the string.  The course is already on the event screen;
                # what a leaderboard wants is the score, and in the form a
                # golfer says it.
                # `par` is the COURSE's, the same for every row on this
                # board.  Scoring each card against a par worked out from
                # itself put 78 (+3) above 77 (+4) on a leaderboard that was
                # correctly sorted by strokes -- see twtourney.card_par.
                row['text'] = twtourney.to_par(row['fields'], row['par'])
                # And the sort key has to run the other way from the score:
                # in stroke play the lowest round wins, but the client puts the
                # largest `P` on top.  Not drawn anywhere -- purely the order.
                row['p'] = max(0, twtourney.SORT_BASE - row['strokes'])
            # Tied scores share a rank, as on the web site.
            return ('daily, %s' % twtourney.from_day(day),
                    [(row['place'], row) for row in rows])

        if self.WEEKLY_BASE <= index <= self.WEEKLY_BASE + span // 7:
            monday = first + (index - self.WEEKLY_BASE) * 7
            rows = self.week_earnings(monday)
            return ('weekly, %s..%s' % (twtourney.from_day(monday),
                                        twtourney.from_day(monday + 6)),
                    list(enumerate(rows, 1)))

        if index == self.LIST_WEEK_GOLFERS:
            return 'golfers of the week', list(enumerate(self.weekly_winners(), 1))

        if index == self.LIST_TOURNEY_WINNERS:
            return 'tournament winners', list(enumerate(self.event_winners(), 1))

        kind, window = self.LISTS.get(index, (None, None))
        rows = DB.leaderboard(kind=kind,
                              since=(time.time() - window) if window else None)
        return ('%s%s' % (kind or 'any', ', last 7 days' if window else ''),
                list(enumerate(rows, 1)))

    def on_snap(self, ident, tags):
        """Ask for a page of a list, or for one named player's place in it.

        Trapped live at 0x00276DD0, the front end sends two of these when the
        leaderboard opens:

            INDEX=14 CHAN=4 START=0 RANGE=25      the visible page
            INDEX=14 CHAN=5 FIND=<persona> RANGE=1  "and where am I?"

        `INDEX` is the list -- 14 is the stroke leaderboard -- and `CHAN` is
        which channel to deliver on, which is why `Lobby_Init` registers 4 and
        5 and nothing else in that range.

        The REPLY is what arms the channel: 0x002BBE20 takes `CHAN` from it
        into [conn+0x508], and only then does a `+snp` know where to go.  So
        answer first, push second.
        """
        channel = tags.get('CHAN', '0')
        find = tags.get('FIND')
        try:
            start = int(tags.get('START') or 0)
            count = int(tags.get('RANGE') or 25)
        except ValueError:
            start, count = 0, 25

        try:
            index = int(tags.get('INDEX') or 0)
        except ValueError:
            index = 0
        label, board = self.list_rows(index)
        if find:
            rows = [(rank, row) for rank, row in board if row['name'] == find]
        else:
            rows = board[start:start + count]

        self.send('snap', ident, {'~~': 'OK', 'CHAN': channel,
                                  'COUNT': str(len(rows)),
                                  'RANGE': str(len(rows)), 'MORE': '0'})
        log('***', '    snap INDEX=%s (%s) CHAN=%s %s -> %d row(s)'
            % (tags.get('INDEX', '-'), label, channel,
               ('FIND=%s' % find) if find else
               ('START=%s RANGE=%s' % (start, count)), len(rows)))
        if rows:
            self.push_leaderboard(channel, rows)

    def on_room(self, ident, tags):
        """Lobby_CreateRoom. _CreateRoomCallback reads NAME and COUNT.

        The client names its own rooms hierarchically too -- observed live:
            NAME=Match.C.iii  DESC="Created by jed2"  PASS=pppp  MAX=50
        `C` is index 5 of the T/I/G/E/R/C table, and it is the browser's
        CREATED row, so the letters are category codes.

        Keep the room and broadcast it, otherwise it exists only for the
        instant of the reply and never appears in anyone's browser.
        """
        name = tags.get('NAME', '')
        if name and name not in CREATED:
            # Bounded: a room here is never removed, and nothing stops a client
            # creating them in a loop.  Oldest out first, so the list stays a
            # list of recent rooms rather than a way to exhaust the server.
            if len(CREATED) >= MAX_CREATED_ROOMS:
                dropped = CREATED.pop(0)
                log('!!!', '    room list full, forgot the oldest: %r' % dropped)
            CREATED.append(name)
            log('***', '    %s created room %r (now %d created)'
                % (self.persona, name, len(CREATED)))
        # The host never sends `move` -- the client goes straight from
        # _CreateRoomCallback into the room screen -- so creating IS joining.
        # Without this the host is not in WHERE, every occupant list is short
        # by one, and the host's own PLAYER column is empty.
        if name and self.persona:
            WHERE[self.persona] = name
            log('***', '    %s is in %r' % (self.persona, name))
        self.send('room', ident, {'~~': 'OK', 'NAME': name,
                                  'COUNT': str(len(self.occupants(name)))})
        broadcast_rooms()
        broadcast_users(name)
        if name and self.persona:
            note('room', '%s opened %s'
                 % (self.persona, room_label(name) or name), who=self.persona)
        publish_live()

    def on_move(self, ident, tags):
        """Join a room, or leave it when NAME is absent. 0x00273B70 reads COUNT.

        This is what gives the server real room membership, so `peek` can report
        who is actually in a room instead of guessing.
        """
        name = tags.get('NAME', '')
        was = WHERE.get(self.persona) if self.persona else None
        if self.persona:
            if name:
                WHERE[self.persona] = name
                log('***', '    %s joined %r' % (self.persona, name))
            else:
                WHERE.pop(self.persona, None)
                log('***', '    %s left %r' % (self.persona, was))
        here = self.occupants(name) if name else []
        self.send('move', ident, {'~~': 'OK', 'NAME': name,
                                  'COUNT': str(len(here))})
        # everyone already in the room needs the new list, not just the joiner
        broadcast_users(name)
        if was and was != name:
            broadcast_users(was)
        if not name:
            self.push_users([])      # clear the leaver's own list
        if self.persona and name and name != was:
            note('room', '%s joined %s'
                 % (self.persona, room_label(name) or name), who=self.persona)
        publish_live()

    def on_peek(self, ident, tags):
        """Lobby_PeekRoom -- "who is in this room?".  _PeekRoomCallback
        (0x00273C40) reads exactly one field, COUNT, and stores it at
        gp-0x7738; that is the "PLAYERS: n" figure on the room browser.  The
        names themselves arrive separately as `+usr` pushes."""
        room = tags.get('NAME', '')
        who = self.occupants(room)
        self.send('peek', ident, {'~~': 'OK', 'COUNT': str(len(who))})
        if who:
            self.push_users(who)

    @staticmethod
    def occupants(room):
        """The personas actually in `room`, per the `move` requests seen."""
        return sorted(p for p, r in WHERE.items() if r == room)

    def push_users(self, personas):
        """`+usr`, handler at 0x002BC6C8, channel 1.  Read from the ELF:

        | tag | into  | reader              | size |
        |-----|-------|---------------------|------|
        | `I` | +0x00 | number, id          |      |
        | `F` | +0x04 | 0x002BF228, BIT-CHARACTERS, as on `+msg` | |
        | `N` | +0x08 | string              | 32   |
        | `P` | +0x28 | string              | 8    |
        | `A` | +0x30 | 0x002BF270, a DOTTED QUAD | |
        | `R` | +0x34 | number              |      |
        | `S` | +0x38 | string              | 128  |
        | `X` | ?     | string              | 128  |

        An absent `N` means "remove this user", as on `+rom`.

        Two of those were being sent wrongly.  `F` is the same bit-character
        codec as `+msg`'s, so `F=0` did not mean "no flags" -- `'0'`
        is bit 27, `0x08000000` -- and the field is now simply omitted, which
        0x002BF228 reads as zero.  `A` is parsed as an address, so `A=0` was
        not a number either.
        """
        for i, who in enumerate(personas):
            rank, _points = self.standing(who)
            addr, _port = peer_address(who)
            self.send('+usr', 0, {
                'I': str(i),
                'N': who,
                'P': 'good',
                'A': addr or '0.0.0.0',
                'R': str(rank),
                # 128 bytes, same shape as `onln`'s S on the theory that the
                # other player's panel reads the same packed record.
                'S': self.stat_record(who).decode('latin-1'),
            })
        for i in range(len(personas), self.usr_high):
            self.send('+usr', 0, {'I': str(i)})       # no N -> remove
        self.usr_high = len(personas)
        log('***', '    pushed %d user(s) to %s: %s'
            % (len(personas), self.persona or '?', ', '.join(personas) or '(none)'))

    # The snapshot channels.  `+snp` does not have a channel of its own -- the
    # dispatcher reads `CHAN` out of the frame into [conn+0x508] (0x002BBE34)
    # and `+snp` then dispatches to that entry of the table at conn+0x310,
    # rejecting anything outside 4..7 (0x002BCC74, 0x002BCC84).
    #
    # Channel 4's handler is 0x00273540, and it calls **0x00272390** -- the
    # function that draws the leaderboard, or prints "Data unavailable at this
    # time" when the count says there is nothing.
    CHAN_LEADERBOARD = 4

    # How far either side of today the tournament season runs.  The calendar
    # itself does not care -- it worked with the season unset -- but the daily
    # and weekly leaderboards refuse to ask about a day outside it
    # (0x002DEEC0), so this is what makes those screens send anything at all.
    # KEEP THIS SMALL.  The index is computed from the day, so the season's
    # length IS the number of list indices the client will invent, and those
    # have to land on lists it actually has.  Every index ever seen on the wire
    # is in the 13..35 range; a season of +/-90 days produced INDEX=154 and the
    # client crashed pushing rows into a list object that was never configured
    # -- `jalr` through a comparison callback at 0x002C090C that held garbage.
    SEASON_DAYS = 7

    # A daily leaderboard is a LIST, and its index is worked out from the day:
    # roughly DAILY_BASE + (day - season start), and WEEKLY_BASE + that over
    # seven for the money leaders.  The two bases have to clear the built-in
    # lists -- 13 and 14 are the match and stroke boards, 32 is golfer of the
    # week -- and not run into each other.
    DAILY_BASE = 36                       # 36 .. 36 + 2*SEASON_DAYS
    WEEKLY_BASE = 52                      # 52 .. 52 + 2*SEASON_DAYS/7

    # The largest list index the client may ask for (0x00276DF4 rejects any
    # request above it).  64 is the value that was in place when every screen
    # that works today started working, so it stays -- and every computed index
    # above has to fit under it.
    MAX_LIST_INDEX = 64

    # The optional-feature bitmask.  Only three bits are known and each one
    # turns on an extra block the client would then expect the server to
    # understand -- bit 2 adds a section to the `5d0tr` report (0x002DF7C4),
    # bit 1 to another message (0x002DFDAC), bit 3 answers a capability query
    # (0x002DEEB0).  Everything works with them off, so they stay off until
    # there is a reason to turn one on.
    FEATURE_BITS = 0

    def push_leaderboard(self, channel, rows):
        """`+snp`, one frame per row, on the channel the `snap` reply named.

        | tag | into | reader | |
        |---|---|---|---|
        | `P` | row+0x00 | number | points |
        | `R` | row+0x04 | number | rank |
        | `N` | row+0x08, 32 | string | the player name |
        | `S` | row+0x28, 128 | string | the packed statistics record |

        `CHAN` on this frame is ignored -- the channel comes from the preceding
        `snap` reply -- but it is sent anyway because it costs
        nothing and makes the log readable.
        """
        for rank, row in rows:
            self.send('+snp', 0, {
                'CHAN': str(channel),
                'R': str(rank),
                # `P` lands at row+0x00, and for lists 33, 34 and 35 that is
                # where the renderer reads a DATE from (0x002726C0 picks the
                # '%d/%d/%02d' path by list index, 0x002726F0 reads the
                # halfword).  Those rows put the day there instead of a number,
                # counted from 2003 rather than absolutely -- see
                # twtourney.LIST_EPOCH.
                # `P` IS THE SORT KEY, and the client sorts DESCENDING.
                # Measured: Tiger went out R=1 P=64 and JeddyH2 R=2 P=72, and
                # the board drew JeddyH2 first.  So whatever goes here has to
                # be "bigger is better" -- which a stroke count is not.  Rows
                # that know better set 'p' themselves.
                'P': (str(twtourney.to_list_day(row['day'])) if 'day' in row
                      else str(row['p']) if 'p' in row
                      else str(_row_points(row))),
                'N': row['name'],
                # `S` lands at row+0x28, and what the renderer does with it
                # depends on the list's descriptor (0x00272290):
                #
                #   type 1  a PACKED RECORD -- it pulls a stat field out of it
                #   type 2  a STRING -- it draws it as text, verbatim
                #
                # 13, 14 and 32 are type 1; the tournament lists are type 2,
                # read live at [gp-0x7758] and [gp-0x7750].  Sending the packed
                # record to a type 2 list draws 128 bytes of 0x80-and-up across
                # the row as boxes, which is exactly what it did.
                'S': (row['text'] if 'text' in row
                      else self.stat_record(row['name']).decode('latin-1')),
            })
        log('***', '    pushed %d row(s) on channel %s: %s'
            % (len(rows), channel,
               ', '.join('%d %s' % (n, r['name']) for n, r in rows) or '(none)'))

    def on_user(self, ident, tags):
        """Look up another player.  0x00274330 reads CRPIN out of the reply --
        the created-golfer blob, which `cusr whomi` uploaded for that persona.
        Hand back the real one if we have it."""
        who = tags.get('PERS', '')
        # The database is authoritative: it is how a golfer survives a restart
        # and follows its persona between consoles.  Memory is just a cache for
        # a persona that has uploaded but is not registered (--open).
        blob = DB.golfer(who) or CRPIN.get(who)
        reply = {'~~': 'OK', 'PERS': who}
        if blob is not None:
            reply['CRPIN'] = blob
            log('***', '    returning %s\'s stored golfer (%d bytes)'
                % (who, len(blob)))
        else:
            log('!!!', '    no stored golfer for %r -- it has not sent '
                       '`cusr whomi` yet' % who)
        self.send('user', ident, reply)

    # `+msg` flag bits, read from tag F at 0x002BC164:
    #   0x00004 -> the client treats it as 'cast' (broadcast)
    #   0x10000 -> 'priv' (private)
    # otherwise it is plain 'chat'.  Handler at 0x002BC124; it hands the event
    # to the MESGS channel callback at [conn+0x520].
    # +msg flag bits, from the 0x003145D0 table.  tagfield.flags_encode turns
    # these into the character form the wire actually carries.
    FL_CAST = 0x00000004      # 'B' -- record kind becomes 'cast'
    FL_PRIV = 0x00010000      # 'P' -- record kind becomes 'priv'
    FL_IGNORE = 0x00200000    # 'V' -- a priv message with this set is dropped
    FL_ATTR3 = 0x40000000     # '3' -- a priv message with this IS a challenge

    CHALLENGE_VERBS = ('challenge', 'accept', 'decline', 'revoke', 'busy',
                       'ignore', 'ignoreall')

    def on_mesg(self, ident, tags):
        """Chat -- and the challenge handshake rides on it.

        The request and the push do NOT use the same field names.  A request
        carries TEXT / PRIV / ATTR; the push handler (0x002BC128 in the
        connection layer, then 0x00273150 in the lobby) reads only three:

            N   the sender, 64 bytes      0x00273190
            T   the body, 1024 bytes      0x002731B8
            F   flags, bit-characters     0x002BC164

        and the flags alone decide how it is rendered.  0x002BC178 onwards:

            F & 0x00000004  -> kind 'cast'   "%s: *broadcast* %s"
            F & 0x00010000  -> kind 'priv'   "%s%s: *private* %s"
            neither         -> kind 'chat'   "%s%s: %s"

        then, for a 'priv' message only (0x0027328C):

            F & 0x40000000 and not F & 0x00200000
                -> hand the body to the challenge parser at 0x0028A460
                   instead of printing it

        `Lobby_SendChallenge` (0x0028A340) builds exactly that: TEXT is
        "challenge\n" followed by the match setup (COUR GLFR SHOT MFLG CFLG PTS
        RANK STUS PNG WIN LOSS TIE INC, all read back by 0x002897D0), PRIV names
        the target, and ATTR is 0x40000000 -- which is why the capture shows
        `ATTR=3`, '3' being bit 30.  Relaying that bit into F is the whole job.
        """
        text = tags.get('TEXT', '')
        target = tags.get('PRIV')
        attr = tagfield.flags_decode(tags.get('ATTR', ''))
        verb = text.split('\n', 1)[0]     # 'challenge' carries its setup after
        self.send('mesg', ident, {'~~': 'OK'})

        if verb in self.CHALLENGE_VERBS:
            log('***', '    CHALLENGE %r from %s to %s (ATTR=0x%08x)'
                % (verb, self.persona, target or '(room)', attr))
        if verb == 'challenge' and target and self.persona:
            # A NEW challenge is a new match.  `start_session` keeps one session
            # per pair so the two `chal`s of ONE acceptance get one seed -- but
            # that record used to outlive the match.  A pair whose first match
            # never connected (a Steam Deck and a Windows PC, 2026-09-19) then
            # challenged again, and the second acceptance got "already decided
            # -- not re-pushing": no `+ses` at all, so the retry could never
            # start.  Retire the old session and both halves' old agreement.
            pair = frozenset((self.persona, target))
            old = SESSIONS.pop(pair, None)
            for who in pair:
                if (MATCHED.get(who) or {}).get('opp') in pair:
                    MATCHED.pop(who, None)
            if old:
                log('***', '    new challenge between %s and %s -- the earlier '
                           'session (seed=%s) is retired'
                    % (self.persona, target, old.get('seed')))
            # Someone issuing a challenge is in the lobby, not in a match -- and
            # so is the player they challenge, but ONLY if that player is
            # connected.  A third player challenging someone away in a real
            # match must not end it.
            end_matches(self.persona, 'is issuing a challenge')
            if target in ONLINE:
                end_matches(target, 'is being challenged')
            # The setup rides on the challenge as `key=value` lines after the
            # verb: COUR GLFR SHOT MFLG CFLG and the challenger's own record.
            setup = {}
            for line in text.split('\n')[1:]:
                if '=' in line:
                    k, v = line.split('=', 1)
                    setup[k.strip()] = v.strip()
            if setup:
                PENDING_SETUP[frozenset((self.persona, target))] = setup
                log('***', '    setup: %s, clock %ss, MFLG=%s CFLG=%s'
                    % (twstats.course_name(setup.get('COUR')),
                       setup.get('SHOT', '?'), setup.get('MFLG', '?'),
                       setup.get('CFLG', '?')))
                # CFLG is one-hot per setting (twstats.cflg_groups).  Print the
                # decomposition so a run of one-setting-at-a-time challenges
                # can be read straight off the log.
                log('   ', '        conditions: %s'
                    % twstats.describe_cflg(setup.get('CFLG')))

        # The sender's ATTR is already the flag word the recipient needs; carry
        # it through rather than reconstructing it, so a verb we have not seen
        # yet still routes correctly.
        flags = attr & ~self.FL_IGNORE
        relay = {'N': self.persona or '', 'T': text}
        if verb not in self.CHALLENGE_VERBS:
            record_chat(self.persona, text, to=target or '',
                        room='' if target else WHERE.get(self.persona, ''),
                        via='private' if target else 'room')
        if target:
            relay['F'] = tagfield.flags_encode(flags | self.FL_PRIV)
            self.deliver(target, relay)
        else:
            relay['F'] = tagfield.flags_encode(flags)
            room = WHERE.get(self.persona)
            for who in self.occupants(room) if room else []:
                self.deliver(who, relay)

    def deliver(self, persona, tags):
        """Push a `+msg` to one persona's connection."""
        for h in list(CONNS):
            if h.persona == persona:
                try:
                    h.send('+msg', 0, tags)
                    log('***', '    relayed to %s' % persona)
                except OSError:
                    CONNS.discard(h)
                return
        log('!!!', '    %r is not connected; message dropped' % persona)

    def on_rept(self, ident, tags):
        """REPORT ABUSE -- `rept PERS PROD LANG`, built at 0x00275430 with no
        callback, so the reply is never read and the game shows its own "you
        have reported abuse from %s" regardless.

        Stored with the chat this server relayed (`chat_for_report`) for the
        operator's reports page on the web site.  The reporter is the persona
        this CONNECTION signed in as -- never a field the console fills in.
        """
        self.send('rept', ident, {'~~': 'OK'})
        accused = tags.get('PERS', '').strip()
        if not self.persona or not accused:
            log('!!!', '    report ignored: %s'
                % ('not signed in' if not self.persona else 'no PERS'))
            return
        if accused.lower() == self.persona.lower():
            return
        now = time.time()
        key = (self.persona.lower(), accused.lower())
        if now - REPORTED.get(key, 0) < REPORT_REPEAT:
            log('***', '    %s reported %s again within %ds -- not stored twice'
                % (self.persona, accused, REPORT_REPEAT))
            return
        REPORTED[key] = now
        chat = chat_for_report(self.persona, accused, now)
        room = WHERE.get(self.persona, '')
        try:
            rid = DB.add_report(self.persona, accused, room, chat)
        except Exception as exc:                        # noqa: BLE001
            log('!!!', '    could not store the report: %s' % exc)
            return
        # Deliberately NOT `note()`: the activity feed is public on /live.
        log('***', '    REPORT #%d: %s reported %s%s, %d line(s) of chat attached'
            % (rid, self.persona, accused, ' in %s' % room if room else '',
               len(chat)))

    def on_rank(self, ident, tags):
        """Lobby_SendTwoPlayerResults. _SendResultsCallback reads TITLE, MESG.

        Both consoles report the same match, so this lands twice -- once per
        REPT.  AUTH is the token we minted for the session in `+ses`, which is
        what ties a result to a match the server actually brokered."""
        fields = {k: v for k, v in tags.items()
                  if k != '~~' and isinstance(v, str)}
        token = fields.get('AUTH', '')
        ses = DB.session(token)
        who = self.persona or ''

        # Only a player who was in the match may report it, and only from the
        # connection they are logged in on.  `REPT` is the console's word for
        # who is speaking and is not evidence of anything; the persona this
        # socket authenticated as is.  Without this, anyone holding a session
        # token could file a result for two other people.
        if not ses:
            log('!!!', '    result from %s carries AUTH %r, which is not a '
                       'session this server brokered -- dropped'
                % (who or fields.get('REPT', '?'), token))
            return
        if who not in (ses['host'], ses['guest']):
            log('!!!', '    %r reported a result for %s vs %s, a match they '
                       'were not in -- dropped'
                % (who or '(not signed in)', ses['host'], ses['guest']))
            return

        DB.add_result(fields)
        # The match is over, so it is no longer one of the games in progress.
        # Both consoles report it; dropping a row twice is harmless.
        try:
            DB.stop_playing(token)
        except Exception as exc:                        # noqa: BLE001
            log('!!!', '    could not close the live match: %s' % exc)
        log('***', '    result from %s for %s vs %s in %r (%d fields, stored)'
            % (who, ses['host'], ses['guest'], ses['room'], len(fields)))
        note('result', '%s vs %s finished in %s'
             % (ses['host'], ses['guest'],
                room_label(ses['room']) or ses['room']), who=who)
        publish_live()
        self.send('rank', ident, {'~~': 'OK', 'TITLE': 'SUCCESS',
                                  'MESG': 'Game results were received by the server'})

    def on_pers(self, ident, tags):
        """Lobby_SetPersona -- the client picks one of the names we advertised
        in PERSONAS.  Register it so the other player can be told about it."""
        wanted = tags.get('PERS') or self.account
        if self.account_id is None or not DB.owns_persona(self.account_id, wanted):
            return self.fail('pers', ERR_NO_PERSONA,
                             '%r is not a persona on %r' % (wanted, self.account))
        self.persona = wanted
        DB.seen_persona(self.persona)
        # Signing in again means whatever match they were in is over -- it
        # finished, or the console crashed and came back.
        end_matches(self.persona, 'signed back in')
        ONLINE[self.persona] = self.peer
        # Normalised, because this is handed to the OTHER console as the
        # address to send UDP to, and a v6-mapped form would not parse there.
        seen = dotted_quad(self.client_address[0])
        if seen:
            REACH[self.persona] = seen
        else:
            log('!!!', '    %s is connected over IPv6 (%s); the game has no '
                       'way to express that, so peer-to-peer will need '
                       '--peer-addr or an IPv4 path'
                % (self.persona, self.client_address[0]))
        # Push the rooms again here as well as after `sele`.  By the time a
        # persona is selected the client is fully in the lobby, whereas the
        # `sele` reply is the very next frame after subscribing and may land
        # before the channel table is wired up.
        self.push_rooms()
        log('***', 'persona %r online from %s:%s; online now: %s'
            % (self.persona, self.peer[0], self.peer[1], ', '.join(sorted(ONLINE))))
        note('login', '%s came online' % self.persona, who=self.persona)
        publish_live()
        if len(ONLINE) > 1:
            log('***', '>>> TWO OR MORE PLAYERS ONLINE -- matchmaking is now testable')
        # The EA Messenger login key -- see "login keys live in the database"
        # near the top.  Hex, so it can never hold the ':' that would send the
        # connect call down its name:password path, and 32 characters inside
        # the 64-byte slot at lobby context +0x2B0.  One live key per persona:
        # issuing a new one retires the old.
        self.lkey = DB.issue_lkey(self.persona)
        self.send('pers', ident, {'~~': 'OK', 'LKEY': self.lkey,
                                  'EX-GAME': '0'})


class BuddyHandler(Handler):
    """EA Messenger -- the second server, on `--buddy-port`.

    Buddy and block lists (kept in the database), presence, and messages
    between players.  The protocol was read off the game's ELF; the first
    capture (2026-09-23) confirmed the login, both list requests, `PSET` and
    `RADD` exactly as read.

    Framing is the lobby's own -- the buddy sender 0x002C2350 calls the lobby
    frame writer 0x002B9478 -- so `handle` and `send` are inherited unchanged.
    Handlers are `bd_<verb>`; the verbs are upper case on this protocol.

    Replies echo the request's `ID`: the client matches `RADD` and `RDEL`
    replies to the pending entry by it (0x002C421C, 0x002C4384), and one
    without it leaves the entry pending for ever.
    """

    IN, OUT = '<B=', '=B>'
    PREFIX = 'bd_'

    # The client's own error table, 0x003029C0: the header's second word is
    # looked up there and the matching text is what the player sees.
    ERR_MISSING = 'miss'        # Required field missing
    ERR_AUTH = 'auth'           # Authorization error
    ERR_USER = 'user'           # User is invalid

    # The presence of someone not signed in.  `SHOW` indexes the table at
    # 0x00303DA0 -- DISC CHAT AWAY XA DND PASS -- and DISC is index 0, which is
    # also what a fresh roster entry starts as ("jed2 is offline").
    OFFLINE = {'SHOW': 'DISC'}

    def setup(self):
        self.buf = b''
        self.wlock = threading.Lock()
        self.persona = None
        # what this console last said about itself in `PSET`
        self.presence = dict(self.OFFLINE)
        BUDDY_CONNS.add(self)
        log('***', 'EA Messenger: connect from %s' % self.who())

    def finish(self):
        BUDDY_CONNS.discard(self)
        if self.persona and MESSENGER.get(self.persona) is self:
            del MESSENGER[self.persona]
            self.presence = dict(self.OFFLINE)
            self.announce()
        log('***', 'EA Messenger: %s disconnected (%s)'
            % (self.persona or 'an unauthenticated client', self.who()))

    def unhandled(self, name, ident, tags):
        # The dispatcher at 0x002C3A50 reads the header's ident for success,
        # and nothing in the body for most verbs, so an empty frame with ident
        # 0 is the least-committal "yes".
        log('!!!', '    EA Messenger: no handler for %r -- answering an empty '
                   'success' % name)
        self.send(name, 0, {'ID': tags['ID']} if 'ID' in tags else {})

    def refuse(self, verb, code, tags, why):
        log('!!!', '    EA Messenger %s refused (%s): %s' % (verb, code, why))
        self.send(verb, cc2i(code), {'ID': tags['ID']} if 'ID' in tags else {})

    # ---- presence --------------------------------------------------------

    @staticmethod
    def presence_of(persona, viewer):
        """The `PGET` `viewer` should get about `persona` right now.  Someone
        who has blocked the viewer reads as offline to them."""
        conn = MESSENGER.get(persona)
        tags = conn.presence if conn else BuddyHandler.OFFLINE
        if conn and DB.blocks(persona, viewer):
            tags = BuddyHandler.OFFLINE
        return dict(tags, USER=persona)

    def tell(self, persona):
        """Push `persona`'s presence to this console."""
        try:
            self.send('PGET', 0, self.presence_of(persona, self.persona))
        except OSError:
            pass

    def announce(self):
        """Push this persona's presence to everyone who has it as a buddy."""
        for watcher in DB.watchers(self.persona):
            conn = MESSENGER.get(watcher)
            if conn and conn is not self:
                conn.tell(self.persona)

    # ---- login -----------------------------------------------------------

    def bd_auth(self, ident, tags):
        """`AUTH PROD VERS PRES USER LKEY` -- built at 0x002C2B60.

        On success the game's callback (0x00285430) reads nothing from the
        reply and asks for both lists straight away with `RGET`.  Any non-zero
        ident is looked up in the error table and shown.
        """
        if 'PASS' in tags:
            # The name:password path -- the key string had a ':' in it.  The
            # lobby never produces one, so this means the reading is wrong.
            log('!!!', '    EA Messenger AUTH came with PASS, not LKEY -- the '
                       'connect call took its name:password path')
        key = tags.get('LKEY', '')
        persona = DB.lkey_persona(key)
        if not key:
            return self.refuse('AUTH', self.ERR_MISSING, tags, 'no LKEY')
        if not persona:
            return self.refuse('AUTH', self.ERR_AUTH, tags,
                               'an LKEY this server did not issue, or whose '
                               'lobby session has ended')
        self.persona = persona
        old = MESSENGER.get(persona)
        MESSENGER[persona] = self
        if old and old is not self:
            log('***', '    EA Messenger: %s signed in again; the older '
                       'connection is dropped' % persona)
            try:
                old.request.close()
            except OSError:
                pass
        log('***', '    EA Messenger: %s signed in (USER=%r PROD=%r PRES=%r)'
            % (persona, tags.get('USER'), tags.get('PROD'), tags.get('PRES')))
        self.send('AUTH', 0, {})

    def bd_pset(self, ident, tags):
        """`PSET SHOW STAT PROD` -- my presence, as the client states it:

            SHOW=CHAT
            STAT="en=\\"Tiger Woods 2004\\"\\nP=tig4\\n"
            PROD="JeddyH is online"

        Kept verbatim and relayed as `PGET` to everyone watching -- the parser
        at 0x002C2548 reads exactly these three names back."""
        if not self.persona:
            return self.refuse('PSET', self.ERR_AUTH, tags, 'not signed in')
        self.presence = {k: tags[k] for k in ('SHOW', 'STAT', 'PROD') if k in tags}
        self.presence.setdefault('SHOW', 'CHAT')
        log('***', '    EA Messenger: %s is %s' % (self.persona,
                                                   self.presence['SHOW']))
        self.send('PSET', 0, {})
        self.announce()

    # ---- lists -----------------------------------------------------------

    def bd_rget(self, ident, tags):
        """`RGET LRSC LIST PRES ID` -- fetch a list.  `LIST=B` (sent as ID=1)
        is buddies, `LIST=I` (ID=2) the ignore list.

        Reply `RGET ID SIZE`, then one `ROST ID USER GROUP` per entry.  The
        ROST `ID` names the list (0x002C3EC4: 1 flags the entry a buddy, 2
        blocked) and for list 2 the client counts `SIZE` down to know when the
        roster is complete.  With `PRES=Y` the presence of every buddy follows,
        as `PGET` -- after the ROSTs, because the parser drops a PGET for
        anyone not already on the roster (0x002C4074)."""
        if not self.persona:
            return self.refuse('RGET', self.ERR_AUTH, tags, 'not signed in')
        list_ = tags.get('LIST', 'B')
        rid = tags.get('ID', '0')
        rows = DB.buddy_list(self.persona, list_)
        log('***', '    EA Messenger: %s list %r -> %d: %s'
            % (self.persona, list_, len(rows),
               ', '.join(n for n, _ in rows) or '(empty)'))
        self.send('RGET', 0, {'ID': rid, 'SIZE': str(len(rows))})
        for name, group in rows:
            self.send('ROST', 0, {'ID': rid, 'USER': name, 'GROUP': group})
        if list_ == 'B' and tags.get('PRES') == 'Y':
            for name, _ in rows:
                if name in MESSENGER:
                    self.tell(name)

    def bd_radd(self, ident, tags):
        """`RADD LRSC ID LIST PRES USER GROUP` -- add to a list.

        Captured: `RADD ID=101 LIST=B PRES=Y USER=jed2 GROUP=`.  The client has
        already put the entry in its roster, flagged pending; the reply must
        carry the same `ID` to clear that, and `FUSR` renames the entry to the
        name as the server knows it (0x002C4280) -- so a buddy typed in the
        wrong case ends up spelled properly."""
        if not self.persona:
            return self.refuse('RADD', self.ERR_AUTH, tags, 'not signed in')
        list_ = tags.get('LIST', 'B')
        try:
            name = DB.add_buddy(self.persona, tags.get('USER', ''), list_,
                                tags.get('GROUP', ''))
        except twdb.Error as exc:
            return self.refuse('RADD', self.ERR_USER, tags, exc)
        log('***', '    EA Messenger: %s %s %s'
            % (self.persona, 'blocked' if list_ == 'I' else 'added', name))
        self.send('RADD', 0, {'ID': tags.get('ID', '0'), 'FUSR': name})
        if list_ == 'B' and name in MESSENGER:
            self.tell(name)
        elif list_ == 'I':
            # From now on I read as offline to them.
            conn = MESSENGER.get(name)
            if conn and self.persona in [n for n, _ in DB.buddy_list(name)]:
                conn.tell(self.persona)

    def bd_rdel(self, ident, tags):
        """`RDEL` -- the same shapes as `RADD`, to take someone off a list.
        The reply is matched by `ID` against the one pending delete
        (0x002C4384)."""
        if not self.persona:
            return self.refuse('RDEL', self.ERR_AUTH, tags, 'not signed in')
        list_ = tags.get('LIST', 'B')
        name = tags.get('USER', '')
        DB.drop_buddy(self.persona, name, list_)
        log('***', '    EA Messenger: %s %s %s'
            % (self.persona, 'unblocked' if list_ == 'I' else 'removed', name))
        self.send('RDEL', 0, {'ID': tags.get('ID', '0')})
        if list_ == 'I':
            conn = MESSENGER.get(name)
            if conn and self.persona in [n for n, _ in DB.buddy_list(name)]:
                conn.tell(self.persona)

    # ---- messages --------------------------------------------------------

    def bd_send(self, ident, tags):
        """`SEND TYPE USER BODY` -- a message.  Built at 0x0028671C: `TYPE=C`,
        `USER` the recipient, `BODY` already encoded by the sender (0x002C1D70)
        and decoded by the recipient (0x002C1E18), so it is relayed untouched.

        Delivered as `RECV` with `USER` rewritten to the SENDER -- the
        recipient's handler (0x002856C0) reads TYPE, USER and BODY.  A message
        that cannot be delivered gets a non-zero ident, which the sender's
        callback (0x00285CF0) turns into a dialog."""
        if not self.persona:
            return self.refuse('SEND', self.ERR_AUTH, tags, 'not signed in')
        to = tags.get('USER', '')
        target = MESSENGER.get(to) or next(
            (c for p, c in MESSENGER.items() if p.lower() == to.lower()), None)
        if not target:
            return self.refuse('SEND', self.ERR_USER, tags,
                               '%s -> %s: not on EA Messenger' % (self.persona, to))
        if DB.blocks(target.persona, self.persona):
            return self.refuse('SEND', self.ERR_USER, tags,
                               '%s -> %s: blocked' % (self.persona, to))
        relay = dict(tags, USER=self.persona)
        record_chat(self.persona, tags.get('BODY', ''), to=target.persona,
                    via='messenger')
        try:
            target.send('RECV', 0, relay)
        except OSError:
            return self.refuse('SEND', self.ERR_USER, tags,
                               '%s -> %s: connection gone' % (self.persona, to))
        log('***', '    EA Messenger: message %s -> %s (TYPE=%s)'
            % (self.persona, target.persona, tags.get('TYPE')))
        self.send('SEND', 0, {'ID': tags['ID']} if 'ID' in tags else {})

    def bd_ping(self, ident, tags):
        """The echo of our `PING`.  The client bounces EVERY inbound `PING`
        straight back (0x002C3D10) and never originates one, so this is only
        ever an echo -- and answering it would ping-pong for ever."""

    def bd_disc(self, ident, tags):
        log('***', '    EA Messenger: %s said goodbye'
            % (self.persona or 'an unauthenticated client'))


def buddy_keepalive():
    """`PING` every Messenger connection on the lobby's schedule.  Whether the
    buddy client has an idle timer of its own is not known yet, and the client
    answers `PING` by itself, so this costs nothing and rules one thing out."""
    while not PING.wait(ARGS.ping):
        for h in list(BUDDY_CONNS):
            try:
                h.send('PING', 0, {})
            except OSError:
                BUDDY_CONNS.discard(h)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler):
        """Listen on IPv6 as well when asked, without giving up IPv4.

        The console can only ever dial IPv4 -- see `dotted_quad` -- so this is
        not about consoles.  It is about whatever sits between: a relay, a
        tunnel, or a host doing 464XLAT for an emulator on an IPv6-only
        network.  Those arrive over v6 and are perfectly serviceable.

        `::` with IPV6_V6ONLY off takes both families on one socket, which is
        why there is no second listener here.
        """
        host = addr[0]
        if ':' in host:
            self.address_family = socket.AF_INET6
        socketserver.ThreadingTCPServer.__init__(self, addr, handler)

    def handle_error(self, request, client_address):
        # socketserver's default prints to stderr; keep it in the log.
        log_exception('a connection from %s' % (client_address,))

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6,
                                       socket.IPV6_V6ONLY, 0)
            except OSError as exc:      # some systems refuse; v4 is then lost
                log('!!!', 'could not make the socket dual-stack (%s); '
                           'IPv4 clients will not be able to connect' % exc)
        socketserver.ThreadingTCPServer.server_bind(self)


def main(argv=None):
    global ARGS
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--host', default='0.0.0.0',
                    help="where to listen.  '::' takes IPv6 and IPv4 on one "
                         'socket, which is worth doing even though no console '
                         'can speak IPv6 -- a relay or a tunnel in front of one '
                         'can, and arrives that way')
    ap.add_argument('--port', type=int, default=None,
                    help='defaults to whatever setup_pcsx2.py patched the game to')
    ap.add_argument('--password', help='what you will type at the login screen; '
                                       'checked, never printed')
    ap.add_argument('--log-passwords', action='store_true',
                    help='PUT PASSWORDS IN THE LOG.  Only for working on the '
                         'cipher, and only against accounts you own -- the log '
                         'is a plain file and this writes real credentials into '
                         'it.')
    ap.add_argument('--persona', default='tester')
    # Room names are HIERARCHICAL: "<type>.<id>.<name>".  The lobby screen
    # builds a prefix with sprintf("%s.%s.", type, id) at 0x00275A48 and then
    # strncmp's every list entry's name against it (0x00275AC4) -- entries that
    # do not start with the prefix are invisible, however many are in the list.
    #   type: 0 -> "Stroke", 1 or 0x19 -> "Match"   (0x0029B370)
    #   id:   0..5 -> "T" "I" "G" "E" "R" "C"       (table at 0x00303850)
    #
    # Each ROW of the browser is one id letter, and a row with no rooms leaves
    # the selected-name buffer at 0x003B6E58 empty -- which is the -10
    # "Invalid name." error.  So seed every id, or navigating onto an empty row
    # fails.  Confirmed so far: T = EAST/WEST, C = CREATED (the client named its
    # own room Match.C.iii from CREATE ROOM).  The Lobby<letter> naming makes the
    # rest self-identifying: whatever a row displays tells you its letter.
    ap.add_argument('--rooms', nargs='*', default=default_rooms(),
                    help='room names to push after sele; must be <type>.<id>.<name>')
    ap.add_argument('--probe-stats', action='store_true',
                    help='fill every statistic with its own field index, so the '
                         'resume screen names its own fields.  A mapping aid, '
                         'not real data.')
    ap.add_argument('--months', type=int, default=1,
                    help='how many months PAST the current one to generate '
                         '(default 1).  A console asking about anything further '
                         'out gets an empty calendar, whatever its clock says.')
    ap.add_argument('--calendar-tick', type=float, default=300,
                    help='seconds between checks for the turn of the month '
                         '(default 300)')
    ap.add_argument('--probe-icons', action='store_true',
                    help='give every day of the calendar a different icon '
                         'number, to find out how many there are and what they '
                         'look like.  A mapping aid, not real data.')
    ap.add_argument('--probe-conditions', action='store_true',
                    help='answer the tournament calendar with one event '
                         'condition set per day, each event NAMED for what the '
                         'UPCOMING EVENT screen should then show (TEES WHITE), '
                         'to confirm the condition flags.  Today stays a normal '
                         'event.  A check for a LAN server, not real data.')
    ap.add_argument('--probe-tourney', action='store_true',
                    help='answer the tournament calendar with entries whose 16 '
                         'data bytes hold their own offsets, so a screen names '
                         'its own fields.  A mapping aid, not real data.')
    ap.add_argument('--news', default=os.path.join(
                        os.path.dirname(twdb.DEFAULT_DB), 'news.txt'),
                    help='text file shown on the in-game news screen, re-read '
                         'on every request so it can be edited live')
    ap.add_argument('--backup-dir', default='',
                    help='where the daily database copies go (default: '
                         'backups/ beside the database)')
    ap.add_argument('--backup-keep', type=int, default=7,
                    help='daily copies to keep (default 7); 0 turns backups '
                         'off')
    ap.add_argument('--no-auto-news', action='store_true',
                    help='show only the --news text on the news screen, '
                         'without the generated digest (today\'s event, '
                         'yesterday\'s winner, new records, the week)')
    ap.add_argument('--buddy-addr', metavar='HOST:PORT',
                    help='the EA Messenger server handed out after login.  '
                         'Leave unset until one exists -- the client checks for '
                         'an empty reply and carries on.')
    ap.add_argument('--buddy-port', type=int, default=10202,
                    help='the EA Messenger server (buddy lists, presence, '
                         'messages) runs on this TCP port, handed out after '
                         'login at the address the console reached the lobby '
                         'on (--buddy-addr overrides that, e.g. behind NAT).  '
                         'Default 10202; 0 turns it off.  On by default because '
                         'a lobby restarted without it leaves consoles that '
                         'were using it with blank buddy lists')
    ap.add_argument('--db', default=twdb.DEFAULT_DB,
                    help='the account database, shared with webui.py.  '
                         'The default is beside the project, not beside wherever '
                         'you happen to be standing.')
    ap.add_argument('--open', action='store_true',
                    help='create an account on first login instead of refusing '
                         'it.  Handy on a LAN, wrong on the internet.')
    ap.add_argument('--peer-addr',
                    help='the address to put in the +ses ADDR field instead of '
                         'what the peer reported.  Under the Sockets DEV9 '
                         'backend every PS2 is 192.0.2.100, so the reported '
                         'address is useless and lobbyd substitutes the host '
                         'it was reached on; use this to override that.')
    ap.add_argument('--ping', type=float, default=20.0,
                    help='seconds between `~png` keepalives; the client drops '
                         'the session after 60 s of silence, so keep this well '
                         'under that.  0 disables it.')
    ap.add_argument('--logfile', default=DEFAULT_LOG,
                    help='the one log file, every frame and event (default '
                         'logs/lobbyd.log beside data/).  Empty for none')
    ap.add_argument('--log-max-mb', type=float, default=twlog.DEFAULT_MAX_MB,
                    help='roll the log over at this size (default %d MB)'
                         % twlog.DEFAULT_MAX_MB)
    ap.add_argument('--log-keep', type=int, default=twlog.DEFAULT_KEEP,
                    help='rolled-over copies to keep, lobbyd.log.1 onwards '
                         '(default %d)' % twlog.DEFAULT_KEEP)
    ap.add_argument('--quiet', action='store_true',
                    help='write the log file only, not the console as well -- '
                         'for running under tw04.sh, which would otherwise '
                         'store every line twice')
    ap.add_argument('-v', '--verbose', action='store_true', help='hexdump every frame')
    ARGS = ap.parse_args(argv)

    global LOG
    LOG = twlog.Log(ARGS.logfile, max_bytes=ARGS.log_max_mb * (1 << 20),
                    keep=ARGS.log_keep, echo=not ARGS.quiet)
    threading.excepthook = lambda a: log_exception(
        'thread %s' % (a.thread.name if a.thread else '?'))

    rig = rig_config()
    if ARGS.port is None:
        ARGS.port = rig.get('port', 10200)
    elif rig.get('port') and rig['port'] != ARGS.port:
        print('WARNING: the game is patched to dial port %d, but you asked for %d.'
              % (rig['port'], ARGS.port))
        print('         The emulator will log WSAECONNREFUSED (10061), which '
              'looks exactly like the server being down.')

    if ARGS.logfile:
        log('***', 'logging to %s (rolls over at %g MB, keeps %d)'
            % (LOG.path, ARGS.log_max_mb, LOG.keep))

    global DB
    DB = twdb.DB(ARGS.db)
    known = DB.count_accounts()
    log('***', 'accounts in %s -- %d registered%s'
        % (DB.path, known, ' (open registration)' if ARGS.open else ''))
    if not known and not ARGS.open:
        log('!!!', 'that database has no accounts, so every login will be '
                   'refused.')
        log('!!!', 'point webui.py at the SAME path -- it prints the one '
                   'it opened -- or pass --open.')
    if ARGS.probe_stats:
        log('!!!', 'PROBE MODE -- statistics are field indices, not real values')
    if ARGS.probe_conditions:
        global PROBE_ANCHOR
        PROBE_ANCHOR = twtourney.today()
        log('!!!', 'PROBE MODE -- tournament event conditions: each day is '
                   'named for what UPCOMING EVENT should show (from %s):'
            % twtourney.from_day(PROBE_ANCHOR + 1))
        day = PROBE_ANCHOR + 1
        while twtourney.probe_condition_for(day, PROBE_ANCHOR):
            name, _conds = twtourney.probe_condition_for(day, PROBE_ANCHOR)
            log('!!!', '    %s  %s' % (twtourney.from_day(day), name))
            day += 1
    if ARGS.probe_tourney:
        log('!!!', 'PROBE MODE -- tournament data bytes are their own offsets')
    if ARGS.probe_icons:
        log('!!!', 'PROBE MODE -- every calendar day carries a different icon')
    log('***', 'news from %s%s' % (ARGS.news, '' if os.path.isfile(ARGS.news)
                                  else ' (not there -- using the built-in '
                                       'message; create it to change that)'))
    if ARGS.buddy_port:
        if ARGS.buddy_port == ARGS.port:
            ap.error('--buddy-port must differ from the lobby port (%d)'
                     % ARGS.port)
        log('***', 'EA Messenger listening on %s:%d, advertised as %s'
            % (ARGS.host, ARGS.buddy_port,
               ARGS.buddy_addr or '<the address each console reached the '
                                  'lobby on>:%d' % ARGS.buddy_port))
    elif ARGS.buddy_addr:
        log('***', 'EA Messenger server advertised as %s' % ARGS.buddy_addr)
    log('***', 'session key %s' % SESSION_KEY.hex())
    if ARGS.log_passwords:
        log('!!!', 'LOGGING PASSWORDS IN CLEAR -- %s will contain real '
                   'credentials' % (ARGS.logfile or 'this console'))
    if ARGS.password and ARGS.log_passwords:
        log('***', 'expecting password %r -> %r' % (
            ARGS.password, '~' + eacrypt.encode(ARGS.password, SESSION_KEY).decode('latin-1')))
    elif ARGS.password:
        log('***', 'checking each login against the expected password '
                   '(%d chars); use --log-passwords to see it' % len(ARGS.password))
    log('***', 'listening on %s:%d' % (ARGS.host, ARGS.port))
    if rig:
        log('***', 'the game is patched to dial %s:%s'
            % (rig.get('ip'), rig.get('port')))
    try:
        addrs = sorted({i[4][0] for i in socket.getaddrinfo(
            socket.gethostname(), None, socket.AF_INET)})
    except OSError:
        # A host whose own name does not resolve is normal on a fresh Linux
        # box; it is a convenience line, not a requirement.
        addrs = []
    for ip in addrs:
        log('***', '  this machine is %s on the LAN' % ip)

    # A server that was killed could not tidy up after itself, so anyone it
    # thought was online is still sitting in the table.  Nobody is connected
    # yet, so the truth right now is "nobody".
    DB.clear_all_presence()
    DB.set_live('started', int(time.time()))
    DB.set_live('port', ARGS.port)
    DB.set_live('rooms', ' '.join(ARGS.rooms))
    publish_live()
    note('server', 'the master server started up')
    threading.Thread(target=heartbeat, daemon=True).start()
    if ARGS.backup_keep > 0:
        ARGS.backup_dir = ARGS.backup_dir or os.path.join(
            os.path.dirname(DB.path), 'backups')
        log('***', 'daily database backups in %s, keeping %d'
            % (ARGS.backup_dir, ARGS.backup_keep))
        threading.Thread(target=backup_tick, daemon=True).start()

    if ARGS.ping > 0:
        log('***', 'keepalive: ~png every %gs (the client drops at 60s idle)'
            % ARGS.ping)
        threading.Thread(target=keepalive, daemon=True).start()
        ensure_season()
        threading.Thread(target=calendar_tick, daemon=True).start()
    else:
        log('***', 'keepalive DISABLED -- expect a disconnect after 60s idle')

    if ARGS.buddy_port:
        buddy = Server((ARGS.host, ARGS.buddy_port), BuddyHandler)
        threading.Thread(target=buddy.serve_forever, daemon=True).start()
        if ARGS.ping > 0:
            threading.Thread(target=buddy_keepalive, daemon=True).start()

    with Server((ARGS.host, ARGS.port), Handler) as srv:
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            PING.set()
            CALENDAR.set()
            # Say so, so the web site reports the server as down rather than
            # leaving its last heartbeat to go stale over the next few minutes.
            try:
                DB.clear_all_presence()
                DB.set_live('heartbeat', 0)
                note('server', 'the master server shut down')
            except Exception:                           # noqa: BLE001
                pass
            log('***', 'stopped')


if __name__ == '__main__':
    main()
