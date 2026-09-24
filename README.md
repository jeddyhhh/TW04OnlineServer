# Tiger Woods PGA Tour 2004 — online master server

A replacement for EA's long-dead online service for **Tiger Woods PGA Tour 2004**
on the PlayStation 2, for playing online through the
[PCSX2](https://pcsx2.net) emulator.

It brings back the game's whole online menu:

- **Lobby:** accounts and personas, game rooms, chat, and challenges.
- **Head-to-head play:** match play and stroke play, with results recorded.
- **Online tournaments:** a daily event with its own leaderboards.
- **Leaderboards and stats:** your rank and statistics on the in-game screens.
- **EA Messenger:** buddy lists, blocking, who's online, and messages between players.
- **In-game news:** your own text, plus a digest the server writes from recent results.
- **Report abuse:** reports are stored with the chat that led up to them.

Alongside the lobby runs a **web site**. Players create their account and
download the game patch there. It also shows live server status, leaderboards,
the tournament calendar, player profiles, tour stats, records and course pages.

Both are plain Python with **no dependencies**: no framework, no database
server, no build step.

> This is a fan project. It is not affiliated with, endorsed by or connected to
> Electronic Arts or Sony. No game files, BIOS or disc images are included, and
> none are needed to run the server.

---

## Contents

- [What you need](#what-you-need)
- [Quick start](#quick-start)
- [Windows: one-window server for a home network](#windows-one-window-server-for-a-home-network)
- [How it fits together](#how-it-fits-together)
- [Running it for real](#running-it-for-real)
- [How players connect](#how-players-connect)
- [Looking after it](#looking-after-it)
- [Options](#options)
- [Files it creates](#files-it-creates)
- [Tests](#tests)
- [Troubleshooting](#troubleshooting)
- [Known limits](#known-limits)

---

## What you need

- **Python 3.8 or newer.** There's nothing to `pip install`.
- A machine that players can reach on:

| Port | Protocol | What uses it |
|---|---|---|
| 10200 | TCP | the lobby (`lobbyd.py`); consoles connect straight to it |
| 10202 | TCP | EA Messenger (buddy lists, presence, messages), inside `lobbyd.py` |
| 8080 | TCP | the web site (`webui.py`), or whatever you put in front of it |

The game itself (a match between two players) is peer-to-peer over **UDP 3658**
directly between the players. It never goes through this server; see
[Known limits](#known-limits).

## Quick start

```bash
git clone <this repository>
cd <repository folder>

python3 webui.py --port 8080      # the web site
python3 lobbyd.py                 # the lobby, on port 10200
```

Run each in its own terminal. Then open `http://localhost:8080/`, create an
account, and follow the **Connect from PCSX2** steps on that page to point a
game at the server.

The site marks its login cookie `Secure`, which browsers accept over plain HTTP
only at `localhost`. To try it from another machine before you've set up
HTTPS, add `--no-secure-cookie`, or you'll be signed straight back out.

Both programs open the same database, `data/tw04.db`, next to the scripts. It's
created the first time either one starts. Each prints the full path it opened.
**If those two paths ever differ, accounts made on the web site won't exist at
the game's login screen.**

## Windows: one-window server for a home network

`tw04_local.py` runs the lobby and the web site together in one window, set up
for playing on a home network with nothing to configure:

```bash
python tw04_local.py
```

or build it into a single `.exe` that anyone can double-click:

```bash
pip install pyinstaller
python -m PyInstaller --onefile --console --name TW04-LocalServer --hidden-import make_pnach tw04_local.py
```

The exe appears in `dist\`. When it runs, it:

- finds this PC's address on the network, and makes the web site hand out a
  patch pointing the game at it;
- keeps everything in `data\` and `logs\` next to the exe;
- lets players sign in at the console with any new name and password; the
  account is created on first sign-in, so the web site is optional
  (`--closed` turns this off);
- lets people sign in to the web site over plain `http://` from other PCs;
- tells you if it's already running, or if a port it needs is taken.

The window shows the web site's address. Players on the network open it,
download the patch, and follow the connection steps. Close the window to stop
the server. If Windows asks whether to allow it on the network, allow **private
networks**, or other PCs can't connect. If the PC has more than one network
address and the wrong one is picked, add `--ip <address>` to the end of a
shortcut's Target.

## How it fits together

```
 PCSX2 + the game ──TCP 10200──▶  lobbyd.py  ──┐
          │         ──TCP 10202──▶  (Messenger) │
          │                                    ├──▶  data/tw04.db  (SQLite)
          │                                    │
          └── UDP 3658 to the other player     │
                                               │
 web browser ─────────HTTP──────▶  webui.py  ──┘
```

- **`lobbyd.py`** talks to the consoles. It speaks EA's lobby protocol,
  introduces two players to each other when a challenge is accepted, and
  records results. It also writes the live picture (who's online, matches in
  play) into the database for the web site.
- **`webui.py`** is the web site. It only ever reads what the lobby has
  written, apart from account sign-up and account management.
- **The game patch.** The lobby's address is an IP written into the game disc,
  so every player's game has to be patched to reach your server. The web site
  builds that patch (a PCSX2 `.pnach` file) for *your* server on demand, so
  there's nothing to prepare by hand.

The supporting modules, for anyone reading the code:

| File | What it is |
|---|---|
| `twdb.py` | the database: accounts, personas, results, tournaments, buddy lists, reports |
| `twrecords.py` | player pages, stat leaders, records, course pages, and the news digest |
| `twtourney.py` | the online tournament calendar and its wire format |
| `twstats.py` | the packed statistics record, and the course list |
| `tagfield.py`, `eacrypt.py` | EA's message encoding and the login password cipher |
| `make_pnach.py` | builds the game patch |
| `twlog.py` | the size-capped log both programs write |
| `tw04.sh` | runs and supervises both on Linux (see below) |
| `tw04_local.py` | runs both in one window for a home network (see above) |

## Running it for real

### As a service (Linux)

`tw04.sh` starts both programs and restarts either one a few seconds after it
exits, so a crash doesn't need anyone to notice:

```bash
chmod +x tw04.sh
./tw04.sh start            # start both; safe to run again, won't double-start
./tw04.sh start webui      # just one of them
./tw04.sh status
./tw04.sh restart [lobbyd|webui]
./tw04.sh stop [lobbyd|webui]
./tw04.sh log lobbyd       # follow a log
```

Settings are at the top of the script, or can be given in the environment:

| Setting | Default | Meaning |
|---|---|---|
| `LOBBY_PORT` | `10200` | the lobby's TCP port |
| `BUDDY_PORT` | `10202` | EA Messenger's TCP port; empty to run without it |
| `BUDDY_ADDR` | *(empty)* | `host:port` to give consoles for Messenger, if this machine's own address isn't the public one (behind NAT) |
| `WEB_HOST` | `127.0.0.1` | where the web site listens; keep it local behind a reverse proxy |
| `WEB_PORT` | `8080` | the web site's port |
| `WEB_BASE` | `/TW04Online` | the path the site is served under |
| `LOG_MAX_MB` / `LOG_KEEP` | `10` / `3` | each log rolls over at this size, keeping this many old copies |
| `PYTHON` | `python3` | the interpreter to use |

To start everything at boot, add this to `crontab -e`, as the user that owns
the files rather than root:

```cron
@reboot /path/to/repository/tw04.sh start
```

Optionally, add a watchdog that restarts anything that isn't running:

```cron
* * * * * /path/to/repository/tw04.sh start >/dev/null 2>&1
```

### Behind a web server, with HTTPS

The web site is plain HTTP, so put it behind a reverse proxy that handles TLS.
With Apache, serving it at `https://example.com/TW04Online`:

```apache
# a2enmod proxy proxy_http
ProxyPreserveHost On
ProxyPass        /TW04Online  http://127.0.0.1:8080/TW04Online
ProxyPassReverse /TW04Online  http://127.0.0.1:8080/TW04Online
```

and run the site on localhost with the matching path, which `tw04.sh` does by
default:

```bash
python3 webui.py --host 127.0.0.1 --port 8080 --base-path /TW04Online --trust-proxy
```

- **`--trust-proxy` matters here.** Without it, every visitor appears to come
  from `127.0.0.1`, so the site's lockout after repeated wrong passwords becomes
  one shared counter for everybody. Only use it with a proxy actually in front,
  because anyone who can reach the port directly can fake the header it reads.
- **The session cookie is marked `Secure`.** `--no-secure-cookie` exists only
  for testing over plain HTTP.
- **If the downloaded patch points players at the wrong address**, start the
  site with `--advertise <your public hostname or IPv4>`. It works out the
  address automatically otherwise. It's also needed if the lobby runs on a
  different machine from the site.

Only the web site goes behind the proxy. Consoles connect straight to TCP 10200
and 10202, so open both on your firewall.

### Before it faces the internet

- Put HTTPS in front of the web site (above).
- Don't run `lobbyd.py` with `--open`. It creates an account for anyone who
  types a new name at the console, which is handy on a LAN and wrong on the
  internet.
- Open TCP 10200 and 10202 on the firewall.

## How players connect

The web site's front page walks players through all of this and gives them the
patch file. In short, in PCSX2:

1. **Install the patch.** Download the `.pnach` file from the site and put it
   in PCSX2's `cheats` folder, keeping its name exactly: PCSX2 matches it to
   the disc by name. Then right-click the game → *Properties* → *Patches* and
   tick **Enable Cheats**.
2. **Turn on networking.** Settings → Network & HDD:
   - tick **Enable Network (DEV9)**;
   - set the Ethernet device type to **Sockets**;
   - set **Ethernet Device** to the network adapter you use on **Windows**, and
     to **Auto** on **Linux and the Steam Deck**; naming the adapter there gets
     you into the lobby, but matches never start;
   - set **DNS1** to a real resolver, such as your router or `1.1.1.1`.
     Leaving it on Auto makes the game's DNAS screen slow, especially on Linux.
3. **Sign in.** Create an account on the web site, then sign in on the
   console's ONLINE menu with the same account name and password. Choose a
   persona on the SELECT ACCOUNT screen.

The patch never modifies the disc image. Deleting the `.pnach` file undoes it.
It works with **Tiger Woods PGA Tour 2004, USA (NTSC-U), serial `SLUS-20757`,
CRC `64F9781E`**, and no other release.

## Looking after it

### Accounts

```bash
python3 twdb.py --list
python3 twdb.py --create-account NAME --password PASS [--persona PERSONA]
python3 twdb.py --add-persona ACCOUNT PERSONA
python3 twdb.py --set-password ACCOUNT PASS
python3 twdb.py --disable ACCOUNT        # a ban; --enable undoes it
```

Players normally manage their own accounts and personas on the web site. An
account can hold up to four personas.

### News

The game's news screen shows the text of `data/news.txt`, if it exists. It's
re-read on every request, so you can edit it while the server runs. Below it,
the server adds a digest it writes itself: today's event and leader,
yesterday's winner, the week's new records, and the busiest player.
`--no-auto-news` turns the digest off.

### Abuse reports

When a player uses REPORT ABUSE in the game, the report is stored with the
chat the server relayed in the hour before. Reports are listed on a page that
nothing links to:

```
<your site>/reports/<key>
```

The key is created the first time the web site starts, kept in
`data/reports.key`, and printed at every start. Anyone with the address can
read the reports, so keep it private. To change it, delete the file and
restart the site. `webui.py --reports-key off` turns the page off. Banning is
done from the shell, with `twdb.py --disable`.

## Options

The most useful ones; `--help` on either program lists them all.

**`lobbyd.py`**

| Option | Default | Meaning |
|---|---|---|
| `--port N` | `10200` | the lobby's TCP port; it must match the port in the players' patch |
| `--host ADDR` | `0.0.0.0` | where to listen; `::` takes IPv6 and IPv4 together |
| `--buddy-port N` | `10202` | EA Messenger's port; `0` turns it off |
| `--buddy-addr HOST:PORT` | | the Messenger address to give consoles, when this machine's own address isn't the public one |
| `--db PATH` | `data/tw04.db` | the database; must be the same file the web site uses |
| `--news FILE` | `data/news.txt` | the news screen text |
| `--no-auto-news` | | the news file only, without the generated digest |
| `--open` | | create an account on first login instead of refusing it (LAN only) |
| `--logfile FILE` | `logs/lobbyd.log` | the log; `''` for none |
| `--quiet` | | log to the file only, not the terminal too |
| `--log-max-mb` / `--log-keep` | `10` / `3` | log rollover size and copies kept |
| `-v, --verbose` | | hex dump of every message, for debugging |

**`webui.py`**

| Option | Default | Meaning |
|---|---|---|
| `--port N` | `8080` | the site's port |
| `--host ADDR` | `0.0.0.0` | where to listen; use `127.0.0.1` behind a proxy |
| `--base-path PATH` | | serve under a path, e.g. `/TW04Online` |
| `--trust-proxy` | | read the visitor's address from `X-Forwarded-For` (proxy only) |
| `--advertise HOST` | | the address the downloadable patch points players at |
| `--lobby-port N` | `10200` | the lobby port put in the patch, if the lobby hasn't published one |
| `--no-secure-cookie` | | for testing over plain HTTP only |
| `--reports-key KEY` | *(from `data/reports.key`)* | the abuse-reports page's secret; `off` turns the page off |
| `--db PATH` | `data/tw04.db` | the database; must be the same file the lobby uses |
| `--logfile FILE` | `logs/webui.log` | the request log; `''` for none |

## Files it creates

Everything the servers write goes in two folders next to the scripts. Both are
in `.gitignore`.

| Path | What it is |
|---|---|
| `data/tw04.db` | the database: every account and password hash, results, tournaments, buddy lists and reports. **Back this up.** |
| `data/reports.key` | the secret in the abuse-reports page's address |
| `data/news.txt` | your news text, if you create it |
| `logs/lobbyd.log`, `logs/webui.log` | the logs, each capped at `LOG_MAX_MB` with `LOG_KEEP` old copies |

Passwords are stored as salted PBKDF2 hashes, and they're kept out of the logs
unless you start the lobby with `--log-passwords`, a debugging switch that
says so loudly when it's on.

## Tests

Each test starts a real server on a spare port with a throwaway database, and
drives it the way the game does:

```bash
python3 tests/lobbyd_selftest.py      # message format and the password cipher
python3 tests/lobbyd_authtest.py      # only real credentials get in
python3 tests/lobbyd_roomtest.py      # rooms, challenges, rematches
python3 tests/lobbyd_livetest.py      # the live picture the web site reads
python3 tests/lobbyd_buddytest.py     # EA Messenger
python3 tests/lobbyd_reporttest.py    # abuse reports and their private page
python3 tests/twdb_statstest.py       # scoring real captured rounds
python3 tests/webui_pagestest.py      # player, stats, records and course pages; the news
```

Most modules also test themselves: `python3 twrecords.py`, `twlog.py`,
`twtourney.py`, `twstats.py`, `tagfield.py` and `eacrypt.py`.

## Troubleshooting

- **Nobody can sign in, but the web site works.** The two programs are using
  different databases. Compare the path each one prints at startup.
- **The console says the server can't be reached.** Check the lobby is running
  and TCP 10200 is open. Also check the port in the players' patch matches
  `--port`: a port mismatch looks exactly like a server that's down.
- **Players get into the lobby, but matches never start.** The two players have
  to reach each other on UDP 3658, as the lobby only introduces them. Check each
  player can receive on that port (a port forward, behind a home router). On
  Linux or a Steam Deck, check the Ethernet Device is set to **Auto**. Wi-Fi
  networks that isolate devices from each other also break this.
- **The DNAS screen takes 30 seconds or more.** Set DNS1 in PCSX2 to a real
  resolver (see [How players connect](#how-players-connect)).
- **What happened to that connection?** `logs/lobbyd.log` records every
  message both ways. Passwords are always redacted.

## Known limits

- **Matches are peer-to-peer.** The two consoles play each other directly over
  UDP 3658, and there's no relay. Each player needs that port reachable (a port
  forward behind a home router). Two players behind the same router can play
  each other through an internet-hosted lobby only if their router supports
  "hairpin" NAT (NAT loopback); many do.
- **IPv4 only, for players.** The game can only express IPv4 addresses. The
  lobby can listen on IPv6 (`--host ::`), but a player connecting over IPv6
  can't be introduced to an opponent.
- **Two emulators on one PC can't play each other**, because both need UDP
  3658.
- **DNAS is passed, not removed.** The patch makes the game's dead Sony DNAS
  check succeed, but the game still tries to reach Sony first, hence the DNS1
  advice above.
- **Only the one disc.** The patch is a list of addresses in one build of the
  game (`SLUS-20757`). Other regions and Tiger Woods PGA Tour 2005 aren't
  supported.
