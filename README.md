# TW04 master server

Everything needed to run the lobby and the web site. Nothing here needs
anything installed beyond Python 3 -- no framework, no database server, no
build step.

## Running it

    python3 webui.py --port 8080      # the sign-up site
    python3 lobbyd.py                 # the lobby, on port 10200

Both open the same SQLite file, `data/tw04.db`, created beside these files on
first run. Each prints the absolute path it opened at startup; **if those two
paths ever differ, accounts made on the site will not exist at the login
screen.**

Players register on the web site and sign in on the console with the same
account name and password. The personas on an account are the names offered on
the console's SELECT ACCOUNT screen.

## Useful switches

    lobbyd.py --open            create an account on first login instead of
                                refusing it -- convenient on a LAN, wrong on
                                the internet
    lobbyd.py --news FILE       the in-game news text, re-read on every request
                                so it can be edited while running.  It is
                                shown first, then a digest written from the
                                results: today's event and leader, yesterday's
                                winner, new records, the week's busiest player
    lobbyd.py --no-auto-news    the news file only, no digest
    lobbyd.py --probe-stats     fill every statistic with its own field index,
                                for mapping the resume screen; not real data
    lobbyd.py --probe-tourney   fill the tournament calendar with entries whose
                                data bytes hold their own offsets; not real data
    lobbyd.py --probe-icons     give every calendar day a different icon number,
                                to see how many there are; not real data
    lobbyd.py --logfile FILE    where the one log goes (default
                                logs/lobbyd.log); '' for none
    lobbyd.py --quiet           log to the file only, not the console too
    lobbyd.py --buddy-port N    the EA Messenger server (buddy and block
                                lists, who is online, messages) runs on TCP
                                N, default 10202 -- it has to be open on the
                                firewall too.  0 turns it off.  --buddy-addr
                                HOST:PORT overrides the address handed out
                                (behind NAT)
    webui.py --host 127.0.0.1   bind somewhere other than every interface

Passwords are never written to the log. `--log-passwords` turns that off for
cipher work and says so loudly; it writes real credentials to a plain file.

## Running it as a service

`tw04.sh` starts both, keeps them up, and writes to `logs/`: one file each,
`logs/lobbyd.log` and `logs/webui.log`. Each rolls over at `LOG_MAX_MB`
(default 10) into `.1`, `.2` ..., keeping `LOG_KEEP` (default 3) old copies, so
the logs can never take more than about 40 MB apiece.

    ./tw04.sh start          start both; safe to run again, will not double-start
    ./tw04.sh start webui    just the one
    ./tw04.sh status
    ./tw04.sh restart [name]
    ./tw04.sh stop [name]
    ./tw04.sh log lobbyd     follow a log

Each service runs inside a loop that restarts it a few seconds after it exits,
so a crash does not need a person. Settings at the top of the script, or in the
environment: `LOBBY_PORT`, `BUDDY_PORT`, `BUDDY_ADDR`, `WEB_PORT`, `WEB_HOST`,
`WEB_BASE`, `LOG_MAX_MB`, `LOG_KEEP`, `PYTHON`.

`BUDDY_PORT` (default 10202) runs EA Messenger alongside the lobby; set it
empty (`BUDDY_PORT= ./tw04.sh restart lobbyd`) to run without it.
`BUDDY_ADDR=HOST:PORT` is only for a server behind NAT, where the address the
consoles should dial is not this machine's own.

On reboot, from `crontab -e`:

    @reboot /home/YOU/TW04Online/tw04.sh start

or, for one of them on its own:

    @reboot /home/YOU/TW04Online/tw04.sh start webui

and optionally a watchdog, in case the supervisor itself is ever killed:

    * * * * * /home/YOU/TW04Online/tw04.sh start >/dev/null 2>&1

Use the crontab of the user that owns the files (`crontab -e`, not `sudo
crontab -e`), or the services run as root and write root-owned logs and a
root-owned database.

(If the machine has systemd, two unit files with `Restart=always` would do the
same job and give you `journalctl`. The script exists because cron is what was
asked for and it needs nothing installed.)

## Behind Apache, at a path

To serve the site at `https://example.com/TW04Online` alongside whatever else
that host serves, run the web site on localhost only and point Apache at it:

    ./tw04.sh start          # WEB_HOST=127.0.0.1, WEB_BASE=/TW04Online

    a2enmod proxy proxy_http

then inside the existing `<VirtualHost *:443>`:

    ProxyPreserveHost On
    ProxyPass        /TW04Online  http://127.0.0.1:8080/TW04Online
    ProxyPassReverse /TW04Online  http://127.0.0.1:8080/TW04Online

The path is passed through rather than stripped, and `--base-path` tells the
site to expect it, so every link and the session cookie carry the prefix. The
cookie is scoped to `/TW04Online` and is not sent to the rest of the host.

`--no-secure-cookie` exists for testing over plain HTTP. Behind TLS, leave it
alone: without `Secure` a single http:// link puts a live session token on the
wire in clear.

`--trust-proxy` makes the site read `X-Forwarded-For`. **It matters**: without
it every request appears to come from 127.0.0.1, the per-address login throttle
becomes one bucket shared by everybody, and a few wrong passwords lock out the
whole internet. Only turn it on with a proxy actually in front, because the
header is trivially forged by anyone who can reach the port directly -- which
is why the site should bind to 127.0.0.1 and not to every interface.

The game server is separate and is NOT proxied: consoles connect straight to
TCP 10200, and to TCP 10202 for EA Messenger, so both ports have to be open on
the firewall.

## Before it faces the internet

- The web site is plain HTTP. Put a TLS terminator in front of it.
- Do not use `--open`.
- The peer-to-peer leg of a match is UDP 3658 between the two players, not
  through this server. Each player needs that port reachable, which behind NAT
  means a port forward, and two players behind one NAT cannot both be reached.

## Managing accounts from the shell

    python3 twdb.py --list
    python3 twdb.py --create-account NAME --password PASS
    python3 twdb.py --add-persona ACCOUNT PERSONA
    python3 twdb.py --set-password ACCOUNT PASS
    python3 twdb.py --disable ACCOUNT

## Abuse reports

REPORT ABUSE in the game files a report with the chat the lobby relayed in
the hour before it. They are listed on a page that is linked from nowhere:

    <site>/reports/<key>

The key is made the first time the web site starts, kept in
`data/reports.key`, and printed at every start -- `./tw04.sh log webui`, or
`cat data/reports.key`. Anyone with the address can read the reports, so keep
it to yourself; delete the file and restart the site to change it.
`webui.py --reports-key off` switches the page off.

This folder is generated by `tools/sync_forserver.py` in the main project.
Edit the originals there, not these copies.
