# Tiger Woods PGA Tour 2004 (PS2): the online protocol

These are the research notes behind this server: how the game's online client
talks to EA's lobby, worked out by reading the game's executable and by
watching a real console (in PCSX2) talk to a server built to answer it.  They
are a **lab notebook, kept in the order things were found**, so an early
section can be corrected by a later one -- when a section says "resolved",
"correction" or "was wrong", the later reading is the one the code follows.

A few things to know before reading:

- **Addresses** (`0x002BAE88`) are virtual addresses in `SLUS_207.57`, the
  game's main executable from the USA disc (serial SLUS-20757, CRC 64F9781E).
  You need your own copy of the game to follow along; nothing from it is
  included here.
- **Code** named here (`lobbyd.py`, `twdb.py`, `twtourney.py` ...) is in this
  repository.  The analysis helpers (`xref.py`, `disfn.py`, `tagscan.py` and
  so on) are in [`analysis/`](../analysis) -- its README explains setup.  The
  PCSX2 setup scripts, the network probes (`p2pwatch.py`, `udpcheck.py`) and
  the raw capture logs were part of the development workspace and are **not**
  included.
- **Section numbers** are referred to throughout ("see section 57"); GitHub's
  outline button (top right of this file) jumps between them.
- **Dates** are when a finding was made (2026).

---

## Where it started

Derived by static analysis of `SLUS_207.57` (TW04 USA master ELF, `VER = 1.01`,
built with "MW MIPS C Compiler (2.4.1.01)"). Everything below is read out of the
binary; the "Confidence" notes say where I am inferring rather than reading.

The stack is EA **DirtySock LobbyAPI** ("CSO"). It is a text protocol inside a
tiny binary frame. There is no GameSpy anywhere in the image.

**Addressing.** One `PT_LOAD` at vaddr `0x00100000`, file offset `0x100`, so
`vaddr = file_offset + 0xFFF00`. `$gp = 0x0031EBF0`. String offsets printed by
`analysis/strings.py` are file offsets; everything in this document is a vaddr.

---

## 1. Endpoint

| | |
|---|---|
| Lobby server | `159.153.229.231` port `10200` — **hardcoded, not a hostname** |
| Buddy server | port `3658`, address fetched at runtime via `Lobby_GetBuddyServerAddr` |
| Product | `PROD=tiger-ps2-2004` |
| Client version | `VERS=PS2/B10` |
| Disc id | `SLUS=SLUS_20757` |
| Language | `LANG=en` |

The IP literal lives at `0x0030FAC0` (and a second copy at `0x00311040`), the
port string `"10200"` at `0x0030FAD0`. `Lobby_Init` (`0x002745F0`) passes them
to setters at `0x00274B20` and `0x00274BB0`.

`0x00274B20` and `0x00274BB0` are setters, not trace calls — they copy the
address and the port into the lobby context at `+0x5EC` and `+0x60C`.

**Settled by live capture (2026-09-17).** These two strings really are the
address the game dials: patching them to `192.168.1.50` and `10201` produced a
TCP connection to exactly that endpoint. No lobby hostname is involved — the
only names TW04 resolves are `www.ea.com` (a connectivity check) and
`gate1.us.dnas.playstation.org` (DNAS). So **a DNS override will not redirect
TW04** the way it will TW05; patch the string or route the IP.

One practical trap when redirecting: PCSX2's socket adapter sources connections
from the NIC named in `EthDevice`, so the address you patch in must be reachable
*from that interface*. Pointing the game at a second NIC's address on this
machine produced a 21-second `WSAETIMEDOUT` and looked exactly like "the patch
didn't work".

---

## 2. Frame format

Sender: `0x002B9478`, called as
`Send(pConn, u4CC_kind, u4CC_ident, pPayload, iLen)` — `iLen = -1` means
"compute it".

```
offset  size  endian  field
0       4     BE      kind   (4CC)  e.g. 'room', 'auth', '@dir'
4       4     BE      ident  (4CC)  0 on every client request I found
8       4     BE      size          = 12 + strlen(payload) + 1
12      ...           payload       TagField text, NUL-terminated
```

The byte stores at `0x002B950C`–`0x002B954C` write each u32 MSB-first, which is
what makes the header big-endian on a little-endian machine. `size` **includes**
both the 12-byte header and the payload's NUL terminator: the code computes
`strlen(payload) + 1` at `0x002B94BC` then adds `0xC`.

The two-4CC header is confirmed independently by the trace format string at
`0x00313F00`: `recv: %c%c%c%c/%c%c%c%c`.

**Confirmed against the live client**, 2026-09-17. Its first frame:

```
0000  40 64 69 72 00 00 00 00 00 00 00 46 50 52 4f 44  @dir.......FPROD
0010  3d 74 69 67 65 72 2d 70 73 32 2d 32 30 30 34 0a  =tiger-ps2-2004.
```

`'@dir'`, ident `0`, size `0x46` = 70 = 12 + 57 payload + 1 NUL. Big-endian,
exactly as read from the stores. **Transport is TCP** — no longer an inference.

---

## 3. TagField payload encoding

Encoder: `TagFieldSetString` at `0x002BE400`, signature
`(char *pBuf, int iBufLen, const char *pKey, const char *pValue)`.
Numeric variant `TagFieldSetNumber` at `0x002BE0C0`.

Payload is a flat `KEY=VALUE` list. Read off the encoder:

- Fields are separated by a **newline** (`0x0A`), with a trailing newline after
  the last field, then the NUL. Live capture:

  ```
  PROD=tiger-ps2-2004\nVERS=PS2/B10\nLANG=en\nSLUS=SLUS_20757\n\0
  ```

  **This corrects an earlier reading of "space".** Space-separated payloads do
  occur, but every one seen so far is a prebuilt string constant the game sends
  verbatim rather than building through `TagFieldSetString` — for example
  `ROOMS=1 GAMES=1 USERS=1 RANKS=1 MESGS=1` at `0x003114D0`. Emit newlines;
  accept either.
- If the value contains a space, the whole value is wrapped in `"` (`0x22`).
  The check is a forward scan for `0x20` at `0x002BE44C`; the opening quote is
  emitted at `0x002BE490`, the closing one at `0x002BE53C`.
- These characters are escaped as `%xx`, **lowercase hex**:
  `=` (`0x3D`), `"` (`0x22`), `:` (`0x3A`), `%` (`0x25`).
- Any byte outside `0x20..0x7E` is escaped the same way. The range test is
  `addiu $v0,$a1,-0x20; sltiu $v0,$v0,0x5f` at `0x002BE4C0`.
- The two nibble tables are at `0x00313FB0` (high nibble) and `0x003140B0`
  (low nibble), both indexed by the raw byte.

Decoders: `TagFieldFind(pBuf, pKey)` at `0x002BD958` returns a field pointer;
`TagFieldGetString(pField, pDst, iLen, pDefault)` at `0x002BF5F0` and
`TagFieldGetNumber(pField, iDefault)` at `0x002BF1A8` read it.

**The `~~` pseudo-key** (`0x003178A8`, helper at `0x002BDB38`) means "the bare
leading token of the payload", i.e. a value with no `KEY=` in front. The helper
finds it and then skips bytes `<= 0x20`. A `~~=` form also exists at
`0x003178B0`. Server replies use this for their status/result token.

---

## 4. Request verbs

Every outbound request goes through one function,
`LobbyApiRequest(pApi, u4CC, pTagBuf, pCallback)` at `0x002BAD78` — 43 call
sites, all enumerated in [`lobby-requests.txt`](lobby-requests.txt).

| Verb | Issued by | Tags sent |
|---|---|---|
| `@dir` | connect handshake (`0x002BA4C8`) | client info block |
| `auth` | `Lobby_Login` | `TOS` `NAME` `PASS` `MID` `HWFLAG` `HWMASK` `PROD` `VERS` `LANG` `SLUS` (+`MASK` on the public-key path) |
| `acct` | `Lobby_Register`, `Lobby_Register_ParentalConsent` | `NAME` `PASS` `MAIL` `BORN` `GEND` `SPAM` `ALTS` `MINAGE=17`/`13` (+`PMAIL` for consent) |
| `pass` | `Lobby_ChangePassword` | `PASS` `CHNG` |
| `edit` | `Lobby_EditAccountInfo` | `NAME` `MAIL` `SPAM` `PASS` `CHNG` |
| `lost` | `Lobby_RetrieveLogin_Email` | `MAIL` |
| `cper` / `dper` | `Lobby_AddPersona` / `Lobby_DeletePersona` | `PERS` (+`ALTS`) |
| `pers` | `Lobby_SetPersona` | `PERS` `CDEV` |
| `room` | `Lobby_CreateRoom` | `NAME` `DESC` `PASS` `MAX` |
| `move` | `Lobby_JoinRoom` / `Lobby_LeaveRoom` | `NAME` `PASS` (none on leave) |
| `peek` | `Lobby_PeekRoom` | `NAME` |
| `snap` | `0x00276DD0`, `0x00276F20` | `NAME` `FIND` `INDEX` `CHAN` `START` `RANGE` |
| `mesg` | chat + challenge verbs | `TEXT` `PRIV` |
| `chal` | `_SendChalMessage` | `PERS` `HOST` |
| `news` | `Lobby_GetNews`, `Lobby_GetBuddyServerAddr` | — |
| `onln` | `0x00277060` | `PERS` |
| `user` | `0x002775D0`, `0x00286C10` | `PERS` |
| `rept` | `0x00275430` | `PERS` `PROD` `LANG` |
| `rank` | `Lobby_SendTwoPlayerResults` | the 60-field result block, below |
| `cusr` | custom-command channel | `PERS` `CMD=<5-char opcode>` |
| `sele` | `_ConnCallback` | — |
| `addr` / `skey` | connection layer (`0x002BB830`) | — |
| `PING` | buddy/messaging module (`0x002C3A50`) | — |

### `cusr` sub-opcodes

`cusr` is a generic "run a server-side command" envelope; the actual command is
a five-character `CMD` value. Observed:

| `CMD` | Meaning |
|---|---|
| `myrnk` | fetch my ranking (reply read from tag `RNKRS`) |
| `whomi` | who am I |
| `mg5ri` | tournament info for N days |
| `qdb@w` | tournament results |
| `lts5d` | today's date on the server |
| `5d0tr` | report round results (payload in `DATA`) |
| `esr2t` | request permission to start a tourney round (reply `TKEY`, `DATA`) |
| `ufpvt` | `0x002DF630`, unidentified -- sent unconditionally at login |

Captured at login, in order: `myrnk`, `ufpvt`, `lts5d`, then `mg5ri` and
`esr2t`. The last two carry a block of what is plainly the player's
progress/unlock state:

```
PERS=tester CMD=mg5ri START=-1 NUM=1
BIOT=0 BIOL=0 WRLD=0 PROG=0 SCEN=0 TBAL=0 RTE0=0 RTE1=0 RTE2=0 RTE3=0 PGAS=0 SAV0=0
```

`START=-1 NUM=1` matches `Tourn_GetNDaysTourneyInfoFromServer`'s `START`/`NUM`
arguments exactly. The twelve flags ride along on both `mg5ri` and `esr2t`.
Their individual meanings are unknown, but the shape -- career progress
(`PROG`), scenarios (`SCEN`), world (`WRLD`), a balance (`TBAL`), four `RTE`
slots, a save slot (`SAV0`) -- says the tournament service is also the
unlock/entitlement channel. Answering these with a bare `OK` was enough for the
game to award "Online exclusive merchandise now available" and open the Pro
Shop, so the entitlement grant is evidently opt-out rather than opt-in.
*Confidence:* field names are captured; the reading of what they mean is
inference.

### Challenge negotiation

Matchmaking is **not** a separate service — it is `mesg` traffic with a fixed
verb in `TEXT`, parsed by `Lobby_ProcessChallengeChatMessage` (`0x0028A460`):
`challenge`, `accept`, `decline`, `revoke`, `busy`, `ignore`, `ignoreall`.
A challenge carries the match setup as numeric tags:
`COUR` (course) `GLFR` (golfer) `SHOT` (shot type) `MFLG` `CFLG` `PTS` `RANK`
`STUS` `PNG` (ping) `WIN` `LOSS` `TIE` `INC`. `0x002897D0` is the reader for
exactly that set.

### `rank` result block

`Lobby_SendTwoPlayerResults` (`0x0028ABC0`) sends `REPT`, `AUTH`, `NAME0/1`
plus paired per-player numbers, suffix `0` = reporter, `1` = opponent:
`RANK QUIT TYPE DONE SCORE CLUB STROKES PUTTS HOLES EAGS BIRD ACES GIR LPUT
DRVS FRWY LDRV SHTC PARS SBOG DBOG TBOG COMP`.

---

## 5. Inbound vocabulary

The connection layer at `0x002BB830` is the single inbound dispatcher and reads
this set — this is the list a replacement server must be able to produce:

```
DIRECT ADDR PORT SESS MASK DOWN SKEY NAME CHAN MORE SLOTS PERS SELF HOST OPPO
P1 P2 P3 P4 AUTH FROM SEED WHEN LIDENT LCOUNT IDENT COUNT FLAGS
F N RI RT R RF I H A T L P Z S X D
```

`ADDR`/`PORT`/`DIRECT` are how the lobby hands one peer the other's endpoint —
this is the hinge between the lobby and the peer-to-peer game session. `SEED`
is almost certainly the shared RNG seed for the lockstep simulation.
*Confidence:* the tag list is read directly; the roles of `SEED` and
`DIRECT` are inference from name and context.

Per-callback readers:

| Callback | Reads |
|---|---|
| `_AuthCallback` | `PERSONAS` `MAIL` `GEND` `BORN` `SPAM` `CPAT` |
| `_RegisterCallback` | `OPTS` `AGE` |
| `_PersCallback` | `LKEY` `EX-GAME` |
| `_CreateRoomCallback` | `NAME` `COUNT` |
| `_ChalCallback` | `MODE` |
| `_SendResultsCallback` | `TITLE` `MESG` |
| `_TourneyStartCallback` | `TKEY` `DATA` |
| buddy module | `USER` `DOMN` `RSRC` `SHOW` `STAT` `PRES` `LKEY` `LRSC` `LIST` `BODY` `SUBJ` `ID` `SIZE` `GROUP` `FUSR` |

Presence values live at `0x003178D8`: `DND` `XA` `AWAY` `CHAT` `DISC`.
Server-originated messages use the sender name `@server` (`0x00317730`).

---

## 6. Connection state machine

The API handle keeps a 4CC state at `+0x0C`. `LobbyApiRequest` rejects any verb
unless the state is `idle`, except `auth`, `acct` and `skey`, which are allowed
during login (`0x002BADB0`–`0x002BADE4`).

Handshake **as captured live**, 2026-09-17. It takes two TCP connections:

```
connection 1
  --> @dir   PROD=tiger-ps2-2004 VERS=PS2/B10 LANG=en SLUS=SLUS_20757
  <-- @dir   OK NAME=... ADDR=<lobby> PORT=<lobby> COUNT=1
  (client disconnects)

connection 2
  --> addr   ADDR=192.0.2.100 PORT=58375        the PS2's own endpoint
  <-- addr   OK
  --> skey   SKEY=$5075626c6963204b6579         hex of the ASCII "Public Key"
  <-- skey   OK SKEY=$<32 hex chars>            16 bytes -> handle +0x24
  --> sele   ROOMS=1 GAMES=1 USERS=1 RANKS=1 MESGS=1
  <-- sele   OK
  (client reaches the SELECT ACCOUNT screen)
```

`@dir` is a directory lookup on its own connection — the client asks where the
lobby is, is told, drops the connection and reconnects to the answer. A real
deployment could point it at a different host here.

The `SKEY=$5075626c6963204b6579` placeholder is exactly what section 6a
predicted from `0x002BBBC0`, and the `sele` payload is the verbatim literal
from `0x003114D0`.

A captured `auth`, for reference:

```
TOS=1  NAME=jed  PASS=$...  MID=$00041f123456  HWFLAG=4  HWMASK=67620
PROD=tiger-ps2-2004  VERS=PS2/B10  LANG=en  SLUS=SLUS_20757  MASK=0
```

**`MID` is the console's MAC address** — `00:04:1F:12:34:56` here, matching what
DHCP handed the emulated PS2 exactly. It is the machine identifier a ban list
would key on.

**`cusr whomi` uploads the created golfer.** Captured at 707 bytes, it carries
a `CRPIN` blob -- the Create-A-Player record from `FE_CrAPDB.c`, the same tag
`0x00274330` reads. Two captures taken after a slider change differed by a
single byte, so it is the raw appearance/attribute array rather than anything
packed. A revival server has to store this per persona: it is how your golfer
follows you between consoles.

**The padding half of `PASS` is not reproducible.** Two logins with the same key
and password produced ciphertexts identical for the first 9 characters -- `~`
plus `hunter2` plus the `0x7F` terminator -- and different after that. The
padding comes from the global generator, which keeps absorbing key +
`ru paranoid?` on *every* call without ever resetting, so it never repeats.
Servers must ignore everything past the `0x7F`; only the password half is
deterministic.

After a successful `auth`, the client immediately sends `chal PERS=*`
(subscribe to challenges from anyone), `news NAME=0`, then `pers PERS=<name>`
selecting one of the personas the `auth` reply advertised in `PERSONAS`. Our
stub advertised `tester` and the client duly selected `tester`, so that field
round-trips as specced.

`addr` was not in the static map at all — the client volunteering its own
`ADDR`/`PORT` is presumably what the lobby later hands the opposite player to
start the peer-to-peer session.

The state machine underneath (`0x002BA4C8`): state ← `skey`, connect, `@dir`,
then on the `skey` reply the handler at `0x002BBC60` decodes 16 bytes into the
API handle `+0x24` and `0x002BBCA0` sets state ← `idle`, at which point `auth`
becomes legal.

**The 16 bytes at handle `+0x24` are the session key, and the server chooses
them.** That is the whole answer to the password question: a replacement server
knows the key because it issued it, so it can decrypt `PASS` outright.

---

## 6a. The `PASS` transform

Before an `auth`, `acct` or `pass` request goes out, `LobbyApiRequest` extracts
the `PASS` field (max 31 chars) and re-encodes it. It branches on the flag byte
at handle `+0x24`, i.e. on whether a session key has arrived:

| | |
|---|---|
| byte 0 of the key is non-zero | `0x002C59A0`, symmetric, result written back as `PASS=~<30 chars>` |
| byte 0 of the key is zero | `0x002BE948`, the public-key path, `PASS=$<raw hex>` plus `MASK=<handle+0x4B8>` |

**The test is `lb $v1, 0x24($s1); bnez $v1` at `0x002BAE88`, and handle `+0x24`
is the key buffer itself** — so it is literally "is the first byte of the stored
key non-zero", not "did a key arrive". A server that issues a session key
beginning `00` silently pushes the client onto the public-key path. Observed:
issuing `000102…0f` produced

```
PASS=$04d8f267577a05   MASK=0
```

— a raw binary field the same length as the plaintext (7 bytes for `hunter2`),
not the `~`-prefixed symmetric form. **Always issue keys with a non-zero first
byte.** The public-key path is otherwise undecoded and does not need to be: the
server controls the key, so it can always steer the client to the symmetric one,
which is implemented and round-trip tested in
[`../eacrypt.py`](../eacrypt.py).

**The generator** (`ssc_init` `0x002C5780`, `ssc_gen` `0x002C5900`) is RC4's
shape — 256-byte permutation, swap on every output — with two changes:

- the running index `j` is a **32-bit CRC-32 register**, stepped through the
  standard reflected table (poly `0xEDB88320`) at `0x00314BF8`, twice per KSA
  round and once per output byte;
- the output byte is `S[(si - sj) & 0xFF]`, a **subtraction**, where RC4 adds.

A stock RC4 will not match. `ssc_init(state, key, keylen, reset)` runs
`abs(reset) << 8` rounds; a negative `reset` absorbs into the existing state
instead of rebuilding it, and a negative `keylen` means "measure the key".

**The encoder** (`0x002C59A0`) walks the password one character at a time:

```
cipher[n] = ((plain[n] + (ks[n] % 96) + 0x40) % 96) + 0x20
```

over a 96-character alphabet `0x20..0x7F`. Three things are easy to get wrong:

- `ssc_gen` **XORs into** its destination rather than overwriting it, and the
  encoder reuses one scratch byte for the whole loop without re-zeroing. So
  `ks[n]` is the XOR of every byte the generator has produced up to `n`, not
  the nth byte on its own.
- The source is a **C string and its NUL is encoded too**. A NUL is outside
  `0x20..0x7E`, so it is substituted with `0x7F` — which means the plaintext
  the server recovers is `password` + `\x7F` + padding. **`0x7F` is the
  end-of-password marker; the server does not have to guess the length.**
- After the NUL, output is padded to a fixed 30 characters from a *second*
  generator (seeded `hello world` at startup, then the session key, then the
  literal `ru paranoid?`), so ciphertext length never leaks password length.

Decryption is the modular subtraction, folding results below `0x20` back up by
96 — the encoder adds the raw ASCII value, so the top half of the alphabet
wraps.

**CONFIRMED against the live client, 2026-09-17.** `eacrypt.py` reproduces
a captured ciphertext byte for byte, padding included:

```
key  a1b2c3d4e5f60718293a4b5c6d7e8f90   (issued by us in SKEY)
pw   hunter2                            (typed at the game's login screen)
wire PASS="~zP< 1JZD%7f$WeC5m4$76&/DAe}1n<WH"
```

The capture also confirms the quoting and escaping rules in section 3 in one
go: the value is wrapped in `"` because it contains a space, and the literal
`0x7F` end-of-password marker appears escaped as `%7f`. That vector is pinned
as a regression test in `eacrypt.py`.

**One correction the capture forced.** The KSA runs `j` in a local register
starting at zero and never writes it back to the state -- there is no store to
`state+0x100` or `+0x104` between `0x002C5844` and the epilogue. So the PRGA
starts from `j = 0`, not from whatever the KSA ended on. Carrying it over, as
an RC4-shaped implementation naturally would, produces a keystream that looks
entirely plausible and decrypts to garbage.

TW05's `SLUS_210.02` carries the identical constants — CRC-32 table at
`0x00378A08`, `hello world` at `0x00378E08`, `ru paranoid?` at `0x00378E18` —
so this routine, now verified, should port to TW05 unchanged.

**Binary tag encoding.** `SKEY` and anything else binary uses
`TagFieldSetBinary` (`0x002BE578`) / `TagFieldGetBinary` (`0x002BF7F0`): a `$`
prefix followed by two lowercase hex characters per byte, reusing the same
nibble tables as the string escaper (`0x00313FB0` / `0x003140B0`). The decoder's
inverse tables at `0x003141B0` / `0x003142B0` accept upper or lower case.

---

## 7. What this means for a revival

- The server needs **no game logic**. Gameplay is deterministic lockstep P2P
  (`OnlineGolf.c`), so the lobby only has to get two clients each other's
  `ADDR`/`PORT` and agree a `SEED`.
- Minimum viable server: accept TCP on 10200, answer `@dir`, `auth`, `pers`,
  `news`, `room`, `move`, `peek`, `snap`, `mesg`. `rank` and `cusr` can return
  a benign error and the game still plays.
- The full server error table is in plain English from `0x0030FC80`
  (`"No error"`) through `0x00310B90`, and doubles as a list of every failure
  the client already knows how to render.
- Blockers now: DNAS (`DirtyDnasRelInit` at `0x00316A98`, with `...Updt` and
  `...Exit` following it) and the hardcoded IP. The `PASS` transform is solved
  (section 6a) -- the server issues the session key, so it can read passwords.

---

## 8. Reproducing / extending this

Scripts live in [`../analysis`](../analysis) (they need capstone and pyelftools --
see its README), apart from `eacrypt.py`, which is part of the server:

| Script | Does |
|---|---|
| `strings.py <file> [minlen]` | offset-tagged strings dump |
| `elfinfo.py <elf>` | segment/section layout |
| `ee.py` | address map, constant scanner, `jal` scanner, prologue finder |
| `xref.py <elf> <addr\|string>` | who references this |
| `names.py <elf>` | function names recovered from debug labels |
| `disfn.py <elf> <addr> [n]` | disassembly with string annotation |
| `tagscan.py <elf> <callee> [argc]` | constant args at every call site |
| `requests_map.py <elf>` | the whole table in section 4 (and `docs/lobby-requests.txt`) |
| `mips.py` | manual decode for the R5900 forms capstone mangles |
| `eacrypt.py` | the `PASS` cipher; run it directly for a round-trip test |

`analysis/_cache/` holds the pickled xref index; delete it if you change `ee.py`.

Note capstone decodes MIPS32 only, so R5900 `daddu`/`daddiu` (the compiler's
`move`) show up as `.byte` lines in `disfn.py` output. `tagscan.py` handles them
properly, which is why its argument recovery is more reliable than reading the
listing.


---

## 9. The room / matchmaking layer (not yet reached)

Across every capture so far the client has sent `@dir` `addr` `skey` `sele`
`auth` `chal` `news` `pers` `onln` `cusr` and `user` -- and **never** `snap`,
`room`, `move`, `peek` or a challenge `mesg`, even with two personas online and
Quick Play pressed repeatedly. The room layer is not being entered at all.

Statically, all of it hangs off one state machine, `0x00285290`, switching on a
word at `$gp-0x76E0` = **`0x00317510`**:

| state | handler | what it does |
|---|---|---|
| 0 | `0x002847A0` | create-or-join: `Lobby_CreateRoom`, `Lobby_JoinRoom`, `snap`(find) |
| 1 | `0x00284B00` | match flow: `Lobby_PeekRoom`, `Lobby_JoinRoom`, `Lobby_SendChallenge` |
| 2 | `0x00284550` | join room |
| 3 | `0x00284F80` | unidentified |

`0x002A2210` refreshes all five lists (six `snap` calls, one per channel) and has
**zero `jal` call sites** -- it is only reachable through a function pointer, so
the online front end dispatches through handler tables.

So the blocker is upstream of the protocol: the front end is not pumping this
state machine. `0x00317510` is the address to watch in the PCSX2 debugger --
whether it ever leaves its initial value distinguishes "the UI never triggers
online match mode" from "it triggers and bails out immediately", and those need
completely different fixes.

### Measured: the state word never moves (2026-09-17)

That rules out "enters and bails". Tracing further:

**The pump.** `0x00285290` has exactly one caller, `0x002744EC` inside
`sub_00274490` -- the per-frame online update. It reaches the state machine only
if bit `0x400` is set in the online flags word at `$gp-0x66FC` =
**`0x003184F4`**:

```
0x00274498  lw   $a1, -0x66fc($gp)     ; online flags
0x0027449c  andi $v1, $a1, 0x200       ; 0x200 = start requested -> Lobby_Init path
0x002744e0  andi $v1, $a1, 0x400       ; 0x400 = lobby initialised
0x002744e4  beqz $v1, <skip>           ; not set -> the room layer never runs
0x002744ec  jal  0x285290
```

`Lobby_Init` sets `0x400` itself at `0x00274880`, and `Lobby_Connect` refuses
with `-3` unless it is set, so it is set by the time we are logged in.

**The setter.** `0x00284500` is a leaf `SetOnlineMatchState(int)` that clamps to
`[-1, 6]`. It has exactly two call sites:

| site | value | in |
|---|---|---|
| `0x00288F28` | `6` | `sub_00288EC0`, alongside `0x00284540` -- teardown |
| `0x0028B474` | `-1` | `sub_0028B3F0`, gated on bit `0x4000` at `0x00320940` -- idle |

Those three stores inside the setter are the **only** writes to `0x00317510`
anywhere in the ELF, and the setter's address is never taken as a pointer.

**So nothing in this build ever assigns states 0-3** -- the very states that
drive create-or-join, the match flow and join-room. The word's BSS default is 0,
and `sub_0028B3F0` moves it to -1 early.

That is a strange enough result to be worth doubting: it may mean this state
machine is not the path Quick Play uses at all, and the room verbs are driven
from somewhere else. The cheap way to tell:

1. **Read the value** at `0x00317510`, not just watch it -- `-1` and `0` mean
   very different things here.
2. Check bit `0x400` at `0x003184F4`.
3. Breakpoint `0x00285290` and see whether it executes at all.

If `0x400` is set and `0x00285290` never executes, `sub_00274490` is not being
pumped. If it executes with the word at `-1`, the machine is idling and the
question becomes what is supposed to call the setter with `0`.

### Resolved: that state machine is dead code

Measured in the debugger: `0x00317510` reads **`FF` (-1, idle) and never
changes**, while a breakpoint on `0x00285290` **hits constantly**. So the machine
runs every frame, sees `-1`, and falls straight through.

Nothing can ever move it. The only writes to `0x00317510` in the entire ELF are
the three inside the setter; the setter's only two call sites pass `6` and `-1`;
its address is never taken as a pointer; and there are no `jalr` sites anywhere
in `0x00284000-0x0028C000`. **The `0x00284xxx` room cluster is unreachable in
this build.** I spent a while treating it as the target; it is not.

### The live front end is a dispatch table

The same lobby calls have a *second* set of callers, and those are the live ones:

| function | calls |
|---|---|
| `0x002A1EE0` | `Lobby_CreateRoom` |
| `0x0029FA10` | `Lobby_JoinRoom` |
| `0x0029FD20` | `Lobby_SendChallenge` |
| `0x002A2210` | six `snap` calls -- refresh all five channels |
| `0x002A2690` | `user` lookup |

None is called by `jal`. Each is written as a function pointer into a table at
**`0x00354D00`-`0x00355000`**, populated by `sub_0020D6F0` -- a very large
registration routine in the UIStudio region (`UIStudio.c` at `0x003152A0`). So
the online front end is UI-script driven: screens invoke handlers by table slot.

`0x002A2690` is the `user` handler, and `user PERS=<other>` **has** been observed
on the wire -- so the table is live and being dispatched. The UI is reaching some
handlers and not others.

The next measurement is therefore breakpoints on the handlers themselves rather
than more static tracing. With Quick Play pressed, does anything hit:

- `0x002A2210` (refresh lists -- would produce `snap`)
- `0x002A1EE0` (create room -- would produce `room`)
- `0x0029FA10` (join room -- would produce `move`)

If none hit, the Quick Play screen is not wired to them and the UI is waiting on
state it never receives, which is the remaining support for the push theory. If
one hits but no frame appears on the wire, the fault is between the handler and
`LobbyApiRequest` and is findable from there.

*Confidence:* the state machine and the dispatch are read directly. That the
front end is gated on something we are not supplying is inference -- the
competing explanation is that `sele` is a subscription and the server is meant
to PUSH room/user lists (the inbound dispatcher reads `LIDENT` `LCOUNT` `IDENT`
`COUNT` `FLAGS`, which is list-push shaped), and the UI stays empty until one
arrives. Watching `0x00317510` separates these.

---

## 10. Why matchmaking fails: the client has no room list

Solved 2026-09-17 with the debugger. Two UI errors, one root cause.

**"INVALID NAME." (Match Play -> Game Lobbies).** The dialog text is
`'Invalid name.'` at `0x00312C48`, reached from `sub_002A2CA0` -- a front-end
handler that is a jump table over **negative** error codes, `code + 0x3A < 0x3A`,
table at `0x003134F0`. Index 48 -> code **-10** -> that string.

`-10` is returned by `Lobby_JoinRoom` (`0x00275500`) at its second check:

```
0x00275510  lw   $v0, -0x66fc($gp)     ; online flags
0x00275514  andi $v0, $v0, 0x400       ; lobby initialised?
0x00275518  bnez $v0, ok               ; no  -> return -3
0x00275528  lb   $v0, ($a3)            ; a3 = room NAME, read first byte
0x0027552c  bnez $v0, ok               ; non-empty -> proceed
0x00275530  addiu $v0, $zero, -0xa     ; EMPTY NAME -> return -10
```

So the client asked to join a room **whose name is the empty string**, and bailed
locally without sending anything. That is exactly what happens when the room list
is empty and the UI hands the selected entry -- nothing -- to `Lobby_JoinRoom`.
`Lobby_PeekRoom` and `Lobby_SendChatToPersona` carry the same `-10` check.

**"The server is temporarily unavailable" (Quick Play)** is entry **4** of the
positive server-error table at `0x0030FC80`, and is consistent with the same
cause: no games to quick-match into.

**Neither error involves a request.** Confirmed on the wire: `grep -c "<-- snap"`
over the whole capture is **0**, and breakpoints on `Lobby_JoinRoom`,
`Lobby_CreateRoom`, both `snap` senders and `Lobby_SendChallenge` did not fire
while the dialogs appeared. The client fails these actions locally, before the
lobby layer.

### So how is the list supposed to arrive?

The client *can* ask -- `sub_002A2210` (refresh-all-lists) was caught live
calling the `snap` sender at `0x00276DD0` with `INDEX=-1, RANGE=25`, `ra` =
`0x002A2250`. But that path fires rarely and the request never reached the
socket, so in practice the list stays empty.

That leaves the push model as the remaining explanation, and it fits everything:

- `sele` subscribes to `ROOMS=1 GAMES=1 USERS=1 RANKS=1 MESGS=1`, which is only
  meaningful if the server sends those channels unprompted
- the inbound dispatcher `0x002BB830` reads `LIDENT` `LCOUNT` `IDENT` `COUNT`
  `FLAGS` -- list-push shaped fields that no reply we send ever contains

**Next step:** work out the unsolicited list frame from `0x002BB830`'s handling
of those five tags, and have `lobbyd` push a room after `sele`. If a room appears
in Game Lobbies, the whole matchmaking path opens up.

### Aside: the 60-second disconnect is the client's

`lobbyd` sets no socket timeout and never closes a connection; every
`disconnect` line in the capture is the client hanging up. It drops after ~60 s
of silence, and it goes silent once an error dialog stops the polling loop. Fix
the empty list and the idle disconnects should stop with it.

---

## 11. The `+` push family, and how far it gets

Found and verified live, 2026-09-17. The inbound dispatcher at `0x002BB830`
accepts a family of **unsolicited** verbs that no request ever asks for:

```
+ses   +msg   +who   +rom   +pop   +usr   +rnk   +snp
```

Each is gated on the matching channel having a callback registered in the table
at `conn+0x310`, stride 0x14 -- which is what `sele`'s
`ROOMS=1 GAMES=1 USERS=1 RANKS=1 MESGS=1` subscription is for. `Lobby_Init`
registers channel 0 at `0x002746E4` via `0x2BA818(handle, 0, 0x002739F0)`.

### `+rom` -- one room, handler at `0x002BC310`

Allocates a 0x68-byte record and parses single-letter tags:

| tag | into | notes |
|---|---|---|
| `I` | `+0x00` | room id, `GetNumber` default -1; **negative is discarded** |
| `N` | `+0x1C`, 32 bytes | name; **absent means "remove this room"** |
| `H` | `+0x3C`, 32 bytes | |
| `F` | `+0x08` | default -1 |
| `A` | `+0x64` | |
| `T` | — | number |

Only `I` and `N` are required. A working frame, as emitted by `lobbyd`:

```
0000  2b 72 6f 6d 00 00 00 00 00 00 00 2e 49 3d 30 0a  +rom........I=0.
0010  4e 3d 46 61 69 72 77 61 79 0a 48 3d 6a 65 64 32  N=Fairway.H=jed2
0020  0a 46 3d 30 0a 41 3d 30 0a 54 3d 30 0a 00        .F=0.A=0.T=0..
```

### Verified end to end in the debugger

Every stage confirmed on the running game, not inferred:

- the frame reaches the `+rom` case -- trapped at `0x002BC31C` with
  `v1 = 0x2B726F6D`
- the channel gate passes -- `[conn+0x310] = 0x01C5FE54`, non-zero, with the
  channel-0 callback `0x002739F0` and context `0x01F47FC0` sitting at `+0x318`
  and `+0x31C` exactly as `Lobby_Init` set them
- the CREATE path is taken -- trapped at `0x002BC364` with `s2 = 0` (our `I=0`)
  and the `N` lookup returning a live pointer
- the room reaches the game layer -- the channel callback stores the count at
  lobby context `+0x28`, and after 8 pushes it reads **2**, matching the two
  rooms pushed

The same context read confirms two long-standing inferences: `ctx+0x0C` =
`0xC0A80132` = `192.168.1.50` and `ctx+0x10` = `0x27D8` = `10200` -- the fields
`Lobby_Connect` refuses to proceed without.

### Where it still stops

Game Lobbies remains empty and still fails with "Invalid name." (`-10`,
`Lobby_JoinRoom` handed an empty room name).

So the pushed list is **not** what the UI screen reads. The working theory is
that `+rom` maintains an already-populated list, while the initial population
comes from `snap` -- and `grep -c "<-- snap"` over every capture ever taken is
still **0**. Nothing in `0x00270000-0x002B0000` reads `ctx+0x28` either, which
supports the same reading.

`sub_002A2210` (refresh-all-lists, six `snap` calls, one per channel) *has* been
caught running once, and that attempt never put a frame on the wire. That is the
next thing to measure, and it is a small question:

| breakpoint | answers |
|---|---|
| `0x002A2210` | does the Game Lobbies screen invoke the refresh at all? |
| `0x00276EF4` | `v0` from `LobbyApiRequest('snap')` -- `>=0` sent, `-1` bad state, `-2` no free request slot |

If `snap` can be made to go out, the reply can carry the room entries and the UI
list should populate -- at which point `Lobby_JoinRoom` finally gets a real name.

---

## 12. The actual blocker: one UI buffer at `0x003B6E58`

Proven live, 2026-09-17, by writing to it.

"Game Lobbies" does **not** call `Lobby_JoinRoom` -- it calls **`Lobby_PeekRoom`**
(`0x00275600`), from `ra = 0x0029FB90` in the front-end cluster. `PeekRoom` has
the same empty-name check as `JoinRoom`, returning `-10` -> "Invalid name."

The room name it reads comes from a **fixed global buffer at `0x003B6E58`**, and
that buffer is all zeros:

```
003b6e58  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
```

Writing `"Fairway\0"` into it with the debugger and resuming produced, for the
first time in any capture:

```
18:10:05 <-- peek/0x00000000 size=26  NAME=Fairway
18:10:05 --> peek/0x00000000 size=24  OK COUNT=0
```

**So the protocol side is complete.** Frame format, handshake, cipher, login,
pushes, and now a room-layer request and reply all work. The single thing
standing between this and a usable lobby is that `0x003B6E58` is never filled,
because the UI's room list is empty and there is nothing for the player to
select.

### What this rules in and out

- not the wire format, not the server, not `sele`, not the channel gates
- not `+rom` -- that lands correctly and the game layer counts the rooms at
  lobby context `+0x28`
- the UI's list is a **separate structure** from the pushed one, and
  `0x003B6E58` is written when the player selects an entry from it

### Next

Find what writes `0x003B6E58`. A **write watchpoint** on it during a working
flow is the direct route, but nothing writes it while the list is empty, so the
more promising order is:

1. answer `peek` with real content (`0x00273C40` reads `COUNT` from the reply)
   and see whether the screen advances now that a peek succeeds
2. failing that, find the UI list structure that feeds `0x003B6E58` -- the
   caller at `0x0029FB90` is the thread to pull

A crude but genuine workaround already exists: poking a room name into
`0x003B6E58` makes the lobby flow run. That is enough to exercise the rest of
the room and match path from the server side without solving the UI question
first.

---

## 13. Room names are hierarchical -- and that was the whole blocker

Solved 2026-09-17. The room browser now populates.

`0x002759E0` does not simply enumerate the list at `ctx+0x20`. It builds a
**name prefix** and filters on it:

```
0x00275A48  sprintf(prefix, "%s.%s.", <type>, <id>)
0x00275A60  len = strlen(prefix)
            for each entry:
0x00275AB0    entry = list_get(ctx+0x20, i)
0x00275AC4    strncmp(entry+0x1C, prefix, len)     ; must START with the prefix
0x00275ACC    if != 0 -> skip
0x00275AD4    if match_index != requested -> next
0x00275ADC    *out = entry, return 0
```

The two components:

| part | from | values |
|---|---|---|
| type | `0x0029B370` | `0` -> `"Stroke"`, `1` or `0x19` -> `"Match"` |
| id | table at `0x00303850`, 6 entries | `T` `I` `G` `E` `R` `C` -- it spells TIGER |

Live, the Match Play lobby screen used type `1`, id `0` -> prefix `"Match.T."`.
Both are read from the global struct: type is a byte at `0x003B6E50`, id a word
at `0x003B6E54`.

So a pushed room must be named **`<type>.<id>.<name>`**, e.g. `Match.T.East1`.
The ELF ships exactly these as examples at `0x00311080` and `0x00311090`:

```
0x00311080  'Match.T.East1'
0x00311090  'Stroke.T.East1'
```

Pushing `+rom` with plain names like `Fairway` put real records in the right
list -- the list object at `ctx+0x20` genuinely held 2 -- but **nothing matched
the prefix**, so the filtered count was zero and every downstream check looked
correct while the screen stayed empty. That single detail cost most of an
evening.

### Working, end to end

With `lobbyd` pushing `Match.T.East1` / `Match.T.West1` / `Stroke.T.East1` /
`Stroke.T.West1`, the Game Lobbies screen lists the rooms under its EAST / WEST
headings and the client peeks them as you move the selector:

```
18:24:17 <-- peek  NAME=Match.T.East1
18:24:35 <-- peek  NAME=Match.T.West1
```

That is the full chain working: `+rom` push -> `ctx+0x20` list -> prefix filter
-> selection copies `record+0x1C` into `0x003B6E58` -> `Lobby_PeekRoom` -> a real
request on the wire, answered by our server.

### The screen's five rows

EAST, WEST, CREATED, BEGINNER, ADVANCED. Each row almost certainly filters on a
deeper prefix (`Match.T.East`, `Match.T.West`, ...), so populating the other
three is a matter of naming rooms to suit. `CREATE ROOM` is also offered, which
should exercise `Lobby_CreateRoom` and the `room` verb.

### Next

`peek` is currently answered `OK COUNT=0`, which the screen renders as
"PLAYERS: 0 / ROOM IS EMPTY" -- correct, but worth filling in.
`0x00273C40` reads `COUNT` from the reply. After that, **`move`** (join) is the
next verb to see on the wire, and then the challenge handshake between two
logged-in personas.

---

## 14. A working lobby

State at the end of 2026-09-17. Verbs seen on the wire from the real client,
answered by `lobbyd.py`:

| verb | meaning | working |
|---|---|---|
| `@dir` `addr` `skey` `sele` | handshake | yes |
| `auth` | login, PASS cipher verified byte for byte | yes |
| `pers` `onln` `chal` `news` `cusr` | session setup and polling | yes |
| `+rom` `+usr` | server-initiated room and user lists | yes |
| `peek` | who is in a room -> "PLAYERS: n" | yes |
| `room` | CREATE ROOM -- client sends `NAME=Match.C.iii DESC="Created by jed2" PASS=pppp MAX=50` | yes |
| `move` | join / leave a room | yes |
| `mesg` | lobby chat (`TEXT="See you later!"`) | yes |
| `snap` | never sent by this client in any capture | n/a |

`lobbyd` keeps created rooms and broadcasts `+rom` to every connection, so a
room one player makes appears in the other's browser -- the first state that
propagates *between* clients. `move` now gives real room membership, which
`peek` reports and `+usr` fills in.

### The room-name categories

Names are `<type>.<id>.<name>`. The client chooses them itself when creating a
room, which is how the mapping was confirmed rather than guessed:

| row | prefix | evidence |
|---|---|---|
| EAST | `Match.T.East…` | ELF example `Match.T.East1` |
| WEST | `Match.T.West…` | ELF example |
| CREATED | `Match.C.…` | client sent `Match.C.iii` from CREATE ROOM |
| BEGINNER / ADVANCED | two of `I G E R` | create a room from each row and read the name it sends |

### What is left

1. The challenge handshake -- `mesg` with `TEXT=challenge` plus the numeric match
   setup (`COUR` `GLFR` `SHOT` …), then `accept`, parsed by
   `Lobby_ProcessChallengeChatMessage` at `0x0028A460`.
2. Gameplay itself is peer to peer, and **PCSX2's `Sockets` DEV9 backend cannot
   do it** -- outbound-only NAT, both instances on `192.0.2.100`, no inbound
   path. Use PCAP Bridged for a real match.
3. `A` (+0x30) and `S` (+0x38, 128 bytes) in the `+usr` record are still
   unidentified; `P` (+0x28, 8 bytes) is a guess at the CONNECTION column.

---

## 15. The 60-second idle disconnect

Solved 2026-09-18, statically, out of `LobbyApiUpdate` (`0x002BB830`; its
epilogue is at `0x002BD0DC`, so it is one large function that both drains the
socket and runs the timers).

### The timer

```
0x002BB86C  jal  NetTick                     ; 0x002B98F0, milliseconds
0x002BB874  s6 = now
0x002BB878  v1 = [api+0x0C]                  ; the 4CC state
0x002BB884  if v1 == 'offl' -> skip
0x002BB88C  v0 = [api+0x14]                  ; tick of the previous update
0x002BB890  if v0 == 0 -> 0x002BB8AC
0x002BB894  v1 = now - v0
0x002BB898  if v1 >= 0x1389 (5001 ms):       ; the client was not being pumped
0x002BB8A0      v0 = [api+0x10]
0x002BB8A8      [api+0x10] = v0 + v1         ; forgive the whole stall
0x002BB8AC  v0 = [api+0x10]                  ; the DEADLINE
0x002BB8B0  v0 = v0 - now
0x002BB8B4  if v0 >= 0 -> alive
0x002BB8C8  jal  0x002BA1D8(api, 'time', 0x800)   ; <-- the disconnect
0x002BB8D4  [api+0x14] = now
```

So the whole thing is one word, **`[api+0x10]`, an absolute deadline in
`NetTick` milliseconds**. Two details matter:

- the stall forgiveness at `0x002BB898` means a load screen or a modal dialog
  does *not* burn the budget -- gaps over 5 s are added back. The session only
  dies when the client is running normally and hears nothing.
- `0x002BB8DC` bails out early when the state is already `term`, and
  `0x002BB884` when it is `offl`.

### What refreshes it

```
0x002BD080  bgez a2, 0x002BB910              ; a2 = bytes received
0x002BD084  v0 = 0xEA60                      ; 60000 -- in the delay slot
0x002BB910  v1 = '~png'
0x002BB914  v0 = v0 + s6                     ; now + 60 s
0x002BB918  a0 = [sp+0x360]                  ; the inbound verb
0x002BB920  bne  a0, v1, 0x002BB988          ; not a ping -> normal dispatch
0x002BB924  [api+0x10] = v0                  ; IN THE DELAY SLOT, so it runs
                                             ; for EVERY inbound frame
```

`sw` sitting in the `bne`'s delay slot is the whole answer: **any frame at all
resets the 60-second clock**, ping or not. There is no "the client must have
asked for it" condition.

### `~png` -- the server-initiated keepalive

The verb the client intercepts before dispatch is `~png`, and it answers it
itself:

```
0x002BB92C  v1 = [api+0x1C]                  ; last measured round trip
0x002BB934  if v1 == -1 -> 0x002BB968        ; never measured: echo unchanged
0x002BB940  0x002BDDE0(buf, 0x100, body)     ; copy the received TagField
0x002BB958  0x002BE0C0(buf, 0x100, "TIME", [api+0x1C])
0x002BB978  0x002B9478(sock, verb, ident, body, t0)   ; send it straight back
```

An empty body is fine -- with no RTT measured yet the client takes the
`0x002BB968` path and does not touch it at all.

The client also has its **own** 30-second ping, but it is disabled here:

```
0x002BB7F8  _SendPing(api): 0x002BB028(api, "@server", [api+0x3B4], 3000,
                                       callback=0x002BB758, 0)
0x002BB758  _PingCallback: on success  [api+0x18] = NetTick() + 0x7530 (30 s)
                           on failure  [api+0x20]++ , give up at 3
0x002BD090  v0 = [api+0x18]
0x002BD094  if v0 == 0 -> skip                ; <-- never armed on this path
0x002BD098  if now < v0 -> skip
0x002BD0A4  jal _SendPing
0x002BD0AC  [api+0x18] = now + 0x7530
```

`[api+0x18]` starts at zero and only ever gets set *by* a successful ping
reply, so the outbound ping never starts on its own. The server has to speak
first, which is presumably exactly how EA's did it.

### The fix in `lobbyd`

A background thread pushes `~png` to every live connection every 20 s
(`--ping`, `0` to disable). Each one is logged, and the client's echo comes
back as `~png TIME=...` and is swallowed by `on_png` -- answering a reply would
loop forever.

Because the refresh is unconditional, any other traffic works too: a session
that is actively browsing rooms was never at risk. It is the idle client --
sitting on the account screen while you set the other one up -- that dropped.

### If you want it gone entirely

The 60 000 is a single immediate and can be patched instead:

```
patch=1,EE,002bd084,word,3c020100      ; ori v0,zero,0xEA60 -> lui v0,0x0100
```

`0x01000000` ms is about 4.6 hours and still comfortably positive for the
signed `bgez` at `0x002BB8B4`. Not installed by default -- the keepalive is the
honest fix and it is what a real server has to do anyway.

---

## 16. Room membership: creating is joining, and `+usr` has to be broadcast

Two clients reached the same room screen on 2026-09-18 -- `Match.C.hhhh`, made
by `jed2`, joined by `ooo` -- and the PLAYER column was wrong on both. The
joiner saw exactly one name (itself); the host saw an empty row and a blank
PROFILE panel. The capture says why, and it is entirely server-side.

### The host never sends `move`

```
01:01:57 <-- room  NAME=Match.C.hhhh DESC="Created by jed2" MAX=50
01:01:57 --> room  OK NAME=Match.C.hhhh COUNT=1
...
01:02:09 <-- move  NAME=Match.C.hhhh          <- the JOINER, and only the joiner
01:02:09 ***     ooo joined 'Match.C.hhhh'
```

`_CreateRoomCallback` takes the client straight into the room screen. There is
no `move` after a `room`, so a server that only learns membership from `move`
never knows the host is in its own room. `WHERE` held one entry where it should
have held two, which is why the joiner's list was short by one and why `peek`
had been answering `COUNT=0` for a room that already had someone in it.

**Creating a room is joining it.** `on_room` now records the creator in `WHERE`
and reports `COUNT` from the real occupant list.

### `+usr` only ever reached whoever asked

`push_users` is a method on a connection, and it was only called from `on_peek`
and `on_move` -- both of which are requests, so both only ever push back down
the socket that sent one. The host asked for nothing after `room`, so it was
told nothing, forever.

A membership change has to reach **every member**, so there is now a
`broadcast_users(room)` alongside `broadcast_rooms()`, called on create, on
join, and on the room someone just left. The same thing happens when a
connection drops, so a crashed client does not linger in the list.

`on_peek` still pushes only to the asker: peek is the browser asking about a
room you are *not* in, and its answer belongs to that one screen.

### Removals

`+usr` follows the same convention as `+rom` -- a record with no `N` deletes
that index. Pushing a shrinking list therefore leaves ghosts at the tail, so
each connection tracks the highest index it has been sent and the surplus
indices are explicitly removed. Leaving a room clears the leaver's list
outright.

### Verified

A two-client harness drives the real server over TCP: host creates without
joining, the other peeks then joins, then leaves.

```
after create:  host sees ['jed2']           joiner sees []
after join:    host sees ['jed2', 'ooo']    joiner sees ['jed2', 'ooo']
after leave:   host sees ['jed2']           joiner sees []
```

---

## 17. `+msg`, and why every challenge arrived as an empty chat line

Solved 2026-09-18. Two clients in one room, `jed2` issues a challenge from the
ONLINE PROFILE menu, gets `WAITING FOR OTHER USER...` -- and `ooo` shows four
blank lines reading `JED2:`. The relay was reaching the other client; it was
being *rendered* wrong, for three separate reasons that all reduce to one:
**the request and the push do not use the same field names, and flags are not
decimal.**

### The request

`Lobby_SendChallenge` (`0x0028A340`) builds an ordinary `mesg`:

```
0x0028A39C  TagFieldSetString(buf, 0x400, "TEXT", <the setup block>)
0x0028A3C0  TagFieldSetString(buf, 0x400, "PRIV", <target persona>)
0x0028A3D4  TagFieldSetFlags (buf, 0x400, "ATTR", 0x40000000)
0x0028A410  LobbyApiRequest(api, 'mesg', buf, _SendChalMessage)
```

and `TEXT` is the verb followed by the match setup, newline-separated:

```
challenge\nCOUR=5\nGLFR=0\nSHOT=40\nMFLG=33\nCFLG=134367332\n
PTS=0\nRANK=0\nSTUS=0\nPNG=2\nWIN=0\nLOSS=0\nTIE=0\nINC=0\n
```

The verbs are the literals at `0x00311D98`-`0x00311E20`: `accept` `decline`
`busy` `revoke` `challenge`.

### Flag fields are bit-characters, not numbers

This is the one that cost the evening. `ATTR=3` in the capture is not the
number three. The writer at `0x002BE1A8` and the reader at `0x002BF228` are
inverses of each other over a 31-character alphabet:

```
0x003145B0  "@ABCDEFGHIJKLMNOPQRSTUVWXYZ0123"      the alphabet
0x003145D0  a 256-word table, its exact inverse

writer:  for c in ALPHABET: if v & 1: emit c;  v >>= 1;  stop when v == 0
reader:  for c in text:     v |= TABLE[c];     stop at the first c not in it
```

Bit 0 is `@`, bits 1-26 are `A`-`Z`, bits 27-30 are `0`-`3`. There is no bit 31.
So `0x40000000` is bit 30 is `'3'`, and `LOBBYAPI_FL_ATTR0` (the name is in the
format string at `0x0030F7F0`) is bit 27, `'0'`.

The reader **stops at the first unknown character**, so a decimal decodes to
zero: `F=65536` reads as `'6'` -> not in the table -> `0`. Our pushes were
flagged `F=65536`, so every one of them arrived with no flags at all.

### The push reads `N`, `T` and `F` -- not `TEXT`

`+msg` lands at `0x002BC128` in the connection layer, which builds a 4-word
record and calls the registered handler at `api+0x520`:

```
0x002BC150  record+0x00 = 1
0x002BC158  record+0x04 = 'chat'                    ; the default kind
0x002BC164  f = TagFieldGetFlags(body, "F")         ; "F" is at 0x003177D8
0x002BC180  record+0x08 = f
0x002BC168  record+0x0C = the TagField body
0x002BC17C  if f & 0x00000004:  record+0x04 = 'cast'
0x002BC19C  if f & 0x00010000:  record+0x04 = 'priv'
```

and the lobby's handler is `0x00273150`, which reads **two** fields out of that
body:

| field | offset | size | what |
|---|---|---|---|
| `N` | `0x00273190` | 64 | the sender's name |
| `T` | `0x002731B8` | 1024 | the message body |

`TEXT` is never looked at. We were sending `TEXT=`, so `T` came back empty --
hence `JED2:` with nothing after it.

### How the kind is rendered

```
0x0027325C  'cast' -> 0x00273CE8
0x00273268  'chat' -> 0x00273318
0x00273278  'priv' -> 0x00273288
0x00273280  anything else -> dropped
```

| kind | flags | format | at |
|---|---|---|---|
| `chat` | — | `"%s%s: %s"` | `0x0030F810` |
| `chat` | `& 0x8` | `"*** %s%s %s"` | `0x0030F7D8` |
| `chat` | `& 0x08000000` | `"(LOBBYAPI_FL_ATTR0 is set)%s %s"` | `0x0030F7F0` |
| `cast` | — | `"%s: *broadcast* %s"` | `0x0030F820` |
| `priv` | — | `"%s%s: *private* %s"` | `0x0030F7C0` |

The `%s` prefix in front of the name is a badge picked out of the flags at the
top of `0x00273150`: `0x0002` -> `" (admin)"`, `0x0100` -> `" (host)"`,
`0x2000` -> `" (mod)"`.

### The challenge branch

A `priv` message is only a challenge if the flags say so:

```
0x0027328C  if (flags & 0x40000000):
0x0027329C      if (flags & 0x00200000):  ignore
0x002732B0      else: 0x0028A460(N, prefix, T)     <- the challenge parser
0x002732C0  else: print it as a private chat line
```

`0x0028A460` then `strncmp`s the body against `"challenge"`, `"accept"` and the
rest, and on a match runs four gates before accepting:

| test | at | meaning |
|---|---|---|
| `[gp-0x66F8] & 0x1FF` must be 0 | `0x0028A4AC` | not already in a challenge -- the *issuer* sets bit 0 at `0x0028A440` |
| `[0x003B6EA0]` must be non-zero | `0x0028A4D0` | challenges enabled |
| `[0x00322244] & 1` must be 0 | `0x0028A4F8` | not "block challenges" |
| `0x00286E50(sender)` must be 0 | `0x0028A520` | sender is not on the ignore list |

then `0x002897D0` parses `COUR`/`GLFR`/.../`INC` out of the body.

### So a challenge push is

```
N = <sender persona>
T = <the whole TEXT block, verbatim>
F = P3                      0x00010000 | 0x40000000
```

`P` makes it private, `3` makes it a challenge. `lobbyd` now relays the
sender's own `ATTR` word into `F` rather than reconstructing it, so a verb we
have not seen yet still routes correctly, and masks off `0x00200000` so a relay
is never silently ignored. `tagfield.py` gained `flags_encode` / `flags_decode`
for the character form.

Room chat (no `PRIV`) is pushed with no flags at all, which is the plain
`"NAME: text"` line, and now goes to the sender as well as everyone else.

---

## 18. `chal` -- `MODE` is a word, and the error codes behind the dialogs

The challenge dialog works: `CHALLENGE RECEIVED` shows the issuer's profile and
the full match setup (Bethpage Black, all 18, ranked, the tee/pin/speed block),
with ACCEPT / DECLINE / BLOCK. Accepting produced `COULDN'T ISSUE CHALLENGE TO
OPPONENT` on both clients.

### What accept sends

```
01:40:43 <-- mesg  TEXT=accept PRIV=jed2 ATTR=3      the accepter -> the issuer
01:40:43 --> +msg  N=ooo T=accept F=P3
01:40:43 <-- chal  PERS=ooo  HOST=1                  the issuer   (it hosts)
01:40:43 <-- chal  PERS=jed2 HOST=0                  the accepter
01:40:43 <-- chal  PERS=*                            both re-subscribe
```

So `chal` is two different requests wearing one verb. With no `HOST` it is the
subscribe-to-challenges call made right after `auth`, whose callback ignores the
reply. With `HOST` it is `_SendChalMessage` (`0x00289AF0`), sent by **both**
clients the instant a challenge is accepted -- the issuer with `HOST=1`, the
accepter with `HOST=0`, each naming the other in `PERS`.

### `MODE` is a four-character word

`_ChalCallback` is `0x00289470`. It reads `MODE` as a string (default `""` from
`0x00311AA0`) and strcmps it:

```
0x002894C8  MODE == "play"  -> return, proceed
0x002894DC  MODE == "chal"  -> return, proceed (standby)
0x002894F0  MODE == "idle"  -> 0x00311AC0 "Challenge was cancelled"
            anything else   -> 0x0028A920(), then
                               0x00311AE0 "Couldn't issue challenge to opponent"
```

`MODE=0` matched none of the three and fell straight into the last case. The
words are the literals at `0x00311AA8`/`AB0`/`AB8`, right next to each other.

### The rejection codes

Before it looks at `MODE` at all, `0x002894B4` reads the request's error 4CC and
each value has its own dialog:

| code | message | at |
|---|---|---|
| `nrom` | Your opponent has left the room | `0x00311B10` |
| `uusr` | Your opponent has left the room | `0x00311B10` |
| `igno` | Your opponent is not accepting challenges | `0x00311B30` |
| `ingm` | Your opponent is in a game | `0x00311B60` |
| `paut` | (not authorized) | `0x00311B90` |
| `maut` | Your account is not authorized to issue challenges | `0x00311BD0` |

All of them also clear `[gp-0x66F8]`, the "in a challenge" word the issuer set
at `0x0028A440`. That is the vocabulary a real server used to turn a match down,
and it is worth implementing properly rather than only ever answering OK.

### What the recipient answers with when a gate fails

The four gates in `0x0028A460` do not error -- they send a verb back:

```
0x0028A4C4  "busy"       already in a challenge, or challenges disabled
0x0028A514  "ignoreall"  [0x00322244] & 1
0x0028A538  "ignore"     the sender is on the ignore list
```

which is why `busy`, `ignore` and `ignoreall` are in the verb list at
`0x00311E00`-`0x00311E80` alongside `accept`, `decline` and `revoke`.

### Now

`lobbyd` answers the subscribe form with a bare `OK` and the paired form with
`MODE=play`, and records the pairing plus both endpoints -- which is what a
`+ses` push (`0x002BBEE0`: `NAME` `SELF` `HOST` `OPPO` `P1`..`P4`) would have to
hand over for the peer-to-peer leg.

---

## 19. `+ses` -- the match-start push, and the address problem

`MODE=play` works. Both clients leave the lobby and sit on `CONNECTING TO PEER
/ PLEASE WAIT...`, and the lobby socket goes quiet apart from keepalives:

```
01:46:46 <-- chal  PERS=ooo  HOST=1
01:46:46 --> chal  OK MODE=play
01:46:46 <-- chal  PERS=jed2 HOST=0
01:46:46 --> chal  OK MODE=play
01:46:48 --> ~png                     ...and nothing else, ever
```

`_ChalCallback` reads nothing but `MODE`, so the address of the other console
has to arrive some other way. It does: **`+ses`**.

### The handler

`+ses` is handled inline in the connection layer -- the `bne` at `0x002BBEF0`
falls through into `0x002BBEF4`, and the block runs to `0x002BC118`. It reads
thirteen fields onto the API handle:

| field | offset | size | reader |
|---|---|---|---|
| `NAME` | `api+0x200` | 32 | string |
| `SELF` | `api+0x220` | 32 | string |
| `HOST` | `api+0x240` | 32 | string |
| `OPPO` | `api+0x260` | 32 | string |
| `P1`..`P4` | `api+0x280`.. | 16 each | string |
| `ADDR` | `api+0x2C0` | — | `0x002BF270`, a dotted-quad parser |
| `FROM` | `api+0x2C4` | — | `0x002BF1A8` |
| `SEED` | `api+0x2C8` | — | `0x002BF270` |
| `WHEN` | `api+0x2CC` | — | `0x002BFD80`, which tests for a leading `$` |
| `AUTH` | `api+0x2D0` | 64 | string |

then `api+0x08 |= 0x200` and it calls `[api+0x538]` with a record whose kind is
`'play'` and whose first word is `4`.

### Which callback that is

`0x002BA4B0(api, slot, fn, arg)` is the push-handler registry:

```
0x002BA4B0  a1 <<= 3
            [api + slot*8 + 0x518] = fn
            [api + slot*8 + 0x51C] = arg
```

so slot 1 is `api+0x520` (which is where `+msg` dispatches, section 17) and
slot 4 is `api+0x538`. `Lobby_Init` fills them at `0x002747F0`-`0x00274854`:

| slot | handler | at |
|---|---|---|
| 1 | `0x00273150` | `+msg` |
| 2 | `0x00273510` | |
| 3 | `0x00273430` | |
| 4 | `0x00273470` | `+ses` |

`0x00273470` re-reads two fields as 32-byte strings and copies them into a peer
record, then flags the challenge state word:

```
0x00273494  FROM (0x0030F838) -> 0x0028B210 -> strcpy(peer + 0x20, s)
0x002734C4  ADDR (0x0030F840) -> 0x0028B260 -> strcpy(peer + 0x40, s)
0x002734F0  [gp-0x66F8] |= 0x10
```

So of the thirteen, the two that carry the match are **`FROM`** (the other
player's name) and **`ADDR`** (their dotted quad). There is no `PORT`: the port
is the one each console volunteered in its own `addr` request at login.

### The address problem

That is where this stops being a protocol question. Under the `Sockets` DEV9
backend PCSX2 runs a userspace stack behind a virtual DHCP server that hands
out **192.0.2.100 to every instance**, so both consoles report the same
address:

```
MATCH jed2 (host=1, 192.0.2.100:7547)  vs ooo  (192.0.2.100:21458)
MATCH ooo  (host=0, 192.0.2.100:21458) vs jed2 (192.0.2.100:7547)
```

Relaying those verbatim tells each client to connect to itself. `lobbyd`
therefore substitutes the address that client reached *us* on -- both emulators
are on that host, the ports differ because each console picked its own, and the
Sockets backend maps a PS2 socket onto a host socket. Whether an inbound
connection survives that mapping is **unproven**; `--peer-addr` overrides it,
and if it does not work the fallback is PCAP Bridged, which gives each console a
real LAN address. That needs a wired NIC (bridging is generally dropped on
Wi-Fi) and two instances would need distinct MACs.

`lobbyd` now pushes `+ses` to both halves as soon as each has named the other
in `chal`. `NAME`/`SELF`/`HOST`/`OPPO`/`P1`/`P2`/`SEED`/`WHEN`/`AUTH` are
best-guess; `FROM` and `ADDR` are the ones read out of the disassembly.

---

## 20. The P2P leg: UDP 3658, and why two instances on one host collide

`+ses` works. The host loaded Bethpage Black and played the flyover; the joiner
showed `UNABLE TO CONNECT TO PEER`, and the host then lost the connection. So
the lobby side is finished and the failure is entirely in the peer link.

### The connect string

Live memory settles it. At `0x0036D8C0`:

```
0036d8c0  31 39 32 2e 31 36 38 2e 31 2e 35 30 3a 33 36 35  |192.168.1.50:365|
0036d8d0  38 3a 33 36 35 38 00                             |8:3658.|
```

`192.168.1.50` is the `ADDR` we put in `+ses`, so that field reaches the peer
layer intact. The rest is built by `0x0027AB40`:

```
0x0027AB40(addr, suffix):
0x0027AB58  [gp-0x66B8] = 0x101
0x0027AB6C  sprintf(0x0036D8C0, "%s%s%s", addr, suffix, suffix)   ; 0x00310FE0
0x0027ABA4  [gp-0x66B4] |= 2
```

and the only caller passes the string literal at `0x00312238`, which is
**`":3658"`** -- appended twice, so the port is hardcoded and identical on both
consoles. Its callers pick the address out of the peer record built in
section 19:

```
0x0028B488  if [peer+0x88] & 0x40:  use peer+0x60
0x0028B4B0  else:                   use peer+0x40     <- our ADDR
0x0028B4B4  0x0027AB40(that, ":3658")
```

So `ADDR` is free-form as far as the peer layer is concerned -- it is
`strcpy`'d as a string at `0x002734C4` and only *also* parsed as a dotted quad
by `0x002BF270` at the connection layer, which stops at the first character
that is not a digit or a dot.

### The collision

PCSX2's `Sockets` DEV9 backend implements a PS2 bind by binding the **host** to
the same port, on the selected NIC's address. Watching both emulators through a
match attempt:

```
02:56:37  +  pcsx2-qt[20880]  192.168.1.50:3658
02:56:37  -  pcsx2-qt[18776]  192.168.1.50:3658
02:56:38  +  pcsx2-qt[18776]  192.168.1.50:3658
02:56:38  -  pcsx2-qt[20880]  192.168.1.50:3658
02:56:40  +  pcsx2-qt[20880]  192.168.1.50:3658
02:56:40  -  pcsx2-qt[18776]  192.168.1.50:3658
```

The second bind does not fail -- it **succeeds and takes the port away**. That
is Windows `SO_REUSEADDR` on UDP: a later bind to the same address and port
displaces the earlier socket, which then silently stops receiving. Each console
retries its peer connection every couple of seconds, and every retry steals the
port back, so neither ever holds a stable receive path for longer than the gap
between the other's retries.

That is also the precise shape of the symptom: the host happened to own 3658
through the course load and the flyover, and lost it on the joiner's next retry
-- `THE CONNECTION TO YOUR OPPONENT HAS BEEN LOST`, while the joiner, holding
the port only in the gaps, reported `UNABLE TO CONNECT TO PEER`.

The same ping-pong happens on `9999` before a match starts, and a third port,
`6000`, appears during one.

This is not fixable by anything the server says. The port is a literal in the
ELF and both consoles use it.

### What does fix it

Put the two emulators on **different host addresses**. The bind is
address-specific, so `192.168.1.50:3658` and `192.168.0.5:3658` can coexist,
and each console can then dial the other.

`lobbyd` picks the right address up automatically: `+ses` `ADDR` now comes from
the **source address of that client's lobby connection** (`client_address`),
not from the address it reports in `addr` (which is `192.0.2.100` for every
instance) and not from the address it dialled. Whatever NIC an instance's DEV9
is bound to is the address its traffic comes from, so the substitution follows
the configuration without being told.

`tools/p2pwatch.py` prints every UDP endpoint each PCSX2 owns and shouts when
two processes want the same port, which is how the above was measured.

### Other routes, if that is not workable

- **PCAP Bridged** gives each console a real LAN address of its own. Wants a
  wired NIC -- bridging is usually dropped on Wi-Fi -- and two instances would
  need distinct MACs.
- **Two machines.** The lobby side already works over the LAN.
- Patching the `":3658"` literal per instance does *not* work on its own,
  because the same literal supplies both ports in `"%s%s%s"`, so it cannot be
  made asymmetric without also working out which of the two is the local one.

---

## 21. Two NICs on one host is not a path either

Section 20's fix was wrong, and the way it is wrong is worth recording.

Putting the two emulators on different adapters did everything it was supposed
to at the lobby layer:

```
03:13:12 *** connect from 192.168.1.50:55304     PCSX2      (WiFi)     -> ooo
03:13:57 *** connect from 192.168.0.5:53961      PCSX2-MCP  (Ethernet) -> jed2
03:14:42 ***     +ses to ooo:  peer jed2 at 192.168.0.5:33875
03:14:42 ***     +ses to jed2: peer ooo  at 192.168.1.50:16964
```

and the address reached the peer layer intact -- `0x0036D8C0` in the host read
`192.168.1.50:3658:3658`, aimed correctly at the other console. The port fight
was gone: only the Ethernet instance bound `3658`, on its own address. Neither
console loaded.

### The measurement

`tools/udpcheck.py` binds a socket to each local address in turn and sends to
each of the others:

```
OK    127.0.0.1       -> 127.0.0.1
OK    192.168.1.50    -> 192.168.1.50
OK    192.168.0.5     -> 192.168.0.5
BLOCK 192.168.1.50    -> 192.168.0.5
BLOCK 192.168.0.5     -> 192.168.1.50
OK    *               -> 192.168.1.50
OK    *               -> 192.168.0.5
```

A datagram whose source is **pinned to one interface** and whose destination
belongs to **another interface on the same machine** is not delivered. An
unbound source reaches either address; a source on the same address as the
destination is fine. This is Windows' strong-host send behaviour, and PCSX2's
`Sockets` backend pins the source to the NIC it was configured with -- that is
why `p2pwatch` shows `192.168.1.50:3658` rather than `0.0.0.0:3658`.

So the two consoles had clean, uncontended sockets and no route between them.

### Where that leaves the single-machine case

| | |
|---|---|
| one NIC, both instances | they fight over UDP 3658 and steal it from each other (section 20) |
| two NICs | no contention, but the OS will not carry a pinned-source datagram between them |

Neither works, and no server-side change affects either. The lobby half is
finished; this is entirely a host-networking problem.

### Routes that could work

- **Two machines.** Nothing further to build -- the lobby already works across
  the LAN, each console gets its own address, and `+ses` picks the right one up
  from the connection source with no configuration. This is the cheap answer.
- **`weakhostsend`.** `netsh interface ipv4 set interface <idx> weakhostsend=enabled`
  is precisely the knob that governs the blocked case above. It is a
  system-wide networking change, so it is the operator's call, and it is
  untested here.
- **Different ports plus a relay.** The port is the literal `":3658"` at
  `0x00312238`, and each install has its own `.pnach`, so one instance can be
  moved to another port. The catch is `sprintf("%s%s%s", addr, ":3658",
  ":3658")` -- one literal supplies both ports, so patching it alone shifts
  both ends together and the two consoles still miss each other. `ADDR` is
  free-form though (it is `strcpy`'d at `0x002734C4`, and only *also* parsed as
  a dotted quad by a parser that stops at the first non-digit), so
  `ADDR=192.168.1.50:3659` yields `192.168.1.50:3659:3658:3658`. Whether
  DirtySDK reads that as `addr:remote:local` and ignores the fourth component
  is unverified; if it does, an asymmetric pair of ports is reachable without a
  relay at all.
- **PCAP Bridged**, which gives each console a real LAN address rather than a
  host-stack one. Wants a wired NIC and distinct MACs per instance.

---

## 22. Two seeds for one match

First full match: both consoles connected, loaded the hole, and played. After
the host's first shot both screens went black and the two disconnected from
each other. The cause was in `lobbyd`, and the log says it outright:

```
14:51:18 ***     MATCH jed2 (host=1, ...) vs ooo (...)
14:51:18 ***     SESSION 'Match.C.hhhhh': host=jed2 vs ooo, seed=242048934
14:51:18 ***     +ses to jed2 ...
14:51:18 ***     +ses to ooo ...
14:51:18 ***     MATCH ooo (host=0, ...) vs jed2 (...)
14:51:18 ***     SESSION 'Match.C.hhhhh': host=jed2 vs ooo, seed=1748185401
14:51:18 ***     +ses to ooo ...
14:51:18 ***     +ses to jed2 ...
```

**Two sessions, two seeds, four pushes.** Both clients send `chal` when a
challenge is accepted, and `start_session` ran once per `chal`, minting a fresh
`random.randrange()` seed each time. Each console got two `+ses` records with
different `SEED` values, and which one it ended up holding was a race. Two
consoles playing the same hole from different seeds agree right up until the
first shot resolves.

(The first of the two firings was only possible because `MATCHED` was never
cleared, so a stale entry from an earlier attempt completed the pair early. The
second firing needed no staleness at all -- whichever `chal` arrives second
always completes the pair -- so the duplicate was inevitable either way.)

The session is now decided **once per pair** and kept in `SESSIONS`, keyed by
`frozenset({a, b})`; a second `chal` replays nothing and logs that it did not.

### A crash hiding behind it

Fixing that surfaced a second bug in the same path. `peer_address` did

```python
addr, port = ONLINE.get(peer, ('', ''))
...
if addr.startswith(PCSX2_VIRTUAL):
```

and `ONLINE[persona]` is whatever the client sent in `addr`, which is
`(None, None)` for a client that never completed that step. The
`AttributeError` killed the handler thread *after* the session was minted and
*before* anything was pushed: the log showed a `SESSION` line, no `+ses`, and
an immediate disconnect with no explanation. Guarded now.

`tests/lobbyd_roomtest.py` covers both: it drives challenge -> accept -> two
`chal`s and asserts exactly one `+ses` per console, one shared `SEED`, and the
right `FROM` on each side.

---

## 23. Round results, and moving the server

### `rank` arrives

A finished match reports, from **both** consoles, and the block is the 60-field
one from section 9:

```
14:59:51 <-- rank  WHEN=2026.9.18 4:51:18  REPT=ooo  AUTH=tw04-local
                   NAME0=jed2 NAME1=ooo  RANK0=1 RANK1=1  QUIT0=1 QUIT1=0
                   ... LDRV0=300 LDRV1=272  SHTC0=3 SHTC1=0 ...
```

Three things that confirm guesses made earlier:

- **`AUTH` is the session token.** `tw04-local` is the literal `lobbyd` put in
  the `+ses` push, handed straight back when the match ends. That is how a real
  server ties a result to the session it issued -- and how it would reject a
  fabricated one.
- **`WHEN` is the session timestamp**, echoed from the same push: `+ses` carried
  the Unix time as a binary field and the result reports it back formatted.
- **`REPT` is who is reporting**, so the two submissions of one match are
  distinguishable. `NAME0`/`NAME1` are the players, and the `0`/`1` suffix on
  every other field picks the side.

`SHTC` is the shot-clock violation count -- the game disqualifies on the third
-- and `LDRV` the longest drive in yards. `QUIT` distinguishes a completed
match from an abandoned one, which is what a ranking server would need to
penalise.

### Changing the server address

The lobby address is an IP literal in the ELF, so moving the server means
regenerating the patch. `tools/tw04_patcher.py` is the front end for that,
built as a standalone `TW04-MasterServerPatch.exe`:

```
python -m PyInstaller --onefile --console --name TW04-MasterServerPatch \
    --paths tools --hidden-import make_pnach tools/tw04_patcher.py
```

It asks for the address and port, finds the PCSX2 installs beside it, writes
`cheats/SLUS-20757_64F9781E.pnach` plus the per-game `EnableCheats` ini, and
remembers the answers for next time. A hostname is **resolved at patch time**
and the resulting IP is what gets written, because the field is 15 characters
and the game parses it as a dotted quad rather than resolving it.

### What still has to be solved before an internet server

The lobby half travels fine -- it is one TCP connection to a port you control.
The peer link does not, and the reason is section 20: the P2P port is the
literal `":3658"` at `0x00312238`, used for both ends.

- Each player needs **inbound UDP 3658** reachable, which behind NAT means a
  port forward. There is no hole-punch: the server never sees the peer traffic
  and cannot relay it.
- **Two players behind one NAT cannot both be reached**, because they would
  both need the same external port.
- `+ses` `ADDR` is the source address of that player's lobby connection, which
  on the internet is their public IP -- correct by construction, and it needs
  no configuration. But a player on the *same* LAN as the server would be
  handed a public address that their own router may not loop back.

---

## 24. Accounts: the database and the sign-up site

Two new files, standard library only -- no framework, no ORM, nothing to
install beyond Python itself.

### The error channel, first

Worth stating plainly because everything below depends on it: **an error is the
frame header's second word**, the field this project has been calling `ident`.
`0x002BB994` copies it into the request record at `+0x08` and every callback
tests it before looking at the body -- `_AuthCallback` at `0x002875C0`,
`_ChalCallback` at `0x002894B4`. Zero means success, which is why echoing the
request's ident has always read as OK.

`_RegisterCallback` (`0x002877E0`) knows three by name: `dupl` (name taken),
`tooy` (too young) and `pmal` (bad parent/guardian address). `_AuthCallback`
has no table at all -- it formats whatever code it is given into a dialog -- so
a readable 4CC is the friendliest thing to send. `lobbyd` uses `nusr`, `badp`,
`bann` and `nper`.

### `twdb.py`

sqlite, WAL mode, one file. The schema mirrors the login exactly:

```
auth NAME=<account> PASS=<enciphered>  ->  PERSONAS=<comma-separated>
pers PERS=<one of those>
```

so an **account** is the credential and a **persona** is the name other players
see. `_AuthCallback` parses `PERSONAS` at `0x002875E8` into four 32-byte slots
with a ',' separator, which fixes the limits: **at most four personas, at most
31 characters each, and no comma in a name**. The client's own validation caps
passwords at 4-16 characters (`0x00312BF0`), so the database refuses anything
that could never be typed at the console.

| table | holds |
|---|---|
| `accounts` | name, PBKDF2-SHA256 hash + salt, mail / gend / born / spam, disabled |
| `personas` | up to four per account, globally unique |
| `golfers` | the `CRPIN` blob per persona -- what `cusr whomi` uploads and `user` serves |
| `results` | every `rank` submission, verbatim |

The password arrives in plaintext -- the wire cipher is reversible by design and
the server has to decrypt it to check anything -- so it is hashed at rest and
never stored. `verify()` runs the full derivation even for an account that does
not exist, so a missing name and a wrong password take the same time.

### `webui.py`

`http.server` and nothing else: register, sign in, and a profile page for
personas, profile fields, password and match history. Sessions are in-memory
tokens behind an `HttpOnly; SameSite=Lax` cookie, POSTs carry a CSRF token, all
output goes through `html.escape`, and failed logins are rate-limited per
address. It is plain HTTP -- put a TLS terminator in front before it faces the
internet.

### What `lobbyd` does with it

- `auth` verifies against the database and answers with the account's real
  `PERSONAS`, `MAIL`, `GEND`, `BORN`, `SPAM`. An unknown name gets `nusr`, a
  wrong password `badp`, a disabled account `bann`.
- `pers` refuses a persona the account does not own (`nper`). Without that, the
  persona list would be advice rather than a rule and anyone could log in as
  anyone.
- `acct` -- account creation from the console -- creates a real account, and
  answers `dupl` for a name already taken.
- `cusr whomi` stores the golfer against the persona, `user` serves it from the
  database, so a created player survives a restart and follows its persona.
- `rank` stores both consoles' submissions. `AUTH` ties them to the session the
  server minted in `+ses`, so a result for a match the server never brokered is
  recognisable.

`--open` restores the old behaviour of creating an account on first login,
which is convenient on a LAN and wrong on the internet. The test suites use it;
`tests/lobbyd_authtest.py` deliberately does not, and asserts that a wrong
password, an unknown account and someone else's persona are all refused:

```
the real account         -> auth 0x00000000 pers 0x00000000
a wrong password         -> auth badp       pers None
an unknown account       -> auth nusr       pers None
someone else's persona   -> auth 0x00000000 pers nper
```

### Running it

```bash
python webui.py --port 8080
python lobbyd.py
```

Both open the same file; sqlite's locking handles the overlap and WAL means the
web site never blocks the game.

### The default path is anchored to the project, not to the shell

It did not start that way, and the first deployment found it immediately. The
default was the relative `data/tw04.db`, `lobbyd` was started from inside
`tools/`, and the two processes quietly used two different files:

```
18:01:34 *** accounts in .../TigerWoods04-05Network/tools/data/tw04.db
18:03:26 !!!     auth refused: no account 'JeddyH' -- make one on the web site
```

The account existed. It was in `.../TigerWoods04-05Network/data/tw04.db`, which
is where the web site had been started from. A relative default does not make
two processes agree on a file -- it makes them agree only when they happen to be
launched from the same folder, which is not a property anyone can see.

`twdb.DEFAULT_DB` is now derived from `twdb.py`'s own location, so every tool
resolves the same absolute path from any working directory. `lobbyd` also prints
the account count at startup and says so plainly when there are none:

```
*** accounts in /srv/tw04/data/tw04.db -- 0 registered
!!! that database has no accounts, so every login will be refused.
!!! point webui.py at the SAME path -- it prints the one it opened -- or pass --open.
```

This is the same shape of mistake as the lobby port mismatch in `bringup.md`:
two things that must agree, with nothing making them agree. The cure is the
same -- one derived source of truth, and print it.

---

## 25. Passwords stay out of the log

`lobbyd` spent most of this project as a measuring instrument, and its most
useful line was:

```
PASS ciphertext '~zP< 1JZD\x7f$WeC5m4$76&/DAe}1n<WH' (31 chars)
PASS decrypted  'hunter2'
```

That is exactly how `eacrypt.py` was verified against the real client. It is
also completely wrong for a server that real people log into, and the first
deployment proved it: a log shipped for debugging carried a live account's
password in clear.

Both halves are sensitive, not just the plaintext. The session key is a fixed
constant in the source, so anyone holding the ciphertext holds the password.

### What is logged now

| | |
|---|---|
| the frame body | `PASS=<redacted>` -- substituted before the line is written |
| the decoded fields | `PASS '<redacted, 31 chars>'` |
| `--verbose` hexdump | suppressed for any frame carrying a secret field |
| the decrypt | `PASS decrypted, 7 chars` |
| `--password` | `MATCH` / `MISMATCH` with lengths, never the values |
| startup | the expected password's length, not the password |

`--log-passwords` restores the old behaviour in full, announces itself loudly at
startup, and is the only way to get the ciphertext back for cipher work.

The redaction is a substitution on the decoded body plus a filter on the field
list, so it survives a new verb carrying `PASS` without anyone remembering to
handle it. `SECRET_FIELDS` is the list to extend if another one appears.

### Logs already written

Redaction only applies from here. Any `capture.log` from before this change
contains whatever passwords were typed while it was running, and should be
deleted or treated as a credential store.

---

## 26. The first real round, and what is left

A completed Front 9 between two players, 2026-09-18. Both consoles reported and
the numbers are real:

```
STROKES0=30 STROKES1=41   PUTTS0=14 PUTTS1=18   HOLES0=9  HOLES1=9
EAGS0=1     BIRD0=4       GIR0=8    LDRV0=369   COMP0=9   COMP1=9
DONE0=1     DONE1=1       QUIT0=0   QUIT1=0
```

### Three things that round exposed

**`SCORE` is not the score.** `SCORE0` and `SCORE1` are both `0` in stroke play.
`STROKES` is the result and fewer is better. Anything deciding a winner from
`SCORE` decides every match is a tie, which is what the first version did.

**The `NAME` fields cannot be trusted.** The two submissions of one match were:

```
REPT=JeddyH2  NAME0=JeddyH2  NAME1=JeddyH
REPT=JeddyH   NAME0=JeddyH2  NAME1=JeddyH2      <- both sides, same name
```

The numbers in both are identical and in the same order, so the suffix is
**positional, not relative to the reporter**: `0` is the host, `1` the guest,
in every submission. Which persona that is comes from the session the server
brokered, not from the frame.

**`AUTH` was a constant.** `tw04-local` in every `+ses`, so every match in the
database looked like the same one and no result could be tied to a pairing.
It is now a per-session `secrets.token_hex(8)`.

And results arrive **long** after the match: the round started at 18:24 and the
two submissions landed at 18:46 and 18:47, with both consoles having
disconnected and logged in again in between. So the pairing cannot live in
memory -- there is now a `sessions` table, and a result whose token names no
session is stored but explicitly not scored.

`tests/twdb_statstest.py` keeps those three traps honest, replaying the real
submissions verbatim.

### What is still to build

Nothing below is guesswork about *whether* the feature exists -- every one is
something the client already asks for and we currently answer with a bare OK.

| feature | the client's side of it | what is missing |
|---|---|---|
| **Rankings / leaderboard** | `sele` subscribes `RANKS=1`; `+rnk` push; `0x002741E0` reads `S` (128 bytes), `R`, `P`; `cusr myrnk` reply reads `RNKRS` (144 bytes, `0x002742B0`) | the wire shape of a `+rnk` record and of `RNKRS`. The server now *has* the data |
| **Profile statistics** | ONLINE POINTS / RANK / TIGER STATUS / RECORD / INCOMPLETES on the profile screen; the challenge blob carries `PTS RANK STUS WIN LOSS TIE INC` (`0x002897D0`) | which field feeds which line. `+usr` `A` (+0x30) and `S` (+0x38, 128 bytes) are the two unidentified slots |
| **Tournaments** | `cusr mg5ri` (info, `START`/`NUM`), `esr2t` (permission -> `TKEY` + `DATA`, `_TourneyStartCallback` `0x002DE160`), `5d0tr` (report a round, payload in `DATA`), `qdb@w` (results) | the `DATA` blob format. The largest single feature left |
| **EA Messenger / buddy list** | a whole second module at `0x002C3A50` with its own server, whose address `news` hands out (`Lobby_GetBuddyServerAddr`); reads `USER DOMN RSRC SHOW STAT PRES LKEY LRSC LIST BODY SUBJ ID SIZE GROUP FUSR`; presence values `DND XA AWAY CHAT DISC` at `0x003178D8` | everything -- but the field names are XMPP-shaped, which is a strong hint about the protocol |
| **News / MOTD** | `Lobby_GetNews`, `news NAME=0`, answered `COUNT=0` today | the news record shape. Cheapest visible win on the list |
| **Quick Play** | `snap` with `FIND INDEX CHAN START RANGE` (`0x00276DD0`, `0x00276F20`); reply read at `0x00273D30` (`RANGE`) plus `LIDENT LCOUNT IDENT COUNT FLAGS` at the connection layer | a paged snapshot reply. This is the same channel machinery as the rankings |
| **Report abuse** | `rept PERS PROD LANG` (`0x00275430`) | nothing but a table to write it to |
| **Entitlements / Pro Shop** | the flags riding on `mg5ri`/`esr2t`: `BIOT BIOL WRLD PROG SCEN TBAL RTE0-3 PGAS SAV0` | already effectively granted -- a bare OK was enough to unlock the Pro Shop |

### The order worth doing them in

1. **News** -- smallest, self-contained, and it puts a visible message on the
   screen the moment it works, which makes it a good test of the reply shape.
2. **Rankings** -- the data exists now. `+rnk` is a push on a channel already
   subscribed, and `0x002741E0` is three fields. Trap it and push a guess.
3. **Profile statistics** -- same session, since `+usr` `A` and `S` are the
   remaining unknowns on a record already being sent.
4. **Quick Play** -- reuses whatever the rankings work establishes about paged
   snapshots.
5. **Tournaments** -- the big one, and the only one where the payload is opaque
   rather than merely unknown.
6. **EA Messenger** -- a separate server; worth doing last, and worth checking
   first whether anything in the game actually needs it.

The method that has worked every time here: answer with a shaped guess, watch
the screen, and trap the reader when the screen disagrees. Every field name
above was read out of the client, so the guesses start well informed.

---

## 27. `news` is two requests wearing one verb

Both send the verb `news`; `NAME` tells them apart, and neither reply is a
TagField.

### `NAME=0` -- the EA Messenger address

`Lobby_GetBuddyServerAddr` (`0x00287F60`) sends the literal body `NAME=0` from
`0x003115B8`. Its only caller is **inside `_AuthCallback`, at `0x00287770`** --
which is why every capture in this project shows a `news NAME=0` immediately
after a successful login. It has never been a news request.

The callback is `0x002873D0`:

```
0x002873DC  body = [request+0x0C];  if NULL -> show the error code
0x002873EC  if *body == 0 -> return quietly          ; an empty reply is fine
0x00287408  copy body into a buffer until '\n' (0x0A) or '\r' (0x0D)
0x00287460  p = strchr(first_line, ':')              ; ":" is at 0x003113B0
0x00287480  if p:  0x00286120(p + 1)                 ; the port
0x00287488         *p = 0
0x00287490  0x00286110(first_line)                   ; the host
0x002874A0  [gp-0x66FC] |= 0x10000000                ; "buddy server known"
```

So the entire reply is **one line, `host:port`**. That single line is the hinge
to the whole EA Messenger / buddy-list module -- pointing it somewhere is how
that service would ever be reached.

An empty body is explicitly checked for and ignored, so answering with nothing
is the correct thing to do until such a server exists. What `lobbyd` used to
send -- `OK\nCOUNT=0\n` -- has no colon, so the client took `"OK"` as the buddy
server's hostname.

### `NAME=1` -- the news

`Lobby_GetNews` (`0x00287ED0`) formats `"NAME=%d"` (`0x00311598`) with a
constant `1`. Its callback `0x002872E0` does not parse the body at all:

```
0x00287300  s0 = [request+0x0C]                      ; the whole body
0x00287314  memset(0x003B5A44, 0, 0x1388)            ; a 5000-byte buffer
0x00287320  if [0x003B6DCC] -> skip                  ; only taken once
0x00287344  strcpy(0x003B5A44, s0)                   ; or strncpy at 0x1387
0x00287378  [0x003B6DCC] = 1
0x00287384  0x00272D80(0x003B5A44)                   ; word-wrap at 0x40 and show
```

**The reply body IS the news text**, verbatim. No `OK`, no tags -- anything in
the usual `~~` slot is printed as the first line of the news. It is fetched
once per session (`0x003B6DCC` latches), capped at 4999 bytes, and wrapped at
64 characters by `0x00272ED0`.

`Lobby_GetNews` has five callers: `0x002846B4`, `0x002848E4`, `0x00284C54`,
`0x002892DC` and `0x002A2494` -- the last inside front-end handler slot 640
(`0x00354E8C` -> `0x002A2470`).

### What `lobbyd` does now

`--news <file>`, default `data/news.txt`, **re-read on every request** so it can
be edited while the server runs. Falls back to a built-in message when the file
is not there, and says so at startup. `--buddy-addr HOST:PORT` sets the
Messenger address; unset means an empty reply, which the client handles.

```
news NAME=0 -> body=b'192.168.1.88:5222\n\x00'
news NAME=1 -> body=b'COURSE OF THE WEEK: Bethpage Black\nServer maintenance...\n\x00'
```

---

## 28. Rankings: `onln` and `cusr myrnk`

Done from the ELF at
`SLUS_207.57` (extracted from the disc image) with
`analysis/disfn.py` and `analysis/xref.py` -- no emulator, no debugger. That file
should have been found much earlier; everything static in these notes can be
done from it.

### Two requests, one context

`0x00277060` and `0x00277130` are near-identical: both rate-limit themselves
against a stored timestamp (the float compare at `0x002770BC`), both build
`PERS=<persona>`, and both pass **the global online context at `[gp-0x6714]`**
as the request's user pointer -- which is why their callbacks can write
straight into it.

| sender | verb | callback | reads |
|---|---|---|---|
| `0x00277060` | `onln` | `0x002741E0` | `S` `R` `P` |
| `0x00277130` | `cusr CMD=myrnk` | `0x002742B0` | `RNKRS` |

### `onln` -- `0x002741E0`

```
0x002741FC  memset(ctx + 0x7C, 0, 0x80)
0x00274208  if [req+0x08] != 0 -> bail          ; the error word
0x00274234  GetString (body, "S", ctx + 0x7C, 0x80)    ; 0x002BF5F0
0x00274250  ctx + 0xFC  = GetInt(body, "R")            ; 0x002BF1A8
0x00274274  ctx + 0x100 = GetInt(body, "P")
0x00274288  0x00294A00(0xD4)                           ; redraw
```

### `cusr myrnk` -- `0x002742B0`

```
0x002742D0  memset(ctx + 0x104, 0, 0x90)
0x002742DC  if [req+0x08] != 0 -> bail
0x002742FC  GetBinary(body, "RNKRS", ctx + 0x104, 0x90)    ; 0x002BF7F0
0x00274308  0x00294A00(0xD4)
```

**`RNKRS` is a binary field, not a number.** `0x002BF7F0` tests the first byte
for `'$'` (`0x24`) and returns `-1` for anything else, so the `RNKRS=0` this
server used to send was rejected outright. It takes 144 bytes.

### The context struct at `[gp-0x6714]`

| offset | size | from |
|---|---|---|
| `+0x08` | 4 | the LobbyAPI handle |
| `+0x7C` | 128 | `S`, a string |
| `+0xFC` | 4 | `R` |
| `+0x100` | 4 | `P` |
| `+0x104` | 144 | `RNKRS`, binary |
| `+0x198` | 8 | `onln` rate-limit timestamp |
| `+0x1A0` | 8 | `myrnk` rate-limit timestamp |

Both callbacks finish by posting UI message `0xD4`, which is what makes the
profile screen redraw -- so a reply to either is visible immediately.

### What is answered now

`R` and `P` line up with the **ONLINE RANK** and **ONLINE POINTS** lines on the
profile screen, which is inference from position, not proof. `lobbyd` computes
both from the stored results: rank is the position on `DB.leaderboard()`, points
are two for a win and one for a tie -- **our scheme, not EA's**, which is not
recoverable from a client that only ever displays the number it is given.

`S` is 128 bytes and unidentified. It is sent as the `W-L-T` record in text, on
the grounds that if it appears anywhere on screen that identifies it, and if it
does not, nothing is lost.

```
onln JeddyH2  -> OK  S=1-0-0  R=1  P=2
onln JeddyH   -> OK  S=0-1-0  R=2  P=0
cusr myrnk    -> OK  CMD=myrnk  RNKRS=$0000...   (144 zero bytes)
```

`RNKRS`'s 144 bytes are the leaderboard itself and the layout is still unknown.
Zeros at least satisfy the reader. Finding the layout means tracing what reads
`ctx+0x104`, which is the next step for this feature.

### `onln` is about YOURSELF -- a correction

Both ranking replies write into the **one** global context at `[gp-0x6714]`, so
they describe the logged-in player and nobody else. Opening another player's
ONLINE PROFILE does not send `onln` at all -- it sends `user`, whose callback
`0x00274330` reads exactly one field, `CRPIN`. Nothing in the `onln` work can
affect that screen, and expecting it to was a mistake.

The other player's numbers therefore have to arrive on the `+usr` push.

### `+usr` in full, from the ELF

`0x002BC6C8`, channel 1:

| tag | into | reader | size |
|---|---|---|---|
| `I` | `+0x00` | number, the id; negative is discarded | |
| `F` | `+0x04` | **`0x002BF228`** -- the bit-character codec from section 17 | |
| `N` | `+0x08` | string | 32 |
| `P` | `+0x28` | string | 8 |
| `A` | `+0x30` | **`0x002BF270`** -- a dotted quad | |
| `R` | `+0x34` | number | |
| `S` | `+0x38` | string | 128 |
| `X` | — | string | 128 |

Two fields were being sent wrongly for as long as `+usr` has worked:

- **`F=0` did not mean "no flags".** `F` uses the same bit-character encoding as
  `+msg`, where `'0'` is bit 27 -- `0x08000000`. Every user record pushed since
  section 16 has carried that bit set. The field is now omitted, which
  `0x002BF228` reads as zero.
- **`A=0` was not a number.** `A` is parsed as an address, and now carries the
  player's actual one.

`R` and `S` are now filled with the rank and the `W-L-T` record, the same values
`onln` reports, on the theory that the profile panel reads them from here.
`X`, the second 128-byte string, is left alone until there is a reason to guess.

```
+usr -> I=0  N=JeddyH2  P=good  A=192.168.1.11  R=1  S=1-0-0
```

---

## 29. The statistics record: 56 bit-fields in `S`

The VIEW RESUME screen shows about twenty numbers -- scoring average, best
round, holes in one, longest drive and putt, tournament earnings and finishes,
and separate match-play and stroke-play records with streaks. All of them come
from one field.

### `P` is ping, not points

A correction to section 28. `Lobby_SendChallenge` (`0x00289FA0`) builds the
challenge blob from the same getters the profile screen uses, and it is explicit
about which is which:

```
0x0028A214  jal 0x00276CC0   -> tag 'RANK'      ; returns ctx+0xFC  == our R
0x0028A254  jal 0x00276CD0   -> tag 'PNG'       ; returns ctx+0x100 == our P
0x0028A1F4  jal 0x00276C20(1) -> tag 'PTS'
0x0028A234  jal 0x00276C20(6) -> tag 'STUS'
```

So `R` really is the rank, but **`P` is the ping** -- the green connection dots
-- and online points are `0x00276C20(1)`, which comes from somewhere else
entirely.

### `0x00276C20(index)` -- the indexed statistic getter

```
0x00276C30  ctx = [gp-0x6714]
0x00276C34  if ctx->byte[0xF4] != 0x21:                  ; '!'
0x00276C44      return [0x00302448 + index * 16]         ; the table default
0x00276C58  0x002736C0(ctx + 0x7C, tmp, 0x78)            ; unescape 120 bytes
0x00276C6C  return 0x00273780(tmp, index)                ; extract bit-field
```

Three things fall out of that:

**`S` is the statistics record.** `ctx+0x7C` is where the `onln` reply puts `S`,
and this is the only thing that reads it.

**Byte 120 of `S` must be `'!'`.** `ctx+0xF4` is `ctx+0x7C+0x78` -- the byte
just past the payload. Without it the client ignores the record entirely and
uses the defaults from the table, which is exactly why every line on the resume
screen reads `0` or `N/A` no matter what the server sends.

**The payload is high-bit-escaped.** `0x002736C0` walks the buffer in groups:
one mask byte, then eight payload bytes, with bit *n* of the mask supplying the
top bit of payload byte *n*. That is the same encoding the `CRPIN` golfer blob
uses -- which is why those hexdumps are full of `0x80` and end in `0x21`.

### The descriptor table at `0x00302440`

56 entries of 16 bytes: width, default, mask, and a flag.

```
idx  0: 32 bits      idx  7-12: 13 bits each     idx 21-22: 20 bits
idx  1: 17 bits      idx 13-14:  8 bits, default 1
idx  6:  3 bits      idx 15-16: 11 bits each     ...
```

707 bits in total, about 89 bytes, inside a 120-byte payload. `0x00273780`
accumulates the widths to find each field's bit offset, so the packing is
sequential and the table is the whole specification.

### Indices identified so far

Every call to `0x00276C20` is inside `Lobby_SendChallenge`, and each result is
immediately written to a named tag, which names the index:

| index | width | tag |
|---|---|---|
| 1 | 17 | `PTS` -- online points |
| 6 | 3 | `STUS` -- Tiger status |
| 7, 8, 9 | 13 | `WIN` `LOSS` `TIE` -- one play mode |
| 10, 11, 12 | 13 | `WIN` `LOSS` `TIE` -- the other |
| 15, 16 | 11 | `INC` -- incompletes, one per mode |

Two sets of win/loss/tie matches the screen, which keeps MATCH PLAY and STROKE
PLAY records separately. The remaining 45 indices are not referenced from the
challenge path and will have to be found from the resume screen's own code.

### What this means for the server

Nothing will appear on that screen until `lobbyd` sends an `S` that is a
properly escaped, bit-packed, `'!'`-terminated record. The data exists -- the
`results` table has strokes, putts, GIR, longest drive and the rest -- so this
is now a codec problem rather than a protocol one.

---

## 30. The codec, built and verified

`twstats.py`. Two layers, both transcribed from the ELF, both tested.

### Layer 1 -- high-bit escaping (`0x002736C0`)

Groups of eight: **one mask byte then seven payload bytes**, with bit *n* of the
mask supplying the top bit of payload byte *n*. `0x0027374C` is the proof of the
seven -- `slti v1, t2, 7`.

The encoder forces bit 7 on in every transmitted byte, mask and payload alike.
`0x002736C0` ignores bit 7 of a mask and overwrites bit 7 of a payload, so
setting it is free, and it guarantees no byte can be NUL and cut the text field
short.

**Verified against real game data.** The `CRPIN` golfer blob uses the same
encoding, and a captured one is 665 bytes = 83 groups plus the `'!'`:

```
83 groups -> 581 decoded bytes
re-encodes byte-for-byte: True
decoded head: 02 00 32 32 32 32 32 32 32 32 32 32 32 32 ...
```

A run of `0x32` -- 50, the middle of every Create-A-Player slider -- which is
exactly what a default golfer should look like. That is the codec confirmed
against bytes the game itself produced, not against a guess.

### Layer 2 -- bit fields (`0x00273780`)

A plain LSB-first bit stream over the decoded bytes. The function word-aligns
the pointer and adds the slack to the bit offset (`0x00273850`), reads 32-bit
words, and takes bit *n* of the field from bit `(offset+n) & 31` of word
`(offset+n) >> 5` -- which on a little-endian machine is the same as bit
`(offset+n) & 7` of byte `(offset+n) >> 3`. No padding, no alignment between
fields; each one starts where the last ended.

### The record

```
121 bytes = 15 groups x 8 + the marker
105 decoded bytes, 707 bits used by 56 fields
```

`S` is read by `0x002BF5F0`, whose size limit counts **output** bytes, so 121
decoded fits inside the 128 it allows. It also stops at any byte below `0x20`,
which the `%xx` escaping in the TagField layer already avoids.

### What is filled

Ten indices are named, all from `Lobby_SendChallenge`. `lobbyd` fills points and
one win/loss/tie/incompletes set from the stored results and leaves the other 46
at their table defaults:

```
onln reply: R=1 P=0, S is 121 bytes, marker 0x21
decoded back: PTS=2, WIN/a=1, LOSS/a=0, TIE/a=0, INC/a=0
```

Set **B** (indices 10-12, 16) is deliberately left at zero. The two sets are
MATCH PLAY and STROKE PLAY, but which is which is not established -- filling
only one means the screen identifies it.

The same record now goes out in `+usr` `S` as well, on the theory that another
player's panel reads the same structure from their user record.

---

## 31. The statistic indices, read off the screen

`--probe-stats` fills every field with its own index and the resume screen then
names its own fields. One pass mapped everything visible:

| index | width | MY RESUME line |
|---|---|---|
| 1 | 17 | ONLINE POINTS |
| 5 | 17 | TOTAL EARNINGS -- a value of 5 rendered **$5,000** |
| 6 | 3 | ONLINE TIGER STATUS -- 6 rendered `T-I-G-E-R` |
| 7, 8, 9 | 13 | MATCH PLAY RECORD (W-L) |
| 10, 11, 12 | 13 | STROKE PLAY RECORD (W-L-T) |
| 13 | 8 | STROKE PLAY CURRENT STREAK |
| 14 | 8 | MATCH PLAY CURRENT STREAK |
| 15 | 11 | STROKE PLAY INCOMPLETES |
| 16 | 11 | MATCH PLAY INCOMPLETES |
| 26 | 10 | EVENTS ENTERED |
| 27 | 10 | EVENTS WON |
| 28 | 10 | TOP 10 FINISHES |
| 29 | 10 | TOP 25 FINISHES |
| 32 | 16 | HOLES IN ONE |
| 34 | 8 | LONGEST PUTT |
| 37 | 9 | LONGEST DRIVE |
| 39 | 8, signed | BEST ROUND |
| 41 | 8, signed | SCORING AVERAGE |

Two things the probe settled that guessing had got backwards:

- **7-9 are match play and 10-12 are stroke play**, not the other way round.
- **The incompletes are crossed over**: 15 is stroke play and 16 is match play,
  while the streaks run 13 stroke, 14 match.

`EARNINGS` being `$5,000` for a stored `5` means the field is thousands, which
also explains 17 bits being enough.

### What is still unnamed

Fields 0, 2, 3, 4, 17-25, 30, 31, 33, 35, 36, 38, 40 and 42-55 did not appear
anywhere on the resume screen. Some will be on screens not visited yet; some
are probably unused.

EARNINGS RANK showed `N/A`, which is how both rank lines render a zero, so
whichever field feeds it held 0 during the probe -- field 0 is the obvious
suspect, since it is the only one the probe could not distinguish from unset.

Fields **17 and 18** are three bits and were clamped to 7, so they could not
name themselves. They are the best candidates for the **W/L prefix** on the two
streak lines: the probe showed `W13` and `W14` for positive values, and 13 and
14 are unsigned, so the letter comes from somewhere else. Until that is
settled `lobbyd` sends only winning streaks -- a losing one would be drawn as a
win.

### Filled from real results

Match and stroke play are told apart by the room name, which carries the type
(section 13). A stroke-play win and a match-play loss produce:

```
ONLINE POINTS    = 2
MATCH L          = 1
STROKE W         = 1
HOLES IN ONE     = 1
LONGEST DRIVE    = 369
BEST ROUND       = 30
SCORING AVERAGE  = 37
```

`BEST ROUND` and `SCORING AVERAGE` are signed 8-bit, so they hold a raw stroke
count comfortably for nine holes but would overflow a full eighteen-hole round
above 127. If they turn out to be strokes-relative-to-par, that range makes
much more sense, and the fix is one subtraction once par is known.

---

## 32. Course and conditions: they are in the challenge, not the result

`rank` carries no course and no conditions. The only place a match's settings
are ever stated is the **challenge that set it up**, minutes earlier:

```
challenge\nCOUR=5\nGLFR=0\nSHOT=40\nMFLG=33\nCFLG=134367332\n...
```

`Lobby_SendChallenge` reads them from one struct at `0x0028A17C` onwards:

| tag | from | |
|---|---|---|
| `COUR` | `byte [s0+0x80]` | course index |
| `GLFR` | `byte [s0+0x81]` | golfer |
| `SHOT` | `word [s0+0x84]` | shot clock, seconds |
| `MFLG` | `word [s0+0x88]` | |
| `CFLG` | `word [s0+0x8C]` | |

So the server has to catch the setup on the `mesg` and keep it. `lobbyd` now
stashes it against the pair and `start_session` writes it into the new `setup`
column on `sessions`.

### The course table

The names are a plain block at `0x00308550` and `COUR` indexes it from zero:

```
0  Pebble Beach          5  Bethpage Black       15 St Andrews
1  Princeville Resort    6  Royal Birkdale       ...
2  TPC at Sawgrass       7  Skillz               22 Tiger's Dream 18
3  Black Rock Cove       8  Bay Hill Club        23 Random 18
4  Penguin Falls         9  The Predator         24 Compilation 1
```

Confirmed rather than assumed: the capture carrying `COUR=5` is the challenge
whose setup screen read **COURSE: BETHPAGE BLACK**, and index 5 is Bethpage
Black.

The tee colours follow the courses in the same block at `0x00308768` --
`Black`, `Blue`, `White`, `Red` -- then `Short`, `Average`, `Long`.

### `MFLG` and `CFLG` are not decoded

The setup screen sets ten things: game mode, course, ranked, shot clock, holes,
tees, pins, green speed, fairway speed and rough length. Course and shot clock
have their own tags, so the other seven must be packed into the two flag words.

Three samples exist, all with the low bits `0x24864` and differing only in the
top nibble (`0x04`, `0x08`, `0x10`) -- consistent with a course or mode field up
there, but not enough to place the rest. `MFLG` was `33` every time.

Rather than invent a reading, the web site shows them raw. **Decoding them needs
four or five challenges that vary one setting at a time** -- change only the
tees, issue a challenge, cancel; change only the pins, and so on. Diffing the
`CFLG` values names the bits directly.

### Also fixed

`LPUT` -- longest putt -- was in every result block and never extracted, which
is why that line stayed at zero while the rest of RECORDS/STATISTICS filled in.

---

## 33. `CFLG` is one-hot, not packed

Three samples settle the structure, though not yet the names.

```
0x08024864  bits 2,5,6,11,14,17,27   pins Easy, green Med,  fairway Med, clock 40
0x04024864  bits 2,5,6,11,14,17,26   pins Easy, green Med,  fairway Med, clock 60
0x080450A4  bits 2,5,7,12,14,18,27   pins Med,  green Hard, fairway Hard, clock 60
```

**Bits 2, 5 and 14 are set in all three** -- fixed settings or plain flags.
Tees are locked to Hard in online play, which is a good candidate for one of
them.

Everything else falls into **four groups of exactly one bit**:

| group | observed |
|---|---|
| base 6 | 6 or 7 |
| base 11 | 11 or 12 |
| base 17 | 17 or 18 |
| base 26 | 26 or 27 |

Between the last two samples every one of the four moved up by exactly one
position. That is one bit per option value, not a small integer -- which is why
the raw numbers looked so unlike each other while only three settings changed.

The model explains every set bit in all three samples with nothing left over:

```
0x08024864  g6=0 g11=0 g17=0 g26=1
0x04024864  g6=0 g11=0 g17=0 g26=0
0x080450A4  g6=1 g11=1 g17=1 g26=1
```

### The groups, named

Four challenges varying exactly one setting each named four of the five:

```
0x10024864  pins=0 green=0 rough=0 fairway=0    baseline, everything lowest
0x040248A4  pins=1                              only the pins were changed
0x08025064         green=1                      only the green speed
0x04028864                rough=1               only the rough length
0x080450A4  pins=1 green=1        fairway=1     pins Med, green + fairway Hard
```

| group | setting |
|---|---|
| base 6 | pins |
| base 11 | green speed |
| base 14 | rough length |
| base 17 | fairway speed |
| base 26 | **not a condition** -- see below |

`fairway` was never touched in the four single-variable samples and never moved
in them, then moved in the one sample where the fairway speed changed. That is
as good a confirmation as the three that were varied deliberately.

**Bit 14 was wrongly listed as fixed.** It looked constant across the first
three samples and only revealed itself when a rough-length change moved it to
15. The `leftover` list in `cflg_groups` is what caught it -- a model that
cannot explain every set bit says so instead of quietly mis-reporting.

### Group 26 is not a setting

It took three different values across three challenges whose conditions were
identical, and it moved in every single-variable sample without being touched:

| sample | pins | green | rough | fairway | group 26 |
|---|---|---|---|---|---|
| baseline | 0 | 0 | 0 | 0 | 2 |
| pins +1 | 1 | 0 | 0 | 0 | 0 |
| green +1 | 0 | 1 | 0 | 0 | 1 |
| rough +1 | 0 | 0 | 1 | 0 | 0 |
| earlier, same conditions | 0 | 0 | 0 | 0 | 1 |
| earlier, same conditions | 0 | 0 | 0 | 0 | 0 |

Three identical condition sets, three different values. It is not a function of
the other groups and it is not a setting on the screen -- a nonce, a counter or
a cursor position. The server decodes it and deliberately does not report it.

### What the server does with it

`twstats.conditions()` returns `{name: index}` for the four named groups, and
the web site prints them beside each match:

```
60 s clock · fairway speed 1 · green speed 1 · pins 1 · rough length 0 · MFLG=34
```

The option *labels* per index are only partly known -- pins 0 is Easy and 1 is
Medium, observed -- so the index is shown rather than a guessed word.

### Why the names were not assignable before

Sample A to B changed **three** settings and **four** groups moved, so a fourth
thing moved with them -- rough length is the obvious suspect, but it is a
suspicion. And the first two samples differ only in group 26 while pins, green
and fairway are identical between them, so group 26 is something else again.

Assigning them needs challenges that vary **one setting at a time**. `lobbyd`
now prints the decomposition on every challenge:

```
***     setup: Bethpage Black, clock 60s, MFLG=34 CFLG=67258468
            conditions: g6=0 g11=0 g17=0 g26=0
```

so a run of single-variable challenges names the groups by inspection. Three
challenges changing only the pins, then three changing only the green speed,
and so on, is enough.

`MFLG` was 33 in the first capture and 34 in both later ones. It is a small
number and changes rarely, so it is probably the game mode and hole count
rather than conditions.

---

## 34. `cusr ufpvt` is the leaderboard's gate

"DATA UNAVAILABLE AT THIS TIME" on the STROKE PLAY LEADERBOARD and GOLFER OF
THE WEEK screens is one string at `0x0030F780`, printed from one place:

```
0x002723CC  v1 = [gp-0x773C]
0x002723D0  if v1 >= 0 -> render the rows
0x002723E8  else print "Data unavailable at this time"
```

So the whole thing hangs on one signed count. Who writes it:

```
0x002DE7A0  if [req+0x08] != 0:                    ; an error reply
0x002DE7FC      [gp-0x7748] = [gp-0x7744] = [gp-0x7740] = [gp-0x773C] = -1
            else:
0x002DE7D4      sscanf(body, "%d %d %d %d %d %d",
                       &a, &b, gp-0x7748, gp-0x7744, gp-0x7740, gp-0x6538)
0x002DE7E8      [gp-0x6542] = (short) a
0x002DE7EC      [gp-0x6540] = (short) b
0x002DE7F4      [gp-0x773C] = [gp-0x7740]
```

and that callback belongs to **`cusr CMD=ufpvt`** (`0x002DF630`) -- the command
this server has answered with a bare `OK` since the first capture, listed as
"purpose unknown" for the entire project.

### Two things follow

**The reply is plain text, not a TagField.** `sscanf` runs straight over the
body, so `OK\nCMD=ufpvt\n` matches nothing and leaves the counts unset. Like
`news`, the body *is* the payload: six space-separated integers.

**The fifth integer is the leaderboard's row count.** It lands in `[gp-0x7740]`
and is copied to `[gp-0x773C]`, which is what the renderer tests -- and what the
`snap` senders test before they will ask for a page:

```
0x00276DF0  v1 = [gp-0x773C]
0x00276DF4  if v1 < requested_index: do not ask
```

So the sequence is **`ufpvt` for the counts, then `snap` for the pages**. The
client will not send a single `snap` until a count says there is something to
fetch, which is why `snap` has been seen exactly once in this whole project.

### What the server sends now

```
ufpvt -> '0 0 0 0 2 0' (2 ranked players)
```

Only the one position whose meaning is established is filled. The other five --
`[gp-0x7748]`, `[gp-0x7744]`, `[gp-0x6538]` and the two shorts -- size other
lists, and which is which is not known. Leaving them zero means the log will
show exactly which list the client asks about first.

`myrnk` is unaffected and still a TagField; `cusr` reply shapes are per-command,
not per-verb.

### The statistics screen names more fields

ONLINE GAME MODES -> STATISTICS lists about twenty-six values against the same
56-field record from section 31 -- total eagles, holes per eagle, birdie
average, fairways hit, driving accuracy, total GIR, GIR percentage, putts per
hole, rounds completed and points for each play mode. Running `--probe-stats`
and reading *that* screen would name most of the 45 indices still unaccounted
for, in one pass.

---

## 35. The leaderboard rows are `+rnk`, and they carry the same record

Answering `cusr ufpvt` with six integers cleared "DATA UNAVAILABLE AT THIS
TIME" -- the screen now draws an empty list instead of an error, which is the
count being accepted. The rows themselves come from somewhere else.

### The renderer

`0x00272410` pulls five values out of each row with **`0x00273990`**, and that
function is `0x00276C20` with the record passed in rather than taken from the
global context:

```
0x0027399C  if row[0x78] != 0x21 -> return the table default
0x002739CC  0x002736C0(row, tmp, 0x78)        ; the same unescape
0x002739D8  return 0x00273780(tmp, index)     ; the same bit-field extract
```

Five calls, five columns: RANK, PLAYER NAME, POINTS, DROP%, STREAK. **A
leaderboard row is a 121-byte packed statistics record**, identical in format to
the `S` field from section 30 -- marker and all.

### The push

`+rnk`, handler at `0x002BC9F4`:

| tag | reader | |
|---|---|---|
| `D` | `0x002BF1A8` | number |
| `A` | `0x002BF1A8` | number |
| `N` | `0x002BF5F0`, 32 | the player's name |
| `S` | `0x002BF5F0`, 128 | the packed record |

So one push per player, with the same blob the profile screen already uses.
`lobbyd` sends them straight after answering `ufpvt`, on the grounds that the
count is only a promise and the rows have to follow it:

```
cusr  -> b'0 0 0 0 2 0'
+rnk  -> D=0 A=0 N=JeddyH2  S=121 bytes marker=0x21  points=2 strokeW=1
+rnk  -> D=1 A=0 N=JeddyH   S=121 bytes marker=0x21  points=0 strokeW=0
```

`D` is filled with the row index and `A` with zero; neither meaning is
established, and `D` is the better candidate for the index because `+rom` and
`+usr` both use a number in the same position for exactly that.

### Why `snap` has never fired

`0x00276DF0` -- the `snap` sender -- reads the same `[gp-0x773C]` count and
refuses to ask for a page unless it says there is something there. That is why
`snap` appears exactly once in this entire project's captures: nothing had ever
told the client a list was non-empty.

---

## 36. `+rnk` cannot work in this build

The leaderboard stayed blank after the rows were pushed, and the reason is not
the row format.

Every `+` push is gated on its channel having a callback registered, at
`conn+0x310` with stride `0x14`:

| channel | offset | verbs |
|---|---|---|
| 0 | `0x310` | `+rom`, `+pop` |
| 1 | `0x324` | `+usr` |
| 2 | `0x338` | **`+rnk`** |

`Lobby_Init` registers exactly four, at `0x002746E4`, `0x00274720`,
`0x0027476C` and `0x002747C4`:

```
channel 0 -> 0x002739F0
channel 1 -> 0x00273530
channel 4 -> 0x00273540
channel 5 -> 0x002735B0
```

**Channel 2 is never registered**, by `Lobby_Init` or anywhere else -- those
four are the only calls to `0x002BA818` in the whole ELF. So `+rnk` reaches
`0x002BCA00`, reads a null callback, and is dropped at `0x002BCA04`. The
handler is complete, the field list is real, and nothing can ever be delivered
through it.

That also explains why `+rom` and `+usr` have worked from the start while
`+rnk` does nothing: rooms are channel 0 and users are channel 1, both
registered.

### So the rows come from `snap`

The FE has nine call sites for the `snap` sender (`0x00276DD0`) and five for its
sibling (`0x00276F20`), all in the `0x002A2xxx` cluster -- one per list, fired
when a screen opens. `snap` is a request, so its reply goes to a request
callback rather than a channel, which sidesteps the unregistered channel
entirely.

Its gate is now satisfied:

```
0x00276DE8  if index < 0 -> return
0x00276DF0  v1 = [gp-0x773C]            ; the ufpvt count
0x00276DF4  if v1 < index -> return
0x00276E08  ...
0x00276E10  a0 = [ctx+0x44]
0x00276E14  if a0 != 1 -> a different path
```

`[ctx+0x44]` is set to 0 by `Lobby_Init` at `0x002747B8` and written in only one
other place outside the snap sender itself: `0x0027359C`, inside
**`0x00273540` -- the channel 4 handler**. So something arriving on channel 4
flips the switch that the snap path tests.

Channel 4 is registered, and no `+` verb in the dispatcher gates on it, so
whatever feeds it is not one of the eight push verbs already known. That is the
next thread.

### Where this leaves the leaderboard

- the count gate is solved (`cusr ufpvt`, section 34)
- the row format is solved (a packed record, section 35)
- the delivery mechanism is **not** `+rnk`, and cannot be
- it is `snap`, and something on channel 4 appears to arm it

`lobbyd` still sends the `+rnk` rows. They cost nothing, they are correct as far
as anyone can tell, and TW05 may well register the channel -- but the log now
says plainly that this client discards them.

---

## 37. `+snp` and the runtime channel

`+rnk` is dead (section 36), but the leaderboard is not: `+snp` reaches the same
place by a different route.

### The channel is a field, not a constant

Every `+` verb so far has had a fixed channel. `+snp` does not:

```
0x002BBE34  [conn+0x508] = GetInt(body, "CHAN")     ; for EVERY inbound frame
...
0x002BCC70  v1 = [conn+0x508]
0x002BCC74  if v1 < 4 -> drop
0x002BCC84  if v1 >= 8 -> drop
0x002BCC8C  table = conn + 0x310
0x002BCC90  entry = table + v1 * 0x14
0x002BCC98  if callback is null -> drop
```

So `+snp` carries `CHAN` and is delivered to that entry of the same channel
table, restricted to **4..7**. `Lobby_Init` registers channel 4, and channel 4's
handler is `0x00273540`:

```
0x0027354C  s0 = [record+0x0C]              ; the list the connection layer built
0x00273564  [ctx+0x40] = 0x002C07D0(s0)     ; how many rows
0x00273560  0x00272390(s0)                  ; <- the leaderboard renderer
0x0027359C  [ctx+0x44] = 0                  ; clear the in-flight flag
```

`0x00272390` is the function from section 34 -- the one that prints "Data
unavailable at this time" when the count is negative. **Channel 4 is the
leaderboard.**

### The row

| tag | into | reader | |
|---|---|---|---|
| `CHAN` | `conn+0x508` | number | 4..7, which channel to deliver on |
| `P` | `row+0x00` | number | |
| `R` | `row+0x04` | number | |
| `N` | `row+0x08`, 32 | string | player name |
| `S` | `row+0x28`, 128 | string | the packed statistics record |

The same shape as `+rnk`, which is presumably why `+rnk` exists at all -- and
why leaving its channel unsubscribed was survivable for EA.

### What the server sends

```
cusr -> b'0 0 0 0 2 0'
+snp -> CHAN=4 R=1 P=2 N=JeddyH2  S=121 bytes marker=0x21 points=2
+snp -> CHAN=4 R=2 P=0 N=JeddyH   S=121 bytes marker=0x21 points=0
```

`R` is the rank, one-based, and `P` the points -- which is what the RANK and
POINTS columns want. DROP% and STREAK come out of the packed record, like
every other statistic.

Channels 5, 6 and 7 are the other three snapshot lists. Channel 5 is registered
(`0x002735B0`); 6 and 7 are not, which suggests two of the four snapshot screens
are as dead as `+rnk`.

---

## 38. The leaderboard: what is established, and what is still guesswork

Two rounds of blind testing have not put a row on screen. Separating the two
kinds of claim, because they are not equally reliable.

### Established, read directly from the ELF

- **The count gate.** `cusr ufpvt` answers with six space-separated integers;
  the fifth reaches `[gp-0x773C]`, and `0x002723D0` prints "Data unavailable at
  this time" when it is negative. Confirmed live -- the message stopped.
- **`+rnk` is unreachable.** It gates on channel 2 and `Lobby_Init` registers
  only 0, 1, 4 and 5. The four calls at `0x002746E4`, `0x00274720`,
  `0x0027476C` and `0x002747C4` are the only calls to `0x002BA818` anywhere.
- **`+snp` takes its channel from a field.** `0x002BBE34` copies `CHAN` into
  `[conn+0x508]` for every inbound frame, and `0x002BCC74`/`0x002BCC84` limit it
  to 4..7.
- **Channel 4 is the leaderboard.** Its handler `0x00273540` calls
  `0x00272390`, the renderer, with the list at `[record+0x0C]`.
- **The row fields**: `P` -> +0x00, `R` -> +0x04, `N` -> +0x08 (32),
  `S` -> +0x28 (128), the same packed record as everywhere else.

### Not established

- **How a snapshot list is closed.** `LIDENT`/`LCOUNT` (`0x002BCF00`) looked
  like the answer, but `0x002B9D68` reads `[conn+0x310]` -- channel **0** --
  so that pair belongs to the rooms list, not to snapshots.
- **Whether a pushed row is retained across a screen change.** The rows are
  sent when `ufpvt` is answered, which is at login, minutes before the
  leaderboard is opened.
- **Whether the screen expects to pull rather than be pushed.** The FE has nine
  call sites for the `snap` sender and none of them has been seen firing, even
  with the count gate satisfied.

### The method that has worked before

Section 11 settled the `+rom` path by trapping the dispatcher on the running
game: the frame reaching its case, the channel gate passing, the callback and
context being non-null, the count arriving at the game layer. Every one of those
was a measurement, not a deduction, and it took one session.

The same three traps would settle this outright:

| address | question |
|---|---|
| `0x002BCC70` | does a `+snp` reach its case, and what `CHAN` does it read? |
| `0x002BCC98` | is the channel-4 callback non-null at that moment? |
| `0x00273540` | does the handler run, and how many rows are in the list? |

If the first misses, the push is not arriving. If the second is null, channel 4
is registered later than assumed. If the third runs with zero rows, the rows are
being accumulated somewhere that is emptied before delivery -- and that is the
one case where the answer is "push them when the screen asks, not at login".

---

## 39. Measured, not deduced: the snapshot channel comes from the REPLY

Three blind attempts failed. One trap settled it in a minute.

### What the live client said

With the game sitting on the STROKE PLAY LEADERBOARD, before touching anything:

```
[gp-0x773C]        = 2            the ufpvt count landed
ctx+0x0C / +0x10   = C0A80158 / 27D8   192.168.1.88:10200
```

The channel table at `conn+0x310`, stride `0x14`, entry = {?, list, callback, ctx, 0}:

| chan | callback |
|---|---|
| 0 | `0x002739F0` |
| 1 | `0x00273530` |
| **2** | **all zero** -- `+rnk` confirmed dead on the running game |
| 3 | all zero |
| 4 | `0x00273540` |
| 5 | `0x002735B0` |

and the two list objects, same layout with the count at `+0x14`:

```
rooms       (chan 0)  cap=100  count=12
leaderboard (chan 4)  cap=100  count=0
```

Twelve rooms had landed and no leaderboard rows had, so the problem was
delivery, not rendering and not list completion.

### The trap

A breakpoint at `0x002BCC70`, the first instruction of the `+snp` case, hit on
the next login with `v1 = 0x2B736E70` -- the frame arrived and matched. And:

```
[conn+0x508] = 0
```

Zero, though the push carried `CHAN=4`. Reading backwards from where that word
is written explains it:

```
0x002BBDF4  if verb != 'snap' -> skip
0x002BBDFC  v0 = [conn+0x50C] - 1        ; outstanding `snap` requests
0x002BBE04  if v0 != 0 -> skip           ; only the last one counts
0x002BBE0C  if the error word != 0 -> skip
0x002BBE20  [conn+0x508] = GetInt(body, "CHAN")
```

**The channel is taken from the reply to a `snap` request, not from the push.**
`CHAN` on a `+snp` frame is ignored entirely. A push sent at any other time is
delivered to channel 0 and thrown away, which is exactly what had been
happening.

### The sequence

1. `cusr ufpvt` -> six integers; the fifth is the row count and ungates both the
   renderer and the `snap` sender
2. the client sends `snap CHAN=n START=s RANGE=r`
3. the server answers `snap` **echoing `CHAN`**, which arms `[conn+0x508]`
4. the server pushes the `+snp` rows, which now land on channel *n*

`lobbyd` does that, and no longer pushes rows from `ufpvt` where they could only
be discarded:

```
snap reply -> CHAN=4 COUNT=2 RANGE=2 MORE=0
+snp       -> R=1 P=2 N=JeddyH2  S=121 bytes
+snp       -> R=2 P=0 N=JeddyH   S=121 bytes
```

### The lesson, again

Section 11 made this point and it held here: three rounds of static reading
produced three wrong answers, and one breakpoint produced the right one. When a
push is silently dropped, trap the case and read the gate rather than reasoning
about which gate it might be.

---

## 40. `snap` fires -- the count was a list index all along

`[gp-0x773C]` is **not** a row count. Trapped at `0x00276DD0` with the
leaderboard open:

```
a0 = 0x0E   the requested INDEX  -- 14
a2 = 0x19   RANGE                -- 25
ra = 0x002A20E8                  the FE call site
```

and the gate two instructions in:

```
0x00276DF4  if [gp-0x773C] < INDEX: return
```

The server had been sending the number of ranked players -- **2** -- so every
request was rejected before it reached the socket. That is why `snap` never
appeared in a single capture in this entire project, and why three rounds of
fixing what happens *after* a `snap` changed nothing: there was never a `snap`.

It is a ceiling on the list index, not a population count. The stroke
leaderboard is list **14**. `lobbyd` now reports `MAX_LIST_INDEX = 64`, which is
generous rather than correct -- the real enumeration is still unknown, but 64
covers every screen without pretending otherwise.

### Two requests per screen

With the gate open the client immediately showed what it actually wants:

```
snap INDEX=14 CHAN=4 NAME=$ START=0 RANGE=25      the visible page
snap INDEX=14 CHAN=5 FIND=JeddyH2 RANGE=1         "and where am I?"
```

`INDEX` names the list, `CHAN` says where to deliver -- and that is why
`Lobby_Init` registers exactly 4 and 5 in that range and nothing else. One
channel for the page, one for the player's own row.

`FIND` is a lookup by name, answered with that player's row and their rank in
the full list rather than in the page.

```
CHAN=4 START=0    -> COUNT=2, +snp R=1 JeddyH2, +snp R=2 JeddyH
CHAN=5 FIND=JeddyH2 -> COUNT=1, +snp R=1 JeddyH2
CHAN=5 FIND=nobody  -> COUNT=0, nothing pushed
```

### The full chain, finally

1. `cusr ufpvt` -> six integers; the fifth must be >= the highest list index
2. the FE sends `snap INDEX=<list> CHAN=<n> START/RANGE`, or `FIND=<name>`
3. the server answers `snap` **echoing CHAN**, which arms `[conn+0x508]`
4. the server pushes `+snp` rows, which land on channel *n*
5. the channel handler renders them -- channel 4's is `0x00273540`, which calls
   the leaderboard renderer `0x00272390` directly

Every step of that was wrong at some point in sections 34 to 39. The one that
mattered was step 1, and it was only findable by trapping the sender and reading
the two numbers it compares.

## 41. The leaderboard columns, and two words of the stat table read wrong

With rows finally on screen, two of the five columns were visibly wrong: DROP%
read `100` for both players, and the loser's STREAK read `0` instead of `L1`.
Both came out of the row renderer, which is small enough to read whole.

### What a row is made of

`0x00272390` loops thirteen visible rows.  Per row it calls the row-level field
getter `0x00273990(row + 0x28, index)` -- the same bit-field extractor as the
resume screen, but reading the record carried in the row rather than the global
one -- and it does so for exactly **six** indices.  A scan of every
`jal 0x00273990` in the image finds no others:

| list | which board | streak | incomplete | completed |
|---|---|---|---|---|
| 14 (`0x0027243C`) | stroke play | 13 | 15 | 19 |
| 13 (`0x0027250C`) | match play | 14 | 16 | 20 |

So 19 and 20 are named, and 17/18 -- long-standing candidates for the W/L
prefix -- are ruled out: the leaderboard never reads them.

### DROP% is derived, not sent

`0x002724A0` onwards, with `0x42C80000` = `100.0f`:

    inc  = field(15)
    done = field(19)
    if inc + done == 0:      drop = 0            ; 0x002724AC
    elif inc >= inc + done:  drop = 100          ; 0x002724BC
    else:                    drop = inc / (inc + done) * 100.0f

`done` had never been sent, so it was 0 for everyone, which takes the
`inc >= inc + done` branch -- **100% dropped, no matter how many rounds you
finished**.  Sending `won + lost + tied` in 19 and 20 fixes it.

### The second descriptor word is a sign flag, not a default

The 16-byte entries at `0x00302440` were read as
`(width, default, mask, signed)`.  Three of the four are used at sites that pin
them down, and the order is different:

| word | use |
|---|---|
| `+0x00` | width -- `0x002737C8` sums widths to find a field's bit offset |
| `+0x04` | **signed** -- `0x00273930`: `if word[1] == 1` and the top bit is set, `0x00273960` floods bits up to 31 |
| `+0x08` | default -- `0x002739B0`, returned when the record has no `'!'` |
| `+0x0C` | invert -- `0x002727A0`, display only: draws `(1 << width) - value` |

Only fields 13 and 14 have `word[1] == 1`, and they are the two streaks.  So a
streak is a signed 8-bit number, and `0x002A1048` reads it exactly that way:

    blez  v0, L                ; <= 0
    ...   "W%d", v0            ; a winning run
    L:    negu a2, v0
          ...   "L%d", a2      ; a losing one, negated

with a preceding `bnez` that prints a bare `0` when the value is zero -- which
is what the loser's row was showing while the server clamped the run at zero.
Send the negative and it draws `L1`.

This also explains the old "default of 1" on fields 13 and 14, which never made
sense as a default: it was the sign flag being read one word early.

## 42. `INDEX` names the list; 32 is Golfer of the Week

The capture shows the front end asking for two different lists with the same
pair of requests each time:

    snap INDEX=32 CHAN=4 START=0 RANGE=25      GOLFER OF THE WEEK
    snap INDEX=32 CHAN=5 FIND=JeddyH2
    snap INDEX=14 CHAN=4 START=0 RANGE=25      STROKE PLAY LEADERBOARD
    snap INDEX=14 CHAN=5 FIND=JeddyH2

`0x00272390` has hard-wired branches for **14** (stroke: fields 13/15/19) and
**13** (match: 14/16/20).  Everything else, 32 included, takes the generic path
at `0x002725E0`, where the column list is read from a runtime table at
`0x003B6DD4`: a `-1`/`0`-terminated array of column descriptors, each run
through `0x00277220` and then `0x00272330` to get a kind, where kind 1 means
"a stat field, by this index" and calls the same `0x00273990`.

That table is filled in when a screen opens, so **reading `0x003B6DD4` while the
STATISTICS screen is up would name every field that screen shows** -- the
cheapest route to the ~45 indices still unmapped, and much cheaper than another
`--probe-stats` pass.

The server had been ignoring `INDEX` and answering every list with the same
all-time board, which is why Golfer of the Week and the leaderboard were
identical.  `lobbyd` now maps it:

| INDEX | board | query |
|---|---|---|
| 14 | stroke play | rooms named `Stroke.*` |
| 13 | match play | rooms named `Match.*` |
| 32 | golfer of the week | any room, results received in the last 7 days |

The week is measured against the time the result ARRIVED, not the `WHEN` the
console reported -- the console's clock is whatever it is set to, and the two
consoles in a match rarely agree.

## 43. Why the rest of the statistics cannot be found by disassembly

Measured live, with the STATISTICS screen open.

### The record arrives intact

The online context is `[gp-0x6714]`, and the packed record sits at `ctx+0x7C`
with its `'!'` at `ctx+0xF4` -- the offsets `0x00276BB0` uses.  Read back out of
a running console and decoded with `twstats.py`:

    1  ONLINE POINTS = 2     15 STROKE INC   = 1
    10 STROKE W      = 1     19 STROKE DONE  = 1
    13 STROKE STREAK = 1     34 LONGEST PUTT = 28
    37 LONGEST DRIVE = 378   39 BEST ROUND   = 72
    41 SCORING AVG   = 72    52 (unset)      = 255

Exactly what `lobbyd` packed.  Field 52 is the table's own default of 255, which
independently confirms that word `+0x08` of a descriptor is the default -- the
reading section 41 changed the codec to.

So the blank lines are not a mapping failure.  Those values are simply never
sent, and most of them are already in the database from the `rank` submissions.

### Only 25 indices appear anywhere in the code

Every call to the five getters -- `0x00276B60`, `0x00276BB0`, `0x00276C20`,
`0x00276AE0` (another player's record, from `ctx+0x2C`, marker at `+0xB0`) and
the row getter `0x00273990` -- with a literal index:

| function | indices |
|---|---|
| `0x00272390`, `0x002728C0` (leaderboard rows) | 13 14 15 16 19 20 |
| `0x00289FA0` (the challenge blob) | 1 6 7 8 9 10 11 12 15 16 |
| `0x002A0620` (resume / statistics lines) | 1 6 7 8 10-16 26-29 32 34 37 38 39 41 50 |

That is 25 of 56, and it adds **38** and **50** to the named set.  The other 31
are never named by an instruction.

### The rest are bound by frontend script

`0x002A2410` is a callback registered into a dispatch table in RAM at
`0x00354E10` (set up at `0x0020FCBC`), and all it does is

    *a1 = get_stat(*(u8 *)a0)

Breaking on it with the screen open: `a0 = 0x0186DD08` holding **6**,
`a1 = 0x0186DD00`, and `ra = 0x001DD4B4` -- the caller is
`0x0020D6C0(widget, ...)` with widget id `0x25C`, reached through the mode byte
at `0x00320944`.  The memory around both arguments is `0x33` heap poison, so
they are a scratch frame, not a table.

**The field index is an operand in the frontend's own data, not in the ELF.**
There is no table to dump: one breakpoint hit names one field, so mapping the
remaining lines that way costs one stop each.

`0x00276CE0` is not a getter either -- it indexes a 36-word array at `ctx+0x104`,
a different namespace from the packed record, and that array is what these
bindings write into.  So a screen line is:

    packed field --0x002A2410--> slot in ctx+0x104 --0x00276CE0--> the line

which means `--probe-stats` remains the cheapest way to map them: it makes every
field hold its own index, so the screen names its own fields in one screenshot.

## 44. The STATISTICS screen, named by itself

`--probe-stats` on ONLINE GAME MODES -> STATISTICS, which makes every field hold
its own index so each line prints the number of the field behind it.

| line | field | | line | field |
|---|---|---|---|---|
| Tiger Status | 6 | | Stroke Rounds Completed | 19 |
| Rank Points | 1 | | Stroke Points | **5** |
| Best Round | 39 | | Stroke Wins / Losses / Ties | 10 / 11 / 12 |
| Average Score | 41 | | Stroke Disconnect | 15 |
| Total Holes In One | 32 | | Stroke Win Streak | 13 |
| Longest Drive / Putt | 37 / 34 | | Match Rounds Completed | 20 |
| Total Eagles | **30** | | Match Points | **4** |
| Holes Per Eagle | **44** | | Match Wins / Losses | 7 / 8 |
| Total Birdies | **31** | | Match Disconnect | 16 |
| Birdie Average | **45** | | Match Win Streak | 14 |
| Total Fairways Hit | **36** | | | |
| Driving Accuracy % | **46** | | | |
| Total GIR | **33** | | | |
| GIR Percentage | **42** | | | |
| Putts Per Hole | **43** | | | |

Twelve new, and four confirmations that were until now only inferred: 19 and 20
really are the completed counts, 15 and 16 really are the drop counters (the
screen calls them "Disconnect"), and 13/14 are the streaks -- drawn as "W13" and
"W14", the W coming from the sign as section 41 said.

### Field 5 is not earnings

5 had been recorded as TOTAL EARNINGS from a MY RESUME probe.  That could not
have been right: 5 is not among the indices `0x002A0620` reads.  The STATISTICS
screen names it plainly as **Stroke Points**, with **Match Points** in 4 beside
the single **Rank Points** in 1.  So points are kept three ways.

### The client does no arithmetic

Every ratio is a stored field, and the server has to work it out:

| line | drew | meaning |
|---|---|---|
| GIR PERCENTAGE | `42%` | whole percent |
| DRIVING ACCURACY % | `46` | whole percent |
| BIRDIE AVERAGE | `45` | a whole number |
| PUTTS PER HOLE | `0.43` | **hundredths** |

Only 43 is fixed point.  Their widths agree: 42, 45 and 46 are seven bits, which
holds a percentage and little else, and 43 is ten, which holds 10.23 putts a
hole.

`lobbyd` now fills all of them from the `rank` submissions already in the
database, each guarded by its own denominator.  There is no "Match Ties" line on
the screen even though field 9 is read by the challenge blob, so match play may
not record one.

## 45. Online Tournaments -- `OnlineTourn.c`

The mode is **asynchronous**, not real-time.  Nothing in it goes near the
`chal` / `+ses` / peer path that stroke play uses: every call is a `cusr`
command to the master server, and there is no room, no peer address and no
session token.  The debug strings name the whole API:

| `CMD` | arguments | function |
|---|---|---|
| `esr2t` | `PERS` | `_GetStartPermissionFromServer` -- may I start today's round? |
| `mg5ri` | `START`, `NUM` | `Tourn_GetNDaysTourneyInfoFromServer` -- the calendar |
| `mg5ri` | `START=-1 NUM=1` | `Tourn_GetTodaysTourneyInfoFromServer` |
| `qdb@w` | `START`, `NUM` | `Tourn_GetNDaysTourneyResultsFromServer` -- daily leaderboards |
| `lts5d` | -- | `Tourn_GetTodaysDateFromServer` (already answered) |
| `5d0tr` | `DATA` | `Tourn_ReportRoundResults` |

So the shape of a tournament is: ask permission, play the round alone, post the
score, and the server keeps a leaderboard per day.  "Tournament already started."
and "Tournament server has failed" are the two refusals.

### The reply body is hex, not a TagField

`0x002DDCC0` parses the info list and `0x002DDEA0` the results list, and neither
touches the TagField codec.  `0x002DDBD0(dst, nbytes, src)` reads `nbytes * 2`
ASCII hex characters through the tables at `0x00304480` (high nibble) and
`0x00304580` (low nibble) -- either case -- and stops at any character below
`'0'`.  The list is:

    XX                 entry count, one byte
      XX               name length, one byte
      <name>           that many LITERAL characters, not hex
      32 hex chars     16 bytes of tournament data

An entry is 48 bytes: the name at `+0x00`, zero-filled to 32, and the 16 bytes at
`+0x20`.  `0x002DECE0` allocates `0x13B0` for the info list and `0x120C` for the
results, both attributed to `OnlineTourn.c`.

`lobbyd` has been answering `mg5ri` with the TagField `COUNT=0`, which the hex
reader chews into a count of 0xC0 -- 192 entries, more than the array holds --
so the parser bails and the screen has nothing to open.  **The meaning of the
16 bytes is still unknown**, and the cheapest way to get it is the trick that
worked for the statistics screen: send an entry whose 16 bytes are `00` to `0F`
and read the positions off the calendar and the round-details screen.

### Reporting a score is signed

`5d0tr` is the one message in this protocol that is not plaintext.
`0x002DF6F0` derives a 16-byte key from `[gp-0x6520]` -- seeded at `0x0036D3E0`
and from two values at `0x003EEACC` -- and runs a 0x200-byte result blob through
`0x002C44A0` / `0x002C4570` before sending it as `DATA`.  Accepting scores means
working that out first; reading the calendar does not.

### 45.1 Answering the lists

`twtourney.py` is the codec and `lobbyd` now answers both commands with a
raw body instead of a TagField, the same way `ufpvt` does:

    mg5ri START=0 NUM=7   -> 020CPebble Beach000102...   a real list
    mg5ri START=-1 NUM=1  -> the same, one entry
    (no --probe-tourney)  -> "00", a valid empty list

An empty list is the two characters `00`.  That matters: the old `COUNT=0`
decoded to 192 entries and was thrown away, so the client could not tell "no
tournaments" from "the server is broken".

One reply is one frame, so `TOURNEY_PAGE` caps a page at 32 entries -- a probe
entry costs 41 characters, which keeps a reply near 1300, well inside the 0x800
buffer the request side of this exchange is built in.  The client's array holds
105, so that cap can be raised once it is known the client copes.

### 45.2 `START` is a date

Measured, not guessed.  Showing September 2026 the calendar asked for

    mg5ri START=46266 NUM=30
    qdb@w START=46266 NUM=30

and 46266 days after **1899-12-30** is 2026-09-01 -- the OLE/Excel serial day.
No other epoch lands on the 1st, and `NUM=30` is exactly that month's length.
So the calendar asks for one month by day number; it is not paging through rows,
and `START=-1 NUM=1` is the separate "today" call.

`--probe-tourney` therefore hunts for the date field rather than labelling
offsets.  Entry `k` is the day `start + k`, written as a 32-bit little-endian
number at byte offset `k`, with every other byte zero, and named `OFF00` to
`OFF12`.  Whichever day the calendar lights up names the offset: the fifth of
the month means `+0x04`.  A 32-bit write also satisfies a 16-bit reader at the
same offset -- the low half sits first and a day number stays under 65536 until
2079 -- so one pass finds the offset whatever the width.

### 45.3 The day is a u16 at data offset 12

Read out of the running client rather than guessed.  With the calendar open,
`[gp-0x6554]` held the parsed array and `[gp-0x6550]` the count:

    INFO_ARRAY   = 0x01A59AC0    INFO_COUNT   = 30
    RESULT_ARRAY = 0x01A5AE80    RESULT_COUNT = 0

and the array itself:

    01a59ac0  50 52 4f 42 45 34 36 32  36 36 00 ...   |PROBE46266......|
    01a59ae0  00 01 02 03 04 05 06 07  08 09 0a 0b 0c 0d 0e 0f

So the info format is right: name at `+0x00`, the 16 data bytes at `+0x20`,
stride 48, all 30 entries accepted.  **The results list refused the same body**
-- see 45.4.

A read watchpoint on those 16 bytes then landed in `0x002DEFF8`, which is "give
me the tournament on day N":

    0x002DF038  v1 = INFO_ARRAY
    0x002DF03C  if day < *(u16 *)(v1 + 0x2C):            return 0   ; first
    0x002DF060  if *(u16 *)(v1 + count*0x30 - 4) < day:  return 0   ; last
    0x002DF088  for each entry: if *(u16 *)(e + 0x2C) == day: return e

`+0x2C` is data byte 12, read with `lhu`.  So **the day is a 16-bit little-endian
number at data offset 12**, and because the first and last entries are
range-checked before the scan, **the list must be sorted ascending by day** or
everything outside that span is unreachable.

That is also why the first probe changed nothing on screen: its data bytes were
`00 01 02 ...`, so every entry claimed day 0x0B0C, and no September cell matched.

### 45.4 The two lists are different widths

`0x002DDCC0` (info) reads 0x10 data bytes and strides 0x30.  `0x002DDEA0`
(results) reads **0x0C** and strides **0x2C** -- same shape, narrower entry,
and `0x120C / 0x2C` is the same 105 entries.

Sending 16-byte entries to the results list desynchronises it: the four extra
bytes are read as the next entry's name length and name.  That is exactly what
the live client showed -- 30 entries accepted on the info list and 0 on the
results list, from one and the same body.  `lobbyd` now sends each list at its
own width.

The results list's own day offset has not been found yet; it cannot be 12,
because only bytes 0 to 11 exist there.

### 45.5 The entry, named by the screen

TODAY'S EVENT, read with every data byte holding its own offset:

| line | drew | field |
|---|---|---|
| PURSE | `$50,462,976` | **u32 at 0** -- 0x03020100 is exactly that |
| DATE | `9/19/2026` | the u16 day at 12 |
| COURSE | `TORREY PINES` | **u8 at 14** -- index 14 of the course table |

Three confirmations at once, including the course table, which until now had
only ever had one entry verified.

HOLES, TEES, ROUGH, FAIRWAYS and GREENS also drew values, but every probe byte
was non-zero, so nothing said which byte fed which line.  `probe_bytes` sets one
byte at a time instead, and puts the varied entries on days **after today**: a
past day opens EVENT RESULTS, which draws none of those lines, and only today's
event can be entered at all.

### 45.6 The password is a flag in the entry, not a server check

With the unknown bytes all non-zero the client demanded a password; with them
all zero it did not, and `esr2t` never reached the server in either case.  So
one of bytes 4..11 or 15 marks an event "invitation only", and the prompt is
raised before anything is asked of the server.

The password itself is still checked server side once typed: `0x002DE440`
appends `PASS` from the 32-byte buffer at `0x003EEB50` (empty until the player
types), and the client has messages for a whole table of error codes at
`0x003029C0`, stored little-endian so they read backwards in the image:

| 4CC | message | | 4CC | message |
|---|---|---|---|---|
| `miss` | Required field missing | | `hack` | Attempted password hacking |
| `auth` | Authorization error | | `rsrc` | Resource is invalid |
| `user` | User is invalid | | `netw` | Network problem |
| `pass` | Password is invalid | | `bsod` | Internal error |

These are EA's own codes and the client has real text for every one, which our
invented `badp` / `nusr` / `dupl` do not have.  Worth switching the login
failures over to `pass`, `user` and `miss` once it can be seen on screen.

### 45.7 `esr2t` hands out the anti-cheat key

`_TourneyStartCallback` (`0x002DE160`) on a successful reply:

    0x002DE18C  memset([gp-0x6520], 0, 0x10)
    0x002DE1AC  TKEY -> [gp-0x6520], 16 bytes, BINARY ('$' + hex, 0x002BF7F0)
    0x002DE1CC  DATA -> a string, up to 0x400
    0x002DE1F4  0x002DDCC0(DATA, 0x003EEAA0)      <- the same list parser
    0x002DE1FC  if it returned 0: "The server is temporarily unavailable."

So **`DATA` is a one-entry tournament list in the hex format** -- the buffer it
lands in is a single 0x30 entry -- and `TKEY` is binary, not a number.  The old
`TKEY=0 DATA=` reply failed both tests, which is exactly the warning the client
drew.

`[gp-0x6520]` is the same 16 bytes `0x002DF6F0` derives the `5d0tr` result
blob's key from.  So the server issues the key that signs the score it will
later be sent.  `lobbyd` keeps it per persona so that it can be checked once
that blob is understood.

### 45.8 `5d0tr` is not encrypted -- correcting section 45

Section 45 said the round report was "the one message in this protocol that is
not plaintext", encrypted with a 16-byte key.  That was wrong, and it was wrong
because it was read off the disassembly alone: `0x002DF6F0` derives 16 bytes and
runs a 0x200 buffer through `0x002C44A0` / `0x002C4570`, which looks like a
cipher until you see the output.  The first real round settled it -- `DATA` is
plain little-endian struct data.  Those calls serialise; they do not encrypt.

    +0x00   23 x u32, the round -- the SAME field order as a `rank` result
    +0x5C   the 16-byte TKEY the server issued from `esr2t`, echoed back
    +0x6C   the event's own data[12:16]: day u16, course u8, byte 15
    +0x70   '$' + 12 hex characters, NUL padded -- unidentified

The first captured round, from an 18-hole event at Torrey Pines:

    RANK=1 DONE=1 QUIT=0 TYPE=0 SCORE=0 CLUB=0 STROKES=67 PUTTS=25 HOLES=18
    EAGS=0 BIRD=8 ACES=0 GIR=14 LPUT=22 DRVS=14 FRWY=10 LDRV=377 SHTC=0
    PARS=8 SBOG=1 DBOG=1 TBOG=0 COMP=18

The field order is not assumed -- two identities fix it, and both hold exactly:

    EAGS + BIRD + PARS + SBOG + DBOG + TBOG  ==  HOLES      8+8+1+1 = 18
    72 - BIRD + SBOG + 2*DBOG + 3*TBOG       ==  STROKES    72-8+1+2 = 67

**So the anti-cheat is an echo, not a signature.**  A report is authentic if the
key inside it is the key this server handed that player when it let them start,
which also ties the score to one event on one day.  `lobbyd` checks that, checks
the scorecard adds up, and stores the round in a `tourney` table keyed on
(persona, day).

### 45.9 The reply is shown to the player

`_RoundResultsCallback` (`0x002DE390`) passes the reply BODY straight to
`0x0028B880`, the message box -- which is why the first attempt drew

    Report Results
    OK
    CMD=5d0tr

on screen: the client was faithfully displaying our TagField.  The reply is a
line of text for a person to read, not a structure.  It now says

    Your round of 67 is recorded.
    You are 1st of 1.

On an error the same callback formats the error text instead, so a refusal is
visible to the player too.

### 45.10 A real calendar

Confirmed end to end on 2026-09-19:

    14:16:27  esr2t JeddyH2 starts 'BYTE04' on 2026-09-19, key 5bdb01c2...
    14:27:19  JeddyH2 scored 72 over 18 holes on 2026-09-19 -- 1st of 1

with the client drawing "Your round of 72 is recorded.  You are 1st of 1."

`lobbyd` now serves a real event a day rather than only serving one under
`--probe-tourney`.  Course, purse and name are pure functions of the day, so
the month the calendar draws and the single event `esr2t` hands out cannot
disagree -- if they did, a player would start one event and be scored in
another.

Courses 21 ("NA"), 23 ("Random 18") and the six compilations are left out of
the rotation: a daily leaderboard only means anything if every entrant plays the
same known layout.

`qdb@w` still answers with the empty list "00".  Its entries are 12 bytes and
that layout is not worked out yet, so there is nothing honest to put in them.

### 45.11 The results list: the day is at offset 4, and a day holds many

`0x002DF0D0(day, *count)` is the results equivalent of `0x002DEFF8`, and it
differs in two ways that matter:

    0x002DF0EC  if day < *(u16 *)(first + 0x24):        return 0
    0x002DF118  if *(u16 *)(last + 0x2C - 8) < day:     return 0
    0x002DF140  for each entry: if *(u16 *)(e + 0x24) == day: keep the FIRST
    0x002DF170  *count = how many matched

`+0x24` is data offset **4**, not 12 -- the two lists do not even agree on where
the day lives.  And it counts the matches instead of stopping at one, so **a day
holds many entries, one per player**.  That is the daily leaderboard, and the
entry name is a player's name rather than an event's.

`0x002DFFA0` reads a u32 at entry+0x20 (data offset 0).  EVENT RESULTS has four
lines fed from this list -- WINNER, WINNER SCORE, YOUR FINISH, YOUR SCORE -- and
`probe_results` names the bytes behind them the same way the calendar probe did:
the day where the lookup expects it, bytes 0..3 left holding 50462976, and bytes
6..11 holding 6..11.

### 45.12 The results entry, named by the screen

EVENT RESULTS with every byte holding its own offset:

    WINNER:        WINNER17
    WINNER SCORE:  6
    YOUR SCORE:    7
    YOUR FINISH:   185207049th Place

| offset | width | field |
|---|---|---|
| 0..3 | u32 | read by `0x002DFFA0`, drawn nowhere on this dialog |
| 4..5 | u16 | the day, as `0x002DF0EC` looks it up |
| 6 | u8 | the winner's score |
| 7 | u8 | the viewer's score |
| 8..11 | u32 | the viewer's finish, **zero-based** |

The finish is the giveaway: bytes 8..11 are `08 09 0A 0B`, which is 185207048,
and the screen drew 185207049.  The client adds one, so a stored 0 is 1st.

And note what an entry IS.  The name is the WINNER while the scores and the
finish are the VIEWER's, so an entry is not "a player's round" but "a day, from
one player's point of view" -- which is how one entry fills all four lines.  It
has to be built per request rather than per player, and `lobbyd` does.

Days the player did not enter are left out entirely.  With no entry the dialog
draws "Not available" on all four lines, which is the truth; sending a row with
a zero finish would draw "1st Place" instead.

### 45.13 `ufpvt`'s six numbers, all named

The DAILY LEADERBOARDS screen drew an empty table and **sent nothing at all** --
no `snap`, no `cusr`, nothing.  A screen that does not ask has already decided,
and what it decided comes from `ufpvt`.

`0x002DE7C0` hands sscanf its six destinations in EE argument order, and the
readers say what each is for:

| # | lands in | meaning |
|---|---|---|
| 1 | `[gp-0x6542]` short | the FIRST day of the season |
| 2 | `[gp-0x6540]` short | the LAST day |
| 3 | `[gp-0x7748]` int | the daily leaderboards' base list index |
| 4 | `[gp-0x7744]` int | the weekly money leaders' base index |
| 5 | `[gp-0x7740]` int | the highest list index that exists |
| 6 | `[gp-0x6538]` int | a bitmask of optional features |

    0x002DEEC0  "is day D in season?"   ->  S1 <= D <= S2
    0x002DEEF0  a day's daily index     ->  from N1 and D - S1
    0x002DEF30  a day's weekly index    ->  the same, divided by SEVEN
                                            (the 0x92492493 multiply at
                                             0x002DEF64 -- that is what makes
                                             it *weekly* money leaders)

Only the fifth had ever been filled in.  With the first two at zero every day
failed `D <= S2`, so the screen had already concluded today was out of season
before it considered asking anything.

So a daily leaderboard is a LIST, like the stroke board, and its index is
COMPUTED from the date rather than fixed.  That is also why the ceiling matters
so much: it has to clear every index the arithmetic can produce.

`lobbyd` now sends a season of +/- 90 days, daily indices from 64, weekly from
300, and a ceiling of 400 -- checked so the two ranges cannot overlap, cannot
collide with the built-in lists (13, 14, 32) and all sit under the ceiling.

The sixth number stays zero.  Each known bit turns on an extra block the client
then expects the server to understand: bit 2 adds a section to the `5d0tr`
report (`0x002DF7C4`), bit 1 to another message (`0x002DFDAC`), bit 3 answers a
capability query (`0x002DEEB0`).  Everything works with them off.

### 45.14 `lts5d` is a DAY NUMBER, and it gated everything

The season was in place -- read live, `[gp-0x7748..]` held 64, 300, 400, 400 and
the two shorts held 46194 and 46374, exactly as sent -- and DAILY LEADERBOARDS
still sent nothing.  So the gate was somewhere else, and it was two bytes away.

`0x00277220(screen)` maps a screen to a `snap` INDEX:

| screen | index |
|---|---|
| 0x13, 0x14 | the match and stroke boards |
| 0x26 | 32, golfer of the week |
| 0x27, 0x28 | 30 and 31 |
| 0x32 | 31 |
| **0x33** | **weekly** -- `0x002DEF30(current day)` |
| **0x34, 0x36** | **daily** -- `0x002DEEF0(current day)` |

and both of those take the current day from `0x002DEFA0`, which is a plain
`lhu [gp-0x6544]`.

`[gp-0x6544]` read **0** on the running client.  It is written in exactly one
place -- `_TodaysDateCallback`, `0x002DE2E0`, the callback for `lts5d`:

    0x002DE308  atoi(body)
    0x002DE310  [gp-0x6544] = that, as a short
    0x002DE320  0x00265640 splits it into year / month / day

So `lts5d` is not "today's date" in any printable sense.  **It is a raw day
number, read by atoi straight off the reply body**, and it is how the client
learns what day it is at all.  The reply had been the TagField

    OK
    CMD=lts5d
    DATA=20260919

and `atoi("OK\n...")` is zero.  With the day at zero, `0x002DEEF0` and
`0x002DEF30` both bail on `day <= 0`, the index resolves to -1, and the screen
never asks the server anything -- which is exactly the silence in the log.

The reply is now the body `46284` and nothing else.

This one had been wrong since the day `lts5d` was first answered.  It looked
right because the client never complained: it simply believed it was day zero.

### 45.15 The computed index has to land on a list that exists

With the day set, the screen asked exactly what the arithmetic predicted:

    15:29:42  snap INDEX=154 (daily, 2026-09-19) CHAN=4 START=0 RANGE=25 -> 1 row

and the client then jumped to an unmapped page.  The backtrace put the return
address at `0x002C0914`:

    0x002C08F8  v1 = [s2+0x24]          ; a container's comparison callback
    0x002C0908  a2 = [v0]
    0x002C090C  jalr v1                 ; v1 = 0x05A45700

So the list object behind index 154 was never configured -- its sort callback
was uninitialised memory -- and pushing a row into it jumped through the
garbage.

The arithmetic is not the problem: the CLIENT computed 154 and asked for it.
The problem is that the season's length IS the number of indices the client will
invent, and those have to land on lists it actually has.  Every index ever seen
on the wire is between 13 and 35, so +/-90 days put the request 120 past the end
of whatever table backs them.

The season is now +/-7 days, which puts the daily lists at 36..50 and the weekly
at 52..54 -- above every index the client uses for itself, and under the ceiling
of 64 that was in place when every screen that works today started working.

Worth stating plainly: a large season is not a harmless setting.  It is the
server choosing how many list slots the client will address, and there is no
message in which the client says how many it has.

### 45.16 Lists have descriptors, and 36 is not a free choice

`0x00272290(index)` resolves a list to an 8-byte descriptor, and it settles two
things at once:

    if index < 0:            return 0
    if index < 0x24:         return 0x003027C0 + index*8   ; 36 BUILT-IN lists
    if index < [gp-0x7744]:  return gp-0x7758              ; the DAILY one
    if index < [gp-0x7740]:  return gp-0x7750              ; the WEEKLY one

So **the daily base has to be exactly 36**: the built-in table is 36 entries and
the daily range starts where it ends.  It is not a value the server picks -- it
is a boundary compiled into the client, and `ufpvt`'s third number only says
where daily stops and weekly starts.

A descriptor is `{ u8 field; u32 type; }`:

| list | field | type |
|---|---|---|
| 13 match board | 4 | 1 |
| 14 stroke board | 5 | 1 |
| 32 golfer of the week | 38 | 1 |
| 33, 35 | 0 | **2** |
| daily (`gp-0x7758`, read live) | 54 | **2** |
| weekly (`gp-0x7750`, read live) | 51 | **2** |

and the type decides what `S` -- the 128 bytes at row+0x28 -- actually is:

* **type 1**: a PACKED RECORD.  `0x002727C4` pulls stat field `field` out of it.
* **type 2**: a STRING.  `0x00272788` draws it verbatim with `%s`.

Sending the packed statistics record to a type 2 list puts 128 bytes of 0x80
and up straight on screen, which drew a row of boxes with the player's name
somewhere in the middle of it.

`lobbyd` now sends text for those lists -- the course for a daily row, the
number of rounds for a weekly one -- and keeps the packed record for 13, 14
and 32.

### 45.17 What belongs in the one free column

Both boards have RANK, PLAYER NAME and a single string column, and the weekly
one labels it **EARNINGS** -- so it is money, not a description.

*Daily* now carries the score, written the way a golfer says it: `-5`, `E`,
`+4`.  Par is not assumed to be 72 -- the rotation runs over twenty courses and
they are not all par 72 -- it is derived from the scorecard using the identity
from section 45.8:

    STROKES = par - BIRD - 2*EAGS - 3*ACES + SBOG + 2*DBOG + 3*TBOG

so `par = STROKES + BIRD + 2*EAGS + 3*ACES - SBOG - 2*DBOG - 3*TBOG`.  On the
captured round that gives exactly 72, and the round reads -5.

*Weekly* carries a share of each day's purse by where the player finished that
day, using the PGA Tour's own top-ten percentages and tapering past tenth so a
large field does not fall off a cliff.  It has to be worked out a day at a time:
a placing only means anything inside its own event, and the purse differs from
day to day.  The self-test holds it to two rules -- a better finish never pays
less, and the field is never paid more than the purse.

    RANK 1  JeddyH2   -5           RANK 1  JeddyH2   $360,000
    RANK 2  JeddyH    +4           RANK 2  JeddyH    $218,000

### 45.18 Golfers of the Week and Tournament Winners

Lists **33** and **35**, both `field 0, type 2` in the built-in table -- so both
take a string in `S`, the same as the daily and weekly boards.  They were still
being sent the packed record, and drew the same row of boxes.

They have one more wrinkle.  `0x002726C0` checks the list index before it
formats the first column:

    v0 = listindex - 0x21
    if v0 < 2:            -> the date path      ; 33 and 34
    if listindex == 0x23: -> the date path      ; 35
    else:                 -> '%d' of row+0x04

and the date path reads **row+0x00 as a u16 day** and draws it `%d/%d/%02d`.
That is the WEEK column.  So a row on these lists carries a DAY in `R`, not a
rank -- which is why the first column is a date on both screens.

`lobbyd` serves 33 as one row per week (the top earner, with their money) and 35
as one row per event (the winner, with their score to par):

    2026-09-19  JeddyH2  $360,000        golfers of the week
    2026-09-19  JeddyH2  -5              tournament winners

Which of 33 and 35 is which was NOT established -- the screens are tabbed
through in either order and both were requested several times in a row.  If they
are the wrong way round, `LIST_WEEK_GOLFERS` and `LIST_TOURNEY_WINNERS` are two
constants to swap and nothing else changes.

### 45.19 Those two lists count their days from 2003 -- and in `P`

Two corrections to 45.18, both measured off the screen.

**The date comes from `P`, not `R`.**  It is `row+0x00` the renderer reads
(`0x002726F0`, `lhu`), and `P` is the tag that lands there -- `R` is at
`row+0x04`.  Section 45.18 assumed the opposite and put the day in `R`, where
nothing read it.

**The zero is 1 January 2003, not 1899-12-30.**  `0x00272360` builds that date's
day number with `0x00265570(&out, 1, 1, 0x7D3)` and `0x002726FC` adds it to the
row's halfword before splitting.  So these rows carry **days since 2003**, and
the two epochs are 37622 apart.

Both fell out of one screenshot.  Two rows went out carrying 72 and 1 in that
field -- a stroke count and a round count, sent there by mistake -- and the
screen drew 3/14/03 and 1/2/03:

    72 + 37622 = 37694 = 2003-03-14
     1 + 37622 = 37623 = 2003-01-02

which fixes both the field and the epoch at once, from values that were never
meant to be dates at all.

**And the two lists were the wrong way round.**  33 is TOURNAMENT WINNERS and 35
is GOLFERS OF THE WEEK, the opposite of the guess in 45.18 -- the headings on
screen named them.

### 45.20 The date field is 13 bits -- these lists stop in 2025

Sending the real day drew **2025-06-05**, which is 8191 days past the epoch --
`0x1FFF` exactly.  The value saturates at thirteen bits.

The client's own splitter is not the limit.  `0x00265640` reads the halfword as
days since **1900-01-01** and re-bases anything past 36525 onto the year 2000:

    0x0026566C  s3 = *(u16 *)a0
    0x00265670  if s3 < 0x8EAD:  year = 0x76C (1900)
    0x0026567C  else: s3 -= 0x8EAD; year = 0x7D0 (2000)

so it would have drawn 2026 quite happily.  Something upstream clips the row to
13 bits before it gets there.

TW04 shipped in 2003 and 8191 days from its epoch runs out in mid-2025, so this
reads as a deliberate compact field rather than an accident.  Either way it is a
hard ceiling: **lists 33, 34 and 35 cannot draw a date after 2025-06-05**,
whatever the server sends.  `to_list_day` clamps there so the limit is explicit
rather than surprising.

Note also that the game uses TWO date epochs.  The calendar's day is counted
from 1899-12-30 -- verified twice, by the cell that lit up and by the date on
the event screen -- while `0x00265640` counts from 1900-01-01.  It does not
matter here because these lists carry days since 2003, which is the same number
in either frame, but it is a trap for anything that mixes the two.

### 45.21 The clamp is four instructions, and a pnach can move it

Section 45.20 said "something upstream clips the row".  It is the generic
`+snp` / `+rnk` row reader, right after it stores `P` at row+0x00:

    0x002BCAE8  lw    v1, (s2)          ; the value it just stored
    0x002BCAEC  slti  v1, v1, 0x2000    ; under 8192?
    0x002BCAF0  bnel  v1, zero, +4      ; yes -> leave it alone
    0x002BCAF8  addiu v0, zero, 0x1FFF
    0x002BCAFC  sw    v0, (s2)          ; no  -> clamp to 8191

An explicit `if (row[0] >= 0x2000) row[0] = 0x1FFF;`.  It is not a bitfield and
not a side effect -- someone wrote it.

Raising the two immediates moves the ceiling from 2025-06-05 to 2092-09-16:

    patch=1,EE,002BCAEC,word,28637FFF    // slti  $v1, $v1, 0x7FFF
    patch=1,EE,002BCAF8,word,24027FFE    // addiu $v0, $zero, 0x7FFE

Both were re-encoded and checked against the words in the ELF, and each differs
from the original in the immediate only -- the opcode and register fields are
untouched, so the instructions do the same thing with a bigger number.

`make_pnach.py --date-clamp` enables them; without the flag they are
written commented out, so the generated file documents the option without
turning it on.  The clamp still runs either way, which is the point: this raises
a limit rather than removing a check.

Why not simply NOP the store?  Because `P` is the same word on every list, not
just these three, and 8191 may mean something to a screen not looked at yet.
Moving a ceiling nobody can reach is a smaller claim than deleting a check.

### 45.22 The date patch is not optional

The ceiling of 2025-06-05 is in the past.  Every console this will ever run on
has a clock set later than that, so without the patch those two columns read
6/5/25 for everyone.  That is a broken screen, not a preference, and it was
wrong to ship it as a question -- first commented out, then as a prompt.

It is now simply one of the patches, beside the lobby address and the DNAS
bypass.  There is no flag and no prompt, and `make_pnach.build()` has no
parameter for it.  The full set is:

| what | where |
|---|---|
| lobby IP, two copies | `0x0030FAC0`, `0x00311040` |
| DNAS check | `0x002E1468` |
| leaderboard date ceiling | `0x002BCAEC`, `0x002BCAF8` |

A patch is either needed to make the game work or it does not belong in the
file.  This one is needed.

### 45.23 The server was clamping too

With the game patched, the column still read 6/5/25 -- because `to_list_day`
had its own clamp at 0x1FFF, added in 45.20 to stop the server sending a value
the client would mangle.  Once the client's ceiling moved, that workaround was
the only thing still enforcing the old limit.

It now follows the patched ceiling (0x7FFE, 2092-09-16).  An unpatched client is
unaffected: it clamps anything larger itself, exactly as it always did, and
reads 2025-06-05.  So sending the real day is right either way -- correct on a
patched console, no worse than before on one without.

That was not the whole story, though -- see 45.24.

### 45.24 There are TWO clamps, and the first patch hit the wrong one

After the pnach and the server change, the column still read 6/5/25, with
`P=8662` plainly on the wire and the patched words plainly in memory:

    0x002BCAEC  28637FFF        the patch, live
    0x002BCAF8  24027FFE

Searching the image for every `addiu rX, $zero, 0x1FFF` found three, and two of
them are this same clamp:

| at | in the handler that reads | message |
|---|---|---|
| `0x002BCAEC` | `A`, `N`, `S` | `+rnk` |
| `0x002BCD44` | `P`, `N`, `S` | `+snp` |

(The third, `0x002BB498`, is a loop bound and nothing to do with rows.)

The two are the same five instructions with the same registers, so they look
identical in isolation -- but the leaderboards are fed by `+snp`, and the one
first patched was `+rnk`.  The giveaway is four instructions later:
`lw $v0, 0x508($s3)` is `[conn+0x508]`, the snapshot channel, which only the
`+snp` path touches.

Both are in the patch set now.  Every replacement still differs from the shipped
word in the immediate only.

The lesson is about how it was found rather than what it was: a clamp was
located, patched, and confirmed live in memory, and the conclusion drawn was
"the patch works, so the problem is elsewhere".  The right question was whether
the clamp that was patched is the clamp on this path, and one grep for the
constant would have answered it before any of the rest.

## 46. A generated calendar, a month at a time

The events were a formula -- course `day % 22`, purse from the day number --
which worked but repeated visibly and gave every month the same shape.  They
are now generated and stored.

**A month is generated the first time anything asks for a day in it.**  There is
no scheduler: this server has no clock tick to fire at midnight on the 31st, and
a month nobody has looked at does not need to exist.  The first request for
October makes October, once, and everything after it is served from the
database.

    CREATE TABLE events (day PRIMARY KEY, name, course, purse, created)

**Stored rather than recomputed, because results point at it.**  A round
recorded at Torrey Pines has to stay a round at Torrey Pines even if the
generator changes afterwards, and the weekly money board pays a share of the
purse the player was shown when they entered -- so `week_earnings` reads that
purse out of the event rather than deriving it again.

**Seeded from the month itself**, not from the clock.  Persistence alone would
be enough day to day, but if the database were lost every past event would come
back different and the rounds already recorded against them would describe a
course nobody played.  Seeding this way means a regenerated month is the same
month.

Courses are drawn from a shuffled pool that refills when empty, so a month reads
like a tour rather than a shuffle that lands on Pebble Beach three times in a
week.  Purses are round numbers between $500,000 and $5,000,000.

`INSERT OR IGNORE` on a whole month in one transaction, so generation can never
rewrite a day somebody has already played, and `month_generated` can decide from
a count.

The invariant worth keeping: **the calendar and `esr2t` must name the same
event**, or a player starts one tournament and is scored in another.  Both now
read the same stored row, and the self-test walks six months day by day
comparing them.

### 46.1 The clock is the server's, not the console's

Generating on demand was wrong, and for a reason worth writing down: **`START`
on a `mg5ri` is whatever the console's clock says**, and a console's clock
belongs to the player.  On-demand generation let anyone wind their PS2 forward
and mint next year's calendar, then enter those events.

Generation is now a server decision on the server's clock:

* `ensure_season()` makes the current month and `--months` past it (default 1).
* `calendar_tick()` re-runs it every `--calendar-tick` seconds (default 300),
  so a server left running through midnight on the 31st has the new month
  before anyone can ask.  It also runs once at startup.
* Requests are **read only**.  A month outside the horizon has no events and
  the calendar draws empty cells, whatever date the console asks about.

Measured against a wound-forward clock:

    2026-09  this month             -> 30 events
    2026-10  next month             -> 31 events
    2026-11  beyond the horizon     ->  0 events
    2030-01  a wound-forward clock  ->  0 events

### 46.2 A round is filed against the day the key was issued

The same question applied to results, and there the hole was already open:
`5d0tr` carries a day and a course, and both were being taken at face value --
`DB.add_tourney(who, day, course, ...)` straight out of the report.  The
mismatch with the day the server issued the key for was logged and then
ignored.

Both now come from the server: the day from the `esr2t` that issued the key,
the course from the event generated for that day.  A report claiming a date 400
days out and course 99 is recorded against today, on today's real course, and
the attempt is logged:

    *** JeddyH2 scored 68 over 18 holes on 2026-09-19 -- 1st of 1
    !!! JeddyH2 started 2026-09-19 but reported 2027-10-24 -- recorded
        against the day it started

The key was already the thing tying a score to an event (section 45.8).  This
just stops reading the parts of the report the key already establishes.

### 46.3 The site shows the tournament data too

`/tournaments`, linked from both the front page and a signed-in profile:

* **Schedule** -- the next fortnight from the stored calendar, today's row
  highlighted, rolling across the month boundary as the events are generated.
* **Money list** -- the season, by earnings, with events, wins and best finish.
* **Recent winners** -- who won each event, their score and their number to par.

and a **Tournaments** card on the profile with each persona's earnings, events,
wins, best finish and last played.

The money is the same function the console sees.  `week_earnings` in `lobbyd`
and the site's money list both call `DB.tourney_standings(first, last, payout)`
with `twtourney.payout`, so a figure on the web page and the figure on WEEKLY
MONEY LEADERS cannot drift apart -- which they would have, written twice.

One bug the end-to-end check caught that a unit test would not: `DB.personas()`
returns names, not rows, and the profile was passing `p['name']` over a list of
strings.  Calling the page function directly with a list of names passed
happily; only signing in over HTTP and fetching `/account` hit it.

### 46.4 A round records its own event

Adding the event name and course to the site turned up a real problem rather
than a display question.  The calendar is generated; a round played before the
`events` table existed has no event attached, so labelling it from the calendar
would name it with whatever event that day happens to be **now**.  The round
played on 2026-09-19 was the Wallaby Creek Open; regenerate the month and that
day is the Royal Birkdale Open.  The course stored on the round is right, the
name would be fiction.

So `tourney` gained an `event` column, filled at report time from the event the
server issued the key for, with a migration for existing rows.  Reads report
`named`, which is False when the name had to come from the calendar, and the
site prints **unrecorded** rather than a name it cannot stand behind.  The
COURSE is always the round's own, because that is what was actually played.

The site now shows, on `/tournaments`, date / event / course / winner / score /
to par, and on a profile a Rounds table of date / persona / event / course /
score / to par / finish.

Older rounds read like this, which is the honest rendering:

    19 Sep 2026 | Royal Birkdale Open | Royal Birkdale | 70 | -2 | 1st of 1
    18 Sep 2026 | unrecorded          | Torrey Pines   | 73 | +1 | 1st of 1

### 46.5 `P` is the sort key, and the client sorts DESCENDING

The daily board drew rank 2 above rank 1.  The rows went out in the right
order with the right ranks --

    R=1 P=64  Tiger        (-8)
    R=2 P=72  JeddyH2      (E)

-- and the client drew JeddyH2 first.  It does not keep the order rows arrive
in; it sorts them, by the row's first word, **largest first**.  That is the
comparison callback from section 45.15, the one whose uninitialised pointer
caused the crash.

`R` is only the number printed in the RANK column.  **`P` decides the order.**

That works by accident on the boards where bigger is better -- points on the
stroke board, the date on lists 33 and 35 so the newest is on top -- and fails
on exactly one thing: a stroke count, where the lowest round wins.  So the
daily board now sends `SORT_BASE - strokes` and the weekly board sends the
money, neither of which is drawn anywhere; they exist purely to be ordered by.

The self-test now sorts each board's pushed rows by `P` descending and checks
that reproduces the rank order, so a board cannot be given a key that runs the
wrong way again without saying so.

## 47. The room ids are fixed, and there are five

A sixth room was being pushed and never appeared on GAME LOBBIES.  The client
has the prefixes compiled in, as a pointer table at `0x00303820`:

    Stroke.T.  Stroke.I.  Stroke.G.  Stroke.E.  Stroke.R.
    Match.T.   Match.I.   Match.G.   Match.E.   Match.R.

Five per type, and **no `C`** -- so `Match.C.*` and `Stroke.C.*` were always
going to be ignored, whatever they were called.  The letters spell TIGER, which
is why the sixth was there in the first place: the original list was generated
from the string `'TIGERC'`, and the C had nothing behind it.

More rooms cannot be added from the server side.  The set is the set.

`Match.T.East1` and `Stroke.T.East1` are also in the image, at `0x00311080` --
EA's own defaults.  So **East is their name for the T room**, and the numbering
suggests they ran more than one of each.

The five are now East, West, Beginner, Advanced and Open, on T, I, G, E and R.

Nothing about `R` connects it to Quick Play: it is an ordinary room, and it sits
in the same table as the other four.  Whatever Quick Play does, it is not this.

## 48. A security pass over both servers

### 48.1 A losing player could rewrite the match

`matches()` deduplicated on the session token and kept the **newest** row.  Both
consoles report the same match, so two rows are normal -- but nothing stopped a
third, later, with better numbers.  Demonstrated: a player reports 80 against
70, loses, reports again with 60, and the leaderboard has them winning.

It now takes the **earliest** row per token (`MIN(id) GROUP BY auth`), so the
first report of a match is the one that stands.

### 48.2 Anyone could report anyone's match

`on_rank` stored whatever arrived, and identified the reporter from `REPT` --
a field the console fills in.  A signed-in player holding any session token
could file a result for two other people, and one for a token this server never
issued was stored anyway.

Now the persona **this socket authenticated as** must be one of the two in the
session, and a result for an unknown token is dropped rather than kept.  Same
rule as the tournament fix: if the server issued it, do not read it back from
the client.

### 48.3 Smaller things

* The session cookie had `HttpOnly` and `SameSite` but not **`Secure`**, so one
  `http://` link would have put a live token on the wire in clear.  On by
  default now; `--no-secure-cookie` for testing without TLS.
* `CREATED` grew without limit -- a client could make rooms in a loop until the
  server ran out of memory.  Capped at 64, oldest dropped first.
* Behind a proxy every request appeared to come from 127.0.0.1, so the login
  throttle was one bucket for the whole internet.  `--trust-proxy` reads
  `X-Forwarded-For`; it is off by default because the header is forged
  trivially by anyone who can reach the port directly.

### 48.4 Looked at and found sound

* Every SQL statement is parameterised.  Three build SQL with `%`, and all
  three interpolate only hard-coded column names, never user input.
* POST routes other than register and login check a CSRF token with
  `compare_digest`.
* Passwords are PBKDF2-SHA256, 200k rounds, per-account salt, and never logged.
* Frames over 64 KiB are refused before allocation (`0x10000` at the reader).
* Session tokens are `secrets.token_urlsafe(24)`; a new one is minted at login,
  so a fixed cookie cannot be made to survive it.

## 49. Not every entry in the course table is a course

**Skillz (index 7) was in the tournament rotation.**  It is the
skills-challenge venue, not a golf course, and it does not work online.  The
rotation was built as "everything except NA, Random 18 and the compilations",
which was a guess about what the remaining entries were.

The exclusions are now named individually, with a reason each:

    7   Skillz          not a golf course
    21  NA              a placeholder
    23  Random 18       a different layout for every player
    24-29 Compilations  ditto

22 (Tiger's Dream 18) stays: it is a fixed eighteen holes like any other.

### Fixing a calendar already written

Months are generated once and kept, so correcting the list does not correct a
calendar that already exists -- September had Skillz on the 4th and the 26th
and October on the 8th, all already in the database.

`repair_calendar()` runs after `ensure_season()` and replaces **only the
offending days, and only from today onward**:

    !!! rescheduled 2026-09-26: Skillz was not playable, now Pebble Beach
    !!! rescheduled 2026-10-08: Skillz was not playable, now Sahalee CC

Regenerating the month would have been one line, and would have rewritten every
other day in it -- days people have already seen on the calendar, and days with
results pointing at them by name.  A past day is left alone even when it is
wrong: it is a record of what happened, and nobody can play it again.

The replacement is seeded from the day alone, so repairing twice is a no-op,
and the self-test walks two years of generated calendars checking that nothing
unplayable appears in any of them.

## 50. Byte 15 is the calendar icon

Every day on the calendar draws a heart.  Looking back at the one-byte-at-a-time
probe, the single day drawn with something else -- a top hat -- was the
`BYTE15=1` day; every other day carried 0 there and had the heart.  So **byte 15
of a calendar entry chooses the icon**, and everything so far has been sending
0.

`make_entry` takes an `icon` now, defaulting to 0, and `--probe-icons` gives
every day of the month a different number with a name to match:

    Icon 0, Icon 1, Icon 2 ... one per day, byte 15 = 0..30

One screenshot of the calendar then shows what each number draws and where the
numbers run out -- which is the part that cannot be worked out from the image,
because the art is frontend data rather than code.

(Adding the field broke `probe_days`, which builds its entries with every byte
holding its own offset and hands them to `make_entry` -- which now overwrote
byte 15 with the default.  The same thing happened when purse and course were
added.  Any field `make_entry` owns has to be passed back in by a probe that
wants to control it.)

### 50.1 What the icons are

Read off the calendar with `--probe-icons`, one number a day through September.
Confidence varies and the table says so:

     0  red heart                12  half-shaded circle
     1  stars-and-stripes hat    13  half-shaded circle
     2  plain golf ball          14  reddish ball
     3  plain golf ball          15  plain ball
     4  gold star                16  face or statue?
     5  plain ball               17  small yellow thing
     6  grey hat?                18  not seen, under ACTIVE
     7  pink, unclear            19  green shamrock
     8  snowflake                20  Santa
     9  yellow burst             21  blue gem
    10  plain ball               22  jack-o'-lantern
    11  plain ball               23  yellow devil face
    24  firework burst           25  red and yellow bird?
    26  cake                     27  dog?
    28  green tree               29  green-white-red flag

Eight dates now get one, and take their name from the day:

    01-01  New Year's        24  firework burst
    02-14  Valentine's        0  heart
    03-17  St Patrick's      19  shamrock
    05-05  Cinco de Mayo     29  (?) flag
    07-04  Independence Day   1  stars-and-stripes hat
    10-31  Halloween         22  jack-o'-lantern
    12-24  Christmas Eve     28  (?) green tree
    12-25  Christmas         20  Santa

Every other day is a golf ball (2), not the heart -- the heart was only ever
showing because 0 was the default for a byte nobody had identified.

The name becomes "Christmas at Pebble Beach" where that fits in the 32-byte
field and just "St Patrick's" where it does not; the client truncates silently,
so a long course name would otherwise read "St Patrick's at Kapalua Plantati".

The two marked (?) are guesses at meaning rather than at appearance, and are
the first to check if a day draws something odd.  Several icons are still
unidentified, and nothing uses them.

### 50.2 An event for every icon

Sixteen invented events now use the icons the real holidays do not.  They are
kept in the same table, `SPECIAL_DAYS`, but the comment separates them, because
the two are not the same kind of thing:

* the holidays are dates the art was plainly drawn for, and the only
  uncertainty is reading a small image;
* the invented ones exist so the icons get used at all.  **Nothing in the game
  says these dates mean anything** -- the icon suggested the event, not the
  other way round -- so they are free to move or rename.

    01-15  Winter Open            snowflake
    02-22  Founders Cup           a face or a statue
    03-01  Red Ball Challenge     a reddish ball
    03-26  Anniversary Classic    cake
    04-08  Eclipse Invitational   half-shaded circle
    04-22  Birdie Bonanza         a bird of some kind
    05-02  Derby Day              a hat
    06-02  Diamond Jubilee        blue gem
    06-20  All-Star Invitational  gold star
    06-21  Midsummer Shootout     yellow burst
    08-05  Sunrise Open           small and yellow
    08-15  Dog Days Open          a dog
    09-10  Half Moon Classic      the other half-shaded circle
    10-01  Pink Ribbon Classic    pink, whatever it is
    10-30  Devil's Night          yellow devil face
    11-11  Wildcard Open          never seen -- it was under ACTIVE

24 special days a year, 24 distinct icons, and the self-test refuses two days
sharing one or any of them taking the everyday golf ball.

Five icons are still unused -- 3, 5, 10, 11 and 15 -- because they are plain
golf balls like the default and would say nothing on a calendar.

## 51. IPv6: the console cannot, the server now can

**No console will ever speak IPv6 to this server.**  Two things in the game
settle it, and neither is reachable from the server side:

* the lobby address is a **15-character field** in the ELF (`0x0030FAC0` and
  `0x00311040`) parsed with `%d.%d.%d.%d` at `0x00310FD0` -- a dotted quad, and
  not even a hostname;
* the peer address for the UDP leg travels in `+ses ADDR` the same way, so two
  players cannot be introduced to each other except as IPv4.

Widening the field would mean rewriting the game's parser, its socket calls and
the PS2's own IPv4-only stack.  That is not a patch.

### What is worth doing anyway

Something in front of a console can speak IPv6 -- a relay, a tunnel, a host
doing 464XLAT for an emulator on an IPv6-only network -- and those arrive on
the server over v6 while the console still thinks it dialled IPv4.  So the
listener takes both:

    lobbyd.py --host ::        one socket, IPV6_V6ONLY off, both families

### Two things that had to be fixed for it

* `client_address` is a **4-tuple** on an IPv6 socket -- host, port, flowinfo,
  scope -- and `'%s:%d' % self.client_address` raised inside `setup()`, killing
  every connection before it did anything.  Found by opening one.
* An IPv4 peer on a dual-stack socket reports as `::ffff:192.0.2.1`.  That was
  being stored as the peer's reachable address and handed to the other console,
  which would have parsed it with `%d.%d.%d.%d` and got nonsense.  `dotted_quad`
  unwraps the mapped form and returns None for a genuine IPv6 address, which is
  logged plainly rather than sent:

      !!! JeddyH2 is connected over IPv6 (2001:db8::1); the game has no way to
          express that, so peer-to-peer will need --peer-addr or an IPv4 path

So: an IPv6-connected player can use the lobby, the leaderboards, the
tournaments and everything else the server answers.  What they cannot do is be
introduced to another player for a match, because the introduction itself is a
dotted quad.

## 52. The web site, rebuilt

A golf palette -- fairway green, a gold accent, tabular figures -- with a fixed
header and the same navigation on every page, so the site reads as one thing
rather than three forms.

**Front page** leads with today's event, because it is the only thing here that
changes daily: the name, course, purse and date, and the three leading scores
under it.  Then the account forms, then a short "playing online" card that
answers the question someone arriving actually has.

**Leaderboard** and **Tournaments** use the same scorecard table: right-aligned
tabular numbers, the leader in gold, a score under par in green and over in red.

**Server stats** sits on the foot of EVERY page, not just one:

    Accounts  Golfers  Active this week  Matches  Tournament rounds
    Events scheduled  Holes played

    Best round 64 - Longest drive 341 yd - Longest putt 28 ft - 12 eagles
    - Most played Pinehurst No. 2 (3) - Online since 19 Sep 2026

Deliberately a handful of figures and one line of records rather than a report:
the point is that a visitor can see the place is alive and being played on, and
two dozen numbers would hide that rather than show it.  `DB.stats()` is one
pass over small tables, and `stats_board()` swallows any exception -- a status
board must never be the thing that breaks a page.

Three things the rendered page showed that the markup did not:

* the gold "today" marker was an inset shadow on every `td`, so it drew a bar
  between every column instead of one down the left edge;
* `tourney` totals were missing from the stats -- a server that had only ever
  played tournaments reported no eagles and no holes at all;
* a 21-course pool over a 30-day month reuses nine courses, and with the name
  suffix keyed off `day % 7` the repeats came back identically named.  The
  suffix now comes from the month's own generator and is checked against the
  names already used, so no month repeats an event name.

## 53. Par belongs to the course, not to the scorecard

Three players finished the same event at Emerald Dragon and the daily
leaderboard came back in this order:

    1  JeddyH       74   -3
    2  MrKitty      77   +4
    3  TigerWoods   78   +3

Sorted correctly by strokes, and reading as nonsense: +3 is a better round than
+4 and it is underneath it.  The order was never wrong.  The to-par column was.

Section 45.8 took this for an identity, having checked it against exactly one
round:

    STROKES = par - BIRD - 2*EAGS + SBOG + 2*DBOG + 3*TBOG

so `par_of` rearranged it and worked out each card's par from the card itself.
Six real rounds later:

    course          strokes  triples   implied par
    Penguin Falls      63       0          72
    Emerald Dragon     63       0          73
    Emerald Dragon     77       1          73
    Emerald Dragon     78       1          75
    Emerald Dragon     74       2          77

Same course, four different pars, and the error grows with the number of
triple-bogey holes.  That is what **TBOG counting "triple bogey or worse"**
looks like from the outside: a quadruple adds one to TBOG and four to STROKES,
and the formula hands three of them back.  A card with a blow-up hole on it
therefore over-states par, and never under-states it.

Two consequences, both now in `twtourney`:

* `card_par(fields)` is an **upper bound** on the course's par, not a
  measurement.  It refuses a card with an ace on it -- the model scores an ace
  -2 and one on a par 4 is -3, the only way the bound can err low -- and
  refuses anything outside `PAR_RANGE`, which is how the 77 above is thrown
  away rather than allowed to vote.
* The smallest bound a course has ever produced is the best estimate of its
  par.  `twdb.note_par` keeps that running minimum in a `course_par` table and
  `tourney.par` caches each card's bound, so `course_pars()` is one GROUP BY.
  Nothing has to be hardcoded and the figure only ever improves.

`to_par(fields, par)` now takes the course's par and every row on a board is
scored against the same one, which is what makes the column agree with the
order it was sorted into.  Learnt from the rounds above: Penguin Falls 72,
Emerald Dragon 73.  Both are consistent with DRVS=14 -- fourteen holes that
are not par 3s -- and 4x3 + 9x4 + 5x5 is 73.

`round_is_consistent` was wrong in the same family: **ACES is its own hole
class**, not a kind of eagle.  A card with a hole-in-one summed to 17 of 18 and
was rejected with "that scorecard does not add up" -- a real round thrown away
by the check meant to catch fake ones.  Section 45.8's hole identity should
read

    ACES + EAGS + BIRD + PARS + SBOG + DBOG + TBOG == HOLES

## 54. The live picture: lobbyd publishes, the web site reads

`lobbyd` knows who is online -- `ONLINE`, `WHERE`, `SESSIONS` -- and `webui` is
a different process that can see none of it.  They share one thing, the sqlite
file, so that is where the picture goes:

    presence   persona, room, state, detail, since, seen
    playing    auth, room, host, guest, kind, course, started
    activity   at, kind, who, text          -- a rolling feed, trimmed to 400
    live       key, value, at               -- heartbeat, started, peak_online

Three decisions worth keeping:

* **Written whole, not incrementally.**  `publish_live()` recomputes the lot
  from the globals and runs after anything that could have changed them.
  Incremental updates have to be right at a dozen call sites and are wrong the
  moment one is missed.
* **A row is only as true as its timestamp.**  A server that is killed cannot
  tidy up after itself, so readers age presence out after
  `twdb.DB.PRESENCE_STALE` (150 s) and a `heartbeat` thread refreshes it every
  30 s -- separate from `keepalive`, which `--ping 0` switches off.  Startup
  clears the table outright, because nobody is connected yet.
* **Nothing in there may raise.**  A web site that cannot be updated is
  cosmetic; a lobby connection that dies because of it is not.  Both
  `publish_live` and `note` swallow everything and log.

The site gained `/live` (who is on, what is being played, what just happened,
meta-refreshing every 20 s), `/live.json` for anyone who would rather poll, a
one-line status strip under the nav on **every** page -- the question a visitor
arrives with is "can I play right now?" and it should not take a click -- and
`Online now` / `Most at once` in the server stats.

`tests/lobbyd_livetest.py` is the end-to-end check: it starts a real server,
signs two consoles in, joins them to rooms, and reads the picture back through
`twdb` and `webui.live_strip` exactly as the site does.  It waits on the table
rather than on the reply, because the server answers the console first and
writes the picture afterwards -- which is the right way round.

## 55. Why --strong-dnas hung on PLEASE WAIT

The no-DNAS patch stubbed the driver at `0x002E1430` with "set the pass byte,
return", on the theory that a check which reports success cannot block.  It
blocked: the game sat on AUTHENTICATING DNAS DATA / PLEASE WAIT for ever.

The screen is not waiting to be told the answer.  It is waiting to be told
there IS one.  Two one-line accessors, next door to each other:

    0x002E1590  jr $ra ; lbu $v0, -0x650e($gp)      DNAS_IsDone()
    0x002E15A0  jr $ra ; lbu $v0, -0x650d($gp)      DNAS_Passed()

and the UI polls the first.  `-0x650e` is set to 1 by the three-instruction
function at `0x002E1580`, which the real module calls on its way out:

    0x002E1580  addiu $v1, $zero, 1
    0x002E1584  jr    $ra
    0x002E1588  sb    $v1, -0x650e($gp)     ; delay slot

With the driver stubbed, `0x002E11A0` never runs, nothing ever calls
`0x002E1580`, and IsDone stays 0 for the life of the process.  The stub was
answering a question nobody had got round to asking.

What named the bytes was the init function's own preamble -- `0x002E11A8`
onwards clears four of them in a row, `-0x650e`, `-0x6510`, `-0x650d`,
`-0x650f`, which is what a "reset my state" block looks like.  `-0x650f` is
"needs init" (tested at `0x002E1438`) and `-0x6510` is "a run is in progress"
(tested at `0x002E1450`, cleared at `0x002E1568`).

The stub now writes both bytes, with the values their own setters use:

    addiu $v1, $zero, 1
    sb    $v1, -0x650e($gp)      ; done,   as 0x002E1588 writes it
    sb    $v1, -0x650d($gp)      ; passed, as 0x002E1484 writes it
    jr    $ra
    nop

Five words, and safe: every branch inside the driver targets `0x002E1450` or
later, so nothing jumps into what they replace.

It stays opt-in.  The module's own success path also calls
`0x00294A00(0xBA)` at `0x002E1474` before setting the pass byte, and this does
not; `0x00294B30` is the four-argument error-dialog call next to it
(`'Unknown DNAS Error Occurred'` at `0x003168B0`), so `0x00294A00` is most
likely its dismiss/notify counterpart.  If it turns out to matter the symptom
would be a dialog that never closes although the game has moved on -- in which
case the default patch, which leaves the module running, is still right.

Worth separating the two problems: the default patch is SLOW on Linux because
the module really does try to reach `gate1.us.dnas.playstation.org` and pays a
full DNS timeout.  Pointing PCSX2's DEV9 DNS1 at a real resolver instead of
Auto fixes that without touching the patch at all, and is the first thing to
try.

## 56. --strong-dnas, second attempt, and why the download was withdrawn

Setting both bytes (section 55) did not fix it either: the game still stops on
AUTHENTICATING DNAS DATA.  Mapping the callers settled what the shape of the
problem is, without settling the cause.

`0x00277E00` is the per-frame ONLINE pump, and `gp-0x66fc` is the online state
bitmask it dispatches on:

    0x00277E0C  if !(state & 0x04):  return           <-- nothing runs at all
    0x00277E18  DNAS driver          0x002E1430
    0x00277E20  online state machine 0x00288FB0
    0x00277E2C  if state & 0x20:     0x00277B10
    0x00277E48  if state & 0x40:     the lobby stack (0x2B6580, 0x27A150,
                                     0x274490, 0x285E00, 0x28BB30, 0x2DEE60)

`0x00288FB0` is the state machine, stepped by `gp-0x6674`, and `0x00294A00(id)`
sets the status line -- 0xCC, 0xCD, 0xCE are its successive steps and 0xBA is
the one the driver itself uses on success.  The DNAS step is at `0x00289148`:

    0x00289148  0x00294A00(0xCE)        ; "authenticating"
    0x00289150  0x002E1360              ; DNAS_Begin -- sets -0x650f = 1
    0x00289158  0x00277E00              ; pump once
    0x00289160  0x002E15A0              ; DNAS_Passed()
    0x00289168  bnez -> 0x00289190      ; passed: 0x294A00(0xBA), step = 1,
                                        ; state |= 0x200
                (else)                  ; failed: step = 6, error

So the advance really does hinge on the pass byte, and the stub really does set
it -- which means the game is not reaching `0x00289148` at all, and the hang is
in an earlier step that the module's absence breaks.  `0x001E7C80` is the
blocking wait the module runs inside:

    0x001E7CA0  if !0x00137FF0():  break      <-- the ONLY way out
    0x001E7CB8  if DNAS_IsDone():  0x0012BE90 ; and loop ROUND AGAIN
                else:              0x00277F50 ; draw, 0x0012EA20 yield, loop

Note that being "done" does not leave that loop; only `0x00137FF0` going false
does.  It is reached from `0x002E11A0` (`0x002E1234`), which the stub skips --
so it is not itself the hang, but it shows the module is not a thing you can
politely decline.  Deciding this properly needs a breakpoint on `0x00277E00`
and a read of `gp-0x66fc` and `gp-0x6674` on a console that is actually stuck.

Withdrawn from the web site meanwhile.  `--strong-dnas` stays in
`make_pnach.py` for whoever picks it up with a debugger, and `?dnas=skip` is
ignored rather than removed so an old link still returns a patch that works.

The slowness it was meant to solve is not the patch's fault anyway: the module
resolves `gate1.us.dnas.playstation.org`, and on Linux that is a full DNS
timeout.  Pointing PCSX2's DEV9 DNS1 at a real resolver instead of Auto is the
fix, and the site says so where the reader will be looking.

## 57. EA Messenger: the second server, read off the ELF

Static reading only, 2026-09-23.  **Nothing below has been on the wire yet** --
every capture in this project shows `buddy server address requested ->
'(none configured)'`, so the client has never once dialled it.

### It is live code with a whole front end behind it

Unlike the 0x00284xxx room cluster (section 9), this module runs.  The online
pump calls `0x00285E00` every frame (section 56's list), and `FEND.PS2` carries
the screens: `ONLINE_BuddyList`, `ONLINE_BuddyManage`, `ONLINE_BlockedManage`,
a per-buddy menu -- ONLINE PROFILE, CHALLENGE, SEND MESSAGE, REMOVE FROM BUDDY
LIST, VIEW RESUME, BLOCK, REPORT ABUSE -- a user search ("User Found" -> Add to
List / Send a Message / Block), "No Buddies", "the maximum of 25 buddies has
been reached", and the columns "User Name" / "Product".

### What makes the client connect

`0x00285E00` edge-detects the online flags at `gp-0x66fc` against last frame's
copy at `gp-0x668c`:

| edge | set by | calls |
|---|---|---|
| `0x2000` rises | `_AuthCallback`, `0x0028776C` -- lobby login succeeded | `0x00286410`, create the buddy client |
| `0x10000000` and `0x80000000` both up | `_NewsCallback` `0x002874A0` (a `host:port` came back) and `_PersCallback` `0x00287C80` | `0x002861F0`, connect |
| `0x2000` falls | logout | `0x00286350`, destroy |

Then `0x002C3A50`, the buddy update, runs every frame while the client exists.

So **`lobbyd --buddy-addr HOST:PORT` is already the whole switch**: answer
`news NAME=0` with a line containing a colon, and a console that finishes
`pers` will dial it.  Send the port every time -- the non-LKEY path returns
early at `0x00286268` when the port string is empty.

The address goes through a lookup object (`0x002C5E68`, 1000 ms) that the
update loop polls and prints as `connecting to %08x:%d`, rather than through the
lobby's `%d.%d.%d.%d` parser -- so a hostname probably works here where it
cannot for the lobby.  Unconfirmed.

### Same framing as the lobby

The buddy sender `0x002C2350` calls `0x002B9478`, the lobby's own frame writer:
12-byte big-endian header, TagField body, TCP.  Everything `tagfield.py` and
`lobbyd`'s reader already do applies unchanged.  User ids are XMPP-shaped --
`0x002C23C8` splits `user@domain/resource` at `@` and `/` -- but the protocol
is not XMPP.

### Login: `AUTH`, keyed by the lobby's `LKEY`

`_PersCallback` (`0x00287BB0`) copies `LKEY` out of the `pers` reply into the
lobby context at `+0x2B0` (64 bytes).  `0x00277460` hands that to the connect
call `0x002C2B60`, which builds, at `ctx+0x394`:

    AUTH  PROD=tiger-ps2-2004  VERS=...  PRES=...
          USER=/cso/tiger-ps2-2004  LKEY=<the lobby's LKEY>

Resource is the literal `/cso/tiger-ps2-2004` (`0x00311370`).  If the key
string contains a `:` the connect call instead splits `name:secret`: `USER` becomes
`name` + resource, and the secret goes out as `LKEY` when it starts with `$`,
`PASS` otherwise.  The lobby path never produces a colon, so **the server has to
identify the player from `LKEY` alone**.

`lobbyd` currently sends `LKEY=lkey-<persona>`.  That is fine as a placeholder
and wrong for a real Messenger server: anyone could claim any persona by
typing the pattern.  It should be a random token minted at `pers` and looked
up at `AUTH`.

Reply: `AUTH` with ident `0` is success; a non-zero ident is taken as a
failure and the client disconnects (`0x002C3D70` -> `0x002C2DC8`).

### Requests (client -> server)

| verb | built in | fields |
|---|---|---|
| `AUTH` | `0x002C2B60` | `PROD VERS PRES USER LKEY` (or `PASS`) |
| `PSET` | `0x002C2824` | `STAT PROD` -- set my presence |
| `RGET` | `0x002C2F08` | `LRSC LIST=B PRES=Y ID`, and again with `LIST=I` -- fetch buddy list and block list |
| `RADD` | `0x002C30B0` | `LRSC ID LIST=B PRES=Y USER GROUP` (add buddy) or `LIST=I USER` (block); plus `PADD USER` |
| `RDEL` | `0x002C3470` | the same shapes to remove; plus `PDEL USER` |
| `SEND` | `0x002C3950` | `BODY SUBJ` (and a recipient) -- a message |
| `PING` | -- | the client echoes a server `PING` straight back (`0x002C3D30`) |
| `DISC` | `0x002C2DC8` | goodbye |

`LIST=B` / `LIST=I` are the buddy list and the ignore (block) list.
`MSG` and `CHL` (`0x00311388`, next to the `Buddy.c` label) are almost
certainly the two `SUBJ` kinds -- a chat line and a challenge -- which is how
CHALLENGE on the buddy menu would reach someone who is not in your room.

### Replies and pushes (server -> client), dispatched in `0x002C3A50`

| verb | reads | meaning |
|---|---|---|
| `AUTH` | ident | login result |
| `RGET` | `ID`, `SIZE` | a list is coming, `SIZE` entries (`ID=2` is the one it counts down) |
| `ROST` | `ID USER GROUP` | one list entry; `ID=1` buddies, `ID=2` blocked |
| `PGET` | `USER SHOW PROD STAT` | a presence change, parsed by `0x002C2548` |
| `RECV` | `USER BODY SUBJ ...` | an incoming message, `0x002C2410` |
| `SEND` | ident | a message was accepted |
| `RADD` | `ID FUSR` | someone added you |
| `RDEL` | `ID` | a removal |
| `ADMN` | -- | an admin notice |
| `PING` | -- | keepalive, echoed |

`SHOW` is a word, looked up in the table at `0x00303DA0`: `DISC CHAT AWAY XA
DND PASS`, index 0-5.  `PROD` present sets bit `0x2000` on the entry ("in a
game").  `STAT` is itself a TagField: `P=<n>` plus one key per language (`en=`
etc.), and the client picks the text for its own language into a 20-byte slot.

### What a server would need

A roster table (owner, buddy, list B/I), a way to push `PGET` when a persona
logs in or out of the lobby -- which `lobbyd` already knows about -- and
message routing for `SEND` -> `RECV`.  It can live inside `lobbyd` on a
second port, sharing `ONLINE` and the database, rather than as a separate
process.

### Errors, and what success leads to

The game's Messenger callback `0x00285430` reads nothing from a successful
`AUTH` reply -- it goes straight to `RGET` (`0x00285504`).  A non-zero ident is
looked up in the client's own table at `0x003029C0`, stored little-endian, so
on the wire they are ordinary 4CCs:

    miss  Required field missing      rsrc  Resource is invalid
    auth  Authorization error         netw  Network problem
    user  User is invalid             bsod  Internal error
    pass  Password is invalid         (anything else) Unknown error
    hack  Attempted password hacking

The same callback has the connection-level texts: 'Unable to resolve hostname',
'Unable to connect to server', 'Timeout connecting to server', 'The server has
disconnected'.  The first of those is a second hint that the address really is
looked up by name.

`PING` is only ever server-initiated: the client bounces every inbound `PING`
back at `0x002C3D10` and never originates one, so a server must not answer a
`PING` it receives -- that is an echo, and replying would loop.

### The capture stub (2026-09-23)

`lobbyd --buddy-port N` runs a second listener (`BuddyHandler`) with the same
framing, logging its frames as `<B=` / `=B>` so they cannot be mistaken for the
lobby's.  It:

* mints a random 32-hex `LKEY` per `pers` (replacing `lkey-<persona>`), and
  forgets it when that lobby connection closes;
* hands out `<address the console reached the lobby on>:N` for `news NAME=0`,
  unless `--buddy-addr` says otherwise;
* accepts `AUTH` only with a live issued key -- `auth` for an unknown or
  expired one, `miss` for none -- and logs loudly if `PASS` turns up instead;
* answers `RGET` with `ID=<same> SIZE=0`, and every other verb with an empty
  success;
* sends `PING` on the lobby's `--ping` schedule.

`tests/lobbyd_buddytest.py` covers all of that against a real server.

### The first capture (2026-09-23): the reading holds

One console, one Messenger session, no surprises in the shape of anything:

    <B= AUTH  PROD=tiger-ps2-2004 VERS=1.0 PRES=tiger-ps2-2004
              USER=/cso/tiger-ps2-2004 LKEY=<the key pers issued>
    <B= RGET  LRSC=cso LIST=B PRES=Y ID=1
    <B= RGET  LRSC=cso LIST=I PRES=Y ID=2
    <B= PSET  SHOW=CHAT
              STAT="en=\"Tiger Woods 2004\"\nP=tig4\n"
              PROD="JeddyH is online"
    <B= RADD  LRSC=cso ID=101 LIST=B PRES=Y USER=jed2 GROUP=

Corrections and additions:

* **`PROD` is the status line, `STAT` the product.**  `PROD` carries the
  "%s is online" text built at `0x002862F0`; `STAT` is a TagField of the
  product name per language plus `P=tig4`.  The earlier table had them the
  other way round in spirit.
* **Find User is a LOBBY request**, `user PERS=jed2`, not a Messenger one --
  and the plain `OK PERS=jed2` the lobby already sends is enough for "User
  Found".
* The `RADD` `ID` is a request number the client picks (101, 102...), not a
  list number.  The list is `LIST`.
* The client added jed2 to its screen before any reply -- which is why the bare
  stub reply "worked".  Without the `ID` echoed the entry stays flagged pending
  (bit `0x10000`) and the `addu` event never fires.

### The reply shapes, now implemented

Read off the dispatcher and built into `BuddyHandler`:

| request | reply | notes |
|---|---|---|
| `RGET ID LIST` | `RGET ID SIZE`, then `SIZE` x `ROST ID USER GROUP` | `ROST ID` names the list: 1 flags the entry a buddy (`4`), 2 blocked (`0x200`), and only list 2 counts `SIZE` down to "roster complete" (`0x002C3EC4`) |
| (after `RGET` with `PRES=Y`) | `PGET USER SHOW STAT PROD` per online buddy | must come AFTER the `ROST`s -- a `PGET` for someone not on the roster is dropped (`0x002C4074`) |
| `RADD ID LIST USER GROUP` | `RADD ID FUSR` | `ID` clears the pending entry (`0x002C421C`); `FUSR` renames it to the canonical name.  Non-zero ident: the entry is removed and the error shown |
| `RDEL ID LIST USER` | `RDEL ID` | matched against the one pending delete (`0x002C4384`) |
| `PSET SHOW STAT PROD` | empty | relayed verbatim as `PGET` to everyone with you on list B |
| `SEND TYPE USER BODY` | empty, or an error ident | `SUBJ` must be ABSENT (`0x002C39DC` returns -3 if present) and `BODY` under 64.  The recipient gets `RECV TYPE USER=<sender> BODY`, read by `0x002856C0`.  `BODY` is encoded by the sender (`0x002C1D70`) and decoded by the recipient (`0x002C1E18`), so the server relays it untouched.  A non-zero ident on the reply raises the sender's dialog 6 (`0x00285CF0`) |

A player who has blocked you reads as `SHOW=DISC` to you, and your messages to
them are refused.  Offline is `SHOW=DISC` with nothing else, index 0 of the
`SHOW` table.  Lists live in the `buddies` table (`twdb`), keyed by persona id
so dropping a persona takes it off every list; the server caps each list at the
client's own 25.

`tests/lobbyd_buddytest.py` walks all of it with two fake consoles.

### Second capture: two consoles, still on the stub

Run against the stub rather than the implementation (the server machine had
not been updated), so nothing was relayed -- but it pinned three more shapes:

    SEND  TYPE=C USER=JeddyH BODY="hiiiii Yoooo"      plain text on the wire
    RADD  ID=103 LIST=B PRES=Y USER=jed5 GROUP=       BLOCK is two requests,
    RADD  ID=103 LIST=I USER=jed5                     same ID, B then I
    RDEL  ID=104 LIST=I USER=jed5                     unblock

So a blocked player **stays on the buddy list** and gets the red icon beside
their name; the ignore list is an overlay, not a move.  The `ID` counter is per
console (both started at 101).

**`MSG` and `CHL` are row icons, not message subjects.**  `0x00286970`, called
from the buddy list screen (`0x002A1724`), fills one row: the name, `PROD`
and `STAT` decoded, and flags -- blocked (`0x200`), online (`SHOW` index
non-zero), in a game (`0x2000`), pending (`0x100000`) -- and sets the icon to
`MSG` when `0x002871A0(name)` says there is an unread message from them, then
`CHL` when `0x00286B50(name)` says they have a challenge waiting.  So a
challenge is not started from EA Messenger; it is the lobby's own challenge,
and the buddy list only shows that one is pending.  The Online Action menu seen
for an offline buddy is Send Message / Remove From List / Block / Cancel;
whether it grows when the buddy is online is still to be seen.

### Working on real consoles (2026-09-23, third capture)

Two consoles on one PC, against the implementation:

* each added the other and **both showed Online** -- `PSET` relayed as `PGET`;
* **messages both ways**, drawn in the MESSAGE box with a Reply button;
* **block**: the blocked player's message was refused and their console showed
  "Undeliverable Message / Unknown Error." -- the text is the sender's dialog 6
  whatever the ident, so no code reads better than another; unblock restored
  delivery;
* no unhandled verb and no exception in the session.

A challenge between the two went through the **lobby**, not Messenger:
`mesg PRIV=JeddyH TEXT=challenge...`, `mesg TEXT=accept`, both `chal`, `+ses`
-- exactly the section 17-19 path.

**The game signs out of Messenger when a match starts**: `DISC` from the
challenger at the moment of `+ses`.  Their buddies see them go offline for the
match; the game's own "in a game" flag (`0x2000`, set when a `PGET` carries
`PROD`) is never reached that way.  Nothing to fix unless it turns out to
matter to people.

### Blank buddy lists after a restart (2026-09-23)

The server was restarted four times in three minutes, alternating between
command lines with and without `--buddy-port`.  One run without it issued new
`LKEY`s at `pers` and was stopped; the consoles still held the Messenger
address from earlier, reconnected as soon as the next run (with Messenger) came
up, and presented keys that only the dead process had known -- `AUTH` refused
with `auth`.  After that refusal the game drew its buddy list as blank rows
showing offline, and removing one froze the emulator.  The lists themselves
were intact in the database throughout.

Two fixes:

* **Keys live in the database** (`twdb` `lkeys`, one per persona, 12-hour
  limit), so any lobbyd process honours a key any other one issued.  A clean
  lobby logout still retires the key; a restart does not, which is the point.
* **Messenger is on by default** (`--buddy-port` 10202, `0` to switch off), so
  a hand-started lobby cannot silently leave it out.  `tw04.sh` passes
  `--buddy-port 0` for an empty `BUDDY_PORT`.

The test for it turned up a harness bug worth knowing: a frame reader that
drops bytes past the end of the first frame loses a `ROST` whenever it arrives
in the same recv as its `RGET` -- an intermittent timeout, invisible with
server logging on because logging slowed the server enough to split them.  All
four test readers now keep their leftovers.

### Next

1. Challenge between two PCs -- that is the P2P leg (sections 20-23), not
   Messenger.
2. `PADD`/`PDEL` (presence subscribe without a list entry) have not been seen;
   they get an empty success.

## 58. Report abuse

`rept PERS PROD LANG` (`0x00275430`) is fire-and-forget: no callback, so the
reply is never read, and the game shows its own "You have reported abuse from
%s.  A copy of the chat log will be sent to customer service." whatever
happens.  The request names only who is being reported -- the reporter is the
connection, and there is no chat in it.  So the chat log the dialog promises
has to be the server's.

`lobbyd` keeps the last 2000 relayed lines in memory (`CHATLOG`): lobby room
chat and private chat from `mesg`, and EA Messenger `SEND`s.  The challenge
handshake verbs are left out -- they ride on `mesg` but are not chat.  On
`rept` it stores, in the `reports` table:

* the reporter -- the persona this socket signed in as, never a field;
* the reported persona and the reporter's room;
* from the last hour, what the reported player said in rooms, and every private
  or Messenger line between the two, at most 60.

A repeat of the same pair within ten minutes and a report of yourself are not
stored.  Nothing goes to the activity feed, which is public on `/live`.

The web site shows them at `/reports/<key>` and nowhere else: no link to it,
no login, any other path under `/reports` is a plain 404, and the page is sent
`no-store`, `noindex` and `no-referrer`.  The key is `secrets.token_urlsafe`,
kept in `reports.key` beside the database (so an upgrade copied over the top
keeps the address) and printed at startup.  "Mark handled" posts to
`/reports/<key>/handle` -- the key in the path is the credential and the CSRF
token at once.  Acting on a report stays in the shell: `twdb.py --disable`.

`tests/lobbyd_reporttest.py` runs it end to end through a real lobby and a real
site behind a base path.

## 59. The news screen writes itself, and the site grows player pages

Section 27 established that the `news NAME=1` reply body is shown verbatim,
wrapped at 64 columns, fetched once per session.  So the server can put
anything it knows on the console's own screen.  `lobbyd` now appends a digest
to the operator's `--news` text (which stays first): today's event with its
course, purse and current leader; yesterday's winner; records set in the last
week (lowest round, longest drive, longest putt, course records, holes in one
-- at most six lines); and the week's round count, busiest player and best
round.  Lines are wrapped at 60.  `--no-auto-news` turns it off, and a failure
building it logs and falls back to the plain text rather than failing the
request.

The digest and the new web pages -- `/player/<name>`, `/stats`, `/records`,
`/courses`, `/course/<n>` -- are all computed by `twrecords.py` from one
list of rounds (`rounds()`), which folds head-to-head results (host/guest from
the session, section 26) and tournament cards into one shape.  One list, so
the site and the console cannot disagree about who holds a record.

Two rules in it worth keeping:

* **Nothing from the console is taken on trust.**  A real tournament card
  arrived with `PUTTS=1025` for 18 holes.  Every field is range-checked in
  `clean()` and an impossible value becomes None -- out of averages and never
  a record.
* **Scoring uses 18-hole rounds only; everything else is per 18 holes.**  A
  Front 9 is half a round, not a low score.  To par uses the course's learnt
  par (section 53), tightened by any 18-hole head-to-head card that bounds it
  lower.

`tests/webui_pagestest.py` serves the sample data behind a base path, with a
golfer called `Tom & <Jo>/#1` to prove names are escaped and URL-encoded, and
reads the news back from a real lobby.

## 60. A rematch got no `+ses` -- and the Steam Deck log

The only Steam Deck match on record (LAN server, 2026-09-19 21:29) shows two
separate things.

**The first attempt was introduced correctly and still did not connect.**
TigerWoods (Windows, `192.168.1.50`) challenged SteamDeck (`192.168.1.16`), the
Deck accepted, and each `+ses` carried the other's LAN address on one subnet.
About 30 s later both were back in the lobby.  The lobby did its part; the UDP
3658 leg between the two emulators did not happen.  Not yet explained -- see
below.

**The retry could never have worked, and that was ours.**  The Deck then
challenged back without either player leaving the lobby.  `start_session`
keeps one session per pair so the two `chal`s of one acceptance share a seed
(section 22), but that record lived until a lobby disconnect -- so the second
acceptance got `session ... already decided -- not re-pushing` and no `+ses` at
all.  Any rematch between the same two players in one sitting was dead on
arrival, on any platform.  A new `challenge` between a pair now retires the
pair's old session and both `MATCHED` entries first; the accept and both
`chal`s that follow still mint exactly one.  `lobbyd_roomtest.py` replays the
Deck sequence.

What is known about the first failure: the Deck runs PCSX2 as an AppImage with
DEV9 on Sockets; the Windows bundle is PCSX2 2.9.78; Windows can ping the Deck,
so there is no client isolation.  Under Sockets the PS2's UDP socket on 3658
becomes a host socket that PCSX2 binds to the SELECTED ADAPTER's address on the
same port -- `p2pwatch` shows `192.168.1.50:3658`, not `0.0.0.0:3658`.  So the
Deck's Ethernet Device setting, and whether its PCSX2 build binds the port the
same way, are the two things to measure: `ss -uanp | grep -i pcsx2` on the Deck
during the connect, and Wireshark on the Windows side filtered to
`udp.port == 3658` to see whether the Deck's packets arrive and from which
source port.

### Solved (2026-09-23): the Deck's Ethernet Device

It was the Deck's DEV9 **Ethernet Device**.  Set to `wlan0` by name, the Deck
got into the lobby, was introduced correctly, and never connected -- on the LAN
server and through the online one alike.  Set to **Auto**, Deck <-> Windows
connects.  PCSX2 was 2.7.242 on the Deck and 2.9.78 on Windows throughout, so
the version gap was not it.

Why is not established.  The likely reading is that with an adapter named,
PCSX2 on Linux ties the UDP 3658 socket to that adapter's specific address,
while Auto leaves it on the wildcard -- but that is a guess, not something read
out of PCSX2.  What is established is the rule: **Linux and Steam Deck, Auto;
Windows, the adapter by name** (on Windows a blank device fails outright,
"Failed to Get Adapter", see the bring-up notes).  The site's setup steps and
its "if it will not connect" note now say so.

Two corrections to the reasoning above, for the record: the router DOES
hairpin -- two Windows PCs in one house play each other through the online
server -- and the empty `ss` output meant nothing, since PCSX2 only holds the
3658 socket during the ~30 s connect window.

## 61. A match stays on the live board until it is over

Section 54's rule -- a match is shown only while somebody in it is still
connected -- hid every match the moment it started, because starting is
exactly when both consoles leave the lobby (within a second of `+ses` in every
capture).  The board now follows the match, not the connection:

* `twdb.playing()` lists every match from `+ses` until it ends or is
  `MATCH_MAX_AGE` (3 h) old -- presence no longer comes into it;
* `publish_live` lists the players of those matches as **playing, vs <opponent>**
  even while they are away, and counts them as online.

A match ends on any of:

| signal | why it means the match is over |
|---|---|
| a `rank` result for its token | the match finished (unchanged) |
| either player's `pers` | they signed back in -- finished, or crashed and came back |
| `chal PERS=*` from a player still connected | the console re-subscribes whenever it is back in the lobby; 30 s after a `+ses` it means the peer connection failed (13:14:01, 2026-09-23) |
| a new `challenge` involving a connected player | they are in the lobby, not a match |
| 3 hours | nobody told us -- both consoles switched off, say |

At login `chal PERS=*` arrives before `pers`, when the connection has no
persona yet, so it cannot end the wrong match; `pers` does it a moment later.
A challenge to someone who is away in a match cannot end their match: only a
connected target counts.  `lobbyd_livetest.py` walks all four endings.

## 62. Purses follow course difficulty

Purses were a random $500,000-$5,000,000 per day whatever the course.  They are
now set by the course (`twtourney.course_purse`): `DIFFICULTY_ORDER` ranks the
21 tournament courses hardest first -- `course_difficulty.json` (CPU versus CPU
averages) in its own order, except Bay Hill Club moved from first to ninth --
and the purse steps evenly from $5,000,000 (Emerald Dragon) to $2,000,000 (TPC
of Scottsdale), $150,000 a place, rounded to $50,000.  The rank, not the file's
numbers, sets it: the numbers do not follow the file's own order.

`generate_month` still draws the old random purse and throws it away, so the
course and name sequence is unchanged -- regenerating September and October
2026 against the live server's stored calendar matched all 61 days.

Stored months are brought up to the rule by `reprice_calendar` (lobbyd, after
`repair_calendar`, at start-up and every calendar tick): days from today on,
skipping any day with a round already on it, since the money list pays out of
the purse.  Past days are never touched.  Against a copy of the live calendar
it repriced 36 upcoming events and changed nothing on a second pass.

**Conditions are next.**  The event screen also shows HOLES, TEES, ROUGH,
FAIRWAYS and GREENS, fed from entry bytes 4-11, which are still unmapped
(section 45.5; `--probe-tourney` / `probe_bytes` set one byte at a time).  Once
mapped, the agreed multipliers go on top of the course purse: tees Red x0.80 /
White x0.90 / Blue x1.00 / Black x1.10; rough Short x0.95 / Medium x1.00 /
Long x1.10; greens Slow x0.95 / Medium x1.00 / Fast x1.10; fairways Slow x0.97
/ Medium x1.00 / Fast x1.05; nine holes x0.50.  The option names are assumed
until the probe shows the real ones.

## 63. The event conditions are one-hot flags at data byte 8

The first conditions probe (one byte a day, values 1-3) moved exactly one
line: data byte 10 = 2 or 3 turned FAIRWAYS from Slow to Medium.  Everything
else stayed at the baseline -- All 18, Black, Average, Slow, Medium.  That
pattern is a bit field, and the code says which.

`0x002DFFD0`..`0x002E0230` are eight one-line getters on a calendar entry
(`$a0`; `+0x20` purse, `+0x2E` course and `+0x2F` icon are their neighbours).
Each reads the u32 at entry `+0x28` -- **data bytes 8-11, little-endian** -- and
turns ONE-HOT flags into an option index, the same scheme as a challenge's
CFLG (section 33).  UPCOMING EVENT (`0x002AB298`..) prints five of them through
the text tables beside them, which name every option:

| line | getter | no flag (default) | flags |
|---|---|---|---|
| Holes | `0x002DFFD0` | All 18 | bit 0 Front 9, bit 1 Back 9 |
| Tees | `0x002E0000` | Black | bit 3 White, bit 4 Blue |
| Rough | `0x002E00E0` | Average | bit 13 Short, bit 15 Long |
| Fairways | `0x002E0030` | Slow | bit 17 Medium, bit 18 Fast |
| Greens | `0x002E00B0` | Medium | bit 10 Slow, bit 12 Fast |

Red tees and the table's Par 3's / Par 4's / Par 5's / Famous Holes exist as
text but no flag reaches them.  Fairways is the one line the probe confirmed:
bit 17 is byte 10 = 2 exactly, and 3 = bits 16+17 still reads Medium.

Starting an event (`0x002DEB30`) calls all eight getters and stores the round's
setup -- greens, rough and fairways at `0x0032178D`/`E`/`F`, each followed by
its apply call.  Three settings are applied but never drawn and nothing names
them: bits 7-9 -> `0x00326E84`, bits 19-25 -> `0x0032178A` (default 4), bits
26-29 -> `0x0032178B`.  They stay at their defaults.  Bit 11 of the word at
data byte 4 is tested alone at `0x002E0630`, the likeliest "invitation only"
flag (45.6).

**Open question:** by this table data byte 8 = 1 and 2 should have drawn Front 9
and Back 9, and the probe report says HOLES stayed All 18 throughout.  So
`--probe-conditions` is now a CONFIRMATION calendar (`twtourney.PROBE_PLAN`,
built from the same `CONDITIONS` table events will use): tomorrow the
baseline, then one option a day NAMED for what the screen should show -- HOLES
FRONT 9, TEES WHITE, ... -- then ALL HARD (flags combining) and INVITE FLAG.
Thirteen days; each is checked by "does the line match the name".

**Holes are never varied.**  An Online Tournament round is always All 18, the
no-flag default, so `EVENT_SETTINGS` is tees, rough, fairways and greens only;
the holes flags stay in `CONDITIONS` as a record.  That drops the Front/Back 9
days from the confirmation calendar (eleven days now) and the nine-hole
multiplier from the purse plan -- which also retires the open question above.

## 64. Events have conditions, and purses follow them

The confirmation calendar matched on every tees, rough, fairways and greens
option and on ALL HARD, so the section-63 table is right.  INVITE FLAG drew
nothing on UPCOMING EVENT -- expected, since a password is asked for when an
event is STARTED and only today's can be.  It stays unconfirmed and is never
set.

Each event now carries conditions (`twtourney.event_conditions`): for each of
tees, rough, fairways and greens, the game's default half the time and an
even pick of the others otherwise, from `random.Random('TW04 conditions
<day>')` -- a seed of its own, so no course or name in a stored month moves and
the same day always gets the same conditions.  Holes stay All 18.  They reach
the console as the u32 at data byte 8 (`entries_for`), and are stored as JSON
in a new `events.conditions` column ('' reads as the defaults, which is what
every earlier event was played on).

The purse is `course_purse x` the agreed multipliers (`PURSE_MULTIPLIERS`):
tees Black x1.10 / Blue x1.00 / White x0.90; rough Short x0.95 / Average /
Long x1.10; fairways Slow x0.97 / Medium / Fast x1.05; greens Slow x0.95 /
Medium / Fast x1.10.  The game's defaults are not all 1.00 -- Black tees are
its default and its hardest -- so an untouched event pays about 1.07 x its
course purse.

`reprice_calendar` (lobbyd, at start-up and each calendar tick) gives stored
events from TOMORROW onward their conditions and every unplayed event from
today onward the matching purse; today keeps the defaults it may already be
being played on, and a day with a round on it keeps everything.  Against a copy
of the live calendar: 37 events updated, past days and a played day untouched,
a second pass changed nothing.  The site's schedule, the front page's today
card and the news digest now name the conditions ("Long rough, fast greens").

One slip worth recording: splicing the new `reprice_calendar` in by text range
deleted `repair_calendar` along with it.  Every test that runs lobbyd with
`--ping 0` skips the calendar at start-up and passed; `lobbyd_selftest`, the one
that runs with keepalives on, caught it.  Check that test first after touching
start-up code.

**The site shows every setting, not a summary.**  "Standard conditions" meant
nothing to anyone who did not know the game's defaults, so wherever the site
shows an event -- the Tournaments schedule and the Today's event card (front
page and Tournaments) -- it now lists all four: `Tees Black · Rough Long ·
Fairways Slow · Greens Medium`, from `twtourney.condition_items`.  An option
that differs from the default is in gold, and the schedule says so in a line
under it, along with "every round is 18 holes".  On a wide screen the schedule
gives them four columns; on a phone the same line sits under the event's name.
`describe_conditions` (the short form) is still what the in-game news uses.

### 2026-09-24: a replayed tournament round keeps the player's best

`tourney` is still one row per player per day, but `twdb.add_tourney` now only
overwrites it when the new round took fewer strokes (`ON CONFLICT ... DO UPDATE
... WHERE excluded.strokes < tourney.strokes`) and returns the score that counts.
A worse replay is still acknowledged on the console ("Your round of 58 is
recorded, but your best of 55 still counts.") and in the live feed. Before this
the last round reported won, so a replay could only make a result worse.

Same day, later: `tourney_log` keeps EVERY accepted tournament round, replays
included (`add_tourney` writes both tables). The Server Stats card's rounds,
holes, strokes, birdies/eagles/aces, best round, longest drive/putt and top
course now count from `tourney_log`; leaderboards, standings and player pages
still read `tourney` (best of the day). An older database seeds the log from
`tourney` the first time it opens, so earlier replays are not recoverable.

### 2026-09-25: ties, open days, and every match counted

- **Ties share.** `twdb.tourney_day` rows carry `place` (1 + everyone with
  fewer strokes) and `tied` (how many share that score). Tied players split the
  prizes for the places they cover, e.g. two tied for 1st each get
  (1st + 2nd) / 2. A tie for 1st is a win for each player. The in-game daily
  board sends the shared place as the rank.
- **An open day has no winner.** `tourney_standings(open_day=today)` counts
  today's round and money (a live standing) but not `wins`/`best`.
  `tourney_recent`, lobbyd `event_winners` and `twrecords.tourney_wins` all
  stop at yesterday.
- **Every match counts.** `DB.all_matches()` holds every brokered match and is
  cached on (MAX results.id, MAX sessions.rowid, COUNT sessions). Server Stats,
  `leaderboard` and `record` read all of them. Before this, they read the last
  500 (stats) or the last 400 results server-wide, filtered by persona
  afterwards (record).
- Test: `tests/twdb_tourneytest.py`.

### 2026-09-25: event pages, head to head, achievements, activity chart, admin

- **`/event/YYYY-MM-DD`** (`webui.event_page`): an event's details and its full
  field, with tie-aware place (`T1`) and prize (`webui.prize` gives the same
  split as `tourney_standings`). Today's page is live, a future day shows
  "not played yet", and there are links to the previous and next days. It is
  linked from the schedule (today's date), Today's event ("Full
  leaderboard"), Recent winners, and every tournament round in a rounds table
  (`_kind`) or on the account page.
- **`/h2h/<a>/<b>`** (`twrecords.head_to_head`): W/halved/L overall and by
  match or stroke play, plus the last 10 meetings with both scores. It is
  linked from the W-L-H figure on a player's head-to-head card.
- **Countdown:** `webui.closes_in()` counts to the server's local midnight,
  since `twtourney.today()` is `date.today()`.
- **Achievements** (`twrecords.achievements`): first eagle, hole in one,
  under 60 (18 holes), five tournament wins (finished days only), and grand
  tour, which means a win on every one of the 21 `TOURNEY_COURSES` (a match
  win there, or a tournament win on an event held there).
- **Activity chart** (`webui.activity_card`, `DB.activity_days`): 30 days of
  tournament rounds (from `tourney_log`) and matches (by the time the result
  arrived), plus the daily peak online. The peak comes from the new
  `daily_peak` table, which lobbyd's `publish_live` writes via `DB.note_online`,
  so it only starts from this deploy. The chart is pure CSS, as the site uses
  no JS.
- **Admin page `/admin/<key>`** (`data/admin.key`, `--admin-key`, off with
  `off`): find an account by name or persona, then reset its password (blank
  generates 8 easy characters, shown once and never put in a URL, because
  POSTs render the page and do not redirect), ban or unban it (the
  `accounts.disabled` flag, which the lobby already refuses with `bann`), or
  rename a persona. `DB.rename_persona` updates every name column in
  `PERSONA_COLUMNS` in one transaction, and a rename is refused while the
  persona is online. The page also edits the news: `--news`, default
  `news.txt` beside the database, the same file as lobbyd's default. Only
  ASCII is accepted, up to 4000 characters. As with reports, the key in the
  path is both the credential and the CSRF token.
- Test: `tests/webui_featurestest.py`.

Later on 2026-09-25, a player noticed that a leader's share of an open event was
being added to their earnings. The change: `tourney_standings` now pays prizes
for finished days only, and today counts only towards `rounds` (Events). The
same rule applies to the in-game Weekly Money Leaders board. Recent winners
now has an Earnings column showing 1st place's share, split between
co-winners. The event page for today still shows the prize each place would
earn, marked as able to change until midnight.

### 2026-09-25: the news box is about 40 characters wide, not 64

The client wraps news at 64 characters (0x00272ED0), but on a real console the
visible box shows only about 45: a 49-character line reached the edge, and
longer ones ran off the side. `twrecords.NEWS_WIDTH` is now 40, and
`twrecords.wrap_news` wraps the operator's text as well as the digest before
lobbyd sends it. The default text is just the welcome line, since anyone
reading it is already signed in.

### 2026-09-25: MY RESUME and tournaments

A player's resume read all zeros after two tournament rounds. `stat_record` (the
`S` in `onln` and `+usr`) was built from head-to-head matches alone. It now
also folds in each `tourney` round (best of the day, run through
`twrecords.clean`) for the records and statistics lines. Tournament
Performance comes from `DB.tourney_career`, which covers all events ever held:
entered (today included), and won, top 10, top 25 and earnings from finished
days only.

- 26-29 EVENTS ENTERED / WON / TOP 10 / TOP 25: named by the old probe, now filled.
- **50 TOTAL EARNINGS, in hundreds of dollars: inferred.** The resume renderer
  0x002A0620 reads 38 and 50, and no screen has named either. The first probe
  drew earnings as "$5,000", which fits field 50 holding 50 in hundreds, and
  50 is the only field wide enough at 25 bits.
- **38 EARNINGS RANK: inferred**, with a caveat. In that probe EARNINGS RANK
  read N/A while 38 held 38. If a real record still shows N/A, the rank comes
  from somewhere else (`cusr myrnk`'s 144-byte RNKRS is the other candidate).

To be confirmed on a console: $756,000 is sent as 7560 and should draw as
$756,000, with rank 1.

Confirmed on a console the same day: **field 50 is TOTAL EARNINGS in hundreds**
(7560 drew $756,000). **EARNINGS RANK is not in `S`.** Field 38 held 1 and the
line still read N/A. From the ELF:

```
0x002A0E08  v0 = 0x00276CE0(0x1F)        ; RNKRS word reader
0x002A0E10  if v0 <= 0: draw "N/A" else draw "%d"
```

`0x00276CE0(key)` calls `0x00277220`, a switch that maps a key to a word of
the 36-word RNKRS array at `ctx+0x104`, bounds-checks it (< 0x24), and returns
`lw 0x104(ctx + 4*word)`. Key 0x1F maps to word **10** (bytes 40-43, little
endian). lobbyd's `rank_record` now answers `cusr myrnk` with the all-time
money-list rank in word 10. The other 35 words are still zero. The rest of the
key-to-word switch is at 0x00277220 if another rank line is ever needed, and
`0x00276CE0` has one other caller, at 0x002A2BF0.

### 2026-09-25: Tiger Status, daily backups, the day's timezone

- **Tiger Status (field 6)** is drawn by 0x002A08B8 as 0 "T-", 1 "T-I-",
  2 "T-I-G-", 3 "T-I-G-E-", and >= 4 "T-I-G-E-R". EA's rule is lost. This server's
  rule is by online points (field 1): a letter at 50, 100, 200 and 500
  (`twstats.tiger_status`, `TIGER_STEPS`).
- **Backups:** lobbyd's `backup_tick` calls `DB.backup` hourly and once at
  startup. It uses the SQLite backup API from its own connection, writes one
  `tw04-YYYY-MM-DD.db` a day to `--backup-dir` (default `backups/` beside the
  database) and keeps `--backup-keep` copies (7; 0 turns it off). The tests
  pass `--backup-keep 0`, except `lobbyd_selftest`, which proves the thread
  starts.
- **Timezone:** the tournament day is the server's local date. The site now
  says which zone that is (`webui.server_tz`: "AEST, UTC+10" on Linux, just the
  offset where the zone name is long, as on Windows). It appears on Today's
  event, in the Tournaments subtitle and on a live event page.

### 2026-09-25: handicaps, seasons, conditions cost, compare

- **Handicap** (`twrecords.handicap`): World Handicap System short-record
  table over the last 20 finished 18-hole rounds (best 8 of 20; 3 rounds
  minimum, lowest minus 2). The game has no course or slope rating, so a
  differential is just the score against par, and most indexes are plus
  handicaps ("+9.9"). It is shown on player pages, on /compare, and on /h2h
  as a net-game strokes-given line.
- **Seasons**: a season is a calendar month. The Tournaments money list is now this month's.
  `/halloffame` shows the current season's leaders, past seasons (money
  champion, most wins, match-play leader, low round) and the all-time money
  list with a titles count. It is in the nav.
- **What the conditions cost** (`twrecords.conditions_cost`, a card on
  /courses): each tournament round's to-par minus its course's average,
  averaged per option. Only courses that have hosted 2 or more events count:
  with one event every round cancels to zero, which the first version showed
  as +0.0 everywhere. A figure needs 3 rounds.
- **/compare?a=&b=**: 17 figures side by side with the better one in gold,
  with name suggestions from a `<datalist>` (no JS). It is linked from
  player pages (a Compare box) and /h2h.
- Phone widths: recent rounds on course pages hide the Round column, and
  Records hides Course.
- Test: `webui_featurestest.py` (handicap table, conditions with a known
  answer, and the new pages).
