# Analysis helpers

The small scripts the [protocol notes](../docs/PROTOCOL.md) were worked out
with: a disassembler that understands this compiler's habits, cross-references,
constant recovery at call sites, and function names recovered from the game's
own debug strings. None of them are needed to run the server.

## Setup

Unlike the server, these need two libraries:

```bash
pip install -r analysis/requirements.txt     # capstone and pyelftools
```

They work on **`SLUS_207.57`**, the game's main executable. It's a file in
the root of the disc, so any ISO tool will extract it from your own image of
Tiger Woods PGA Tour 2004 (USA, `SLUS-20757`), for example with 7-Zip:

```bash
7z e "Tiger Woods PGA Tour 2004.iso" SLUS_207.57
```

Nothing from the game is included in this repository.

## Addresses

The ELF is one `PT_LOAD` at `0x00100000`, file offset `0x100`, so

```
virtual address = file offset + 0xFFF00
```

Every address in the notes, and every argument these tools take, is a
**virtual address** in hex, except `strings.py`, which prints file offsets
(like `strings -t x`). `elfinfo.py` prints the mapping for any ELF.

## The tools

Run them from anywhere, e.g. `python analysis/xref.py SLUS_207.57 Lobby_GetNews`.

| Script | What it does | Example |
|---|---|---|
| `strings.py <file> [minlen]` | printable strings, tagged with their file offset | `strings.py SLUS_207.57 8` |
| `elfinfo.py <elf>` | segment and section layout, and the address map | `elfinfo.py SLUS_207.57` |
| `xref.py <elf> <addr\|string> ...` | who references an address, or a string by its text | `xref.py SLUS_207.57 Lobby_GetNews` |
| `disfn.py <elf> <addr> [n]` | disassembly, with string and constant operands annotated | `disfn.py SLUS_207.57 0x00276CE0 20` |
| `tagscan.py <elf> <callee> [argc] [--sort]` | the constant arguments at every call site of a function | `tagscan.py SLUS_207.57 0x002BAD78` |
| `names.py <elf>` | function names recovered from the debug labels the code passes around | `names.py SLUS_207.57` |
| `requests_map.py <elf>` | every LobbyAPI request: its verb, the tags it sends, its callback | `requests_map.py SLUS_207.57` |
| `fetable.py <elf> [start] [end]` | the online menu's handler table, which no call graph shows | `fetable.py SLUS_207.57` |

`requests_map.py` is what produced [`docs/lobby-requests.txt`](../docs/lobby-requests.txt).

Two modules are shared by the rest rather than run:

- `ee.py` loads the ELF and holds the address map, the constant and `jal`
  scanners, and the function-start finder.
- `mips.py` decodes the 64-bit forms capstone gets wrong on the PS2's R5900
  (below).

## Notes

- **The first run on an ELF takes a while.** `xref.py` builds an index of
  every constant and call in the image and keeps it in `analysis/_cache/`, so
  later runs are instant. Set `TW_CACHE` to keep it somewhere else, and delete
  it if you change `ee.py`.
- **capstone only knows MIPS32.** The compiler that built the game (Metrowerks,
  "MW MIPS C Compiler 2.4.1.01") emits the R5900's 64-bit instructions all the
  time -- `daddu rd, rs, $zero` is its `move` -- and capstone shows those as
  `.byte` lines or nonsense. `disfn.py` decodes them itself through `mips.py`,
  and `tagscan.py` does its own constant propagation for the same reason, which
  makes its argument recovery more reliable than reading a listing.
- `ee.py` was written with Tiger Woods PGA Tour 2005's executable
  (`SLUS_210.02`) in mind too, which shares much of this code; the notes and
  the server only cover TW04.
