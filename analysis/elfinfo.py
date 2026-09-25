"""Dump PS2 ELF program/section layout and the vaddr<->file offset map."""
import sys
from elftools.elf.elffile import ELFFile

if len(sys.argv) < 2:
    sys.exit('usage: elfinfo.py <elf>')
path = sys.argv[1]
with open(path, 'rb') as f:
    e = ELFFile(f)
    print("entry     0x%08x  machine=%s  endian=%s" % (
        e.header.e_entry, e.header.e_machine, e.little_endian and "LE" or "BE"))
    print("\n-- program headers --")
    for i, s in enumerate(e.iter_segments()):
        h = s.header
        print("  [%d] %-8s vaddr=0x%08x off=0x%08x filesz=0x%06x memsz=0x%06x flags=%d"
              % (i, h.p_type, h.p_vaddr, h.p_offset, h.p_filesz, h.p_memsz, h.p_flags))
    print("\n-- sections --")
    for s in e.iter_sections():
        h = s.header
        if h.sh_size == 0:
            continue
        print("  %-12s addr=0x%08x off=0x%08x size=0x%06x  %s"
              % (s.name, h.sh_addr, h.sh_offset, h.sh_size, h.sh_type))
