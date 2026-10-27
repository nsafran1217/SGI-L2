# snxscan: boundary scan and LLP tests

`snxscan-1.62.0` is SGI's JTAG test suite for SN1/SN2 bricks: Origin 3000
(IP27/IP35 C-bricks, I/P/X/R bricks), Altix 3000/350/4700, and their
routers and I/O. Its uses are manufacturing and field repair:

- checking scan-chain integrity;
- boundary-scan interconnect tests between chips;
- at-speed NUMAlink/XIO (LLP) link tests;
- dumping internal scan chains of a stopped system.

**Boundary scan (EXTEST) and clock-stop dumps crash a running OS.** The
wrappers say so, and you must reset the system afterwards. Shut the OS
down first.

The programs are i386, statically linked except for libc. They embed SGI's
scan library (`scan/libsrc`) and the L3 client stack, the same stack
`l2cmd` uses. They reach the L1s' JTAG engines through an L2 on port 8000:

- `--l2 <host>`;
- or `--sysname`/`--ssn` (L2 discovery);
- or `--sc`/`--scdev` (`/dev/snsc/*`: the L1 seen from the host OS of
  the machine itself);
- or `--serial`/`--dev`.

Environment (set by `ist/orig/run`, as in sgidiag's profile):

| Variable | Value |
| --- | --- |
| `SCAN_PATH_DATA` | `/stand/sysco/data/scan` |
| `SCAN_PATH_CFG` / `SCAN_PATH_CONFIG` | `/stand/sysco/cfg/scan` / `/stand/sysco/cfg` |
| `SCAN_PATH_BIN` | `/stand/sysco/bin` |
| `TCL_LIBRARY` | `/stand/sysco/lib/tcl8.2` (scantool) |

## Programs

| Program | Version | Does |
| --- | --- | --- |
| `scancfg` | 2.4.17 | Read the scan configuration from the L1s and write it as a `.cfg`. `-links` also writes `.links` (cabling, for slit). Read-only |
| `scantest` | 4.2.1 | Scan integrity and boundary-scan interconnect tests. `-t` picks from `irp irl ir prp prl pr brp brl br int id all`. `id` only reads device IDCODEs; `int` is EXTEST |
| `slit` | 4.4.4 | Scan-based LLP interconnect test: at-speed link tests between ports (`-i slit.in`, or a `.links` file) |
| `scandump` | 3.7.5 | Dump internal scan chains. `-stop yes` (the default) stops the system clocks first. `-chip <brick>:<board>:<chip>` or `-type shub\|shub2\|tio\|nl4r\|pic\|rtr\|br` |
| `nettest` | 1.4 | Boundary-scan net test generated from BSDL files and Allegro netlists (`data/scan/bsdl`, `bdf`) |
| `scantool` | 0.9.7 | Interactive JTAG: a Tcl 8.2/Tk 8.2 shell (`libtcl8.2.so`, `libtk8.2.so` in `/stand/sysco/lib`) with scan commands, and a console GUI. It runs Tcl diagnostics from `data/scan/diags/<board>/` (memory BIST, MMR dumps, debug port). Man page `scantool(1M)`, `README.scantool` |
| `brick_scan` | | Tk GUI (`#!/usr/bin/wish`, the host's Tk) that picks a brick and runs `scantest` on it |
| `scan_<brick>` | | ksh wrappers (`scan_tw` is Perl). They prompt for the brick's options (riser, I/O card), write a `.cfg`, and run the `scantest`/`slit` sequence for that brick type |

The `scan_*` brick types:

- abacus, altix, asterix, asterix01, athena, baseio, cg, ch2u, chws,
  daytona, dorado;
- expb2084, expb2108, gemini, i, ip37_001/002 (`.dimms`, `.ni`), ip41,
  ip57, ip63, ip67, ip69, ip71, ip73, ip81;
- ix, kcar_l1, nbrick, nl4r, opus, p, pa, pebrick, pxbrick;
- ris2091, ris2098, rtr2061, rtr2085, sa, speedo2, system, tollhouse, tw,
  vortix, x.

The common options are `-h`, `-p` (don't prompt), `-ID <rack*64+slot>`
and `--l2 <host>`.

### Recommended sequence

This is SGI's order (`README.sys`, `README.scan`); each step should pass
before the next:

1. `scantest -t ir+pr+br`: scan-path integrity.
2. `scantest -t int`: slow boundary-register interconnect.
3. `slit`: at-speed LLP links.

## Files

| Path | Contents |
| --- | --- |
| `cfg/scan/*.cfg` | 1181 chain definitions per brick and board, and some whole systems (`altix_001_<n>p`, `th*`, `vtx*`). `README.cfg` lists SIC addresses and chains per brick |
| `cfg/scan/*.links` | 558 port-to-port cabling files for slit |
| `data/scan/cmp` | component (board) descriptions: chips on each SIC chain, IR lengths, IDs |
| `data/scan/bsdl`, `bdf` | BSDL files and board definitions for nettest |
| `data/scan/brdtest`, `systest` | pre-generated interconnect test vectors |
| `data/scan/dsh`, `map`, `reg2` | internal scan chain descriptions for scandump |
| `data/scan/diags` | scantool Tcl diagnostics per board |

### .cfg format

This is the file scancfg wrote for the test Altix 350:

```
CMP_PATH=/stand/sysco/data/scan/cmp
DSH_PATH=/stand/sysco/data/scan/dsh
VEC_PATH=/stand/sysco/data/scan/brdtest

START_CHAIN 0
NAME=001c02
ID=66
SIC=0x0:0x4:0x000002
NODE         ip57_001S2   1
END_CHAIN
```

- `ID` is `rack*64 + slot`. 0 means the local brick, for testing over a
  direct L1 connection.
- `SIC` describes the brick's scan interface controller: its address, its
  CER value, and optionally an MR value (scantest's names; it prints
  `SIC 0x00 (CER=0x04)` for this line).
- Each board line names a component file in `cmp/` and a count.

## Tested

The tools were run against this repository's `l2` and an Altix 350 (Opus
brick 001c02):

- `scancfg --l2 <host> -links -o opus` worked.
- `scantest --l2 <host> -f opus.cfg -t id` worked:

  ```
  001c02:NODE       ID REGISTER:              PACKED
  CHIP NAME         REV PART#  MFGID LSB      32-BIT VAL
  SHUB0/K9E2        0x3 0x4363 0x024  1       0x34363049
  ```
- `scantool --l2 <host>` connected and showed its GUI.
- `brick_scan` showed its GUI.
- The `scan_*` wrappers printed their usage.

The interconnect, LLP and dump tests weren't run, because the machine was
running Linux.
