# SGI IST tools

The Integrated Support Tools (IST) CD, version 3.24, installed SGI's system
controller software on an L3, which was an i386 Linux PC beside an Origin
3000 or Altix. The L2 emulator and its clients (`l2`, `l2term`, `l2cmd`,
`l2gui`) are reconstructed in the rest of this repository. This directory
covers the rest of the CD: the diagnostic, dump and scan tools that field
engineers ran on the L3.

They are mostly Perl, plus i386 programs and Perl XS modules. All of them
reach the hardware through an L2 (hardware or `l2`), so any L2 on the
network works. That includes this repository's modern `l2` on a Raspberry
Pi.

| Directory | Contents |
| --- | --- |
| [`orig/`](orig/) | SGI's original tools, unmodified, on current x86 Linux |
| [`docs/`](docs/) | What each tool is for, how to run it, and what it does to the hardware |

## The packages

| RPM | Installs | What it is | Docs |
| --- | --- | --- | --- |
| `sscope` 1.62.0 | `/stand/sysco/bin`, `lib/sscope` | SuperScope: Perl tools that read SHub/TIO/NL4 router registers over JTAG. Includes `errdmp`, `sgidmp` and `superscope` | [sscope.md](docs/sscope.md) |
| `snxscan` 1.62.0 | `/stand/sysco/bin`, `cfg/scan`, `data/scan` | Boundary-scan and LLP tests (`scantest`, `slit`, `scandump`, `scantool`), with ksh wrappers per brick type | [snxscan.md](docs/snxscan.md) |
| `sysco_tools` 1.0.2 | `/stand/sysco/tools` | Perl 5.6.1 with Perl/Tk, the interpreter for sscope | [sscope.md](docs/sscope.md#perl-561) |
| `snxsc_l3` 1.62.0 | `/stand/sysco/bin` | The L2 emulator and its clients, plus configuration, FRU and link tools | [snxsc_l3.md](docs/snxsc_l3.md) |
| `snxsc_firmware` 1.62.1 | `/usr/cpu/firmware`, `/usr/sbin` | L1/L2/power bay/FPGA firmware images and the flash tools | [firmware.md](docs/firmware.md) |
| `sgidiag` 1.7.3 | `/usr/people/sgidiag` | The `sgidiag` account's ksh profile: `PATH` and `SCAN_*` variables | [orig/run](orig/run) sets the same |

How the tools talk to the L2 is described in
[docs/protocol.md](docs/protocol.md).

## Running the original tools

All that's needed are the IST CD's RPMs. Point the build at the directory
holding them:

```sh
make ist-orig RPMS=/path/to/ist        # unpacks the RPMs into ist/orig/build/root
ist/orig/run errdmp --l2 <l2-host>     # any tool from /stand/sysco/bin or /usr/sbin
ist/orig/run superscope --l2 <l2-host> # Tk GUIs need $DISPLAY
ist/orig/run flashsc -v /usr/cpu/firmware/l2.bin
ist/orig/run perl -v                   # the shipped perl 5.6.1
ist/orig/run man sgidmp                # SGI's man pages
```

The directory needs five RPMs; the newest version of each is used:

| RPM | Needed for |
| --- | --- |
| `sysco_tools-*.i386.rpm` | perl 5.6.1 |
| `sscope-*.i386.rpm` | errdmp, sgidmp, superscope, ... |
| `snxscan-*.i386.rpm` | the scan tools |
| `snxsc_l3-*.i386.rpm` | the L3 tools |
| `snxsc_firmware-*.i386.rpm` | firmware images and flash tools |

The other RPMs on the CD aren't used: `sgidiag` is only a profile, which
`run` replaces, and the `kernel_*` RPMs are the sgil1 driver.

The build re-unpacks only when an RPM or the Makefile changes, so it is
safe to rerun. `make -C ist/orig clean` removes the unpacked tree. That
tree is about 370 MB, and it's gitignored.

The tools hardcode `/stand`, `/usr/cpu/firmware` and `/usr/people/sgidiag`.
`run` maps those paths with an `LD_PRELOAD` shim (`orig/stand_shim.c`)
instead of needing root:

- `/stand` and `/usr/cpu/firmware` are mapped into
  `ist/orig/build/root`. The RPMs' absolute symlinks are rewritten to
  point within that tree.
- `/usr/people/sgidiag`, where errdmp and friends write their logs (for
  example `sn2/dumps/errdmp/`), is mapped to `$SGIDIAG_HOME`, default
  `~/sgidiag`.

`run` prints the mapping on stderr before the tool starts, so the tool's
own output can still be redirected cleanly:

```
run: path mapping (IST_QUIET=1 to hide):
  /stand               -> .../ist/orig/build/root/stand
  /usr/cpu/firmware    -> .../ist/orig/build/root/usr/cpu/firmware
  /usr/people/sgidiag  -> /home/<you>/sgidiag
```

Set `IST_QUIET=1` to leave it out.

Requirements:

- To unpack: `rpm2cpio` and `cpio` (Debian: `apt install rpm2cpio cpio`),
  or else `bsdtar` (`libarchive-tools`).
- An x86 host with i386 multilib: `gcc -m32` (`gcc-multilib`, for the
  shim), and the i386 libc (which includes libnsl on Debian 13) and
  libcrypt (`libc6:i386`, `libcrypt1:i386`).
- For the GUIs, `libx11-6:i386`.
- For the `scan_*` wrappers, a ksh (`apt install ksh`, or `KSH=<path>`).

Tested on Debian 13 against this repository's `l2` on a Raspberry Pi. The
Pi was attached to an Altix 350 (one Opus C-brick, 001c02, IP57 node board
with SHub 1.2, two Itanium 2 CPUs, running Linux):

| Tool | Result |
| --- | --- |
| `errdmp`, full dump and `-abbrev` | Works. Full dump: 1282 lines, 330 JTAG round trips, 13 s |
| `sgidmp` | Works. Writes the password-zipped errdmp log |
| `superscope` | Works. GUI connects; JTAG initialised |
| `eeprom_chk`, `link_err` | Work |
| `scancfg`, `cfg_snap`, `cfg_dump`, `fru dump-txt` | Work |
| `scantest -t id` | Works. Reads SHub0's IDCODE `0x34363049` |
| `scantool` | Works. Tcl/Tk 8.2 GUI connects |
| Perl/Tk (`widget` demo) | Works |
| Every other tool | Starts and prints its usage; not run against the hardware |

Not run against the hardware:

- Anything that stops clocks (`scandump`).
- Anything that drives boundary-scan EXTEST (`scantest -t int`, the
  `scan_*` wrappers, `nettest`).
- Anything that writes memory or MMRs on purpose (`shubmb`, `shubbt`,
  `rtr_clr.pl`, `run_diag`).
- The flash tools.

The first three stop or upset a running system.

## Original bugs found so far

These are SGI's bugs, present on a real L3 as well:

- `shubbt` can't start: its `use lib` lines name a developer's directories
  (`/home/moose/beighley/sn2/rel/lib`, `/usr/people/sgidiag/sn2/oster`)
  instead of `/stand/sysco/lib/sscope`.
- `sgidmp -c <comment>` passes `-title`, which errdmp rejects (errdmp takes
  `-t`).
- Perl/Tk's `ptked`, `ptksh` and `widget` have `#!` lines naming SGI's build
  tree (`/work/ssh/sn1/sys_ctrl/tools/local.linux/bin/perl`). Run them as
  `ist/orig/run perl /stand/sysco/tools/bin/widget`.
- errdmp's exit status is a bitmask (`lib/sscope/err_codes.pm`). The NL4
  router and TIO bits are above bit 7, so the exit status loses them.
- `run_diag` runs errdmp from a developer path
  (`/data/cf/sn2-diag-sw/sn2/scripts/errdmp`).
- `flashioc4` needs `/stand/sysco/bin/x_svf`, which no IST package ships.
- `scantest --irtr` says "dumping IR pkts" and then prints nothing.

## Toward a modern port

The tools in `orig/` need an x86 host. For other platforms (the Pi itself,
for instance), the plan is:

- **Perl:** the scripts and `.pm` modules move to a current Perl 5.
- **`SysAccess` XS module:** this is the L2 console session on port 8001
  (send Ctrl-T and a command, then read up to the prompt). It becomes pure
  Perl.
- **`JTAGAccess` XS module:** this is SGI's scan library (`scan/libsrc`:
  chain configuration, SIC and TAP control, JTAG MMR access). It runs over
  the same Router/IRouter client code as `l2cmd`, on port 8000. It needs
  reconstructing in C, like `l2`, from the STABS debug info in
  `JTAGAccess.so`; `retools/stabs` already parses it: 825 functions, 2111
  types. The snxscan programs (`scantest`, `scandump`, `slit`, ...) link the
  same library, so they come with it.
- **Testing:** the traces of the original tools against real hardware
  (strace of ports 8000 and 8001) serve as the reference for differential
  tests, as `tests/` does for `l2`.
