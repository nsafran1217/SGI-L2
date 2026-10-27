# sscope: SuperScope and errdmp

`sscope-1.62.0` is SGI's register-level debug kit for SN2 systems: Altix
350/3000/4700 and the Itanium Origin follow-ons. These systems are built
from SHub 1.x/2.x node controllers, TIO I/O chips and NL4 routers. The kit
reads and writes these chips' memory-mapped registers (MMRs) through their
JTAG ports, and it talks to the L2/L1 console. The L1 does the JTAG; nothing
runs on the host OS, so it works on a hung or powered-off-OS machine. That
was its purpose: post-mortem dumps for SGI support.

Everything is Perl 5.6.1 (`#!/stand/sysco/tools/bin/perl`, from
`sysco_tools`). The scripts are in `/stand/sysco/bin` and the modules in
`/stand/sysco/lib/sscope`, which also holds the compiled XS modules.
`sscope.zip` in that directory is a byte-identical copy of the rest of the
directory.

## Connections

Every tool takes `--l2 <host>` (some spell it `-l2`, or take the host as
their first argument). `--copy <n>` adds `10*n` to the ports, to reach the
nth `l2` on one host (several USB-attached software L2s).

| Port | Module | Used for |
| --- | --- | --- |
| 8001 | `SysAccess` (`sysco_subs.pm`) | L2 console commands (`cfg`, `pwr`, `r 1 s * leds`, `fru ...`), parsed from the text output |
| 8000 | `JTAGAccess` (`jtag_subs.pm`, `scancfg.pm`, `mmr_subs.pm`) | JTAG: reading the scan configuration, SIC and TAP setup, MMR reads and writes |

Without `--l2`, most tools fall back to `JTAGAccess`'s software emulator
(errdmp's `-sim`), which returns no data. See [protocol.md](protocol.md).

## Tools

### errdmp: SN2 error dump

`errdmp [--l2 <host>] [-m <machine>] [options]`, errdmp V4.14 (2007).

Reads the error state of every SHub, TIO and NL4 router in the system, plus
L1 status, and writes one long report. The report covers:

- error, first-error and detail registers;
- credits;
- PI CRBs (outstanding requests);
- directory state for failing cache lines;
- DIMM configuration;
- a FRU (field-replaceable unit) summary ranking likely failed parts.

Main options (all of them: `errdmp -help`):

| Option | Meaning |
| --- | --- |
| `--l2 <host>` | the L2 to use; logs go to `~sgidiag/sn2/dumps/errdmp/` |
| `-m <machine>` | the L2 is `l2-<machine>`; logs go to `~sgidiag/sn2/dumps/<machine>/` |
| `-abbrev` | read only each node's ID register |
| `-fast` | error registers only: no PI CRBs, XB state, L1 environment, II or config MMRs |
| `-rack/-slot/-part/-b` | restrict to bricks, partitions, brick types |
| `-f <cfg>` | scan configuration file instead of asking the L1s (needs L1 firmware 1.19.10+ otherwise) |
| `-sim` | no hardware; with `-f`, runs against the software emulator |
| `-noparse` | print register values without decoding them |
| `-pic` | also read PIC (PCI-X bridge) registers; SGI warns this can crash a running Linux |

**Output.** errdmp prints progress, and writes the report to
`~sgidiag/sn2/dumps/<dir>/errdmp_<yy>_<Day>_<Mon>_<dd>_<HH>_<MM>`.
`ist/orig/run` maps `~sgidiag` to `$SGIDIAG_HOME`, default `~/sgidiag`.

**Exit status.** The exit status is a bitmask from `err_codes.pm`:

| Bit | Meaning |
| --- | --- |
| 0x01 | SHub hardware error |
| 0x02 | Correctable ECC error |
| 0x04 | Credit error |
| 0x08 | NUMAlink CB/SN/retry error |
| 0x10 | Uncorrectable ECC error |
| 0x20 | SHub configuration problem |
| 0x40 | L1 link error |
| 0x80 | Aborted on JTAG errors |

The NL4R (`0x0101`...) and TIO (`0x1001`...) values don't fit in an exit
status; only their low bits survive.

**What it writes.** errdmp isn't strictly read-only:

- On every node it turns the PROM's "kernel WAR" off while dumping, and
  back on at the end. The WAR is a flag word that errdmp keeps in
  `SH_XN_MD_SIC_CMP_DATA0`: errdmp saves node 0's value and writes it back
  to every node.
- On Shub2 systems it also turns the L1's workaround off and back on
  (`war e`).
- It sets SHub debug test-point selects to read PI XB state.
- It reads directory state through MD registers, and restores LB mask
  registers afterwards.
- It runs `fru capture`.
- `-enable_fence`, `-disable_tuning` and `-withhold` write to the hardware
  on purpose.

On the test Altix 350, a full dump of a running Linux didn't disturb it.

**Example.** A full dump of a single Opus brick takes 13 seconds. Its
summary looks like this:

```
Reading Shub Registers on NODE of 001c02       NASID: 0x0000     Rev: 3    (Shub 1.2)
0x0000: SH_SHUB_ID                            Addr: 0x10060580,  Data = 0x0001000034363049
...
Config Problems found on NODE of 001c02    NASID: 0x0000    Rev: 3  (Shub 1.2)
0x0000: Express Reply mode is NOT enabled.
```

### sgidmp: dump for SGI support

`sgidmp --l2 <host> [-p <partition>] [-c <comment>] [-o <file>]` (sh script,
man page `sgidmp(1M)`).

Runs `errdmp --l2 <host> [-part <p>]` into `<file>` (default
`sgidmp_<yy>_<Day>_<Mon>_<dd>_<HH>_<MM>`). It then zips the file with SGI's
fixed password, `4sgionly`, and deletes the plain copy. It needs
`/usr/bin/zip`.

`-c` is broken: it passes `-title "<comment>"`, which errdmp doesn't accept
(errdmp takes `-t`).

### par_dmp: errdmp in parallel

`par_dmp [-m <machine>] [--l2 <host>] -part <p>`

Runs one errdmp per L2 on large systems, then merges their FRU summaries.
The errdmp instances use `-parallel`, `-peers`, `-l` and `-parent_id`, and
coordinate through files in the log directory.

### superscope: the GUI

`superscope [--l2 <host>] [-part <list>] [-b <types>] [-f <cfg>]`, a Perl/Tk
GUI.

The window has a command entry and a results pane, plus menus:

- Connect;
- Reset (SIC/TAP);
- MMRs: register windows per chip type, from the `*_mmrs.pm` tables;
- Debug: the debug-port test-point selector, from `DebugSel`;
- Scan: JTAG data registers, from the `*_jtdrs.pm` tables.

The logic analyzer windows (`laaccess.pm`, `TLAControl`) drive a Tektronix
TLA over a socket, and `vstation_subs.pm` (`VStationCtl`) drives a Mentor
IKOS VStation emulator. Both were SGI lab equipment.

### Register and memory tools

| Tool | Usage | Does |
| --- | --- | --- |
| `mmr_dump` | `-chip <brick>:<board>:<chip> [--l2 <host>] [-n <list>] [-i <in>] [-o <out>]` | Dump a chip's MMRs (PIC, NL4R) through the JTAG backdoor |
| `mem_read` | `[--l2 <host>] -addr <addr> [-chip <name>]` | Read a cache line from memory with the SHub packet generator (`pktgen.pm`) |
| `memdmp.pl` | `[--l2 <host>] [-module <m>] ...` | Dump memory ranges through the packet generator |
| `read_dir_state.pl` | `[-f <cfg>] [--l2 <host>]` | Read a cache line's directory state |
| `prom_read` | `[-f <cfg>] [--l2 <host>]` | Read the boot PROM version from each node |
| `rtrdmp` | `--l2 <host> -src_nasid <n> -dst_nasid <n> [...]` | Trace a NUMAlink route through router tables (`trace_numalink_route.pm`) |
| `rtr_clr.pl` | `[--l2 <host>]` | **Writes**: clear NL4 router error registers and arm first-error capture |
| `shubmb` | `-l2 <host> -<command> ...` | **Writes**: SHub MMRBIST (memory init/test, directory fill, NASID assignment) |
| `shubbt` | `-l2 <host> -copy/-zero ...` | **Writes**: SHub block-transfer engine copy/zero. Broken as shipped (`use lib` paths) |
| `sn2mon` | `-l2 <host> ...` | System monitor. Its usage text is shubbt's, copied |
| `run_diag` | `-m <machine> [-diag <cmd>] [-kern <k>] ...` | Loop over SMDK (SGI's diagnostic monitor, booted from the EFI shell) diagnostics on the console, clearing and sampling its logs. Its errdmp-on-failure step is broken: `$ERRDMP_PATH` is a developer path (`/data/cf/sn2-diag-sw/...`) |

### L1 console tools (SysAccess only)

| Tool | Usage | Does |
| --- | --- | --- |
| `eeprom_chk` | `eeprom_chk <l2-host> [<copy>]` | Read every brick's `serial all v`. Checks CPU EEPROM fields to classify CPUs as old or new |
| `link_err` | `link_err --l2 <host> [-copy n] [-limit <ber>] [-sort ...] [-a]` | `linkerr s` on every brick; a table of NUMAlink bit error rates |
| `beru` | `beru -m <machine> \| -l2 <host> [...]`, `beru -data <file>` | Run SMDK BER diagnostics on the console and report link BERs |

### Offline decoders

| Tool | Usage | Does |
| --- | --- | --- |
| `elog_decode` | `elog_decode [-B IP47\|IP57] [-F] [<file>...]` | Decode SMDK error logger output (`smdk> el *`) into register fields and FRUs (`elog_decode.pm`). Without a file, opens `vi` to paste the log into |
| `wirestat.pl` | `wirestat -data <a>[,<b>] [-format excel] [-sort ...]` | Format and compare SMDK `dscr 1 wiresummary 3` BER samples |

## Modules

The `.pm` files in `lib/sscope` fall into these groups:

- **Connections:**
  - `common_defs` (constants, error hook);
  - `sysco_subs` (console);
  - `jtag_subs` and `scancfg` (JTAG, scan configuration);
  - `smdk_subs` (the SMDK diagnostic monitor on the console).
- **Register access:**
  - `reg_subs` and `mmr_subs` (generic);
  - `shub_subs`, `shub2_subs`, `tio_subs`, `nl4rtr_subs`, `orbit_subs`
    (per chip);
  - `pktgen` (the SHub packet generator: memory and remote MMR access).
- **Register tables:** `<chip>_01_mmrs.pm` and `<chip>_01_jtdrs.pm`, for
  `shub`, `shub2`, `tio`, `pic`, `nl4rtr`, `orbit` and `lbi`. They're
  generated from the chip specs and make up most of the kit's size.
- **errdmp analysis:**
  - `error_regs`, `fru_funcs`, `sys_ctrl_funcs`;
  - `mem_err_funcs`, `ip*_memory_bit_map`, `dimm`, `ecc`;
  - `md_dir_state`, `pi_tools`, `ii_regs`;
  - `nl4r_funcs`, `nl4rtr_perf`;
  - `shub2_funcs`, `scct_funcs`, `trace_numalink_route`, `err_codes`.
- **GUI:**
  - `cmdutil`, `connect`, `wincfg`;
  - `mmrsel`, `namesel`, `selchip`, `selreg`, `groupdef`;
  - `dbg*` (debug port), `la*` (logic analyzer), `drawplot`.

### XS modules

The XS modules are i386 `.so` files built against perl 5.6.1. They are
unstripped and carry STABS debug info:

| Module | Sources (from STABS) | Purpose |
| --- | --- | --- |
| `SysAccess` | `sscope/libsrc/scapi`, `sdrs` | The L2 console session on port 8001: send a command, collect text up to the prompt, parse brick lists (`pcf_sysco_*`, `pcf_smdk_*`) |
| `JTAGAccess` | `scan/libsrc/*`, `sscope/libsrc/jtagmmr`, `l3/{api,IRouter,Router,main,sys}` | SGI's scan library plus the L3 client stack. It reads the configuration from the L1s, builds chains from `/stand/sysco/data/scan/cmp`, and does SIC/TAP control, IR/DR scans and JTAG MMR access (`pcf_jtag_*`, `pcf_scancfg_*`, `pcf_icd_*`) |
| `DebugSel` | `sscope/libsrc/{dbgcfg,shub,shub2,tio,pic,nl4rtr}` | Debug-port test-point tables per chip |
| `TLAControl` | `sscope/libsrc/laapi` | Tektronix logic analyzer control over TCP |
| `VStationCtl` | `sscope/libsrc/{cmdserv,laapi}` | IKOS VStation emulator control |

## Perl 5.6.1

`sysco_tools-1.0.2` is a complete Perl 5.6.1 for `/stand/sysco/tools`:

- built for `i686-linux-64all-ld` (64-bit integers, long doubles);
- Perl/Tk in `site_perl`;
- the usual `pod2*` and `h2xs` scripts.

errdmp's register arithmetic depends on the 64-bit integers. A current
64-bit Perl has them as well.
