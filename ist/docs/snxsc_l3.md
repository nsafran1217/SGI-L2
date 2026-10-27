# snxsc_l3: the remaining L3 tools

`snxsc_l3-1.62.0` holds the L2 emulator and its clients, and this repository
reconstructs them: `l2`, `l2term`, `l2cmd`, `l2passwd`, `l2gui`. This page
covers the other programs in the package. They are i386 C programs with
STABS debug info, built from the same `sys_ctrl/l3` tree, and the
reconstruction pipeline (`retools/stabs`, `retools/recon`) applies to them.
They accept the usual system controller options:

- `--l2 <host>`;
- `--sysname`/`--ssn` (L2 discovery);
- `--interface`;
- `--sc`/`--scdev` (`/dev/snsc`, on the machine itself);
- `--serial <host>:<port>` / `--dev <tty>`;
- `--pw`;
- `--irtr` (dump IRouter packets).

| Program | Usage | Does | Tested against an L2 |
| --- | --- | --- | --- |
| `cfg_snap` | `cfg_snap [<sysco>] [<file>]` | Read the configuration (bricks, cables) from the L2/L1s into a system configuration file (`.scf`, default `default.scf`) | Works |
| `cfg_dump` | `cfg_dump [-v] <file>` | Print an `.scf` | Works |
| `cfg_diff` | `cfg_diff <file> [--l2 <L2>] [-v] [-add <n>] [-e <max>]` | Compare the hardware's configuration with an `.scf`: missing or moved bricks and cables | Works ("0 differences") |
| `fru` | `fru [<sysco>] [-p <parts>] capture\|reset\|dump\|dump-txt\|dump-xml [<file>]` | The L1s' FRU analyzer: capture, reset, or dump its data (L1 log, SHub/NL4R/TIO MMRs) as text or XML. errdmp's `-fru_file` reads these dumps | `dump-txt` works |
| `l2find` | `l2find [-raw] [<iface>]` | Broadcast L2 discovery on the network; prints IP, serial, name, rack, firmware | Not on this network |
| `l2part` | `l2part [<sysco>]` | Show the system's partitions (from its strings; it never got that far here) | Hangs (see below) |
| `l2slit` | `l2slit [<file>] [<target>] [--l2 <L2>] [-m <mode>] [-e <max>]` | Scan-based link test between bricks, through the L2 | Not run (writes the links' test registers) |
| `l2tune` | `l2tune [<sysco>] <max> [<file>\|<rack>.<slot>[.<port>]]` | Read NL4 link tuning values and flag differences over `<max>` | Works (no links here) |
| `l2dhcps` | | The hardware L2's DHCP server for its private L2/L1 network (eth1) | Needs root and the L2's interfaces |
| `l2staticip` | | The hardware L2's boot step that sets its IP address from NVRAM (`.l2_NVRAM`) | Needs root |

`l2dhcps` and `l2staticip` belong to the hardware L2. Its PowerPC firmware
has its own builds of them (`ist/l2-firmware-1.62.0/rootfs`); the i386
copies on the CD are of little use on an L3.

## l2part

`l2part` connects to the L2's port 9002 (the `l2gui` port), and asks the L2
for its list of L2s and L1s. Then it sends an event to an L1 and waits for
the answer with no timeout. `l2part --irtr` shows the exchange:

```
PKT send:    0 REQ(1,0) D: L2 1023.63, 0,  4  S: L2 1023.63, 0, 10
PKT recv:        0 RSP(4,0,0) D: IP e 0a 1010000 S: IP e 04 1010000
PKT send:    1 EVT(1,0) D: L1    0. 0, 0,  0  S: L2 1023.63, 0, 10
PKT recv:        1 EVT(1,0,5) D: L1    0. 0, 0,  0  S: L2 1023.63, 0, 10
```

The event goes to the L1 at rack 0, slot 0. The L2 bounces it with error
5, and l2part then waits forever. SGI's original `l2 -noconn` and this
repository's `l2` behave the same.

Both L2s in the test had no rack ID set ("(no rack ID set)", rack 0),
while the brick is 001c02. That's a likely cause, but untested: an L2 with
`rackid` set hasn't been tried.
