# snxsc_firmware: controller firmware and flash tools

`snxsc_firmware-1.62.1` installs firmware images in `/usr/cpu/firmware`, and
the tools that write them in `/usr/sbin`. The same RPM went on L3s and on
the Altix/Origin hosts themselves. On the hosts, the tools reach the L1
through `/dev/snsc`; `etc/init.d/sgi_snsc_mkdev` creates those nodes on
ia64 Linux.

**None of these tools has been run against hardware here.** A failed or
interrupted flash can leave a controller unbootable. Each tool's `-v` only
reads an image file; that is how the versions below were read.

## Images (`/usr/cpu/firmware/sysco`)

The small files in `/usr/cpu/firmware` (`l1.bin`, `l2.bin`, `io9.svf`, ...)
are one-line pointers to the versioned image (`l2.bin` contains
`l2-1.62.0.bin`).

| Image | Contents (from `flashsc -v` / `flashsvf -v` / `flashpbay -v`) |
| --- | --- |
| `l1-1.62.1.bin` | L1 1.62.1, 11/10/2008, 5 images: NL3R 1MB, Legacy 2MB, Legacy Linux L1, 2MB, Linux L1 |
| `l1_mips-1.48.1.bin` | L1 1.48.1, 01/2007, 7 images: Base 1MB, Fuel/PE/O300 1MB, MIPS 2MB, Legacy 2MB, Legacy Linux L1, 2MB, Linux L1 |
| `l2-1.62.0.bin` | Hardware L2 1.62.0, 11/07/2008: PowerPC Linux 2.4.7 kernel and cramfs root (unpacked by `retools/extract_l2fw.sh` into `ist/l2-firmware-1.62.0/`) |
| `l2_mips-1.48.0.bin` | Hardware L2 1.48.0, 01/2007 (the last for MIPS systems) |
| `pbay-00.18.bin` | Power bay 00.18 (09/2000) |
| `io9-0.83.svf`, `io10-0.83.svf` | IOC4 FPGA on the IO9/IO10 base I/O cards, 0.83 |
| `athena-1.17.svf` | SSP PROM 1.17 |
| `ab_lfprom-1.0.svf`, `ab_ufprom-1.0.svf` | Abacus LFPROM/UFPROM 1.0 |
| `dm7-1.0.svf` | DM7 PROMs 1.0 |
| `is2-1.10.svf`, `is3-2.0.svf`, `is_cpld-1.2.svf` | IS2 PROM0 1.10, IS3 PROM 2.0, Gemini CPLD 1.2 |
| `sgc-1.12.svf` | SGC PROMs 1.12 |

The test Altix's L1 reports `L1 1.62.1 (Image B) ... [Legacy 2MB image]`,
which is image 1 of `l1-1.62.1.bin`.

## Tools (`/usr/sbin`)

All except `flashioc4` are i386 programs from the same `sys_ctrl` tree,
with the usual system controller options (`--l2`, `--sc`, `--scdev`,
`--serial`, `--dev`, ...). The `flashsc` etc. in `/usr/cpu/firmware` are
pointer files to `/usr/sbin`, probably symlinks in the RPM that the
extraction flattened.

| Tool | Usage | Does |
| --- | --- | --- |
| `flashsc` 1.4.1 | `flashsc [-p] [-f] [<sysco>] <image> <rack>.<slot>\|all\|local`, `flashsc -v <image>`, `flashsc -l2recover ...` | Flash L1/L2 firmware. The L1 has a bootstrap plus images A and B, and boots the newer one; updates go to the other image, so the running one isn't overwritten. The L2 has room for only one image, so it has a recovery mode (`-l2recover`). `-p` flashes in parallel; `-f` skips the version check. Man page `flashsc(1M)` |
| `flashfile` 1.3.8 | `flashfile [-p [<n>]] [-f] [<sysco>] <src> <remote name> <target>` | Copy a file into the controllers' flash file systems |
| `flashpbay` | `flashpbay [-f] [<sysco>] <image> <rack>.<slot>\|all\|local` | Flash power bay firmware. Man page `flashpbay(1M)` |
| `flashsvf` 2.35 | `flashsvf [<sysco>] <svf> <rack>.<slot>` | Program a board's configuration EEPROM/CPLD by playing an SVF file through the L1's JTAG. Man page `flashsvf(1M)` |
| `flashioc4` | `flashioc4 [x_svf options] <svf> <rack>.<slot>` | sh wrapper for the IO9 IOC4 FPGA. It checks the brick and powers it up with `l2cmd`, then plays the SVF with `/stand/sysco/bin/x_svf`. No IST package ships `x_svf`, so it can't run as shipped. Man page `flashioc4(1M)` |
| `l2cmd` | `l2cmd [<sysco>] <command>` | Same binary as `snxsc_l3`'s `l2cmd` (reconstructed in this repo) |
| `l1cmd` | `l1cmd [<sysco>] <command>` | `l2cmd` under another name: the binaries differ only in the source file name in their strings (`l1cmd.c`) |

The flash tools reach the L1s through an L2, the same way `l2cmd` does.
None of them has been tried against this repository's `l2`.
