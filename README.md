# SGI L3 system-controller tools, reconstructed

Source for SGI's `l2` (the L2 controller emulator), `l2term`, `l2cmd`,
`l2passwd` and `l2gui` (the L2's touch-screen GUI) from snxsc_l3 1.62.0
(IST 3.24), rebuilt from the original i386 binaries' STABS debug info and
Ghidra decompilation. The layout mirrors SGI's original tree (`sys_ctrl/...`).

## Build and test

    make            # build/bin/{l2,l2term,l2cmd,l2passwd,l2gui}: 32-bit, matching the original ABI
    make ARCH=-m64 B=build64          # native 64-bit build in build64/
    make test       # every SGI struct's size and field offsets match the originals (32-bit)
    make difftest   # l2/l2cmd/l2term outputs and the NVRAM file match the original binaries

The 32-bit build needs gcc with 32-bit support (Debian: `gcc-multilib`).

`l2gui` needs FLTK. `../retools/setup_fltk.sh 32` (or `64`, for `ARCH=-m64`)
builds FLTK 1.3.8 from the `../refs/fltk` checkout into `../tools/fltk/`, with
no root needed (the 32-bit build links the host's i386 X11 runtime libraries).
Without it, `make` skips `l2gui`; `FLTK_CONFIG=<path to fltk-config>` uses
another FLTK 1.3 or 1.4. The windows are FLUID files (`sys_ctrl/l3/gui/ui/*.fl`)
that FLUID turns into code at build time, as SGI's build did.
`make difftest` uses the original binaries from
`../ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin`; to test another
build, run the scripts with `NEW_BIN`:

    NEW_BIN=$PWD/build64/bin tests/difftest.sh
    NEW_BIN=$PWD/build64/bin tests/l2term_test.py
    NEW_BIN=$PWD/build64/bin tests/nvram_test.py
    NEW_BIN=$PWD/build64/bin tests/l2gui_test.py   # needs Xvfb, xdotool, ImageMagick, strace

`tests/l1_test.py` covers the L1 side, which the other tests (all `l2
-noconn`) never reach: the original and the rebuilt `l2 -net` each get a fake
L1 (`tests/fakel1.py`, one brick) and the commands in `tests/l1_commands.txt`;
transcripts and the requests the L1 receives must match. The original needs
`tests/usrtmp_shim.c` (built on the fly, 32-bit) for its hardcoded `/usr/tmp`.
`tests/l1net_test.py` is a quicker smoke test of the same path.

`tests/l2gui_test.py` runs the same touch session (destination window, power
and reset commands, the logo screen) through the original and the rebuilt
`l2gui` under Xvfb and compares every byte each exchanges with the L2;
`KEEP=1` keeps a screenshot of each step.
An AddressSanitizer build: `make ARCH=-m64 B=build64asan
EXTRA_CFLAGS=-fsanitize=address EXTRA_LDFLAGS=-fsanitize=address`, tested with
`ASAN_OPTIONS=detect_leaks=0` (the API leaks response packets at exit, as the
original does).

A big-endian build (s390x), run under qemu-user. `../retools/setup_s390x.sh`
unpacks the cross toolchain and qemu into `../tools/s390x/` without root:

    . ../tools/s390x/env.sh
    S=$(cd ../tools/s390x/root/usr && pwd)
    make CC=s390x-linux-gnu-gcc-14 AR=s390x-linux-gnu-ar ARCH= B=builds390x \
         QEMU="$S/bin/qemu-s390x -L $S/s390x-linux-gnu"
    NEW_BIN=$PWD/builds390x/qemu-bin tests/difftest.sh     # etc.

The tests then pit the big-endian tools against the original i386 binaries.

## Configurable paths

The originals hardcoded these. Unset, each keeps the original value.

| Variable | What | Default |
|---|---|---|
| `SGI_L2_NVRAM` | `l2`'s NVRAM file (`.N` appended with `--copy N`) | `./.l2_NVRAM`: the directory `l2` is started in |
| `SGI_L3_SOCKET_DIR` | local `UNIX_xxxx` sockets | `/usr/tmp`, or `/tmp` if `/usr/tmp` does not exist |
| `SGI_L3_DEV_DIR` | `sgil1_cs`, `sgil1_N`, `snsc/`, `ttyS1`, `com2` | `/dev` |
| `SGI_L3_ROOT` | prefix for the files `l2passwd` rewrites | empty: the real `/etc/passwd`, `/etc/.rhosts`, `/rhosts.allow` |
| `SGI_L3_MTRACE_DIR` | `--mtrace` output | `/tmp` |

`l2passwd` sets the host's root password from the L2 NVRAM. Without
`SGI_L3_ROOT` it edits the real `/etc/passwd`, as the original did.

## Status

- All five tools build and match the originals on the differential tests.
- `l2gui` sends and receives byte-identical L2 traffic. It draws with FLTK
  1.3 on X11 rather than SGI's FLNX on Nano-X, so the pixels differ (see
  `DEVIATIONS.md`).
- Files still include `compat/decomp.h` (Ghidra's types) and carry Ghidra's
  naming; cleanup into idiomatic C continues file by file.
- 64-bit: builds without pointer/integer conversion warnings and passes the
  differential tests (also under ASan) against the original i386 binaries.
- Byte order: everything the tools write — the Router wire format, IRouter
  frame prefixes, the NVRAM file — is encoded byte by byte to match what the
  i386 originals produce, so the same code runs on any host. IRouter frames
  carry their own byte-order tag, as in the original (the PPC L2 firmware is
  big-endian). Verified on s390x (big-endian, 64-bit) under qemu: all
  differential tests pass against the i386 originals.
- `char` is signed (`-fsigned-char`), as on i386: the code depends on it.
- `ORIGINAL_BUGS.md` lists SGI bugs found (kept or fixed); `DEVIATIONS.md`
  lists intentional behaviour differences.
