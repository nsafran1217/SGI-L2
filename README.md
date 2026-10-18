# SGI L3 system-controller tools, reconstructed

Source for SGI's `l2` (the L2 controller emulator), `l2term`, `l2cmd` and
`l2passwd` from snxsc_l3 1.62.0 (IST 3.24), rebuilt from the original i386
binaries' STABS debug info and Ghidra decompilation. The layout mirrors SGI's
original tree (`sys_ctrl/...`). `l2gui` is not included yet.

## Build and test

    make            # build/bin/{l2,l2term,l2cmd,l2passwd}: 32-bit, matching the original ABI
    make ARCH=-m64 B=build64          # native 64-bit build in build64/
    make test       # every SGI struct's size and field offsets match the originals (32-bit)
    make difftest   # l2/l2cmd/l2term outputs and the NVRAM file match the original binaries

The 32-bit build needs gcc with 32-bit support (Debian: `gcc-multilib`).
`make difftest` uses the original binaries from
`../ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin`; to test another
build, run the scripts with `NEW_BIN`:

    NEW_BIN=$PWD/build64/bin tests/difftest.sh
    NEW_BIN=$PWD/build64/bin tests/l2term_test.py
    NEW_BIN=$PWD/build64/bin tests/nvram_test.py

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

- All four tools build and match the originals on the differential tests.
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
