# SGI L3 system-controller tools, reconstructed

Source for SGI's `l2` (the L2 controller emulator), `l2term`, `l2cmd` and
`l2passwd` from snxsc_l3 1.62.0 (IST 3.24), rebuilt from the original i386
binaries' STABS debug info and Ghidra decompilation. The layout mirrors SGI's
original tree (`sys_ctrl/...`). `l2gui` is not included yet.

## Build and test

    make            # build/bin/{l2,l2term,l2cmd,l2passwd}: 32-bit, matching the original ABI
    make test       # every SGI struct's size and field offsets match the originals
    make difftest   # l2/l2cmd/l2term outputs match the original binaries (needs them, see below)

Needs gcc with 32-bit support (Debian: `gcc-multilib`). `make difftest` uses
the original binaries from `../ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin`.

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
- Not yet 64-bit or big-endian clean.
- `ORIGINAL_BUGS.md` lists SGI bugs found (kept or fixed); `DEVIATIONS.md`
  lists intentional behaviour differences.
