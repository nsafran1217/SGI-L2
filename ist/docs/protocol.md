# How the IST tools talk to the L2

These notes come from strace captures of SGI's original tools: `errdmp`,
`scantest` and `l2part`, run through `ist/orig/run` against this
repository's `l2`, with an Altix 350 on USB. They are the reference for a
reimplementation.

## Port 8001: the L2 console (SysAccess)

`SysAccess.so` (`pcf_sysco_*`, used by `sysco_subs.pm`) opens a TCP
connection to port 8001, the L2's SMP/console port. It talks to the text
console a person would see:

```
< ?-127.0.1.1-L2>                         the prompt
> \n
< \r\n?-127.0.1.1-L2>
> \x14cfg s\n                             Ctrl-T, the command, newline
< cfg s\r\nL2s: 1\r\nL1s: 1\r\n  C Bricks: 1\r\n?-127.0.1.1-L2>
```

- **Commands.** Each command is preceded by Ctrl-T (`0x14`), which returns
  the console to the L2 prompt if it was attached to a system console.
  `sysco_cmd()` sends this; `sysco_raw_cmd()` sends the text as given.
- **Response.** The response is everything up to the next prompt; the echo
  of the command is dropped. The text arrives in arbitrary pieces. The
  timeout defaults to 10 seconds (`cmd_to_sec` in SysAccess.so). errdmp
  raises it to 25 with `sysco_set_timeout(25, 0)`, because `link` takes
  longer on big systems.
- **Brick lists.** `sysco_cfg()` parses the `cfg` output into brick names
  (`001c02`). Commands to every brick use the `r <rack> s * <cmd>` form.
- **SMDK.** The `pcf_smdk_*` calls drive SMDK, the diagnostic monitor on a
  partition's system console, over the same connection.

`--copy <n>` adds `10*n` to the port.

## Port 8000: the Router connection (JTAGAccess)

`JTAGAccess.so`, and every scan program, connects to port 8000 like
`l2cmd`. It speaks the same Router protocol, which the code in
`sys_ctrl/common/Router` implements. It registers as application `scan`,
with the user's name and GECOS. IRouter frames then travel as Router events:
the argument `"IR"` followed by one argument per frame (see
`IRouter2Router.c`). The frames use the standard 20-byte IRouter header
(`tests/fakel1.py` has a parser).

Addresses are `rack<<18 | slot<<12 | task` for L1s, and `0x1ffff000 |
task` for the L2. One errdmp run made these requests, in order:

| Request | Destination | Opcode | Arguments | Purpose |
| --- | --- | --- | --- | --- |
| 1 | `0x1ffff004` (L2, task 4) | 0 | `0` | L2/L1 list, as text (`l2:127.0.1.1,l2rack:0,...`) |
| 2 | `0x42006` (001c02, task 6) | 0 | `5` | brick configuration |
| 3 | `0x42006` | 0 | `0x4000` | EEPROM/FRU list, as text (`0,INTERFACE,IPMI,OKAY,IPF_2UINT,NJW943,...`) |
| 4 onward | `0x4200f` (001c02, task 15, the L1's scan engine) | `0xabcd` | one data buffer | JTAG operations |

Each scan request carries one buffer. Its first byte appears to be the
operation: `0x84`, `0x86` and `0x87` in this run. The second byte is `00`
in the request and `01` in the response; the rest is mostly echoed, with
the scanned-out data filled in. Two examples:

```
> 860400 00 01000000 60000100 00004000 ...    (a 0x40-byte DR scan)
< 860401 00 01000000 60000100 00004000 00000001 00 49303634 ...
```

The response's `49303634` is SH_SHUB_ID's low word (`0x34363049`),
little-endian. The scan buffer format belongs to the L1 firmware and the
scan library (`scan/libsrc/jtagio`, `scancmd.c`, `snl3sc.c`). Decoding it
is part of reconstructing `JTAGAccess`.

A full errdmp of one SHub 1.2 node made 330 scan round trips. They are
strictly sequential: one outstanding request at a time.

## Port 9002: l2part

`l2part` uses the l2gui port (9002), with the same Router/IRouter framing.
See [snxsc_l3.md](snxsc_l3.md#l2part).

## Capturing

```sh
strace -f -e trace=connect,read,write,close -s 65535 -xx -o trace.txt \
    ist/orig/run errdmp --l2 <host> -abbrev
```

The 32-bit tools' socket reads and writes show up in the trace as plain
`read`/`write` calls. The scan programs also accept `--irtr`, which is
supposed to print IRouter packets. `l2part --irtr` does print them;
`scantest --irtr` says "dumping IR pkts" but prints nothing.
