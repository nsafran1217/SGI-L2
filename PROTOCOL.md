# The L2 network protocol

This is how a program talks to an L2: SGI's hardware L2, SGI's `l2` for
Linux (the L3's L2 emulator, 1.62.0), or this repository's `l2`. All three
speak the same protocol, so a client written from this document works with
any of them. It is the protocol `l2cmd`, `l2term`, `l2gui`, the IST tools
and `l2api` use.

Everything here was taken from the reconstructed source (file names below
are under `sys_ctrl/`) and checked on the wire. The worked example in
[A complete exchange](#a-complete-exchange) was captured from SGI's original
1.62.0 `l2` and from this repository's `l2`. Both sent the same bytes.

Two programs implement the client side and can serve as references:

- `contrib/l2client.py`: Python, standard library only, under 400 lines.
  It runs commands, reads the configuration, prints events and discovers
  L2s. Its output for `help` is byte-identical to SGI's `l2cmd`.
- The SGI-L2-WUI backend (`backend/functions/router.js`, `irouter.js`,
  `l2-client.js`): the same client in Node.js.

If HTTP is easier, `l2api` (README.md, "HTTP API") already does all of this
and serves the L2 as JSON and WebSockets.

## Contents

- [Overview](#overview)
- [Router packets](#router-packets) (the connection)
- [IRouter packets](#irouter-packets) (the messages)
- [Addresses and tasks](#addresses-and-tasks)
- [Running commands](#running-commands)
- [The configuration](#the-configuration)
- [Events](#events)
- [The application port](#the-application-port-9002)
- [The console port](#the-console-port-8001)
- [Discovery](#discovery-udp-10000)
- [A complete exchange](#a-complete-exchange)
- [Checklist](#checklist-for-a-new-client)

## Overview

### Ports

| Port | Protocol | Used by | Purpose |
|---|---|---|---|
| TCP 8000 | Router + IRouter | `l2cmd`, `l2term`, `l2api`, IST tools | L3 clients: commands, configuration, events |
| TCP 8002 | the same | (quiet clients) | as 8000, but the L2 does not log the connection |
| TCP 8001 | plain bytes | `l2term`, telnet, `l2telnetd` | the L2 console, as a person types it |
| TCP 8003 | plain bytes | | as 8001, not logged |
| TCP 9002 | Router + IRouter | `l2gui`, `l2part` | L2 applications, which act as one of the L2's own tasks |
| TCP 9004 | the same | | as 9002, not logged |
| TCP 9001 | Router + IRouter | other L2s | L2 to L2. Clients don't use it. |
| UDP 10000 | text | `l2find`, every tool given no `--l2` | discovery |

An L2 started with `--copy N` adds `10*N` to every port, so several can run
on one host.

### Layers

On TCP 8000, 8002, 9002 and 9004 a connection carries **Router packets**
(`common/Router/`). Router is a general request/response/event transport
with a short handshake.

Once connected, an L2 and its client exchange only Router *events*. Each
event carries one **IRouter packet** (`common/IRouter/`). IRouter is the
system controller's message format, the same one L1s and L2s use over USB
and serial lines. It has requests, responses and events, addressed to tasks
on L1s, L2s and clients.

A command such as `pwr u` is an IRouter request to the L2's command task.
Its output comes back as an IRouter response:

```
TCP ── Router packet (class EVENT) ── args: "IR\0", <16-byte prefix + IRouter frame>, ...
```

### Byte order

The wire is big-endian, with two exceptions:

- Router value arguments (class 0) are little-endian. See below. The L2
  never sends them to clients.
- The 16-byte prefix in front of each IRouter frame is an i386 memory image.

## Router packets

Source: `common/Router/Router.c`, `RouterCl.c` (client side), `RouterSv.c`
(server side), `Buff.c` (compression).

### Header

Every packet starts with 8 bytes:

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 2 | opcode | depends on the class (see below) |
| 2 | 1 | class | what the packet is (table below) |
| 3 | 1 | id | a request's number, copied into its response. 0 in other packets. |
| 4 | 1 | config | bit 0x80: the body is compressed |
| 5 | 3 | length | bytes in the body, after this header |

The body is a list of arguments, end to end. A packet has as many arguments
as fit in its length. There is no count.

### Arguments

Each argument starts with a 4-byte big-endian word, `class << 24 | size`:

- **class 0, a value:** the next 4 bytes are a 32-bit number, and *size* is
  0. SGI's code writes them in host order (little-endian on the i386 L3) and
  reads them with `ntohl`. A value therefore changes byte order on its way
  between two i386 hosts. Avoid value arguments. Nothing an L2 sends a
  client uses them.
- **class 1, data:** *size* bytes, then zero to three bytes of padding to the
  next multiple of 4. SGI's original fills the padding with whatever was in
  memory, so ignore it.

When parsing, stop when 4 or fewer bytes remain. SGI's parser does this, so
it never reads an argument word in the last 4 bytes (an empty data argument
at the very end is lost).

### Classes

| Class | Name | Sent by | Opcode | Arguments |
|---|---|---|---|---|
| 0x01 | PASSWORD_REQ | server | server's process ID (2) | none |
| 0x02 | PASSWORD | client | client's process ID | the password, NUL-terminated |
| 0x04 | ACCEPT | server | server's process ID (2) | the server's RouterID |
| 0x08 | CLIENT_ID | client | client's process ID | client type, RouterID, group bits (optional) |
| 0x10 | REQUEST | either | the request's opcode | any |
| 0x11 | DISCONNECT_REQ | either | 0 | none |
| 0x12 | DISCONNECT_RSP | either | 0 | none |
| 0x14 | CONFIG_INIT | server | 0 | a RouterConfig |
| 0x18 | CONFIG_REQ | client | 0 | the RouterConfig, echoed |
| 0x20 | REL_REQUEST | either | as REQUEST | as REQUEST |
| 0x21 | CONFIG_RSP | server | 0 | the RouterConfig, echoed again |
| 0x22 | DENIED | server | server's process ID (2) | none |
| 0x24 | PING | either | 0 | none. Ignore it. |
| 0x40 | RESPONSE | either | 0 | any |
| 0x80 | EVENT | either | any (0 here) | any |

Between an L2 and a client, only the handshake classes and EVENT are used.
The L2 logs and ignores a REQUEST (it answers with an empty RESPONSE), and
never sends one.

### Connecting

```
client                                   L2
  |  ------------- TCP connect ------------>  |
  |  <---- ACCEPT (opcode 2, RouterID) ------  |   or PASSWORD_REQ, or DENIED
  |  ---- CLIENT_ID (opcode = event mask) -->  |
  |  <---------- CONFIG_INIT ---------------   |   only if CLIENT_ID asked for it
  |  ----------- CONFIG_REQ (echo) -------->   |
  |  <---------- CONFIG_RSP (echo) ---------   |
  |  <========= EVENTs both ways ==========>   |
```

1. **The server speaks first.** Its first packet's opcode is its process
   ID, which is always 2 for an L2. SGI's client refuses any other value.
   The class is:
   - ACCEPT: go on. Its argument is the server's RouterID (below).
   - PASSWORD_REQ: send PASSWORD (below), then wait for ACCEPT or DENIED.
   - DENIED: give up.
2. **CLIENT_ID.** The opcode is the client's *process ID*. For an L2 this is
   the client's **event mask** on ports 8000 and 8002 (see
   [Events](#events)), or its L2 task number on 9002 and 9004. `l2cmd`
   sends 0, which means no events. The arguments are:
   1. 8 bytes, the client type: a big-endian `use` word, then a big-endian
      group count. In `use`, only 0x4000 (`RU_CONFIGURE`: "send me
      CONFIG_INIT") means anything to the server. SGI's clients send
      `00 00 40 00 00 00 00 00`, or a group count of 256 to receive one
      partition's console output (below).
   2. The client's RouterID.
   3. Only if the group count is not 0: `(count + 7) / 8` bytes of group
      bits. Bit *n* (byte *n*/8, bit *n*%8) selects partition *n*.
      `l2term -syscon` uses this.
3. **The configuration exchange.** This happens only if `use` had 0x4000.
   The server sends CONFIG_INIT with an 8-byte RouterConfig: big-endian
   `rev`, then `flags`. SGI's L2s send `00 00 00 02 80 00 00 00`. The client
   echoes the argument back unchanged as CONFIG_REQ, and the server echoes it
   again as CONFIG_RSP. Then the connection is up. SGI's clients wait for
   CONFIG_RSP. A client that sends `use` 0 skips this step and is connected
   as soon as CLIENT_ID is sent. Both the original and this `l2` accept that.
   **Events can arrive before CONFIG_RSP**, so a client that subscribes must
   keep them, not treat them as a protocol error.

**RouterID.** Three NUL-terminated strings, then 4 bytes:

| Field | Max | Example |
|---|---|---|
| process name | 16 chars | `l2cmd`, `L2` from an L2 |
| user name | 8 chars | `root` |
| full name (GECOS) | 32 chars | may be empty |
| IPv4 address | 4 bytes, network order | may be 0 |

The L2 only logs it ("Connection - root () @ host running 'l2cmd'"). A
trailing address may be omitted.

**Passwords.** SGI's `l2` asks clients on ports 8000 and 8002 for a password
when one is set with `l2passwd`. Send PASSWORD, with the password in plain
text as a NUL-terminated data argument. A wrong one gets PASSWORD_REQ again;
the third wrong one gets DENIED. An empty password is always wrong. This
repository's `l2` never asks, and ignores a password it is sent.

**Request ids.** The id byte counts requests 1 to 255 and skips 0. It is not
needed between an L2 and a client, because both sides send only events.

**Disconnecting.** Close the socket, or send DISCONNECT_REQ and wait for
DISCONNECT_RSP. Answer a DISCONNECT_REQ from the L2 with DISCONNECT_RSP.

**Compression.** If bit 0x80 of `config` is set, the body is run-length
coded. It starts with the uncompressed length (4 bytes, big-endian), then:

- `fe n c`: *n* (1 to 255) copies of byte *c*
- `fd n1 n0 c`: *n* (big-endian, up to 65535) copies of *c*
- any other byte: itself

In practice nobody compresses: SGI's code reads only the low 24 bits of the
RouterConfig flags, so the compression flag (bit 31) never takes effect
(ORIGINAL_BUGS.md). A careful client decodes it anyway.

## IRouter packets

Source: `common/IRouter/IRouter.c`, `IRouter2Router.c`; the L2's routing is
`l3/l2/irtr.c`.

### In a Router event

An IRouter packet travels as one Router EVENT (opcode 0) with these data
arguments:

1. `49 52 00`: the string `"IR"` with its NUL (3 bytes, padded to 4).
2. One argument per frame of the packet, in order. Each is a 16-byte prefix
   followed by the frame.

The prefix is the frame's in-memory header on SGI's i386 build. Two of its
bytes mean anything:

| Prefix bytes | Meaning |
|---|---|
| 0-3 | a pointer. Send 0, ignore. |
| 4-5 | little-endian. Bit 0: received from the network; bits 1-15: reference count. Send 0, ignore. |
| 6 | bits 0-1: **the frame's byte order**, 1 = big-endian, 2 = little-endian. Send 1. |
| 7-15 | flags and pointers. Send 0, ignore. |

So a client sends `00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00` before
each frame, with the frame in big-endian order. When reading, skip the 16
bytes: every L2 sends big-endian frames. SGI's i386 `l2` and this
repository's mark them with 1 in byte 6. A hardware L2, a big-endian
PowerPC, lays the prefix out in its own order and puts the flag in the top
two bits of byte 6 (`0x40`); its byte-order conversions are `htons` and
`ntohs`, which do nothing there, so it reads every frame as big-endian
whatever the flag says.

### Frame header

Each frame is at most 1024 bytes, with exceptions (see
[Packets of several frames](#packets-of-several-frames)). It starts with 20
bytes:

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 2 | size | the whole frame, header included |
| 2 | 1 | rev | 2. (Revision 0 packets carry only an 8-bit sequence number.) |
| 3 | 1 | err | 0, or in a response an error code (table below) |
| 4 | 1 | seqnum low | |
| 5 | 1 | fnum | `0x80 \| n` on the first of *n* frames, then *n*-1 down to 1 on the rest. `0x81` for a single frame. |
| 6 | 1 | class | 0 request, 1 response, 2 event |
| 7 | 1 | pdata/authority | `pdata << 3 \| authority`. Clients send 0. A response copies the request's pdata. |
| 8 | 4 | dest | the destination address (an event has 0) |
| 12 | 4 | src | the source address |
| 16 | 1 | argc | the number of arguments (0 on frames after the first) |
| 17 | 1 | seqnum high | |
| 18 | 2 | opcode | depends on the task: 0 for commands and the configuration |

The first frame's header is followed by *argc* 8-byte arguments, then the
data of the data arguments.

### Arguments

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | class: low 3 bits 0 value, 1 bytes, 2 string. Bit 3 (0x08) is the sender's "free after sending" flag, which also shows up on the wire: mask it off. |
| 1 | 1 | frame: for data, the frame its data starts in, counting the first frame as 1. 0 for values. |
| 2 | 2 | size: for data, its length (a string's includes its NUL). 0 for values. |
| 4 | 4 | value: for a value, the value. For data, **its offset in the frame plus 16** (because the original pointed into its in-memory frame, which had the 16-byte prefix). |

A string argument is NUL-terminated text, and *size* counts the NUL. The L2
speaks ASCII; treat it as Latin-1.

### Packets of several frames

A packet bigger than one frame continues in further frames. Each extra
frame repeats the first frame's 20-byte header with its own *size* and
*fnum*, and with *argc* 0. Data then continues at offset 20 of the next
frame: an argument whose data does not fit in one frame runs on into the
following ones.

In a Router event, the frames come one per argument, in order (first frame
first), so a client never reassembles from the TCP stream. To read data
argument *k*, take *size* bytes from frame number *frame*, starting at
*value* - 16, and continue at offset 20 of each following frame until you
have them all. `IRArg()` in `IRouter.c` and `ir_decode()` in
`contrib/l2client.py` do exactly this.

Frame size limits:

- Requests must fit in frames of 1024 bytes. A short command fits in one
  frame.
- A response from an L2 to a client may use **extended frames** of up to
  0x3400 bytes, if the request was revision 2. (This applies to responses
  between L2, L3 and IP-type addresses, which includes every client.) A
  2-KB `help` output arrives as a single 2043-byte frame, so do not assume
  1024.
- Responses passed through from an L1 keep the L1's 1024-byte frames.

### Sequence numbers

A request carries a 16-bit sequence number (bytes 4 and 17). Its response
carries the same number. Count up from 0 per connection, and match each
response to its request by number. If the response's *rev* is 0, compare
only the low 8 bits. Responses can arrive interleaved with events, and with
other responses if several requests are outstanding.

### Errors

An IRouter error comes back as a response with *err* set and usually no
arguments: for instance when the L2 can't deliver a request (no such brick),
or a brick reports a failure. The codes (`IRErrorCodes` in `IRouter.h`;
messages from `Logger.c`):

| err | Meaning | err | Meaning |
|---|---|---|---|
| 1 | bad packet type | 15 | read failed - select() error |
| 2 | bad task ID | 16 | read timeout on multiframe packet |
| 3 | duplicate target ID | 17 | write failed |
| 4 | malloc failed | 18 | sequence ID mismatch |
| 5 | duplicate task ID | 19 | wait further for response |
| 6 | bad event entry | 20 | timeout waiting for packet |
| 7 | bad argument list argument count | 21 | read failed - end of file |
| 8 | no receiver for packet | 22 | write failed - end of file |
| 9 | no device to read/write | 23 | framing error, frame incomplete |
| 10 | attempt to send to full queue | 24 | framing error, frame overflow |
| 11 | queue is full | 25 | framing error, frame underflow |
| 12 | read failed - read error | 26 | framing error, frame control |
| 13 | read failed - not first frame | 27 | response packet is too large |
| 14 | read failed - unexpected frame | | |

SGI's tools report these as status `-600 - err`.

## Addresses and tasks

An IRouter address is 32 bits (`IRouter.h`, `IR_ADDR_*`):

- **Top bit clear:** `type << 28 | rack << 18 | slot << 12 | num << 5 | task`.
  - type: 0 L1, 1 L2, 2 L3; 3, 4, 5 and 6 are the L1s of attached C and I/O
    bricks.
  - rack: 10 bits.
  - slot: 6 bits.
  - num: 7 bits, usually 0.
  - task: 5 bits.

  Rack 0x3ff and slot 0x3f together mean "local": the L2 you are connected
  to, or the L1 at the other end of the link.
- **Top bit set:** an IP-routed address. `0x80000000 | task << 24 | the low
  24 bits of an L2's IP address` is an L2. With `0xc0000000` instead, it is a
  client of that L2. Here *task* is 6 bits.

### Addresses a client uses

| Address | What |
|---|---|
| `0x1ffff003` | the local L2's command task: run a command line |
| `0x1ffff004` | the local L2's configuration task |
| `0x2ffff000` | the source address SGI's L3 clients put in their requests |
| `rack << 18 \| slot << 12 \| task` | a brick's L1. For example `0x42003` is brick 001c02's command task (rack 1, slot 2, task 3). |

The L2 overwrites the source address of every request and response that a
client sends. On port 8000 or 8002, the client becomes `0xc0000000 | socket
<< 24 | the L2's low 24 IP bits`. On 9002 or 9004 it becomes
`0x80000000 | process ID << 24 | the same IP bits`. Responses come back to
that address, so a client can put anything in *src*; `0x2ffff000` is what
SGI's tools send. Events keep their source.

To reach a brick on another L2 of the same system, send to the brick's
address. The L2 forwards the request to the L2 that has it.

### Tasks

| L1 task | | L2 task | |
|---|---|---|---|
| 1 | IRouter | 1 | IRouter |
| 2 | SMP | 2 | console (SMP sessions) |
| 3 | command | 3 | command |
| 4 | environment | 4 | configuration |
| 5 | board (console output) | 5 | loopback |
| 6 | request | 6 | display (`l2gui`) |
| 14 | configuration | 7 | modem |
| 15 | scan (JTAG) | 8 | flash |
| 16 | flash | 9 | auto power |
| 17 | USB | 10 | partitioning (`l2part`) |
| 18 | loopback | 11 | demo |
| 20 | auto power | 12 | command (internal) |
| 22 | FRU | 13 | route |
| 23 | route | 14 | web server |

(L1 tasks 10-12, 19, 21 and 24 also exist; `IRouter.h` lists them all.)

## Running commands

This is what `l2cmd` does (`l3/api/SCapi.c`, `sn1SCTextCmd()`), and what
the L2 does with it (`l3/l2/cmd.c`).

**Request:** to `0x1ffff003`, opcode 0, two arguments:

1. value 0
2. string: one command line, as typed at the `L2>` prompt (`pwr u`,
   `r 1 s 2 pwr u`, `cfg s`)

**Response:** opcode 0, with the request's sequence number. The arguments
are:

1. value: the status. 0 is success; any error is -1 (`0xffffffff`).
2. Then strings: the output, split into arguments of up to 65534 bytes at
   line ends.

To build the output the way `l2cmd` prints it, concatenate the string
arguments and add a newline after any that is empty or does not already end
with one. If the status is not 0, the text is the error (`l2cmd` prints it to
stderr). If *err* is set instead, there is no output: report the IRouter
error.

Details:

- **One command per request.** `l2cmd 'a; b'` splits at `;` itself and
  sends each part in turn. Wait for each response before sending the next.
- **One command at a time per L2.** The L2 runs one command line at a time
  for all its clients together. A request that arrives while another is
  running gets status -1 and `ERROR: command library is busy`, unless the L2
  can answer it without asking a brick. Retry after a moment, or queue
  commands in the client.
- **Commands for bricks.** A command the L2 sends on to bricks comes back as
  their combined output, each brick's text under its address (`001c02:`).
  Bricks that did not answer appear as `ERROR: no response from 001c02`, and
  the status is -1.
- **`reboot`.** A command line containing `reboot` gets no response. SGI's
  tools only send it.
- **Timeout.** `l2cmd` waits 30 seconds. The L2 waits 15 seconds for bricks
  by default, so give commands to many bricks a little more than that.

A brick's L1 command task (task 3) takes the same request, so a client can
also address one brick directly. For example, `0x42003` with `[0, "serial
all"]` behaves like `r 1 s 2 l1 serial all`, without the L2's command
processing. If the brick doesn't exist, the L2 answers with *err* 8 (no
receiver), from its own address.

## The configuration

The L2 keeps its system's configuration (`common/main/L2Cfg.c`): itself,
the other L2s of the system, their USB ports and the bricks (L1s) on each.

**Request:** to `0x1ffff004`, opcode 0, one argument: value 0, which means
"query". (1 is "exchange", which is used between L2s.)

**Response:** opcode 0, with these arguments:

1. value 0
2. value 2: the format revision
3. strings: the configuration text, in pieces of up to 63488 bytes.
   Concatenate them.
4. the last string: the events part: what each L2 wants to receive (useful
   only between L2s)

### The text

The text is a list of `key:value,` pairs. Neither keys nor values contain
`,` or `:`. A new L2 begins at each `l2` key, a new port at each `port` key,
and a new brick at each `l1` key; the keys after it belong to that L2, port
or brick. For example (one brick, ports 2 to 39 cut):

```
l2:127.0.1.1,l2rack:0,l2os:linux,port:0,state:2,device:<l1net 0>,usbp:socket,
l1:0,rack:1,slot:2,type:67,conena:1,cstate:2,bsn:FAKE0001,ssn:,port:1,...,port:39,
```

| Key | Belongs to | Value |
|---|---|---|
| `l2` | starts an L2 | its IP address |
| `l2rack` | L2 | its rack number |
| `l2ssn` | L2 | system serial number (only if set) |
| `l2name` | L2 | system name (only if set) |
| `l2os` | L2 | `linux`, `ppclinux` (hardware L2), `armlinux`, `irix` |
| `l2pri` / `l2sec` | L2 | primary / secondary L2 mode (with the primary's address) |
| `l2dspdis` | L2 | 1 if its display is disabled |
| `DELETE_L2` | L2 | in an event: forget this L2 (it disconnected) |
| `port` | starts a port | 0 to 39. Every port is listed; one with no `state` is free. |
| `state` | port | 1 open, no configuration yet; 2 configured |
| `device`, `usbp` | port | the L1 link's device name and USB path |
| `l1` (`L1`) | starts a brick | its index on the port |
| `rack`, `slot` | brick | its rack and slot (brick 001c02 is rack 1, slot 2) |
| `type` | brick | its type, as a character code: 67 `C`, 82 `R`, 73 `I`, ... |
| `part` | brick | partition (0 or absent: none) |
| `pstate`, `mstate`, `estate`, `cstate` | brick | power, margin, environment and connection state |
| `conena`, `consub` | brick | console enabled; console subchannel |
| `rtype`, `sh_amode`, `sh_shrmode` | brick | router type; SHub address and sharing modes |
| `bsn`, `ssn` | brick | brick serial number; system serial number |

Keys with a value of 0 are left out. **The brick keys are lower case for a
port's first brick and upper case for the rest** (`l1:0,rack:1,...,L1:1,
RACK:1,...`). Compare keys case-insensitively. `parse_config()` in
`contrib/l2client.py` builds this into a tree.

A brick's name, such as `001c02`, is its rack (3 digits), its type letter
(lower case) and its slot (2 digits).

## Events

A client receives the events its CLIENT_ID process ID asked for. On ports
8000 and 8002, the low 5 bits are a mask (`l3/l2/irtr.c`):

| Bit | Events | From |
|---|---|---|
| 0x01 | brick console output, by partition | L1 task 5 |
| 0x02 | brick environment | L1 task 4 |
| 0x04 | **configuration changes** | L2 task 4 |
| 0x08 | console session output from other sessions | L2 task 2 |
| 0x10 | events from address type 7 | |

Most clients want 0x04, which is what `l2api` and the WUI use. `l2cmd` asks
for nothing (0), and a client with a mask of 0 gets no events at all. Any
other mask also brings L2 console events whose opcode is 0, and events from
L2 tasks other than 2 and 4. Ignore events you don't handle.

Events arrive as IRouter packets of class 2. To tell them apart, look at the
source's type and task (`src`) and the opcode.

### Configuration changed: L2 task 4, opcode 1000

The L2 checks its configuration every few seconds and sends this event when
it has changed, at most every 2 seconds. The arguments are:

1. value 0
2. value 2
3. the new configuration text, as a **bytes** argument (class 1, with its
   NUL), or value 0 if only the events part changed
4. the events part, the same way

The text has the same format as the response to a configuration request.
Fetch the configuration once with a request when you connect: the event
comes only on a change. An event whose text has `DELETE_L2:1` after an `l2`
key means that L2 has left the system.

### Console sessions: L2 task 2

All console (SMP) sessions, and everything the L2 prints, are reported. The
opcode is 1 for ordinary output, 0 for text meant for system consoles. The
arguments are:

1. value: 1 a session opened, 2 output, 3 a session closed, 4 console text
2. value: the session group (-1 for the L2's own messages)
3. string: the text (for 2 and 4)

Typed characters are echoed as output events one at a time, so this is a
transcript of every console session.

### Brick console output: L1 task 5

These events carry the output of a partition's system console. The text is
in their string arguments; their pdata (byte 7 >> 3) is the CPU. The L2
sends them only to clients with bit 0x01 that joined that partition's group
(the group bits in CLIENT_ID). An event with opcode 1 is a "purge" that the
L2 handles itself. For an interactive system console it is simpler to use
the console port and its `Ctrl-D` console mode.

## The application port (9002)

Port 9002 is for programs that act as one of the L2's own tasks.
`l2gui` connects there as task 6 (display); `l2part` uses it too. The handshake is the same, but the CLIENT_ID process ID is
the **task number**, not an event mask:

- The client's address becomes `0x80000000 | task << 24 | the L2's IP bits`.
  Requests from other parts of the system addressed to that L2 task are
  forwarded to the client.
- The events it gets depend on the task, in the same bits as above: task 6
  gets 0x16 (configuration, environment and type-7 events), tasks 8 and 14
  get none, and any other task gets 0xffffffe6 (all but bits 0x01, 0x08 and
  0x10).

Commands and configuration requests work as on port 8000. SGI's `l2gui`
uses `0x1ffff006` as its source address.

## The console port (8001)

Port 8001 is the L2's command line, as a person sees it over telnet (`l3/l2/smp.c`, `enet.c`). It is plain bytes in both directions, with no telnet option
negotiation and no framing:

- On connect, the L2 sends its prompt, with no newline before it:
  `<name>-<rack>-L2>`. *name* is the system name, else the serial number,
  else `?`. *rack* is three digits, or the L2's IP address while its rack is
  0 (`?-127.0.1.1-L2>`). In a partition, the prompt ends in `L2:p<n>>`.
- Send characters. CR or LF runs the line. The L2 echoes, ends lines with
  CR LF, and sends the prompt again when the command is done.
- `Ctrl-D` enters system console mode (keys go to the partition's console;
  `Ctrl-T` escapes back to the L2). `Ctrl-T` also leaves L1 mode (`l1`).
  `Ctrl-C` clears the line. Backspace and DEL rub out.
- Output from other sessions in the same group, and the L2's messages, can
  arrive at any time.
- SGI's `l2` asks for the L2 password first if one is set; this
  repository's does not.

Use 8003 to keep the connection out of the L2's log. Screen-scraping the
console (finding the prompt) is how SGI's IST tools and the original WUI
worked. Port 8000 is better for commands: each command gets exactly its own
output and a status.

## Discovery (UDP 10000)

`l3/api/SCapiL2.c` (client), `l3/l2/discover.c` (L2).

Send a UDP datagram to port 10000 at a broadcast address, or at one L2. It
may be empty, or hold `key:value` pairs separated by commas that filter which
L2s answer: `ssn:<serial>` and `name:<system name>`. (`clientid`, `l2` and
`l2pri` are used between L2s.) Every matching L2 answers to the sender's
address and port with one datagram (NUL-terminated):

```
version:1.62.0 (SW),ssn:L01234567,name:tester,rack:1,l2pri:0
```

`ssn` and `name` appear only if set; `l2pri:0` or `l2sec:0` only in primary
or secondary mode. The answer's source address is the L2's address. SGI's
tools send twice and wait a second for answers each time, and send on every
interface's broadcast address.

## A complete exchange

Captured from SGI's 1.62.0 `l2` (the same bytes as this repository's), on
port 8000. The first 8 bytes of each line are the Router header; the rest is
the body.

```
L2:     00 02 04 00 00 00 00 1c | 01 00 00 18  4c 32 00 6e 61 74 68 61 6e 00 6e 61 74 68 61 6e 2c 2c 2c 00 7f 00 01 01
```
ACCEPT (class 04) from process 2, one data argument of 0x18 bytes: the
RouterID "L2", "nathan", "nathan,,,", 127.0.1.1.

```
client: 00 00 08 00 00 00 00 28 | 01 00 00 08  00 00 40 00 00 00 00 00
                                  01 00 00 15  6c 32 63 6c 69 65 6e 74 00 6e 61 74 68 61 6e 00 00 00 00 00 00 00 00 00
```
CLIENT_ID with process ID 0 (no events): the type (`use` 0x4000, no groups),
then the RouterID "l2client", "nathan", "", 0.0.0.0, padded.

```
L2:     00 00 14 00 00 00 00 0c | 01 00 00 08  00 00 00 02 80 00 00 00     CONFIG_INIT
client: 00 00 18 00 00 00 00 0c | 01 00 00 08  00 00 00 02 80 00 00 00     CONFIG_REQ (echo)
L2:     00 00 21 00 00 00 00 0c | 01 00 00 08  00 00 00 02 80 00 00 00     CONFIG_RSP (echo)
```

The request `version` to the command task:

```
client: 00 00 80 00 00 00 00 48 | 01 00 00 03  49 52 00 00
                                  01 00 00 3c  00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00
                                               00 2c 02 00 00 81 00 00 1f ff f0 03 2f ff f0 00 02 00 00 00
                                               00 00 00 00 00 00 00 00
                                               02 01 00 08 00 00 00 34
                                               76 65 72 73 69 6f 6e 00
```
A Router EVENT with two data arguments: `"IR\0"`, then 0x3c bytes: the
16-byte prefix (byte order 1), and a 44-byte frame. The frame is rev 2,
seqnum 0, one frame (`81`), class 0 (request), dest `1ffff003`, src
`2ffff000`, 2 arguments, opcode 0. Its arguments are value 0, and a string
in frame 1 of 8 bytes at offset 0x34 - 16 = 36: `version\0`.

```
L2:     00 00 80 00 00 00 00 54 | 01 00 00 03  49 52 00 00
                                  01 00 00 48  00 00 00 00 04 00 01 00 00 00 00 00 00 00 00 00
                                               00 38 02 00 00 81 01 00 cc 00 01 01 83 00 01 01 02 00 00 00
                                               00 00 00 00 00 00 00 00
                                               0a 01 00 14 00 00 00 34
                                               4c 32 20 76 65 72 73 69 6f 6e 3a 20 31 2e 36 32 2e 30 0a 00
```
The response: class 1, seqnum 0, to `cc000101` (a client of 127.0.1.1, on
the L2's socket 0x0c), from `83000101` (that L2's task 3). Its arguments are
the status, 0, and a string of 0x14 bytes with class `0a` (string, with the
free flag): `L2 version: 1.62.0\n`.

## Checklist for a new client

1. Connect to TCP 8000. Read 8-byte headers and their bodies, so packets
   can be split or joined across reads.
2. Expect ACCEPT from process 2. Handle PASSWORD_REQ and DENIED.
3. Send CLIENT_ID: opcode = event mask (0x04 for configuration changes),
   type `00 00 40 00 00 00 00 00`, a RouterID.
4. Echo CONFIG_INIT as CONFIG_REQ, and wait for CONFIG_RSP. Queue any events
   that arrive meanwhile.
5. Send IRouter requests as Router EVENTs: `"IR\0"`, then a 16-byte prefix
   with byte 6 = 1, then the big-endian frame. Number them, and keep each
   one in a single 1024-byte frame.
6. For each EVENT from the L2 whose first argument is `"IR\0"`, strip 16
   bytes from each frame argument and decode the packet across all its
   frames. Accept frames larger than 1024 bytes.
7. Match responses by sequence number (8 bits if rev is 0). Check *err*
   before the arguments. Mask argument classes with 7.
8. Send one command at a time, and retry on `command library is busy`.
9. Fetch the configuration on connect, then follow event 1000 from
   `0x8xxxxxxx` task 4.
10. Answer DISCONNECT_REQ with DISCONNECT_RSP. Ignore PING and classes you
    don't use. Reconnect when the connection drops.
