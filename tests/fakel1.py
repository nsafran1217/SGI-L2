"""A fake L1 for tests: speaks IRouter frames on the L2's L1 network port.

l2 -net accepts L1 connections on port 9003 (as from SGI's L1 simulator).
The fake L1 answers the L2's configuration request (task IR_L1_CFG, first
argument 6) with one brick, echoes loopback requests (task 0x12), adds its
entry to route requests (task 0x17), answers a request whose text contains
"errtest" with an IRouter error, and answers every other request with a success response
whose text echoes the request; it records the text of each request it gets.

Frames are big-endian: a 20-byte header (size, rev, err, seqnum0, fnum,
class, pdata/auth, dest, src, argc, seqnum1, opcode), 8-byte arguments
(class, frame, size, value), then argument data. A data argument's value is
its offset in the frame + 16, and its frame number counts from 1.
"""

import socket
import struct
import threading

REQ, RSP = 0, 1
L1_CFG = 14
L1_LPBK = 0x12                  # the loopback task: requests are echoed
L1_ROUTE = 0x17                 # the route task: this L1 adds its entry


def l1_addr(rack, slot, task):
    return rack << 18 | slot << 12 | task


def l1cfg(rack, slot, brick_type, partition=0, power=0, sn=b"FAKE0001"):
    """An L1CfgL1 (112 bytes, big-endian ints, as an L1 sends it)."""
    f = struct.pack(">7iBBHiiiiiiii", 1, 1, rack, slot, brick_type, 0, 1, 0, 0, 0, 0,
                    0, 0, 0, 0, power, 0, partition)
    f += sn.ljust(12, b"\0") + b"\0" * 12
    f += struct.pack(">iIi", 0, 0, 0) + b"\0" * 12
    assert len(f) == 112
    return f


def frame(req, args, err=0, src=None):
    """A one-frame response to req; args: ints (inline) or bytes (data)."""
    n = len(args)
    data, argv = b"", b""
    off = 20 + 8 * n
    for a in args:
        if isinstance(a, int):
            argv += struct.pack(">BBHI", 0, 0, 0, a & 0xffffffff)
        else:
            argv += struct.pack(">BBHI", 2, 1, len(a), off + len(data) + 16)
            data += a
    size = 20 + len(argv) + len(data)
    hdr = struct.pack(">HBBBBBBIIBBH", size, 2, err, req["seq0"], 0x81, RSP, 0,
                      req["src"], src, n, req["seq1"], req["opcode"])
    return hdr + argv + data


def parse(buf):
    size, rev, err, seq0, fnum, clas, pa, dest, src, argc, seq1, opcode = \
        struct.unpack(">HBBBBBBIIBBH", buf[:20])
    args = []
    for i in range(argc):
        c, fr, sz, val = struct.unpack(">BBHI", buf[20 + 8 * i:28 + 8 * i])
        if c & 7:
            args.append(buf[val - 16:val - 16 + sz])
        else:
            args.append(val)
    return dict(clas=clas, dest=dest, src=src, seq0=seq0, seq1=seq1, opcode=opcode,
                fnum=fnum, args=args)


class FakeL1(threading.Thread):
    def __init__(self, port=9003, rack=1, slot=2, brick_type=ord("C"), sock=None):
        """sock: an accepted SOCK_SEQPACKET connection instead (a fake USB
        device, tests/libusb_shim.c), one frame per message."""
        super().__init__(daemon=True)
        self.packet = sock is not None
        self.sock = sock if sock is not None else socket.create_connection(("127.0.0.1", port))
        self.rack, self.slot, self.type = rack, slot, brick_type
        self.requests = []          # (dest task, texts) of non-config requests
        self.config_requests = 0
        self.start()

    def recv_frame(self):
        if self.packet:
            return self.sock.recv(65536) or None
        hdr = b""
        while len(hdr) < 2:
            d = self.sock.recv(2 - len(hdr))
            if not d:
                return None
            hdr += d
        size = struct.unpack(">H", hdr)[0]
        buf = hdr
        while len(buf) < size:
            d = self.sock.recv(size - len(buf))
            if not d:
                return None
            buf += d
        return buf

    def run(self):
        try:
            while True:
                buf = self.recv_frame()
                if buf is None:
                    return
                p = parse(buf)
                if p["clas"] != REQ:
                    continue
                task = p["dest"] & 0x1f
                me = l1_addr(self.rack, self.slot, task)
                if task == L1_LPBK:
                    # echo the session and the data; record only the data's length
                    self.requests.append((task, [len(a) if isinstance(a, bytes) else a
                                                 for a in p["args"]]))
                    self.sock.sendall(frame(p, p["args"], src=me))
                elif task == L1_ROUTE:
                    # the first free pair: this brick (a response), in port IIA
                    # (33), out port NIA (1), time 1234
                    args = list(p["args"])
                    for i in range(0, len(args) - 1, 2):
                        if args[i] == 0:
                            args[i] = 1 << 30 | self.slot << 20 | self.rack << 10 | self.type
                            args[i + 1] = 33 << 24 | 1 << 16 | 1234
                            break
                    self.requests.append((task, [len(args)]))
                    self.sock.sendall(frame(p, args, src=me))
                elif task == L1_CFG and p["args"] and p["args"][0] == 6:
                    self.config_requests += 1
                    cfg = [l1cfg(self.rack, self.slot, self.type)] + [b"\0" * 112] * 3
                    self.sock.sendall(frame(p, [6] + cfg, src=me))
                else:
                    texts = [a.rstrip(b"\0").decode("latin-1") for a in p["args"]
                             if isinstance(a, bytes)]
                    self.requests.append((task, texts))
                    reply = ("fake L1 %03d%c%02d: %s\n" % (self.rack, self.type, self.slot,
                                                           " ".join(texts))).encode() + b"\0"
                    # "errtest": an IRouter error instead (5, "invalid opcode"?)
                    err = 5 if any("errtest" in t for t in texts) else 0
                    self.sock.sendall(frame(p, [] if err else [0, reply], err=err, src=me))
        except OSError:
            return

    def close(self):
        self.sock.close()
