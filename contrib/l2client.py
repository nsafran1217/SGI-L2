#!/usr/bin/env python3
"""A minimal L3 client of an SGI L2, in plain Python: the reference
implementation for PROTOCOL.md (standard library only, Python 3.8+).

    l2client.py HOST cmd 'cfg s'       run L2 commands, as l2cmd does
    l2client.py HOST config            the L2's configuration, decoded
    l2client.py HOST events [MASK]     print the events the L2 sends
    l2client.py HOST discover          (HOST: a broadcast address) find L2s

Options: --port N (default 8000), --password PW, --trace (dump frames).
"""

import argparse
import os
import socket
import struct
import sys
import time

# ---- Router: the connection (PROTOCOL.md, "Router packets") ----

PASSWORD_REQ, PASSWORD, ACCEPT, CLIENT_ID = 0x01, 0x02, 0x04, 0x08
REQUEST, DISCONNECT_REQ, DISCONNECT_RSP = 0x10, 0x11, 0x12
CONFIG_INIT, CONFIG_REQ, REL_REQUEST, CONFIG_RSP = 0x14, 0x18, 0x20, 0x21
DENIED, PING, RESPONSE, EVENT = 0x22, 0x24, 0x40, 0x80
SERVER_PROCESS_ID = 2
RU_CONFIGURE = 0x4000
RH_COMPRESSED = 0x80

trace = False


def router_pack(opcode, clas, args=(), pid=0):
    """A Router packet whose arguments are all data (bytes)."""
    body = b""
    for a in args:
        body += struct.pack(">I", 1 << 24 | len(a)) + a + b"\0" * (-len(a) % 4)
    return struct.pack(">HBBB", opcode, clas, pid, 0) + len(body).to_bytes(3, "big") + body


def router_unpack(body):
    """The arguments: data as bytes, values as ints. (An argument word in
    the last 4 bytes is not read, as SGI's RouterUnpack() does.)"""
    args, p = [], 0
    while p + 4 < len(body):
        w, = struct.unpack_from(">I", body, p)
        clas, size = w >> 24, w & 0xffffff
        p += 4
        if clas == 0:
            args.append(struct.unpack_from("<I", body, p)[0])   # little-endian (i386)
            p += 4
        else:
            args.append(body[p:p + size])
            p += size + (-size % 4)
    return args


def uncompress(buf):
    """BuffUncompress(): never used by SGI's L2s (PROTOCOL.md), kept for safety."""
    size, = struct.unpack_from(">I", buf)
    out, i = bytearray(), 4
    while i < len(buf):
        c, n = buf[i], 1
        i += 1
        if c == 0xfe:
            n, c = buf[i], buf[i + 1]
            i += 2
        elif c == 0xfd:
            n, c = buf[i] << 8 | buf[i + 1], buf[i + 2]
            i += 3
        out += bytes([c]) * n
    return bytes(out[:size])


def router_id(procname):
    """RouterPackID(): procname, username, full name (NUL-terminated), IPv4."""
    user = os.environ.get("USER") or "l2client"
    return (procname[:16].encode() + b"\0" + user[:8].encode() + b"\0" + b"\0" +
            b"\0\0\0\0")


class RouterConnection:
    def __init__(self, host, port, process_id, password=""):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b""
        tries = 0
        # the handshake: ACCEPT (or PASSWORD_REQ / DENIED) from the server
        while True:
            opcode, clas, args = self.recv()
            if opcode != SERVER_PROCESS_ID:
                raise ConnectionError(f"not an L2 (process ID {opcode})")
            if clas == ACCEPT:
                break
            if clas == PASSWORD_REQ:
                tries += 1
                if tries > 3:
                    raise ConnectionError("password refused")
                self.send(router_pack(process_id, PASSWORD, [password.encode() + b"\0"]))
            elif clas == DENIED:
                raise ConnectionError("connection denied" + (" (password)" if tries else ""))
            else:
                raise ConnectionError(f"unexpected class 0x{clas:x} in handshake")
        ctype = struct.pack(">II", RU_CONFIGURE, 0)       # use, group count
        self.send(router_pack(process_id, CLIENT_ID, [ctype, router_id("l2client")]))
        # the configuration exchange: CONFIG_INIT -> CONFIG_REQ -> CONFIG_RSP.
        # Events may come in between: keep them for later.
        self.early = []
        while True:
            opcode, clas, args = self.recv()
            if clas == CONFIG_INIT:
                self.send(router_pack(0, CONFIG_REQ, args[:1]))
            elif clas == CONFIG_RSP:
                break
            elif clas == EVENT:
                self.early.append((opcode, clas, args))
            elif clas != PING:
                raise ConnectionError(f"unexpected class 0x{clas:x} in configuration")
        self.sock.settimeout(None)

    def send(self, pkt):
        self.sock.sendall(pkt)

    def recv(self):
        """The next packet: (opcode, class, arguments)."""
        if getattr(self, "early", None):
            return self.early.pop(0)
        while True:
            if len(self.buf) >= 8:
                length = int.from_bytes(self.buf[5:8], "big")
                if len(self.buf) >= 8 + length:
                    hdr, body = self.buf[:8], self.buf[8:8 + length]
                    self.buf = self.buf[8 + length:]
                    opcode, clas, pid, config = struct.unpack(">HBBB", hdr[:5])
                    if config & RH_COMPRESSED:
                        body = uncompress(body)
                    if clas == DISCONNECT_REQ:
                        self.send(router_pack(0, DISCONNECT_RSP))
                        raise ConnectionError("the L2 disconnected")
                    return opcode, clas, router_unpack(body)
            d = self.sock.recv(65536)
            if not d:
                raise ConnectionError("connection closed")
            self.buf += d

    def close(self):
        self.sock.close()


# ---- IRouter: the messages (PROTOCOL.md, "IRouter packets") ----

REQ, RSP, EVT = 0, 1, 2
ARG_VALUE, ARG_BYTES, ARG_STRING = 0, 1, 2
FRAME_HDR = 20
L3_ADDR = 0x2ffff000                    # an L3 client (rack, slot all ones)
L2_CMD = 0x1ffff003                     # the L2's command task
L2_CFG = 0x1ffff004                     # its configuration task
# the 16 bytes before each frame in a Router event: i386 memory, with the
# byte-order flag (1 = big-endian) at offset 6
FRAME_PREFIX = bytes(6) + b"\x01" + bytes(9)

ERRORS = ["none", "bad packet type", "bad task ID", "duplicate target ID", "malloc failed",
          "duplicate task ID", "bad event entry", "bad argument count", "no receiver",
          "no device", "send to full queue", "queue full", "read error", "not first frame",
          "unexpected frame", "select() error", "multiframe read timeout", "write failed",
          "sequence ID mismatch", "wait further", "timeout", "end of file",
          "write: end of file", "frame incomplete", "frame overflow", "frame underflow",
          "frame control", "response too large"]


def ir_encode(clas, seq, dest, src, args, opcode=0):
    """A one-frame packet. args: ints (values) and str/bytes (strings with
    their NUL added). At most 1024 bytes."""
    data, argv = b"", b""
    off = FRAME_HDR + 8 * len(args)
    for a in args:
        if isinstance(a, int):
            argv += struct.pack(">BBHI", ARG_VALUE, 0, 0, a & 0xffffffff)
            continue
        b = (a.encode("latin-1") if isinstance(a, str) else a) + b"\0"
        argv += struct.pack(">BBHI", ARG_STRING, 1, len(b), off + len(data) + 16)
        data += b
    size = FRAME_HDR + len(argv) + len(data)
    if size > 0x400:
        raise ValueError("request too large for one frame")
    hdr = struct.pack(">HBBBBBBIIBBH", size, 2, 0, seq & 0xff, 0x81, clas, 0,
                      dest, src, len(args), seq >> 8 & 0xff, opcode)
    return hdr + argv + data


def ir_decode(frames):
    """A packet from its frames (bytes, prefix removed): a dict with the
    header and args (ints, or bytes; strings without their NUL as str)."""
    f = frames[0]
    (size, rev, err, seq0, fnum, clas, pa, dest, src, argc, seq1,
     opcode) = struct.unpack_from(">HBBBBBBIIBBH", f)
    pkt = dict(rev=rev, err=err, seq=seq1 << 8 | seq0, clas=clas, pdata=pa >> 3,
               dest=dest, src=src, opcode=opcode, args=[])
    for i in range(argc):
        aclas, fno, asize, val = struct.unpack_from(">BBHI", f, FRAME_HDR + 8 * i)
        if aclas & 7 == ARG_VALUE:
            pkt["args"].append(val)
            continue
        # asize bytes from frame fno at val - 16, running on into the next
        # frames after their 20-byte header
        data, k, start = b"", fno - 1, val - 16
        while len(data) < asize:
            fr = frames[k]
            data += fr[start:start + asize - len(data)]
            k, start = k + 1, FRAME_HDR
        if aclas & 7 == ARG_STRING:
            data = data.split(b"\0", 1)[0].decode("latin-1")
        pkt["args"].append(data)
    return pkt


def fmt_addr(a):
    if a & 0x80000000:
        return f"IP({'L2' if a >> 30 == 2 else 'client'}, task {a >> 24 & 0x3f}, .{a & 0xffffff:06x})"
    return f"type {a >> 28} rack {a >> 18 & 0x3ff} slot {a >> 12 & 0x3f} task {a & 0x1f}"


class L2Client:
    """An L3 client: IRouter packets in Router events on port 8000."""

    def __init__(self, host, port=8000, events=0, password=""):
        self.conn = RouterConnection(host, port, events, password)
        self.seq = 0
        self.pending = []           # packets that came while waiting for a response

    def send(self, dest, args, clas=REQ):
        seq = self.seq
        self.seq = (self.seq + 1) & 0xffff
        frame = ir_encode(clas, seq, dest, L3_ADDR, args)
        if trace:
            print("> " + frame.hex(), file=sys.stderr)
        self.conn.send(router_pack(0, EVENT, [b"IR\0", FRAME_PREFIX + frame]))
        return seq

    def packet(self):
        """The next IRouter packet the L2 sends."""
        if self.pending:
            return self.pending.pop(0)
        while True:
            opcode, clas, args = self.conn.recv()
            if clas != EVENT or not args or args[0][:3] != b"IR\0":
                continue
            frames = [a[16:] for a in args[1:]]
            if trace:
                for fr in frames:
                    print("< " + fr.hex(), file=sys.stderr)
            return ir_decode(frames)

    def request(self, dest, args, timeout=30):
        seq = self.send(dest, args)
        end = time.time() + timeout
        held = []
        try:
            while time.time() < end:
                self.conn.sock.settimeout(max(end - time.time(), 0.01))
                try:
                    p = self.packet()
                except socket.timeout:
                    break
                # (revision 0 packets carry only 8 bits of sequence number)
                if p["clas"] == RSP and p["seq"] == (seq & 0xff if p["rev"] == 0 else seq):
                    return p
                held.append(p)
            raise TimeoutError("no response from the L2")
        finally:
            self.conn.sock.settimeout(None)
            self.pending = held + self.pending

    def command(self, line):
        """One command, as typed at the L2> prompt: (status, output)."""
        p = self.request(L2_CMD, [0, line])
        if p["err"]:
            return -600 - p["err"], f"Command response ERROR: {ERRORS[p['err']]}\n"
        out = ""
        for a in p["args"]:
            if isinstance(a, str):
                out += a if a.endswith("\n") else a + "\n"
        status = p["args"][0] if p["args"] and isinstance(p["args"][0], int) else 0
        return (status - (1 << 32) if status & 0x80000000 else status), out

    def config(self):
        """The configuration text (the L2 and its peers, with their bricks)."""
        p = self.request(L2_CFG, [0])
        if p["err"]:
            raise RuntimeError(ERRORS[p["err"]])
        return "".join(a for a in p["args"][2:-1] if isinstance(a, str)), p["args"][-1]


def parse_config(text):
    """The "key:value," text as a list of L2s, each with its ports and L1s."""
    l2s = []
    l2 = port = l1 = None
    for pair in text.split(","):
        if not pair:
            continue
        key, _, val = pair.partition(":")
        k = key.lower()
        if k == "l2":
            l2 = {"ip": val, "ports": []}
            l2s.append(l2)
        elif k == "port" and l2 is not None:
            port = {"port": int(val), "l1s": []}
            l2["ports"].append(port)
        elif k == "l1" and port is not None:
            l1 = {"l1": int(val)}
            port["l1s"].append(l1)
        elif l1 is not None and k in ("rack", "slot", "type", "conena", "consub", "rtype",
                                      "sh_amode", "sh_shrmode", "pstate", "mstate", "estate",
                                      "cstate", "part", "bsn", "ssn"):
            l1[k] = val if k in ("bsn", "ssn") else int(val)
        elif port is not None and k in ("state", "device", "usbp"):
            port[k] = int(val) if k == "state" else val
        elif l2 is not None:
            l2[k] = val
    for l2 in l2s:                      # (a port with no state is free)
        l2["ports"] = [p for p in l2["ports"] if "state" in p]
    return l2s


def discover(bcast, port=10000, wait=2.0):
    """L2 discovery: one UDP datagram, every L2 answers."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("", 0))
    s.sendto(b"", (bcast, port))
    s.settimeout(wait)
    found = []
    try:
        while True:
            data, (ip, _) = s.recvfrom(8192)
            found.append((ip, data.rstrip(b"\0").decode("latin-1")))
    except socket.timeout:
        pass
    return found


def main():
    global trace
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("host")
    ap.add_argument("what", choices=["cmd", "config", "events", "discover"])
    ap.add_argument("rest", nargs="*")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--password", default=None)
    ap.add_argument("--trace", action="store_true")
    a = ap.parse_args()
    trace = a.trace
    pw = a.password if a.password is not None else os.environ.get("L2_PASSWORD", "")

    if a.what == "discover":
        for ip, text in discover(a.host):
            print(ip, text)
        return 0
    if a.what == "cmd":
        c = L2Client(a.host, a.port, 0, pw)
        status = 0
        for part in " ".join(a.rest).split(";"):
            if part.strip():
                status, out = c.command(part.strip())
                (sys.stdout if status == 0 else sys.stderr).write(out)
        return status & 0xff
    if a.what == "config":
        c = L2Client(a.host, a.port, 0, pw)
        text, events = c.config()
        print(text)
        print(events)
        for l2 in parse_config(text):
            print(l2)
        return 0
    mask = int(a.rest[0], 0) if a.rest else 0x0f
    c = L2Client(a.host, a.port, mask, pw)
    while True:
        p = c.packet()
        print(["REQ", "RSP", "EVT"][p["clas"]] if p["clas"] < 3 else p["clas"],
              fmt_addr(p["src"]), "opcode", p["opcode"], p["args"])


if __name__ == "__main__":
    sys.exit(main())
