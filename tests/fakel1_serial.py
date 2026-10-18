"""A fake L1 on a serial line, for tests of L1Direct.c (l2cmd --serial/--dev).

The tool opens the line with a CR, two seconds later a CAN (0x18), and
waits for the CAN to come back; a telnet port answers with IAC WILL
instead. From then on IRouter frames (as in fakel1.py) travel in PPP
framing: 0x7e, the frame with 0x7d, 0x7e and CR escaped (0x7d, byte ^
0x20), the FCS-16 low byte first, 0x7e.

The fake answers each request with a success response echoing its text;
a text containing "fail" gets an error response, "event" an event first,
"stray" a response to some other request first, "corrupt" a frame with a
bad checksum first, and "ignore" no answer.
"""

import os
import select
import socket
import struct
import threading

from fakel1 import frame, parse, l1_addr

FLAG, ESC, CAN = 0x7e, 0x7d, 0x18
EVT = 2


def fcs16(data):
    fcs = 0xffff
    for b in data:
        fcs ^= b
        for _ in range(8):
            fcs = (fcs >> 1) ^ 0x8408 if fcs & 1 else fcs >> 1
    return fcs


def ppp_encode(data):
    fcs = fcs16(data) ^ 0xffff
    out = bytearray([FLAG])
    for b in data + bytes([fcs & 0xff, fcs >> 8]):
        if b in (FLAG, ESC, 0x0d, 0x11, 0x13):
            out += bytes([ESC, b ^ 0x20])
        else:
            out.append(b)
    out.append(FLAG)
    return bytes(out)


class FakeSerialL1(threading.Thread):
    """Serves one connection: a TCP port (mode "tcp") or a pty ("pty")."""

    def __init__(self, mode, port=0, telnet=False):
        super().__init__(daemon=True)
        self.telnet = telnet
        self.requests = []
        self.stopping = False
        if mode == "tcp":
            self.listener = socket.socket()
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(("127.0.0.1", port))
            self.listener.listen(1)
            self.port = self.listener.getsockname()[1]
            self.fd = None
        else:
            self.listener = None
            self.fd, slave = os.openpty()
            self.slave = slave
            self.device = os.ttyname(slave)
        self.start()

    def read(self, n=4096):
        for _ in range(300):        # 30 seconds, stopping when told
            if self.stopping:
                return b""
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    return os.read(self.fd, n)
                except OSError:
                    return b""
        return b""

    def write(self, data):
        os.write(self.fd, data)

    def run(self):
        if self.listener is not None:
            self.listener.settimeout(30)
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.conn = conn
            self.fd = conn.fileno()
        # the opening: wait for the CAN
        while True:
            d = self.read(1)
            if not d:
                return
            if d[0] == CAN:
                break
        if self.telnet:
            self.write(b"\xff\xfb\x01\xff\xfb\x03")
            return
        self.write(bytes([CAN]))
        buf, inframe, esc = bytearray(), False, False
        while True:
            data = self.read()
            if not data:
                return
            for b in data:
                if b == FLAG:
                    if inframe and len(buf) > 2:
                        self.handle(bytes(buf[:-2]))
                    buf, inframe, esc = bytearray(), True, False
                elif not inframe:
                    continue
                elif b == ESC:
                    esc = True
                else:
                    buf.append(b ^ 0x20 if esc else b)
                    esc = False

    def handle(self, buf):
        p = parse(buf)
        if p["clas"] != 0:
            return
        texts = [a.rstrip(b"\0").decode("latin-1") for a in p["args"] if isinstance(a, bytes)]
        self.requests.append((p["dest"], p["opcode"], p["seq0"], p["seq1"], texts))
        text = " ".join(texts)
        me = l1_addr(1, 2, p["dest"] & 0x1f)
        if "ignore" in text:
            return
        if "corrupt" in text:       # a frame with a bad FCS first
            bad = bytearray(ppp_encode(frame(p, [0, b"corrupted\0"], src=me)))
            bad[-2] ^= 0x01 if bad[-2] not in (0x7c, 0x7f, 0x5c, 0x5f) else 0x02
            self.write(bytes(bad))
        if "stray" in text:         # a response to another request
            stray = bytearray(frame(p, [7, b"a stray response\0"], src=me))
            stray[4] ^= 0x55        # (its sequence number)
            self.write(ppp_encode(bytes(stray)))
        if "event" in text:         # an event first (the class is header byte 6)
            ev = bytearray(frame(p, [7, b"an event\0"], src=me))
            ev[6] = EVT
            self.write(ppp_encode(bytes(ev)))
        reply = ("fake L1: %s\n" % text).encode() + b"\0"
        err = 5 if "fail" in text else 0
        self.write(ppp_encode(frame(p, [0, reply], err=err, src=me)))

    def close(self):
        # (the thread must be done before the descriptors go: a new pty
        # would get the same numbers)
        self.stopping = True
        self.join()
        for f in (getattr(self, "conn", None), self.listener):
            if f is not None:
                f.close()
        if self.listener is None:
            os.close(self.fd)
            os.close(self.slave)
