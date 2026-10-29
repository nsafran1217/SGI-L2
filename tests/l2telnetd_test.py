#!/usr/bin/env python3
"""l2telnetd: the L2's console for telnet clients.

    tests/l2telnetd_test.py

Starts 'l2 -noconn' and runs l2telnetd as inetd would, with one end of a
socket pair as its stdin and stdout, then checks that:
  - it asks the client for character mode (WILL ECHO, WILL SUPPRESS-GO-AHEAD);
  - the client's option negotiation, split across writes, never reaches the
    L2, and CR NUL and CR LF reach it as CR: the L2 echoes exactly what it got;
  - the console answers (version), and l2telnetd ends when the client goes;
  - with no L2 to connect to, the client is told so.
"""

import os
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from golden import NEW   # noqa: E402
from smp_test import start_l2   # noqa: E402

IAC, WILL, DO, SB, SE = 255, 251, 253, 250, 240
fails = 0


def check(name, ok, detail=b""):
    global fails
    print(f"{'PASS' if ok else 'FAIL'}  l2telnetd {name}")
    if not ok:
        fails += 1
        print(f"      got {detail!r}")


def read_for(sock, secs, until=None):
    out = b""
    end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], 0.1)
        if r:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if until is not None and out.endswith(until):
                break
    return out


def l2telnetd(*args, stderr=None):
    ours, theirs = socket.socketpair()
    proc = subprocess.Popen([os.path.join(NEW, "l2telnetd"), *args], stdin=theirs, stdout=theirs,
                            stderr=stderr)
    theirs.close()
    return proc, ours


def main():
    work = tempfile.mkdtemp(prefix="l2telnetd_test.")
    l2, fd, _ = start_l2(os.path.join(NEW, "l2"), os.path.join(work, "l2"))
    try:
        proc, s = l2telnetd()
        out = read_for(s, 3, until=b"L2>")
        check("asks for character mode", out.startswith(bytes([IAC, WILL, 1, IAC, WILL, 3])), out)
        check("gives the prompt", out.endswith(b"L2>"), out)

        # a client's opening (WILL TTYPE, DO ECHO, the window size), a
        # byte at a time where it can hurt, then the keys
        for part in (bytes([IAC]), bytes([WILL]), bytes([24]),
                     bytes([IAC, DO, 1, IAC, SB, 31, 0, 80]), bytes([0, 24, IAC]), bytes([SE])):
            s.sendall(part)
            time.sleep(0.05)
        for ch in b"version\r\0":
            s.sendall(bytes([ch]))
            time.sleep(0.02)
        out = read_for(s, 3, until=b"L2>")
        check("passes keys, not options (CR NUL)", out.startswith(b"version\r\nL2 version: "), out)
        s.sendall(b"version\r\n")
        out = read_for(s, 3, until=b"L2>")
        check("CR LF as one CR", out.startswith(b"version\r\nL2 version: ") and out.count(b"L2>") == 1, out)

        s.close()
        try:
            rc = proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            rc = None
        check("ends with the client", rc == 0, str(rc).encode())
    finally:
        l2.kill()
        l2.wait()
        os.close(fd)

    # (the L2's port, with no l2 there now)
    proc, s = l2telnetd("--port", "8001", stderr=subprocess.DEVNULL)
    out = read_for(s, 3)
    rc = proc.wait(timeout=5)
    check("no L2", out.startswith(b"can't connect to the L2 at localhost:8001") and rc == 1, out)
    s.close()
    if not os.environ.get("KEEP"):
        shutil.rmtree(work)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
