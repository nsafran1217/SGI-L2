#!/usr/bin/env python3
"""Smoke test of the L1 side of l2: a fake L1 over the network port.

    tests/l1net_test.py

The other tests run 'l2 -noconn', so no L1 code runs in them. Here the
rebuilt 'l2 -net' accepts a TCP connection on the L1 port (9003), as from an
L1 simulator, and must keep sending configuration pings (every 2 seconds
until an L1 answers) without crashing; cfg_ping_l1() once crashed on its
reschedule. Not differential: the original can't open the port on hosts
without /usr/tmp. NEW_BIN selects the rebuilt binaries, as in difftest.sh.
"""

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
NEW = os.environ.get("NEW_BIN", os.path.join(SRC, "build/bin"))
L1_PORT = 9003


def main():
    work = tempfile.mkdtemp()
    try:
        fifo = os.path.join(work, "stdin")
        os.mkfifo(fifo)
        log = open(os.path.join(work, "daemon.log"), "wb")
        fd = os.open(fifo, os.O_RDWR)        # l2 spins on stdin EOF
        proc = subprocess.Popen([os.path.join(NEW, "l2"), "-net"], cwd=work, stdin=fd,
                                stdout=log, stderr=log)
        os.close(fd)
        for _ in range(30):
            time.sleep(0.2)
            with open(log.name, "rb") as f:
                if b"SMP listening on port: 8003" in f.read():
                    break
        pings = 0
        s = socket.create_connection(("127.0.0.1", L1_PORT))
        s.settimeout(0.5)
        end = time.time() + 7
        while time.time() < end:
            try:
                if s.recv(4096):
                    pings += 1
            except socket.timeout:
                pass
        s.close()
        time.sleep(0.5)
        alive = proc.poll() is None
        proc.terminate()
        proc.wait()
        ok = alive and pings >= 3
        print(f"{'PASS' if ok else 'FAIL'}  l1net: {pings} configuration pings to a fake L1, "
              f"l2 {'still running' if alive else 'died'}")
        if not ok:
            print(open(log.name, errors="replace").read()[-800:])
    finally:
        shutil.rmtree(work)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
