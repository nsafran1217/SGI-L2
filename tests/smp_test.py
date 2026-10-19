#!/usr/bin/env python3
"""The L2's own consoles (SMP): the network ports and stdin.

    tests/smp_test.py

Starts 'l2 -noconn', and:
  - connects to SMP port 8001 and to the quiet port 8003, types the lines of
    tests/smp_commands.txt (Python string escapes, so editing keys can be
    sent) and records what comes back;
  - types the same lines on the daemon's stdin (the serial console) and
    records its output.
Every transcript, and the daemon's log, must match tests/golden/smp/
(tests/golden.py; only the daemon runs, so there is no interop run).
"""

import os
import re
import select
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from golden import Golden, NEW   # noqa: E402
PROMPT = re.compile(rb"L2>\s*$")


def start_l2(binary, workdir):
    os.makedirs(workdir)
    fifo = os.path.join(workdir, "stdin")
    os.mkfifo(fifo)
    logname = os.path.join(workdir, "daemon.log")
    log = open(logname, "wb")
    # l2 spins on stdin EOF: hold the fifo open read/write so reads block
    fd = os.open(fifo, os.O_RDWR)
    proc = subprocess.Popen([binary, "-noconn", "-console"], cwd=workdir, stdin=fd, stdout=log,
                            stderr=log)
    for _ in range(30):
        time.sleep(0.2)
        with open(logname, "rb") as f:
            if b"SMP listening on port: 8003" in f.read():
                return proc, fd, logname
    proc.kill()
    raise RuntimeError(f"{binary} did not start")


def read_until_prompt(sock, timeout=5.0):
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([sock], [], [], 0.2)
        if r:
            chunk = sock.recv(4096)
            if not chunk:
                break
            out += chunk
            if PROMPT.search(out):
                break
    return out


def net_session(port, lines):
    s = socket.create_connection(("127.0.0.1", port))
    out = read_until_prompt(s)
    for line in lines:
        s.sendall(line + b"\r\n")
        out += read_until_prompt(s)
    s.close()
    time.sleep(0.5)     # (l2 closes its side: the next session gets the same socket number)
    return out


def log_size(logname):
    return os.path.getsize(logname)


def wait_log_prompt(logname, start, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        with open(logname, "rb") as f:
            f.seek(start)
            if PROMPT.search(f.read()):
                return
        time.sleep(0.1)


def stdin_session(fd, logname, lines):
    for line in lines:
        start = log_size(logname)
        os.write(fd, line + b"\n")
        wait_log_prompt(logname, start)


def mask(data):
    text = data.decode("latin-1")     # (with the CRs: the console sends CR LF)
    text = re.sub(r"^.*SMP \d+ waited [0-9.]+\r?\n", "", text, flags=re.M)
    text = re.sub(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ [\d:]{8} \d{4}", "<DATE>", text)
    text = re.sub(r"\d{2}:\d{2}:\d{2}", "<TIME>", text)
    text = re.sub(r"\d{2}/\d{2}/\d{2}(\d{2})?", "<DATE>", text)
    text = re.sub(r":\d{4,5}\)", ":<PORT>)", text)      # client ports in "accepted" lines
    return text


def run(ddir, workdir, lines):
    proc, fd, logname = start_l2(os.path.join(ddir, "l2"), workdir)
    try:
        out = {"8001": net_session(8001, lines), "8003": net_session(8003, lines)}
        stdin_session(fd, logname, lines)
        time.sleep(0.3)
    finally:
        proc.terminate()
        proc.wait()
        os.close(fd)
    with open(logname, "rb") as f:
        out["daemon"] = f.read()
    return {k: mask(v) for k, v in out.items()}


def main():
    with open(os.path.join(HERE, "smp_commands.txt")) as f:
        lines = [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]
    lines = [l.encode().decode("unicode_escape").encode("latin-1") for l in lines]
    g = Golden("smp")
    work = tempfile.mkdtemp()
    try:
        new = run(NEW, os.path.join(work, "new"), lines)
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    # the rebuilt l2 alone: a line too long for the console's 128 bytes
    # rings the bell, and the console goes on working (the original's did
    # not: ORIGINAL_BUGS.md, smp.c)
    work2 = tempfile.mkdtemp()
    try:
        proc, fd, _ = start_l2(os.path.join(NEW, "l2"), os.path.join(work2, "long"))
        try:
            out = net_session(8001, [b"a" * 130, b"version"])
        finally:
            proc.terminate()
            proc.wait()
            os.close(fd)
    finally:
        shutil.rmtree(work2)
    long_ok = out.count(b"\a") == 3 and re.search(rb"version.*\n.*\d+\.\d+\.\d+", out, re.S) is not None
    g.ok &= long_ok
    print(f"{'PASS' if long_ok else 'FAIL'}  smp: a 130-character line, then a command")
    for key in new:
        g.check(key, new[key])
    return g.status()


if __name__ == "__main__":
    sys.exit(main())
