#!/usr/bin/env python3
"""Differential test of the L2's own consoles (SMP): the network ports and stdin.

    tests/smp_test.py [ORIG_BIN_DIR]

Starts the original and the rebuilt 'l2 -noconn', and in each:
  - connects to SMP port 8001 and to the quiet port 8003, types the lines of
    tests/smp_commands.txt (Python string escapes, so editing keys can be
    sent) and records what comes back;
  - types the same lines on the daemon's stdin (the serial console) and
    records its output.
Every transcript, and the daemon's log, must match the original's.
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
SRC = os.path.dirname(HERE)
ORIG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    SRC, "..", "ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin")
NEW = os.environ.get("NEW_BIN", os.path.join(SRC, "build/bin"))
PROMPT = re.compile(rb"L2>\s*$")


def start_l2(binary, workdir):
    os.makedirs(workdir)
    fifo = os.path.join(workdir, "stdin")
    os.mkfifo(fifo)
    logname = os.path.join(workdir, "daemon.log")
    log = open(logname, "wb")
    # l2 spins on stdin EOF: hold the fifo open read/write so reads block
    fd = os.open(fifo, os.O_RDWR)
    proc = subprocess.Popen([binary, "-noconn"], cwd=workdir, stdin=fd, stdout=log, stderr=log)
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
    text = data.decode("latin-1").replace("\r", "")
    text = re.sub(r"^.*SMP \d+ waited [0-9.]+\n", "", text, flags=re.M)
    text = re.sub(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ [\d:]{8} \d{4}", "<DATE>", text)
    text = re.sub(r"\d{2}:\d{2}:\d{2}", "<TIME>", text)
    text = re.sub(r"\d{2}/\d{2}/\d{2}", "<DATE>", text)
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
    work = tempfile.mkdtemp()
    try:
        ref = run(ORIG, os.path.join(work, "orig"), lines)
        new = run(NEW, os.path.join(work, "new"), lines)
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    ok = True
    for key in ref:
        same = new[key] == ref[key]
        ok &= same
        print(f"{'PASS' if same else 'FAIL'}  smp {key}: {len(ref[key].splitlines())} lines")
        if not same:
            import difflib
            for line in list(difflib.unified_diff(ref[key].split("\n"), new[key].split("\n"),
                                                  lineterm=""))[:40]:
                print("   ", line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
