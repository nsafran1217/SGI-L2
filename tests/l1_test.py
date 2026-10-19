#!/usr/bin/env python3
"""The L1 side of l2, with a fake L1.

    tests/l1_test.py

The other tests run 'l2 -noconn', so no brick is ever known. Here l2 runs
'-net' and a fake L1 (tests/fakel1.py) connects to its L1 port, reporting
one brick (001c02). Each command in tests/l1_commands.txt then goes through
l2cmd, and each line of tests/l1_console_commands.txt is typed at the L2's
console (SMP port 8001, for commands only the console has, such as
loopback). The transcript and the requests the fake L1 receives must match
tests/golden/l1/. INTEROP=1 runs the session again with SGI's original
l2cmd (tests/golden.py).
"""

import os
import re
import select
import socket
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fakel1 import FakeL1   # noqa: E402
from golden import Golden, INTEROP, NEW, ORIG   # noqa: E402


def mask(text):
    text = re.sub(r"^.*SMP \d+ waited [0-9.]+\n", "", text, flags=re.M)
    text = re.sub(r"^INFO: (attempting connection|connection to) .*\n", "", text, flags=re.M)
    text = re.sub(r"\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", "<DATE>", text)
    return re.sub(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ [\d:]{8} \d{4}", "<DATE>", text)


def console(lines):
    """Type lines at SMP port 8001; the transcript, timings masked."""
    prompt = re.compile(rb"L2>\s*$")
    time.sleep(1)                       # let the last l2cmd's disconnection be logged
    s = socket.create_connection(("127.0.0.1", 8001))

    def until_prompt():
        out, end = b"", time.time() + 10
        while time.time() < end and not prompt.search(out):
            if select.select([s], [], [], 0.2)[0]:
                chunk = s.recv(4096)
                if not chunk:
                    break
                out += chunk
        return out

    out = until_prompt()
    for line in lines:
        s.sendall(line.encode() + b"\r")   # (a newline as well would abort a loopback)
        out += until_prompt()
    s.close()
    text = out.decode("latin-1").replace("\r", "")
    text = re.sub(r"(time|average|min pkt|max pkt|) +[0-9.]+ (seconds|bytes/second)",
                  r"\1 <N> \2", text)
    # route traces: the L2's entries are stamped with the time of day
    text = re.sub(r"^((?:REQ|RSP): .*?) +-?\d+ \((\s*\d+)\)$",
                  lambda m: f"{m[1]} <N> ({'<T>' if ' L2-' in m[1] else m[2]})", text, flags=re.M)
    return text


def session(l2bin, l2cmd, env, commands, work, name):
    d = os.path.join(work, name)
    os.makedirs(d)
    fifo = os.path.join(d, "stdin")
    os.mkfifo(fifo)
    log = open(os.path.join(d, "daemon.log"), "wb")
    fd = os.open(fifo, os.O_RDWR)        # l2 spins on stdin EOF
    proc = subprocess.Popen([l2bin, "-net"], cwd=d, stdin=fd, stdout=log, stderr=log,
                            env=dict(os.environ, **env))
    os.close(fd)
    try:
        for _ in range(30):
            time.sleep(0.2)
            with open(log.name, "rb") as f:
                if b"SMP listening on port: 8003" in f.read():
                    break
        else:
            raise RuntimeError(f"{l2bin} did not start")
        l1 = FakeL1()
        for _ in range(50):             # wait for the brick to be configured
            time.sleep(0.2)
            if l1.config_requests >= 1:
                break
        time.sleep(1)
        out = []
        for c in commands:
            r = subprocess.run([l2cmd, "--l2", "127.0.0.1", *c.split()],
                               capture_output=True, text=True, errors="replace", timeout=30)
            out.append(f"=== {c}\n{mask(r.stdout + r.stderr)}")
        with open(os.path.join(HERE, "l1_console_commands.txt")) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        out.append(f"=== console\n{mask(console(lines))}")
        # an IRouter error from the brick (the original l2's heap broke
        # here, ORIGINAL_BUGS.md, cmd.c)
        r = subprocess.run([l2cmd, "--l2", "127.0.0.1", "r", "1", "s",
                            "2", "l1", "errtest"], capture_output=True, text=True,
                           errors="replace", timeout=30)
        time.sleep(0.5)
        if "ERROR: couldn't send packet to 001c02" not in r.stdout + r.stderr \
                or proc.poll() is not None:
            out.append(f"=== errtest (new only) failed:\n{r.stdout}{r.stderr}")
        l1.requests = [q for q in l1.requests
                       if not any(isinstance(t, str) and "errtest" in t for t in q[1])]
        l1.close()
        return "".join(out), l1.requests
    finally:
        proc.terminate()
        proc.wait()


def main():
    commands = [l.strip() for l in open(os.path.join(HERE, "l1_commands.txt")) if l.strip()]
    g = Golden("l1")
    work = tempfile.mkdtemp()
    try:
        runs = [("l2cmd=new", NEW)] + ([("l2cmd=orig", ORIG)] if INTEROP else [])
        for label, cdir in runs:
            text, reqs = session(os.path.join(NEW, "l2"), os.path.join(cdir, "l2cmd"), {},
                                 commands, work, label)
            with open(os.path.join(work, label, "transcript.txt"), "w") as f:
                f.write(text)
            g.check("transcript", text, label)
            g.check("l1_requests", reqs, label)
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    print(f"{len(commands)} commands")
    return g.status()


if __name__ == "__main__":
    sys.exit(main())
