#!/usr/bin/env python3
"""Interactive sessions: drive l2term in a pty.

    tests/l2term_test.py

Open a session against 'l2 -noconn' (in a temp directory, see difftest.sh),
wait for the L2 prompt, type each command from tests/l2term_commands.txt,
and compare the transcript with tests/golden/l2term/. INTEROP=1 also runs
SGI's original l2term and l2 (tests/golden.py).
"""

import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from golden import Golden, INTEROP, NEW, ORIG   # noqa: E402
PROMPT = re.compile(rb"L2>\s*$")


def start_l2(binary, workdir):
    os.makedirs(workdir)
    fifo = os.path.join(workdir, "stdin")
    os.mkfifo(fifo)
    log = open(os.path.join(workdir, "daemon.log"), "wb")
    # l2 spins on stdin EOF: hold a fifo open read/write so reads just block
    fd = os.open(fifo, os.O_RDWR)
    proc = subprocess.Popen([binary, "-noconn"], cwd=workdir, stdin=fd, stdout=log, stderr=log)
    os.close(fd)
    for _ in range(30):
        time.sleep(0.2)
        with open(log.name, "rb") as f:
            if b"SMP listening on port: 8003" in f.read():
                return proc
    proc.kill()
    raise RuntimeError(f"{binary} did not start")


def read_until_prompt(fd, timeout=8.0):
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
            if PROMPT.search(out):
                break
    return out


def session(l2term, commands):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(l2term, [l2term, "--l2", "127.0.0.1"])
    transcript = read_until_prompt(fd)
    for c in commands:
        os.write(fd, c.encode() + b"\r")
        transcript += read_until_prompt(fd)
    os.write(fd, b"\x1dq")              # CTRL-] q: leave l2term
    time.sleep(0.5)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    os.close(fd)
    return mask(transcript.decode("latin-1"))


def mask(text):
    text = text.replace("\r", "")
    text = re.sub(r"^.*SMP \d+ waited [0-9.]+\n", "", text, flags=re.M)
    text = re.sub(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ [\d:]{8} \d{4}", "<DATE>", text)
    text = re.sub(r"\d{2}:\d{2}:\d{2}", "<TIME>", text)
    text = re.sub(r"\d{2}/\d{2}/\d{2}", "<DATE>", text)
    return text


def main():
    with open(os.path.join(HERE, "l2term_commands.txt")) as f:
        commands = [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]
    g = Golden("l2term")
    work = tempfile.mkdtemp()
    try:
        proc = start_l2(os.path.join(NEW, "l2"), os.path.join(work, "new"))
        try:
            g.check("session", session(os.path.join(NEW, "l2term"), commands))
            if INTEROP:
                g.check("session", session(os.path.join(ORIG, "l2term"), commands),
                        "l2term=orig")
        finally:
            proc.terminate()
            proc.wait()
        if INTEROP:
            proc = start_l2(os.path.join(ORIG, "l2"), os.path.join(work, "orig"))
            try:
                ref = session(os.path.join(ORIG, "l2term"), commands)
                new = session(os.path.join(NEW, "l2term"), commands)
            finally:
                proc.terminate()
                proc.wait()
            g.same("l2=orig: l2term=new gives the original l2term's transcript", ref, new)
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    print(f"{len(commands)} commands")
    return g.status()


if __name__ == "__main__":
    sys.exit(main())
