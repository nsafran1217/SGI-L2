#!/usr/bin/env python3
"""Differential test of interactive sessions: drive l2term in a pty.

    tests/l2term_test.py [ORIG_BIN_DIR]

For each pairing of original/rebuilt l2 daemon and original/rebuilt l2term,
open a session, wait for the L2 prompt, type each command from
tests/l2term_commands.txt, and compare the transcript with the all-original
one. Daemons run 'l2 -noconn' in temp directories (see difftest.sh).
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
SRC = os.path.dirname(HERE)
ORIG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    SRC, "..", "ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin")
NEW = os.environ.get("NEW_BIN", os.path.join(SRC, "build/bin"))   # NEW_BIN: test another build
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
    # the "log" command's answer: the original's ring wraps with "SMP n waited"
    # entries (and a wrapped log shows as empty); nvram_test.py compares the log
    text = re.sub(r"(-L2>log\r?\n)(?:(?![^\n]*-L2>)[^\n]*\n)*", r"\1<LOG>\n", text)
    text = re.sub(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ [\d:]{8} \d{4}", "<DATE>", text)
    text = re.sub(r"\d{2}:\d{2}:\d{2}", "<TIME>", text)
    text = re.sub(r"\d{2}/\d{2}/\d{2}", "<DATE>", text)
    return text


def main():
    with open(os.path.join(HERE, "l2term_commands.txt")) as f:
        commands = [l.rstrip("\n") for l in f if l.strip() and not l.startswith("#")]
    work = tempfile.mkdtemp()
    results = {}
    try:
        for dname, ddir in (("orig", ORIG), ("new", NEW)):
            proc = start_l2(os.path.join(ddir, "l2"), os.path.join(work, dname))
            try:
                for cname, cdir in (("orig", ORIG), ("new", NEW)):
                    results[(dname, cname)] = session(os.path.join(cdir, "l2term"), commands)
            finally:
                proc.terminate()
                proc.wait()
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    ref = results[("orig", "orig")]
    if os.environ.get("KEEP"):
        with open(os.path.join(work, "orig-orig.txt"), "w") as f:
            f.write(ref)
    ok = True
    for key, text in results.items():
        if key == ("orig", "orig"):
            continue
        same = text == ref
        ok &= same
        print(f"{'PASS' if same else 'FAIL'}  l2={key[0]} l2term={key[1]}")
        if not same:
            import difflib
            for line in list(difflib.unified_diff(ref.split("\n"), text.split("\n"), lineterm=""))[:40]:
                print("   ", line)
    print(f"{len(commands)} commands, {len(ref.splitlines())} transcript lines")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
