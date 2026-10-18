#!/usr/bin/env python3
"""Differential test of the L1 side of l2, with a fake L1.

    tests/l1_test.py [ORIG_BIN_DIR]

The other tests run 'l2 -noconn', so no brick is ever known. Here each l2
(original and rebuilt) runs '-net' and a fake L1 (tests/fakel1.py) connects
to its L1 port, reporting one brick (001c02). Each command in
tests/l1_commands.txt then goes through the original l2cmd, and each line of
tests/l1_console_commands.txt is typed at the L2's console (SMP port 8001,
for commands only the console has, such as loopback). The transcripts
must match, and so must the requests the fake L1 receives. The original l2
runs with a 32-bit LD_PRELOAD shim (tests/usrtmp_shim.c) because it
hardcodes /usr/tmp for its local sockets. NEW_BIN selects the rebuilt
binaries, as in difftest.sh.
"""

import difflib
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
SRC = os.path.dirname(HERE)
ORIG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    SRC, "..", "ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin")
NEW = os.environ.get("NEW_BIN", os.path.join(SRC, "build/bin"))
sys.path.insert(0, HERE)
from fakel1 import FakeL1   # noqa: E402


def build_shim(work):
    so = os.path.join(work, "usrtmp_shim.so")
    cmd = ["gcc", "-m32", "-shared", "-fPIC", "-o", so, os.path.join(HERE, "usrtmp_shim.c"), "-ldl"]
    if not os.path.isdir("/usr/include/i386-linux-gnu/bits"):
        cmd[2:2] = ["-isystem", "/usr/include/x86_64-linux-gnu"]
    subprocess.run(cmd, check=True)
    return so


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
    return re.sub(r"(time|average|min pkt|max pkt|) +[0-9.]+ (seconds|bytes/second)",
                  r"\1 <N> \2", text)


def session(l2bin, env, commands, work, name):
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
            r = subprocess.run([os.path.join(ORIG, "l2cmd"), "--l2", "127.0.0.1", *c.split()],
                               capture_output=True, text=True, errors="replace", timeout=30)
            out.append(f"=== {c}\n{mask(r.stdout + r.stderr)}")
        with open(os.path.join(HERE, "l1_console_commands.txt")) as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        out.append(f"=== console\n{mask(console(lines))}")
        l1.close()
        return "".join(out), l1.requests
    finally:
        proc.terminate()
        proc.wait()


def main():
    commands = [l.strip() for l in open(os.path.join(HERE, "l1_commands.txt")) if l.strip()]
    work = tempfile.mkdtemp()
    try:
        shim = build_shim(work)
        ref, ref_reqs = session(os.path.join(ORIG, "l2"), {"LD_PRELOAD": shim}, commands, work,
                                "orig")
        new, new_reqs = session(os.path.join(NEW, "l2"), {}, commands, work, "new")
        for name, text in (("orig", ref), ("new", new)):
            with open(os.path.join(work, name, "transcript.txt"), "w") as f:
                f.write(text)
        ok = ref == new and ref_reqs == new_reqs and ref_reqs
        print(f"{'PASS' if ok else 'FAIL'}  l1: l2=new with a fake L1 ({len(commands)} commands, "
              f"{len(ref_reqs)} L1 requests)")
        if ref != new:
            for line in list(difflib.unified_diff(ref.split("\n"), new.split("\n"), "orig", "new",
                                                  lineterm=""))[:40]:
                print("   ", line)
        if ref_reqs != new_reqs:
            print("    L1 requests differ:\n     orig", ref_reqs, "\n     new ", new_reqs)
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
