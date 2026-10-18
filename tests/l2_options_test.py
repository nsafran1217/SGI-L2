#!/usr/bin/env python3
"""Differential test of the l2 daemon's own command line (main() in l3/l2/l2.c).

    tests/l2_options_test.py [ORIG_BIN_DIR]

Each line of OPTIONS runs the original and the rebuilt l2 in a fresh
directory. Lines that start the daemon run until it listens on its SMP port
(or 5 seconds), then it is stopped. Output, exit status (for lines that exit
by themselves) and the NVRAM file left behind (its settings and log
messages, as tests/nvram_test.py compares them) must match. The original runs
with tests/usrtmp_shim.c for its local sockets (as in l1_test.py), both with
their sockets in the same kind of directory.
"""

import hashlib
import os
import re
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
from l1_test import build_shim   # noqa: E402
from nvram_test import log_messages, settings   # noqa: E402

# (no line may leave a daemon discovering others: they all use -nodiscover
# or exit first)
OPTIONS = """
-help
--copy
--copy -noconn
--copy 200
--copy -5
-serial
-usbpath
-password
-password -noconn
-syncssn NEWSSN01
-noconn -nodiscover
-noconn -nodiscover --copy 3
-noconn -nodiscover --copy 0
-noconn -nodiscover -smpenet
-noconn -nodiscover -debug -irtr -nopwrchk
-nodiscover -l1sim
-nodiscover -l1sim 4 2
-nodiscover -l1sim_manual 6
-nodiscover -net
-noconn -nodiscover --mtrace
-noconn -nodiscover -noconn -bogus
""".strip().splitlines()


def run(binary, args, work, env):
    os.makedirs(work)
    fifo = os.path.join(work, "stdin")
    os.mkfifo(fifo)
    fd = os.open(fifo, os.O_RDWR)       # l2 spins on stdin EOF
    log = open(os.path.join(work, "out"), "wb")
    env = dict(os.environ, SGI_L3_SOCKET_DIR=work, USRTMP_SHIM_DIR=work,
               MALLOC_TRACE=os.path.join(work, "mtrace"), **env)
    proc = subprocess.Popen([binary] + args.split(), cwd=work, stdin=fd, stdout=log,
                            stderr=subprocess.STDOUT, env=env)
    os.close(fd)
    status = None
    end = time.time() + 5
    while time.time() < end:
        status = proc.poll()
        if status is not None:
            break
        with open(log.name, "rb") as f:
            if re.search(rb"SMP listening on port: 80\d3", f.read()):
                time.sleep(0.5)
                break
        time.sleep(0.1)
    if status is None:
        proc.terminate()
        proc.wait()
        status = "running"
    with open(log.name, "rb") as f:
        out = f.read().decode("latin-1")
    out = out.replace(binary, "<l2>")
    nv = os.path.join(work, ".l2_NVRAM")
    digest = None
    if os.path.exists(nv):          # as nvram_test.py compares it
        image = open(nv, "rb").read()
        digest = (hashlib.md5(settings(image)).hexdigest(), log_messages(image))
    return out, status, digest


def main():
    work = tempfile.mkdtemp()
    ok = True
    try:
        shim = build_shim(work)
        for n, args in enumerate(OPTIONS):
            ref = run(os.path.join(ORIG, "l2"), args, os.path.join(work, f"{n}o"),
                      {"LD_PRELOAD": shim})
            new = run(os.path.join(NEW, "l2"), args, os.path.join(work, f"{n}n"), {})
            if ref != new:
                ok = False
                print(f"FAIL  l2 {args}")
                for what, a, b in zip(("output", "status", "nvram"), ref, new):
                    if a != b:
                        print(f"    {what}:\n      orig {a!r}\n      new  {b!r}")
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    if ok:
        print(f"PASS  l2 options: {len(OPTIONS)} command lines, original and rebuilt l2 agree")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
