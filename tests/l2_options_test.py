#!/usr/bin/env python3
"""The l2 daemon's own command line (main() in l3/l2/l2.c).

    tests/l2_options_test.py

Each line of OPTIONS runs l2 in a fresh directory. Lines that start the
daemon run until it listens on its SMP port (or 5 seconds), then it is
stopped. Output, exit status (for lines that exit by themselves) and the
settings file and log left behind must match tests/golden/l2_options/
(tests/golden.py; the options are the daemon's own, so there is no interop
run).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from golden import Golden, NEW   # noqa: E402

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
-noconn -nodiscover -c
-noconn -nodiscover -c my.conf
-noconn -nodiscover -c my.conf --copy 2
-noconn -nodiscover -c nodir/my.conf
""".strip().splitlines()


def run(binary, args, work):
    os.makedirs(work)
    fifo = os.path.join(work, "stdin")
    os.mkfifo(fifo)
    fd = os.open(fifo, os.O_RDWR)       # l2 spins on stdin EOF
    log = open(os.path.join(work, "out"), "wb")
    env = dict(os.environ, SGI_L3_SOCKET_DIR=work)
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
    files = ""
    for name in sorted(os.listdir(work)):
        if name.startswith(("l2.conf", "l2.log", "my.conf")):
            text = open(os.path.join(work, name), errors="replace").read()
            text = re.sub(r"^\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} ", "<DATE> ", text, flags=re.M)
            text = re.sub(r"^.*SMP \d+ waited [0-9.]+\n", "", text, flags=re.M)   # (timing)
            files += f"--- {name}\n{text}"
    return out, status, files


def main():
    g = Golden("l2_options")
    work = tempfile.mkdtemp()
    out = []
    try:
        for n, args in enumerate(OPTIONS):
            text, status, files = run(os.path.join(NEW, "l2"), args, os.path.join(work, str(n)))
            out.append(f"=== l2 {args}\nexit {status}\n{text}{files}")
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    g.check("l2", "".join(out))
    print(f"{len(OPTIONS)} command lines")
    return g.status()


if __name__ == "__main__":
    sys.exit(main())
