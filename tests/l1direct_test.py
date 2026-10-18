#!/usr/bin/env python3
"""Differential test of the direct L1 connection (l3/api/L1Direct.c).

l2cmd --serial <host>:<port> (a terminal server port: TCP) and --dev
<device> (a local serial port: a pty here) talk to an L1 directly in PPP
framing. The original and the rebuilt l2cmd run the same commands against
tests/fakel1_serial.py; their output and the requests the fake L1 got must
match. Each run takes two seconds or more (the L1 opening waits that long).

    NEW_BIN=<build>/bin tests/l1direct_test.py [ORIG_BIN_DIR]
"""

import os
import subprocess
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
from fakel1_serial import FakeSerialL1  # noqa: E402

src = os.path.dirname(here)
orig = sys.argv[1] if len(sys.argv) > 1 else \
    os.path.join(src, "..", "ist", "ist-software-extracted", "IST", "snxsc_l3", "stand", "sysco", "bin")
new = os.environ.get("NEW_BIN", os.path.join(src, "build", "bin"))

CASES = [
    # (mode, options, command, fake L1 options)
    ("tcp", [], "version;l1 ver;power up", {}),
    ("tcp", [], "pwr;fail this;event then;stray one;cfg", {}),
    ("tcp", ["--timeout", "2"], "ignore me;version", {}),
    ("pty", [], "version;fail it;event;stray;l1 serial", {}),
    ("tcp", [], "version", {"telnet": True, "port": 5123}),
    ("tcp", [], "version", {"telnet": True}),
]


def run(bindir, mode, opts, cmd, fake_opts):
    fake = FakeSerialL1(mode, port=fake_opts.get("port", 0), telnet=fake_opts.get("telnet", False))
    where = ["--serial", "127.0.0.1:%d" % fake.port] if mode == "tcp" else ["--dev", fake.device]
    try:
        p = subprocess.run([os.path.join(bindir, "l2cmd")] + where + opts + cmd.split(" "),
                           capture_output=True, timeout=60, cwd=bindir)
        out = p.stdout + b"--- stderr\n" + p.stderr + b"--- exit %d\n" % p.returncode
    except subprocess.TimeoutExpired:
        out = b"timeout\n"
    fake.close()
    # the port and device differ between runs
    out = out.replace(str(getattr(fake, "port", "")).encode() or b"\0", b"<port>") if mode == "tcp" \
        and not fake_opts.get("port") else out
    return out, fake.requests


def main():
    fail = 0
    for mode, opts, cmd, fake_opts in CASES:
        a = run(orig, mode, opts, cmd, fake_opts)
        b = run(new, mode, opts, cmd, fake_opts)
        name = "%s %s%s" % (mode, " ".join(opts) + " " if opts else "", cmd)
        if fake_opts.get("telnet"):
            name += " (telnet)"
        if a != b:
            print("FAIL  l1direct: %s" % name)
            print("  orig: %r\n  new:  %r" % (a, b))
            fail = 1
    # the PPP error message (the original printed one for an address)
    out, _ = run(new, "tcp", [], "corrupt;version", {})
    if b"WARNING: PPP error PPP:bad FCS (checksum)" not in out or b"fake L1: version" not in out:
        print("FAIL  l1direct: PPP error message: %r" % out)
        fail = 1
    if not fail:
        print("PASS  l1direct: %d l2cmd runs over --serial and --dev against a fake L1, PPP errors" % len(CASES))
    return fail


if __name__ == "__main__":
    sys.exit(main())
