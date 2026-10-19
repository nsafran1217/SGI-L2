"""Golden transcripts for the session tests.

Each test runs the tools of this build (NEW_BIN, default build/bin) and
compares what they print with tests/golden/<test>/<name>.txt. The files were
recorded when the tools still matched SGI's original binaries exactly; an
intentional change in behaviour updates them in the same commit, so the
change shows up as a diff of the golden file.

    GOLDEN=update tests/<test>     rewrite the golden files from this build
    INTEROP=1 tests/<test>         also run SGI's original binaries (ORIG_BIN,
                                   default ../ist/...): the original clients
                                   against this l2 must give the golden
                                   output, and this build's clients against
                                   the original l2 the original clients'
                                   output (the wire format is unchanged)

What depends on the host is normalized before comparing: the user's name
and GECOS field where a connection is announced, and the address l2 takes
from the host name (<L2IP>; on hosts where that is 127.0.0.1 the goldens
cannot tell it apart from the loopback address the tests connect to).
"""

import difflib
import os
import re
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
NEW = os.environ.get("NEW_BIN", os.path.join(SRC, "build/bin"))
ORIG = os.environ.get("ORIG_BIN", os.path.join(
    SRC, "..", "ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin"))
UPDATE = os.environ.get("GOLDEN") == "update"
INTEROP = bool(os.environ.get("INTEROP"))
if INTEROP and not os.path.isfile(os.path.join(ORIG, "l2")):
    raise SystemExit(f"INTEROP=1: no original binaries in {ORIG} (set ORIG_BIN)")


def _host_ip():
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        return None
    return None if ip == "127.0.0.1" else ip


HOST_IP = _host_ip()


def normalize(t):
    t = re.sub(r"\S+ \([^()\n]*\) @ (\S+) running", r"<USER> (<GECOS>) @ \1 running", t)
    if HOST_IP:
        t = re.sub(r"(?<![\d.])" + re.escape(HOST_IP) + r"(?!\d)", "<L2IP>", t)
    return t


def text(value):
    """A transcript as text: bytes as latin-1, lists one repr() per line."""
    if isinstance(value, bytes):
        value = value.decode("latin-1")
    elif isinstance(value, (list, tuple)):
        value = "".join(f"{v!r}\n" for v in value)
    return normalize(value)


def show_diff(a, b, aname, bname):
    for line in list(difflib.unified_diff(a.split("\n"), b.split("\n"), aname, bname,
                                          lineterm=""))[:40]:
        print("   ", line)


class Golden:
    def __init__(self, test):
        self.test = test
        self.dir = os.path.join(HERE, "golden", test)
        self.ok = True

    def check(self, name, value, label=None):
        """Compare value with the golden file name (or write it, GOLDEN=update)."""
        value = text(value)
        path = os.path.join(self.dir, name + ".txt")
        label = f"{self.test} {name}" + (f" ({label})" if label else "")
        if UPDATE:
            os.makedirs(self.dir, exist_ok=True)
            with open(path, "w", encoding="latin-1", newline="") as f:
                f.write(value)
            print(f"WROTE {label}: {os.path.relpath(path, SRC)}")
            return True
        try:
            with open(path, encoding="latin-1", newline="") as f:
                ref = f.read()
        except FileNotFoundError:
            print(f"FAIL  {label}: no {os.path.relpath(path, SRC)} (GOLDEN=update writes it)")
            self.ok = False
            return False
        same = value == ref
        print(f"{'PASS' if same else 'FAIL'}  {label}: {len(ref.splitlines())} lines")
        if not same:
            show_diff(ref, value, "golden", "now")
            self.ok = False
        return same

    def same(self, label, a, b, aname="orig", bname="new"):
        """Compare two live results (interop runs)."""
        a, b = text(a), text(b)
        same = a == b
        print(f"{'PASS' if same else 'FAIL'}  {self.test} {label}")
        if not same:
            show_diff(a, b, aname, bname)
            self.ok = False
        return same

    def status(self):
        return 0 if self.ok else 1


if __name__ == "__main__" and sys.argv[1:] == ["normalize"]:     # (for golden.sh)
    sys.stdout.buffer.write(normalize(sys.stdin.buffer.read().decode("latin-1")).encode("latin-1"))
