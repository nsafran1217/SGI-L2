#!/usr/bin/env python3
"""Differential test of l2's USB L1 link (l1.c: l1_open_usb() and on), with a fake driver.

    tests/l1usb_test.py [ORIG_BIN_DIR]

Each l2 (original and rebuilt) runs '-usb' with tests/sgil1_shim.c
preloaded: its /dev/sgil1_* devices are Unix packet sockets served here,
where a fake L1 (tests/fakel1.py) behind device 0 reports brick 001c02.
Each command in tests/l1_commands.txt goes through the original l2cmd; then
device reads fail (once; twice, then a good one; the device is unplugged and
plugged in again; three times, which closes and reopens it; with ENODEV,
which closes it until it is plugged in again), with commands in between. The transcripts, the daemons'
logs and the requests the fake L1 got must match.
"""

import difflib
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
ORIG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    SRC, "..", "ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin")
NEW = os.environ.get("NEW_BIN", os.path.join(SRC, "build/bin"))
sys.path.insert(0, HERE)
from fakel1 import FakeL1   # noqa: E402
from l1_test import mask    # noqa: E402

DEVICES = 40                # the driver's status bytes


def elf_bits(path):
    with open(path, "rb") as f:
        return 32 if f.read(5)[4] == 1 else 64


def build_shim(work, source, bits):
    so = os.path.join(work, f"{os.path.splitext(source)[0]}{bits}.so")
    if not os.path.exists(so):
        cmd = ["gcc", f"-m{bits}", "-shared", "-fPIC", "-o", so, os.path.join(HERE, source), "-ldl"]
        if bits == 32 and not os.path.isdir("/usr/include/i386-linux-gnu/bits"):
            cmd[2:2] = ["-isystem", "/usr/include/x86_64-linux-gnu"]
        subprocess.run(cmd, check=True)
    return so


class FakeUSB:
    """The driver's devices: sgil1_cs (status) and sgil1_0 (a fake L1)."""

    def __init__(self, d):
        self.dir = d
        self.status = bytearray(DEVICES)
        self.status[0] = 1
        self.cs = []                # control connections
        self.l1s = []               # one FakeL1 per open of device 0
        self.lock = threading.Lock()
        for name, fn in (("sgil1_cs", self.serve_cs), ("sgil1_0", self.serve_dev)):
            s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
            s.bind(os.path.join(d, name))
            s.listen(4)
            threading.Thread(target=fn, args=(s,), daemon=True).start()

    def serve_cs(self, s):
        while True:
            c, _ = s.accept()
            with self.lock:
                self.cs.append(c)
                c.sendall(bytes(self.status))

    def serve_dev(self, s):
        while True:
            c, _ = s.accept()
            with self.lock:
                self.l1s.append(FakeL1(sock=c))

    def set_status(self, dev, value):
        with self.lock:
            self.status[dev] = value
            for c in self.cs:
                c.sendall(bytes(self.status))
            if not value:
                for l1 in self.l1s:
                    l1.close()

    def inject(self, err):
        """The device's next read fails with errno err (tests/sgil1_shim.c)."""
        with self.lock:
            self.l1s[-1].sock.send(b"\xff\xfeERR%d" % err)

    def config_requests(self):
        with self.lock:
            return sum(l1.config_requests for l1 in self.l1s)

    def requests(self):
        with self.lock:
            return [r for l1 in self.l1s for r in l1.requests]


def wait(cond, secs=10):
    end = time.time() + secs
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.2)
    return False


def l2cmd(c):
    r = subprocess.run([os.path.join(ORIG, "l2cmd"), "--l2", "127.0.0.1", *c.split()],
                       capture_output=True, text=True, errors="replace", timeout=30)
    return f"=== {c}\n{mask(r.stdout + r.stderr)}"


def session(l2bin, preload, commands, work, name):
    d = os.path.join(work, name)
    devdir = os.path.join(d, "sgil1")
    os.makedirs(devdir)
    usb = FakeUSB(devdir)
    fifo = os.path.join(d, "stdin")
    os.mkfifo(fifo)
    logname = os.path.join(d, "daemon.log")
    log = open(logname, "wb")
    fd = os.open(fifo, os.O_RDWR)        # l2 spins on stdin EOF
    env = dict(os.environ, LD_PRELOAD=" ".join(preload), FAKE_SGIL1_DIR=devdir)
    # (an ASan build: its runtime is not first with the shim preloaded)
    env["ASAN_OPTIONS"] = ":".join(filter(None, [env.get("ASAN_OPTIONS"), "verify_asan_link_order=0"]))
    proc = subprocess.Popen([l2bin, "-usb", "-nodiscover"], cwd=d, stdin=fd, stdout=log,
                            stderr=log, env=env)
    os.close(fd)
    out = []
    try:
        if not wait(lambda: b"SMP listening on port: 8003" in open(logname, "rb").read()):
            raise RuntimeError(f"{l2bin} did not start")
        if not wait(lambda: usb.config_requests() >= 1):
            raise RuntimeError(f"{l2bin}: the fake USB L1 got no configuration request")
        time.sleep(1)
        out += [l2cmd(c) for c in commands]
        # a read error: the read side is reset, the device stays
        usb.inject(5)
        time.sleep(0.5)
        out.append(l2cmd("r 1 s 2 l1 ver"))
        # two in a row, then a good read: "repeated 2 times"
        usb.inject(5)
        time.sleep(0.3)
        usb.inject(5)
        time.sleep(0.3)
        out.append(l2cmd("r 1 s 2 l1 ver"))
        # unplug (the driver's status goes to 0), and plug in again
        usb.set_status(0, 0)
        wait(lambda: b"INFO: closed" in open(logname, "rb").read(), 5)
        time.sleep(0.5)
        out.append(l2cmd("config"))
        before = usb.config_requests()
        usb.set_status(0, 1)
        wait(lambda: usb.config_requests() > before)
        time.sleep(1)
        out.append(l2cmd("config"))
        # three in a row: closed, and opened again 5 seconds later
        before = usb.config_requests()
        for _ in range(3):
            usb.inject(5)
            time.sleep(0.3)
        wait(lambda: b"multiple read errors" in open(logname, "rb").read(), 5)
        wait(lambda: usb.config_requests() > before, 15)
        time.sleep(1)
        out.append(l2cmd("config"))
        # the device is gone (ENODEV): closed until the driver reports it again
        usb.inject(19)
        time.sleep(0.5)
        out.append(l2cmd("config"))
        usb.set_status(0, 0)
        time.sleep(0.5)
        before = usb.config_requests()
        usb.set_status(0, 1)
        wait(lambda: usb.config_requests() > before)
        time.sleep(1)
        out.append(l2cmd("config"))
        out.append(f"=== alive: {proc.poll() is None}\n")
    finally:
        proc.terminate()
        proc.wait()
    with open(logname, "rb") as f:
        daemon = mask(f.read().decode("latin-1"))
    # (each l2cmd's connection lines: where they fall among the USB
    # messages depends on timing)
    daemon = re.sub(r"^INFO: (Validating connection|Connection|Disconnection) .*\n", "", daemon,
                    flags=re.M)
    return "".join(out), daemon, usb.requests()


def main():
    commands = [l.strip() for l in open(os.path.join(HERE, "l1_commands.txt")) if l.strip()]
    work = tempfile.mkdtemp()
    ok = True
    try:
        orig_l2, new_l2 = os.path.join(ORIG, "l2"), os.path.join(NEW, "l2")
        ref = session(orig_l2, [build_shim(work, "usrtmp_shim.c", 32),
                                build_shim(work, "sgil1_shim.c", 32)], commands, work, "orig")
        new = session(new_l2, [build_shim(work, "sgil1_shim.c", elf_bits(new_l2))], commands,
                      work, "new")
        for what, a, b in zip(("transcript", "daemon log", "L1 requests"), ref, new):
            if a != b:
                ok = False
                print(f"FAIL  l1usb: {what} differs")
                if isinstance(a, str):
                    for line in list(difflib.unified_diff(a.split("\n"), b.split("\n"), "orig",
                                                          "new", lineterm=""))[:40]:
                        print("   ", line)
                else:
                    print("     orig", a, "\n     new ", b)
        if ok:
            print(f"PASS  l1usb: l2 -usb with a fake driver ({len(commands)} commands, unplug and "
                  f"replug, {len(ref[2])} L1 requests)")
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
