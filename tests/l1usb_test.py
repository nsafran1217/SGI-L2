#!/usr/bin/env python3
"""l2's USB L1 link (l1.c: l1_open_usb() and on, l1usb.c), with a fake libusb.

    tests/l1usb_test.py

l2 runs '-usb' with tests/libusb_shim.c preloaded: its USB devices are Unix
packet sockets served here (presence on sgil1_cs, device n on sgil1_<n>,
the names of the sgil1 driver the shim once faked), where a fake L1
(tests/fakel1.py) behind device 0 reports brick 001c02. Each command in
tests/l1_commands.txt goes through l2cmd; then
device reads fail (once; twice, then a good one; the device is unplugged and
plugged in again; three times, which closes and reopens it; with ENODEV,
which closes it until it is plugged in again), with commands in between.
The transcript, the daemon's log and the requests the fake L1 got must match
tests/golden/l1usb/ (INTEROP=1: also with SGI's original l2cmd;
tests/golden.py).
"""

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
sys.path.insert(0, HERE)
from fakel1 import FakeL1   # noqa: E402
from golden import Golden, INTEROP, NEW, ORIG   # noqa: E402
from l1_test import mask    # noqa: E402

DEVICES = 40                # the driver's status bytes


def elf_bits(path):
    with open(path, "rb") as f:
        return 32 if f.read(5)[4] == 1 else 64


def build_shim(work, source, bits):
    so = os.path.join(work, f"{os.path.splitext(source)[0]}{bits}.so")
    if not os.path.exists(so):
        cflags = subprocess.run([os.environ.get("PKG_CONFIG", "pkg-config"), "--cflags", "libusb-1.0"],
                                capture_output=True, text=True).stdout.split()
        cmd = ["gcc", f"-m{bits}", "-shared", "-fPIC", *cflags, "-o", so, os.path.join(HERE, source),
               "-pthread"]
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
        """The device's next read fails with errno err (tests/libusb_shim.c)."""
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


L2CMD = os.path.join(NEW, "l2cmd")     # (the interop run: the original's)


def l2cmd(c):
    r = subprocess.run([L2CMD, "--l2", "127.0.0.1", *c.split()],
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
    global L2CMD
    commands = [l.strip() for l in open(os.path.join(HERE, "l1_commands.txt")) if l.strip()]
    with open(os.path.join(NEW, "l2"), "rb") as f:
        if b"built without libusb" in f.read():
            print("SKIP  l1usb: l2 was built without libusb")
            return 0
    g = Golden("l1usb")
    work = tempfile.mkdtemp()
    try:
        new_l2 = os.path.join(NEW, "l2")
        shim = build_shim(work, "libusb_shim.c", elf_bits(new_l2))
        runs = [("l2cmd=new", NEW)] + ([("l2cmd=orig", ORIG)] if INTEROP else [])
        for label, cdir in runs:
            L2CMD = os.path.join(cdir, "l2cmd")
            text, daemon, reqs = session(new_l2, [shim], commands, work, label)
            g.check("transcript", text, label)
            g.check("daemon", daemon, label)
            g.check("l1_requests", reqs, label)
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    print(f"{len(commands)} commands, unplug and replug")
    return g.status()


if __name__ == "__main__":
    sys.exit(main())
