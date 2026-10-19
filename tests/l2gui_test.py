#!/usr/bin/env python3
"""l2gui: a scripted touch session under Xvfb.

    tests/l2gui_test.py

l2gui connects to 'l2 -noconn' and goes through these clicks: the destination window (partition mode, ALL,
Apply, Reset DEST, Cancel), Power DOWN/NMI with OK, RESET with Cancel, and the
logo window. The L2 traffic (every byte l2gui writes and reads on its
connection, from strace) must match tests/golden/l2gui/, apart from Router
argument padding, which SGI's original leaves uninitialized. INTEROP=1 also
runs SGI's original l2gui against this l2, and this l2gui against the
original l2 (tests/golden.py). KEEP=1 keeps the screenshots of each step
(<step>-<run>.png) for a visual comparison: the original's renderings differ
(it draws through Nano-X, with its own fonts). Needs Xvfb, xdotool,
ImageMagick's import and strace.
"""

import os
import pwd
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from golden import Golden, INTEROP, NEW, ORIG   # noqa: E402
DISPLAY = ":77"
PORT = 9002             # the L2's port for its 'l2gui' client (task 6)

# (step name, click x, y) in main-window coordinates (see the ui/*.fl files);
# the command window sits at (0, 64), the others at (0, 0)
SESSION = [
    ("main", None),
    ("dest", (33, 225)),            # DEST:
    ("dest-part", (96, 18)),        # Partition
    ("dest-all", (17, 52)),         # ALL
    ("apply", (64, 220)),           # Apply: dest "p *"
    ("powerdown", (64, 119)),       # Power DOWN
    ("powerdown-ok", (103, 221)),   # OK
    ("reset", (64, 152)),           # RESET
    ("reset-cancel", (233, 221)),   # Cancel
    ("dest2", (33, 225)),           # DEST:
    ("dest2-rack", (33, 18)),       # Rack/Slot
    ("dest2-reset", (159, 220)),    # Reset DEST
    ("dest2-cancel", (255, 220)),   # Cancel
    ("nmi", (64, 186)),             # NMI
    ("nmi-ok", (103, 221)),         # OK
    ("logo", (282, 32)),            # the SGI logo: screen saver
    ("logo-off", (160, 120)),       # touch to dismiss
]


def x(*args, **kw):
    return subprocess.run(list(args), env=dict(os.environ, DISPLAY=DISPLAY),
                          capture_output=True, text=True, **kw).stdout


def start_l2(workdir, l2bin):
    fifo = os.path.join(workdir, "stdin")
    os.mkfifo(fifo)
    log = open(os.path.join(workdir, "daemon.log"), "wb")
    fd = os.open(fifo, os.O_RDWR)        # l2 spins on stdin EOF
    proc = subprocess.Popen([l2bin, "-noconn"], cwd=workdir, stdin=fd,
                            stdout=log, stderr=log)
    os.close(fd)
    for _ in range(30):
        time.sleep(0.2)
        with open(log.name, "rb") as f:
            if b"SMP listening on port: 8003" in f.read():
                return proc
    proc.kill()
    raise RuntimeError("l2 did not start")


def click(ox, oy, x_, y_):
    # Nano-X (the original) misses a press and release in the same instant
    for a in (["mousemove", str(ox + x_), str(oy + y_)], ["mousedown", "1"], ["mouseup", "1"]):
        x("xdotool", *a)
        time.sleep(0.25)
    time.sleep(0.7)


def traffic(strace_log):
    """(direction, bytes) for each read/write on the connection to PORT."""
    fds, out = set(), []
    for line in open(strace_log):
        m = re.match(r"(\d+)\s+connect\((\d+), \{sa_family=AF_INET, sin_port=htons\((\d+)\)", line)
        if m and int(m.group(3)) == PORT:
            fds.add((m.group(1), m.group(2)))
            continue
        m = re.match(r'(\d+)\s+(write|read|send|recv|sendto|recvfrom)\((\d+), "((?:\\x[0-9a-f]{2})*)"', line)
        if m and (m.group(1), m.group(3)) in fds:
            out.append((m.group(2) in ("write", "send", "sendto"),
                        mask_padding(bytes.fromhex(m.group(4).replace("\\x", "")))))
    return out


def mask_padding(data):
    """Zero the alignment padding of each Router argument: the original sends
    uninitialized heap bytes there. A message is an 8-byte header (length in
    bytes 4-7), then arguments: a class<<24|size word and an inline value
    (class 0) or size bytes padded to 4. Reads come as header, then the rest."""
    b = bytearray(data)
    i = 8 if len(b) > 8 and int.from_bytes(b[4:8], "big") == len(b) - 8 else 0
    if len(b) == 8:
        return data
    while i + 4 <= len(b):
        w = int.from_bytes(b[i:i + 4], "big")
        clas, size = w >> 24, w & 0xffffff
        i += 4
        if clas == 0:
            i += 4
            continue
        end = i + (size + 3 & ~3)
        if end > len(b):
            return data             # not a Router message after all
        b[i + size:end] = bytes(end - i - size)
        i = end
    return bytes(b)


def run_session(gui, l2bin, name, work):
    d = os.path.join(work, name)
    os.makedirs(d)
    xvfb = subprocess.Popen(["Xvfb", DISPLAY, "-screen", "0", "800x600x24", "-nolisten", "tcp"],
                            stderr=subprocess.DEVNULL)
    time.sleep(1)
    l2 = start_l2(d, l2bin)
    log = open(os.path.join(d, "gui.log"), "wb")
    trace = os.path.join(d, "strace.log")
    proc = subprocess.Popen(["strace", "-f", "-o", trace, "-s", "65536", "-xx", "-e",
                             "trace=connect,read,write,send,recv,sendto,recvfrom",
                             gui, "--l2", "127.0.0.1"],
                            env=dict(os.environ, DISPLAY=DISPLAY), stdout=log, stderr=log)
    try:
        geom = None
        for _ in range(50):
            time.sleep(0.2)
            m = re.search(r'"(?:Microwindows|L2 Controller GUI)".*?\s\d+x\d+\+(-?\d+)\+(-?\d+)',
                          x("xwininfo", "-root", "-tree"))
            if m:
                geom = int(m.group(1)), int(m.group(2))
                break
        if geom is None:
            raise RuntimeError(f"{gui}: no window")
        time.sleep(2)
        for step, pos in SESSION:
            if pos:
                click(*geom, *pos)
            x("import", "-window", "root", "-crop", "320x240+%d+%d" % geom,
              os.path.join(work, f"{step}-{name}.png"))
        time.sleep(1)
    finally:
        # stop l2gui itself: strace (proc) then exits on its own
        try:
            with open(f"/proc/{proc.pid}/task/{proc.pid}/children") as f:
                for pid in f.read().split():
                    os.kill(int(pid), 15)
        except OSError:
            pass
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        l2.terminate()
        l2.wait()
        xvfb.terminate()
        xvfb.wait()
    return traffic(trace)


def as_text(session):
    """One line per read or write. The connection's identity message (user
    name, GECOS, the L2's address) varies by host: only its direction is kept
    (the interop run compares it byte for byte)."""
    user = pwd.getpwuid(os.getuid()).pw_name.encode() + b"\0"
    return "".join(f"{'>>' if out else '<<'} "
                   f"{'<identity>' if user in data else data.hex()}\n" for out, data in session)


def main():
    for tool in ("Xvfb", "xdotool", "import", "xwininfo", "strace"):
        if not shutil.which(tool):
            print(f"SKIP  l2gui test: {tool} not found")
            return 0
    g = Golden("l2gui")
    work = tempfile.mkdtemp()
    try:
        new_l2, orig_l2 = os.path.join(NEW, "l2"), os.path.join(ORIG, "l2")
        a = run_session(os.path.join(NEW, "l2gui"), new_l2, "new", work)
        writes = sum(1 for out, _ in a if out)
        if writes <= 3:
            print(f"FAIL  l2gui session: only {writes} writes to the L2")
            g.ok = False
        g.check("traffic", as_text(a))
        if INTEROP:
            b = run_session(os.path.join(ORIG, "l2gui"), new_l2, "orig-gui", work)
            g.check("traffic", as_text(b), "l2gui=orig")
            ref = run_session(os.path.join(ORIG, "l2gui"), orig_l2, "orig-orig", work)
            new = run_session(os.path.join(NEW, "l2gui"), orig_l2, "orig-l2", work)
            g.same("l2=orig: l2gui=new sends and gets the original l2gui's traffic",
                   as_text(ref), as_text(new))
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    print(f"{len(SESSION)} steps")
    return g.status()


if __name__ == "__main__":
    sys.exit(main())
