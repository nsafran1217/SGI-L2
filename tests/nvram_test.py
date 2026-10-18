#!/usr/bin/env python3
"""Differential test of the NVRAM file (./.l2_NVRAM).

    tests/nvram_test.py [ORIG_BIN_DIR]

Each daemon (original and rebuilt) starts on an empty directory and gets the
same setting commands through l2cmd. The two NVRAM files must match: header
and settings byte for byte, and the same log messages (timestamps and the
non-deterministic "SMP n waited" entries aside). Then each daemon is started
on each file and the settings are read back: all four transcripts must match
the original daemon reading its own file. NEW_BIN selects the rebuilt
binaries, as in difftest.sh.
"""

import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
ORIG = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    SRC, "..", "ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin")
NEW = os.environ.get("NEW_BIN", os.path.join(SRC, "build/bin"))

SET = [
    "rackid 7", "sysname testsys", "serial set N0000123", "multisys on", "dhcpserver off",
    "l2dsp disable", "autopower delay 42", "ping min 2", "ping max 9", "ping l2 11",
    "ping l1 13", "ping sender 1", "ip 10.1.2.3 255.255.0.0 10.1.255.255",
    "ip gw 10.1.0.1", "psmode primary", "log insert hello from the nvram test",
]
QUERY = ["rackid", "sysname", "serial", "multisys", "dhcpserver", "l2dsp", "autopower",
         "ping", "ip", "psmode", "log", "nvram"]

IUA = 8                 # the common header's internal_use_area is 1 (x 8 bytes)
LOG_START = IUA + 2072  # nvramInternalUseArea.log_start .. log_tail: LE uint32 offsets


def start_l2(binary, workdir):
    fifo = os.path.join(workdir, "stdin")
    os.mkfifo(fifo)
    log = open(os.path.join(workdir, "daemon.log"), "wb")
    fd = os.open(fifo, os.O_RDWR)        # l2 spins on stdin EOF
    proc = subprocess.Popen([binary, "-noconn"], cwd=workdir, stdin=fd, stdout=log, stderr=log)
    os.close(fd)
    for _ in range(30):
        time.sleep(0.2)
        with open(log.name, "rb") as f:
            if b"SMP listening on port: 8003" in f.read():
                return proc
    proc.kill()
    raise RuntimeError(f"{binary} did not start")


def stop_l2(proc):
    proc.terminate()
    proc.wait()


def l2cmd(command):
    r = subprocess.run([os.path.join(ORIG, "l2cmd"), "--l2", "127.0.0.1", *command.split()],
                       capture_output=True, text=True, errors="replace", timeout=15)
    return r.stdout + r.stderr


def mask(text):
    text = re.sub(r"^.*SMP \d+ waited [0-9.]+\n", "", text, flags=re.M)    # timing entries
    text = re.sub(r"\d{2}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}", "<DATE>", text)
    return re.sub(r"[A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ [\d:]{8} \d{4}", "<DATE>", text)


def log_messages(image):
    """The log ring's messages, oldest first, without their timestamps."""
    start, end, head, tail = struct.unpack_from("<4I", image, LOG_START)
    if not (0 < start <= head < end and start <= tail < end <= len(image)):
        return None
    out, i, n = bytearray(), head, 0
    while i != tail and n < end - start:
        if image[i] == 0xF0:
            for _ in range(4):
                i = start if i + 1 >= end else i + 1
        else:
            out.append(image[i])
        i = start if i + 1 >= end else i + 1
        n += 1
    return [m for m in out.decode("latin-1").split("\n") if not re.match(r"SMP \d+ waited", m)]


def settings(image):
    """Header and internal use area, less the log's head/tail and the checksum covering them."""
    b = bytearray(image[:IUA + 2092])
    b[LOG_START + 8:LOG_START + 16] = bytes(8)
    b[IUA + 2091] = 0
    return bytes(b)


def main():
    work = tempfile.mkdtemp()
    ok = True
    try:
        images = {}
        for name, bindir in (("orig", ORIG), ("new", NEW)):
            d = os.path.join(work, "make-" + name)
            os.makedirs(d)
            proc = start_l2(os.path.join(bindir, "l2"), d)
            try:
                for c in SET:
                    l2cmd(c)
                # the daemon may still be saving when l2cmd exits (each save truncates
                # the file first): stop it only once it has logged every disconnection
                for _ in range(100):
                    with open(os.path.join(d, "daemon.log"), "rb") as f:
                        if f.read().count(b"INFO: Disconnection") >= len(SET):
                            break
                    time.sleep(0.1)
            finally:
                stop_l2(proc)
            with open(os.path.join(d, ".l2_NVRAM"), "rb") as f:
                images[name] = f.read()
        a, b = images["orig"], images["new"]
        if settings(a) == settings(b) and log_messages(a) == log_messages(b):
            print(f"PASS  NVRAM files match (settings byte for byte; log messages, timing entries masked)")
        else:
            ok = False
            sa, sb = settings(a), settings(b)
            diffs = [hex(i) for i in range(len(sa)) if sa[i] != sb[i]]
            print(f"FAIL  NVRAM files differ: settings bytes {diffs[:8]}, "
                  f"log {'same' if log_messages(a) == log_messages(b) else 'differs'}")

        results = {}
        for maker in ("orig", "new"):
            for reader, bindir in (("orig", ORIG), ("new", NEW)):
                d = os.path.join(work, f"read-{maker}-{reader}")
                os.makedirs(d)
                with open(os.path.join(d, ".l2_NVRAM"), "wb") as f:
                    f.write(images[maker])
                proc = start_l2(os.path.join(bindir, "l2"), d)
                try:
                    results[(maker, reader)] = "".join(f"=== {c}\n{mask(l2cmd(c))}" for c in QUERY)
                finally:
                    stop_l2(proc)
        ref = results[("orig", "orig")]
        for key, text in results.items():
            if key == ("orig", "orig"):
                continue
            same = text == ref
            ok &= same
            print(f"{'PASS' if same else 'FAIL'}  file={key[0]} read by l2={key[1]}")
            if not same:
                import difflib
                for line in list(difflib.unified_diff(ref.split("\n"), text.split("\n"), lineterm=""))[:30]:
                    print("   ", line)
        print(f"{len(SET)} settings, {len(QUERY)} queries, {len(ref.splitlines())} transcript lines")
    finally:
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
