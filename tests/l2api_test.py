#!/usr/bin/env python3
"""l2api, the HTTP API: its endpoints against an l2 with a fake L1.

    tests/l2api_test.py

l2 runs '-net' with a fake L1 (tests/fakel1.py, brick 001c02) and l2api
connects to it. Each request below goes to l2api; the status and body of
each answer must match tests/golden/l2api/, and a command's output must be
what l2cmd prints for it. The console (a WebSocket relayed to the L2's SMP
port) gets a command typed and must show its answer; the event stream must
start with the configuration.
"""

import base64
import hashlib
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from fakel1 import FakeL1   # noqa: E402
from golden import Golden, NEW   # noqa: E402

PORT = 8180
REQUESTS = [
    ("GET", "/api/v1/l2", None),
    ("GET", "/api/v1/config", None),
    ("POST", "/api/v1/command", '{"command": "version"}'),
    ("POST", "/api/v1/command", "r 1 s 2 l1 serial\n"),
    ("POST", "/api/v1/command", '{"command": "r 1 s 2 l1 say \\"hi\\"\\u0021"}'),
    ("POST", "/api/v1/command", '{"nothing": 1}'),
    ("POST", "/api/v1/command", "two\nlines"),
    ("POST", "/api/v1/power", '{"action": "status"}'),
    ("POST", "/api/v1/power", '{"action": "up", "target": "r 1 s 2"}'),
    ("POST", "/api/v1/power", '{"action": "reset", "target": "r 1; s 2"}'),
    ("POST", "/api/v1/power", '{"action": "explode"}'),
    ("GET", "/api/v1/command", None),
    ("GET", "/api/v1/nothing", None),
    ("GET", "/", None),
    ("GET", "/api/v1/console", None),       # (no upgrade: refused)
]


def request(method, path, body):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=40)
    c.request(method, path, body=body)
    r = c.getresponse()
    data = r.read().decode("latin-1")
    c.close()
    return r.status, r.getheader("Content-Type"), data


def ws_console(lines):
    """The console over a WebSocket: type each line, collect until the prompt."""
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    s.sendall(("GET /api/v1/console HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\n"
               "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
               % key).encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1)
    want = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
                                         .encode()).digest()).decode()
    ok = b" 101 " in head.split(b"\r\n")[0] and ("Sec-WebSocket-Accept: " + want).encode() in head
    buf = b""

    def frames():
        nonlocal buf
        while True:
            while len(buf) < 2 or len(buf) < 2 + (buf[1] & 0x7f if buf[1] & 0x7f < 126 else 2):
                buf += s.recv(4096)
            n = buf[1] & 0x7f
            h = 2
            if n == 126:
                n = int.from_bytes(buf[2:4], "big")
                h = 4
            while len(buf) < h + n:
                buf += s.recv(4096)
            op, data, buf = buf[0] & 0x0f, buf[h:h + n], buf[h + n:]
            yield op, data

    def send(text, op=1):
        mask = os.urandom(4)
        data = bytes(b ^ mask[i % 4] for i, b in enumerate(text))
        s.sendall(bytes([0x80 | op, 0x80 | len(data)]) + mask + data)

    out = b""
    it = frames()

    def until_prompt():
        nonlocal out
        start = len(out)
        end = time.time() + 10
        while time.time() < end and not re.search(rb"L2>\s*$", out[start:]):
            op, data = next(it)
            out += data
    until_prompt()
    for line in lines:
        send(line.encode() + b"\r")
        until_prompt()
    send(b"", 8)                         # close
    s.close()
    text = out.decode("latin-1").replace("\r", "")
    return ok, re.sub(r"^.*SMP \d+ waited [0-9.]+\n", "", text, flags=re.M)


def first_event():
    s = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    s.sendall(b"GET /api/v1/events HTTP/1.1\r\nHost: x\r\n\r\n")
    data = b""
    while b"\n\n" not in data.split(b"\r\n\r\n", 1)[-1] or b"\r\n\r\n" not in data:
        data += s.recv(4096)
    s.close()
    head, body = data.split(b"\r\n\r\n", 1)
    return head.split(b"\r\n")[0].decode() + "\n" + body.split(b"\n\n")[0].decode() + "\n"


def l2cmd(cmd):
    r = subprocess.run([os.path.join(NEW, "l2cmd"), "--l2", "127.0.0.1", *cmd.split()],
                       capture_output=True, text=True, timeout=40)
    return "".join(l for l in r.stdout.splitlines(True) if not l.startswith("INFO: "))


def main():
    g = Golden("l2api")
    work = tempfile.mkdtemp()
    procs = []
    try:
        fifo = os.path.join(work, "stdin")
        os.mkfifo(fifo)
        fd = os.open(fifo, os.O_RDWR)
        log = open(os.path.join(work, "l2.log.txt"), "wb")
        procs.append(subprocess.Popen([os.path.join(NEW, "l2"), "-net", "-nodiscover"], cwd=work,
                                      stdin=fd, stdout=log, stderr=log))
        for _ in range(30):
            time.sleep(0.2)
            if b"SMP listening on port: 8003" in open(log.name, "rb").read():
                break
        l1 = FakeL1()
        alog = open(os.path.join(work, "l2api.txt"), "wb")
        procs.append(subprocess.Popen([os.path.join(NEW, "l2api"), "--listen", f"127.0.0.1:{PORT}",
                                       "--l2", "127.0.0.1"], stdout=alog, stderr=alog))
        for _ in range(50):             # until the brick is configured
            time.sleep(0.2)
            try:
                if "001c02" in request("GET", "/api/v1/config", None)[2]:
                    break
            except OSError:
                pass
        out = []
        for method, path, body in REQUESTS:
            status, ctype, data = request(method, path, body)
            out.append(f"=== {method} {path} {body!r}\n{status} {ctype}\n{data}")
        g.check("requests", "".join(out))
        # the same command through l2cmd
        status, _, data = request("POST", "/api/v1/command", "r 1 s 2 l1 serial")
        # (l2cmd ends each word with a space, which the fake L1 echoes)
        same = [l.rstrip() for l in json.loads(data)["output"].splitlines()] == \
            [l.rstrip() for l in l2cmd("r 1 s 2 l1 serial").splitlines()]
        g.ok &= same
        print(f"{'PASS' if same else 'FAIL'}  l2api command output is l2cmd's")
        ok, transcript = ws_console(["version", "r 1 s 2 l1 serial"])
        g.ok &= ok
        print(f"{'PASS' if ok else 'FAIL'}  l2api console: WebSocket handshake")
        g.check("console", transcript)
        g.check("events", first_event())
        l1.close()
    finally:
        for p in procs:
            p.terminate()
            p.wait()
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work)
    return g.status()


if __name__ == "__main__":
    sys.exit(main())
