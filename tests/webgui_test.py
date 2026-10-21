#!/usr/bin/env python3
"""The web l2gui: l2gui_test's touch session in a headless browser.

    tests/webgui_test.py

l2api serves the web l2gui (the build's www directory) and connects to
'l2 -noconn'; headless Chrome or Chromium, driven over the DevTools
protocol, opens it at scale 1 and gets l2gui_test.py's clicks at the same
panel coordinates. The commands the page sends to l2api must match
tests/golden/webgui/. KEEP=1 keeps a screenshot of each step (the
canvas, 320x240): they are pixel for pixel SGI's l2gui's, but for its
mouse cursor.
"""

import base64
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from golden import Golden, NEW          # noqa: E402
from l2gui_test import SESSION, start_l2  # noqa: E402

PORT = 8180
BROWSERS = ("google-chrome", "chromium", "chromium-browser")


class DevTools:
    """A page of a browser, over its DevTools WebSocket (text frames only)."""

    def __init__(self, url):
        host, path = url[len("ws://"):].split("/", 1)
        name, port = host.rsplit(":", 1)
        self.s = socket.create_connection((name, int(port)), timeout=30)
        self.s.sendall((f"GET /{path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
                        "Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                        "Sec-WebSocket-Version: 13\r\n\r\n").encode())
        head = b""
        while b"\r\n\r\n" not in head:
            head += self.s.recv(1)
        self.buf = b""
        self.id = 0
        self.events = []

    def _read(self, n):
        while len(self.buf) < n:
            data = self.s.recv(65536)
            if not data:
                raise EOFError("the browser went away")
            self.buf += data
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _message(self):
        msg = b""
        while True:
            b0, b1 = self._read(2)
            n = b1 & 0x7f
            if n == 126:
                n = struct.unpack(">H", self._read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self._read(8))[0]
            msg += self._read(n)
            if b0 & 0x80:
                return json.loads(msg)

    def call(self, method, **params):
        self.id += 1
        data = json.dumps({"id": self.id, "method": method, "params": params}).encode()
        n = len(data)
        head = bytes([0x81]) + (bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + struct.pack(">H", n))
        self.s.sendall(head + b"\0\0\0\0" + data)       # (a zero mask)
        while True:
            m = self._message()
            if m.get("id") == self.id:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m["result"]
            self.events.append(m)

    def eval(self, expr):
        r = self.call("Runtime.evaluate", expression=expr, returnByValue=True)
        return r["result"].get("value")


def start_browser(work):
    exe = next(shutil.which(b) for b in BROWSERS if shutil.which(b))
    profile = os.path.join(work, "profile")
    proc = subprocess.Popen([exe, "--headless=new", "--remote-debugging-port=0",
                             f"--user-data-dir={profile}", "--no-first-run", "--window-size=800,600",
                             "--force-device-scale-factor=1", "about:blank"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        time.sleep(0.1)
        try:
            port = open(os.path.join(profile, "DevToolsActivePort")).read().split()[0]
            pages = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list"))
            return proc, DevTools(next(p for p in pages if p["type"] == "page")["webSocketDebuggerUrl"])
        except (OSError, IndexError, StopIteration):
            pass
    proc.kill()
    raise RuntimeError("the browser did not start")


def main():
    if not any(shutil.which(b) for b in BROWSERS):
        print("SKIP  webgui test: no Chrome or Chromium")
        return 0
    www = os.path.join(os.path.dirname(NEW), "www")
    g = Golden("webgui")
    work = tempfile.mkdtemp()
    procs = []
    try:
        procs.append(start_l2(work, os.path.join(NEW, "l2")))
        log = open(os.path.join(work, "l2api.txt"), "wb")
        procs.append(subprocess.Popen([os.path.join(NEW, "l2api"), "--listen", f"127.0.0.1:{PORT}",
                                       "--l2", "127.0.0.1", "--www", www], stdout=log, stderr=log))
        time.sleep(1)
        browser, page = start_browser(work)
        procs.append(browser)
        page.call("Network.enable")
        page.call("Page.navigate", url=f"http://127.0.0.1:{PORT}/?scale=1")
        for _ in range(50):
            time.sleep(0.2)
            if page.eval("document.readyState") == "complete":
                break
        time.sleep(3)                   # (connecting to l2api's events)
        left, top = page.eval("(r => [r.left, r.top])(document.getElementById('screen')"
                              ".getBoundingClientRect())")
        for step, pos in SESSION:
            if pos:
                for kind in ("mouseMoved", "mousePressed", "mouseReleased"):
                    page.call("Input.dispatchMouseEvent", type=kind, x=left + pos[0] + 0.5,
                              y=top + pos[1] + 0.5, button="left", clickCount=1)
                    time.sleep(0.1)
                time.sleep(0.7)
            if os.environ.get("KEEP"):
                png = page.eval("document.getElementById('screen').toDataURL()").split(",")[1]
                with open(os.path.join(work, f"{step}.png"), "wb") as f:
                    f.write(base64.b64decode(png))
        sent = [json.loads(e["params"]["request"]["postData"])["command"] for e in page.events
                if e.get("method") == "Network.requestWillBeSent" and
                e["params"]["request"]["url"].endswith("/api/v1/command")]
        if not sent:
            print("FAIL  webgui session: no commands sent")
            g.ok = False
        g.check("commands", sent)
    finally:
        for p in reversed(procs):
            p.terminate()
            p.wait()
        if os.environ.get("KEEP"):
            print("kept", work)
        else:
            shutil.rmtree(work, ignore_errors=True)
    print(f"{len(SESSION)} steps")
    return g.status()


if __name__ == "__main__":
    sys.exit(main())
