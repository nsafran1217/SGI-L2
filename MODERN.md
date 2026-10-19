# The modern L2

This repository turns the reconstructed SGI L2 tools into something a
hobbyist can run on a current Linux machine next to an Origin 3000, Altix
or Onyx: no kernel driver, no 32-bit libraries, no binary NVRAM image, and
a web-friendly API. `l2` stays the daemon; `l2term`, `l2cmd` and `l2gui`
stay its clients.

It was cloned from the reconstruction (`origin`, the `src` repository):
`origin/main` is the faithful reconstruction of SGI's 1.62.0 source,
`origin/rewrite` the same code made readable without changing what it does.
Fixes to the reconstruction can still be fetched and merged.

## Rules

- **The wire stays compatible.** The Router and IRouter protocols, the
  ports, discovery and the SMP console are unchanged, so SGI's original
  clients and hardware L2s keep working with the new `l2`, and the new
  clients with theirs. `make interop` checks this against the original
  binaries.
- **Behaviour is pinned by `tests/golden/`.** An intentional change updates
  the goldens in the same commit (`make golden`), and the diff is reviewed;
  DEVIATIONS.md lists each change from SGI's tools.
- One kind of change per commit. Every commit passes `make check`.

## Phases

### 0. The repository
Native build by default; the session tests compare with golden
transcripts instead of needing the original binaries; `make interop`.

### 1. Removals
What a hobbyist installation doesn't need:
- authentication: `l2passwd`, the L2 password, the console login, `--pw`
  (a password arriving on the wire is ignored);
- host control from the console: `halt_l2`, `reboot_l2`, `shell`, `ip`,
  `dhcpserver`, setting the host's date and timezone, `smp modem baud`,
  `l2dbg dump`;
- the L1 simulator (`-l1sim`), serial and terminal-server L1 links
  (`-serial`, PPP), and the clients' direct L1 connections (`--dev`,
  `--serial`, `--sc`, `--scdev`);
- the PC L2's modem console, malloc profiling (`l2dbg m*`, `--mtrace`).

Kept: `-net` (L1s over TCP, which the tests' fake L1 uses), discovery, peer
L2s, `--copy`, `l2gui`.

### 2. Settings in a text file
The NVRAM image becomes a `key = value` file (`-c <file>`), rewritten
line by line when a console command changes a setting; its log ring becomes
a text log. `nvram reset` keeps its name.

### 3. USB without the kernel driver
L1s over libusb (`065e:1234`): bulk endpoints, the frame-length header the
`sgil1` driver added, hotplug, `-usbpath`, all in the existing event loop.
A udev rule lets `l2` run unprivileged.

### 4. Daemon behaviour and packaging
The stdin console only on request, `make install`, systemd units, udev
rule, socket directory.

### 5. `l2api`
A separate daemon serving HTTP and WebSockets on top of the client
library: the L2 and its bricks as JSON, commands, power, the console as a
WebSocket (for a later web version of `l2term` and `l2gui`), events.

## Progress

| Phase | State |
|---|---|
| 0 | done |
| 1 | done: no authentication, no host control from the console, no L1 simulator, serial L1 links, direct client L1 connections, modem console or malloc profiling (see DEVIATIONS.md) |
| 2 | done: `l2.conf` (settings.c) and `l2.log` (l2log.c) replace the NVRAM image; `-c <file>` |
| 3 | done: l1usb.c (libusb, a thread for its events, hotplug), the udev rule; tested with a fake libusb (tests/libusb_shim.c), not yet on hardware |
| 4 | done: the stdin console only with `-console` or on a terminal (and no spin at EOF), messages to stderr as a service; `make install`, `install-service`, the systemd unit; a Docker note. The socket directory needed no change: clients use TCP |
| 5 | done: `l2api` (its own small HTTP/WebSocket server, http.c, instead of a vendored library), `sgi-l2api.service`; tests/l2api_test.py |
