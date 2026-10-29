# SGI L2, prebuilt

This archive holds the SGI L2 tools built for one architecture (the
name says which: `amd64`, `arm64`, or `armv7` for 32-bit ARM, such as
32-bit Raspberry Pi OS on a Pi 2 or later). They are static (built with
musl), so they need no libraries and run on any Linux of that
architecture, whatever its distribution or age.

| | |
|---|---|
| `bin/l2` | the L2 system controller (a daemon) |
| `bin/l2term`, `bin/l2cmd` | its console and its command line client |
| `bin/l2api` | the HTTP API, and the web l2gui at its `/` with `--www share/sgi-l2/www` |
| `bin/l2telnetd` | the console for telnet clients, started by `sgi-l2-telnet.socket` |
| `bin/l2gui` | the touch screen GUI, an X11 program: `l2gui --l2 <host>` |
| `systemd/`, `udev/` | the services and the udev rule for the L1s |

`l2gui` needs an X display, and draws with the X server's core fonts:
for the look of SGI's, Helvetica from `xfonts-75dpi` or `xfonts-100dpi`
(Debian's names) on the machine with the display.

## Install

    sudo ./install.sh

`install.sh` puts the tools in `/usr/local/bin` (`PREFIX=` for another
place), installs the udev rule that gives the L1s (USB `065e:1234`) to
the group `sgi-l2` (GID 1234), and creates that group. Add yourself to it
(`sudo usermod -aG sgi-l2 $USER`; the user at the console has access
anyway) to run `l2` as yourself. `./install.sh --tools-only` installs
only the tools.

To run `l2` as a service instead:

    sudo ./install.sh --service
    sudo systemctl enable --now sgi-l2        # l2, settings in /var/lib/sgi-l2/l2.conf
    sudo systemctl enable --now sgi-l2api     # optional: http://127.0.0.1:8080/
    sudo systemctl enable --now sgi-l2-telnet.socket   # optional: the console on telnet port 23

`--service` also installs the systemd units and creates the user
`sgi-l2` they run as; it enables nothing. Options for `l2` go
in `/etc/default/sgi-l2` (`L2_OPTIONS=-discover` is the default), and for
`l2api` in `/etc/default/sgi-l2api` (`L2API_OPTIONS=--listen 0.0.0.0:8080`
to reach it from other machines: it has no authentication). The telnet
console has no login either: whoever reaches port 23 can power the system
up and down. Another port: `sudo systemctl edit sgi-l2-telnet.socket`
(`contrib/systemd/sgi-l2-telnet.socket` shows how).

Then:

    l2term --l2 localhost      # the console; CTRL-] q quits
    telnet localhost           # the same, with sgi-l2-telnet.socket enabled
    l2cmd --l2 localhost cfg

SGI's own L3 and IST tools reach this `l2` as they would SGI's: ports
8000-8003, 9001, 9002, and discovery on UDP 10000.

The source, and a Docker setup: https://github.com/nsafran1217/SGI-L2
