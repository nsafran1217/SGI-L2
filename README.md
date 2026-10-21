# SGI L2 controller tools, modern

`l2` (the L2 system controller, as SGI's L3 software emulated it on a PC),
and its clients `l2term`, `l2cmd` and `l2gui`, rebuilt from source for
current Linux. The source was reconstructed from SGI's snxsc_l3 1.62.0
binaries (IST 3.24).

This repo will have improvments and bug fixes to the original tools, 
as well as fixes to allow them to compile on modern hosts and architectures.

The biggest improvment is the removing the need for a kernel driver for `sgil1`.   
Just run the `l2` binary with a L1 connected to your computer.

TODO:  
Dockerfile  
Better Readme  
test the IST tools (`errdump`, etc.) and fix if broken

The vast majority of this content has been written by an LLM (Claude Opus 5.5).

### Branches
 - decomp - ghidra and claude decomp of original binaries with changes to allow it to build on 64 bit hosts  
- rewrite-decomp - Claude rewritten to be more readable. Matches behavior of original totols
- main - Modernized as needed, removes the requirement for the `sgil1` driver

## Build

    make            # build/bin/{l2,l2term,l2cmd,l2api,l2gui}

Needs gcc, make and libusb (Debian: `libusb-1.0-0-dev`); without libusb
the build fails, and `make USB=no` builds an `l2` with no USB L1s
(`-net` and `-noconn` only). `l2gui` also needs FLTK 1.3 or 1.4
(`FLTK_CONFIG=<path to fltk-config>`); without it, `make` skips `l2gui`.
In the reconstruction workspace, `../retools/setup_fltk.sh 64` builds one
into `../tools/fltk/`.

Other builds:

    make ARCH=-m32 B=build32          # 32-bit (the original binaries' struct layouts)
    make B=build64asan EXTRA_CFLAGS=-fsanitize=address EXTRA_LDFLAGS=-fsanitize=address

## Run

`l2` reaches the L1s on USB itself, through libusb: no kernel driver.
To run it as a user rather than root, `sudo make install-udev` installs
the udev rule (`contrib/udev/60-sgi-l1.rules`), which gives the L1s to the
group `sgi-l2`, and creates that group with GID 1234 (`L1_GID=` for
another); add yourself to it (the user at the console has access anyway). With SGI's `sgil1`
driver loaded, `l2` detaches it from the L1s it opens.

    l2                                # USB L1s; settings in ./l2.conf
    l2 -usbpath 'b1;p2'               # only the L1s behind bus 1, port 2
    l2 -noconn                        # an L2 with no bricks
    l2 -console                       # also a console on stdin (on by default on a terminal)

As a service: `sudo make install-service` installs the tools, the udev rule
and its group, and a systemd unit (`contrib/systemd/sgi-l2.service`, which says how to
create its user); settings are then in `/var/lib/sgi-l2/l2.conf`.
`contrib/docker/README.md` runs it in a container.
    l2term --l2 localhost             # its console; CTRL-] q quits
    l2cmd --l2 localhost version

## HTTP API (l2api)

`l2api` is an L2 client, like `l2term`, that serves an HTTP API for
scripts and for a web interface:

    l2api --l2 localhost              # http://127.0.0.1:8080/api/v1/
    curl localhost:8080/api/v1/config
    curl -d '{"command": "r 1 s 7 pwr"}' localhost:8080/api/v1/command

| Endpoint | |
|---|---|
| `GET /api/v1/l2` | the L2s of the system (address, rack, serial, system name, whether the display is locked) and whether `l2api` is connected |
| `GET /api/v1/config` | the bricks: name (`001c07`), rack, slot, type, partition, power, serial numbers |
| `POST /api/v1/command` | an L2 command, as `l2cmd` runs it: `{"command": "..."}` or plain text; answers `{"status": 0, "output": "..."}` (and a `"message"` for a status other than 0) |
| `POST /api/v1/power` | `{"action": "up\|down\|reset\|status", "target": "r 1 s 7"}` (target optional: the L2's destination) |
| `GET /api/v1/console` | a WebSocket to the L2's console, byte for byte, as `l2term` has it |
| `GET /api/v1/events` | server-sent events: `config`, with the bricks, and `l2`, as `/api/v1/l2` has it, whenever they change |

`--www <dir>` also serves the files in a directory (a web interface).
`l2api` has no authentication: it listens on 127.0.0.1 only, unless
`--listen 0.0.0.0:8080`. To reach it from elsewhere, put a web server with
TLS and a password in front of it. With Caddy:

    l2.example.net {
        basic_auth { admin <hash from caddy hash-password> }
        reverse_proxy 127.0.0.1:8080
    }

or Apache (mod_proxy, mod_proxy_http, mod_proxy_wstunnel):

    <Location /api/>
        AuthType Basic
        AuthName "L2"
        AuthUserFile /etc/apache2/l2.htpasswd
        Require valid-user
        ProxyPass http://127.0.0.1:8080/api/ upgrade=websocket
    </Location>

Requests are served one at a time: a command holds the others up for as
long as the L2 takes to answer it.

## Web l2gui

`sys_ctrl/l3/webgui` is `l2gui` as a web page: plain JavaScript modules,
no build step, served by `l2api --www` (`make` copies it, with the logos,
to `build/www`; `make install` to `$(PREFIX)/share/sgi-l2/www`, which the
installed `sgi-l2api.service` serves):

    l2api --l2 localhost --www build/www      # http://127.0.0.1:8080/

It draws the L2's 320x240 panel on a canvas, pixel for pixel as SGI's
`l2gui` did (its FLTK 1.0 widgets on Nano-X, with Nano-X's font and
palette; `tools/mkwebdata.py` takes those from the original binary into
`fldata.js`), scaled by a whole number to fit the window (`?scale=N` fixes
it). Each module is a port of the `gui/*.cc` file of the same name. It
follows the L2 through `/api/v1/events` and sends its commands to
`/api/v1/command`, so it works wherever the API does, behind a proxy too.

## Test

    make check      # unit tests, then every session test against tests/golden/
    make golden     # rewrite tests/golden/ from this build: review the diff
    make interop    # also run SGI's original binaries (../ist, or ORIG_BIN=<dir>)
    make test       # struct layouts as in the original i386 binaries

The session tests (`tests/*_test.py`, `difftest.sh`, `options_test.sh`)
run the tools of one build (`NEW_BIN=<build>/bin`, default `build/bin`)
and compare what they print, what the fake L1 receives and the bytes
`l2gui` exchanges with the golden transcripts. They were recorded while the
tools still matched SGI's binaries exactly; any intentional change updates
them in the same commit. Run one test at a time: they share ports 8000-8003
(and display :77).

`make interop` adds runs with SGI's original binaries: the original
clients against this `l2` must produce the goldens, and this build's
clients against the original `l2` must produce what the original clients
do. That is the check that the wire format stays compatible.

The unit tests (`tests/unit/`) compare modules with the faithful
reconstruction in the `decomp` branch (`RECON_REF=<ref>`) and are skipped if
it is not in git.

`l2gui_test.py` needs Xvfb, xdotool, ImageMagick and strace;
`webgui_test.py` needs Chrome or Chromium (it runs l2gui's session in the
web l2gui, headless).

## Configurable paths

| Variable | What | Default |
|---|---|---|
| `SGI_L2_CONFIG` | `l2`'s settings file (`.N` appended with `--copy N`; `l2 -c <file>` overrides); its log, `l2.log`, is in the same directory | `$STATE_DIRECTORY/l2.conf` under systemd, else `./l2.conf` |
| `SGI_L3_SOCKET_DIR` | local `UNIX_xxxx` sockets | `/usr/tmp`, or `/tmp` if `/usr/tmp` does not exist |

## Documents

- MODERN.md: the plan and its progress.
- DEVIATIONS.md: every way the tools differ from SGI's 1.62.0.
- ORIGINAL_BUGS.md: SGI's bugs found in the reconstruction, kept or fixed.

The SGI code is SGI's; this is a reconstruction for running and preserving
their hardware.
