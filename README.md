# SGI L2 controller tools, modern

`l2` (the L2 system controller, as SGI's L3 software emulated it on a PC),
and its clients `l2term`, `l2cmd` and `l2gui`, rebuilt from source for
current Linux. The source was reconstructed from SGI's snxsc_l3 1.62.0
binaries (IST 3.24); this repository is where it becomes a tool for
hobbyists with an Origin 3000, Altix or Onyx: see MODERN.md for what is
changing and how far along it is.

## Build

    make            # build/bin/{l2,l2term,l2cmd,l2gui}

Needs gcc, make and libusb (Debian: `libusb-1.0-0-dev`; without it `l2`
has no USB L1s). `l2gui` also needs FLTK 1.3 or 1.4
(`FLTK_CONFIG=<path to fltk-config>`); without it, `make` skips `l2gui`.
In the reconstruction workspace, `../retools/setup_fltk.sh 64` builds one
into `../tools/fltk/`.

Other builds:

    make ARCH=-m32 B=build32          # 32-bit (the original binaries' struct layouts)
    make B=build64asan EXTRA_CFLAGS=-fsanitize=address EXTRA_LDFLAGS=-fsanitize=address

## Run

`l2` reaches the L1s on USB itself, through libusb: no kernel driver.
To run it as a user rather than root, install the udev rule
(`contrib/udev/60-sgi-l1.rules`, instructions inside). With SGI's `sgil1`
driver loaded, `l2` detaches it from the L1s it opens.

    l2                                # USB L1s; settings in ./l2.conf
    l2 -usbpath 'b1;p2'               # only the L1s behind bus 1, port 2
    l2 -noconn                        # an L2 with no bricks
    l2 -console                       # also a console on stdin (on by default on a terminal)

As a service: `sudo make install-service` installs the tools, the udev rule
and a systemd unit (`contrib/systemd/sgi-l2.service`, which says how to
create its user); settings are then in `/var/lib/sgi-l2/l2.conf`.
`contrib/docker/README.md` runs it in a container.
    l2term --l2 localhost             # its console; CTRL-] q quits
    l2cmd --l2 localhost version

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
reconstruction in `origin/main` (`RECON_REF=<ref>`) and are skipped if
it is not in git.

`l2gui_test.py` needs Xvfb, xdotool, ImageMagick and strace.

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
