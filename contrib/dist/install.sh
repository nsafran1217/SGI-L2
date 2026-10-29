#!/bin/sh
# Installs this release archive (make dist) as make install would from a
# build: the tools into $PREFIX/bin, the web l2gui into
# $PREFIX/share/sgi-l2/www, and the udev rule with its group sgi-l2 (GID
# 1234). --service also installs the systemd units and the user sgi-l2 they
# run as (make install-service); it enables nothing. Run it as root from the
# unpacked archive.
#
#   sudo ./install.sh                  # the tools, the udev rule and its group
#   sudo ./install.sh --service        # these and the systemd units
#   sudo ./install.sh --tools-only     # only the tools and the web l2gui
#
# PREFIX (default /usr/local), DESTDIR (a staging root: no group, user or
# udev reload), L1_GID (default 1234).

set -e
cd "$(dirname "$0")"

PREFIX=${PREFIX:-/usr/local}
BINDIR=$PREFIX/bin
WWWDIR=$PREFIX/share/sgi-l2/www
UDEVDIR=${UDEVDIR:-/etc/udev/rules.d}
SYSTEMDDIR=${SYSTEMDDIR:-/etc/systemd/system}
L1_GROUP=sgi-l2
L1_GID=${L1_GID:-1234}
D=${DESTDIR:-}

tools_only= service=
case "$1" in
    --tools-only) tools_only=1 ;;
    --service) service=1 ;;
    "") ;;
    *) echo "usage: $0 [--service | --tools-only]" >&2; exit 2 ;;
esac

install -d "$D$BINDIR" "$D$WWWDIR/images"
install -m 755 bin/* "$D$BINDIR"
install -m 644 share/sgi-l2/www/*.* "$D$WWWDIR"
install -m 644 share/sgi-l2/www/images/* "$D$WWWDIR/images"
echo "installed $(ls bin | tr '\n' ' ')into $D$BINDIR, the web l2gui into $D$WWWDIR"

if ldd bin/l2 2>/dev/null | grep -q 'libusb.*not found'; then
    echo "warning: no libusb-1.0 found; l2 needs it (Debian: apt install libusb-1.0-0)" >&2
fi
[ -n "$tools_only" ] && exit 0

install -d "$D$UDEVDIR"
install -m 644 udev/60-sgi-l1.rules "$D$UDEVDIR"
if [ -n "$service" ]; then
    install -d "$D$SYSTEMDDIR"
    sed "s|@BINDIR@|$BINDIR|g" systemd/sgi-l2.service > "$D$SYSTEMDDIR/sgi-l2.service"
    sed "s|@BINDIR@|$BINDIR|g; s|@WWWDIR@|$WWWDIR|g" systemd/sgi-l2api.service \
        > "$D$SYSTEMDDIR/sgi-l2api.service"
fi

if [ -n "$D" ]; then
    echo "next: groupadd --system --gid $L1_GID $L1_GROUP"
    [ -n "$service" ] &&
        echo "      useradd --system --gid $L1_GROUP --no-create-home --shell /usr/sbin/nologin $L1_GROUP"
    exit 0
fi

gid=$(getent group $L1_GROUP | cut -d: -f3)
if [ -z "$gid" ]; then
    echo "groupadd --system --gid $L1_GID $L1_GROUP"
    groupadd --system --gid "$L1_GID" $L1_GROUP
elif [ "$gid" != "$L1_GID" ]; then
    echo "group $L1_GROUP exists with GID $gid, not $L1_GID" >&2; exit 1
fi
udevadm control --reload && udevadm trigger --subsystem-match=usb --attr-match=idVendor=065e || true

if [ -z "$service" ]; then
    echo "next: usermod -aG $L1_GROUP <you> (to run l2 as yourself), or $0 --service for the systemd units"
    exit 0
fi
if ! getent passwd $L1_GROUP >/dev/null; then
    echo "useradd --system --gid $L1_GROUP --no-create-home --shell /usr/sbin/nologin $L1_GROUP"
    useradd --system --gid $L1_GROUP --no-create-home --shell /usr/sbin/nologin $L1_GROUP
fi
systemctl daemon-reload || true

echo "next: systemctl enable --now sgi-l2"
echo "      (the HTTP API and web l2gui: systemctl enable --now sgi-l2api)"
