#!/bin/sh
# The image's entry point (sgi-l2-entry). docker-compose.yml runs one
# container of each kind from the same image:
#
#   l2 [options]  l2, with its settings (l2.conf) and log in /var/lib/sgi-l2;
#                 options from L2_OPTIONS (default -discover) when none given
#   telnet        the L2's console on telnet port TELNET_PORT (default 23),
#                 with no login
#   webgui        l2api and the web l2gui on WEBGUI_LISTEN (default
#                 0.0.0.0:8080)
#
# Anything else runs as a command (docker run ... l2cmd --l2 <host> cfg).

set -e

case "$1" in
l2)
    shift
    cd /var/lib/sgi-l2
    # (L2_OPTIONS split into words)
    [ $# -gt 0 ] || set -- ${L2_OPTIONS--discover}
    exec l2 "$@"
    ;;
telnet)
    # BusyBox's telnetd runs l2-console in place of login (-l), shows no
    # /etc/issue (-f), and hangs up when the console ends (-K)
    port=${TELNET_PORT:-23}
    echo "the L2 console on telnet port $port" >&2
    exec telnetd -F -K -f /dev/null -p "$port" -l /usr/local/sbin/l2-console
    ;;
webgui)
    shift
    exec l2api --l2 localhost --www /usr/local/share/sgi-l2/www \
        --listen "${WEBGUI_LISTEN:-0.0.0.0:8080}" "$@"
    ;;
*)
    exec "$@"
    ;;
esac
