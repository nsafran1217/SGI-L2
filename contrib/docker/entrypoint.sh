#!/bin/sh
# The image's entry point (sgi-l2-entry):
#
#   all [options]  (the default) l2, its telnet console and, with WEBGUI=1,
#                  the web l2gui, in one container. When one of them ends
#                  (quit on the console ends l2), so does the container, and
#                  Docker's restart policy starts them all again.
#   l2 [options]   l2 alone, with its settings (l2.conf) and log in
#                  /var/lib/sgi-l2; options from L2_OPTIONS (default
#                  -discover) when none given
#   telnet         the L2's console on telnet port TELNET_PORT (default 23),
#                  with no login
#   webgui         l2api and the web l2gui on WEBGUI_LISTEN (default
#                  0.0.0.0:8080)
#
# (l2, telnet and webgui each in its own container, on the host's network,
# make the same as all.) Anything else runs as a command
# (docker run ... l2cmd --l2 <host> cfg).

set -e

run_l2() {
    cd /var/lib/sgi-l2
    # (L2_OPTIONS split into words)
    [ $# -gt 0 ] || set -- ${L2_OPTIONS--discover}
    exec l2 "$@"
}

run_telnet() {
    # BusyBox's telnetd runs l2-console in place of login (-l), shows no
    # /etc/issue (-f), and hangs up when the console ends (-K)
    port=${TELNET_PORT:-23}
    echo "the L2 console on telnet port $port" >&2
    exec telnetd -F -K -f /dev/null -p "$port" -l /usr/local/sbin/l2-console
}

run_webgui() {
    exec l2api --l2 localhost --www /usr/local/share/sgi-l2/www \
        --listen "${WEBGUI_LISTEN:-0.0.0.0:8080}" "$@"
}

case "$1" in
all|"")
    [ $# -gt 0 ] && shift
    run_l2 "$@" &
    pids=$!
    run_telnet &
    pids="$pids $!"
    if [ "${WEBGUI:-0}" = 1 ]; then
        run_webgui &
        pids="$pids $!"
    fi
    # until one ends (BusyBox's sh has no wait -n), then end with it
    while :; do
        for pid in $pids; do
            if ! kill -0 "$pid" 2>/dev/null; then
                set +e
                wait "$pid"
                exit $?
            fi
        done
        sleep 2
    done
    ;;
l2)
    shift
    run_l2 "$@"
    ;;
telnet)
    run_telnet
    ;;
webgui)
    shift
    run_webgui "$@"
    ;;
*)
    exec "$@"
    ;;
esac
