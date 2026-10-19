#!/bin/bash
# The L2's commands through l2cmd, against golden transcripts.
#
#   tests/difftest.sh
#
# Runs each command in tests/l2_commands.txt through l2cmd against 'l2
# -noconn' (no L1s), in a temp directory so the files it writes stay out of
# the tree, and compares the output and the daemon's own log with
# tests/golden/difftest/. Lines with clock times are masked. INTEROP=1 also
# pits SGI's original l2cmd and l2 against these (tests/golden.sh).
set -u

here=$(cd "$(dirname "$0")" && pwd)
. "$here/golden.sh"
cmds=$here/l2_commands.txt
work=$(mktemp -d)
trap 'kill $dpid 2>/dev/null; [ "${KEEP:-}" ] && echo "kept $work" || rm -rf "$work"' EXIT INT TERM
dpid=

start_l2() {        # start_l2 <l2 binary> <dir>
    mkdir -p "$2"
    mkfifo "$2/stdin"
    # l2 spins if stdin hits EOF; give it a fifo that never delivers data
    (cd "$2" && exec "$1" -noconn < stdin > daemon.log 2>&1) &
    dpid=$!
    exec 3> "$2/stdin"
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        grep -q "SMP listening on port: 8003" "$2/daemon.log" 2>/dev/null && return 0
        sleep 0.3
    done
    echo "l2 did not start: $1" >&2
    cat "$2/daemon.log" >&2
    return 1
}

stop_l2() {
    kill "$dpid" 2>/dev/null
    wait "$dpid" 2>/dev/null
    exec 3>&-
    dpid=
}

mask() {            # hide wall-clock times, and the timing entries l2 logs per connection
    sed -E '/SMP [0-9]+ waited [0-9.]+$/d;
            s/[A-Z][a-z]{2} [A-Z][a-z]{2} +[0-9]+ [0-9:]{8} [0-9]{4}/<DATE>/g;
            s/[0-9]{2}:[0-9]{2}:[0-9]{2}/<TIME>/g;
            s|[0-9]{2}/[0-9]{2}/[0-9]{2}|<DATE>|g'
}

run_all() {         # run_all <l2cmd binary> <outfile>
    : > "$2"
    while IFS= read -r c; do
        case "$c" in ''|'#'*) continue ;; esac
        echo "=== $c" >> "$2"
        timeout 10 "$1" --l2 127.0.0.1 $c 2>&1 | mask >> "$2"
    done < "$cmds"
}

start_l2 "$new/l2" "$work/new" || exit 1
run_all "$new/l2cmd" "$work/new-new.txt"
sleep 0.5
mask < "$work/new/daemon.log" > "$work/daemon.txt"
[ -n "${INTEROP:-}" ] && run_all "$orig/l2cmd" "$work/new-orig.txt"
stop_l2
golden_check difftest l2cmd "$work/new-new.txt"
golden_check difftest daemon "$work/daemon.txt"
if [ -n "${INTEROP:-}" ]; then
    golden_check difftest l2cmd "$work/new-orig.txt"    # (the original l2cmd)
    start_l2 "$orig/l2" "$work/orig" || exit 1
    run_all "$orig/l2cmd" "$work/orig-orig.txt"
    run_all "$new/l2cmd" "$work/orig-new.txt"
    stop_l2
    golden_same "difftest: l2=orig, l2cmd=new gives the original l2cmd's output" \
        "$work/orig-orig.txt" "$work/orig-new.txt"
fi
echo "$(grep -c '^===' "$work/new-new.txt") commands"
exit $golden_fail
