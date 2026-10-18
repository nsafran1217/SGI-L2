#!/bin/sh
# Differential test against SGI's original binaries.
#
#   tests/difftest.sh [ORIG_BIN_DIR]
#
# Runs each command in tests/l2_commands.txt through l2cmd in four pairings
# (original/rebuilt l2 daemon x original/rebuilt l2cmd) and requires the
# output to match the all-original pairing. Each daemon runs 'l2 -noconn'
# (no L1s) in its own temp directory, so the NVRAM file it creates
# (./.l2_NVRAM) never touches the tree. Lines with clock times are masked.
set -u

here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/.." && pwd)
orig=${1:-$src/../ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin}
new=$src/build/bin
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
            s/[0-9]{2}:[0-9]{2}:[0-9]{2}/<TIME>/g'
}

run_all() {         # run_all <l2cmd binary> <outfile>
    : > "$2"
    while IFS= read -r c; do
        case "$c" in ''|'#'*) continue ;; esac
        echo "=== $c" >> "$2"
        timeout 10 "$1" --l2 127.0.0.1 $c 2>&1 | mask >> "$2"
    done < "$cmds"
}

fail=0
for daemon in orig new; do
    eval d=\$$daemon
    start_l2 "$d/l2" "$work/$daemon" || exit 1
    for client in orig new; do
        eval c=\$$client
        run_all "$c/l2cmd" "$work/$daemon-$client.txt"
    done
    stop_l2
done

for pair in orig-new new-orig new-new; do
    if cmp -s "$work/orig-orig.txt" "$work/$pair.txt"; then
        echo "PASS  l2=${pair%-*} l2cmd=${pair#*-}"
    else
        echo "FAIL  l2=${pair%-*} l2cmd=${pair#*-}"
        diff "$work/orig-orig.txt" "$work/$pair.txt" | head -40
        fail=1
    fi
done
echo "$(grep -c '^===' "$work/orig-orig.txt") commands"
exit $fail
