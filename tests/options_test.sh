#!/bin/bash
# The system controller command-line options (sn1SCParseCmdline() and the
# connection setup in l3/api/SCapi.c): each line of options below goes to
# l2cmd, against one local 'l2 -noconn', and the output must match
# tests/golden/options/ (tests/golden.sh). No line leaves the L2 unnamed, so
# nothing broadcasts for discovery. The options are the client's own, so
# there is no interop run.
#
#   tests/options_test.sh
set -u

here=$(cd "$(dirname "$0")" && pwd)
. "$here/golden.sh"
work=$(mktemp -d)
trap 'kill $dpid 2>/dev/null; [ "${KEEP:-}" ] && echo "kept $work" || rm -rf "$work"' EXIT INT TERM
dpid=

L='--l2 127.0.0.1'
cat > "$work/options" <<OPTS
$L version
--l2
--l2 --irtr version
--if
--if 0 $L version
--interface lo $L version
--ssn
--ssn ABC:x $L version
--ssn ABC:0 $L version
--ssn ABC:2 $L version
--sysname foo:2 $L version
--sysname
--r
--rack 3 $L version
--pw
--pw secret $L version
--copy
--copy 999 $L version
--copy -1 $L version
--copy 1 $L version
--irtr $L version
--irtr $L l1 version
--quiet $L version
--timeout
--timeout 5 $L version
--scdev
--scdev /nonexistent/sc version
--sc version
$L --unknown version
$L
--mtrace $L version
OPTS

mkdir -p "$work/l2" "$work/new"
mkfifo "$work/l2/stdin"
(cd "$work/l2" && exec "$new/l2" -noconn < stdin > daemon.log 2>&1) &
dpid=$!
exec 3> "$work/l2/stdin"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -q "SMP listening on port: 8003" "$work/l2/daemon.log" 2>/dev/null && break
    sleep 0.3
done

# the program name is in the messages
ln -s "$new/l2cmd" "$work/new/l2cmd"
for v in new; do
    : > "$work/$v.txt"
    while IFS= read -r opts; do
        echo "=== $opts" >> "$work/$v.txt"
        # shellcheck disable=SC2086
        (cd "$work/$v" && \
            timeout 20 ./l2cmd $opts) > "$work/out" 2>&1
        status=$?
        sed -E "s/[0-9]{2}:[0-9]{2}:[0-9]{2}/<TIME>/g; s|$work|<work>|g" "$work/out" >> "$work/$v.txt"
        echo "exit $status" >> "$work/$v.txt"
    done < "$work/options"
done

golden_check options l2cmd "$work/new.txt"
echo "$(grep -c . "$work/options") option lines"
exit $golden_fail
