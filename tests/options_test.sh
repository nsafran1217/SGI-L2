#!/bin/sh
# Differential test of the system controller command-line options
# (sn1SCParseCmdline() and the connection setup in l3/api/SCapi.c): each
# line of options below goes to the original and the rebuilt l2cmd, against
# one local 'l2 -noconn', and their output must match. No line leaves the
# L2 unnamed, so nothing broadcasts for discovery.
#
#   tests/options_test.sh [ORIG_BIN_DIR]
set -u

here=$(cd "$(dirname "$0")" && pwd)
src=$(cd "$here/.." && pwd)
orig=${1:-$src/../ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin}
new=${NEW_BIN:-$src/build/bin}
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

mkdir -p "$work/l2" "$work/orig" "$work/new"
mkfifo "$work/l2/stdin"
(cd "$work/l2" && exec "$new/l2" -noconn < stdin > daemon.log 2>&1) &
dpid=$!
exec 3> "$work/l2/stdin"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    grep -q "SMP listening on port: 8003" "$work/l2/daemon.log" 2>/dev/null && break
    sleep 0.3
done

# the same program name for both (it is in the messages)
ln -s "$orig/l2cmd" "$work/orig/l2cmd"
ln -s "$new/l2cmd" "$work/new/l2cmd"
for v in orig new; do
    : > "$work/$v.txt"
    while IFS= read -r opts; do
        echo "=== $opts" >> "$work/$v.txt"
        # shellcheck disable=SC2086
        (cd "$work/$v" && MALLOC_TRACE=$work/mtrace SGI_L3_DEV_DIR=/nonexistent \
            timeout 20 ./l2cmd $opts) > "$work/out" 2>&1
        status=$?
        sed -E 's/[0-9]{2}:[0-9]{2}:[0-9]{2}/<TIME>/g' "$work/out" >> "$work/$v.txt"
        echo "exit $status" >> "$work/$v.txt"
    done < "$work/options"
done

n=$(grep -c . "$work/options")
if cmp -s "$work/orig.txt" "$work/new.txt"; then
    echo "PASS  options: $n option lines, l2cmd=orig and l2cmd=new agree"
else
    echo "FAIL  options"
    diff "$work/orig.txt" "$work/new.txt" | head -40
    exit 1
fi
