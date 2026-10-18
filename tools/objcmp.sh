#!/bin/sh
# objcmp.sh <ref-build-dir> <new-build-dir>
#
# For mechanical cleanups: compare every object file of two builds of the tree
# (same ARCH and flags) with debug info stripped. Identical code proves a
# transform changed no behaviour. Lists the objects that differ; exit 1 if any.
set -eu
ref=$1 new=$2
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
status=0
n=0
for o in $(cd "$ref" && find . -name '*.o' | sort); do
    n=$((n + 1))
    if [ ! -f "$new/$o" ]; then echo "missing: $o"; status=1; continue; fi
    objcopy --strip-debug "$ref/$o" "$tmp/a.o"
    objcopy --strip-debug "$new/$o" "$tmp/b.o"
    cmp -s "$tmp/a.o" "$tmp/b.o" || { echo "differs: $o"; status=1; }
done
[ $status = 0 ] && echo "objcmp: all $n objects identical"
exit $status
