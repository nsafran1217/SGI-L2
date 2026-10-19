#!/bin/sh
# Equivalence test of L2 discovery (l3/api/SCapiL2.c) against the decomp
# branch's (original) reconstruction, under ASan: slot sorting, response
# parsing, the interface list, and a whole discovery on lo against a fake
# responder. Needs the decomp branch in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show decomp:compat/decomp.h > "$tmp/decomp.h"
git show decomp:sys_ctrl/l3/api/SCapiL2.c | sed -e '/syslimits.h/d' > "$tmp/orig_SCapiL2.c"
cp sys_ctrl/l3/api/SCapiL2.c "$tmp/new_SCapiL2.c"
for v in new orig; do
    gcc -g -fsanitize=address -w -Icompat -I"$tmp" -iquote sys_ctrl/l3/api -DIMPL="\"$v"_SCapiL2.c\" \
        -DPREFIX=$v -c -o "$tmp/$v.o" tests/unit/discover_wrap.c
done
gcc -g -fsanitize=address -Isys_ctrl/l3/api -Icompat -o "$tmp/discover_test" tests/unit/discover_test.c \
    "$tmp/new.o" "$tmp/orig.o"
ASAN_OPTIONS=detect_leaks=0 "$tmp/discover_test"
