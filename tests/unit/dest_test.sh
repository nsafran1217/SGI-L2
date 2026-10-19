#!/bin/sh
# Equivalence test of the destination selection (l3/l2/dest.c) against the
# decomp branch's (original) reconstruction, under ASan. Needs the decomp branch
# in git. (decomp's dest.c names a function exp(): -fno-builtin-exp.)
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show decomp:compat/decomp.h > "$tmp/decomp.h"
grep '^[a-zA-Z].*dest_.*(' sys_ctrl/l3/l2/dest.h | sed -e 's/\bdest_/Origdest_/' > "$tmp/orig_dest.h"
git show decomp:sys_ctrl/l3/l2/dest.c | sed -e 's/\bdest_\([a-z0-9]*\)\b/Origdest_\1/g' \
    -e '/#include "decomp.h"/r '"$tmp/orig_dest.h" > "$tmp/orig_dest.c"
gcc -g -fsigned-char -fno-builtin-exp -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/l3/l2 -o "$tmp/dest_test" \
    tests/unit/dest_test.c sys_ctrl/l3/l2/dest.c "$tmp/orig_dest.c" sys_ctrl/common/sys/brick_types.c
ASAN_OPTIONS=detect_leaks=0 "$tmp/dest_test"
