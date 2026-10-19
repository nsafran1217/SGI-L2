#!/bin/sh
# Equivalence test of broadcasting (l3/l2/broadcast.c) against the decomp
# branch's (original) reconstruction, under ASan. Needs the decomp branch in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show decomp:compat/decomp.h > "$tmp/decomp.h"
rename='s/(?<![>.\w])(broadcast\w*)\b(?!\.h)/Orig$1/g'
grep '^[a-zA-Z].*broadcast' sys_ctrl/l3/l2/broadcast.h | perl -pe "$rename" > "$tmp/orig_broadcast.h"
git show decomp:sys_ctrl/l3/l2/broadcast.c | perl -pe "$rename" |
    sed -e '/#include "decomp.h"/r '"$tmp/orig_broadcast.h" > "$tmp/orig_broadcast.c"
gcc -g -fsigned-char -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/l3/l2 -o "$tmp/broadcast_test" \
    tests/unit/broadcast_test.c sys_ctrl/l3/l2/broadcast.c "$tmp/orig_broadcast.c" \
    sys_ctrl/l3/l2/reqrspq.c sys_ctrl/common/sys/brick_types.c
ASAN_OPTIONS=detect_leaks=0 "$tmp/broadcast_test"
