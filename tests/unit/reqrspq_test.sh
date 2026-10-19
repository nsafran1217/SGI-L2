#!/bin/sh
# Equivalence test of the request/response queues (l3/l2/reqrspq.c) against
# the main branch's (original) reconstruction, under ASan. Needs the faithful reconstruction
# branch in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
. tests/unit/recon.sh
git show "${RECON_REF:-origin/main}":compat/decomp.h > "$tmp/decomp.h"
# the functions, not the struct fields of the same names (q->rspq_head)
rename='s/(?<![>.\w])(reqrspq_(init|reset|free)|reqq_\w+|rspq_\w+)\b(?!\.h)/Orig$1/g'
grep '^[a-zA-Z].*(' sys_ctrl/l3/l2/reqrspq.h | perl -pe "$rename" > "$tmp/orig_reqrspq.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/l3/l2/reqrspq.c | perl -pe "$rename" |
    sed -e '/#include "decomp.h"/r '"$tmp/orig_reqrspq.h" > "$tmp/orig_reqrspq.c"
gcc -g -fsigned-char -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/l3/l2 -o "$tmp/reqrspq_test" \
    tests/unit/reqrspq_test.c sys_ctrl/l3/l2/reqrspq.c "$tmp/orig_reqrspq.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/reqrspq_test"
