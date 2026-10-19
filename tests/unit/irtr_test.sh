#!/bin/sh
# Equivalence test of the L2's packet switch (l3/l2/irtr.c) against the decomp
# branch's (original) reconstruction, under ASan. Needs the faithful reconstruction (decomp, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
. tests/unit/recon.sh
git show "${RECON_REF:-decomp}":compat/decomp.h > "$tmp/decomp.h"
rename='s/(?<![>.\w])(IRouterSend\w+|irtr_debug)\b(?!\.h)/Orig$1/g'
grep '^[a-zA-Z]' sys_ctrl/l3/l2/irtr.h | perl -pe "$rename" > "$tmp/orig_irtr.h"
git show "${RECON_REF:-decomp}":sys_ctrl/l3/l2/irtr.c | perl -pe "$rename" |
    sed -e '/#include "decomp.h"/r '"$tmp/orig_irtr.h" > "$tmp/orig_irtr.c"
gcc -g -fsigned-char -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/l3/l2 -o "$tmp/irtr_test" \
    tests/unit/irtr_test.c sys_ctrl/l3/l2/irtr.c "$tmp/orig_irtr.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/irtr_test"
