#!/bin/sh
# Equivalence test of the L2's discovery responder (l3/l2/discover.c)
# against the main branch's (original) reconstruction, under ASan, over UDP
# on lo. Needs the main branch in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show main:compat/decomp.h > "$tmp/decomp.h"
rename='s/(?<![>.\w])(discover_\w+|version_attr|client_id)\b(?!\.h)/Orig$1/g'
grep '^[a-zA-Z].*' sys_ctrl/l3/l2/discover.h | grep -v '^#' | perl -pe "$rename" > "$tmp/orig_discover.h"
git show main:sys_ctrl/l3/l2/discover.c | perl -pe "$rename" |
    sed -e '/#include "decomp.h"/r '"$tmp/orig_discover.h" > "$tmp/orig_discover.c"
gcc -g -fsigned-char -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/l3/l2 -o "$tmp/l2discover_test" \
    tests/unit/l2discover_test.c sys_ctrl/l3/l2/discover.c "$tmp/orig_discover.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/l2discover_test"
