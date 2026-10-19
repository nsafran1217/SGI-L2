#!/bin/sh
# Equivalence test of the console address formats (l3/l2/format.c) against
# the main branch's (original) reconstruction, under ASan. Needs the faithful reconstruction
# branch in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show "${RECON_REF:-origin/main}":compat/decomp.h > "$tmp/decomp.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/l3/l2/format.c |
    sed -e 's/\bformat_\(c\{0,1\}address\)\b/Origformat_\1/g' > "$tmp/orig_format.c"
gcc -g -fsigned-char -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/l3/l2 -o "$tmp/format_test" \
    tests/unit/format_test.c sys_ctrl/l3/l2/format.c "$tmp/orig_format.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/format_test"
