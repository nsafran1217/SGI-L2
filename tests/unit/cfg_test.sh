#!/bin/sh
# Equivalence test of the configuration upkeep (l3/l2/cfg.c) against the
# decomp branch's (original) reconstruction, under ASan. Needs the decomp branch
# in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show decomp:compat/decomp.h > "$tmp/decomp.h"
rename='s/(?<![>.\w])(cfg_\w+|pp|strdiff|del_client|del_addr|find_client_to_delete)\b(?!\.h)/Orig$1/g'
grep '^[a-zA-Z]' sys_ctrl/l3/l2/cfg.h | perl -pe "$rename" > "$tmp/orig_cfg.h"
git show decomp:sys_ctrl/l3/l2/cfg.c | perl -pe "$rename" |
    sed -e '/#include "decomp.h"/r '"$tmp/orig_cfg.h" > "$tmp/orig_cfg.c"
gcc -g -fsigned-char -fno-builtin-fprintf -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/l3/l2 -o "$tmp/cfg_test" \
    tests/unit/cfg_test.c sys_ctrl/l3/l2/cfg.c "$tmp/orig_cfg.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/cfg_test" 2>/dev/null   # (its messages)
