#!/bin/sh
# Equivalence test of the brick type conversions (common/sys/brick_types.c)
# against the main branch's (original) reconstruction, under ASan, for every
# type value. Needs the main branch in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show main:compat/decomp.h > "$tmp/decomp.h"
git show main:sys_ctrl/common/sys/brick_types.c |
    sed -e '/#include "PPP.h"/d' -e 's/#include "brick_types.h"/#include <stdint.h>/' \
        -e 's/\bbrick\([A-Z][A-Za-z]*\)\b/Origbrick\1/g' > "$tmp/orig_brick.c"
gcc -g -fsanitize=address -Icompat -I"$tmp" -o "$tmp/brick_test" tests/unit/brick_test.c \
    sys_ctrl/common/sys/brick_types.c "$tmp/orig_brick.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/brick_test"
