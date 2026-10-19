#!/bin/sh
# Equivalence test of common/Router/Buff.c against the main branch's
# (original) reconstruction, under ASan. Needs the faithful reconstruction (origin/main, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show "${RECON_REF:-origin/main}":compat/decomp.h > "$tmp/decomp.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/common/Router/Buff.c |
    sed -e '/#include "..\/sys\/PPP.h"/d' -e 's/#include "Buff.h"/#include "decomp.h"/' \
        -e 's/\bBuff\(Compress\|Uncompress\|Free\)\b/OrigBuff\1/g' > "$tmp/orig_buff.c"
gcc -g -fsanitize=address -I"$tmp" -o "$tmp/buff_test" tests/unit/buff_test.c \
    sys_ctrl/common/Router/Buff.c "$tmp/orig_buff.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/buff_test"
