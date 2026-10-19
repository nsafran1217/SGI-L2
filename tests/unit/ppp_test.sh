#!/bin/sh
# Equivalence test of the PPP framing (common/sys/PPP.c) against the main
# branch's (original) reconstruction, under ASan. Needs the faithful reconstruction (origin/main, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
orig='s/\b\(_\{0,1\}\)\(PPP[A-Za-z]*\|buff\)\b/\1Orig\2/g'
git show "${RECON_REF:-origin/main}":compat/decomp.h > "$tmp/decomp.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/common/sys/PPP.h |
    sed -e 's/_PPP_H\b/_ORIG_PPP_H/' -e "$orig" > "$tmp/orig_ppp.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/common/sys/PPP.c |
    sed -e 's/#include "PPP.h"/#include "orig_ppp.h"/' -e '/syslimits.h/d' -e "$orig" > "$tmp/orig_ppp.c"
gcc -g -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/common/sys \
    -o "$tmp/ppp_test" tests/unit/ppp_test.c sys_ctrl/common/sys/PPP.c "$tmp/orig_ppp.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/ppp_test"
