#!/bin/sh
# Equivalence test of the malloc profiler's bookkeeping and reports
# (common/sys/minfo.c) against the main branch's (original) reconstruction,
# under 32-bit ASan. The malloc hooks are gone from glibc, so the test drives the
# block list directly. Needs the faithful reconstruction (origin/main, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show "${RECON_REF:-origin/main}":compat/decomp.h > "$tmp/decomp.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/common/sys/minfo.c |
    sed -e 's|#include "\.\./\.\./l3/l2/smp.h".*||' \
        -e 's|#include "minfo.h".*|#include "../sys_ctrl/common/sys/minfo.h"|' \
        -e 's|#include "\.\./\.\./l3/main/nvram.h".*|void nvramLogFinsert(char *fmt, ...);|' > "$tmp/orig_minfo.c"
cp sys_ctrl/common/sys/minfo.c "$tmp/new_minfo.c"
# 32-bit, as the original's reports assume (its map lines overflow with 64-bit
# addresses); Debian keeps the i386 headers under the x86_64 multiarch dir
isystem=$([ -d /usr/include/i386-linux-gnu/bits ] || echo -isystem /usr/include/x86_64-linux-gnu)
for v in new orig; do
    gcc -m32 $isystem -g -fsanitize=address -Wno-deprecated-declarations -Icompat -I"$tmp" -Isys_ctrl/common/sys -DIMPL="\"$v"_minfo.c\" -DPREFIX=$v \
        -c -o "$tmp/$v.o" tests/unit/minfo_wrap.c
done
gcc -m32 $isystem -g -fsanitize=address -o "$tmp/minfo_test" tests/unit/minfo_test.c "$tmp/new.o" "$tmp/orig.o"
ASAN_OPTIONS=detect_leaks=0 "$tmp/minfo_test" 2>"$tmp/stderr" || { grep -m6 "ERROR\\|#[0-9] \\|located" "$tmp/stderr"; exit 1; }
