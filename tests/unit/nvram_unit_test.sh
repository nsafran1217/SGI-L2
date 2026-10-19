#!/bin/sh
# Equivalence test of the NVRAM image code (l3/main/nvram.c) against the
# main branch's (original) reconstruction, under ASan: random settings,
# log messages (enough to wrap the ring) and resets, comparing the files
# and the log text. Needs the faithful reconstruction (origin/main, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
. tests/unit/recon.sh
git show "${RECON_REF:-origin/main}":compat/decomp.h > "$tmp/decomp.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/l3/main/nvram.c |
    sed -e 's/\bnvram\([A-Z][A-Za-z]*\)\b/Orignvram\1/g' \
        -e 's/\bOrignvram\(InternalUseArea\|ProductInfoArea\|Log\|Instance\)\b/nvram\1/g' \
        -e 's/^nvramInstance nvram;/nvramInstance orig_nvram_;/' -e 's/#include <syslimits.h>//' \
        -e 's/#include "nvram.h"/&\n#include "orig_protos.h"/' > "$tmp/orig_nvram.c"
sed -n 's/^\(int\|void\|char \*\|uintptr_t\) \(nvram[A-Za-z]*(.*)\);.*/\1 Orig\2;/p' \
    sys_ctrl/l3/main/nvram.h > "$tmp/orig_protos.h"
gcc -g -fsanitize=address -Icompat -I"$tmp" -iquote sys_ctrl/l3/main -w \
    -o "$tmp/nvram_test" tests/unit/nvram_unit_test.c sys_ctrl/l3/main/nvram.c "$tmp/orig_nvram.c" \
    sys_ctrl/common/sys/ipmi.c sys_ctrl/common/sys/l3paths.c
cd "$tmp" && TZ=UTC ASAN_OPTIONS=detect_leaks=0 ./nvram_test
