#!/bin/sh
# Equivalence test of the system configuration code (common/main/L2Cfg.c)
# against the decomp branch's (original) reconstruction, under ASan: random
# configuration texts and L1 configurations into both, then every printer,
# query and lookup compared. Links the rest from a 64-bit libsgi.a: LIBSGI,
# else build64/libsgi.a, brought up to date here. Needs the faithful
# reconstruction (decomp, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
lib=${LIBSGI:-build64/libsgi.a}
[ -n "${LIBSGI:-}" ] || make -s ARCH=-m64 B=build64 "$lib"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
. tests/unit/recon.sh
names='s/\b\(L2CfgM[A-Z][A-Za-z0-9_]*\|L2CfgInit[A-Za-z]*\|L2CfgDelete[A-Za-z0-9]*\|L2CfgDebugX\?\|L2CfgMode\|L2CfgLocal\|FmtBrick\)\b/Orig\1/g'
git show "${RECON_REF:-decomp}":compat/decomp.h > "$tmp/decomp.h"
# (the original's undersized buffers enlarged, so that its overflow bugs do not
# stop the comparison: 75 bytes a line, and malloc(0) with no bricks)
git show "${RECON_REF:-decomp}":sys_ctrl/common/main/L2Cfg.c | sed -e '/syslimits.h/d' -e "$names" \
    -e 's/malloc(count \* 0x4b)/malloc(count * 0x4b * 4 + 400)/' \
    -e 's/malloc(count \* 0x50)/malloc(count * 0x50 + 32)/' -e 's/malloc(count << 4)/malloc((count << 4) + 2)/' \
    -e 's/#include "L2Cfg.h"/&\n#include "orig_protos.h"/' > "$tmp/orig_L2Cfg.c"
sed -n 's/^\([A-Za-z].*\) \**\(L2CfgM[A-Za-z0-9_]*\|L2CfgInit[A-Za-z]*\|L2CfgDelete[A-Za-z0-9]*\|FmtBrick\)(\(.*\));$/&/p' \
    sys_ctrl/common/main/L2Cfg.h | sed -e "$names" > "$tmp/orig_protos.h"
cat >> "$tmp/orig_protos.h" <<'P'
extern int OrigL2CfgDebug, OrigL2CfgDebugX, OrigL2CfgMode;
extern L2Cfg OrigL2CfgLocal;
P
gcc -g -m64 -fsanitize=address -w -Icompat -I"$tmp" -iquote sys_ctrl/common/main -fno-builtin-fprintf \
    -fsigned-char -fcommon -o "$tmp/l2cfg_test" tests/unit/l2cfg_test.c sys_ctrl/common/main/L2Cfg.c \
    "$tmp/orig_L2Cfg.c" "$lib"
cd "$tmp" && ASAN_OPTIONS=detect_leaks=0 ./l2cfg_test
