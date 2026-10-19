#!/bin/sh
# Equivalence test of common/sys/Logger.c against the decomp branch's
# (original) reconstruction, under ASan. Needs the faithful reconstruction (decomp, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
. tests/unit/recon.sh
orig='s/\b\(Log[A-Za-z]*\|[A-Za-z]*ErrorList\)\b/Orig\1/g'
git show "${RECON_REF:-decomp}":compat/decomp.h > "$tmp/decomp.h"
git show "${RECON_REF:-decomp}":sys_ctrl/common/sys/Logger.h |
    sed -e '/LoggerMsg.h/d' -e 's/_LOGGER_H\b/_ORIG_LOGGER_H/' -e "$orig" > "$tmp/orig_logger.h"
git show "${RECON_REF:-decomp}":sys_ctrl/common/sys/Logger.c |
    sed -e '/#include "\.\.\//d' -e 's/#include <stdio.h>/&\n#include <time.h>/' -e 's/#include "Logger.h"/#include "orig_logger.h"/' \
        -e "$orig" > "$tmp/orig_logger.c"
gcc -g -fsanitize=address -Icompat -I"$tmp" -o "$tmp/logger_test" tests/unit/logger_test.c \
    sys_ctrl/common/sys/Logger.c "$tmp/orig_logger.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/logger_test"
