#!/bin/sh
# Equivalence test of the command parser (common/sys/Cmd.c) against the
# main branch's (original) reconstruction, under ASan, with l2's command
# table. Needs the faithful reconstruction (origin/main, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
orig='s/\b\(_\{0,1\}\)\(Cmd[A-Za-z]*\|cmdlist[a-z]*\|match_text\|match_range\)\b/\1Orig\2/g'
git show "${RECON_REF:-origin/main}":compat/decomp.h > "$tmp/decomp.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/common/sys/Cmd.h |
    sed -e 's/_CMD_H\b/_ORIG_CMD_H/' -e "$orig" > "$tmp/orig_cmd.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/common/sys/Cmd.c |
    sed -e 's|#include "../../l3/sys/syslogLib.h".*|#include "syslogLib.h"|' \
        -e 's/#include "Cmd.h"/#include "orig_cmd.h"/' -e '/syslimits.h/d' -e "$orig" > "$tmp/orig_cmd.c"
# l2's table, every command recording what it was given
git show "${RECON_REF:-origin/main}":sys_ctrl/l3/l2/l2cmd.c | sed -n 's/^Cmd l2cmd_cmds\[190\] = /Cmd test_cmds[190] = /p' |
    sed -e 's/\.func = l2cmd_[a-z0-9_]*/.func = record/g' > "$tmp/table.h"
gcc -g -fsanitize=address -Icompat -I"$tmp" -Isys_ctrl/common/sys -Isys_ctrl/l3/sys \
    -o "$tmp/cmd_test" tests/unit/cmd_test.c sys_ctrl/common/sys/Cmd.c "$tmp/orig_cmd.c"
ASAN_OPTIONS=detect_leaks=0 "$tmp/cmd_test"
