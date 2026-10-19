#!/bin/sh
# Equivalence test of SGI's syslog() (l3/sys/syslogLib.c) against the main
# branch's (original) reconstruction, under ASan: every level, the stderr
# text and what the callback gets. Needs the faithful reconstruction (origin/main, or RECON_REF) in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show "${RECON_REF:-origin/main}":compat/decomp.h > "$tmp/decomp.h"
git show "${RECON_REF:-origin/main}":sys_ctrl/l3/sys/syslogLib.c | sed -e '/syslimits.h/d' > "$tmp/orig_syslogLib.c"
cp sys_ctrl/l3/sys/syslogLib.c "$tmp/new_syslogLib.c"
for v in new orig; do
    gcc -g -fsanitize=address -w -Icompat -I"$tmp" -iquote sys_ctrl/l3/sys -DIMPL="\"$v"_syslogLib.c\" \
        -DPREFIX=$v -c -o "$tmp/$v.o" tests/unit/syslog_wrap.c
done
gcc -g -fsanitize=address -o "$tmp/syslog_test" tests/unit/syslog_test.c "$tmp/new.o" "$tmp/orig.o"
cd "$tmp" && ASAN_OPTIONS=detect_leaks=0 ./syslog_test
