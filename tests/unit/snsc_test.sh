#!/bin/sh
# Equivalence test of the system controller device's chunk framing
# (l3/IRouter/IRouterOS.c) against the decomp branch's (original)
# reconstruction, under ASan, over a SOCK_SEQPACKET pair (which keeps the
# chunks apart, as the device does). Needs the decomp branch in git.
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git show decomp:compat/decomp.h > "$tmp/decomp.h"
git show decomp:sys_ctrl/l3/IRouter/IRouterOS.c | sed -e '/syslimits.h/d' > "$tmp/orig_IRouterOS.c"
cp sys_ctrl/l3/IRouter/IRouterOS.c "$tmp/new_IRouterOS.c"
for v in new orig; do
    gcc -g -fsanitize=address -w -Icompat -I"$tmp" -iquote sys_ctrl/l3/IRouter -DIMPL="\"$v"_IRouterOS.c\" \
        -DPREFIX=$v -c -o "$tmp/$v.o" tests/unit/snsc_wrap.c
done
gcc -g -fsanitize=address -o "$tmp/snsc_test" tests/unit/snsc_test.c "$tmp/new.o" "$tmp/orig.o"
ASAN_OPTIONS=detect_leaks=0 "$tmp/snsc_test"
