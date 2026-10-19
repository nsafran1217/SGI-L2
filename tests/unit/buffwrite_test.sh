#!/bin/sh
# common/sys/BuffWrite.c against plain concatenation, under ASan (the
# original wrote its terminator one past the buffer when the text filled it
# exactly, so there is no comparison with decomp).
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gcc -g -fsanitize=address -Icompat -o "$tmp/buffwrite_test" tests/unit/buffwrite_test.c \
    sys_ctrl/common/sys/BuffWrite.c
ASAN_OPTIONS=detect_leaks=0 "$tmp/buffwrite_test"
