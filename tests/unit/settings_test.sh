#!/bin/sh
# Unit test of l2's settings file (l3/main/settings.c), under ASan: each
# case in its own process (settingsInit() reads the file once).
set -eu
cd "$(dirname "$0")/../.."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
gcc -g -fsanitize=address -Wall -Isys_ctrl/l3/main -o "$tmp/settings_test" \
    tests/unit/settings_test.c sys_ctrl/l3/main/settings.c sys_ctrl/common/sys/l3paths.c
cd "$tmp"
for c in new edited readonly; do
    ASAN_OPTIONS=detect_leaks=0 ./settings_test $c || exit 1
done
echo "PASS  settings: new file, widths, a hand-edited file rewritten in place, read-only, reset"
