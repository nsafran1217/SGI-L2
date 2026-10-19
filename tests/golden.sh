# Golden transcripts for the shell tests (sourced); see tests/golden.py.
#
#   golden_check <test> <name> <file>   compare <file> with tests/golden/<test>/<name>.txt
#                                       (GOLDEN=update: write it); sets golden_fail
#   golden_same <label> <file a> <file b>   compare two live results (interop runs)
# Both normalize the files first (tests/golden.py: user names, l2's address).

golden_py=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/golden.py
golden_dir=${golden_py%.py}
src=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
new=${NEW_BIN:-$src/build/bin}
orig=${ORIG_BIN:-$src/../ist/ist-software-extracted/IST/snxsc_l3/stand/sysco/bin}
golden_fail=0
export TZ=UTC                   # (local times and zone names: every host the same)
if [ -n "${INTEROP:-}" ] && [ ! -f "$orig/l2" ]; then
    echo "INTEROP=1: no original binaries in $orig (set ORIG_BIN)" >&2
    exit 1
fi

golden_check() {
    local g="$golden_dir/$1/$2.txt"
    python3 "$golden_py" normalize < "$3" > "$3.norm" && mv "$3.norm" "$3"
    if [ "${GOLDEN:-}" = update ]; then
        mkdir -p "$(dirname "$g")"
        cp "$3" "$g"
        echo "WROTE $1 $2: tests/golden/$1/$2.txt"
    elif [ ! -f "$g" ]; then
        echo "FAIL  $1 $2: no tests/golden/$1/$2.txt (GOLDEN=update writes it)"
        golden_fail=1
    elif cmp -s "$g" "$3"; then
        echo "PASS  $1 $2: $(wc -l < "$g") lines"
    else
        echo "FAIL  $1 $2"
        diff -u --label golden --label now "$g" "$3" | head -40
        golden_fail=1
    fi
}

golden_same() {
    local f
    for f in "$2" "$3"; do
        python3 "$golden_py" normalize < "$f" > "$f.norm" && mv "$f.norm" "$f"
    done
    if cmp -s "$2" "$3"; then
        echo "PASS  $1"
    else
        echo "FAIL  $1"
        diff -u --label orig --label new "$2" "$3" | head -40
        golden_fail=1
    fi
}
