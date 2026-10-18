#!/usr/bin/env python3
"""Add the parentheses gcc's -Wparentheses asks for, at gcc's own ranges.

    tools/fix_parens.py <gcc command line ...> -- file.c [file.c ...]

Compiles each file with -fsyntax-only -fdiagnostics-format=json and wraps the
highlighted operand of each "suggest parentheses" warning in parentheses.
The ranges come from the compiler, so the grouping (and the code) is unchanged;
tools/objcmp.sh confirms it.
"""
import json
import subprocess
import sys

i = sys.argv.index("--")
cc, files = sys.argv[1:i], sys.argv[i + 1:]
for path in files:
    r = subprocess.run(cc + ["-fsyntax-only", "-fdiagnostics-format=json", path],
                       capture_output=True, text=True)
    inserts = set()     # (line, byte column 0-based, char)
    for d in json.loads(r.stderr or "[]"):
        msg = d["message"]
        if d.get("option") != "-Wparentheses" or not msg.startswith("suggest parentheses around") \
                or "assignment" in msg:
            continue
        loc = d["locations"][0]
        s, f = loc["start"], loc["finish"]
        if s["file"] != path or f["file"] != path:
            continue
        inserts.add((s["line"], s["byte-column"] - 1, "("))
        inserts.add((f["line"], f["byte-column"], ")"))
    if not inserts:
        continue
    lines = open(path).read().split("\n")
    # one character at a time, last position first, so columns stay valid
    for line, col, ch in sorted(inserts, reverse=True):
        lines[line - 1] = lines[line - 1][:col] + ch + lines[line - 1][col:]
    open(path, "w").write("\n".join(lines))
    print(f"{path}: {len(inserts) // 2} parentheses")
