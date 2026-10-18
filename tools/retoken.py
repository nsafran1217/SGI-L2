#!/usr/bin/env python3
"""Rename identifiers in C sources, outside strings, character constants and comments.

    tools/retoken.py old=new [old=new ...] -- file.c [file.h ...]

For mechanical cleanups (e.g. the decompiler's type names). Prints how many
replacements each file got. tools/objcmp.sh then proves the code unchanged.
"""
import re
import sys

TOKEN = re.compile(r'''
    (?P<comment>/\*.*?\*/|//[^\n]*)
  | (?P<string>"(?:\\.|[^"\\\n])*")
  | (?P<char>'(?:\\.|[^'\\\n])*')
  | (?P<ident>[A-Za-z_][A-Za-z_0-9]*)
  | (?P<other>.)
''', re.S | re.X)


def retoken(text, mapping):
    out, count = [], 0
    for m in TOKEN.finditer(text):
        tok = m.group(0)
        if m.lastgroup == "ident" and tok in mapping:
            out.append(mapping[tok])
            count += 1
        else:
            out.append(tok)
    return "".join(out), count


def main():
    i = sys.argv.index("--")
    mapping = dict(a.split("=", 1) for a in sys.argv[1:i])
    total = 0
    for path in sys.argv[i + 1:]:
        text = open(path).read()
        new, n = retoken(text, mapping)
        if n:
            open(path, "w").write(new)
            print(f"{path}: {n}")
            total += n
    print(f"total: {total}")


if __name__ == "__main__":
    main()
