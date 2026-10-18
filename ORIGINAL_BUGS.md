# Bugs in the original SGI code

Found while reconstructing. Each entry says whether the reconstruction keeps
the original behaviour (so output matches the shipped binaries) or fixes it.
The rule: keep it when the bug shapes normal output; fix it when the original
only misbehaves in cases that print garbage or crash anyway.

| Where | Bug | Decision |
|---|---|---|
| `l3/sys/syslogLib.c` `syslog()` | Levels 0–2 build the prefix with `sprintf(buf, "%s: %s line %d ; ", hwType, msgno, level_text, file, line)`: five arguments for three conversions, so `msgno` is printed by the second `%s` ("(null)" when 0) and `%d` gets a pointer. Verified in the machine code. | **Kept.** It shapes every critical-level log line. Needs a 64-bit-safe equivalent before the 64-bit port (`%s` of an int is undefined there). |
| `l3/main/nvram.c` `nvramLogFinsert()` | Passes its `va_list` to `snprintf` instead of `vsnprintf`, so any `%` conversion in `fmt` prints garbage. Verified in the machine code. | **Fixed** (`vsnprintf`). Identical output for format strings without conversions. |
| `common/main/EnetServer.c` `EnetServerConnect()` | "could not get IP value for host %s:%d" is passed `host` only, so `%d` prints stack garbage. Verified in the machine code. | **Fixed:** passes `port`, the evident intent. Identical except in the line that printed garbage. |
| `l3/l2/l2cmd.c`, `l3/sys/syslogLib.c` | Some `sprintf`/`fprintf` calls pass more arguments than their format uses (`syslog`'s console writes pass six trailing zeros). Verified in the machine code. | **Kept.** Harmless. |
| `common/sys/Cmd.c` `CmdFormat()` | Builds usage text in a 40-byte static buffer with `strcat` and no length check. | **Kept for now.** No shipped command overflows it; to be bounded in the cleanup pass. |
