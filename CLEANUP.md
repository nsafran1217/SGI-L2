# Cleanup plan (modern branch)

`main` keeps the faithful reconstruction of SGI's 1.62.0 source: Ghidra's
naming and structure, SGI's bugs where they shape output, the `sgil1` kernel
driver. This branch turns it into maintainable C. Fixes to the historical
reconstruction land on `main` first and are merged here.

## Rules

- **Behaviour is defined by the differential tests.** Every commit passes
  `make check` (below) on the 32-bit, 64-bit, ASan and s390x builds: l2cmd,
  l2term, NVRAM, L1 (fake L1) and l2gui sessions identical to SGI's original
  binaries. A cleanup that changes output is a bug unless it is an
  intentional, documented change (DEVIATIONS.md).
- Disk and wire formats stay byte-identical to the originals (NVRAM file,
  Router and IRouter frames), so mixed old/new installations keep working.
- One kind of change per commit, so a regression bisects to one transform.
- SGI's names stay where they are SGI's (functions, globals, struct fields,
  STABS locals); only decompiler inventions (`iVar1`, `pcVar3`, `LAB_...`,
  `local_14`, `auStack_...`) are renamed.
- SGI bugs that `main` keeps for output fidelity stay kept until we decide
  otherwise, one by one (ORIGINAL_BUGS.md).

## Phases

### 0. Ground rules in the build
- `make check`: every test against one build (`B=`); `make check-all`: all builds.
- Warnings: drop the `-Wno-error=int-conversion/incompatible-pointer-types/
  return-mismatch` escape hatch, then fix `-Wall` (parentheses, unused
  values, `extraout_*` maybe-uninitialized), then `-Wextra`; finally
  `-Werror` on this branch.
- Still hidden: `-Wno-unused-variable`, `-Wno-unused-but-set-variable`,
  `-Wno-unused-label`, `-Wno-pointer-sign`. These cover decompiler residue
  (STABS locals the code no longer uses, `LAB_` labels) and go per file in
  phase 2.

### 1. Tree-wide mechanical transforms (scripted, each its own commit)
- Ghidra's types (`uint`, `uchar`, `byte`, `ushort`, `ulong`, `undefinedN`,
  `code`) to standard or SGI types (`unsigned int`, `uint8_t`, SGI's
  `uint8/uint16/uint32`); about 720 uses. No SGI declaration used them (the
  STABS only have glibc's typedefs). Careful with `ulong` (18 uses): it
  was 32 bits to Ghidra but is 64 on LP64 hosts, so each becomes
  `uintptr_t` (holds a pointer, e.g. `RouterArgument.val`) or `uint32_t`.
- Character literals used as numbers (`== '\0'` on ints, `'\x05'`) to numbers;
  about 250.
- `/* WARNING: ... */` decompiler notes removed (43).
- `syslog(level, file, 0x2f8, ...)` line numbers in decimal (112).
- `compat/decomp.h` shrinks as these go; deleted at the end of phase 2.

### 2. File by file (manual), leaf modules first
Order: common/Router (Buff, Event, SocketIO, Socket, RouterCl, RouterSv,
Router), common/IRouter, common/sys (Cmd, Logger, PPP, brick_types, minfo),
l3/main (nvram, SysCfg), l3/api (SCapi*, L1Direct), l3/IRouter, then l3/l2
(smallest first, l2cmd.c last) and l3/utils. l3/gui is already hand-written.

Per file:
- name every temporary after what it holds, or fold it away
  (`iVar2 = strcmp(...); if (iVar2 == 0)` → `if (strcmp(...) == 0)`);
- structured control flow instead of `goto LAB_...`, `switch` where the
  decompiler split one;
- magic numbers to names: IRouter classes/tasks/errors (enums already in
  IRouter.h, LoggerMsg.h), nvram item numbers, address fields
  (`addr >> 0x1c` → an `IR_ADDR_TYPE()` macro), Router opcodes;
- prototypes in the module's header, `static` for file-local functions,
  `const` where SGI's API allows it without changing behaviour;
- drop `#include "decomp.h"` and the "needed by the reconstruction" includes
  that are no longer needed.

### 3. Structure (after the code reads cleanly)
- L1 transport interface under `l3/l2/l1.c` (sgil1 driver, L1 network link,
  serial/PPP) and a libusb backend: `l2` without the kernel driver.
- Then: portability beyond Linux (macOS/BSD via libusb and FLTK), build
  system if the Makefile stops being enough.

## Progress

| Phase | State |
|---|---|
| 0 | done: warning-free with `-Wall -Wextra` (less `-Wunused-parameter`), `-Werror` (`WERROR=` to drop it); `tools/objcmp.sh` proves mechanical commits; `make check` / `check-all` |
| 1 | |
| 2 | |
| 3 | |
