/*
 * sys_ctrl/common/sys/MemUsage.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/MemUsage.c
 */

#include "MemUsage.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <malloc.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

char *MemUsageBuf(void)
{
  static char buf[400];
  struct mallinfo info;
  char *bptr;

  info = mallinfo();
  bptr = buf;
  bptr += sprintf(bptr, "\narena:        %d\n", info.arena);
  bptr += sprintf(bptr, "ordblks:      %d\n", info.ordblks);
  bptr += sprintf(bptr, "smblks:       %d\n", info.smblks);
  bptr += sprintf(bptr, "hblks:        %d\n", info.hblks);
  bptr += sprintf(bptr, "hblkhd:       %d\n", info.hblkhd);
  bptr += sprintf(bptr, "usmblks:      %d\n", info.usmblks);
  bptr += sprintf(bptr, "fsmblks:      %d\n", info.fsmblks);
  bptr += sprintf(bptr, "uordblks:     %d\n", info.uordblks);
  bptr += sprintf(bptr, "fordblks:     %d\n", info.fordblks);
  bptr += sprintf(bptr, "keepcost:     %d\n", info.keepcost);
  sprintf(bptr, "\n");
  return buf;
}

void MemUsage(void)
{
  char *__s;
  
  __s = MemUsageBuf();
  puts(__s);
  fflush(stdout);
  return;
}
