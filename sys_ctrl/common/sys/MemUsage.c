/*
 * sys_ctrl/common/sys/MemUsage.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/MemUsage.c
 *
 * The malloc arena statistics, as text.
 */

#include <malloc.h>
#include <stdio.h>
#include "MemUsage.h"

/* the statistics (a static buffer) */
char *MemUsageBuf(void)
{
  static char buf[400];
  char *bptr = buf;
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
  struct mallinfo2 info = mallinfo2();     /* mallinfo() is deprecated since glibc 2.33 */
#elif defined(__GLIBC__)
  struct mallinfo info = mallinfo();
#else
  /* (musl keeps no such statistics) */
  struct { long arena, ordblks, smblks, hblks, hblkhd, usmblks, fsmblks, uordblks, fordblks, keepcost; } info = { 0 };
#endif

  bptr += sprintf(bptr,"\narena:        %d\n",(int)info.arena);
  bptr += sprintf(bptr,"ordblks:      %d\n",(int)info.ordblks);
  bptr += sprintf(bptr,"smblks:       %d\n",(int)info.smblks);
  bptr += sprintf(bptr,"hblks:        %d\n",(int)info.hblks);
  bptr += sprintf(bptr,"hblkhd:       %d\n",(int)info.hblkhd);
  bptr += sprintf(bptr,"usmblks:      %d\n",(int)info.usmblks);
  bptr += sprintf(bptr,"fsmblks:      %d\n",(int)info.fsmblks);
  bptr += sprintf(bptr,"uordblks:     %d\n",(int)info.uordblks);
  bptr += sprintf(bptr,"fordblks:     %d\n",(int)info.fordblks);
  bptr += sprintf(bptr,"keepcost:     %d\n",(int)info.keepcost);
  sprintf(bptr,"\n");
  return buf;
}

void MemUsage(void)
{
  puts(MemUsageBuf());
  fflush(stdout);
}
