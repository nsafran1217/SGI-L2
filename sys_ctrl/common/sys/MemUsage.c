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
  char *pcVar1;
  static char buf[400];
  size_t sVar2;
  struct mallinfo info;
  char *bptr;
  
  mallinfo(&info);
  sprintf((char *)0x80a9680,"\narena:        %d\n",info.arena);
  sVar2 = strlen((char *)0x80a9680);
  pcVar1 = (char *)(sVar2 + 0x80a9680);
  sprintf(pcVar1,"ordblks:      %d\n",info.ordblks);
  sVar2 = strlen(pcVar1);
  bptr = pcVar1 + sVar2;
  sprintf(bptr,"smblks:       %d\n",info.smblks);
  sVar2 = strlen(bptr);
  pcVar1 = bptr + sVar2;
  sprintf(pcVar1,"hblks:        %d\n",info.hblks);
  sVar2 = strlen(pcVar1);
  pcVar1 = pcVar1 + sVar2;
  sprintf(pcVar1,"hblkhd:       %d\n",info.hblkhd);
  sVar2 = strlen(pcVar1);
  pcVar1 = pcVar1 + sVar2;
  sprintf(pcVar1,"usmblks:      %d\n",info.usmblks);
  sVar2 = strlen(pcVar1);
  pcVar1 = pcVar1 + sVar2;
  sprintf(pcVar1,"fsmblks:      %d\n",info.fsmblks);
  sVar2 = strlen(pcVar1);
  pcVar1 = pcVar1 + sVar2;
  sprintf(pcVar1,"uordblks:     %d\n",info.uordblks);
  sVar2 = strlen(pcVar1);
  pcVar1 = pcVar1 + sVar2;
  sprintf(pcVar1,"fordblks:     %d\n",info.fordblks);
  sVar2 = strlen(pcVar1);
  pcVar1 = pcVar1 + sVar2;
  sprintf(pcVar1,"keepcost:     %d\n",info.keepcost);
  sVar2 = strlen(pcVar1);
  sprintf(pcVar1 + sVar2,"\n");
  strlen(pcVar1 + sVar2);
  return &ram0x080a9680;
}

void MemUsage(void)
{
  char *__s;
  
  __s = MemUsageBuf();
  puts(__s);
  fflush(stdout);
  return;
}
