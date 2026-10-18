/*
 * sys_ctrl/common/sys/ipmi.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/ipmi.c
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "ipmi.h"
#include "sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

void ipmiInit(void)
{
  return;
}

uint8 ipmiCheckCSum(uint8 *cptr, uint32 bytes)
{
  uint8 sum;
  
  sum = '\0';
  while (bytes != 0) {
    sum = sum + *cptr;
    cptr = cptr + 1;
    bytes = bytes - 1;
  }
  return sum;
}

uint8 ipmiCalcCSum(uint8 *cptr, uint32 bytes)
{
  uint8 sum;
  
  sum = '\0';
  while (bytes = bytes - 1, bytes != 0) {
    sum = sum + *cptr;
    cptr = cptr + 1;
  }
  return ~sum + 1;
}
