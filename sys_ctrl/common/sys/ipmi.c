/*
 * sys_ctrl/common/sys/ipmi.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/ipmi.c
 *
 * IPMI FRU checksums (used for the NVRAM's IPMI-style layout): an area
 * checks out when its bytes, checksum included, sum to zero (mod 256).
 */

#include "ipmi.h"

void ipmiInit(void)
{
}

/* the sum of the area's bytes: zero if its checksum is right */
uint8 ipmiCheckCSum(uint8 *cptr, uint32 bytes)
{
  uint8 sum = 0;

  while (bytes-- != 0)
    sum += *cptr++;
  return sum;
}

/* the checksum for the area's last byte: minus the sum of the others */
uint8 ipmiCalcCSum(uint8 *cptr, uint32 bytes)
{
  uint8 sum = 0;

  for (; bytes > 1; bytes--)
    sum += *cptr++;
  return -sum;
}
