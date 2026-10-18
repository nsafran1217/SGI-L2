/*
 * sys_ctrl/l3/l2/dmp.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/dmp.c
 */

#include "../../common/sys/PPP.h"   /* needed by the reconstruction */
#include "dmp.h"   /* needed by the reconstruction */
#include "smp.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

void dmp(char *s, unsigned char *bptr, int blen, int newline)
{
  int n;
  char buff [80];
  
  if (s != NULL) {
    fprintf(stderr,"\n%s %x\n",s,bptr);
  }
  for (n = 0; n < blen; n = n + 1) {
    fprintf(stderr,"%02x ",(uint)bptr[n]);
    if ((newline != 0) && ((n + 1U & 7) == 0)) {
      fprintf(stderr,"\n");
    }
  }
  if (newline != 0) {
    fprintf(stderr,"\n");
  }
  return;
}
