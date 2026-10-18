/*
 * sys_ctrl/l3/l2/dmp.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/dmp.c
 *
 * Hex dump of the L1 link's traffic for the debug flags (l1.c).
 */

#include <stdint.h>
#include <stdio.h>
#include "dmp.h"

/* blen bytes at bptr to stderr, after a "<s> <address>" line if s is set;
 * with newline set, eight bytes to a line */
void dmp(char *s, unsigned char *bptr, int blen, int newline)
{
  int n;

  if (s != NULL)
    fprintf(stderr,"\n%s %lx\n",s,(unsigned long)(uintptr_t)bptr);
  for (n = 0; n < blen; n++) {
    fprintf(stderr,"%02x ",bptr[n]);
    if (newline && (n + 1) % 8 == 0)
      fprintf(stderr,"\n");
  }
  if (newline)
    fprintf(stderr,"\n");
}
