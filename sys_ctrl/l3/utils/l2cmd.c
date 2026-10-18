/*
 * sys_ctrl/l3/utils/l2cmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2cmd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/l2cmd.c
 */

#include "../api/SCapi.h"   /* needed by the reconstruction */
#include "../l2/l2cmd.h"   /* needed by the reconstruction */
#include "../l2/smp.h"   /* needed by the reconstruction */
#include "lxcmd.c"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

char *myname;

void usage(void)
{
  char *pcVar1;
  
  fprintf(stderr,"usage: %s [sysco options] <command>\n",myname);
  pcVar1 = sn1SCUsage();
  fprintf(stderr,"System Controller command options\n%s",pcVar1);
  fprintf(stderr,"\n");
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
