/*
 * sys_ctrl/l3/utils/l2cmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2cmd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/l2cmd.c
 *
 * l2cmd: run L2 commands from the command line (main() is lxcmd.c's).
 */

#include <stdio.h>
#include <stdlib.h>
#include "../api/SCapi.h"

char *myname;
void usage(void);
#include "lxcmd.c"

void usage(void)
{
  fprintf(stderr,"usage: %s [sysco options] <command>\n",myname);
  fprintf(stderr,"System Controller command options\n%s",sn1SCUsage());
  fprintf(stderr,"\n");
  exit(-1);
}
