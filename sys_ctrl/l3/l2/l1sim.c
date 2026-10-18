/*
 * sys_ctrl/l3/l2/l1sim.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l1sim.c
 *
 * "-l1sim": listen for L1s as l1net.c does, and start four simulated L1s
 * (SGI's l1sim.linux, which was not shipped) in this L2's rack.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "l2.h"
#include "l1sim.h"
#include "l1net.h"
#include "../main/nvram.h"

#define SIM_BRICKS  4

int l1sim_partition;
int l1sim_auto = 1;             /* 0 for -l1sim_manual: start no simulators */

/* the simulator executable, looked for in SGI's work areas; 0 if found */
static int find_simulator(char *path, size_t size)
{
  struct stat sbuf;
  const char *wa = getenv("WORKAREA");
  const char *home = getenv("HOME");

  snprintf(path,size,"../utils/l1sim.%s","linux");
  if (stat(path,&sbuf) == 0)
    return 0;
  if (wa != NULL) {
    snprintf(path,size,"%s/sys_ctrl/l3/utils/l1sim.%s",wa,"linux");
    if (stat(path,&sbuf) == 0)
      return 0;
  }
  if (home == NULL)
    return -1;
  snprintf(path,size,"%s/sn1/sys_ctrl/l3/utils/l1sim.%s",home,"linux");
  if (stat(path,&sbuf) == 0)
    return 0;
  snprintf(path,size,"%s/tot/sys_ctrl/l3/utils/l1sim.%s",home,"linux");
  return stat(path,&sbuf) == 0 ? 0 : -1;
}

int l1sim_export(void)
{
  static const int slots[SIM_BRICKS] = { 1, 5, 9, 13 };
  static const char *const types[SIM_BRICKS] = { "V", "V", "V", "V" };
  char simpath[200];
  char cmdopts[64] = "";
  char cmd[200];
  int l1;

  l1net_export();
  if (find_simulator(simpath,sizeof(simpath)) != 0) {
    fprintf(stderr,"SORRY--can\'t find the simulator executable!!\n");
    return 0;
  }
  for (l1 = 0; l1sim_auto && l1 < SIM_BRICKS; l1++) {
    if (l2_copynum > 0)
      sprintf(cmdopts,"--copy %d",l2_copynum);
    if (snprintf(cmd,sizeof(cmd),"%s -sn2 -t %s -rs %d %d -p %d %s &",simpath,types[l1],
                 (int)nvramGet(NVRAM_RACK),slots[l1],l1sim_partition,cmdopts) >= (int)sizeof(cmd)) {
      fprintf(stderr,"l1sim: command too long\n");   /* (the original overflowed cmd) */
      continue;
    }
    printf("starting l1sim: %s\n",cmd);
    system(cmd);
  }
  return 0;
}
