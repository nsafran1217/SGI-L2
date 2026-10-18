/*
 * sys_ctrl/l3/l2/l1sim.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l1sim.c
 */

#include "l1net.h"   /* needed by the reconstruction */
#include <sys/stat.h>
#include <stddef.h>
#include "l2.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "../../common/Router/Socket.h"
#include "../../common/Router/Event.h"
#include <sys/time.h>
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../../common/sys/sysutils.h"
#include <pthread.h>
#include <sched.h>
#include "../../common/sys/Logger.h"
#include "../sys/LoggerMsg.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../../common/Router/Router.h"
#include "../../common/sys/PPP.h"
#include "../../common/sys/brick_types.h"
#include "../../common/main/EnetServer.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/main/L1Cfg.h"
#include "l2_rev.h"
#include "l1sim.h"
#include "smp.h"
#include "l2cmd.h"
#include "reqrspq.h"
#include "dest.h"
#include "../../common/sys/Cmd.h"
#include "cfg.h"
#include "format.h"
#include "serial.h"
#include "../main/nvram.h"
#include "../../common/sys/ipmi.h"
#include "l1.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int l1sim_partition;
int l1sim_auto = 1;

int l1sim_export(void)
{
  int iVar1;
  char *wa;
  char *home;
  uint32 uVar2;
  int iVar3;
  char *pcVar4;
  struct stat sbuf;
  char simpath [200];
  char *arch;
  char cmdopts [64];
  char cmd [200];
  int l1;
  char *types [4];
  int slots [4];
  
  slots[0] = 1;
  slots[1] = 5;
  slots[2] = 9;
  slots[3] = 0xd;
  types[0] = "V";
  types[1] = "V";
  types[2] = "V";
  types[3] = "V";
  cmdopts[0] = '\0';
  memset(cmdopts + 1,0,0x3f);
  l1net_export();
  sprintf(simpath,"../utils/l1sim.%s","linux");
  iVar1 = stat(simpath,&sbuf);
  if (iVar1 != 0) {
    wa = getenv("WORKAREA");
    if (wa != NULL) {
      sprintf(simpath,"%s/sys_ctrl/l3/utils/l1sim.%s",wa,"linux");
      iVar1 = stat(simpath,&sbuf);
      if (iVar1 == 0) goto LAB_0804da70;
    }
    home = getenv("HOME");
    if (home == NULL) {
LAB_0804da53:
      fprintf(stderr,"SORRY--can\'t find the simulator executable!!\n");
      return 0;
    }
    sprintf(simpath,"%s/sn1/sys_ctrl/l3/utils/l1sim.%s",home,"linux");
    iVar1 = stat(simpath,&sbuf);
    if (iVar1 != 0) {
      sprintf(simpath,"%s/tot/sys_ctrl/l3/utils/l1sim.%s",home,"linux");
      iVar1 = stat(simpath,&sbuf);
      if (iVar1 != 0) goto LAB_0804da53;
    }
  }
LAB_0804da70:
  for (l1 = 0; (l1sim_auto != 0 && ((unsigned int)l1 < 4)); l1 = l1 + 1) {
    if (0 < l2_copynum) {
      sprintf(cmdopts,"--copy %d",l2_copynum);
    }
    pcVar4 = cmdopts;
    iVar1 = slots[l1];
    iVar3 = l1sim_partition;
    uVar2 = nvramGet(NVRAM_RACK);
    sprintf(cmd,"%s -sn2 -t %s -rs %d %d -p %d %s &",simpath,types[l1],uVar2,iVar1,iVar3,pcVar4);
    printf("starting l1sim: %s\n",cmd);
    system(cmd);
  }
  return 0;
}
