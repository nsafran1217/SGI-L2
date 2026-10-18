/*
 * sys_ctrl/l3/l2/format.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/format.c
 */

#include "l2.h"
#include <stdio.h>
#include <stddef.h>
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
#include "format.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static int BRICK_TASKNUM_SLAB(int btype, int tasknum);

char *format_address(IRAddress addr)
{
  char *pcVar1;
  
  pcVar1 = L2CfgMAddrStr(&L2CfgLocal,addr,0);
  return pcVar1;
}

char *format_caddress(IRAddress addr, int partition)
{
  static char buff[80];
  char *pcVar1;
  size_t sVar2;
  L2CfgL1 *cfg;
  int iVar3;
  int iVar4;
  int slab;
  int subc;
  int iVar5;
  int tasknum;
  uint uVar6;
  uint uVar7;
  int blot;
  int brick;
  int slot;
  int rack;
  
  pcVar1 = format_address(addr);
  strcpy((char *)&buff,pcVar1);
  if (partition != 0) {
    pcVar1 = ".%d";
    sVar2 = strlen((char *)&buff);
    sprintf((char *)&buff + sVar2,pcVar1,partition);
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,addr >> 0x12 & 0x3ff,addr >> 0xc & 0x3f,0);
  if (cfg != NULL) {
    if (((cfg->type == ',') || (cfg->type == '}')) || (cfg->type == '.')) {
      if ((addr & 0x80000000) == 0) {
        uVar6 = addr >> 5 & 0x7f;
      }
      else {
        uVar6 = 0xffffffff;
      }
      iVar5 = BRICK_TASKNUM_SLAB((uint)cfg->type,uVar6);
      iVar3 = BRICK_TASKNUM_SUBCHAN((uint)cfg->type,uVar6);
      if ((addr & 0x80000000) == 0) {
        uVar6 = addr & 0x1f;
      }
      else {
        uVar6 = addr >> 0x18 & 0x3f;
      }
      if (iVar3 < 4) {
        iVar4 = iVar3 + 0x41;
        pcVar1 = " CPU %d%c";
        uVar7 = uVar6;
        sVar2 = strlen((char *)&buff);
        sprintf((char *)(sVar2 + 0x80a25e0),pcVar1,uVar7,iVar4,uVar6,iVar3,iVar5);
      }
      else if (iVar3 == 4) {
        pcVar1 = " console%d";
        sVar2 = strlen((char *)&buff);
        sprintf((char *)(sVar2 + 0x80a25e0),pcVar1,uVar6);
      }
      else {
        pcVar1 = " slot %d, subchannel %d";
        uVar7 = uVar6;
        iVar4 = iVar3;
        sVar2 = strlen((char *)&buff);
        sprintf((char *)(sVar2 + 0x80a25e0),pcVar1,uVar7,iVar3,uVar6,iVar4,iVar5);
      }
    }
    else if (((((cfg->type == '5') || (cfg->type == '@')) ||
              ((cfg->type == '6' || ((cfg->type == '$' || (cfg->type == ',')))))) ||
             (cfg->type == '}')) || (cfg->type == '.')) {
      if ((addr & 0x80000000) == 0) {
        uVar6 = addr >> 5 & 0x7f;
      }
      else {
        uVar6 = 0xffffffff;
      }
      slab = BRICK_TASKNUM_SLAB((uint)cfg->type,uVar6);
      subc = BRICK_TASKNUM_SUBCHAN((uint)cfg->type,uVar6);
      if (subc < 4) {
        iVar5 = subc + 0x41;
        pcVar1 = " CPU %d%c";
        sVar2 = strlen((char *)&buff);
        sprintf((char *)(sVar2 + 0x80a25e0),pcVar1,slab,iVar5);
      }
      else if (subc == 4) {
        pcVar1 = " console%d";
        sVar2 = strlen((char *)&buff);
        sprintf((char *)(sVar2 + 0x80a25e0),pcVar1,slab);
      }
      else {
        pcVar1 = " slab %d, subchannel %d";
        sVar2 = strlen((char *)&buff);
        sprintf((char *)(sVar2 + 0x80a25e0),pcVar1,slab,subc);
      }
    }
    else {
      if ((addr & 0x80000000) == 0) {
        tasknum = addr >> 5 & 0x7f;
      }
      else {
        tasknum = -1;
      }
      switch(tasknum) {
      case 0:
        strcat((char *)&buff," CPU0");
        break;
      case 1:
        strcat((char *)&buff," CPU1");
        break;
      case 2:
        strcat((char *)&buff," CPU2");
        break;
      case 3:
        strcat((char *)&buff," CPU3");
        break;
      case 4:
        strcat((char *)&buff," console");
        break;
      default:
        if ((addr & 0x80000000) == 0) {
          uVar6 = addr >> 5 & 0x7f;
        }
        else {
          uVar6 = 0xffffffff;
        }
        pcVar1 = " subchannel %d";
        sVar2 = strlen((char *)&buff);
        sprintf((char *)(sVar2 + 0x80a25e0),pcVar1,uVar6);
      }
    }
  }
  return (char *)&buff;
}

static int BRICK_TASKNUM_SLAB(int btype, int tasknum)
{
  int iStack_8;
  
  if (btype == 0x36) {
    iStack_8 = (tasknum / 6 + (tasknum >> 0x1f) >> 2) - (tasknum >> 0x1f);
  }
  else {
    if (btype < 0x37) {
      if (btype == 0x2e) {
        iStack_8 = tasknum;
        if (tasknum < 0) {
          iStack_8 = tasknum + 0x1f;
        }
        return iStack_8 >> 5;
      }
    }
    else if (btype == 0x40) {
      return tasknum / 0x14;
    }
    iStack_8 = tasknum;
    if (tasknum < 0) {
      iStack_8 = tasknum + 0x1f;
    }
    iStack_8 = iStack_8 >> 5;
  }
  return iStack_8;
}
