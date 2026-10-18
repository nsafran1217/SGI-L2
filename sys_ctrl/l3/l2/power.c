/*
 * sys_ctrl/l3/l2/power.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/power.c
 */

#include "irtr.h"   /* needed by the reconstruction */
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
#include "power.h"
#include "smp.h"
#include "l2cmd.h"
#include "reqrspq.h"
#include "dest.h"
#include "../../common/sys/Cmd.h"
#include "../main/nvram.h"
#include "../../common/sys/ipmi.h"
#include "serial.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int power_check;
int power_abort;
static int powerup;
static char buff[128];

void power_init(void)
{
  uint32 uVar1;
  int iVar2;
  
  uVar1 = nvramGet(2);
  if ((uVar1 != 0) && (iVar2 = power_query(), iVar2 == 0)) {
    sprintf(buff,"\nINFO: auto power up appears enabled\n");
    fprintf(stderr,buff);
    nvramLogInsert(buff);
    powerup = nvramGet(0x14);
    if (powerup < 0x1f) {
      powerup = 0x1e;
    }
    powerup = powerup / 5;
    EventAddTimeOut(5,0,power_timer,(EventData)0x0,"power_init");
    sprintf(buff,"INFO: auto power up in %2d seconds...\n",powerup * 5);
    fprintf(stderr,buff);
    nvramLogInsert(buff);
  }
  return;
}

void power_timer(void)
{
  uint32 uVar1;
  int iVar2;
  char *pcVar3;
  char *ssn;
  L2CfgNode *node;
  uint32 ip_addr;
  
  ip_addr = L2CfgLocal.net.ip_addr;
  if (power_abort == 0) {
    uVar1 = nvramGet(2);
    if (uVar1 == 0) {
      sprintf(buff,"INFO: auto power up disabled!\n");
      fprintf(stderr,buff);
      nvramLogInsert(buff);
    }
    else {
      iVar2 = power_query();
      if (iVar2 == 0) {
        powerup = powerup + -1;
        if (powerup < 1) {
          power_process_request();
        }
        else {
          for (node = L2CfgLocal.net.next; node != NULL; node = node->next) {
            iVar2 = strcmp(L2CfgLocal.ssn,L2CFG_OF(node)->ssn);
            if ((iVar2 == 0) && (node->ip_addr < ip_addr)) {
              if (L2CFG_OF(node)->rack == 0) {
                pcVar3 = SocketAddrStr(node->ip_addr);
                sprintf(buff,"INFO: auto power up control transfered to %s (rack number not set).\n"
                        ,pcVar3);
              }
              else {
                pcVar3 = SocketAddrStr(node->ip_addr);
                sprintf(buff,"INFO: auto power up control transfered to rack %d (%s).\n",
                        L2CFG_OF(node)->rack,pcVar3);
              }
              fprintf(stderr,buff);
              nvramLogInsert(buff);
              return;
            }
          }
          sprintf(buff,"INFO: auto power up in %2d seconds...\n",powerup * 5);
          fprintf(stderr,buff);
          nvramLogInsert(buff);
          EventAddTimeOut(5,0,power_timer,(EventData)0x0,"power_timer");
        }
      }
      else {
        sprintf(buff,"INFO: power appears on, auto power up disabled.\n");
        fprintf(stderr,buff);
        nvramLogInsert(buff);
      }
    }
  }
  else {
    power_abort = 0;
    sprintf(buff,"INFO: auto power up aborted!\n");
    fprintf(stderr,buff);
    nvramLogInsert(buff);
  }
  return;
}

int power_query(void)
{
  L2CfgPort *port;
  int l1_index;
  int port_index;
  L2CfgNode *node;
  
  node = &L2CfgLocal.net;
  do {
    if (node == NULL) {
      return 0;
    }
    for (port_index = 0; port_index < 0x28; port_index = port_index + 1) {
      port = &L2CFG_OF(node)->port_list[port_index];
      if (port->state != 0) {
        for (l1_index = 0; l1_index < port->l1count; l1_index = l1_index + 1) {
          if ((port->l1cfg[l1_index].configured != '\0') &&
             (port->l1cfg[l1_index].power_state != '\0')) {
            return 1;
          }
        }
      }
    }
    node = node->next;
  } while( true );
}

void power_process_request(void)
{
  char *cmd;
  size_t sVar1;
  IRArgument argv [2];
  IRAddress a;
  IRPacket *p;
  
  cmd = strdup("* power up");
  sprintf(buff,"INFO: initiating auto power up.\n");
  fprintf(stderr,buff);
  nvramLogInsert(buff);
  a = 0x1ffff003;
  argv[0]._clas = '\0';
  argv[0]._frame = '\0';
  argv[0]._val = 0;
  argv[0]._size = 0;
  argv[1]._clas = '\n';
  argv[1]._frame = '\0';
  argv[1]._val = IR_PTR_VAL(cmd);
  sVar1 = strlen(cmd);
  argv[1]._size = (short)sVar1 + 1;
  p = IRouterMakePacket(&l2_apwr_id,&a,0,0,0,2,2,argv);
  IRouterSendPacket(NULL,p);
  return;
}

void power_process_response(IRPacket *p)
{
  char *rsp;
  uint uVar1;
  char *format;
  int err;
  
  if (p->_err == 0) {
    if ((p->_argv[0]._clas & 7) == 0) {
      uVar1 = p->_argv[0]._val;
    }
    else {
      uVar1 = IRArg(p,0);
    }
    if (uVar1 != 0) {
      sprintf(buff,"ERROR: auto power up error.\n");
      fprintf(stderr,buff);
      nvramLogInsert(buff);
    }
    if ((1 < p->_argc) && ((p->_argv[1]._clas & 7) == 2)) {
      if ((p->_argv[1]._clas & 7) == 0) {
        format = (char *)IR_VAL_PTR(p->_argv[1]._val);
      }
      else {
        format = (char *)IRArg(p,1);
      }
      fprintf(stderr,format);
      nvramLogInsert(format);
    }
    IRouterFreePacket(p);
  }
  else {
    rsp = IRFmtError((uint)p->_err);
    sprintf(buff,"ERROR: auto power up error, %s\n",rsp);
    fprintf(stderr,buff);
    nvramLogInsert(buff);
    IRouterFreePacket(p);
  }
  return;
}

int power_status(int rack, int slot)
{
  uint uVar1;
  L2CfgL1 *cfg;
  
  if (power_check == 0) {
    cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
    if (cfg == NULL) {
      uVar1 = 0;
    }
    else {
      uVar1 = (uint)cfg->power_state;
    }
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
