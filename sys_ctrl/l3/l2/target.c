/*
 * sys_ctrl/l3/l2/target.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/target.c
 */

#include "irtr.h"   /* needed by the reconstruction */
#include "l1.h"   /* needed by the reconstruction */
#include "smp.h"   /* needed by the reconstruction */
#include <malloc.h>
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
#include "target.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int target_response_timeout = 10;

int target_l2(L2CMD *c, char **results, int ip, char *cptr, int response, int delay, int final)
{
  L2CfgNode *node;
  int iVar1;
  unsigned int uVar2;
  uint32_t uVar3;
  size_t sVar4;
  int fd;
  int slot;
  int rack;
  int type;
  IRAddress addr;
  IRPacket *p;
  IRArgument argv [2];
  
  addr = 0;
  node = L2CfgMFindNode(&L2CfgLocal,ip,0,NULL);
  if (node == NULL) {
    iVar1 = -1;
  }
  else if ((L2Cfg *)node == &L2CfgLocal) {
    iVar1 = l2cmd_process(c,cptr,results,NULL);
  }
  else {
    addr = (addr & 0x3fffffff) | 0x80000000;
    if (IRByteOrder == 1) {
      uVar2 = (ip & 0xffffffU) | 0x80000000;
    }
    else {
      uVar3 = ntohl(ip);
      uVar2 = (addr & 0xff000000) | (uVar3 & 0xffffff);
    }
    addr = (uVar2 & 0xc0ffffff) | 0x3000000;
    argv[0]._clas = '\0';
    argv[0]._frame = '\0';
    argv[0]._val = 0;
    argv[0]._size = 0;
    argv[1]._clas = '\x02';
    argv[1]._frame = '\0';
    argv[1]._val = IR_PTR_VAL(cptr);
    sVar4 = strlen(cptr);
    argv[1]._size = (short)sVar4 + 1;
    p = IRouterMakePacket(c->id,&addr,0,0,0,2,2,argv);
    if (response != 0) {
      l2cmd_queue_response(c,c->id->seqnum - 1,addr,0);
    }
    IRouterSendPacket(NULL,p);
    if (delay != 0) {
      usleep(delay * 1000);
    }
    if (final != 0) {
      rspq_timeout_set(c->q,target_response_timeout);
    }
    iVar1 = 0;
  }
  return iVar1;
}

int target_l1(L2CMD *c, int ip, int port, int l1, char *cptr, int response, int delay, int final)
{
  int iVar1;
  size_t sVar2;
  char cmd_ [256];
  char cmd [256];
  int fd;
  int slot;
  int rack;
  int type;
  IRAddress addr;
  IRPacket *p;
  IRArgument argv [2];
  L2CfgNode *node;
  
  iVar1 = L2CfgMFindBrickRS(&L2CfgLocal,ip,port,l1,&rack,&slot);
  if (iVar1 == 0) {
    if ((uint32)ip == L2CfgLocal.net.ip_addr) {
      argv[0]._clas = '\0';
      argv[0]._frame = '\0';
      argv[0]._val = 0;
      argv[0]._size = 0;
      cmd_[0] = '\0';
      memset(cmd_ + 1,0,0xff);
      strcpy(cmd_,cptr);
      addr = 0xffff003;
      argv[1]._clas = '\x02';
      argv[1]._frame = '\0';
      argv[1]._val = IR_PTR_VAL(cmd_);
      sVar2 = strlen(cmd_);
      argv[1]._size = (short)sVar2 + 1;
      p = IRouterMakePacket(c->id,&addr,0,0,0,2,2,argv);
      if (response != 0) {
        l2cmd_queue_response(c,c->id->seqnum - 1,addr,0);
      }
      l1_write_packet(l2_l1_ports[port].fd,p);
      if (delay != 0) {
        usleep(delay * 1000);
      }
      if (final != 0) {
        rspq_timeout_set(c->q,target_response_timeout);
      }
      iVar1 = 0;
    }
    else {
      sprintf(cmd,":%d:%d %s",port,l1,cptr);
      iVar1 = target_l2(c,NULL,ip,cmd,response,delay,final);
    }
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

int target_pkt(L2CMD *c, IRAddress addr, int opcode, int argc, IRArgument *argv, int response, int delay, int final)
{
  IRPacket *p;
  
  p = IRouterMakePacket(c->id,&addr,0,opcode,0,2,argc,argv);
  if (response != 0) {
    l2cmd_queue_response(c,c->id->seqnum - 1,addr,0);
  }
  IRouterSendPacket(NULL,p);
  if (delay != 0) {
    usleep(delay * 1000);
  }
  if (final != 0) {
    rspq_timeout_set(c->q,target_response_timeout);
  }
  return 0;
}
