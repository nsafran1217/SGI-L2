/*
 * sys_ctrl/common/IRouter/IRouter2Router.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/IRouter/IRouter2Router.c
 */

#include "../../l3/IRouter/IRouterL3.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "../Router/Router.h"
#include "IRouter2Router.h"
#include "IRouter.h"
#include "../sys/sysctl_types.h"
#include <netinet/in.h>
#include "../sys/sysutils.h"
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include "../sys/Logger.h"
#include "../../l3/sys/LoggerMsg.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int IRouterForwardPacket(IRClient *client, IRIdent *id, IRPacket *pkt)
{
  ushort uVar1;
  uint uVar2;
  RouterArgument *arglist;
  uint uVar3;
  uint slot;
  IRAddress src_;
  uint data;
  IRAddress src;
  uchar priority;
  IRPacket *pf;
  int argc;
  int rarg_size;
  RouterArgument *rarg;
  int rval;
  
  rval = 0;
  data = 0;
  if (pkt->_clas == '\x02') {
    uVar2 = pkt->_src;
    if (((uVar2 & 0x80000000) == 0) && (uVar2 >> 0x1c == 0)) {
      if ((uVar2 & 0x80000000) == 0) {
        uVar3 = uVar2 & 0x1f;
      }
      else {
        uVar3 = uVar2 >> 0x18 & 0x3f;
      }
      if (uVar3 == 5) {
        data = uVar2 & 0xfffff01f | (uint)(pkt->_pdata_auth >> 3) << 5;
        priority = '\n';
        goto LAB_0807d4aa;
      }
    }
    priority = '\v';
  }
  else {
    priority = '\x14';
  }
LAB_0807d4aa:
  arglist = malloc(((pkt->_fnum & 0x7f) + 1) * 8);
  if (arglist == NULL) {
    rval = -0x25c;
  }
  else {
    arglist->clas = 0;
    *(byte *)arglist = *(byte *)arglist | 2;
    arglist->val = (ulong)"IR";
    arglist->fre = 0;
    *(uint *)arglist = *(uint *)arglist & 0xff;
    *(byte *)&arglist->size = (byte)arglist->size | 3;
    argc = 1;
    for (pf = pkt; pf != NULL; pf = pf->_next_frame) {
      uVar1 = pf->_size;
      IRouterSetFrameByteOrder(pf,1);
      arglist[argc].clas = 0;
      *(byte *)(arglist + argc) = *(byte *)(arglist + argc) | 2;
      arglist[argc].val = (ulong)pf;
      arglist[argc].fre = 0;
      *(uint *)(arglist + argc) = *(uint *)(arglist + argc) & 0xff;
      *(uint *)(arglist + argc) = *(uint *)(arglist + argc) | (uVar1 + 0x10) * 0x100;
      argc = argc + 1;
    }
    RouterPriClientEventOut(client,0,argc,arglist,(uint)priority,(void *)data);
    free(arglist);
    for (pf = pkt; pf != NULL; pf = pf->_next_frame) {
      IRouterSetFrameByteOrder(pf,IRByteOrder);
    }
    IRouterFreePacket(pkt);
    if (IRouterEventLoop == 0) {
      RouterFlushOutput(client,5);
    }
  }
  return rval;
}

int IRouterPacketToRouter(RouterClient *client, IRIdent *id, IRPacket *pkt)
{
  int iVar1;
  
  iVar1 = IRouterForwardPacket(client,id,pkt);
  return iVar1;
}

IRPacket *IRouterPacketFromRouter(int argcount, RouterArgument *arglistin)
{
  IRFrame *frame;
  int iVar1;
  IRPacket *pf;
  IRPacket *ppf;
  int i;
  int rval;
  
  iVar1 = strcmp("IR",(char *)arglistin->val);
  if (iVar1 == 0) {
    ppf = NULL;
    while (i = argcount + -1, 0 < i) {
      frame = (IRFrame *)arglistin[i].val;
      IRouterSetFrameByteOrder(frame,IRByteOrder);
      frame->_next_frame = ppf;
      frame->_use_count = 0;
      frame->field_0x4 = frame->field_0x4 | 2;
      frame->_arg_data = NULL;
      arglistin[i].clas = 0;
      arglistin[i].val = 0;
      arglistin[i].fre = 0;
      *(uint *)(arglistin + i) = *(uint *)(arglistin + i) & 0xff;
      ppf = frame;
      argcount = i;
    }
  }
  else {
    ppf = NULL;
  }
  return ppf;
}
