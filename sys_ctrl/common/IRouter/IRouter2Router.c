/*
 * sys_ctrl/common/IRouter/IRouter2Router.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/IRouter/IRouter2Router.c
 */

#include <stdlib.h>
#include <string.h>
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

/* Router events carry IRouter frames in the original i386 memory layout: a
 * 16-byte prefix (next pointer, two flag words, two more pointers) followed
 * by the wire frame. Only the flag words mean anything to the receiver
 * (_byte_order in particular). Where the host's IRFrame prefix is not that
 * layout, frames are converted; on i386 they are sent as-is, as originally. */
#define IR_ROUTER_PREFIX 16

static int ir_native_layout(void)
{
  /* same prefix size, and little-endian so the flag bitfields sit where i386 put them */
  const uint16 one = 1;
  return IR_FRAME_PREFIX == IR_ROUTER_PREFIX && *(const uint8 *)&one == 1;
}

/* i386 layout: little-endian uint16 at 4 = _external | _use_count << 1,
 * at 6 = _byte_order | _qsuspend << 2 */
/* wsize: the frame's size in host order (f may already be in network order) */
static uint8 *ir_frame_to_router(IRFrame *f, int wsize)
{
  uint8 *b = calloc(1, IR_ROUTER_PREFIX + wsize);
  uint16 w4, w6;

  if (b == NULL)
    return NULL;
  w4 = (uint16)(f->_external | f->_use_count << 1);
  w6 = (uint16)(f->_byte_order | f->_qsuspend << 2);
  b[4] = (uint8)w4;
  b[5] = (uint8)(w4 >> 8);
  b[6] = (uint8)w6;
  b[7] = (uint8)(w6 >> 8);
  memcpy(b + IR_ROUTER_PREFIX, IR_FRAME_WIRE(f), wsize);
  return b;
}

static IRFrame *ir_frame_from_router(const uint8 *b, int size)
{
  int wsize = size - IR_ROUTER_PREFIX;
  IRFrame *f;
  uint16 w4, w6;

  if (wsize < 0)
    return NULL;
  f = calloc(1, IR_FRAME_PREFIX + (wsize > 0x400 ? wsize : 0x400));
  if (f == NULL)
    return NULL;
  w4 = (uint16)(b[4] | b[5] << 8);
  w6 = (uint16)(b[6] | b[7] << 8);
  f->_external = w4 & 1;
  f->_use_count = w4 >> 1;
  f->_byte_order = w6 & 3;
  f->_qsuspend = w6 >> 2;
  memcpy(IR_FRAME_WIRE(f), b + IR_ROUTER_PREFIX, wsize);
  return f;
}

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
  int i;
  
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
        data = (uVar2 & 0xfffff01f) | (uint)(pkt->_pdata_auth >> 3) << 5;
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
  arglist = malloc(((pkt->_fnum & 0x7f) + 1) * sizeof(RouterArgument));
  if (arglist == NULL) {
    rval = -0x25c;
  }
  else {
    arglist->clas = 1;
    arglist->val = (ulong)"IR";
    arglist->fre = 0;
    arglist->size = 3;
    argc = 1;
    for (pf = pkt; pf != NULL; pf = pf->_next_frame) {
      uVar1 = pf->_size;
      IRouterSetFrameByteOrder(pf,1);
      arglist[argc].clas = 1;
      arglist[argc].fre = 0;
      arglist[argc].size = uVar1 + IR_ROUTER_PREFIX;
      /* data copied while the event is packed below */
      arglist[argc].val = ir_native_layout() ? (ulong)pf : (ulong)ir_frame_to_router(pf, uVar1);
      argc = argc + 1;
    }
    RouterPriClientEventOut(client,0,argc,arglist,(uint)priority,(void *)(uintptr_t)data);
    if (!ir_native_layout()) {
      for (i = 1; i < argc; i++)
        free((void *)arglist[i].val);
    }
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
      if (ir_native_layout()) {
        /* take over the received buffer: it is already an IRFrame */
        frame = (IRFrame *)arglistin[i].val;
        arglistin[i].clas = 0;
        arglistin[i].val = 0;
        arglistin[i].fre = 0;
        arglistin[i].size = 0;
      }
      else {
        frame = ir_frame_from_router((uint8 *)arglistin[i].val, arglistin[i].size);
        if (frame == NULL) {
          while (ppf != NULL) {
            pf = ppf->_next_frame;
            free(ppf);
            ppf = pf;
          }
          return NULL;
        }
      }
      IRouterSetFrameByteOrder(frame,IRByteOrder);
      frame->_next_frame = ppf;
      frame->_use_count = 1;
      frame->_arg_data = NULL;
      ppf = frame;
      argcount = i;
    }
  }
  else {
    ppf = NULL;
  }
  return ppf;
}
