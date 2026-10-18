/*
 * sys_ctrl/common/IRouter/IRouter2Router.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/IRouter/IRouter2Router.c
 *
 * IRouter packets carried over Router connections (between L2s, and from an
 * L2 to the L3 tools), as Router events.
 */

#include <stdlib.h>
#include <string.h>
#include "../Router/Router.h"
#include "IRouter2Router.h"
#include "IRouter.h"
#include "../../l3/IRouter/IRouterL3.h"     /* IRouterEventLoop */

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

/*
 * Send an IRouter packet over a Router connection as an event: the argument
 * "IR", then one argument per frame. Board events from an L1 (task
 * IR_L1_BDR) go at priority 10 with a purge key (the source address with the
 * packet's pdata in the number field), other events at 11, requests and
 * responses at 20. The packet is freed.
 */
int IRouterForwardPacket(IRClient *client, IRIdent *id, IRPacket *pkt)
{
  RouterArgument *arglist;
  IRPacket *pf;
  unsigned int data = 0;
  int priority, argc, i;
  uint16 wsize;

  if (pkt->_clas != IR_EVT) {
    priority = 20;
  }
  else if (IR_ADDR_TYPE(pkt->_src) == IR_ADDR_L1 && IR_ADDR_TASK(pkt->_src) == IR_L1_BDR) {
    data = (pkt->_src & 0xfffff01f) | (pkt->_pdata_auth >> 3) << 5;
    priority = 10;
  }
  else {
    priority = 11;
  }
  arglist = malloc(((pkt->_fnum & 0x7f) + 1) * sizeof(RouterArgument));
  if (arglist == NULL)
    return IR_ERRNO(IRERR_MALLOC_FAILED);
  arglist[0].clas = 1;
  arglist[0].val = (uintptr_t)"IR";
  arglist[0].fre = 0;
  arglist[0].size = 3;
  argc = 1;
  for (pf = pkt; pf != NULL; pf = pf->_next_frame) {
    wsize = pf->_size;
    IRouterSetFrameByteOrder(pf,1);
    arglist[argc].clas = 1;
    arglist[argc].fre = 0;
    arglist[argc].size = wsize + IR_ROUTER_PREFIX;
    /* (the data is copied while the event is packed below) */
    arglist[argc].val = ir_native_layout() ? (uintptr_t)pf : (uintptr_t)ir_frame_to_router(pf,wsize);
    argc++;
  }
  RouterPriClientEventOut(client,0,argc,arglist,priority,(void *)(uintptr_t)data);
  if (!ir_native_layout())
    for (i = 1; i < argc; i++)
      free((void *)arglist[i].val);
  free(arglist);
  for (pf = pkt; pf != NULL; pf = pf->_next_frame)
    IRouterSetFrameByteOrder(pf,IRByteOrder);
  IRouterFreePacket(pkt);
  if (!IRouterEventLoop)
    RouterFlushOutput(client,5);
  return 0;
}

int IRouterPacketToRouter(RouterClient *client, IRIdent *id, IRPacket *pkt)
{
  return IRouterForwardPacket(client,id,pkt);
}

/* the packet in a Router event from IRouterForwardPacket(), or NULL */
IRPacket *IRouterPacketFromRouter(int argcount, RouterArgument *arglistin)
{
  IRFrame *frame, *chain = NULL, *next;
  int i;

  if (strcmp("IR",(char *)arglistin[0].val) != 0)
    return NULL;
  /* from the last frame back, so each links to the next */
  for (i = argcount - 1; i > 0; i--) {
    if (ir_native_layout()) {
      /* take over the received buffer: it is already an IRFrame */
      frame = (IRFrame *)arglistin[i].val;
      memset(&arglistin[i],0,sizeof(arglistin[i]));
    }
    else {
      frame = ir_frame_from_router((uint8 *)arglistin[i].val,arglistin[i].size);
      if (frame == NULL) {
        for (; chain != NULL; chain = next) {
          next = chain->_next_frame;
          free(chain);
        }
        return NULL;
      }
    }
    IRouterSetFrameByteOrder(frame,IRByteOrder);
    frame->_next_frame = chain;
    frame->_use_count = 1;
    frame->_arg_data = NULL;
    chain = frame;
  }
  return chain;
}
