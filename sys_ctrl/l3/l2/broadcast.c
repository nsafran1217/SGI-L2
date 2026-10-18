/*
 * sys_ctrl/l3/l2/broadcast.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/broadcast.c
 *
 * Sending one command to many targets: broadcast_l1() and broadcast_l2()
 * queue a request per brick or L2 of the command's destination, with
 * markers between groups; broadcast() then sends them. A marker with delay
 * -1 waits for the group's responses (broadcast() returns, and is called
 * again once they are in), a positive delay pauses that many milliseconds.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "l2.h"
#include "broadcast.h"
#include "irtr.h"

#define WAIT_RESPONSES  -1      /* the marker's delay that waits */

int broadcast_debug;            /* 1 the sending, 2 the groups, 4 the bricks */
int broadcast_response_timeout = 15;

/*
 * Send q's requests up to the next wait for responses. Returns -1 while
 * responses are awaited, 0 when the queue is done. (A call while it is
 * sleeping between requests returns -1 at once.)
 */
int broadcast(REQRSPQ *q, IRIdent *id)
{
  static int active;
  static int pcount;            /* requests sent since the last pause */
  IRPacket *pkt = NULL;
  int response = 0;
  int delay = 0;

  if (active) {
    if (broadcast_debug & 1)
      fprintf(stderr,"broadcast returning (1)\n");
    pcount--;
    return -1;
  }
  pcount = 0;
  active = 1;
  for (;;) {
    if (reqq_get(q,&pkt,&response,&delay) != 0) {
      if (broadcast_debug & 1)
        fprintf(stderr,"broadcast returning (3)\n");
      active = 0;
      return 0;
    }
    if (pkt != NULL) {
      if (broadcast_debug & 1)
        fprintf(stderr,"%d.%d ",IR_ADDR_RACK(pkt->_dest),IR_ADDR_SLOT(pkt->_dest));
      if (response) {
        rspq_put(q,IR_SEQNUM(pkt),pkt->_dest);
        rspq_timeout_set(q,broadcast_response_timeout);
      }
      pcount++;
      IRouterSendPacket(id,pkt);
    }
    if (delay == 0)
      continue;
    if (delay == WAIT_RESPONSES) {
      if (q->rspq_pending == 0)
        continue;
      if (broadcast_debug & 1)
        fprintf(stderr,"broadcast returning (2)\n");
      active = 0;
      return -1;
    }
    if (broadcast_debug & 1)
      fprintf(stderr,"sleep %d ",delay);
    usleep(delay * 1000);
    pcount = 0;
  }
}

/* a request for cmd (a copy, freed once sent) to addr's command task */
static IRPacket *command_packet(L2CMD *c, IRAddress addr, const char *cmd)
{
  IRArgument argv[2];
  char *copy = strdup(cmd);

  addr = IR_ADDR_WITH_TASK(addr,IR_L2_CMD);   /* (an L1's IR_L1_CMD is the same) */
  argv[0]._clas = IR_ARG_VALUE;
  argv[0]._frame = 0;
  argv[0]._val = 0;
  argv[0]._size = 0;
  argv[1]._clas = IR_ARG_STRING | IR_ARG_FREE;
  argv[1]._frame = 0;
  argv[1]._val = IR_PTR_VAL(copy);
  argv[1]._size = strlen(copy) + 1;
  return IRouterMakePacket(c->id,&addr,0,0,IR_REQ,2,2,argv);
}

/*
 * cmd to every L2 of c's destination, last first; the final call of a
 * command starts sending. A final command for this L2 alone runs at once,
 * into results.
 */
int broadcast_l2(L2CMD *c, char **results, char *cmd, int response, int delay, int final)
{
  L2CfgNode *node;
  int i;

  if (final && c->dest->count == 1) {
    node = L2CfgMFindNode(&L2CfgLocal,IR_ADDR_TO_IP(c->dest->list[0]),0,NULL);
    if ((L2Cfg *)node == &L2CfgLocal)
      return l2cmd_process(NULL,cmd,results,NULL);
  }
  for (i = c->dest->count - 1; i >= 0; i--)
    reqq_put(c->q,command_packet(c,c->dest->list[i],cmd),response,0);
  if (response) {
    reqq_put(c->q,NULL,0,WAIT_RESPONSES);
    if (!final)
      reqq_put(c->q,NULL,0,delay);
    c->busy |= 1;
  }
  if (final) {
    rspq_timeout_set(c->q,broadcast_response_timeout);
    broadcast(c->q,c->id);
  }
  return 0;
}

/* a brick type's BCAST_ class */
static int brick_class(int type)
{
  switch (type) {
  case '-': case 'D': case 'R':
    return BCAST_ROUTER;
  case '#': case '&': case '=': case 'E': case 'G': case 'I':
  case 'N': case 'P': case 'V': case 'X': case 'Y':
    return BCAST_IO;
  default:
    return brickIsCompute(type) ? BCAST_COMPUTE : BCAST_OTHER;
  }
}

/* queue cmd for the brick at addr if it is of class and its power state
 * is wanted; counts it in *pcount */
static void queue_brick(L2CMD *c, IRAddress addr, int class, int type, int method, char *cmd,
                        int response, int delay, int *pcount)
{
  int rack = IR_ADDR_RACK(addr);
  int slot = IR_ADDR_SLOT(addr);
  L2CfgL1 *l1;
  IRPacket *p;

  l1 = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
  if (l1 == NULL || !(brick_class(l1->type) & class) ||
      ((type & BCAST_POWER_OFF) && l1->power_state != 0) ||
      ((type & BCAST_POWER_ON) && l1->power_state == 0))
    return;
  p = command_packet(c,addr,cmd);
  if ((broadcast_debug & 2) && *pcount == 0)
    fprintf(stderr,"sending \'%s\' %s, %d\n",cmd,method == BCAST_SERIAL ? "serial" : "parallel",
            class);
  (*pcount)++;
  if (broadcast_debug & 4)
    fprintf(stderr,"%d.%d ",rack,slot);
  reqq_put(c->q,p,response,0);
  if (response) {
    c->busy |= 1;
    if (method == BCAST_SERIAL) {       /* each brick's response before the next */
      reqq_put(c->q,NULL,0,WAIT_RESPONSES);
      reqq_put(c->q,NULL,0,delay);
      if (broadcast_debug & 2)
        fprintf(stderr,"serial %d\n",delay);
    }
  }
}

/*
 * cmd to the bricks of c's destination of the classes in type (BCAST_ALL:
 * each class in turn) and power states it names; with slots (a list ending
 * in -1), only bricks in those slots, slot by slot. BCAST_SERIAL waits for
 * each brick's response, BCAST_PARALLEL for all of them; then the pause
 * delay unless final. The final call of a command starts sending.
 */
int broadcast_l1(L2CMD *c, int method, char *cmd, int response, int delay, int type, int *slots, int final)
{
  int first_class;
  int last_class;
  int class;
  int pcount = 0;
  int slot;
  int i;

  if ((type & 0xffff) == BCAST_ALL) {
    first_class = BCAST_ROUTER;
    last_class = BCAST_OTHER;
  }
  else
    first_class = last_class = type & 0xffff;
  for (class = first_class; class <= last_class; class <<= 1) {
    if (slots == NULL) {
      for (i = 0; i < c->dest->count; i++)
        queue_brick(c,c->dest->list[i],class,type,method,cmd,response,delay,&pcount);
      continue;
    }
    for (slot = 0; slots[slot] != -1; slot++)
      for (i = 0; i < c->dest->count; i++)
        if (IR_ADDR_SLOT(c->dest->list[i]) == slots[slot])
          queue_brick(c,c->dest->list[i],class,type,method,cmd,response,delay,&pcount);
  }
  if (pcount != 0 && response && method == BCAST_PARALLEL) {
    reqq_put(c->q,NULL,0,WAIT_RESPONSES);
    if (!final)
      reqq_put(c->q,NULL,0,delay);
    if (broadcast_debug & 2)
      fprintf(stderr,"parallel %d\n",delay);
  }
  if (final) {
    if (broadcast_debug & 1)
      fprintf(stderr,"starting broadcast\n");
    rspq_timeout_set(c->q,broadcast_response_timeout);
    broadcast(c->q,c->id);
  }
  return 0;
}
