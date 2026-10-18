/*
 * sys_ctrl/l3/l2/reqrspq.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/reqrspq.c
 */

#include "smp.h"   /* needed by the reconstruction */
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
#include "reqrspq.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void rspq_timeout(REQRSPQ *q);

REQRSPQ *reqrspq_init(void (*tofunc)(), void (*etofunc)(), void *todata)
{
  REQRSPQ *q;
  
  q = malloc(sizeof(REQRSPQ));
  memset(q,0,sizeof(REQRSPQ));
  q->rspq_tofunc = tofunc;
  q->rspq_etofunc = etofunc;
  q->rspq_todata = todata;
  return q;
}

void reqrspq_reset(REQRSPQ *q)
{
  reqq_reset(q);
  rspq_reset(q);
  return;
}

void reqrspq_free(REQRSPQ *q)
{
  reqrspq_reset(q);
  free(q);
  return;
}

void reqq_put(REQRSPQ *q, IRPacket *pkt, int response, int delay)
{
  REQQ *qe;
  
  qe = malloc(sizeof(REQQ));
  qe->pkt = pkt;
  qe->response = response;
  qe->delay = delay;
  if (q->reqq_head == NULL) {
    q->reqq_head = qe;
    q->reqq_tail = qe;
    qe->prev = NULL;
    qe->next = NULL;
  }
  else {
    q->reqq_tail->next = qe;
    qe->prev = q->reqq_tail;
    qe->next = NULL;
    q->reqq_tail = qe;
  }
  q->reqq_length = q->reqq_length + 1;
  return;
}

int reqq_get(REQRSPQ *q, IRPacket **pkt, int *response, int *delay)
{
  struct REQQ_s *pRVar1;
  int iVar2;
  REQQ *qe;
  
  qe = q->reqq_head;
  if (qe == NULL) {
    iVar2 = -1;
  }
  else {
    pRVar1 = qe->next;
    q->reqq_head = pRVar1;
    if (pRVar1 == NULL) {
      q->reqq_tail = NULL;
    }
    else {
      q->reqq_head->prev = NULL;
    }
    *pkt = qe->pkt;
    *response = qe->response;
    *delay = qe->delay;
    free(qe);
    q->reqq_length = q->reqq_length + -1;
    iVar2 = 0;
  }
  return iVar2;
}

int reqq_empty(REQRSPQ *q)
{
  return (uint)(q->reqq_length == 0);
}

void reqq_reset(REQRSPQ *q)
{
  REQQ *__ptr;
  REQQ *qe;
  
  while (q->reqq_head != NULL) {
    __ptr = q->reqq_head;
    q->reqq_head = __ptr->next;
    if (__ptr->pkt != NULL) {
      IRouterFreePacket(__ptr->pkt);
    }
    free(__ptr);
  }
  q->reqq_tail = NULL;
  q->reqq_head = NULL;
  q->reqq_length = 0;
  return;
}

void rspq_put(REQRSPQ *q, unsigned int seqn, IRAddress dest)
{
  RSPQ *qe;
  uint uVar1;
  L2CfgNode *node;
  uint32_t ip_addr;
  IRAddress ir_addr;
  RouterClient *client;
  RSPQ *qp;
  uint sort;
  
  sort = 0;
  qe = malloc(sizeof(RSPQ));
  qe->seqn = seqn;
  qe->dest = dest;
  qe->next = NULL;
  qe->prev = NULL;
  qe->pkt = NULL;
  if ((dest & 0x80000000) == 0) {
    uVar1 = dest >> 0x1c;
  }
  else if (dest >> 0x1e == 2) {
    uVar1 = 0xe;
  }
  else {
    uVar1 = 0xf;
  }
  if ((uVar1 < 0x10) && (0xd < uVar1)) {
    client = NULL;
    ir_addr = 0;
    if (IRByteOrder == 1) {
      ip_addr = dest & 0xffffff;
    }
    else {
      ip_addr = htonl(dest & 0xffffff);
    }
    node = L2CfgMFindNode(&L2CfgLocal,ip_addr,ir_addr,client);
    if (node != NULL) {
      sort = L2CFG_OF(node)->rack;
    }
  }
  else {
    sort = dest >> 0xc;
  }
  qe->sort = sort;
  if (q->rspq_head == NULL) {
    q->rspq_head = qe;
    q->rspq_tail = qe;
  }
  else {
    for (qp = q->rspq_head; (qp != NULL && (qp->sort < sort)); qp = qp->next) {
    }
    if (qp == q->rspq_head) {
      qe->next = q->rspq_head;
      q->rspq_head->prev = qe;
      q->rspq_head = qe;
    }
    else if (qp == NULL) {
      qe->prev = q->rspq_tail;
      q->rspq_tail->next = qe;
      q->rspq_tail = qe;
    }
    else {
      qp->prev->next = qe;
      qe->prev = qp->prev;
      qp->prev = qe;
      qe->next = qp;
    }
  }
  q->rspq_length = q->rspq_length + 1;
  q->rspq_max_length = q->rspq_max_length + 1;
  q->rspq_pending = q->rspq_pending + 1;
  return;
}

int rspq_update(REQRSPQ *q, IRPacket *pkt)
{
  uint uVar1;
  int iVar2;
  void *pvVar3;
  uint uStack_14;
  int timeout;
  RSPQ *qe;
  int rev;
  
  qe = q->rspq_head;
  if (pkt->_err == '\x13') {
    uVar1 = IRArg(pkt,0);
    uVar1 = uVar1 / 100;
    if (q->rspq_etimeout < (int)uVar1) {
      rspq_timeout_clr(q);
      q->rspq_etimeout = uVar1;
      rspq_timeout_set(q,uVar1);
      if (q->rspq_etofunc != NULL) {
        pvVar3 = q->rspq_todata;
        if (pkt->_argc == '\x01') {
          uStack_14 = 0;
        }
        else {
          uStack_14 = IRArg(pkt,1);
        }
        (*q->rspq_etofunc)(uStack_14,pvVar3);
      }
    }
    IRouterFreePacket(pkt);
    iVar2 = q->rspq_pending;
  }
  else {
    for (; qe != NULL; qe = qe->next) {
      if (pkt->_rev == '\0') {
        uVar1 = qe->seqn & 0xff;
      }
      else {
        uVar1 = qe->seqn & 0xffff;
      }
      if (uVar1 == CONCAT11(pkt->_seqnum1,pkt->_seqnum0)) {
        qe->pkt = pkt;
        q->rspq_pending = q->rspq_pending + -1;
        return q->rspq_pending;
      }
    }
    iVar2 = -1;
  }
  return iVar2;
}

void rspq_reset(REQRSPQ *q)
{
  RSPQ *__ptr;
  RSPQ *qe;
  
  while (q->rspq_head != NULL) {
    __ptr = q->rspq_head;
    q->rspq_head = __ptr->next;
    if (__ptr->pkt != NULL) {
      IRouterFreePacket(__ptr->pkt);
    }
    free(__ptr);
  }
  q->rspq_tail = NULL;
  q->rspq_head = NULL;
  q->rspq_length = 0;
  q->rspq_max_length = 0;
  q->rspq_pending = 0;
  if (q->rspq_timer != 0) {
    EventRemoveTimeOut(q->rspq_timer);
  }
  q->rspq_timer = 0;
  q->rspq_timeout = 0;
  q->rspq_etimeout = 0;
  return;
}

int rspq_get(REQRSPQ *q, unsigned int *seqn, IRAddress *dest, IRPacket **pkt)
{
  struct RSPQ_s *pRVar1;
  int iVar2;
  RSPQ *qe;
  
  qe = q->rspq_head;
  if (qe == NULL) {
    iVar2 = -1;
  }
  else {
    pRVar1 = qe->next;
    q->rspq_head = pRVar1;
    if (pRVar1 == NULL) {
      q->rspq_tail = NULL;
    }
    else {
      q->rspq_head->prev = NULL;
    }
    *dest = qe->dest;
    *seqn = qe->seqn;
    *pkt = qe->pkt;
    free(qe);
    q->rspq_length = q->rspq_length + -1;
    iVar2 = q->rspq_length;
  }
  return iVar2;
}

RSPQ *rspq_peek(REQRSPQ *q, RSPQ *qe, unsigned int *seqn, IRAddress *dest, IRPacket **pkt)
{
  if (qe == NULL) {
    qe = q->rspq_head;
  }
  else {
    qe = qe->next;
  }
  if (qe != NULL) {
    *dest = qe->dest;
    *seqn = qe->seqn;
    *pkt = qe->pkt;
  }
  return qe;
}

int rspq_empty(REQRSPQ *q)
{
  return (uint)(q->rspq_length == 0);
}

static void rspq_timeout(REQRSPQ *q)
{
  int iVar1;
  
  q->rspq_timer = 0;
  if ((q->rspq_pending == 0) || (q->rspq_tofunc == NULL)) {
    reqrspq_reset(q);
  }
  else {
    iVar1 = q->rspq_etimeout;
    if (q->rspq_etimeout == 0) {
      iVar1 = q->rspq_timeout;
    }
    (*q->rspq_tofunc)(iVar1,q->rspq_todata);
  }
  return;
}

void rspq_timeout_set(REQRSPQ *q, int to)
{
  EventID EVar1;
  
  if (q->rspq_timer == 0) {
    EVar1 = EventAddTimeOut(to,0,rspq_timeout,(EventData)q,"rspq_timeout_set");
    q->rspq_timer = EVar1;
  }
  q->rspq_timeout = to;
  return;
}

void rspq_timeout_clr(REQRSPQ *q)
{
  if (q->rspq_timer != 0) {
    EventRemoveTimeOut(q->rspq_timer);
  }
  q->rspq_timer = 0;
  return;
}
