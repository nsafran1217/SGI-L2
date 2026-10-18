/*
 * sys_ctrl/l3/l2/reqrspq.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/reqrspq.c
 *
 * A command's queues (l2cmd.c): requests waiting to be sent, and the
 * responses it awaits. Awaited responses are kept sorted by rack and slot
 * (by rack for other L2s) so that output comes in that order; a timer
 * (rspq_timeout_set()) calls the owner back if some never arrive, and a
 * "response wait" reply from a slow target extends it.
 */

#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "reqrspq.h"

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
}

void reqrspq_free(REQRSPQ *q)
{
  reqrspq_reset(q);
  free(q);
}

/* --- requests --- */

/* queue a request: pkt, whether a response is expected, and the pause
 * (ms) after sending it */
void reqq_put(REQRSPQ *q, IRPacket *pkt, int response, int delay)
{
  REQQ *qe;

  qe = malloc(sizeof(REQQ));
  qe->pkt = pkt;
  qe->response = response;
  qe->delay = delay;
  qe->next = NULL;
  qe->prev = q->reqq_tail;
  if (q->reqq_head == NULL)
    q->reqq_head = qe;
  else
    q->reqq_tail->next = qe;
  q->reqq_tail = qe;
  q->reqq_length++;
}

/* take the first request; -1 if there is none */
int reqq_get(REQRSPQ *q, IRPacket **pkt, int *response, int *delay)
{
  REQQ *qe = q->reqq_head;

  if (qe == NULL)
    return -1;
  q->reqq_head = qe->next;
  if (q->reqq_head == NULL)
    q->reqq_tail = NULL;
  else
    q->reqq_head->prev = NULL;
  *pkt = qe->pkt;
  *response = qe->response;
  *delay = qe->delay;
  free(qe);
  q->reqq_length--;
  return 0;
}

int reqq_empty(REQRSPQ *q)
{
  return q->reqq_length == 0;
}

void reqq_reset(REQRSPQ *q)
{
  REQQ *qe;

  while ((qe = q->reqq_head) != NULL) {
    q->reqq_head = qe->next;
    if (qe->pkt != NULL)
      IRouterFreePacket(qe->pkt);
    free(qe);
  }
  q->reqq_tail = NULL;
  q->reqq_length = 0;
}

/* --- responses --- */

/* await the response to request seqn sent to dest */
void rspq_put(REQRSPQ *q, unsigned int seqn, IRAddress dest)
{
  L2CfgNode *node;
  unsigned int sort = 0;
  RSPQ *qe;
  RSPQ *qp;

  qe = malloc(sizeof(RSPQ));
  qe->seqn = seqn;
  qe->dest = dest;
  qe->next = NULL;
  qe->prev = NULL;
  qe->pkt = NULL;
  if (IR_ADDR_IS_IP(dest)) {
    /* another L2: by its rack */
    node = L2CfgMFindNode(&L2CfgLocal,IR_ADDR_TO_IP(dest),0,NULL);
    if (node != NULL)
      sort = L2CFG_OF(node)->rack;
  }
  else
    sort = dest >> 12;          /* type, rack, slot */
  qe->sort = sort;
  /* ahead of the first entry that sorts the same or later */
  for (qp = q->rspq_head; qp != NULL && qp->sort < sort; qp = qp->next)
    ;
  if (qp == NULL) {
    qe->prev = q->rspq_tail;
    if (q->rspq_tail == NULL)
      q->rspq_head = qe;
    else
      q->rspq_tail->next = qe;
    q->rspq_tail = qe;
  }
  else {
    qe->next = qp;
    qe->prev = qp->prev;
    if (qp->prev == NULL)
      q->rspq_head = qe;
    else
      qp->prev->next = qe;
    qp->prev = qe;
  }
  q->rspq_length++;
  q->rspq_max_length++;
  q->rspq_pending++;
}

/*
 * A response arrived: file it with its request. Returns how many are still
 * pending, or -1 if it was not awaited (the caller frees it). A "response
 * wait" (IRERR_RESPONSE_WAIT: the target needs <arg 0>/100 seconds) is
 * consumed, and extends the timeout if that is longer than any before.
 */
int rspq_update(REQRSPQ *q, IRPacket *pkt)
{
  unsigned int seqn;
  int wait;
  RSPQ *qe;

  if (pkt->_err == IRERR_RESPONSE_WAIT) {
    wait = IRArg(pkt,0) / 100;
    if (q->rspq_etimeout < wait) {
      rspq_timeout_clr(q);
      q->rspq_etimeout = wait;
      rspq_timeout_set(q,wait);
      if (q->rspq_etofunc != NULL)
        q->rspq_etofunc(pkt->_argc == 1 ? 0 : (unsigned int)IRArg(pkt,1),q->rspq_todata);
    }
    IRouterFreePacket(pkt);
    return q->rspq_pending;
  }
  for (qe = q->rspq_head; qe != NULL; qe = qe->next) {
    /* (the original also took a second response for an answered request,
     * dropping the first and counting it twice) */
    if (qe->pkt != NULL)
      continue;
    seqn = pkt->_rev == 0 ? qe->seqn & 0xff : qe->seqn & 0xffff;   /* revision 0: 8-bit */
    if (seqn == IR_SEQNUM(pkt)) {
      qe->pkt = pkt;
      return --q->rspq_pending;
    }
  }
  return -1;
}

void rspq_reset(REQRSPQ *q)
{
  RSPQ *qe;

  while ((qe = q->rspq_head) != NULL) {
    q->rspq_head = qe->next;
    if (qe->pkt != NULL)
      IRouterFreePacket(qe->pkt);
    free(qe);
  }
  q->rspq_tail = NULL;
  q->rspq_length = 0;
  q->rspq_max_length = 0;
  q->rspq_pending = 0;
  rspq_timeout_clr(q);
  q->rspq_timeout = 0;
  q->rspq_etimeout = 0;
}

/* take the first entry (its response, or NULL if none came); returns how
 * many are left, or -1 if there was none */
int rspq_get(REQRSPQ *q, unsigned int *seqn, IRAddress *dest, IRPacket **pkt)
{
  RSPQ *qe = q->rspq_head;

  if (qe == NULL)
    return -1;
  q->rspq_head = qe->next;
  if (q->rspq_head == NULL)
    q->rspq_tail = NULL;
  else
    q->rspq_head->prev = NULL;
  *dest = qe->dest;
  *seqn = qe->seqn;
  *pkt = qe->pkt;
  free(qe);
  return --q->rspq_length;
}

/* the entry after qe (the first if qe is NULL), without taking it */
RSPQ *rspq_peek(REQRSPQ *q, RSPQ *qe, unsigned int *seqn, IRAddress *dest, IRPacket **pkt)
{
  qe = qe == NULL ? q->rspq_head : qe->next;
  if (qe != NULL) {
    *dest = qe->dest;
    *seqn = qe->seqn;
    *pkt = qe->pkt;
  }
  return qe;
}

int rspq_empty(REQRSPQ *q)
{
  return q->rspq_length == 0;
}

/* the timer: done if nothing is pending, else tell the owner how long it
 * waited */
static void rspq_timeout(REQRSPQ *q)
{
  q->rspq_timer = 0;
  if (q->rspq_pending == 0 || q->rspq_tofunc == NULL) {
    reqrspq_reset(q);
    return;
  }
  q->rspq_tofunc(q->rspq_etimeout != 0 ? q->rspq_etimeout : q->rspq_timeout,q->rspq_todata);
}

/* start the timer (to seconds) unless it runs */
void rspq_timeout_set(REQRSPQ *q, int to)
{
  if (q->rspq_timer == 0)
    q->rspq_timer = EventAddTimeOut(to,0,rspq_timeout,(EventData)q,"rspq_timeout_set");
  q->rspq_timeout = to;
}

void rspq_timeout_clr(REQRSPQ *q)
{
  if (q->rspq_timer != 0)
    EventRemoveTimeOut(q->rspq_timer);
  q->rspq_timer = 0;
}
