/*
 * Equivalence test of a command's request and response queues
 * (l3/l2/reqrspq.c) against the decomp branch's reconstruction (Orig*): the
 * same random operations on one queue of each, with the packets, timers and
 * L2 lookups stubbed and every result, callback and free compared.
 * reqrspq_test.sh builds it under ASan.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "reqrspq.h"

#include "orig_reqrspq.h"

L2Cfg L2CfgLocal;
int IRByteOrder;
static L2Cfg peers[4];          /* L2s found by IP: racks */
static unsigned int seed = 1;
static int side;                /* 0 the original's calls, 1 the new */
static char log_[2][65536];     /* what each side did */

static unsigned int rnd(unsigned int n)
{
  seed = seed * 1103515245 + 12345;
  return (seed >> 8) % n;
}

static void note(const char *fmt, unsigned long a, unsigned long b)
{
  char *l = log_[side];
  size_t len = strlen(l);
  if (len < sizeof(log_[0]) - 100)
    snprintf(l + len,sizeof(log_[0]) - len,fmt,a,b);
}

/* --- stubs --- */
int IRouterFreePacket(IRPacket *pkt)
{
  note("free %lu%.0lu\n",pkt->_opcode,0);
  free(pkt);
  return 0;
}

uintptr_t IRArg(IRPacket *pkt, int arg)
{
  return arg < pkt->_argc ? pkt->_argv[arg]._val : 0;
}

L2CfgNode *L2CfgMFindNode(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  unsigned int i = ntohl(ip_addr) & 0xff;
  return i < 4 ? &peers[i].net : NULL;
}

static struct { void (*f)(); EventData d; } timers[2][1000];
static unsigned int ntimers[2];

EventID EventAddTimeOut(long unsigned int seconds, long unsigned int microseconds,
                        void (*timer_func)(), EventData client_data, char *desc)
{
  unsigned int n = ntimers[side]++ % 1000;
  timers[side][n].f = timer_func;
  timers[side][n].d = client_data;
  note("timer %lu: %lu s\n",n + 1,seconds);
  return n + 1;
}

void EventRemoveTimeOut(EventID id)
{
  note("remove timer %lu%.0lu\n",id,0);
  timers[side][(id - 1) % 1000].f = NULL;
}

static void tofunc(int to, void *data) { note("timeout %lu %lu\n",to,(uintptr_t)data); }
static void etofunc(unsigned int arg, void *data) { note("etimeout %lu %lu\n",arg,(uintptr_t)data); }

/* --- the test --- */
static int next_id = 1;

static IRPacket *packet(int id, int err, int seq, int rev, int argc, uint32 a0, uint32 a1)
{
  IRPacket *p = calloc(1,sizeof(IRPacket) + 3 * sizeof(IRArgument));
  p->_opcode = id;
  p->_err = err;
  p->_seqnum0 = seq;
  p->_seqnum1 = seq >> 8;
  p->_rev = rev;
  p->_argc = argc;
  p->_argv[0]._val = a0;
  p->_argv[1]._val = a1;
  return p;
}

/* whether q already holds a response with this sequence number */
static int answered(REQRSPQ *q, int seq, int rev)
{
  RSPQ *qe;
  for (qe = q->rspq_head; qe != NULL; qe = qe->next)
    if (qe->pkt != NULL && (rev == 0 ? (qe->seqn & 0xff) == (seq & 0xff) : (qe->seqn & 0xffff) == seq))
      return 1;
  return 0;
}

static IRAddress random_dest(void)
{
  switch (rnd(3)) {
  case 0:
    return 0x80000000 | rnd(6);                     /* an L2 (perhaps unknown) */
  case 1:
    return IR_ADDR_MAKE(IR_ADDR_L1,rnd(4),rnd(4),0,rnd(32));
  default:
    return seed;
  }
}

#define BOTH(call_o, call_n) \
  do { side = 0; ro = (call_o); side = 1; rn = (call_n); } while (0)

int main(void)
{
  REQRSPQ *qo, *qn;
  long ro, rn;
  int step, i;

  IRByteOrder = htonl(1) == 1 ? 1 : 2;
  for (i = 0; i < 4; i++)
    peers[i].rack = rnd(5);
  side = 0;
  qo = Origreqrspq_init(tofunc,etofunc,(void *)7);
  side = 1;
  qn = reqrspq_init(tofunc,etofunc,(void *)7);
  for (step = 0; step < 200000; step++) {
    unsigned int seq = rnd(4) == 0 ? rnd(65536) : rnd(16);
    int rev = rnd(2), id = next_id++;
    ro = rn = 0;
    switch (rnd(12)) {
    case 0: {
      int resp = rnd(2), delay = rnd(100);
      BOTH((Origreqq_put(qo,packet(id,0,0,0,0,0,0),resp,delay),0),
           (reqq_put(qn,packet(id,0,0,0,0,0,0),resp,delay),0));
      break;
    }
    case 1: {
      IRPacket *po = NULL, *pn = NULL;
      int r1 = 0, r2 = 0, d1 = 0, d2 = 0;
      BOTH(Origreqq_get(qo,&po,&r1,&d1),reqq_get(qn,&pn,&r2,&d2));
      if (ro == 0) {
        if (po->_opcode != pn->_opcode || r1 != r2 || d1 != d2)
          ro = -99;
        free(po);
        free(pn);
      }
      break;
    }
    case 2: case 3: case 4: {
      IRAddress dest = random_dest();
      BOTH((Origrspq_put(qo,seq,dest),0),(rspq_put(qn,seq,dest),0));
      break;
    }
    case 5: case 6: case 7: {
      int err = rnd(4) == 0 ? IRERR_RESPONSE_WAIT : 0, argc = rnd(3);
      uint32 a0 = rnd(5000), a1 = rnd(9);
      if (err == 0 && answered(qo,seq,rev))
        break;                  /* (the original mishandles a second response) */
      BOTH(Origrspq_update(qo,packet(id,err,seq,rev,argc,a0,a1)),
           rspq_update(qn,packet(id,err,seq,rev,argc,a0,a1)));
      break;
    }
    case 8: {
      unsigned int s1 = 0, s2 = 0;
      IRAddress d1 = 0, d2 = 0;
      IRPacket *po = NULL, *pn = NULL;
      BOTH(Origrspq_get(qo,&s1,&d1,&po),rspq_get(qn,&s2,&d2,&pn));
      if (ro != -1 && (s1 != s2 || d1 != d2 || (po == NULL) != (pn == NULL) ||
                       (po != NULL && po->_opcode != pn->_opcode)))
        ro = -99;
      free(po);
      free(pn);
      break;
    }
    case 9: {
      RSPQ *eo = NULL, *en = NULL;
      unsigned int s1, s2;
      IRAddress d1, d2;
      IRPacket *po, *pn;
      do {
        eo = Origrspq_peek(qo,eo,&s1,&d1,&po);
        en = rspq_peek(qn,en,&s2,&d2,&pn);
        if ((eo == NULL) != (en == NULL) ||
            (eo != NULL && (s1 != s2 || d1 != d2 || (po == NULL) != (pn == NULL))))
          ro = -99;
      } while (eo != NULL && en != NULL);
      break;
    }
    case 10: {
      int to = rnd(30);
      switch (rnd(4)) {
      case 0:
        BOTH((Origrspq_timeout_set(qo,to),0),(rspq_timeout_set(qn,to),0));
        break;
      case 1:
        BOTH((Origrspq_timeout_clr(qo),0),(rspq_timeout_clr(qn),0));
        break;
      default:                  /* the last timer fires */
        for (side = 0; side < 2; side++) {
          unsigned int n = (ntimers[side] - 1) % 1000;
          if (ntimers[side] != 0 && timers[side][n].f != NULL) {
            void (*f)() = timers[side][n].f;
            timers[side][n].f = NULL;
            f(timers[side][n].d);
          }
        }
        side = 1;
      }
      break;
    }
    default:
      if (rnd(10) == 0)
        BOTH((Origreqrspq_reset(qo),0),(reqrspq_reset(qn),0));
      else
        BOTH(Origrspq_empty(qo) * 2 + Origreqq_empty(qo),rspq_empty(qn) * 2 + reqq_empty(qn));
    }
    if (ro != rn || strcmp(log_[0],log_[1]) != 0 || qo->rspq_length != qn->rspq_length ||
        qo->rspq_pending != qn->rspq_pending || qo->rspq_max_length != qn->rspq_max_length ||
        qo->reqq_length != qn->reqq_length || qo->rspq_timeout != qn->rspq_timeout ||
        qo->rspq_etimeout != qn->rspq_etimeout) {
      printf("FAIL  reqrspq: step %d: %ld vs %ld\n--- orig\n%s--- new\n%s",step,ro,rn,log_[0],
             log_[1]);
      return 1;
    }
    log_[0][0] = log_[1][0] = '\0';
  }
  printf("PASS  reqrspq: %d queue operations compared with the original\n",step);
  return 0;
}
