/*
 * Equivalence test of broadcasting (l3/l2/broadcast.c) against the main
 * branch's reconstruction (Orig*): random destinations, bricks, classes,
 * power filters, slot lists and methods; every request queued, marker,
 * send and pause must match. broadcast_test.sh builds it under ASan with
 * the (new) queues and stubs for packets, timers and the configuration.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include "l2.h"
#include "broadcast.h"
#include "orig_broadcast.h"

L2Cfg L2CfgLocal;
int IRByteOrder;
static unsigned int seed = 1;
static int side;
static char log_[2][1 << 16];

static unsigned int rnd(unsigned int n)
{
  seed = seed * 1103515245 + 12345;
  return (seed >> 8) % n;
}

static void note(const char *fmt, ...)
{
  char *l = log_[side];
  size_t len = strlen(l);
  va_list ap;

  va_start(ap,fmt);
  if (len < sizeof(log_[0]) - 200)
    vsnprintf(l + len,sizeof(log_[0]) - len,fmt,ap);
  va_end(ap);
}

/* --- stubs --- */
static L2CfgL1 bricks[4][16];   /* [rack][slot]; type 0: none */
static int local_l2;            /* whether the first destination is this L2 */

L2CfgL1 *L2CfgMFindBrickCfg(L2Cfg *head, int rack, int slot, int local)
{
  if (rack >= 4 || slot >= 16 || bricks[rack][slot].type == 0)
    return NULL;
  return &bricks[rack][slot];
}

L2CfgNode *L2CfgMFindNode(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  note("find node %08x\n",ip_addr);
  return local_l2 ? &L2CfgLocal.net : NULL;
}

int l2cmd_process(L2CMD *c, char *command, char **rptr, void *data)
{
  note("process '%s'\n",command);
  return 5;
}

IRPacket *IRouterMakePacket(IRIdent *id, IRAddress *toaddr, int pdata, int opcode, int clas,
                            int prev, int argcount, IRArgument *arglist)
{
  IRPacket *p = calloc(1,sizeof(IRPacket) + sizeof(IRArgument));
  char *text = (char *)IR_VAL_PTR(arglist[1]._val);

  p->_dest = *toaddr;
  p->_seqnum0 = id->seqnum;
  p->_seqnum1 = id->seqnum >> 8;
  id->seqnum++;
  p->_client_data = (uint8 *)strdup(text);
  note("make %08x '%s' size %d class %d/%d argc %d opcode %d clas %d prev %d\n",*toaddr,text,
       arglist[1]._size,arglist[0]._clas,arglist[1]._clas,argcount,opcode,clas,prev);
  if (arglist[1]._clas & IR_ARG_FREE)
    free(text);
  return p;
}

int IRouterSendPacket(IRIdent *id, IRPacket *pkt)
{
  note("send %08x '%s'\n",pkt->_dest,(char *)pkt->_client_data);
  return IRouterFreePacket(pkt);
}

int IRouterFreePacket(IRPacket *pkt)
{
  free(pkt->_client_data);
  free(pkt);
  return 0;
}

#if UINTPTR_MAX != 0xffffffffu
/* (IRouter.c's 64-bit handles for pointers in argument values) */
static const void *handles[64];
static unsigned int nhandles;

uint32 IRPtrToVal(const void *p)
{
  handles[nhandles % 64] = p;
  return nhandles++ % 64;
}

void *IRValToPtr(uint32 v)
{
  return (void *)handles[v % 64];
}
#endif

uintptr_t IRArg(IRPacket *pkt, int arg)
{
  return 0;
}

EventID EventAddTimeOut(long unsigned int seconds, long unsigned int microseconds,
                        void (*timer_func)(), EventData client_data, char *desc)
{
  note("timer %lu\n",seconds);
  return 1;
}

void EventRemoveTimeOut(EventID id)
{
  note("remove timer\n");
}

int usleep(useconds_t usec)
{
  note("usleep %u\n",(unsigned int)usec);
  return 0;
}

/* --- the test --- */
static const char types[] = "-DR#&=EGINPVXYC3$,.0456789@ABFLMOQ{}Z!a";

static void dump(L2CMD *c)
{
  REQQ *r;
  RSPQ *s;

  for (r = c->q->reqq_head; r != NULL; r = r->next)
    if (r->pkt == NULL)
      note("  marker %d %d\n",r->response,r->delay);
    else
      note("  req %08x '%s' %d %d\n",r->pkt->_dest,(char *)r->pkt->_client_data,r->response,
           r->delay);
  for (s = c->q->rspq_head; s != NULL; s = s->next)
    note("  rsp %u %08x\n",s->seqn,s->dest);
  note("  busy %d pending %d\n",c->busy,c->q->rspq_pending);
}

int main(void)
{
  static DEST dest;
  static IRIdent ido, idn;
  static const int flags[] = { 0, 0, BCAST_POWER_OFF, BCAST_POWER_ON };
  static const int classes[] = { 1, 2, 4, 0x80, 0xff, 0xff, 0x84, 3 };
  L2CMD co = { &ido }, cn = { &idn };
  int trial;

  IRByteOrder = htonl(1) == 1 ? 1 : 2;
  side = 0;
  co.q = reqrspq_init(NULL,NULL,NULL);
  side = 1;
  cn.q = reqrspq_init(NULL,NULL,NULL);
  co.dest = cn.dest = &dest;
  for (trial = 0; trial < 20000; trial++) {
    int slots[6], nslots = rnd(5), i, r, s;
    int method = 1 + rnd(2), response = rnd(4) != 0, delay = rnd(3) * 7, final = rnd(2);
    int type = classes[rnd(8)] | flags[rnd(4)];
    int l2 = rnd(5) == 0;
    int rets[2];
    int *sl;

    if (trial % 10 == 0)
      for (r = 0; r < 4; r++)
        for (s = 0; s < 16; s++) {
          bricks[r][s].type = rnd(3) ? types[rnd(sizeof(types) - 1)] : 0;
          bricks[r][s].power_state = rnd(2);
        }
    dest.count = rnd(12);
    for (i = 0; i < dest.count; i++)
      dest.list[i] = l2 ? 0x80000000 | rnd(0x1000000)
                        : rnd(8) == 0 ? seed : IR_ADDR_MAKE(IR_ADDR_L1,rnd(5),rnd(17),0,0);
    for (i = 0; i < nslots; i++)
      slots[i] = rnd(17);
    slots[nslots] = -1;
    local_l2 = rnd(2);
    sl = rnd(3) == 0 ? slots : NULL;
    for (side = 0; side < 2; side++) {
      L2CMD *c = side == 0 ? &co : &cn;
      c->busy = 0;
      if (l2)
        rets[side] = side == 0 ? Origbroadcast_l2(c,NULL,"cmd x",response,delay,final)
                               : broadcast_l2(c,NULL,"cmd x",response,delay,final);
      else
        rets[side] = side == 0 ? Origbroadcast_l1(c,method,"cmd y",response,delay,type,sl,final)
                               : broadcast_l1(c,method,"cmd y",response,delay,type,sl,final);
      dump(c);
      /* the responses arrive: send the rest */
      for (i = 0; i < 50 && !reqq_empty(c->q); i++) {
        c->q->rspq_pending = 0;
        note("broadcast %d\n",side == 0 ? Origbroadcast(c->q,c->id) : broadcast(c->q,c->id));
      }
      reqrspq_reset(c->q);
    }
    if (rets[0] != rets[1] || strcmp(log_[0],log_[1]) != 0) {
      printf("FAIL  broadcast: trial %d (%s method %d type %x)\n--- orig\n%s--- new\n%s",trial,
             l2 ? "l2" : "l1",method,type,log_[0],log_[1]);
      return 1;
    }
    log_[0][0] = log_[1][0] = '\0';
  }
  printf("PASS  broadcast: %d broadcasts compared with the original\n",trial);
  return 0;
}
