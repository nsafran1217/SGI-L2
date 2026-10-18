/*
 * sys_ctrl/l3/l2/lpbk.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/lpbk.c
 *
 * The console's "loopback" command: sends count packets of length random
 * bytes, one at a time, to an L1's loopback task, checks each echo, and
 * reports the timing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "l2.h"
#include "lpbk.h"
#include "smp.h"
#include "irtr.h"
#include "../main/nvram.h"

#define LPBK_SESSIONS   16

typedef struct {
    int pending;                /* packets still to come back */
    unsigned char *bptr;        /* the data sent */
    int blen;
    int bcount;                 /* packets in all */
    IRAddress l1addr;
    SMP *smp;                   /* the console that asked */
    struct timeval start_time;
    struct timeval pkt_start_time;
    float pkt_min_time;
    float pkt_max_time;
} LpbkSession;

static void lpbk_process_request(int session);

LpbkSession Lpbk[LPBK_SESSIONS];

/* start a loopback session to the L1 at addr, unless it is already running */
void lpbk(int session, IRAddress addr, int length, int count, SMP *smp)
{
  LpbkSession *l;
  int n;

  /* (the original indexed Lpbk[] with any session number) */
  if (session < 0 || session >= LPBK_SESSIONS)
    return;
  l = &Lpbk[session];
  if (l->pending != 0 || length <= 0 || count <= 0)
    return;
  l->pending = count;
  l->bcount = count;
  l->blen = length;
  l->l1addr = IR_ADDR_WITH_TASK(addr,IR_L1_LPBK);
  l->smp = smp;
  l->pkt_min_time = 1e+06;
  l->pkt_max_time = 0.0;
  smp->grp->lpbk_pending = 1;
  l->bptr = malloc(length);
  for (n = 0; n < length; n++)
    l->bptr[n] = rand();
  gettimeofday(&l->start_time,NULL);
  lpbk_process_request(session);
}

/* send the session's next packet: its number and the data */
static void lpbk_process_request(int session)
{
  IRArgument argv[2];
  IRAddress l1addr = Lpbk[session].l1addr;
  IRPacket *p;

  argv[0]._clas = IR_ARG_VALUE;
  argv[0]._frame = 0;
  argv[0]._val = session;
  argv[0]._size = 0;
  argv[1]._clas = IR_ARG_BYTES;
  argv[1]._frame = 0;
  argv[1]._val = IR_PTR_VAL(Lpbk[session].bptr);
  argv[1]._size = Lpbk[session].blen;
  p = IRouterMakePacket(&l2_lpbk_id,&l1addr,0,0,IR_REQ,2,2,argv);
  gettimeofday(&Lpbk[session].pkt_start_time,NULL);
  IRouterSendPacket(NULL,p);
}

/* end - start in seconds */
static float seconds_since(const struct timeval *start, const struct timeval *end)
{
  struct timeval tdiff;

  tdiff.tv_sec = end->tv_sec - start->tv_sec;
  tdiff.tv_usec = end->tv_usec - start->tv_usec;
  if (tdiff.tv_usec < 0) {
    tdiff.tv_sec--;
    tdiff.tv_usec += 1000000;
  }
  return (float)tdiff.tv_usec / 1e+06 + (float)tdiff.tv_sec;
}

/* an L1's echo: check it, then send the next packet or report */
void lpbk_process_response(IRPacket *p)
{
  char buff[400];
  struct timeval end_time;
  float elapsed_time;
  float total;
  LpbkSession *l;
  unsigned char *data;
  uintptr_t session;

  if (p->_argc != 2) {
    sprintf(buff,"loopback packet no return data, source %08x\n",p->_src);
    nvramLogInsert(buff);
    IRouterFreePacket(p);       /* (the original leaked it) */
    return;
  }
  session = IRArg(p,0);
  /* (the original took any session number, and went on with sessions that
   * had finished, or whose console had gone) */
  if (IR_ARG_TYPE(p->_argv[0]) != IR_ARG_VALUE || session >= LPBK_SESSIONS ||
      Lpbk[session].pending == 0) {
    IRouterFreePacket(p);
    return;
  }
  l = &Lpbk[session];
  if (!smp_is_valid(l->smp)) {
    l->pending = 0;
    free(l->bptr);
    l->bptr = NULL;
    IRouterFreePacket(p);
    return;
  }
  data = IR_ARG_TYPE(p->_argv[1]) == IR_ARG_VALUE ? NULL : (unsigned char *)IRArg(p,1);
  /* (the original compared blen bytes whatever came back) */
  if (data == NULL || p->_argv[1]._size < l->blen || memcmp(data,l->bptr,l->blen) != 0) {
    sprintf(buff,"packet %d loopback miscompare\n",l->pending);
    smp_output(l->smp,buff,strlen(buff));
  }
  IRouterFreePacket(p);
  gettimeofday(&end_time,NULL);
  elapsed_time = seconds_since(&l->pkt_start_time,&end_time);
  if (elapsed_time < l->pkt_min_time)
    l->pkt_min_time = elapsed_time;
  if (l->pkt_max_time < elapsed_time)
    l->pkt_max_time = elapsed_time;
  if (--l->pending != 0) {
    lpbk_process_request(session);
    return;
  }
  total = seconds_since(&l->start_time,&end_time);
  l->smp->grp->lpbk_pending = 0;
  sprintf(buff,
          "loopback %d completed:\n"
          "  packets %10d\n"
          "  size    %10d bytes\n"
          "  total   %10d bytes\n"
          "  time    %10.3f seconds\n"
          "  average %10.2f bytes/second\n"
          "          %10.6f seconds/packet\n"
          "  min pkt %10.6f seconds\n"
          "  max pkt %10.6f seconds\n",
          (int)session,l->bcount,l->blen,l->bcount * l->blen,total,
          ((float)l->blen * (float)l->bcount) / total,total / (float)l->bcount,
          l->pkt_min_time,l->pkt_max_time);
  smp_output(l->smp,buff,strlen(buff));
  free(l->bptr);
  l->bptr = NULL;
  smp_prompt(l->smp);
}
