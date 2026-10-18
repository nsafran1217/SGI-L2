/*
 * sys_ctrl/l3/l2/lpbk.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/lpbk.c
 */

struct timeval;

#include "irtr.h"   /* needed by the reconstruction */
#include "../main/nvram.h"   /* needed by the reconstruction */
#include <malloc.h>
#include <stddef.h>
#include <time.h>
#include "l2.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
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
#include "../../common/IRouter/IRouter2Router.h"
#include "../../common/Router/Router.h"
#include "../../common/sys/PPP.h"
#include "../../common/sys/brick_types.h"
#include "../../common/main/EnetServer.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/main/L1Cfg.h"
#include "l2_rev.h"
#include "lpbk.h"
#include "smp.h"
#include "l2cmd.h"
#include "reqrspq.h"
#include "dest.h"
#include "../../common/sys/Cmd.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */
typedef struct {
    int pending;
    unsigned char *bptr;
    int blen;
    int bcount;
    IRAddress l1addr;
    SMP *smp;
    struct timeval start_time;
    struct timeval pkt_start_time;
    float pkt_min_time;
    float pkt_max_time;
} LpbkSession;

static void lpbk_process_request(int session);

LpbkSession Lpbk[16];

void lpbk(int session, IRAddress addr, int length, int count, SMP *smp)
{
  uchar *puVar1;
  int iVar2;
  IRAddress IVar3;
  int n;
  
  if (((Lpbk[session].pending == 0) && (0 < length)) && (0 < count)) {
    Lpbk[session].pending = count;
    Lpbk[session].bcount = count;
    Lpbk[session].blen = length;
    if ((addr & 0x80000000) == 0) {
      IVar3 = addr & 0xffffffe0 | 0x12;
    }
    else {
      IVar3 = addr & 0xc0ffffff | 0x12000000;
    }
    Lpbk[session].l1addr = IVar3;
    Lpbk[session].smp = smp;
    Lpbk[session].pkt_min_time = 1e+06;
    Lpbk[session].pkt_max_time = 0.0;
    smp->grp->lpbk_pending = 1;
    puVar1 = malloc(length);
    Lpbk[session].bptr = puVar1;
    for (n = 0; n < length; n = n + 1) {
      iVar2 = rand();
      Lpbk[session].bptr[n] = (uchar)iVar2;
    }
    gettimeofday((struct timeval *)&Lpbk[session].start_time,NULL);
    lpbk_process_request(session);
  }
  return;
}

static void lpbk_process_request(int session)
{
  IRPacket *p;
  IRArgument argv [2];
  IRAddress l1addr;
  
  l1addr = Lpbk[session].l1addr;
  argv[0]._clas = '\0';
  argv[0]._frame = '\0';
  argv[0]._val = session;
  argv[0]._size = 0;
  argv[1]._clas = '\x01';
  argv[1]._frame = '\0';
  argv[1]._val = (uint32)Lpbk[session].bptr;
  argv[1]._size = (uint16)Lpbk[session].blen;
  p = IRouterMakePacket(&l2_lpbk_id,&l1addr,0,0,0,2,2,argv);
  gettimeofday((struct timeval *)&Lpbk[session].pkt_start_time,NULL);
  IRouterSendPacket(NULL,p);
  return;
}

void lpbk_process_response(IRPacket *p)
{
  float fVar1;
  uint session;
  uchar *arg;
  int iVar2;
  size_t sVar3;
  struct timeval tdiff;
  struct timeval end_time;
  char buff [400];
  float elapsed_time;
  
  if ((p->_argv[0]._clas & 7) != 0) {
    IRArg(p,0);
  }
  if ((p->_argv[1]._clas & 7) != 0) {
    IRArg(p,1);
  }
  buff[0] = '\0';
  if (p->_argc == '\x02') {
    if ((p->_argv[0]._clas & 7) == 0) {
      session = p->_argv[0]._val;
    }
    else {
      session = IRArg(p,0);
    }
    if ((p->_argv[1]._clas & 7) == 0) {
      arg = (uchar *)p->_argv[1]._val;
    }
    else {
      arg = (uchar *)IRArg(p,1);
    }
    iVar2 = memcmp(arg,Lpbk[session].bptr,Lpbk[session].blen);
    if (iVar2 != 0) {
      sprintf(buff,"packet %d loopback miscompare\n",Lpbk[session].pending);   /* Ghidra dropped the argument */
      sVar3 = strlen(buff);
      smp_output(Lpbk[session].smp,buff,sVar3);
    }
    IRouterFreePacket(p);
    gettimeofday((struct timeval *)&end_time,NULL);
    tdiff.tv_sec = end_time.tv_sec - Lpbk[session].pkt_start_time.tv_sec;
    tdiff.tv_usec = end_time.tv_usec - Lpbk[session].pkt_start_time.tv_usec;
    if (tdiff.tv_usec < 0) {
      tdiff.tv_sec = tdiff.tv_sec + -1;
      tdiff.tv_usec = tdiff.tv_usec + 1000000;
    }
    elapsed_time = (float)tdiff.tv_usec / 1e+06 + (float)tdiff.tv_sec;
    if (elapsed_time < Lpbk[session].pkt_min_time) {
      Lpbk[session].pkt_min_time = elapsed_time;
    }
    if (Lpbk[session].pkt_max_time < elapsed_time) {   /* Ghidra: x87 C0/C2/C3 flag test */
      Lpbk[session].pkt_max_time = elapsed_time;
    }
    Lpbk[session].pending = Lpbk[session].pending + -1;
    if (Lpbk[session].pending == 0) {
      tdiff.tv_sec = end_time.tv_sec - Lpbk[session].start_time.tv_sec;
      tdiff.tv_usec = end_time.tv_usec - Lpbk[session].start_time.tv_usec;
      if (tdiff.tv_usec < 0) {
        tdiff.tv_sec = tdiff.tv_sec + -1;
        tdiff.tv_usec = tdiff.tv_usec + 1000000;
      }
      fVar1 = (float)tdiff.tv_usec / 1e+06 + (float)tdiff.tv_sec;
      (Lpbk[session].smp)->grp->lpbk_pending = 0;
      sprintf(buff,
              "loopback %d completed:\n  packets %10d\n  size    %10d bytes\n  total   %10d bytes\n  time    %10.3f seconds\n  average %10.2f bytes/second\n          %10.6f seconds/packet\n  min pkt %10.6f seconds\n  max pkt %10.6f seconds\n"
              ,session,Lpbk[session].bcount,Lpbk[session].blen,
              Lpbk[session].bcount * Lpbk[session].blen,(double)fVar1,
              (double)(((float)Lpbk[session].blen * (float)Lpbk[session].bcount) / fVar1),
              (double)(fVar1 / (float)Lpbk[session].bcount),(double)Lpbk[session].pkt_min_time,
              (double)Lpbk[session].pkt_max_time);
      sVar3 = strlen(buff);
      smp_output(Lpbk[session].smp,buff,sVar3);
      free(Lpbk[session].bptr);
      Lpbk[session].bptr = NULL;
      smp_prompt(Lpbk[session].smp);
    }
    else {
      lpbk_process_request(session);
    }
  }
  else {
    sprintf(buff,"loopback packet no return data, source %08x\n");
    nvramLogInsert(buff);
  }
  return;
}
