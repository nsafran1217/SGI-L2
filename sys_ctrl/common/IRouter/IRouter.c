/*
 * sys_ctrl/common/IRouter/IRouter.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/IRouter/IRouter.c
 */

#include "../../l3/l2/dest.h"   /* needed by the reconstruction */
#include "../../l3/l2/smp.h"   /* needed by the reconstruction */
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <stdarg.h>
#include "../sys/sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sys/time.h>
#include "IRouter.h"
#include "IRouterInt.h"
#include "../sys/syslog.h"
#include "../sys/pmalloc.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static IRFrame *IRouterCreateFrame(int size, int min, int max, int *act, IRFrame *firstframe, IRFrame *currframe);
static int IRouterCreatePacket(IRPacket **rpkt, int clas, int eframe, int pdata, int authority, int opcode, int errcode, int seqnum, IRAddress *dest, IRAddress *src, int argcount, IRArgument *arglist, void *client_data, int qsuspend);

int IR_PORT_BIAS;
int IRByteOrder;
int IRouterDebugMallocFree;
int IRouterDebugFrameErrors;
int IRouterPackets;
int IRouterTotalPackets;
int IRouterOutstandingPackets;
int IRouterMaxPackets;
IRPacket *IRouterTracePacket;
static int req_rsp_suspend_time = 300;
static int evt_suspend_time = 1000;
IRLocalClient IRouterLocalRequest[15];
IRRemoteClient *IRouterRequestList;
IRLocalClient IRouterRequestDefault;
IREventClient *IRouterEventList;
IRAddress IRouterLocalAddress;
IRIdent IRouterInternalID;

static IRFrame *IRouterCreateFrame(int size, int min, int max, int *act, IRFrame *firstframe, IRFrame *currframe)
{
  struct _IRFrame *p_Var1;
  IRFrame *__s;
  IRFrame *lastframe;
  int max_frame_size;
  IRFrame *nextframe;
  
  *act = size;
  if (min < size) {
    if (size < max) {
      max = size;
    }
    *act = max;
    size = max;
  }
  __s = malloc(size + 0x10);
  if (__s == NULL) {
    while (firstframe != NULL) {
      p_Var1 = firstframe->_next_frame;
      free(firstframe);
      firstframe = p_Var1;
    }
    __s = NULL;
  }
  else {
    memset(__s,0,size + 0x10);
    __s->_rev = '\x02';
    if (firstframe != NULL) {
      memcpy(&__s->_size,&firstframe->_size,0x14);
    }
    if (currframe != NULL) {
      currframe->_next_frame = __s;
    }
  }
  return __s;
}

static int IRouterCreatePacket(IRPacket **rpkt, int clas, int eframe, int pdata, int authority, int opcode, int errcode, int seqnum, IRAddress *dest, IRAddress *src, int argcount, IRArgument *arglist, void *client_data, int qsuspend)
{
  IRFrame *__ptr;
  int iVar1;
  byte bVar2;
  IRFrame *nextframe;
  int argoffset;
  int fragsize;
  int pktpayload;
  int arg;
  uchar *dataptr;
  int framenum;
  int curframesize;
  int actframesize;
  int maxframesize;
  int minframesize;
  int pktsize;
  IRFrame *lastframe;
  IRFrame *currframe;
  IRFrame *firstframe;
  int rval;
  bool fragcount;
  
  framenum = 1;
  if ((argcount == 0) || (arglist != NULL)) {
    pktsize = argcount * 8 + 0x14;
    for (arg = 0; arg < argcount; arg = arg + 1) {
      if ((arglist[arg]._clas & 7) != 0) {
        pktsize = pktsize + (uint)arglist[arg]._size;
      }
    }
    minframesize = 0x400;
    if (eframe == 0) {
      maxframesize = 0x400;
    }
    else {
      maxframesize = 0x3000;
      if ((0x7f < (uint)pktsize / 0x2fec) && (maxframesize = 0x3400, 0x7f < (uint)pktsize / 0x33ec))
      {
        errcode._0_1_ = '\x1b';
        pktsize = 0x14;
        for (arg = 0; arg < argcount; arg = arg + 1) {
          if ((arglist[arg]._clas & 8) != 0) {
            free((void *)arglist[arg]._val);
          }
        }
        argcount = 0;
      }
    }
    firstframe = IRouterCreateFrame(pktsize,minframesize,maxframesize,&actframesize,NULL,
                                    NULL);
    if (firstframe == NULL) {
      iVar1 = -0x25c;
    }
    else {
      firstframe->_next_frame = NULL;
      firstframe->_byte_order = IRByteOrder;
      firstframe->_seqnum0 = (uint8)seqnum;
      firstframe->_seqnum1 = (uint8)((uint)seqnum >> 8);
      firstframe->_clas = (uint8)clas;
      firstframe->_pdata_auth = firstframe->_pdata_auth & 7 | (char)pdata << 3;
      firstframe->_pdata_auth = firstframe->_pdata_auth & 0xf8 | (byte)authority & 7;
      if (dest != NULL) {
        memcpy(&firstframe->_dest,dest,4);
      }
      if (src != NULL) {
        memcpy(&firstframe->_src,src,4);
      }
      firstframe->_opcode = (uint16)opcode;
      firstframe->_err = (uint8)errcode;
      firstframe->_client_data = client_data;
      firstframe->_qsuspend = qsuspend;
      memcpy(firstframe->_argv,arglist,argcount * 8);
      curframesize = argcount * 8 + 0x14;
      pktsize = pktsize + -0x14 + argcount * -8;
      firstframe->_size = (uint16)curframesize;
      lastframe = firstframe;
      currframe = firstframe;
      dataptr = &firstframe->_argv[argcount]._clas;
      for (arg = 0; (pktsize != 0 && (arg < argcount)); arg = arg + 1) {
        pktpayload = (int)arglist[arg]._size;
        if ((arglist[arg]._clas & 7) != 0) {
          if ((uint)actframesize < pktpayload + 0x14U) {
            fragcount = false;
            argoffset = 0;
            do {
              if ((uint)actframesize < pktpayload + 0x14U) {
                fragsize = actframesize - curframesize;
              }
              else {
                fragsize = pktpayload;
              }
              memcpy(dataptr,(void *)(argoffset + arglist[arg]._val),fragsize);
              if (!fragcount) {
                firstframe->_argv[arg]._frame = (byte)framenum;
                firstframe->_argv[arg]._val = (int)dataptr - (int)currframe;
                fragcount = true;
              }
              argoffset = argoffset + fragsize;
              dataptr = dataptr + fragsize;
              curframesize = curframesize + fragsize;
              currframe->_size = (uint16)curframesize;
              pktpayload = pktpayload - fragsize;
              pktsize = pktsize - fragsize;
              if (pktpayload != 0) {
                currframe = IRouterCreateFrame(pktsize + 0x14,minframesize,maxframesize,
                                               &actframesize,firstframe,currframe);
                if (currframe == NULL) {
                  return -0x25c;
                }
                framenum = framenum + 1;
                curframesize = 0x14;
                dataptr = &currframe->_argv[0]._clas;
              }
            } while (pktpayload != 0);
            if ((arglist[arg]._clas & 8) != 0) {
              free((void *)arglist[arg]._val);
            }
          }
          else {
            if (actframesize < curframesize + pktpayload) {
              currframe = IRouterCreateFrame(pktsize + 0x14,minframesize,maxframesize,&actframesize,
                                             firstframe,currframe);
              if (currframe == NULL) {
                return -0x25c;
              }
              framenum = framenum + 1;
              curframesize = 0x14;
              dataptr = &currframe->_argv[0]._clas;
            }
            memcpy(dataptr,(void *)arglist[arg]._val,pktpayload);
            if ((arglist[arg]._clas & 8) != 0) {
              free((void *)arglist[arg]._val);
            }
            firstframe->_argv[arg]._frame = (byte)framenum;
            firstframe->_argv[arg]._val = (int)dataptr - (int)currframe;
            dataptr = dataptr + pktpayload;
            curframesize = curframesize + pktpayload;
            currframe->_size = (uint16)curframesize;
            pktsize = pktsize - pktpayload;
          }
        }
      }
      firstframe->_fnum = firstframe->_fnum & 0x7f | 0x80;
      firstframe->_argc = (uint8)argcount;
      if (framenum < 0x80) {
        currframe = firstframe;
        do {
          currframe->_fnum = (byte)framenum | currframe->_fnum & 0x80;
          currframe = currframe->_next_frame;
          framenum = framenum + -1;
        } while (framenum != 0);
        firstframe->_use_count = 1;
        *rpkt = firstframe;
        if (IRouterDebugMallocFree != 0) {
          fprintf((FILE *)stderr,"CREATE %x\n",*rpkt);
          fflush(stderr);
        }
        iVar1 = 0;
      }
      else {
        while (__ptr = firstframe, firstframe != NULL) {
          lastframe = firstframe;
          firstframe = firstframe->_next_frame;
          free(__ptr);
        }
        iVar1 = -0x272;
      }
    }
  }
  else {
    iVar1 = -0x25f;
  }
  return iVar1;
}

int IRouterInit(uint32 ip)
{
  uint32_t uVar1;
  int status;
  
  if (true) {
    IRByteOrder = 2;
  }
  else {
    IRByteOrder = 1;
  }
  IRouterLocalAddress = 0x80000000;
  if (IRByteOrder == 1) {
    IRouterLocalAddress = ip & 0xffffff | 0x80000000;
  }
  else {
    uVar1 = ntohl(ip);
    IRouterLocalAddress = IRouterLocalAddress & 0xff000000 | uVar1 & 0xffffff;
  }
  IRouterInitID(&IRouterInternalID,1,3);
  return 0;
}

int IRouterInitID(IRIdent *id, uint32 task, int authority)
{
  id->addr = IRouterLocalAddress;
  id->addr = id->addr & 0xc0ffffff | (task & 0x3f) << 0x18;
  id->authority = (uint8)authority;
  id->seqnum = 0;
  return 0;
}

int IRouterSetAuthority(IRIdent *id, int authority)
{
  id->authority = (uint8)authority;
  return 0;
}

int IRouterFreePacket(IRPacket *pkt)
{
  struct _IRFrame *p_Var1;
  ushort uVar2;
  int arg;
  IRFrame *currframe;
  IRFrame *lastframe;
  
  if (IRouterDebugMallocFree != 0) {
    fprintf((FILE *)stderr,"FREE   %x %d\n",pkt,pkt->_use_count - 1);
    fflush(stderr);
  }
  if (pkt->_use_count == 0) {
    printf("packet free error, class: %d, src: %08x\n",(uint)pkt->_clas,pkt->_src);
  }
  else {
    if (--pkt->_use_count == 0) {
      if (pkt->_arg_data != NULL) {
        for (arg = 0; arg < (int)(uint)pkt->_argc; arg = arg + 1) {
          if (pkt->_arg_data[arg] != NULL) {
            free(pkt->_arg_data[arg]);
          }
        }
        free(pkt->_arg_data);
      }
      currframe = pkt;
      while (currframe != NULL) {
        p_Var1 = currframe->_next_frame;
        free(currframe);
        currframe = p_Var1;
      }
    }
  }
  return 0;
}

void IRouterSetQueueSuspendTime(int req_rsp_time, int evt_time)
{
  req_rsp_suspend_time = req_rsp_time;
  evt_suspend_time = evt_time;
  return;
}

void IRouterGetQueueSuspendTime(int *req_rsp_time, int *evt_time)
{
  *req_rsp_time = req_rsp_suspend_time;
  *evt_time = evt_suspend_time;
  return;
}

IRPacket *IRouterMakePacket(IRIdent *id, IRAddress *toaddr, int pdata, int opcode, int clas, int prev, int argcount, IRArgument *arglist)
{
  ushort uVar1;
  uint uVar2;
  int iVar3;
  int eframe;
  IRPacket *pkt;
  
  eframe = 0;
  if (((toaddr != NULL) && (clas == 1)) && (1 < prev)) {
    if ((*toaddr & 0x80000000) == 0) {
      uVar2 = *toaddr >> 0x1c;
    }
    else if (*toaddr >> 0x1e == 2) {
      uVar2 = 0xe;
    }
    else {
      uVar2 = 0xf;
    }
    if ((uVar2 != 0) && ((uVar2 < 3 || ((uVar2 < 0x10 && (0xd < uVar2)))))) {
      if ((id->addr & 0x80000000) == 0) {
        uVar2 = id->addr >> 0x1c;
      }
      else if (id->addr >> 0x1e == 2) {
        uVar2 = 0xe;
      }
      else {
        uVar2 = 0xf;
      }
      if ((uVar2 != 0) && ((uVar2 < 3 || ((uVar2 < 0x10 && (0xd < uVar2)))))) {
        eframe = 1;
      }
    }
  }
  uVar1 = id->seqnum;
  id->seqnum = id->seqnum + 1;
  iVar3 = IRouterCreatePacket(&pkt,clas,eframe,pdata,(uint)id->authority,opcode,0,(uint)uVar1,toaddr
                              ,&id->addr,argcount,arglist,NULL,0);
  if (iVar3 != 0) {
    pkt = NULL;
  }
  return pkt;
}

int IRouterReadPacket(IRIdent *id, int (*rfcn)(), void *fd, IRPacket **pkt)
{
  byte *pbVar1;
  IRFrame *pIVar2;
  int iVar3;
  int selerr;
  __fd_mask *p_Var4;
  char __result;
  int __d1;
  int __d0;
  int fdmax;
  struct timeval rtime;
  fd_set rdset;
  int rlen;
  int rsize;
  int next_expected_framenum;
  int arg;
  IRFrame *lastframe;
  IRFrame *currframe;
  IRFrame *firstframe;
  int32 status;
  
  firstframe = NULL;
  currframe = NULL;
  while( true ) {
    pIVar2 = currframe;
    if (firstframe != NULL) {
      rtime.tv_sec = 1;
      rtime.tv_usec = 0;
      status = 0;
      selerr = 0x20;
      p_Var4 = rdset.fds_bits;
      for (; selerr != 0; selerr = selerr + -1) {
        *p_Var4 = 0;
        p_Var4 = p_Var4 + 1;
      }
      pbVar1 = (byte *)((int)rdset.fds_bits + ((int)((uint)fd & 0x1f) >> 3) + ((uint)fd >> 5) * 4);
      *pbVar1 = *pbVar1 | '\x01' << ((uint)fd & 7);
      iVar3 = select((int)fd + 1,(fd_set *)&rdset,NULL,NULL,(struct timeval *)&rtime);
      if (iVar3 < 0) {
        status = -0x267;
      }
      if ((status == 0) &&
         ((*(byte *)((int)rdset.fds_bits + ((int)((uint)fd & 0x1f) >> 3) + ((uint)fd >> 5) * 4) >>
           ((uint)fd & 7) & 1) == 0)) {
        status = -0x268;
      }
      if (status != 0) {
        while (pIVar2 = firstframe, firstframe != NULL) {
          firstframe = firstframe->_next_frame;
          free(pIVar2);
        }
        return status;
      }
    }
    currframe = malloc(0x410);
    if (currframe == NULL) {
      currframe = NULL;
      while (pIVar2 = firstframe, firstframe != NULL) {
        firstframe = firstframe->_next_frame;
        free(pIVar2);
      }
      return -0x25c;
    }
    memset(currframe,0,0x2c);
    status = (*rfcn)(fd,&currframe,0x400);
    if (status < 1) break;
    IRouterSetFrameByteOrder(currframe,IRByteOrder);
    if (firstframe == NULL) {
      if (-1 < (char)currframe->_fnum) {
        free(currframe);
        return -0x265;
      }
      if (IRouterDebugMallocFree != 0) {
        fprintf((FILE *)stderr,"READ  %x\n",currframe);
        fflush(stderr);
      }
      firstframe = currframe;
    }
    else {
      if ((uint)(currframe->_fnum & 0x7f) != next_expected_framenum) {
        while (pIVar2 = firstframe, firstframe != NULL) {
          firstframe = firstframe->_next_frame;
          free(pIVar2);
        }
        free(currframe);
        return -0x266;
      }
      pIVar2->_next_frame = currframe;
    }
    currframe->_use_count = 0;
    currframe->_next_frame = NULL;
    next_expected_framenum = (currframe->_fnum & 0x7f) - 1;
    if (next_expected_framenum == 0) {
      firstframe->_use_count = 1;
      *pkt = firstframe;
      return 0;
    }
  }
  if (status == -0x25c) {
    __d1 = -0x25c;
  }
  else if (status == 0) {
    __d1 = -0x26d;
  }
  else {
    __d1 = -0x264;
  }
  if (firstframe != NULL) {
    __d0 = (int)firstframe->_next_frame;
    while (__d0 != 0) {
      iVar3 = *(int *)__d0;
      free((void *)__d0);
      __d0 = iVar3;
    }
    firstframe->_next_frame = NULL;
  }
  if (currframe != NULL) {
    free(currframe);
  }
  while (pIVar2 = firstframe, firstframe != NULL) {
    firstframe = firstframe->_next_frame;
    free(pIVar2);
  }
  return __d1;
}

int IRouterWritePacket(IRIdent *id, int (*wfcn)(), void *fd, IRPacket *pkt)
{
  int iVar1;
  
  iVar1 = IRouterWritePacketReliable(id,wfcn,fd,pkt,1);
  return iVar1;
}

int IRouterWritePacketReliable(IRIdent *id, int (*wfcn)(), void *fd, IRPacket *pkt, int foe)
{
  IRFrame *frame;
  int status;
  int wsize;
  IRFrame *sendframe;
  int border;
  IRFrame *p;
  
  p = pkt;
  while( true ) {
    if (p == NULL) {
      IRouterFreePacket(pkt);
      return 0;
    }
    wsize = (int)p->_size;
    frame = malloc(wsize + 0x10);
    if (frame == NULL) break;
    memcpy(frame,p,wsize + 0x10);
    IRouterSetFrameByteOrder(frame,1);
    status = (*wfcn)(fd,&frame->_size,wsize);
    if (status != wsize) {
      free(frame);
      if (foe != 0) {
        IRouterFreePacket(pkt);
      }
      if (status == 0) {
        return -0x26e;
      }
      return -0x269;
    }
    free(frame);
    p = p->_next_frame;
  }
  if (foe != 0) {
    IRouterFreePacket(pkt);
  }
  return -0x25c;
}

void IRouterSetFrameByteOrder(IRFrame *frame, int byteorder)
{
  uint16_t uVar1;
  uint32_t uVar2;
  int arg;
  
  if (frame->_byte_order != byteorder) {
    if (byteorder == 2) {
      uVar1 = ntohs(frame->_size);
      frame->_size = uVar1;
      uVar2 = ntohl(frame->_dest);
      frame->_dest = uVar2;
      uVar2 = ntohl(frame->_src);
      frame->_src = uVar2;
      uVar1 = ntohs(frame->_opcode);
      frame->_opcode = uVar1;
      for (arg = 0; arg < (int)(uint)frame->_argc; arg = arg + 1) {
        uVar1 = ntohs(frame->_argv[arg]._size);
        frame->_argv[arg]._size = uVar1;
        uVar2 = ntohl(frame->_argv[arg]._val);
        frame->_argv[arg]._val = uVar2;
      }
      frame->_byte_order = 2;
    }
    else {
      uVar1 = htons(frame->_size);
      frame->_size = uVar1;
      uVar2 = htonl(frame->_dest);
      frame->_dest = uVar2;
      uVar2 = htonl(frame->_src);
      frame->_src = uVar2;
      uVar1 = htons(frame->_opcode);
      frame->_opcode = uVar1;
      for (arg = 0; arg < (int)(uint)frame->_argc; arg = arg + 1) {
        uVar1 = htons(frame->_argv[arg]._size);
        frame->_argv[arg]._size = uVar1;
        uVar2 = htonl(frame->_argv[arg]._val);
        frame->_argv[arg]._val = uVar2;
      }
      frame->_byte_order = 1;
    }
  }
  return;
}

unsigned int IRArg(IRPacket *pkt, int arg)
{
  uint8 *puVar1;
  uint8 **ppuVar2;
  int argsize;
  uint fnum;
  uint dlen;
  uchar *dptr;
  uchar *bptr;
  IRFrame *fptr;
  
  if (arg < (int)(uint)pkt->_argc) {
    if ((pkt->_argv[arg]._clas & 7) == 0) {
      puVar1 = (uint8 *)pkt->_argv[arg]._val;
    }
    else {
      fnum = (uint)pkt->_argv[arg]._frame;
      fptr = pkt;
      while ((fptr != NULL && (fnum = fnum - 1, fnum != 0))) {
        fptr = fptr->_next_frame;
      }
      if (fptr == NULL) {
        puVar1 = NULL;
      }
      else {
        argsize = (int)pkt->_argv[arg]._size;
        puVar1 = (uint8 *)((int)fptr->_argv + (pkt->_argv[arg]._val - 0x24));
        if ((int)fptr + ((fptr->_size + 0x10) - (int)puVar1) < (uint)argsize) {
          if (pkt->_arg_data == NULL) {
            ppuVar2 = malloc((uint)pkt->_argc * 4);
            pkt->_arg_data = ppuVar2;
            if (ppuVar2 == NULL) {
              return 0;
            }
            memset(pkt->_arg_data,0,(uint)pkt->_argc * 4);
          }
          if (pkt->_arg_data[arg] == NULL) {
            puVar1 = malloc((uint)pkt->_argv[arg]._size);
            pkt->_arg_data[arg] = puVar1;
            if (puVar1 == NULL) {
              puVar1 = NULL;
            }
            else {
              bptr = pkt->_arg_data[arg];
              dptr = (uchar *)((int)fptr->_argv + (pkt->_argv[arg]._val - 0x24));
              dlen = (int)fptr + ((fptr->_size + 0x10) - (int)dptr);
              do {
                memcpy(bptr,dptr,dlen);
                bptr = bptr + dlen;
                argsize = argsize - dlen;
                if (argsize != 0) {
                  fptr = fptr->_next_frame;
                  dptr = &fptr->_argv[0]._clas;
                  dlen = argsize;
                  if (fptr->_size - 0x14 <= (uint)argsize) {
                    dlen = fptr->_size - 0x14;
                  }
                }
              } while (argsize != 0);
              puVar1 = pkt->_arg_data[arg];
            }
          }
          else {
            puVar1 = pkt->_arg_data[arg];
          }
        }
      }
    }
  }
  else {
    puVar1 = NULL;
  }
  return (uint)puVar1;
}

char *IRFmtClas(int clas)
{
  char *pcVar1;
  
  if (clas == 1) {
    pcVar1 = "RSP";
  }
  else {
    if (clas < 2) {
      if (clas == 0) {
        return "REQ";
      }
    }
    else if (clas == 2) {
      return "EVT";
    }
    pcVar1 = "???";
  }
  return pcVar1;
}

char *IRFmtAddr(IRAddress addr, char *bptr)
{
  int type;
  int num;
  int task;
  size_t sVar1;
  uint32_t uVar2;
  int slot;
  int rack;
  char *rptr;
  
  if ((addr & 0x80000000) == 0) {
    type = addr >> 0x1c;
  }
  else if (addr >> 0x1e == 2) {
    type = 0xe;
  }
  else {
    type = 0xf;
  }
  if ((addr & 0x80000000) == 0) {
    num = addr >> 5 & 0x7f;
  }
  else {
    num = -1;
  }
  if ((addr & 0x80000000) == 0) {
    task = addr & 0x1f;
  }
  else {
    task = addr >> 0x18 & 0x3f;
  }
  if (false) {
switchD_0807d0e6_caseD_7:
    sprintf(bptr,"%2d ",type);
  }
  else {
    switch(type) {
    case 0:
      strcpy(bptr,"L1 ");
      break;
    case 1:
      strcpy(bptr,"L2 ");
      break;
    case 2:
      strcpy(bptr,"L3 ");
      break;
    case 3:
      strcpy(bptr,"C  ");
      break;
    case 4:
      strcpy(bptr,"I  ");
      break;
    case 5:
      strcpy(bptr,"CI ");
      break;
    case 6:
      strcpy(bptr,"CC ");
      break;
    default:
      goto switchD_0807d0e6_caseD_7;
    case 0xe:
    case 0xf:
      if (IRByteOrder == 1) {
        uVar2 = addr & 0xffffff;
      }
      else {
        uVar2 = htonl(addr & 0xffffff);
      }
      sprintf(bptr,"IP %01x %02x %06x",type,addr >> 0x18 & 0x3f,uVar2);
      return bptr;
    }
  }
  sVar1 = strlen(bptr);
  sprintf(bptr + sVar1,"%4d.%2d,%2d,%3d ",addr >> 0x12 & 0x3ff,addr >> 0xc & 0x3f,num,task);
  strlen(bptr + sVar1);
  return bptr;
}

char *IRFmtPkt(char *who, IRPacket *p, char *bptr)
{
  char *pcVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  char buf2 [32];
  char buf1 [32];
  char *temp_7bf64f974a1;
  char *temp_7bfe26d060f;
  
  IRFmtAddr(p->_dest,buf1);
  IRFmtAddr(p->_src,buf2);
  temp_7bf64f974a1 = buf2;
  temp_7bfe26d060f = buf1;
  uVar2 = (uint)p->_opcode;
  uVar3 = (uint)p->_err;
  uVar4 = (uint)p->_argc;
  pcVar1 = IRFmtClas((uint)p->_clas);
  sprintf(bptr,"%-12.12s %5d %s(%d,%d,%d) D: %s S: %s",who,(uint)CONCAT11(p->_seqnum1,p->_seqnum0),
          pcVar1,uVar4,uVar3,uVar2,temp_7bfe26d060f,temp_7bf64f974a1);
  return bptr;
}

void IRPrintFrame(char *who, IRFrame *f)
{
  char buff [128];
  
  if (f == NULL) {
    fprintf(stderr,"WHO    ADDR     NEXT     SIZE RV ER S0 FF FN CL DEST     SRC      AC S1 OPCD\n")
    ;
    fprintf(stderr,"------ -------- -------- ---- -- -- -- -- -- -- -------- -------- -- -- ----\n")
    ;
  }
  else {
    fprintf(stderr,"%-6.6s %08x %08x %04x %02x %02x %02x %02x %02x %02x %08x %08x %02x %02x %04x\n",
            who,f,f->_next_frame,(uint)f->_size,(uint)f->_rev,(uint)f->_err,(uint)f->_seqnum0,
            (uint)(f->_fnum >> 7),(uint)(f->_fnum & 0x7f),(uint)f->_clas,f->_dest,f->_src,
            (uint)f->_argc,(uint)f->_seqnum1,(uint)f->_opcode);
  }
  return;
}

char *IRFmtError(int errcode)
{
  char *pcVar1;
  
  if (errcode == 0) {
    pcVar1 = "no error";
  }
  else {
    pcVar1 = LoggerDefaultMessage(-600 - errcode);
  }
  return pcVar1;
}
