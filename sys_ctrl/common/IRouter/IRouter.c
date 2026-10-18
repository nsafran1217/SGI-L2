/*
 * sys_ctrl/common/IRouter/IRouter.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/IRouter/IRouter.c
 *
 * IRouter packets: the messages between L1s, L2s and the L3 tools. A packet
 * is a chain of frames (IRFrame), each a 20-byte header (IR_FRAME_HDR) and up
 * to 1024 bytes in all. The first frame holds the arguments (8 bytes each);
 * data arguments point at bytes in some frame of the chain. In memory a frame
 * is in the host's byte order (_byte_order: 1 big-, 2 little-endian); on the
 * wire it is big-endian, from _size on.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include "IRouter.h"
#include "IRouterInt.h"

static IRFrame *IRouterCreateFrame(int size, int min, int max, int *act, IRFrame *firstframe, IRFrame *currframe);
static int IRouterCreatePacket(IRPacket **rpkt, int clas, int eframe, int pdata, int authority, int opcode, int errcode, int seqnum, IRAddress *dest, IRAddress *src, int argcount, IRArgument *arglist, void *client_data, int qsuspend);

int IR_PORT_BIAS;
int IRByteOrder;                /* this host's: 1 big-endian, 2 little-endian */
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

static void free_frames(IRFrame *frame)
{
  IRFrame *next;

  for (; frame != NULL; frame = next) {
    next = frame->_next_frame;
    free(frame);
  }
}

/*
 * A new, zeroed frame for size bytes: frames of up to min bytes are made to
 * fit, bigger ones are capped at max (*act gets the size made). Later frames
 * copy the first frame's header. On failure every frame from firstframe is
 * freed.
 */
static IRFrame *IRouterCreateFrame(int size, int min, int max, int *act, IRFrame *firstframe, IRFrame *currframe)
{
  IRFrame *frame;

  if (size > min && size > max)
    size = max;
  *act = size;
  frame = calloc(1,size + IR_FRAME_PREFIX);
  if (frame == NULL) {
    free_frames(firstframe);
    return NULL;
  }
  frame->_rev = 2;
  if (firstframe != NULL)
    memcpy(IR_FRAME_WIRE(frame),IR_FRAME_WIRE(firstframe),IR_FRAME_HDR);
  if (currframe != NULL)
    currframe->_next_frame = frame;
  return frame;
}

/*
 * Build a packet from its header fields and arguments. Data arguments
 * (_clas & 7) are copied in after the argument list, split across frames when
 * they do not fit; those marked _clas & 8 are freed. eframe allows extended
 * frames; a packet too big even for them goes out with no arguments and
 * IRERR_PKT_TOO_LARGE.
 */
static int IRouterCreatePacket(IRPacket **rpkt, int clas, int eframe, int pdata, int authority, int opcode, int errcode, int seqnum, IRAddress *dest, IRAddress *src, int argcount, IRArgument *arglist, void *client_data, int qsuspend)
{
  IRFrame *firstframe, *currframe;
  unsigned char *dataptr;
  int pktsize, payload, fragsize, offset;
  int minframesize, maxframesize, actframesize, curframesize;
  int framenum = 1;
  int arg, first_fragment;

  if (argcount != 0 && arglist == NULL)
    return IR_ERRNO(IRERR_BAD_ARGLIST_ARGCOUNT);

  pktsize = IR_FRAME_HDR + argcount * 8;
  for (arg = 0; arg < argcount; arg++)
    if (arglist[arg]._clas & 7)
      pktsize += arglist[arg]._size;
  minframesize = IR_FRAME_MAX;
  maxframesize = IR_FRAME_MAX;
  if (eframe) {
    /* at most 127 frames: try bigger frames, then give up on the arguments */
    maxframesize = 0x3000;
    if ((unsigned int)pktsize / (0x3000 - IR_FRAME_HDR) > 127) {
      maxframesize = 0x3400;
      if ((unsigned int)pktsize / (0x3400 - IR_FRAME_HDR) > 127) {
        errcode = IRERR_PKT_TOO_LARGE;
        pktsize = IR_FRAME_HDR;
        for (arg = 0; arg < argcount; arg++)
          if (arglist[arg]._clas & 8)
            free(IR_VAL_PTR(arglist[arg]._val));
        argcount = 0;
      }
    }
  }

  firstframe = IRouterCreateFrame(pktsize,minframesize,maxframesize,&actframesize,NULL,NULL);
  if (firstframe == NULL)
    return IR_ERRNO(IRERR_MALLOC_FAILED);
  firstframe->_next_frame = NULL;
  firstframe->_byte_order = IRByteOrder;
  firstframe->_seqnum0 = seqnum;
  firstframe->_seqnum1 = seqnum >> 8;
  firstframe->_clas = clas;
  firstframe->_pdata_auth = (pdata << 3) | (authority & 7);
  if (dest != NULL)
    firstframe->_dest = *dest;
  if (src != NULL)
    firstframe->_src = *src;
  firstframe->_opcode = opcode;
  firstframe->_err = errcode;
  firstframe->_client_data = client_data;
  firstframe->_qsuspend = qsuspend;
  memcpy(firstframe->_argv,arglist,argcount * 8);
  curframesize = IR_FRAME_HDR + argcount * 8;
  pktsize -= curframesize;                      /* the data still to place */
  firstframe->_size = curframesize;
  currframe = firstframe;
  dataptr = (unsigned char *)&firstframe->_argv[argcount];

  for (arg = 0; pktsize != 0 && arg < argcount; arg++) {
    if (!(arglist[arg]._clas & 7))
      continue;
    payload = arglist[arg]._size;
    if ((unsigned int)actframesize < payload + (unsigned int)IR_FRAME_HDR) {
      /* bigger than a frame: fill this frame, continue in new ones */
      first_fragment = 1;
      offset = 0;
      do {
        if ((unsigned int)actframesize < payload + (unsigned int)IR_FRAME_HDR)
          fragsize = actframesize - curframesize;
        else
          fragsize = payload;
        memcpy(dataptr,(unsigned char *)IR_VAL_PTR(arglist[arg]._val) + offset,fragsize);
        if (first_fragment) {
          firstframe->_argv[arg]._frame = framenum;
          firstframe->_argv[arg]._val = IR_DATA_OFFSET(currframe,dataptr);
          first_fragment = 0;
        }
        offset += fragsize;
        dataptr += fragsize;
        curframesize += fragsize;
        currframe->_size = curframesize;
        payload -= fragsize;
        pktsize -= fragsize;
        if (payload != 0) {
          currframe = IRouterCreateFrame(pktsize + IR_FRAME_HDR,minframesize,maxframesize,
                                         &actframesize,firstframe,currframe);
          if (currframe == NULL)
            return IR_ERRNO(IRERR_MALLOC_FAILED);
          framenum++;
          curframesize = IR_FRAME_HDR;
          dataptr = (unsigned char *)&currframe->_argv[0];
        }
      } while (payload != 0);
    }
    else {
      /* fits in a frame: this one, or a new one */
      if (actframesize < curframesize + payload) {
        currframe = IRouterCreateFrame(pktsize + IR_FRAME_HDR,minframesize,maxframesize,
                                       &actframesize,firstframe,currframe);
        if (currframe == NULL)
          return IR_ERRNO(IRERR_MALLOC_FAILED);
        framenum++;
        curframesize = IR_FRAME_HDR;
        dataptr = (unsigned char *)&currframe->_argv[0];
      }
      memcpy(dataptr,IR_VAL_PTR(arglist[arg]._val),payload);
      firstframe->_argv[arg]._frame = framenum;
      firstframe->_argv[arg]._val = IR_DATA_OFFSET(currframe,dataptr);
      dataptr += payload;
      curframesize += payload;
      currframe->_size = curframesize;
      pktsize -= payload;
    }
    if (arglist[arg]._clas & 8)
      free(IR_VAL_PTR(arglist[arg]._val));
  }

  firstframe->_argc = argcount;
  if (framenum >= IR_FNUM_FIRST) {
    free_frames(firstframe);
    return IR_ERRNO(IRERR_FRAME_CONTROL);
  }
  /* number the frames down to 1; the first is also marked first */
  for (currframe = firstframe; framenum != 0; currframe = currframe->_next_frame, framenum--)
    currframe->_fnum = framenum;
  firstframe->_fnum |= IR_FNUM_FIRST;
  firstframe->_use_count = 1;
  *rpkt = firstframe;
  if (IRouterDebugMallocFree) {
    fprintf(stderr,"CREATE %lx\n",(unsigned long)(uintptr_t)*rpkt);
    fflush(stderr);
  }
  return 0;
}

int IRouterInit(uint32 ip)
{
  IRByteOrder = htonl(1) == 1 ? 1 : 2;
  /* an IP-routed address: the top bit and the low 24 bits of ip */
  IRouterLocalAddress = 0x80000000 | (ntohl(ip) & 0xffffff);
  IRouterInitID(&IRouterInternalID,1,3);
  return 0;
}

/* an identity for one of this process's tasks (task in bits 24-29) */
int IRouterInitID(IRIdent *id, uint32 task, int authority)
{
  id->addr = (IRouterLocalAddress & 0xc0ffffff) | (task & 0x3f) << 24;
  id->authority = authority;
  id->seqnum = 0;
  return 0;
}

int IRouterSetAuthority(IRIdent *id, int authority)
{
  id->authority = authority;
  return 0;
}

/* drop a reference; the last one frees the frames and assembled arguments */
int IRouterFreePacket(IRPacket *pkt)
{
  int arg;

  if (IRouterDebugMallocFree) {
    fprintf(stderr,"FREE   %lx %d\n",(unsigned long)(uintptr_t)pkt,pkt->_use_count - 1);
    fflush(stderr);
  }
  if (pkt->_use_count == 0) {
    printf("packet free error, class: %d, src: %08x\n",pkt->_clas,pkt->_src);
    return 0;
  }
  if (--pkt->_use_count != 0)
    return 0;
  if (pkt->_arg_data != NULL) {
    for (arg = 0; arg < pkt->_argc; arg++)
      free(pkt->_arg_data[arg]);
    free(pkt->_arg_data);
  }
  free_frames(pkt);
  return 0;
}

void IRouterSetQueueSuspendTime(int req_rsp_time, int evt_time)
{
  req_rsp_suspend_time = req_rsp_time;
  evt_suspend_time = evt_time;
}

void IRouterGetQueueSuspendTime(int *req_rsp_time, int *evt_time)
{
  *req_rsp_time = req_rsp_suspend_time;
  *evt_time = evt_suspend_time;
}

/* L2s, L3s and IP-routed addresses may exchange extended frames */
static int extended_frames_ok(IRAddress addr)
{
  int type = IR_ADDR_TYPE(addr);

  return type == IR_ADDR_L2 || type == IR_ADDR_L3 || type == IR_ADDR_IP || type == IR_ADDR_IP_OTHER;
}

/* a packet from id (its next sequence number); NULL on failure. A response
 * (prev > 1) between L2/L3-type addresses may use extended frames. */
IRPacket *IRouterMakePacket(IRIdent *id, IRAddress *toaddr, int pdata, int opcode, int clas, int prev, int argcount, IRArgument *arglist)
{
  IRPacket *pkt;
  int eframe;

  eframe = toaddr != NULL && clas == IR_RSP && prev > 1 && extended_frames_ok(*toaddr) &&
           extended_frames_ok(id->addr);
  if (IRouterCreatePacket(&pkt,clas,eframe,pdata,id->authority,opcode,0,id->seqnum++,toaddr,
                          &id->addr,argcount,arglist,NULL,0) != 0)
    return NULL;
  return pkt;
}

/*
 * Read a packet, frame by frame, with rfcn(fd, &frame, 1024) (it reads one
 * wire frame into the frame, from _size on, and returns its length). After
 * the first frame each next one must arrive within a second.
 */
int IRouterReadPacket(IRIdent *id, int (*rfcn)(), void *fd, IRPacket **pkt)
{
  IRFrame *firstframe = NULL, *lastframe = NULL, *frame;
  struct timeval rtime;
  fd_set rdset;
  int status, expected = 0;
  int sock = (int)(intptr_t)fd;

  for (;;) {
    if (firstframe != NULL) {
      rtime.tv_sec = 1;
      rtime.tv_usec = 0;
      FD_ZERO(&rdset);
      FD_SET(sock, &rdset);
      status = 0;
      if (select(sock + 1,&rdset,NULL,NULL,&rtime) < 0)
        status = IR_ERRNO(IRERR_READ_FAILED_SELFAIL);
      else if (!FD_ISSET(sock, &rdset))
        status = IR_ERRNO(IRERR_READ_FAILED_TIMEOUT);
      if (status != 0) {
        free_frames(firstframe);
        return status;
      }
    }
    frame = malloc(IR_FRAME_MAX + IR_FRAME_PREFIX);
    if (frame == NULL) {
      free_frames(firstframe);
      return IR_ERRNO(IRERR_MALLOC_FAILED);
    }
    memset(frame,0,sizeof(IRFrame));
    status = rfcn(fd,&frame,IR_FRAME_MAX);
    if (status < 1)
      break;
    /* frames on the wire are big-endian; the original left the tag 0, which its
     * little-endian host's conversion took as "not mine", i.e. big-endian */
    frame->_byte_order = 1;
    IRouterSetFrameByteOrder(frame,IRByteOrder);
    if (firstframe == NULL) {
      if (!(frame->_fnum & IR_FNUM_FIRST)) {
        free(frame);
        return IR_ERRNO(IRERR_READ_FAILED_NOTFF);
      }
      if (IRouterDebugMallocFree) {
        fprintf(stderr,"READ  %lx\n",(unsigned long)(uintptr_t)frame);
        fflush(stderr);
      }
      firstframe = frame;
    }
    else {
      if ((frame->_fnum & 0x7f) != expected) {
        free_frames(firstframe);
        free(frame);
        return IR_ERRNO(IRERR_READ_FAILED_UNEXF);
      }
      lastframe->_next_frame = frame;
    }
    frame->_use_count = 0;
    frame->_next_frame = NULL;
    lastframe = frame;
    expected = (frame->_fnum & 0x7f) - 1;
    if (expected == 0) {
      firstframe->_use_count = 1;
      *pkt = firstframe;
      return 0;
    }
  }
  free(frame);
  free_frames(firstframe);
  if (status == IR_ERRNO(IRERR_MALLOC_FAILED))
    return status;
  if (status == 0)
    return IR_ERRNO(IRERR_READ_FAILED_EOF);
  return IR_ERRNO(IRERR_READ_FAILED_RDERR);
}

int IRouterWritePacket(IRIdent *id, int (*wfcn)(), void *fd, IRPacket *pkt)
{
  return IRouterWritePacketReliable(id,wfcn,fd,pkt,1);
}

/*
 * Write a packet, frame by frame, with wfcn(fd, wire bytes, length) (a
 * big-endian copy of each frame). The packet is freed when written, and on
 * failure if foe ("free on error").
 */
int IRouterWritePacketReliable(IRIdent *id, int (*wfcn)(), void *fd, IRPacket *pkt, int foe)
{
  IRFrame *p, *frame;
  int status, wsize;

  for (p = pkt; p != NULL; p = p->_next_frame) {
    wsize = p->_size;
    frame = malloc(wsize + IR_FRAME_PREFIX);
    if (frame == NULL) {
      if (foe)
        IRouterFreePacket(pkt);
      return IR_ERRNO(IRERR_MALLOC_FAILED);
    }
    memcpy(frame,p,wsize + IR_FRAME_PREFIX);
    IRouterSetFrameByteOrder(frame,1);
    status = wfcn(fd,IR_FRAME_WIRE(frame),wsize);
    free(frame);
    if (status != wsize) {
      if (foe)
        IRouterFreePacket(pkt);
      return status == 0 ? IR_ERRNO(IRERR_WRITE_FAILED_EOF) : IR_ERRNO(IRERR_WRITE_FAILED);
    }
  }
  IRouterFreePacket(pkt);
  return 0;
}

/* put a frame's header and argument words in byteorder (1 big-, 2 little-endian).
 * (The original swapped with ntohs/htonl, which only swap on a little-endian
 * host.) */
void IRouterSetFrameByteOrder(IRFrame *frame, int byteorder)
{
  int arg;

  if (frame->_byte_order == byteorder)
    return;
  frame->_size = __builtin_bswap16(frame->_size);
  frame->_dest = __builtin_bswap32(frame->_dest);
  frame->_src = __builtin_bswap32(frame->_src);
  frame->_opcode = __builtin_bswap16(frame->_opcode);
  for (arg = 0; arg < frame->_argc; arg++) {
    frame->_argv[arg]._size = __builtin_bswap16(frame->_argv[arg]._size);
    frame->_argv[arg]._val = __builtin_bswap32(frame->_argv[arg]._val);
  }
  frame->_byte_order = byteorder == 2 ? 2 : 1;
}

/*
 * An argument's value: inline values as they are, data arguments as a
 * pointer to their bytes (assembled into a copy, kept with the packet, when
 * they run across frames). 0 if there is no such argument.
 */
uintptr_t IRArg(IRPacket *pkt, int arg)
{
  IRArgument *a;
  IRFrame *fptr;
  unsigned char *data, *bptr, *dptr;
  unsigned int fnum, dlen;
  int argsize;

  if (arg >= pkt->_argc)
    return 0;
  a = &pkt->_argv[arg];
  if ((a->_clas & 7) == 0)
    return a->_val;
  for (fptr = pkt, fnum = a->_frame; fptr != NULL && --fnum != 0; )
    fptr = fptr->_next_frame;
  if (fptr == NULL)
    return 0;
  data = IR_DATA_PTR(fptr,a->_val);
  argsize = a->_size;
  if ((unsigned int)(IR_FRAME_WIRE(fptr) + fptr->_size - data) >= (unsigned int)argsize)
    return (uintptr_t)data;     /* all in this frame */

  if (pkt->_arg_data == NULL) {
    pkt->_arg_data = calloc(pkt->_argc,sizeof(uint8 *));
    if (pkt->_arg_data == NULL)
      return 0;
  }
  if (pkt->_arg_data[arg] != NULL)
    return (uintptr_t)pkt->_arg_data[arg];
  pkt->_arg_data[arg] = malloc(a->_size);
  if (pkt->_arg_data[arg] == NULL)
    return 0;
  bptr = pkt->_arg_data[arg];
  dptr = data;
  dlen = IR_FRAME_WIRE(fptr) + fptr->_size - data;
  for (;;) {
    memcpy(bptr,dptr,dlen);
    bptr += dlen;
    argsize -= dlen;
    if (argsize == 0)
      break;
    fptr = fptr->_next_frame;
    dptr = (unsigned char *)&fptr->_argv[0];
    dlen = argsize;
    if ((unsigned int)(fptr->_size - IR_FRAME_HDR) <= (unsigned int)argsize)
      dlen = fptr->_size - IR_FRAME_HDR;
  }
  return (uintptr_t)pkt->_arg_data[arg];
}

char *IRFmtClas(int clas)
{
  switch (clas) {
  case IR_REQ:
    return "REQ";
  case IR_RSP:
    return "RSP";
  case IR_EVT:
    return "EVT";
  default:
    return "???";
  }
}

/* "L1 rack.slot,num,task" and so on, or "IP type task address" */
char *IRFmtAddr(IRAddress addr, char *bptr)
{
  static const char *types[] = { "L1 ", "L2 ", "L3 ", "C  ", "I  ", "CI ", "CC " };
  int type = IR_ADDR_TYPE(addr);
  uint32_t ip;

  if (type == IR_ADDR_IP || type == IR_ADDR_IP_OTHER) {
    ip = IRByteOrder == 1 ? addr & 0xffffff : htonl(addr & 0xffffff);
    sprintf(bptr,"IP %01x %02x %06x",type,IR_ADDR_TASK(addr),ip);
    return bptr;
  }
  if (type <= IR_ADDR_CC)
    strcpy(bptr,types[type]);
  else
    sprintf(bptr,"%2d ",type);
  sprintf(bptr + strlen(bptr),"%4d.%2d,%2d,%3d ",IR_ADDR_RACK(addr),IR_ADDR_SLOT(addr),
          IR_ADDR_NUM(addr),IR_ADDR_TASK(addr));
  return bptr;
}

char *IRFmtPkt(char *who, IRPacket *p, char *bptr)
{
  char dest[32], src[32];

  IRFmtAddr(p->_dest,dest);
  IRFmtAddr(p->_src,src);
  sprintf(bptr,"%-12.12s %5d %s(%d,%d,%d) D: %s S: %s",who,IR_SEQNUM(p),IRFmtClas(p->_clas),
          p->_argc,p->_err,p->_opcode,dest,src);
  return bptr;
}

/* one frame's header (NULL: the column heads) */
void IRPrintFrame(char *who, IRFrame *f)
{
  if (f == NULL) {
    fprintf(stderr,"WHO    ADDR     NEXT     SIZE RV ER S0 FF FN CL DEST     SRC      AC S1 OPCD\n");
    fprintf(stderr,"------ -------- -------- ---- -- -- -- -- -- -- -------- -------- -- -- ----\n");
    return;
  }
  fprintf(stderr,"%-6.6s %08lx %08lx %04x %02x %02x %02x %02x %02x %02x %08x %08x %02x %02x %04x\n",
          who,(unsigned long)(uintptr_t)f,(unsigned long)(uintptr_t)f->_next_frame,f->_size,f->_rev,
          f->_err,f->_seqnum0,f->_fnum >> 7,f->_fnum & 0x7f,f->_clas,f->_dest,f->_src,f->_argc,
          f->_seqnum1,f->_opcode);
}

char *IRFmtError(int errcode)
{
  return errcode == 0 ? "no error" : LoggerDefaultMessage(IR_ERRNO(errcode));
}

#if UINTPTR_MAX != 0xffffffffu
/* 64-bit hosts: pointers placed in a 32-bit IRArgument _val (see IR_PTR_VAL
 * in IRouter.h) are kept in a ring; the value is slot + 1 (0 stays NULL).
 * A pointer only needs to live until the packet is built from the argument
 * list, a few stores later; the ring holds the last 65536. */
#define IR_PTR_RING 65536
static const void *ir_ptr_ring[IR_PTR_RING];
static uint32 ir_ptr_next;

uint32 IRPtrToVal(const void *p)
{
  uint32 slot;

  if (p == NULL)
    return 0;
  slot = ir_ptr_next++ % IR_PTR_RING;
  ir_ptr_ring[slot] = p;
  return slot + 1;
}

void *IRValToPtr(uint32 v)
{
  if (v == 0 || v > IR_PTR_RING)
    return NULL;
  return (void *)ir_ptr_ring[v - 1];
}
#endif
