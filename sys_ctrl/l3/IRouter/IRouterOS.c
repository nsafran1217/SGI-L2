/*
 * sys_ctrl/l3/IRouter/IRouterOS.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/IRouter/IRouterOS.c
 *
 * IRouter through the system controller device of an SN system's OS
 * (/dev/snsc/..., --sc/--scdev): the device takes and gives chunks of at
 * most 128 bytes, one per write() and read(). A chunk is a 9-byte header
 * (4 zero bytes, the chunk type big-endian: 0x3001 starts a packet's first
 * frame, with the packet's frame count; 0x3002 a later frame; 0x3003
 * continues a frame; the frame's size big-endian) and up to 118 bytes of
 * the frame (from IRFrame._size, as on the wire).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>
#include "IRouterOS.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/Router/Router.h"
#include "../../common/Router/RouterMsg.h"
#include "../sys/syslogLib.h"

#define CHUNK_HDR       9
#define CHUNK_MAX       128
#define CHUNK_DATA      (CHUNK_MAX - CHUNK_HDR - 1)     /* 118: what pipe_out() puts in one */
#define CHUNK_FIRST     0x3001  /* the first frame of a packet */
#define CHUNK_FRAME     0x3002  /* a later frame */
#define CHUNK_MORE      0x3003  /* the rest of a frame */
#define CHUNK_MARK      '0'     /* the chunk type's high byte (0x30) */

static int wr(int fd, unsigned char *bptr, int blen);
static int pipe_out(int fd, unsigned char *pptr, int plen);
static int rd(int fd, unsigned char *bptr, int blen);
static int pipe_in(int fd, unsigned char **pptr, int plen);

static int sd = -1;             /* the device */
static RouterClient rtr_conn_server;    /* a stand-in client */

/* open the device (exits if it cannot) */
int IRouterConnectOS(char *cname, char *device, int port, IRClient **client, int events, char *(*pw_cb)())
{
  sd = open(device,O_RDWR);
  if (sd == -1) {
    syslog(3,"IRouterOS.c",89,0,"can\'t open %s, errno %d.\n",device,errno);
    exit(-1);
  }
  *client = &rtr_conn_server;
  return 0;
}

void IRouterDisconnectOS(IRClient *client)
{
  close(sd);
}

int IRouterRequestOS(IRClient *client, IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum)
{
  IRPacket *pkt;

  if (sd == -1)
    return ROUTER_ERR_LOST;
  if (seqnum != NULL)
    *seqnum = id->seqnum;
  pkt = IRouterMakePacket(id,toaddr,0,opcode,IR_REQ,2,argcount,arglist);
  if (pkt == NULL)
    return IR_ERRNO(IRERR_MALLOC_FAILED);
  return IRouterWritePacket(id,pipe_out,(void *)(intptr_t)sd,pkt);
}

/* answer reqpkt; errcode is an IRouter error number (IR_ERRNO()) or 0 */
int IRouterResponseOS(IRClient *client, IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist)
{
  IRPacket *rsppkt;

  if (sd == -1)
    return ROUTER_ERR_LOST;
  rsppkt = IRouterMakePacket(id,&reqpkt->_src,0,reqpkt->_opcode,IR_RSP,reqpkt->_rev,argcount,arglist);
  if (rsppkt == NULL)
    return IR_ERRNO(IRERR_MALLOC_FAILED);
  rsppkt->_err = (-errcode) % 100;
  rsppkt->_seqnum0 = reqpkt->_seqnum0;
  rsppkt->_seqnum1 = reqpkt->_seqnum1;
  return IRouterWritePacket(id,pipe_out,(void *)(intptr_t)sd,rsppkt);
}

int IRouterEventOS(IRClient *client, IRIdent *id, int opcode, int argcount, IRArgument *arglist)
{
  IRPacket *pkt;

  if (sd == -1)
    return ROUTER_ERR_LOST;
  pkt = IRouterMakePacket(id,NULL,0,opcode,IR_EVT,2,argcount,arglist);
  if (pkt == NULL)
    return IR_ERRNO(IRERR_MALLOC_FAILED);
  return IRouterWritePacket(id,pipe_out,(void *)(intptr_t)sd,pkt);
}

/*
 * The next packet (a response, if response is set: others are freed),
 * waiting wait seconds for each (0: a millisecond).
 */
int IRouterGetPacketOS(IRIdent *id, IRPacket **pkt, IRClient **client, int wait, int response)
{
  struct timeval wait_time;
  fd_set fdset;
  int rval;

  if (sd == -1)
    return ROUTER_ERR_LOST;
  for (;;) {
    wait_time.tv_sec = wait;
    wait_time.tv_usec = wait == 0 ? 1000 : 0;
    FD_ZERO(&fdset);
    FD_SET(sd,&fdset);
    if (select(sd + 1,&fdset,NULL,NULL,&wait_time) < 0)
      return IR_ERRNO(IRERR_READ_FAILED_SELFAIL);
    if (!FD_ISSET(sd,&fdset))
      return IR_ERRNO(IRERR_READ_FAILED_TIMEOUT);
    rval = IRouterReadPacket(id,pipe_in,(void *)(intptr_t)sd,pkt);
    if (rval != 0)
      return rval;
    if (!response || (*pkt)->_clas == IR_RSP)
      return 0;
    IRouterFreePacket(*pkt);
  }
}

static int wr(int fd, unsigned char *bptr, int blen)
{
  return write(fd,bptr,blen);
}

/* IRouterWritePacket()'s write function: one frame (plen bytes from
 * _size on) in chunks; returns plen */
static int pipe_out(int fd, unsigned char *pptr, int plen)
{
  unsigned char buff[CHUNK_MAX];
  int rval = plen;
  int blen;
  unsigned char fnum;

  if (fd == -1)
    return ROUTER_ERR_LOST;
  memset(buff,0,CHUNK_HDR);
  buff[4] = CHUNK_MARK;
  fnum = pptr[5];               /* the frame's _fnum (its wire offset) */
  if (fnum & IR_FNUM_FIRST) {
    buff[5] = CHUNK_FIRST & 0xff;
    buff[6] = fnum & 0x7f;      /* the packet's frame count */
  }
  else {
    buff[5] = CHUNK_FRAME & 0xff;
  }
  buff[7] = plen >> 8;
  buff[8] = plen;
  while (plen != 0) {
    blen = plen <= CHUNK_DATA ? plen : CHUNK_DATA;
    memcpy(buff + CHUNK_HDR,pptr,blen);
    pptr += blen;
    plen -= blen;
    wr(fd,buff,blen + CHUNK_HDR);
    buff[5] = CHUNK_MORE & 0xff;
    buff[6] = 0;
    buff[7] = 0;
    buff[8] = 0;
  }
  return rval;
}

static int rd(int fd, unsigned char *bptr, int blen)
{
  errno = 0;
  return read(fd,bptr,blen);
}

/*
 * IRouterReadPacket()'s read function: one frame, from its chunks, into
 * *pptr (plen bytes there). Returns its size or an IRouter error.
 */
static int pipe_in(int fd, unsigned char **pptr, int plen)
{
  static unsigned char ibuf[CHUNK_MAX];
  unsigned char *bptr = *pptr + IR_FRAME_PREFIX;   /* wire frame starts at IRFrame._size */
  int blen = 0;                 /* still to come */
  int rlen = 0;
  int ilen, chunk_type, frame_size;

  if (fd == -1)
    return ROUTER_ERR_LOST;
  do {
    ilen = rd(fd,ibuf,sizeof(ibuf));
    if (ilen < 1)
      return IR_ERRNO(IRERR_READ_FAILED_RDERR);
    if (ilen < CHUNK_HDR) {     /* (the original copied a negative length) */
      syslog(6,"IRouterOS.c",463,0,"frame data underflow");
      return IR_ERRNO(IRERR_FRAME_UNDERFLOW);
    }
    chunk_type = ibuf[4] << 8 | ibuf[5];
    frame_size = ibuf[7] << 8 | ibuf[8];
    ilen -= CHUNK_HDR;
    if (chunk_type == CHUNK_FIRST || chunk_type == CHUNK_FRAME) {
      if (blen != 0) {
        syslog(6,"IRouterOS.c",436,0,"frame data underflow");
        return IR_ERRNO(IRERR_FRAME_UNDERFLOW);
      }
      rlen = frame_size;
      blen = frame_size;
      if (plen < frame_size) {
        syslog(6,"IRouterOS.c",447,0,"frame data overflow");
        return IR_ERRNO(IRERR_FRAME_OVERFLOW);
      }
    }
    else if (chunk_type != CHUNK_MORE) {
      syslog(6,"IRouterOS.c",486,0,"bad chunk type %d\n",chunk_type);
      return IR_ERRNO(IRERR_FRAME_CONTROL);
    }
    if (blen < ilen) {
      syslog(6,"IRouterOS.c",463,0,"frame data overflow");
      return IR_ERRNO(IRERR_FRAME_OVERFLOW);
    }
    memcpy(bptr,ibuf + CHUNK_HDR,ilen);
    bptr += ilen;
    blen -= ilen;
  } while (blen != 0);
  return rlen;
}
