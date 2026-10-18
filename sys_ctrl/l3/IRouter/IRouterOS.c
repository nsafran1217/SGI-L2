/*
 * sys_ctrl/l3/IRouter/IRouterOS.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/IRouter/IRouterOS.c
 */

#include "../l2/smp.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include "../utils/l2term.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <termios.h>
#include "../../common/sys/syslog.h"
#include "../../common/sys/sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../../common/Router/Router.h"
#include "../../common/Router/RouterMsg.h"
#include "../../common/sys/Logger.h"
#include "IRouterOS.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void tty_debug(int fd);
static int wr(int fd, unsigned char *bptr, int blen);
static int pipe_out(int fd, unsigned char *pptr, int plen);
static int rd(int fd, unsigned char *bptr, int blen);
static int pipe_in(int fd, unsigned char **pptr, int plen);

static int sd = -1;
static RouterClient rtr_conn_server;

static void tty_debug(int fd)
{
  int iVar1;
  int *piVar2;
  char index [8];
  struct termios termios;
  int i;
  
  iVar1 = isatty(fd);
  if (iVar1 == 0) {
    fprintf(stderr,"not a tty!\n");
  }
  else {
    iVar1 = tcgetattr(fd,(struct termios *)&termios);
    if (iVar1 == -1) {
      piVar2 = __errno_location();
      fprintf(stderr,"WARNING: can\'t get termios, errno: %d\n",*piVar2);
    }
    else {
      fprintf(stderr,"---\niflag:  %011o\n",termios.c_iflag);
      fprintf(stderr,"oflag:  %011o\n",termios.c_oflag);
      fprintf(stderr,"cflag:  %011o\n",termios.c_cflag);
      fprintf(stderr,"lflag:  %011o\n",termios.c_lflag);
      fprintf(stderr,"ispeed: %011o\n",termios.c_ispeed);
      fprintf(stderr,"ospeed: %011o\n",termios.c_ospeed);
      for (i = 0; i < 0x20; i = i + 1) {
        sprintf(index,"0x%02x",i);
        fprintf(stderr,"%2d cc_c[%-8s]: %011o\n",fd,index,(uint)termios.c_cc[i]);
      }
    }
  }
  return;
}

int IRouterConnectOS(char *cname, char *device, int port, IRClient **client, int events, char *(*pw_cb)())
{
  int *piVar1;
  
  sd = open(device,2);
  if (sd == -1) {
    piVar1 = __errno_location();
    syslog(3,"IRouterOS.c",0x59,0,"can\'t open %s, errno %d.\n",device,*piVar1);
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  *client = &rtr_conn_server;
  return 0;
}

void IRouterDisconnectOS(IRClient *client)
{
  close(sd);
  return;
}

int IRouterRequestOS(IRClient *client, IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum)
{
  int iVar1;
  IRPacket *pkt;
  int rval;
  
  if (sd == -1) {
    iVar1 = -0x12f;
  }
  else {
    if (seqnum != NULL) {
      *seqnum = (uint)id->seqnum;
    }
    pkt = IRouterMakePacket(id,toaddr,0,opcode,0,2,argcount,arglist);
    if (pkt == NULL) {
      iVar1 = -0x25c;
    }
    else {
      iVar1 = IRouterWritePacket(id,pipe_out,(void *)sd,pkt);
    }
  }
  return iVar1;
}

int IRouterResponseOS(IRClient *client, IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist)
{
  int iVar1;
  IRPacket *rsppkt;
  uint8 uStack_14;
  int rval;
  
  if (sd == -1) {
    iVar1 = -0x12f;
  }
  else {
    rsppkt = IRouterMakePacket(id,&reqpkt->_src,0,(uint)reqpkt->_opcode,1,(uint)reqpkt->_rev,
                               argcount,arglist);
    if (rsppkt == NULL) {
      iVar1 = -0x25c;
    }
    else {
      uStack_14 = (char)-errcode + (char)(-errcode / 100) * -100;
      rsppkt->_err = uStack_14;
      rsppkt->_seqnum0 = reqpkt->_seqnum0;
      rsppkt->_seqnum1 = reqpkt->_seqnum1;
      iVar1 = IRouterWritePacket(id,pipe_out,(void *)sd,rsppkt);
    }
  }
  return iVar1;
}

int IRouterEventOS(IRClient *client, IRIdent *id, int opcode, int argcount, IRArgument *arglist)
{
  int iVar1;
  IRPacket *pkt;
  int rval;
  
  if (sd == -1) {
    iVar1 = -0x12f;
  }
  else {
    pkt = IRouterMakePacket(id,NULL,0,opcode,2,2,argcount,arglist);
    if (pkt == NULL) {
      iVar1 = -0x25c;
    }
    else {
      iVar1 = IRouterWritePacket(id,pipe_out,(void *)sd,pkt);
    }
  }
  return iVar1;
}

int IRouterGetPacketOS(IRIdent *id, IRPacket **pkt, IRClient **client, int wait, int response)
{
  byte *pbVar1;
  int fdmax;
  int iVar2;
  int status;
  int __d1;
  char __result;
  int __d0;
  fd_set fdset;
  struct timeval wait_time;
  
  fdmax = sd + 1;
  if (sd == -1) {
    iVar2 = -0x12f;
  }
  else {
    while( true ) {
      if (wait == 0) {
        wait_time.tv_sec = 0;
        wait_time.tv_usec = 1000;
      }
      else {
        wait_time.tv_sec = wait;
        wait_time.tv_usec = 0;
      }
      __d1 = (int)&fdset;
      for (status = 0x20; status != 0; status = status + -1) {
        *(undefined4 *)__d1 = 0;
        __d1 = __d1 + 4;
      }
      FD_SET(sd, &fdset);
      iVar2 = select(fdmax,(fd_set *)&fdset,NULL,NULL,(struct timeval *)&wait_time);
      if (iVar2 < 0) {
        return -0x267;
      }
      if (FD_ISSET(sd, &fdset) == 0) {
        return -0x268;
      }
      iVar2 = IRouterReadPacket(id,pipe_in,(void *)sd,pkt);
      if (iVar2 != 0) {
        return iVar2;
      }
      if ((response == 0) || ((*pkt)->_clas == '\x01')) break;
      IRouterFreePacket(*pkt);
    }
    iVar2 = 0;
  }
  return iVar2;
}

static int wr(int fd, unsigned char *bptr, int blen)
{
  int status;
  
  status = write(fd,bptr,blen);
  return status;
}

static int pipe_out(int fd, unsigned char *pptr, int plen)
{
  int iVar1;
  int rlen;
  int blen;
  uchar buff [128];
  IRPacket *p;
  
  iVar1 = plen;
  if (fd == -1) {
    iVar1 = -0x12f;
  }
  else {
    buff[0] = (uchar)fd;
    buff[1] = '\0';
    buff[2] = '\0';
    buff[3] = '\0';
    buff[4] = '\0';
    if ((char)pptr[5] < '\0') {
      buff[6] = '\x01';
      buff[7] = pptr[5] & 0x7f;
    }
    else {
      buff[6] = '\x02';
      buff[7] = '\0';
    }
    buff[8] = (uchar)((uint)plen >> 8);
    buff[9] = (uchar)plen;
    while (buff[5] = '0', plen != 0) {
      if (plen < 0x77) {
        blen = plen;
        memcpy(buff + 10,pptr,plen);
        plen = 0;
      }
      else {
        blen = 0x76;
        memcpy(buff + 10,pptr,0x76);
        pptr = pptr + 0x76;
        plen = plen + -0x76;
      }
      wr(fd,buff + 1,blen + 9);
      buff[6] = '\x03';
      buff[7] = '\0';
      buff[8] = '\0';
      buff[9] = '\0';
    }
  }
  return iVar1;
}

static int rd(int fd, unsigned char *bptr, int blen)
{
  int *piVar1;
  int status;
  
  piVar1 = __errno_location();
  *piVar1 = 0;
  status = read(fd,bptr,blen);
  return status;
}

static int pipe_in(int fd, unsigned char **pptr, int plen)
{
  static unsigned char *iptr = &ibuf.22;
  static int ioff;
  static unsigned char ibuf[128];
  static int ilen;
  int chunk_type;
  int frame_size;
  int frame_count;
  int subchan;
  int rlen;
  int blen;
  uchar *bptr;
  uint dlen;
  uchar *dptr;
  
  bptr = *pptr + 0x10;
  blen = 0;
  rlen = 0;
  if (fd == -1) {
    rlen = -0x12f;
  }
  else {
    do {
      iptr = &ibuf;
      ilen = rd(fd,(uchar *)&ibuf,0x80);
      if (ilen < 1) {
        return -0x264;
      }
      chunk_type = (int)CONCAT11(*(undefined1 *)(ioff + 0x80767c4),*(undefined1 *)(ioff + 0x80767c5)
                                );
      frame_size = (int)CONCAT11(*(undefined1 *)(ioff + 0x80767c7),*(undefined1 *)(ioff + 0x80767c8)
                                );
      iptr = iptr + ioff + 9;
      ilen = (ilen + -9) - ioff;
      if ((uint)chunk_type < 0x3001) {
LAB_0805c072:
        syslog(6,"IRouterOS.c",0x1e6,0,"bad chunk type %d\n",chunk_type);
        return -0x272;
      }
      if ((uint)chunk_type < 0x3003) {
        if (blen != 0) {
          syslog(6,"IRouterOS.c",0x1b4,0,"frame data underflow");
          return -0x271;
        }
        rlen = frame_size;
        blen = frame_size;
        if (plen < frame_size) {
          syslog(6,"IRouterOS.c",0x1bf,0,"frame data overflow");
          return -0x270;
        }
      }
      else if (chunk_type != 0x3003) goto LAB_0805c072;
      if (blen < ilen) {
        syslog(6,"IRouterOS.c",0x1cf,0,"frame data overflow");
        return -0x270;
      }
      memcpy(bptr,iptr,ilen);
      bptr = bptr + ilen;
      blen = blen - ilen;
    } while (blen != 0);
  }
  return rlen;
}
