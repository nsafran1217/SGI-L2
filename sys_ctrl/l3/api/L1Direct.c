/*
 * sys_ctrl/l3/api/L1Direct.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/L1Direct.c
 */

#include <stdlib.h>
#include <string.h>
#include "../../common/Router/SocketIO.h"   /* needed by the reconstruction */
#include "../IRouter/IRouterL3.h"   /* needed by the reconstruction */
#include "../l2/dmp.h"   /* needed by the reconstruction */
#include "../l2/format.h"   /* needed by the reconstruction */
#include "../l2/l1.h"   /* needed by the reconstruction */
#include "../l2/l2cmd.h"   /* needed by the reconstruction */
#include "../l2/smp.h"   /* needed by the reconstruction */
#include "L1Direct.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <getopt.h>
#include "../../common/Router/Socket.h"
#include "../../common/Router/Event.h"
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
#include "../../common/sys/PPP.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void pkt_timeout(EventData client_data);
static char *format_address(IRAddress addr);
static void dmp(char *s, unsigned char *bptr, int blen, int newline);

unsigned char l1d_pkt_in[1] = { 24 };
unsigned char l1d_pkt_out[1] = "\r";
static char *myname;
static int l1d_conn_serial;
static int l1d_conn_direct;
static int l1d_debug;
static int l1d_debug_irtr;
static int l1d_fd;
static int l1d_fd_connected;
static int l1d_serial_hostport;
static IRPacket *l1d_pkt;
static EventID pkt_timeout_id;
PPPInstance ppp;
unsigned char ppp_ibuf[8];
unsigned char ppp_obuf[256];
static IRIdent l1d_id;
static char l1d_serial_device[64];
static char l1d_serial_host[64];
static ssize_t (*wfcn)();

char *L1DirectUsage(void)
{
  char *msg;
  
  return 
  "    --serial <host>:<port>        ethernet (i.e. Annex) hostname and port\n    --dev <device name>           local serial port device name"
  ;
}

int L1DirectParseCmdline(int *argc, char **argv, int *use_direct)
{
  int iVar1;
  char *__s;
  int iVar2;
  char *pcVar3;
  char *sep;
  char *hostport;
  int argsused;
  int tmp_argc;
  int orig_argc;
  int status;
  int use_direct_in;
  
  status = 0;
  orig_argc = *argc;
  tmp_argc = *argc;
  use_direct_in = *use_direct;
  myname = *argv;
  *use_direct = 0;
  argv = argv + 1;
  do {
    iVar1 = tmp_argc + -1;
    if (iVar1 == 0) {
LAB_080594c1:
      *argc = orig_argc;
      if ((use_direct_in == 0) && (*use_direct != 0)) {
        fprintf(stderr,"%s: --serial/--dev options (direct serial connection) not supported!\n",
                myname);
        status = -1;
      }
      return status;
    }
    argsused = 0;
    iVar2 = strcmp(*argv,"--serial");
    if (iVar2 == 0) {
      if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
        fprintf(stderr,"%s: --serial option missing <hostname:port>\n",myname);
        status = -1;
        goto LAB_080594c1;
      }
      __s = argv[1];
      pcVar3 = strchr(__s,0x3a);
      if (pcVar3 == NULL) {
        fprintf(stderr,"%s: --serial option missing <hostname:port>\n",myname);
        status = -1;
        goto LAB_080594c1;
      }
      if (pcVar3[1] == '\0') {
        fprintf(stderr,"%s: --serial option <hostname:port> bad format\n",myname);
        status = -1;
        goto LAB_080594c1;
      }
      *use_direct = 1;
      l1d_conn_serial = 1;
      l1d_conn_direct = 0;
      strncpy(l1d_serial_host,__s,(int)pcVar3 - (int)__s);
      l1d_serial_hostport = atoi(pcVar3 + 1);
      wfcn = write;
      argsused = 2;
      tmp_argc = tmp_argc + -2;
    }
    else {
      iVar2 = strcmp(*argv,"--dev");
      if (iVar2 == 0) {
        if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
          fprintf(stderr,"%s: --dev option missing <device name>\n",myname);
          status = -1;
          goto LAB_080594c1;
        }
        *use_direct = 1;
        l1d_conn_serial = 1;
        l1d_conn_direct = 1;
        strcpy(l1d_serial_device,argv[1]);
        wfcn = SocketWrite;
        argsused = 2;
        tmp_argc = tmp_argc + -2;
      }
      else {
        iVar2 = strcmp(*argv,"--debug");
        tmp_argc = iVar1;
        if (iVar2 == 0) {
          l1d_debug = 1;
          argsused = 1;
        }
      }
    }
    if (argsused == 0) {
      argv = argv + 1;
    }
    else {
      for (sep = NULL; (int)sep < tmp_argc; sep = sep + 1) {
        argv[(int)sep] = argv[(int)(sep + argsused)];
      }
      orig_argc = orig_argc - argsused;
    }
  } while( true );
}

int L1DirectConnect(void)
{
  int iVar1;
  
  iVar1 = l1d_open(1);
  return iVar1;
}

int L1DirectOpen(void)
{
  int iVar1;
  
  iVar1 = l1d_open(0);
  return iVar1;
}

int L1DirectClose(void)
{
  int iVar1;
  
  iVar1 = l1d_close();
  return iVar1;
}

int L1DirectRequest(IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum)
{
  IRPacket *pkt;
  int iVar1;
  int rval;
  
  if (seqnum != NULL) {
    *seqnum = (uint)id->seqnum;
  }
  pkt = IRouterMakePacket(id,toaddr,0,opcode,0,2,argcount,arglist);
  if (pkt == NULL) {
    iVar1 = -0x25c;
  }
  else {
    iVar1 = L1DirectSendPacket(pkt,l1d_fd);
  }
  return iVar1;
}

int L1DirectResponse(IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist)
{
  IRPacket *pkt;
  int iVar1;
  uint8 uStack_14;
  IRIdent *pIStack_10;
  int rval;
  
  pIStack_10 = id;
  if (id == NULL) {
    pIStack_10 = (IRIdent *)&reqpkt->_dest;
  }
  pkt = IRouterMakePacket(id,&pIStack_10->addr,0,(uint)reqpkt->_opcode,1,(uint)reqpkt->_rev,argcount
                          ,arglist);
  if (pkt == NULL) {
    iVar1 = -0x25c;
  }
  else {
    uStack_14 = (char)-errcode + (char)(-errcode / 100) * -100;
    pkt->_err = uStack_14;
    pkt->_seqnum0 = reqpkt->_seqnum0;
    pkt->_seqnum1 = reqpkt->_seqnum1;
    iVar1 = L1DirectSendPacket(pkt,l1d_fd);
  }
  return iVar1;
}

int L1DirectEvent(IRIdent *id, int opcode, int argcount, IRArgument *arglist)
{
  IRPacket *pkt;
  int iVar1;
  int rval;
  
  pkt = IRouterMakePacket(id,NULL,0,opcode,2,2,argcount,arglist);
  if (pkt == NULL) {
    iVar1 = -0x25c;
  }
  else {
    iVar1 = L1DirectSendPacket(pkt,l1d_fd);
  }
  return iVar1;
}

int L1DirectSendPacket(IRPacket *pkt, int fd)
{
  char x [80];
  
  if (l1d_debug_irtr != 0) {
    IRFmtPkt("L2 Write",pkt,x);
    fprintf(stderr,"%s\n",x);
  }
  l1d_write_packet(fd,pkt);
  return 0;
}

int L1DirectGetPacket(IRPacket **pkt, int wait, int response)
{
  int rval;
  bool waiting;
  
  waiting = false;
  rval = 0;
  if (wait == 0) {
    waiting = true;
    pkt_timeout_id = EventAddTimeOut(0,1000,pkt_timeout,(EventData)0x0,"L1DirectGetPacket");
  }
  else if (wait != -1) {
    waiting = true;
    pkt_timeout_id = EventAddTimeOut(wait,0,pkt_timeout,(EventData)0x0,"L1DirectGetPacket");
  }
  while ((!waiting || (pkt_timeout_id != 0))) {
    EventStart();
    if (l1d_pkt == NULL) {
      *pkt = NULL;
      rval = -1;
      goto LAB_080598c4;
    }
    *pkt = l1d_pkt;
    l1d_pkt = NULL;
    if ((response == 0) || ((*pkt)->_clas == '\x01')) goto LAB_080598c4;
  }
  *pkt = NULL;
  rval = -1;
LAB_080598c4:
  if (pkt_timeout_id != 0) {
    EventRemoveTimeOut(pkt_timeout_id);
    pkt_timeout_id = 0;
  }
  return rval;
}

int l1d_open_serial_direct(void)
{
  int *piVar1;
  int iVar2;
  
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_open_serial_direct() in\n");
  }
  l1d_fd = l1d_tty_open(l1d_serial_device);
  if (l1d_fd < 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"ERROR: can\'t open device %s, errno: %d\n",l1d_serial_device,*piVar1);
    iVar2 = -1;
  }
  else {
    if (l1d_debug != 0) {
      fprintf(stderr,"l1d_open_serial_direct() out\n");
    }
    iVar2 = 0;
  }
  return iVar2;
}

int l1d_close_serial_direct(void)
{
  int iVar1;
  int *piVar2;
  
  iVar1 = l1d_tty_close(l1d_fd);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    piVar2 = __errno_location();
    fprintf(stderr,"ERROR: can\'t close device %s, errno: %d\n",l1d_serial_device,*piVar2);
    iVar1 = -1;
  }
  return iVar1;
}

int l1d_open_serial_enet(void)
{
  int *piVar1;
  int iVar2;
  
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_open_serial_enet() in\n");
  }
  l1d_fd = SocketMakeInetConnection(l1d_serial_host,l1d_serial_hostport,0);
  if (l1d_fd < 0) {
    piVar1 = __errno_location();
    fprintf(stderr," ERROR: can\'t open connection %s:%d, errno: %d\n",l1d_serial_host,
            l1d_serial_hostport,*piVar1);
    iVar2 = -1;
  }
  else {
    if (l1d_debug != 0) {
      fprintf(stderr,"l1d_open_serial_enet() out\n");
    }
    iVar2 = 0;
  }
  return iVar2;
}

int l1d_close_serial_enet(void)
{
  int iVar1;
  int *piVar2;
  
  iVar1 = SocketClose(l1d_fd);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    piVar2 = __errno_location();
    fprintf(stderr," ERROR: can\'t close connection %s:%d, errno: %d\n",l1d_serial_host,
            l1d_serial_hostport,*piVar2);
    iVar1 = -1;
  }
  return iVar1;
}

int l1d_open(int connect)
{
  ssize_t sVar1;
  int *piVar2;
  int iVar3;
  char echo [1];
  uchar prevchar;
  int initialized;
  int status;
  
  prevchar = '\0';
  l1d_fd_connected = 0;
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_open() in\n");
  }
  if (l1d_conn_direct == 0) {
    status = l1d_open_serial_enet();
  }
  else {
    status = l1d_open_serial_direct();
  }
  if (status == 0) {
    iVar3 = l1d_fd;
    if (connect != 0) {
      l1d_fd_connected = 1;
      PPPInit(&ppp,ppp_ibuf,8,ppp_obuf,0x100,0,1,0x10,0,l1d_ppperr,NULL);
      sVar1 = (*wfcn)(l1d_fd,"\r",1);
      if (sVar1 == 1) {
        sleep(2);
        sVar1 = (*wfcn)(l1d_fd,"\x18",1);
        if (sVar1 == 1) {
          while( true ) {
            piVar2 = __errno_location();
            *piVar2 = 0;
            if (l1d_debug != 0) {
              fprintf(stderr,"l1d_open() waiting\n");
            }
            if (l1d_conn_direct == 0) {
              status = SocketRead(l1d_fd,(uchar *)echo,1);
            }
            else {
              status = read(l1d_fd,echo,1);
            }
            if (status < 1) {
              piVar2 = __errno_location();
              fprintf(stderr,"FATAL: can\'t confirm L1 protocol, errno: %d\n",*piVar2);
              return -1;
            }
            if (l1d_debug != 0) {
              piVar2 = __errno_location();
              fprintf(stderr,"l1d_open() read %02x, status %d, errno %d\n",(int)echo[0],status,
                      *piVar2);
            }
            if (echo[0] == '\x18') {
              iVar3 = SocketNodelayMode(l1d_fd,1);
              if (iVar3 != 0) {
                piVar2 = __errno_location();
                fprintf(stderr,
                        "FATAL: can\'t set delay mode on L1 connection, status: %d, errno: %d\n",
                        iVar3,*piVar2);
                return -1;
              }
              EventAddInput(l1d_fd,l1d_read_packet,(EventData)0x0,"l1d_open");
              if (l1d_debug != 0) {
                fprintf(stderr,"l1d_open() out\n");
              }
              return 0;
            }
            if ((prevchar == 0xff) && (echo[0] == -5)) break;
            prevchar = echo[0];
          }
          if ((l1d_conn_direct == 0) &&
             ((4999 < l1d_serial_hostport && (l1d_serial_hostport < 5999)))) {
            fprintf(stderr,
                    "ERROR: can\'t establish a connection to the L1!\nThis connection appears to be using the telnet protocol.\nYou specified port %d when you probably need to use port %d instead.\n"
                    ,l1d_serial_hostport,l1d_serial_hostport + 2000);
          }
          else {
            fprintf(stderr,
                    "ERROR: can\'t establish a connection to the L1!\nThis connection appears to be using the telnet protocol (usually this\nhappens when specifying a 5xxx Annex port instead of a 7xxx port).\n"
                   );
          }
          iVar3 = -1;
        }
        else {
          piVar2 = __errno_location();
          fprintf(stderr,"FATAL: can\'t initiate L1 protocol, errno: %d\n",*piVar2);
          iVar3 = -1;
        }
      }
      else {
        piVar2 = __errno_location();
        fprintf(stderr,"FATAL: can\'t initiate L1 protocol, errno: %d\n",*piVar2);
        iVar3 = -1;
      }
    }
  }
  else {
    fprintf(stderr,"FATAL: can\'t open connection to L1\n");
    iVar3 = -1;
  }
  return iVar3;
}

int l1d_close(void)
{
  int status;
  
  if (l1d_fd_connected != 0) {
    EventRemoveInput(l1d_fd);
    (*wfcn)(l1d_fd,"\r",1);
  }
  if (l1d_conn_direct == 0) {
    status = l1d_close_serial_enet();
  }
  else {
    status = l1d_close_serial_direct();
  }
  if (status == 0) {
    status = 0;
  }
  else {
    fprintf(stderr,"FATAL: can\'t close connection to L1\n");
  }
  return status;
}

void l1d_tty_debug(int td)
{
  int iVar1;
  int *piVar2;
  struct termios termios;
  int i;
  
  iVar1 = tcgetattr(td,(struct termios *)&termios);
  if (iVar1 == -1) {
    piVar2 = __errno_location();
    fprintf(stderr,"WARNING: can\'t get termios, errno: %d\n",*piVar2);
  }
  else {
    fprintf(stderr,"---\niflag:  0%08o\n",termios.c_iflag);
    fprintf(stderr,"oflag:  0%08o\n",termios.c_oflag);
    fprintf(stderr,"cflag:  0%08o\n",termios.c_cflag);
    fprintf(stderr,"lflag:  0%08o\n",termios.c_lflag);
    fprintf(stderr,"ispeed:  %8d\n",termios.c_ispeed);
    fprintf(stderr,"ospeed:  %8d\n",termios.c_ospeed);
    for (i = 0; i < 8; i = i + 1) {
      fprintf(stderr,"cc_c[%d]: %8o\n",i,(uint)termios.c_cc[i]);
    }
  }
  return;
}

int l1d_tty_open(char *device)
{
  int td;
  int *piVar1;
  int iVar2;
  struct termios termios;
  
  td = open(device,2);
  if (td == -1) {
    piVar1 = __errno_location();
    fprintf(stderr,"ERROR: can\'t open %s, errno %d\n",device,*piVar1);
    td = -1;
  }
  else {
    iVar2 = tcgetattr(td,(struct termios *)&termios);
    if (iVar2 == -1) {
      piVar1 = __errno_location();
      fprintf(stderr,"ERROR: can\'t get termios, errno %d.\n",*piVar1);
      td = -1;
    }
    else {
      termios.c_iflag = 5;
      termios.c_oflag = 0;
      termios.c_cflag = 0x800008bf;
      termios.c_lflag = 0;
      termios.c_cc[6] = '\x01';
      termios.c_cc[5] = '\0';
      iVar2 = tcsetattr(td,0,(struct termios *)&termios);
      if (iVar2 == -1) {
        piVar1 = __errno_location();
        fprintf(stderr,"ERROR: can\'t put termios, errno %d.\n",*piVar1);
        td = -1;
      }
    }
  }
  return td;
}

int l1d_tty_close(int td)
{
  int iVar1;
  struct termios termios;
  
  iVar1 = close(td);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

int l1d_read_data(int fd, unsigned char *bptr, int blen)
{
  int *piVar1;
  int status;
  
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_read_data(%d,%x,%d) in\n",fd,bptr,blen);
  }
  piVar1 = __errno_location();
  *piVar1 = 0;
  status = SocketRead(fd,bptr,blen);
  if (l1d_debug != 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"l1d_read_data() out, status %d, errno %d\n",status,*piVar1);
  }
  if (l1d_debug != 0) {
    dmp("READ",bptr,status,1);
  }
  return status;
}

int l1d_read_ppp(int fd, uint8 **bptr, int32 blen)
{
  int status;
  
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_read_ppp(%d,%x,%d) in\n",fd,bptr,blen);
  }
  status = PPPRead(&ppp,l1d_read_data,(void *)fd,bptr,blen);
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_read_ppp() out\n");
  }
  return status;
}

void l1d_read_packet(int port, int fd)
{
  static int lasterr;
  static int lastcnt;
  int status;
  char *pcVar1;
  char *pcVar2;
  char x [80];
  int err;
  IRPacket *p;
  
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_read_packet(%x,%d) in\n",port,fd);
  }
  status = IRouterReadPacket(&l1d_id,l1d_read_ppp,(void *)fd,&p);
  if (status == 0) {
    if (1 < lastcnt) {
      fprintf(stderr,"WARNING: last error on L1 connection repeated %d times\n",lastcnt);
    }
    lastcnt = 0;
    lasterr = 0;
    if (p->_err != 0) {
      pcVar1 = IRFmtError((uint)p->_err);
      pcVar2 = format_address(p->_src);
      fprintf(stderr,"WARNING: packet error %s - %s\n",pcVar2,pcVar1);
    }
    if (l1d_debug_irtr != 0) {
      IRFmtPkt("L2 Read",p,x);
      fprintf(stderr,"%s\n",x);
    }
    l1d_pkt = p;
    EventStop();
  }
  else if (status == lasterr) {
    lastcnt = lastcnt + 1;
  }
  else {
    if (1 < lastcnt) {
      fprintf(stderr,"WARNING: last error on L1 connection repeated %d times\n",lastcnt);
    }
    lastcnt = 1;
    lasterr = status;
    pcVar1 = LoggerDefaultMessage(status);
    fprintf(stderr,"WARNING: can\'t read packet on L1 connection, status: %s\n",pcVar1);
  }
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_read_packet() out\n");
  }
  return;
}

int l1d_write_data(int fd, unsigned char *bptr, int blen)
{
  int status;
  int *piVar1;
  
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_write_data(%d,%x,%d) in\n",fd,bptr,blen);
  }
  status = (*wfcn)(fd,bptr,blen);
  if (l1d_debug != 0) {
    dmp("WRITE",bptr,blen,1);
  }
  if (l1d_debug != 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"l1d_write_data() out, status %d, errno %d\n",status,*piVar1);
  }
  return status;
}

int l1d_write_ppp(int fd, uint8 *bptr, int blen)
{
  int status;
  
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_write_ppp(%d,%x,%d) in\n",fd,bptr,blen);
  }
  status = PPPWrite(&ppp,l1d_write_data,(void *)fd,bptr,blen);
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_write_ppp() out\n");
  }
  return status;
}

void l1d_write_packet(int fd, IRPacket *p)
{
  IRAddress addr;
  int status;
  char *pcVar1;
  char *pcVar2;
  IRAddress dest;
  
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_write_packet(%d, %x) in\n",fd,p);
  }
  addr = p->_dest;
  status = IRouterWritePacket(&l1d_id,l1d_write_ppp,(void *)fd,p);
  if (status != 0) {
    pcVar1 = LoggerDefaultMessage(status);
    pcVar2 = format_address(addr);
    fprintf(stderr,"WARNING: can\'t write L1 packet %s, status: %s\n",pcVar2,pcVar1);
  }
  if (l1d_debug != 0) {
    fprintf(stderr,"l1d_write_packet() out\n");
  }
  return;
}

void l1d_ppperr(void *arg, int err, char *bptr, int blen)
{
  char *pcVar1;
  
  pcVar1 = LoggerDefaultMessage(err);
  fprintf(stderr,"WARNING: PPP error %s\n",pcVar1);
  return;
}

static void pkt_timeout(EventData client_data)
{
  pkt_timeout_id = 0;
  EventStop();
  return;
}

static char *format_address(IRAddress addr)
{
  static char buff[80];
  uint uVar1;
  int slot;
  int rack;
  
  if ((addr & 0x80000000) == 0) {
    uVar1 = addr >> 0x1c;
  }
  else if (addr >> 0x1e == 2) {
    uVar1 = 0xe;
  }
  else {
    uVar1 = 0xf;
  }
  if (false) {
switchD_0805a610_caseD_2:
    sprintf((char *)&buff,"address error");
  }
  else {
    switch(uVar1) {
    case 0:
      sprintf((char *)&buff,"%03d.%02d",addr >> 0x12 & 0x3ff,addr >> 0xc & 0x3f);
    case 3:
      strcpy((char *)&buff,"local attached C");
      break;
    case 1:
      strcpy((char *)&buff,"L2");
      break;
    default:
      goto switchD_0805a610_caseD_2;
    case 4:
      strcpy((char *)&buff,"local attached I/O");
      break;
    case 5:
      strcpy((char *)&buff,"local attached C\'s I/O");
    }
  }
  return buff;
}

static void dmp(char *s, unsigned char *bptr, int blen, int newline)
{
  int n;
  char buff [80];
  
  if (s != NULL) {
    fprintf(stderr,"\n%s %x\n",s,bptr);
  }
  for (n = 0; n < blen; n = n + 1) {
    fprintf(stderr,"%02x ",(uint)bptr[n]);
    if ((newline != 0) && ((n + 1U & 7) == 0)) {
      fprintf(stderr,"\n");
    }
  }
  if (newline != 0) {
    fprintf(stderr,"\n");
  }
  return;
}
