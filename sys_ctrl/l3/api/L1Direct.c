/*
 * sys_ctrl/l3/api/L1Direct.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/L1Direct.c
 *
 * A connection straight to one L1's serial port, without an L2: a local
 * serial device (--dev) or a terminal server port (--serial host:port,
 * an Annex "raw" 7xxx port). The line is opened with a CR and, two seconds
 * later, a CAN, which the L1 echoes; from then on IRouter frames go in PPP
 * framing (PPP.c). SCapi.c uses this when a tool allows it (l2cmd).
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <fcntl.h>
#include <unistd.h>
#include "L1Direct.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/Router/Event.h"
#include "../../common/Router/Socket.h"
#include "../../common/Router/SocketIO.h"
#include "../../common/sys/Logger.h"
#include "../../common/sys/PPP.h"

#define L1_OPEN_CHAR    '\r'    /* wakes the L1 */
#define L1_PROTO_CHAR   0x18    /* CAN: asks for the protocol; echoed */
#define L1_OPEN_DELAY   2       /* seconds between them */
#define TELNET_IAC      0xff
#define TELNET_WILL     0xfb
#define ANNEX_RAW_OFFSET 2000   /* Annex telnet ports 5xxx, raw 7xxx */
#define MALLOC_ERR      IR_ERRNO(IRERR_MALLOC_FAILED)

static void pkt_timeout(EventData client_data);
static char *format_address(IRAddress addr);
static void dmp(char *s, unsigned char *bptr, int blen, int newline);

unsigned char l1d_pkt_in[1] = { L1_PROTO_CHAR };   /* (unused) */
unsigned char l1d_pkt_out[1] = "\r";                /* (unused) */
static char *myname;
static int l1d_conn_serial;     /* a direct connection was asked for */
static int l1d_conn_direct;     /* ... to a local device (else a terminal server) */
static int l1d_debug;
static int l1d_debug_irtr;
static int l1d_fd;
static int l1d_fd_connected;
static int l1d_serial_hostport;
static IRPacket *l1d_pkt;       /* the packet l1d_read_packet() got */
static EventID pkt_timeout_id;
PPPInstance ppp;
unsigned char ppp_ibuf[8];
unsigned char ppp_obuf[256];
static IRIdent l1d_id;
static char l1d_serial_device[64];
static char l1d_serial_host[64];
static ssize_t (*wfcn)();

/* SocketWrite returns int: called through wfcn its result must widen to ssize_t */
static ssize_t l1d_socket_write(int fd, unsigned char *buffer, int len)
{
  return SocketWrite(fd,buffer,len);
}

char *L1DirectUsage(void)
{
  return "    --serial <host>:<port>        ethernet (i.e. Annex) hostname and port\n"
         "    --dev <device name>           local serial port device name";
}

/*
 * Take --serial, --dev and --debug out of argv (*argc adjusted).
 * *use_direct, in: whether the tool allows a direct connection; out:
 * whether one was asked for. 0, or -1 after a message.
 */
int L1DirectParseCmdline(int *argc, char **argv, int *use_direct)
{
  char **args = argv + 1;
  int remaining = *argc - 1;    /* arguments from args[0] on */
  int new_argc = *argc;
  int use_direct_in = *use_direct;
  int status = 0;
  int used;
  char *sep;

  myname = argv[0];
  *use_direct = 0;
  while (remaining > 0) {
    used = 0;
    if (strcmp(args[0],"--serial") == 0) {
      if (remaining < 2 || *args[1] == '-' || (sep = strchr(args[1],':')) == NULL) {
        fprintf(stderr,"%s: --serial option missing <hostname:port>\n",myname);
        status = -1;
        break;
      }
      if (sep[1] == '\0') {
        fprintf(stderr,"%s: --serial option <hostname:port> bad format\n",myname);
        status = -1;
        break;
      }
      *use_direct = 1;
      l1d_conn_serial = 1;
      l1d_conn_direct = 0;
      /* (the original copied up to the ':' without a bound) */
      snprintf(l1d_serial_host,sizeof(l1d_serial_host),"%.*s",(int)(sep - args[1]),args[1]);
      l1d_serial_hostport = atoi(sep + 1);
      wfcn = write;
      used = 2;
    }
    else if (strcmp(args[0],"--dev") == 0) {
      if (remaining < 2 || *args[1] == '-') {
        fprintf(stderr,"%s: --dev option missing <device name>\n",myname);
        status = -1;
        break;
      }
      *use_direct = 1;
      l1d_conn_serial = 1;
      l1d_conn_direct = 1;
      snprintf(l1d_serial_device,sizeof(l1d_serial_device),"%s",args[1]);
      wfcn = l1d_socket_write;
      used = 2;
    }
    else if (strcmp(args[0],"--debug") == 0) {
      l1d_debug = 1;
      used = 1;
    }
    if (used == 0) {
      args++;
      remaining--;
      continue;
    }
    remaining -= used;
    memmove(args,args + used,(remaining + 1) * sizeof(char *));
    new_argc -= used;
  }
  *argc = new_argc;
  if (!use_direct_in && *use_direct) {
    fprintf(stderr,"%s: --serial/--dev options (direct serial connection) not supported!\n",myname);
    status = -1;
  }
  return status;
}

/* open the line and start the L1 protocol */
int L1DirectConnect(void)
{
  return l1d_open(1);
}

/* just open the line */
int L1DirectOpen(void)
{
  return l1d_open(0);
}

int L1DirectClose(void)
{
  return l1d_close();
}

/* send a request; *seqnum (if not NULL) is its sequence number */
int L1DirectRequest(IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum)
{
  IRPacket *pkt;

  if (seqnum != NULL)
    *seqnum = id->seqnum;
  pkt = IRouterMakePacket(id,toaddr,0,opcode,IR_REQ,2,argcount,arglist);
  if (pkt == NULL)
    return MALLOC_ERR;
  return L1DirectSendPacket(pkt,l1d_fd);
}

/*
 * Answer reqpkt; errcode is an IRouter error number (IR_ERRNO()) or 0.
 * (As in the original, the response is addressed to our own address, or
 * with id NULL to the request's destination, which is us too: on a
 * point-to-point line it does not matter. IRouterMakePacket() would not
 * take a NULL id anyway.)
 */
int L1DirectResponse(IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist)
{
  IRAddress *toaddr = id != NULL ? &id->addr : &reqpkt->_dest;
  IRPacket *pkt;

  pkt = IRouterMakePacket(id,toaddr,0,reqpkt->_opcode,IR_RSP,reqpkt->_rev,argcount,arglist);
  if (pkt == NULL)
    return MALLOC_ERR;
  pkt->_err = (-errcode) % 100;
  pkt->_seqnum0 = reqpkt->_seqnum0;
  pkt->_seqnum1 = reqpkt->_seqnum1;
  return L1DirectSendPacket(pkt,l1d_fd);
}

int L1DirectEvent(IRIdent *id, int opcode, int argcount, IRArgument *arglist)
{
  IRPacket *pkt;

  pkt = IRouterMakePacket(id,NULL,0,opcode,IR_EVT,2,argcount,arglist);
  if (pkt == NULL)
    return MALLOC_ERR;
  return L1DirectSendPacket(pkt,l1d_fd);
}

int L1DirectSendPacket(IRPacket *pkt, int fd)
{
  char x[80];

  if (l1d_debug_irtr) {
    IRFmtPkt("L2 Write",pkt,x);
    fprintf(stderr,"%s\n",x);
  }
  l1d_write_packet(fd,pkt);
  return 0;
}

/*
 * The next packet (a response, if response is set: other packets are
 * dropped), waiting wait seconds (0: a millisecond, -1: forever). 0, or -1
 * if none came.
 */
int L1DirectGetPacket(IRPacket **pkt, int wait, int response)
{
  int waiting = 0;
  int rval = -1;

  if (wait == 0) {
    waiting = 1;
    pkt_timeout_id = EventAddTimeOut(0,1000,pkt_timeout,(EventData)0,"L1DirectGetPacket");
  }
  else if (wait != -1) {
    waiting = 1;
    pkt_timeout_id = EventAddTimeOut(wait,0,pkt_timeout,(EventData)0,"L1DirectGetPacket");
  }
  *pkt = NULL;
  while (!waiting || pkt_timeout_id != 0) {
    EventStart();               /* until l1d_read_packet() or the timeout stops it */
    if (l1d_pkt == NULL)
      break;
    *pkt = l1d_pkt;
    l1d_pkt = NULL;
    if (!response || (*pkt)->_clas == IR_RSP) {
      rval = 0;
      break;
    }
    *pkt = NULL;                /* (not freed: as the original) */
  }
  if (pkt_timeout_id != 0) {
    EventRemoveTimeOut(pkt_timeout_id);
    pkt_timeout_id = 0;
  }
  return rval;
}

int l1d_open_serial_direct(void)
{
  if (l1d_debug)
    fprintf(stderr,"l1d_open_serial_direct() in\n");
  l1d_fd = l1d_tty_open(l1d_serial_device);
  if (l1d_fd < 0) {
    fprintf(stderr,"ERROR: can\'t open device %s, errno: %d\n",l1d_serial_device,errno);
    return -1;
  }
  if (l1d_debug)
    fprintf(stderr,"l1d_open_serial_direct() out\n");
  return 0;
}

int l1d_close_serial_direct(void)
{
  if (l1d_tty_close(l1d_fd) != 0) {
    fprintf(stderr,"ERROR: can\'t close device %s, errno: %d\n",l1d_serial_device,errno);
    return -1;
  }
  return 0;
}

int l1d_open_serial_enet(void)
{
  if (l1d_debug)
    fprintf(stderr,"l1d_open_serial_enet() in\n");
  l1d_fd = SocketMakeInetConnection(l1d_serial_host,l1d_serial_hostport,0);
  if (l1d_fd < 0) {
    fprintf(stderr," ERROR: can\'t open connection %s:%d, errno: %d\n",l1d_serial_host,
            l1d_serial_hostport,errno);
    return -1;
  }
  if (l1d_debug)
    fprintf(stderr,"l1d_open_serial_enet() out\n");
  return 0;
}

int l1d_close_serial_enet(void)
{
  if (SocketClose(l1d_fd) != 0) {
    fprintf(stderr," ERROR: can\'t close connection %s:%d, errno: %d\n",l1d_serial_host,
            l1d_serial_hostport,errno);
    return -1;
  }
  return 0;
}

/* read one byte of the line */
static int read_byte(char *c)
{
  return l1d_conn_direct ? read(l1d_fd,c,1) : SocketRead(l1d_fd,(unsigned char *)c,1);
}

/*
 * Open the line; with connect, start the L1 protocol: CR, CAN, and wait
 * for the CAN's echo (a telnet port answers IAC WILL instead: the wrong
 * Annex port).
 */
int l1d_open(int connect)
{
  unsigned char prevchar = 0;
  char echo[1];
  int status;

  l1d_fd_connected = 0;
  if (l1d_debug)
    fprintf(stderr,"l1d_open() in\n");
  status = l1d_conn_direct ? l1d_open_serial_direct() : l1d_open_serial_enet();
  if (status != 0) {
    fprintf(stderr,"FATAL: can\'t open connection to L1\n");
    return -1;
  }
  if (!connect)
    return l1d_fd;

  l1d_fd_connected = 1;
  PPPInit(&ppp,ppp_ibuf,sizeof(ppp_ibuf),ppp_obuf,sizeof(ppp_obuf),0,1,IR_FRAME_PREFIX,0,
          l1d_ppperr,NULL);
  if (wfcn(l1d_fd,"\r",1) != 1) {
    fprintf(stderr,"FATAL: can\'t initiate L1 protocol, errno: %d\n",errno);
    return -1;
  }
  sleep(L1_OPEN_DELAY);
  if (wfcn(l1d_fd,"\x18",1) != 1) {
    fprintf(stderr,"FATAL: can\'t initiate L1 protocol, errno: %d\n",errno);
    return -1;
  }
  for (;;) {
    errno = 0;
    if (l1d_debug)
      fprintf(stderr,"l1d_open() waiting\n");
    status = read_byte(echo);
    if (status < 1) {
      fprintf(stderr,"FATAL: can\'t confirm L1 protocol, errno: %d\n",errno);
      return -1;
    }
    if (l1d_debug)
      fprintf(stderr,"l1d_open() read %02x, status %d, errno %d\n",(int)echo[0],status,errno);
    if (echo[0] == L1_PROTO_CHAR)
      break;
    if (prevchar == TELNET_IAC && (unsigned char)echo[0] == TELNET_WILL) {
      if (!l1d_conn_direct && l1d_serial_hostport > 4999 && l1d_serial_hostport < 5999)
        fprintf(stderr,
                "ERROR: can\'t establish a connection to the L1!\n"
                "This connection appears to be using the telnet protocol.\n"
                "You specified port %d when you probably need to use port %d instead.\n",
                l1d_serial_hostport,l1d_serial_hostport + ANNEX_RAW_OFFSET);
      else
        fprintf(stderr,
                "ERROR: can\'t establish a connection to the L1!\n"
                "This connection appears to be using the telnet protocol (usually this\n"
                "happens when specifying a 5xxx Annex port instead of a 7xxx port).\n");
      return -1;
    }
    prevchar = echo[0];
  }
  status = SocketNodelayMode(l1d_fd,1);
  if (status != 0) {
    fprintf(stderr,"FATAL: can\'t set delay mode on L1 connection, status: %d, errno: %d\n",
            status,errno);
    return -1;
  }
  EventAddInput(l1d_fd,l1d_read_packet,(EventData)0,"l1d_open");
  if (l1d_debug)
    fprintf(stderr,"l1d_open() out\n");
  return 0;
}

int l1d_close(void)
{
  int status;

  if (l1d_fd_connected) {
    EventRemoveInput(l1d_fd);
    wfcn(l1d_fd,"\r",1);
  }
  status = l1d_conn_direct ? l1d_close_serial_direct() : l1d_close_serial_enet();
  if (status != 0)
    fprintf(stderr,"FATAL: can\'t close connection to L1\n");
  return status;
}

void l1d_tty_debug(int td)
{
  struct termios termios;
  int i;

  if (tcgetattr(td,&termios) == -1) {
    fprintf(stderr,"WARNING: can\'t get termios, errno: %d\n",errno);
    return;
  }
  fprintf(stderr,"---\niflag:  0%08o\n",termios.c_iflag);
  fprintf(stderr,"oflag:  0%08o\n",termios.c_oflag);
  fprintf(stderr,"cflag:  0%08o\n",termios.c_cflag);
  fprintf(stderr,"lflag:  0%08o\n",termios.c_lflag);
  fprintf(stderr,"ispeed:  %8d\n",termios.c_ispeed);
  fprintf(stderr,"ospeed:  %8d\n",termios.c_ospeed);
  for (i = 0; i < 8; i++)
    fprintf(stderr,"cc_c[%d]: %8o\n",i,(unsigned int)termios.c_cc[i]);
}

/* open a serial device raw: 38400 8N1, hardware flow control, reads of
 * at least one byte */
int l1d_tty_open(char *device)
{
  struct termios termios;
  int td;

  td = open(device,O_RDWR);
  if (td == -1) {
    fprintf(stderr,"ERROR: can\'t open %s, errno %d\n",device,errno);
    return -1;
  }
  if (tcgetattr(td,&termios) == -1) {
    fprintf(stderr,"ERROR: can\'t get termios, errno %d.\n",errno);
    return -1;                  /* (the device stays open, as in the original) */
  }
  termios.c_iflag = IGNBRK | IGNPAR;
  termios.c_oflag = 0;
  termios.c_cflag = CRTSCTS | CLOCAL | CREAD | CS8 | B38400;
  termios.c_lflag = 0;
  termios.c_cc[VMIN] = 1;
  termios.c_cc[VTIME] = 0;
  if (tcsetattr(td,TCSANOW,&termios) == -1) {
    fprintf(stderr,"ERROR: can\'t put termios, errno %d.\n",errno);
    return -1;
  }
  return td;
}

int l1d_tty_close(int td)
{
  return close(td) == 0 ? 0 : -1;
}

/* PPPRead()'s read function */
int l1d_read_data(int fd, unsigned char *bptr, int blen)
{
  int status;

  if (l1d_debug)
    fprintf(stderr,"l1d_read_data(%d,%lx,%d) in\n",fd,(unsigned long)(uintptr_t)bptr,blen);
  errno = 0;
  status = SocketRead(fd,bptr,blen);
  if (l1d_debug) {
    fprintf(stderr,"l1d_read_data() out, status %d, errno %d\n",status,errno);
    dmp("READ",bptr,status,1);
  }
  return status;
}

/* IRouterReadPacket()'s read function: one PPP frame */
int l1d_read_ppp(int fd, uint8 **bptr, int32 blen)
{
  int status;

  if (l1d_debug)
    fprintf(stderr,"l1d_read_ppp(%d,%lx,%d) in\n",fd,(unsigned long)(uintptr_t)bptr,blen);
  status = PPPRead(&ppp,l1d_read_data,(void *)(intptr_t)fd,bptr,blen);
  if (l1d_debug)
    fprintf(stderr,"l1d_read_ppp() out\n");
  return status;
}

/* the line's input handler: a packet stops the event loop (for
 * L1DirectGetPacket()); repeated errors are counted, not repeated */
void l1d_read_packet(int port, int fd)
{
  static int lasterr;
  static int lastcnt;
  char x[80];
  IRPacket *p;
  int status;

  if (l1d_debug)
    fprintf(stderr,"l1d_read_packet(%x,%d) in\n",port,fd);
  status = IRouterReadPacket(&l1d_id,l1d_read_ppp,(void *)(intptr_t)fd,&p);
  if (status == 0) {
    if (lastcnt > 1)
      fprintf(stderr,"WARNING: last error on L1 connection repeated %d times\n",lastcnt);
    lastcnt = 0;
    lasterr = 0;
    if (p->_err != 0)
      fprintf(stderr,"WARNING: packet error %s - %s\n",format_address(p->_src),
              IRFmtError((unsigned int)p->_err));
    if (l1d_debug_irtr) {
      IRFmtPkt("L2 Read",p,x);
      fprintf(stderr,"%s\n",x);
    }
    l1d_pkt = p;
    EventStop();
  }
  else if (status == lasterr) {
    lastcnt++;
  }
  else {
    if (lastcnt > 1)
      fprintf(stderr,"WARNING: last error on L1 connection repeated %d times\n",lastcnt);
    lastcnt = 1;
    lasterr = status;
    fprintf(stderr,"WARNING: can\'t read packet on L1 connection, status: %s\n",
            LoggerDefaultMessage(status));
  }
  if (l1d_debug)
    fprintf(stderr,"l1d_read_packet() out\n");
}

/* PPPWrite()'s write function */
int l1d_write_data(int fd, unsigned char *bptr, int blen)
{
  int status;

  if (l1d_debug)
    fprintf(stderr,"l1d_write_data(%d,%lx,%d) in\n",fd,(unsigned long)(uintptr_t)bptr,blen);
  status = wfcn(fd,bptr,blen);
  if (l1d_debug) {
    dmp("WRITE",bptr,blen,1);
    fprintf(stderr,"l1d_write_data() out, status %d, errno %d\n",status,errno);
  }
  return status;
}

/* IRouterWritePacket()'s write function: one PPP frame */
int l1d_write_ppp(int fd, uint8 *bptr, int blen)
{
  int status;

  if (l1d_debug)
    fprintf(stderr,"l1d_write_ppp(%d,%lx,%d) in\n",fd,(unsigned long)(uintptr_t)bptr,blen);
  status = PPPWrite(&ppp,l1d_write_data,(void *)(intptr_t)fd,bptr,blen);
  if (l1d_debug)
    fprintf(stderr,"l1d_write_ppp() out\n");
  return status;
}

void l1d_write_packet(int fd, IRPacket *p)
{
  IRAddress addr = p->_dest;
  int status;

  if (l1d_debug)
    fprintf(stderr,"l1d_write_packet(%d, %lx) in\n",fd,(unsigned long)(uintptr_t)p);
  status = IRouterWritePacket(&l1d_id,l1d_write_ppp,(void *)(intptr_t)fd,p);
  if (status != 0)
    fprintf(stderr,"WARNING: can\'t write L1 packet %s, status: %s\n",format_address(addr),
            LoggerDefaultMessage(status));
  if (l1d_debug)
    fprintf(stderr,"l1d_write_packet() out\n");
}

/* PPP's error function. (The original took the PPPError pointer PPP
 * passes as an int error number, and printed the message for an address.) */
void l1d_ppperr(void *arg, PPPError *err)
{
  fprintf(stderr,"WARNING: PPP error %s\n",LoggerDefaultMessage(err->status));
}

static void pkt_timeout(EventData client_data)
{
  pkt_timeout_id = 0;
  EventStop();
}

/* a packet's source, for messages */
static char *format_address(IRAddress addr)
{
  static char buff[80];

  switch (IR_ADDR_TYPE(addr)) {
  case IR_ADDR_L1:
    sprintf(buff,"%03d.%02d",IR_ADDR_RACK(addr),IR_ADDR_SLOT(addr));
    /* ORIGINAL BUG: a missing break (verified in the machine code); the
     * rack.slot text is overwritten (ORIGINAL_BUGS.md) */
    /* fall through */
  case IR_ADDR_C:
    strcpy(buff,"local attached C");
    break;
  case IR_ADDR_L2:
    strcpy(buff,"L2");
    break;
  case IR_ADDR_I:
    strcpy(buff,"local attached I/O");
    break;
  case IR_ADDR_CI:
    strcpy(buff,"local attached C\'s I/O");
    break;
  default:
    sprintf(buff,"address error");
    break;
  }
  return buff;
}

/* bytes in hex, eight to a line (for --debug) */
static void dmp(char *s, unsigned char *bptr, int blen, int newline)
{
  int n;

  if (s != NULL)
    fprintf(stderr,"\n%s %lx\n",s,(unsigned long)(uintptr_t)bptr);
  for (n = 0; n < blen; n++) {
    fprintf(stderr,"%02x ",(unsigned int)bptr[n]);
    if (newline && ((n + 1) & 7) == 0)
      fprintf(stderr,"\n");
  }
  if (newline)
    fprintf(stderr,"\n");
}
