/*
 * sys_ctrl/l3/utils/l2term.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/l2term.c
 *
 * l2term: a terminal on an L2's console (its SMP port, smp.c). The tty is
 * raw; CTRL-] q quits. -syscon [<partition>] starts in system console mode
 * on the L2 that has that console, reconnecting if the connection drops.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include "l2term.h"
#include "../api/SCapi.h"
#include "../main/SysCfg.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/Router/Event.h"
#include "../../common/Router/RouterMsg.h"
#include "../../common/Router/Socket.h"
#include "../../common/sys/Logger.h"

#define SMP_PORT        8001    /* plus IR_PORT_BIAS (smp.h) */
#define SMP_QUIET_PORT  8003
#define ESCAPE          0x1d    /* CTRL-] */
#define NO_SYSCON       0xffffffff

static int tty = 1;
static int l2 = -1;
static char host[64] = "localhost";
static int port;
static unsigned int syscon = NO_SYSCON;  /* -syscon's partition */
static unsigned int retries = 5;        /* reconnections (-syscon: for ever) */
static int tty_reconfigured;
static char *myname;
static char cmd[80];                    /* what puts the L2 into console mode */
static struct termios saved;            /* the tty's settings before */

/* a packet on a Router connection to the L2: configuration events */
void input_l2(EventData data, int fd)
{
  IRPacket *p = NULL;
  int status;

  status = sn1SCPkt(&p,0);
  if (status == ROUTER_ERR_LOST || status == IR_ERRNO(IRERR_TIMEOUT))
    return;
  if (status != 0) {
    fprintf(stderr,"%s: can\'t get packet on L2 connection: %s\n",myname,LoggerDefaultMessage(status));
    return;
  }
  if (p->_clas == IR_EVT)
    SysCfgConnProcessEvent(NULL,myname,p);
  IRouterFreePacket(p);
}

/* connect again after the L2 went (sleeping 5 seconds between tries) */
static void reconnect(void)
{
  unsigned int count = 0;

  SocketClose(l2);
  EventRemoveInput(l2);
  tty_reconfig();
  for (;;) {
    l2 = SocketMakeInetConnection(host,port,0);
    if (l2 >= 0)
      break;
    fprintf(stderr,"INFO: can\'t reconnect to L2 %s:%d - will retry, <ctrl-c> to quit\n",host,port);
    sleep(5);
    if (count++ >= retries) {
      fprintf(stderr,"ERROR: can\'t reconnect to L2 %s:%d, giving up!\n",host,port);
      exit(-1);
    }
  }
  tty_config();
  EventAddInput(l2,read_n_write,(EventData)&tty,NULL);
  fprintf(stderr,"INFO: reconnected to L2 %s:%d, to quit enter <ctrl-]> <q>\n",host,port);
  if (syscon != NO_SYSCON)
    write(l2,cmd,strlen(cmd));
}

/* copy what rfd has (the tty or the L2) to *wfd; CTRL-] q from the tty
 * quits (CTRL-] and anything else are passed on) */
void read_n_write(int *wfd, int rfd)
{
  static unsigned char buff[1024];
  static int escaped;
  int n;

  errno = 0;
  n = read(rfd,buff,sizeof(buff));
  if (n < 1) {
    if (rfd == 0) {
      if (n == 0)
        fprintf(stderr,"ERROR: tty EOF\n");
      else
        fprintf(stderr,"WARNING: can\'t read from tty, %s\n",strerror(errno));
      exit(0);
    }
    if (n == 0)
      fprintf(stderr,"WARNING: connection to L2 %s:%d lost...\n",host,port);
    else
      fprintf(stderr,"WARNING: can\'t read from L2, %s\n",strerror(errno));
    reconnect();
    return;
  }
  if (rfd == 0) {
    if (n == 1 && buff[0] == ESCAPE && !escaped) {
      escaped = 1;
      return;
    }
    if (escaped && n == 1 && buff[0] == 'q')
      cleanup();
    if (escaped) {
      write(l2,"\035",1);   /* pass the escape (CTRL-]) through */
      escaped = 0;
    }
  }
  if (write(*wfd,buff,n) != n)
    fprintf(stderr,wfd == &tty ? "WARNING: can\'t write to tty, %s\n" : "WARNING: can\'t write to L2, %s\n",
            strerror(errno));
}

void syntax(char *opt)
{
  if (opt != NULL)
    fprintf(stderr,"ERROR: bad option %s\n",opt);
  fprintf(stderr,"usage: %s [-syscon <partition>] [sysco options]\n"
                 "              -syscon|-s   start in system console mode, <partition> optional\n",myname);
  fprintf(stderr,"System Controller command options\n%s\n",sn1SCUsage());
  exit(-1);
}

void tty_debug(void)
{
  struct termios termios;
  int i;

  if (tcgetattr(0,&termios) == -1) {
    fprintf(stderr,"ERROR: can\'t get termios, errno: %d.\n",errno);
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

/* the tty raw (no echo, no line editing), its settings kept */
int tty_config(void)
{
  struct termios termios;

  if (tcgetattr(0,&termios) == -1) {
    fprintf(stderr,"ERROR: can\'t get termios, errno: %d\n",errno);
    return -1;
  }
  saved = termios;
  termios.c_iflag = (termios.c_iflag & ~(INLCR | IGNCR | ICRNL | IUCLC | IXON | IXOFF)) | ISTRIP;
  termios.c_oflag = (termios.c_oflag & ~ONLCR) | OPOST;
  termios.c_lflag &= ~(ICANON | ECHO);
  termios.c_cc[VINTR] = 0;
  termios.c_cc[VSUSP] = 0;
  termios.c_cc[VMIN] = 1;
  if (tcsetattr(0,TCSANOW,&termios) == -1) {
    fprintf(stderr,"ERROR: can\'t set termios, errno: %d\n",errno);
    return -1;
  }
  tty_reconfigured = 1;
  return 0;
}

/* the tty's settings back (all but the control flags and speeds) */
void tty_reconfig(void)
{
  struct termios termios;

  if (!tty_reconfigured)
    return;
  if (tcgetattr(0,&termios) == -1)
    fprintf(stderr,"ERROR: can\'t get termios, errno: %d.\n",errno);
  else {
    termios.c_iflag = saved.c_iflag;
    termios.c_oflag = saved.c_oflag;
    termios.c_lflag = saved.c_lflag;
    memcpy(termios.c_cc,saved.c_cc,sizeof(termios.c_cc));
    if (tcsetattr(0,TCSANOW,&termios) == -1)
      fprintf(stderr,"ERROR: can\'t set termios, errno; %d.\n",errno);
  }
  tty_reconfigured = 0;
}

void cleanup(void)
{
  tty_reconfig();
  exit(-1);
}

/* -syscon: the L2 that has the partition's console (from the
 * configuration), into host; NO_SYSCON if there is no console */
static void find_console_l2(void)
{
  IRAddress caddress;
  L2CfgNode *l2node;
  uint32 addr;
  int rack;
  int slot;

  sn1SCUseQuiet();
  sn1SCInit(myname,NULL,4);
  SysCfgConnInit(NULL,myname);
  caddress = L2CfgMGetConsole(&L2CfgLocal,syscon);
  if (caddress == 0) {
    if (syscon == 0)
      fprintf(stderr,"WARNING: current configuration shows no console.\n");
    else
      fprintf(stderr,"WARNING: current configuration shows no partition %d console.\n",syscon);
    fprintf(stderr,"WARNING: request to enter system console mode denied.\n");
    syscon = NO_SYSCON;
    sn1SCDisconnect();
    return;
  }
  rack = IR_ADDR_RACK(caddress);
  slot = IR_ADDR_SLOT(caddress);
  l2node = L2CfgMFindBrickL2(&L2CfgLocal,rack,slot);
  if (l2node == NULL) {
    fprintf(stderr,"ERROR: no L2 for console at %03d.%02d\n",rack,slot);
    exit(-1);
  }
  if (SocketGetAddr(host,&addr) == 0 && addr != l2node->ip_addr) {
    if (syscon == 0)
      fprintf(stderr,"INFO: system console for is at L2 %04d (%s) - redirecting...\n",L2CFG_OF(l2node)->rack,
              inet_ntoa(*(struct in_addr *)&l2node->ip_addr));
    else
      fprintf(stderr,"INFO: system console for partition %d is at L2 %04d (%s) - redirecting...\n",syscon,
              L2CFG_OF(l2node)->rack,inet_ntoa(*(struct in_addr *)&l2node->ip_addr));
  }
  strcpy(host,inet_ntoa(*(struct in_addr *)&l2node->ip_addr));
  sn1SCDisconnect();
}

int main(int argc, char **argv, char **envp)
{
  int serial = 0;
  int i;

  myname = argv[0];
  if (sn1SCParseCmdline(&argc,argv,&serial) < 0) {
    fprintf(stderr,"ERROR: command line parse problems\n");
    exit(-1);
  }
  if (serial) {
    fprintf(stderr,"ERROR: direct serial connection not supported\n");
    exit(-1);
  }
  port = IR_PORT_BIAS + (sn1SCIsQuiet() ? SMP_QUIET_PORT : SMP_PORT);
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i],"-syscon") == 0 || strcmp(argv[i],"-s") == 0) {
      retries = (unsigned int)-1;
      /* (the next argument is the partition, whatever it is) */
      syscon = i + 1 < argc ? (unsigned int)atoi(argv[++i]) : 0;
    }
    else if (strcmp(argv[i],"-h") == 0) {
      if (i + 1 < argc)
        i++;                    /* (left by the system controller options) */
    }
    else if (strcmp(argv[i],"-p") != 0)
      syntax(argv[i]);
  }
  if (sn1SCFindL2(host) < 0)
    exit(-1);
  if (syscon != NO_SYSCON)
    find_console_l2();
  l2 = SocketMakeInetConnection(host,port,0);
  if (l2 < 0) {
    fprintf(stderr,"ERROR: can\'t connection to %s:%d\n",host,port);
    exit(-1);
  }
  fprintf(stderr,"INFO: connection established to %s, to quit enter <ctrl-]> <q>\n",host);
  EventAddInput(l2,read_n_write,(EventData)&tty,NULL);
  tty_config();
  if (syscon != NO_SYSCON) {
    if (syscon == 0)
      sprintf(cmd,"\r\r\x04");
    else
      sprintf(cmd,"\r\rselect partition %d\r\x04",syscon);
    write(l2,cmd,strlen(cmd));
  }
  EventAddInput(0,read_n_write,(EventData)&l2,NULL);
  EventStart();
  cleanup();                    /* exits */
  return 0;
}
