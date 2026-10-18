/*
 * sys_ctrl/l3/utils/l2term.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/l2term.c
 */

#include <stdlib.h>
#include "../../common/Router/Socket.h"   /* needed by the reconstruction */
#include "../l2/l2.h"   /* needed by the reconstruction */
#include "../l2/l2cmd.h"   /* needed by the reconstruction */
#include "../l2/smp.h"   /* needed by the reconstruction */
#include "l2term.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <termio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>
#include "../api/SCapi.h"
#include "../main/SysCfg.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/Router/Router.h"
#include "../../common/Router/RouterMsg.h"
#include "../../common/Router/Event.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static int tty = 1;
static int l2 = -1;
static char host[64] = "localhost";
static int port;
static unsigned int syscon = 4294967295;
static unsigned int retries = 5;
static int tty_reconfigured;
static char *myname;
static char cmd[80];
static int c_iflag;
static int c_oflag;
static int c_lflag;
static int c_cc[32];

void input_l2(EventData data, int fd)
{
  int status;
  char *pcVar1;
  IRAddress src;
  IRPacket *p;
  
  p = NULL;
  status = sn1SCPkt(&p,0);
  if (status != -0x12f) {
    if (status < -0x12e) {
      if (status == -0x26c) {
        return;
      }
    }
    else if (status == 0) {
      if (((true) && (1 < p->_clas)) && (p->_clas == 2)) {
        SysCfgConnProcessEvent(NULL,myname,p);
      }
      IRouterFreePacket(p);
      return;
    }
    pcVar1 = LoggerDefaultMessage(status);
    fprintf(stderr,"%s: can\'t get packet on L2 connection: %s\n",myname,pcVar1);
  }
  return;
}

void read_n_write(int *wfd, int rfd)
{
  static int escaped;
  static unsigned char buff[1024];
  int *piVar1;
  int n;
  ssize_t sVar2;
  size_t __n;
  bool bVar3;
  int count;
  
  piVar1 = __errno_location();
  *piVar1 = 0;
  n = read(rfd,(void *)&buff,0x400);
  if (n < 1) {
    count = 0;
    if (rfd == 0) {
      if (n == 0) {
        fprintf(stderr,"ERROR: tty EOF\n");
      }
      else {
        piVar1 = __errno_location();
        fprintf(stderr,"WARNING: can\'t read from tty, %s\n",
                strerror(*piVar1));
      }
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    if (n == 0) {
      fprintf(stderr,"WARNING: connection to L2 %s:%d lost...\n",host,port);
    }
    else {
      piVar1 = __errno_location();
      fprintf(stderr,"WARNING: can\'t read from L2, %s\n",strerror(*piVar1)
             );
    }
    SocketClose(l2);
    EventRemoveInput(l2);
    tty_reconfig();
    do {
      l2 = SocketMakeInetConnection(host,port,0);
      if (l2 < 0) {
        fprintf(stderr,"INFO: can\'t reconnect to L2 %s:%d - will retry, <ctrl-c> to quit\n",host,
                port);
        sleep(5);
      }
    } while ((l2 < 0) && (bVar3 = (unsigned int)count < retries, count = count + 1, bVar3));
    if (l2 < 0) {
      fprintf(stderr,"ERROR: can\'t reconnect to L2 %s:%d, giving up!\n",host,port);
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
    tty_config();
    EventAddInput(l2,read_n_write,(EventData)&tty,NULL);
    fprintf(stderr,"INFO: reconnected to L2 %s:%d, to quit enter <ctrl-]> <q>\n",host,port);
    if (syscon != 0xffffffff) {
      __n = strlen(cmd);
      write(l2,cmd,__n);
    }
  }
  else {
    if (rfd == 0) {
      if (((n == 1) && (buff[0] == '\x1d')) && (escaped == 0)) {
        escaped = 1;
        return;
      }
      if (((escaped == 0) || (n != 1)) || (buff[0] != 'q')) {
        if (escaped != 0) {
          write(l2,"\035",1);   /* pass the escape (CTRL-]) through */
          escaped = 0;
        }
      }
      else {
        cleanup();
      }
    }
    sVar2 = write(*wfd,(void *)&buff,n);
    if (sVar2 != n) {
      if (wfd == &tty) {
        piVar1 = __errno_location();
        fprintf(stderr,"WARNING: can\'t write to tty, %s\n",
                strerror(*piVar1));
      }
      else {
        piVar1 = __errno_location();
        fprintf(stderr,"WARNING: can\'t write to L2, %s\n",
                strerror(*piVar1));
      }
    }
  }
  return;
}

void syntax(char *opt)
{
  char *pcVar1;
  
  if (opt != NULL) {
    fprintf(stderr,"ERROR: bad option %s\n",opt);
  }
  fprintf(stderr,
          "usage: %s [-syscon <partition>] [sysco options]\n              -syscon|-s   start in system console mode, <partition> optional\n"
          ,myname);
  pcVar1 = sn1SCUsage();
  fprintf(stderr,"System Controller command options\n%s\n",pcVar1);
                    /* WARNING: Subroutine does not return */
  exit(-1);
}

void tty_debug(void)
{
  int iVar1;
  int *piVar2;
  struct termios termios;
  int i;
  
  iVar1 = tcgetattr(0,(struct termios *)&termios);
  if (iVar1 == -1) {
    piVar2 = __errno_location();
    fprintf(stderr,"ERROR: can\'t get termios, errno: %d.\n",*piVar2);
  }
  else {
    fprintf(stderr,"---\niflag:  0%08o\n",termios.c_iflag);
    fprintf(stderr,"oflag:  0%08o\n",termios.c_oflag);
    fprintf(stderr,"cflag:  0%08o\n",termios.c_cflag);
    fprintf(stderr,"lflag:  0%08o\n",termios.c_lflag);
    fprintf(stderr,"ispeed:  %8d\n",termios.c_ispeed);
    fprintf(stderr,"ospeed:  %8d\n",termios.c_ospeed);
    for (i = 0; i < 8; i = i + 1) {
      fprintf(stderr,"cc_c[%d]: %8o\n",i,(unsigned int)termios.c_cc[i]);
    }
  }
  return;
}

int tty_config(void)
{
  int iVar1;
  int *piVar2;
  struct termios termios;
  
  iVar1 = tcgetattr(0,(struct termios *)&termios);
  if (iVar1 == -1) {
    piVar2 = __errno_location();
    fprintf(stderr,"ERROR: can\'t get termios, errno: %d\n",*piVar2);
    iVar1 = -1;
  }
  else {
    c_iflag = termios.c_iflag;
    c_oflag = termios.c_oflag;
    c_lflag = termios.c_lflag;
    memcpy(c_cc,termios.c_cc,0x20);
    termios.c_iflag = (termios.c_iflag & 0xffffe83f) | 0x20;
    termios.c_oflag = (termios.c_oflag & 0xfffffffb) | 1;
    termios.c_lflag = termios.c_lflag & 0xfffffff5;
    termios.c_cc[0] = '\0';
    termios.c_cc[10] = '\0';
    termios.c_cc[6] = '\x01';
    iVar1 = tcsetattr(0,0,(struct termios *)&termios);
    if (iVar1 == -1) {
      piVar2 = __errno_location();
      fprintf(stderr,"ERROR: can\'t set termios, errno: %d\n",*piVar2);
      iVar1 = -1;
    }
    else {
      tty_reconfigured = 1;
      iVar1 = 0;
    }
  }
  return iVar1;
}

void tty_reconfig(void)
{
  int iVar1;
  int *piVar2;
  struct termios termios;
  
  if (tty_reconfigured != 0) {
    iVar1 = tcgetattr(0,(struct termios *)&termios);
    if (iVar1 == -1) {
      piVar2 = __errno_location();
      fprintf(stderr,"ERROR: can\'t get termios, errno: %d.\n",*piVar2);
    }
    else {
      termios.c_iflag = c_iflag;
      termios.c_oflag = c_oflag;
      termios.c_lflag = c_lflag;
      memcpy(termios.c_cc,c_cc,0x20);
      iVar1 = tcsetattr(0,0,(struct termios *)&termios);
      if (iVar1 == -1) {
        piVar2 = __errno_location();
        fprintf(stderr,"ERROR: can\'t set termios, errno; %d.\n",*piVar2);
      }
    }
    tty_reconfigured = 0;
  }
  return;
}

void cleanup(void)
{
  tty_reconfig();
                    /* WARNING: Subroutine does not return */
  exit(-1);
}

int main(int argc, char **argv, char **envp)
{
  int iVar1;
  L2CfgNode *l2node;
  char *pcVar2;
  size_t __n;
  int rack;
  int slot;
  uint32 addr;
  IRAddress caddress;
  int sd;
  int serial;
  struct sigaction sa;
  
  serial = 0;
  myname = *argv;
  iVar1 = sn1SCParseCmdline(&argc,argv,&serial);
  if (iVar1 < 0) {
    fprintf(stderr,"ERROR: command line parse problems\n");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  if (serial != 0) {
    fprintf(stderr,"ERROR: direct serial connection not supported\n");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  iVar1 = sn1SCIsQuiet();
  if (iVar1 == 0) {
    port = IR_PORT_BIAS + 0x1f41;
  }
  else {
    port = IR_PORT_BIAS + 0x1f43;
  }
  while (argc = argc + -1, argc != 0) {
    argv = argv + 1;
    iVar1 = strcmp(*argv,"-syscon");
    if ((iVar1 == 0) || (iVar1 = strcmp(*argv,"-s"), iVar1 == 0)) {
      retries = 0xffffffff;
      if (argc < 2) {
        syscon = 0;
      }
      else {
        syscon = atoi(argv[1]);
        argc = argc + -1;
        argv = argv + 1;
      }
    }
    else {
      iVar1 = strcmp(*argv,"-h");
      if (iVar1 == 0) {
        if (1 < argc) {
          argc = argc + -1;
          argv = argv + 1;
        }
      }
      else {
        iVar1 = strcmp(*argv,"-p");
        if (iVar1 != 0) {
          syntax(*argv);
        }
      }
    }
  }
  iVar1 = sn1SCFindL2(host);
  if (iVar1 < 0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  if (syscon != 0xffffffff) {
    sn1SCUseQuiet();
    sn1SCInit(myname,NULL,4);
    SysCfgConnInit(NULL,myname);
    caddress = L2CfgMGetConsole(&L2CfgLocal,syscon);
    if (caddress == 0) {
      if (syscon == 0) {
        fprintf(stderr,"WARNING: current configuration shows no console.\n");
      }
      else {
        fprintf(stderr,"WARNING: current configuration shows no partition %d console.\n",syscon);
      }
      fprintf(stderr,"WARNING: request to enter system console mode denied.\n");
      syscon = 0xffffffff;
    }
    else {
      rack = caddress >> 0x12 & 0x3ff;
      slot = caddress >> 0xc & 0x3f;
      l2node = L2CfgMFindBrickL2(&L2CfgLocal,rack,slot);
      if (l2node == NULL) {
        fprintf(stderr,"ERROR: no L2 for console at %03d.%02d\n",rack,slot);
                    /* WARNING: Subroutine does not return */
        exit(-1);
      }
      iVar1 = SocketGetAddr(host,&addr);
      if ((iVar1 == 0) && (addr != l2node->ip_addr)) {
        if (syscon == 0) {
          pcVar2 = inet_ntoa(*(struct in_addr *)&l2node->ip_addr);
          fprintf(stderr,"INFO: system console for is at L2 %04d (%s) - redirecting...\n",
                  L2CFG_OF(l2node)->rack,pcVar2);
        }
        else {
          pcVar2 = inet_ntoa(*(struct in_addr *)&l2node->ip_addr);
          fprintf(stderr,
                  "INFO: system console for partition %d is at L2 %04d (%s) - redirecting...\n",
                  syscon,L2CFG_OF(l2node)->rack,pcVar2);
        }
      }
      pcVar2 = inet_ntoa(*(struct in_addr *)&l2node->ip_addr);
      strcpy(host,pcVar2);
    }
    sn1SCDisconnect();
  }
  l2 = SocketMakeInetConnection(host,port,0);
  if (-1 < l2) {
    fprintf(stderr,"INFO: connection established to %s, to quit enter <ctrl-]> <q>\n",host);
    EventAddInput(l2,read_n_write,(EventData)&tty,NULL);
    tty_config();
    if (syscon != 0xffffffff) {
      if (syscon == 0) {
        sprintf(cmd,"\r\r\x04");
      }
      else {
        sprintf(cmd,"\r\rselect partition %d\r\x04",syscon);
      }
      __n = strlen(cmd);
      write(l2,cmd,__n);
    }
    EventAddInput(0,read_n_write,(EventData)&l2,NULL);
    EventStart();
    cleanup();          /* exits */
    return 0;
  }
  fprintf(stderr,"ERROR: can\'t connection to %s:%d\n",host,port);
                    /* WARNING: Subroutine does not return */
  exit(-1);
}
