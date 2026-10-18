/*
 * sys_ctrl/l3/l2/enet.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/enet.c
 */

#include <linux/limits.h>
#include "l2.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
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
#include <stdint.h>
#include "../../common/sys/sysutils.h"
#include <pthread.h>
#include <sched.h>
#include "../../common/sys/Logger.h"
#include "../sys/LoggerMsg.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../../common/Router/Router.h"
#include "../../common/sys/PPP.h"
#include "../../common/sys/brick_types.h"
#include "../../common/main/EnetServer.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/main/L1Cfg.h"
#include "l2_rev.h"
#include "enet.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int enet_only;
SMP *enet_smp;
static IRIdent ids[256];

void enet_init(void)
{
  memset(ids,0,0x800);
  enet_export(IR_PORT_BIAS + 0x1f41);
  enet_export(IR_PORT_BIAS + 0x1f43);
  return;
}

void enet_export(int port)
{
  int fd;
  
  fd = SocketExportInetConnection(port);
  if (fd < 0) {
    printf("FATAL: can\'t export connection for SMP port %d\n",port);
    exit(1);
  }
  fprintf(stderr,"INFO: SMP listening on port: %d\n",port);
  EventAddInput(fd,enet_accept,(EventData)(intptr_t)port,"enet_export");
  return;
}

void enet_accept(int port, int sd)
{
  IRIdent *id_00;
  int s;
  int iVar1;
  char *pcVar2;
  uint32 peer_addr;
  char peer_name [256];
  IRIdent *id;
  
  s = SocketAcceptInetConnection(sd,1);
  if (s < 0) {
    fprintf(stderr,"INFO: SMP failed to accept netwok connection\n");
  }
  else {
    iVar1 = SocketGetPeerAddr(s,&peer_addr);
    if (iVar1 == 0) {
      iVar1 = SocketGetName(peer_addr,peer_name,0x100);
      if (iVar1 != 0) {
        strcpy(peer_name,"unknown");
      }
    }
    else {
      peer_addr = 0xffffffff;
      strcpy(peer_name,"unknown");
    }
    if (port != IR_PORT_BIAS + 0x1f43) {
      iVar1 = port;
      pcVar2 = SocketAddrStr(peer_addr);
      fprintf(stderr,"INFO: SMP accepted network connection, %s (%s:%d)\n",peer_name,pcVar2,iVar1);
    }
    id_00 = ids + s;
    IRouterInitID(id_00,0,0);
    id_00->addr = (id_00->addr & 0x3fffffff) | 0xc0000000;
    id_00->addr = (id_00->addr & 0xc0ffffff) | (s & 0x3fU) << 0x18;
    smp_init(id_00,s,s,enet_reset,peer_addr,port);
  }
  return;
}

void enet_reset(int sd)
{
  if (sd != -1) {
    SocketClose(sd);
  }
  return;
}
