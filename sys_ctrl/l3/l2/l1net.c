/*
 * sys_ctrl/l3/l2/l1net.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l1net.c
 */

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
#include <linux/limits.h>
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
#include "l1net.h"
#include "smp.h"
#include "l2cmd.h"
#include "reqrspq.h"
#include "dest.h"
#include "../../common/sys/Cmd.h"
#include "cfg.h"
#include "format.h"
#include "serial.h"
#include "../main/nvram.h"
#include "../../common/sys/ipmi.h"
#include "l1.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

void l1net_accept(void *cd, int sd)
{
  char *ctype;
  int fd;
  int iVar1;
  char dev_name [20];
  int device;
  bool found;
  
  found = false;
  device = 0;
  if (l2_l1_conn_mode == 5) {
    ctype = "simulator";
  }
  else {
    ctype = "network";
  }
  fd = SocketAcceptUnixConnection(sd,0);
  if (fd < 0) {
    fprintf(stderr,"INFO: accept of L1 simulator connection failed\n",ctype);
  }
  else {
    fprintf(stderr,"INFO: accepted L1 %s connection\n",ctype);
    SocketSetBufferSize(fd,0x400,0x400);
    while ((!found && (device < 0x28))) {
      if (l2_l1_ports[device].fd == -1) {
        found = true;
      }
      else {
        device = device + 1;
      }
    }
    sprintf(dev_name,"<l1net %d>",device);
    if (found) {
      l2_l1_ports[device].fd = fd;
      if (l2_l1_local_port == -1) {
        l2_l1_local_port = device;
      }
      strcpy(l2_l1_ports[device].device,dev_name);
      iVar1 = L2CfgMAddPort(&L2CfgLocal,device,dev_name,"socket",3,fd);
      if (iVar1 == -1) {
        fprintf(stderr,"ERROR: device is already in use.\n");
      }
      else {
        EventAddTimeOut(0,10000,cfg_ping_l1,(EventData)device,"l1net_accept");
        EventAddInput(l2_l1_ports[device].fd,l1_read_packet,(EventData)device,"l1net_accept");
      }
    }
    else {
      fprintf(stderr,"ERROR: no device for L1 %s connection available\n",ctype);
    }
  }
  return;
}

int l1net_export(void)
{
  char *ctype;
  int sd;
  int iVar1;
  int port;
  char cmdopts [64];
  char cmd [200];
  int l1;
  
  if (l2_l1_conn_mode == 5) {
    ctype = "simulator";
  }
  else {
    ctype = "network";
  }
  port = IR_PORT_BIAS + 0x232b;
  cmdopts[0] = '\0';
  memset(cmdopts + 1,0,0x3f);
  sd = SocketExportUnixConnection(port);
  if (sd == -1) {
    fprintf(stderr,"ERROR: can\'t export L1 %s port %d\n",ctype,port,cmdopts[0]);
    iVar1 = -1;
  }
  else {
    EventAddInput(sd,l1net_accept,(EventData)0x0,"l1net_export");
    iVar1 = SocketExportInetConnection(port);
    if (iVar1 == -1) {
      fprintf(stderr,"ERROR: can\'t export L1 %s port %d\n",ctype,port,cmdopts[0]);
      iVar1 = -1;
    }
    else {
      EventAddInput(iVar1,l1net_accept,(EventData)0x0,"l1net_export");
      fprintf(stderr,"INFO: L1 %s port %d initialized\n",ctype,port);
      iVar1 = 0;
    }
  }
  return iVar1;
}

void l1net_close(int fd)
{
  int device;
  L2CfgPort *port;
  
  EventRemoveInput(fd);
  L2CfgMDeletePort(&L2CfgLocal,fd);
  SocketClose(fd);
  for (device = 0; device < 0x28; device = device + 1) {
    if (l2_l1_ports[device].fd == fd) {
      if (l2_l1_ports[device].timer != 0) {
        EventRemoveTimeOut(l2_l1_ports[device].timer);
      }
      l2_l1_ports[device].timer = 0;
      l2_l1_ports[device].fd = -1;
    }
  }
  fprintf(stderr,"INFO: closed connection L1 simulator\n");
  return;
}
