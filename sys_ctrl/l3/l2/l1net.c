/*
 * sys_ctrl/l3/l2/l1net.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l1net.c
 *
 * L1s over a socket instead of USB ("-net", which SGI's L1 simulator
 * used): they connect to L1NET_PORT, locally or over TCP, and each
 * connection becomes one of the L2's L1 ports.
 */

#include <stdio.h>
#include <string.h>
#include "l2.h"
#include "l1net.h"
#include "l1.h"
#include "cfg.h"

#define L1NET_PORT  9003        /* plus IR_PORT_BIAS */

/* a connection on the listening socket sd: give it a free L1 port */
void l1net_accept(void *cd, int sd)
{
  char dev_name[20];
  int device;
  int fd;

  fd = SocketAcceptUnixConnection(sd,0);    /* (accept(), for the TCP socket too) */
  if (fd < 0) {
    fprintf(stderr,"INFO: accept of L1 simulator connection failed\n");
    return;
  }
  fprintf(stderr,"INFO: accepted L1 network connection\n");
  SocketSetBufferSize(fd,0x400,0x400);
  for (device = 0; device < L2_L1_PORTS && l2_l1_ports[device].fd != -1; device++)
    ;
  if (device == L2_L1_PORTS) {
    fprintf(stderr,"ERROR: no device for L1 network connection available\n");
    SocketClose(fd);            /* (the original left it open) */
    return;
  }
  sprintf(dev_name,"<l1net %d>",device);
  l2_l1_ports[device].fd = fd;
  if (l2_l1_local_port == -1)
    l2_l1_local_port = device;
  strcpy(l2_l1_ports[device].device,dev_name);
  if (L2CfgMAddPort(&L2CfgLocal,device,dev_name,"socket",3,fd) == -1) {
    fprintf(stderr,"ERROR: device is already in use.\n");
    return;
  }
  EventAddTimeOut(0,10000,cfg_ping_l1,(EventData)(intptr_t)device,"l1net_accept");
  EventAddInput(fd,l1_read_packet,(EventData)(intptr_t)device,"l1net_accept");
}

/* listen on L1NET_PORT, as a local socket and on TCP; -1 if either fails */
int l1net_export(void)
{
  int port = IR_PORT_BIAS + L1NET_PORT;
  int sd;

  sd = SocketExportUnixConnection(port);
  if (sd == -1) {
    fprintf(stderr,"ERROR: can\'t export L1 network port %d\n",port);
    return -1;
  }
  EventAddInput(sd,l1net_accept,NULL,"l1net_export");
  sd = SocketExportInetConnection(port);
  if (sd == -1) {
    fprintf(stderr,"ERROR: can\'t export L1 network port %d\n",port);
    return -1;
  }
  EventAddInput(sd,l1net_accept,NULL,"l1net_export");
  fprintf(stderr,"INFO: L1 network port %d initialized\n",port);
  return 0;
}

/* an L1 connection closed: free its port */
void l1net_close(int fd)
{
  int device;

  EventRemoveInput(fd);
  L2CfgMDeletePort(&L2CfgLocal,fd);
  SocketClose(fd);
  for (device = 0; device < L2_L1_PORTS; device++) {
    if (l2_l1_ports[device].fd != fd)
      continue;
    if (l2_l1_ports[device].timer != 0)
      EventRemoveTimeOut(l2_l1_ports[device].timer);
    l2_l1_ports[device].timer = 0;
    l2_l1_ports[device].fd = -1;
  }
  fprintf(stderr,"INFO: closed connection L1 simulator\n");
}
