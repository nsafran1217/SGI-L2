/*
 * sys_ctrl/l3/l2/enet.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/enet.c
 *
 * The L2's network consoles: telnet-style SMP sessions on SMP_PORT, and on
 * SMP_QUIET_PORT for connections that are not logged.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "enet.h"
#include "smp.h"

#define IR_IP_L3    0xc0000000  /* an L3 client's IRouter address: | its L2's, task = socket */
#define MAX_SOCKETS 256         /* ids[] is indexed by the socket */

int enet_only;                  /* -enet: no serial consoles (serial.c) */
SMP *enet_smp;
static IRIdent ids[MAX_SOCKETS];

void enet_init(void)
{
  memset(ids,0,sizeof(ids));
  enet_export(IR_PORT_BIAS + SMP_PORT);
  enet_export(IR_PORT_BIAS + SMP_QUIET_PORT);
}

/* listen on port; exits if it can't */
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
}

/* a connection on port's listening socket sd: an SMP session, addressed as
 * an L3 client with its socket as the task */
void enet_accept(int port, int sd)
{
  char peer_name[256];
  uint32 peer_addr;
  IRIdent *id;
  int s;

  s = SocketAcceptInetConnection(sd,1);
  if (s < 0) {
    fprintf(stderr,"INFO: SMP failed to accept netwok connection\n");
    return;
  }
  if (s >= MAX_SOCKETS) {
    /* (the original wrote past ids[]) */
    fprintf(stderr,"INFO: SMP refused network connection, too many open files\n");
    SocketClose(s);
    return;
  }
  if (SocketGetPeerAddr(s,&peer_addr) != 0) {
    peer_addr = 0xffffffff;
    strcpy(peer_name,"unknown");
  }
  else if (SocketGetName(peer_addr,peer_name,sizeof(peer_name)) != 0)
    strcpy(peer_name,"unknown");
  if (port != IR_PORT_BIAS + SMP_QUIET_PORT)
    fprintf(stderr,"INFO: SMP accepted network connection, %s (%s:%d)\n",peer_name,
            SocketAddrStr(peer_addr),port);
  id = &ids[s];
  IRouterInitID(id,s,0);
  id->addr |= IR_IP_L3;
  smp_init(id,s,s,enet_reset,peer_addr,port);
}

/* an SMP's reset function: close its socket */
void enet_reset(int sd)
{
  if (sd != -1)
    SocketClose(sd);
}
