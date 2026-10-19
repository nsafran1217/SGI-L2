/*
 * sys_ctrl/common/main/EnetServer.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/main/EnetServer.c
 *
 * l2's network side: a Router server for L3 tools (the command ports) and
 * other L2s (the L2 port), and connections out to other L2s. Every
 * connection is a node in the configuration (L2Cfg.c); IRouter packets
 * arriving as Router events go to the packet callback.
 */

#include <errno.h>
#include <stdlib.h>
#include "EnetServer.h"
#include "L2Cfg.h"
#include "../IRouter/IRouter.h"
#include "../IRouter/IRouter2Router.h"
#include "../Router/Router.h"
#include "../Router/RouterCl.h"
#include "../Router/RouterMsg.h"
#include "../Router/RouterSv.h"
#include "../Router/Socket.h"
#include "../sys/Logger.h"
#include "../../l3/sys/syslogLib.h"

/* the ports, plus IR_PORT_BIAS */
#define L3_CMD_PORT         8000        /* an L3 tool */
#define L3_QUIET_PORT       8002        /* ... not logged */
#define SMP_PORT            8003        /* (not logged) */
#define L2_PEER_PORT        9001        /* another L2 */
#define L2_APP_QUIET_PORT   9004        /* (not logged) */
#define L2_PEER_BUFSIZE     0x400

#define ROUTER_PROCESS_ID   2
#define CONNECT_TIMEOUT     300

/* connect_cb's opcode (RouterCl.c, RouterSv.c) */
#define CONNECT_PASSWORD    2

RouterServer *enet_server;
uint32 enet_ip;                 /* this host's address */
IRIdent *enet_id;
static void (*enet_connect_cb)();
static void (*enet_disconnect_cb)();
static void (*enet_establish_cb)();
static int (*enet_packet_cb)();

/* the ports whose connections are not logged */
static int quiet_port(int port)
{
  return port == IR_PORT_BIAS + L3_QUIET_PORT || port == IR_PORT_BIAS + SMP_PORT ||
         port == IR_PORT_BIAS + L2_APP_QUIET_PORT;
}

static int peer_port(int port)
{
  return port == IR_PORT_BIAS + L2_PEER_PORT;
}

void EnetServerInit(IRIdent *id, void (*connect_cb)(), void (*disconnect_cb)(), void (*establish_cb)(), int (*packet_cb)())
{
  enet_id = id;
  enet_connect_cb = connect_cb;
  enet_disconnect_cb = disconnect_cb;
  enet_establish_cb = establish_cb;
  enet_packet_cb = packet_cb;
  if (SocketGetHostAddr(&enet_ip) != 0)
    syslog(2,"../../common/main/EnetServer.c",83,0,"EnetServerInit: couldn\'t get IP address for local host\n");
}

/* serve port */
void EnetServerStart(int port, int my_process_id, char *appname)
{
  int status;

  status = RouterInit(0x100,1,appname,my_process_id,NULL);
  if (status < 0) {
    syslog(2,"../../common/main/EnetServer.c",103,0,"EnetServerStart: RouterInit failed [%s]",
           LoggerDefaultMessage(status));
    return;
  }
  RouterSetFreeCB(enet_client_free);
  enet_server = RouterStartServer(port,enet_validate,NULL);
  if (enet_server == NULL)
    syslog(2,"../../common/main/EnetServer.c",115,0,"EnetServerStart: RouterStartServer failed [%s]",
           LoggerDefaultMessage(errno));
}

int EnetServerCheck(int port)
{
  return RouterCheckServer(port);
}

/* a connection (client, else ip:port) into the configuration: an L3 tool
 * on a command port, otherwise an L2 */
int enet_client_add(unsigned int ip, unsigned int port, RouterClient *client)
{
  if (client != NULL) {
    ip = client->addr;
    port = client->port;
  }
  if (port == IR_PORT_BIAS + (unsigned int)L3_CMD_PORT || port == IR_PORT_BIAS + (unsigned int)L3_QUIET_PORT)
    return L2CfgMAddL3(&L2CfgLocal,ip,client);
  return L2CfgMAddL2(&L2CfgLocal,ip,port,client,NULL);
}

/*
 * The Router server's validation of a new connection. Of two L2s that
 * connect to each other at once, the connection the higher address makes
 * wins; a connection to an L2 we are already connected to is refused (and
 * the existing one pinged), a stale one removed.
 */
int enet_validate(RouterClient *client, uint32 addr, char *host)
{
  L2CfgNode *node;

  if (!quiet_port(client->port))
    syslog(6,"../../common/main/EnetServer.c",169,0,"Validating connection from \'%s\' (%s)",host,
           SocketAddrStr(addr));
  if (peer_port(client->port)) {
    node = L2CfgMFindNode(&L2CfgLocal,client->addr,0,NULL);
    if (node != NULL && node->client != NULL) {
      if (RouterFindClient(node->client) != NULL) {
        syslog(6,"../../common/main/EnetServer.c",202,0,
               "Validation failed - connection exists to \'%s\' (%s)",host,SocketAddrStr(addr));
        RouterPing(node->client);
        return VERDICT_DENY;
      }
      syslog(4,"../../common/main/EnetServer.c",193,0,"Stale connection with \'%s\' (%s) detected, removing",
             host,SocketAddrStr(addr));
      L2CfgMDeleteNode(&L2CfgLocal,node->client);
      node = NULL;
    }
    if (node != NULL && client->addr <= enet_ip) {
      syslog(6,"../../common/main/EnetServer.c",218,0,
             "Validation failed - connection in progress to \'%s\' (%s)",host,SocketAddrStr(addr));
      return VERDICT_DENY;
    }
    enet_client_add(0,0,client);
  }
  RouterInitClient(client,CONNECT_TIMEOUT,0,enet_client_connected,enet_request,enet_event,
                   enet_client_disconnected);
  if (peer_port(client->port))
    RouterClientSetBufferSize(client,L2_PEER_BUFSIZE,L2_PEER_BUFSIZE);
  return VERDICT_ACCEPT;      /* (l2 asks no client for a password) */
}

/* the connection is up (or a client sent a password, which is ignored:
 * none is asked for) */
int enet_client_connected(RouterClient *client, int opcode, int id, int retrys, int argcountin, RouterArgument *arglistin)
{
  if (opcode == CONNECT_PASSWORD)
    return VERDICT_ACCEPT;
  if (!quiet_port(client->port))
    syslog(6,"../../common/main/EnetServer.c",291,0,"Connection - %s (%s) @ %s running \'%s\'.",
           client->id.username,client->id.fullname,client->id.hostname,client->id.procname);
  if (!peer_port(client->port))
    enet_client_add(0,0,client);
  if (enet_connect_cb != NULL)
    enet_connect_cb(client);
  return 0;
}

/* a client went away */
void enet_client_disconnected(RouterClient *client, int msgnbr, char *host, int port, int retrys)
{
  switch (msgnbr) {
  case ROUTER_ERR_LOST:
  case ROUTER_ERR_ERROR:
  case ROUTER_ERR_CLOSED_REMOTE:
    if (!quiet_port(port))
      syslog(6,"../../common/main/EnetServer.c",328,0,"Disconnection - %s (%s) @ %s running \'%s\'.",
             client->id.username,client->id.fullname,client->id.hostname,client->id.procname);
    L2CfgMDeleteNode(&L2CfgLocal,client);
    if (enet_disconnect_cb != NULL)
      enet_disconnect_cb(client);
    break;
  default:
    syslog(6,"../../common/main/EnetServer.c",343,0,
           "UNHANDLED CONNECTION ERR - %s (%s) @ %s running \'%s\'.  (%d: %s)",client->id.username,
           client->id.fullname,client->id.hostname,client->id.procname,msgnbr,
           LoggerDefaultMessage(msgnbr));
    L2CfgMDeleteNode(&L2CfgLocal,client);
    break;
  }
}

/* connect to the L2 at host:port (its node is added now) */
int EnetServerConnect(char *host, int port)
{
  uint32 ip = 0;

  if (!quiet_port(port))
    syslog(6,"../../common/main/EnetServer.c",370,0,"attempting connection to %s:%d",host,port);
  if (SocketGetAddr(host,&ip) != 0) {
    /* ORIGINAL BUG (fixed, see ORIGINAL_BUGS.md): the original omitted 'port' */
    syslog(3,"../../common/main/EnetServer.c",377,0,"could not get IP value for host %s:%d",host,port);
    return -1;
  }
  if (enet_client_add(ip,port,NULL) != 0)
    return -1;
  RouterMakeConnection(host,port,ROUTER_PROCESS_ID,CONNECT_TIMEOUT,0x100,enet_established,enet_request,
                       enet_event,enet_failure);
  return 0;
}

/* our connection to an L2 is up */
int enet_established(RouterClient *client, int opcode, RouterArgument **arglistout)
{
  if (!quiet_port(client->port))
    syslog(6,"../../common/main/EnetServer.c",423,0,"connection to %s:%d established.",client->id.hostname,
           client->port);
  if (peer_port(client->port))
    RouterClientSetBufferSize(client,L2_PEER_BUFSIZE,L2_PEER_BUFSIZE);
  enet_client_add(0,0,client);
  if (enet_establish_cb != NULL)
    enet_establish_cb(client);
  return 0;
}

/* our connection to an L2 failed or ended */
void enet_failure(RouterClient *client, int msgnbr, char *host, int port, int retrys)
{
  L2CfgNode *node;

  if (msgnbr != ROUTER_ERR_DENIED)
    syslog(6,"../../common/main/EnetServer.c",453,0,"connection to %s:%d failed: %s",host,port,
           LoggerDefaultMessage(msgnbr));
  node = L2CfgMFindNode(&L2CfgLocal,client->addr,0,NULL);
  if (node != NULL && node->client == NULL)
    node->client = client;      /* (so the node goes with the client) */
  L2CfgMDeleteNode(&L2CfgLocal,client);
  if (enet_disconnect_cb != NULL)
    enet_disconnect_cb(client);
}

/* the Router frees a client */
void enet_client_free(RouterClient *client)
{
  L2CfgNode *node;

  node = L2CfgMFindNode(&L2CfgLocal,client->addr,0,NULL);
  if (node == NULL)
    return;
  if (node->client == NULL)
    node->client = client;
  L2CfgMDeleteNode(&L2CfgLocal,client);
  if (enet_disconnect_cb != NULL)
    enet_disconnect_cb(client);
}

/* (nobody sends Router requests here) */
int enet_request(RouterClient *client, int request, int argcountin, RouterArgument *arglistin, RouterArgument **arglistout)
{
  static RouterArgument arglist[10];

  syslog(4,"../../common/main/EnetServer.c",524,0,"Router request %d (%d args) packet received from %s!",
         request,argcountin,client->id.hostname);
  *arglistout = arglist;
  return 0;
}

/* an IRouter packet from a connection: from an L3 tool's connection, its
 * source is the node's IRouter address (events keep theirs) */
void enet_event(RouterClient *client, int event, int argcountin, RouterArgument *arglistin)
{
  IRPacket *npkt;
  L2CfgNode *node;

  npkt = IRouterPacketFromRouter(argcountin,arglistin);
  if (npkt == NULL) {
    syslog(4,"../../common/main/EnetServer.c",549,0,
           "Invalid Router event %d (%d args) received (not IRouter format) from %s",event,argcountin,
           client->id.hostname);
    return;
  }
  if (!peer_port(client->port)) {
    node = L2CfgMFindNode(&L2CfgLocal,0,0,client);
    if (node == NULL) {
      syslog(4,"../../common/main/EnetServer.c",568,0,"Could not find L2 node for connected client (%s)",
             SocketAddrStr(client->addr));
      return;
    }
    if (npkt->_clas != IR_EVT)
      npkt->_src = node->ir_addr;
  }
  npkt->_external = 1;
  if (enet_packet_cb(enet_id,npkt) == IR_ERRNO(IRERR_BAD_PKT_TYPE))
    syslog(4,"../../common/main/EnetServer.c",585,0,"Invalid IRouter packet class (%d) received from %s",
           (unsigned int)npkt->_clas,client->id.hostname);
}
