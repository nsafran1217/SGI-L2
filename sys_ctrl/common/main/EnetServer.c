/*
 * sys_ctrl/common/main/EnetServer.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/main/EnetServer.c
 */

#include "../Router/RouterCl.h"   /* needed by the reconstruction */
#include "../Router/RouterSv.h"   /* needed by the reconstruction */
#include "../../l3/l2/l2.h"   /* needed by the reconstruction */
#include "../../l3/sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include "EnetServer.h"
#include "../IRouter/IRouter.h"
#include "../sys/sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../sys/sysutils.h"
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include "../sys/Logger.h"
#include "../../l3/sys/LoggerMsg.h"
#include "../IRouter/IRouter2Router.h"
#include "../Router/Router.h"
#include "../sys/syslog.h"
#include <stdarg.h>
#include "../../l3/IRouter/IRouterL3.h"
#include "L2Cfg.h"
#include "../sys/brick_types.h"
#include "L1Cfg.h"
#include "../Router/RouterMsg.h"
#include "../Router/Socket.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

RouterServer *enet_server;
long unsigned int enet_ip;
IRIdent *enet_id;
static int (*enet_password_cb)();
static void (*enet_connect_cb)();
static void (*enet_disconnect_cb)();
static void (*enet_establish_cb)();
static int (*enet_packet_cb)();

void EnetServerInit(IRIdent *id, int (*password_cb)(), void (*connect_cb)(), void (*disconnect_cb)(), void (*establish_cb)(), int (*packet_cb)())
{
  int iVar1;
  
  enet_id = id;
  enet_password_cb = password_cb;
  enet_connect_cb = connect_cb;
  enet_disconnect_cb = disconnect_cb;
  enet_establish_cb = establish_cb;
  enet_packet_cb = packet_cb;
  iVar1 = SocketGetHostAddr(&enet_ip);
  if (iVar1 != 0) {
    syslog(2,"../../common/main/EnetServer.c",0x53,0,
           "EnetServerInit: couldn\'t get IP address for local host\n");
  }
  return;
}

void EnetServerStart(int port, int my_process_id, char *appname)
{
  int status;
  char *pcVar1;
  int *piVar2;
  int limit;
  
  status = RouterInit(0x100,1,appname,my_process_id,NULL);
  if (status < 0) {
    pcVar1 = LoggerDefaultMessage(status);
    syslog(2,"../../common/main/EnetServer.c",0x67,0,"EnetServerStart: RouterInit failed [%s]",
           pcVar1);
  }
  else {
    RouterSetFreeCB(enet_client_free);
    enet_server = RouterStartServer(port,enet_validate,NULL);
    if (enet_server == NULL) {
      piVar2 = __errno_location();
      pcVar1 = LoggerDefaultMessage(*piVar2);
      syslog(2,"../../common/main/EnetServer.c",0x73,0,
             "EnetServerStart: RouterStartServer failed [%s]",pcVar1);
    }
  }
  return;
}

int EnetServerCheck(int port)
{
  int iVar1;
  
  iVar1 = RouterCheckServer(port);
  return iVar1;
}

int enet_client_add(unsigned int ip, unsigned int port, RouterClient *client)
{
  int rval;
  
  if (client != NULL) {
    ip = client->addr;
    port = client->port;
  }
  if ((port == IR_PORT_BIAS + 8000U) || (port == IR_PORT_BIAS + 0x1f42U)) {
    rval = L2CfgMAddL3(&L2CfgLocal,ip,client);
  }
  else {
    rval = L2CfgMAddL2(&L2CfgLocal,ip,port,client,NULL);
  }
  return rval;
}

int enet_validate(RouterClient *client, long unsigned int addr, char *host)
{
  char *pcVar1;
  RouterClient *pRVar2;
  int iVar3;
  RouterClient *cdel;
  uchar *ap;
  L2CfgNode *node;
  
  if (((client->port != IR_PORT_BIAS + 0x1f42) && (client->port != IR_PORT_BIAS + 0x1f43)) &&
     (client->port != IR_PORT_BIAS + 0x232c)) {
    pcVar1 = SocketAddrStr(addr);
    syslog(6,"../../common/main/EnetServer.c",0xa9,0,"Validating connection from \'%s\' (%s)",host,
           pcVar1);
  }
  if (client->port == IR_PORT_BIAS + 0x2329) {
    node = L2CfgMFindNode(&L2CfgLocal,client->addr,0,NULL);
    if (node != NULL) {
      if (node->client != NULL) {
        pRVar2 = RouterFindClient(node->client);
        if (pRVar2 != NULL) {
          pcVar1 = SocketAddrStr(addr);
          syslog(6,"../../common/main/EnetServer.c",0xca,0,
                 "Validation failed - connection exists to \'%s\' (%s)",host,pcVar1);
          RouterPing(node->client);
          return 3;
        }
        pcVar1 = SocketAddrStr(addr);
        syslog(4,"../../common/main/EnetServer.c",0xc1,0,
               "Stale connection with \'%s\' (%s) detected, removing",host,pcVar1);
        L2CfgMDeleteNode(&L2CfgLocal,node->client);
        node = NULL;
      }
      if ((node != NULL) && (client->addr <= enet_ip)) {
        pcVar1 = SocketAddrStr(addr);
        syslog(6,"../../common/main/EnetServer.c",0xda,0,
               "Validation failed - connection in progress to \'%s\' (%s)",host,pcVar1);
        return 3;
      }
    }
    enet_client_add(0,0,client);
  }
  RouterInitClient(client,300,0,enet_client_connected,enet_request,enet_event,
                   enet_client_disconnected);
  if (client->port == IR_PORT_BIAS + 0x2329) {
    RouterClientSetBufferSize(client,0x400,0x400);
  }
  if ((enet_password_cb != NULL) &&
     (iVar3 = (*enet_password_cb)(client,0), iVar3 != 0)) {
    return 2;
  }
  return 1;
}

int enet_client_connected(RouterClient *client, int opcode, int id, int retrys, int argcountin, RouterArgument *arglistin)
{
  int iVar1;
  
  if (opcode == 2) {
    if (enet_password_cb == NULL) {
      iVar1 = 1;
    }
    else if (arglistin->clas == 1) {
      iVar1 = (*enet_password_cb)(client,arglistin->val);
      if (iVar1 == 0) {
        iVar1 = 1;
      }
      else if (retrys < 2) {
        iVar1 = 2;
      }
      else {
        iVar1 = 3;
      }
    }
    else {
      iVar1 = 2;
    }
  }
  else {
    if (((client->port != IR_PORT_BIAS + 0x1f42) && (client->port != IR_PORT_BIAS + 0x1f43)) &&
       (client->port != IR_PORT_BIAS + 0x232c)) {
      syslog(6,"../../common/main/EnetServer.c",0x123,0,"Connection - %s (%s) @ %s running \'%s\'.",
             (client->id).username,(client->id).fullname,&client->id,(client->id).procname);
    }
    if (client->port != IR_PORT_BIAS + 0x2329) {
      enet_client_add(0,0,client);
    }
    if (enet_connect_cb != NULL) {
      (*enet_connect_cb)(client);
    }
    iVar1 = 0;
  }
  return iVar1;
}

void enet_client_disconnected(RouterClient *client, int msgnbr, char *host, int port, int retrys)
{
  char *pcVar1;
  
  if (msgnbr == -0x131) {
LAB_080681b0:
    if (((port != IR_PORT_BIAS + 0x1f42) && (port != IR_PORT_BIAS + 0x1f43)) &&
       (port != IR_PORT_BIAS + 0x232c)) {
      syslog(6,"../../common/main/EnetServer.c",0x148,0,
             "Disconnection - %s (%s) @ %s running \'%s\'.",(client->id).username,
             (client->id).fullname,&client->id,(client->id).procname);
    }
    L2CfgMDeleteNode(&L2CfgLocal,client);
    if (enet_disconnect_cb != NULL) {
      (*enet_disconnect_cb)(client);
    }
  }
  else {
    if (msgnbr < -0x130) {
      if (msgnbr == -0x133) goto LAB_080681b0;
    }
    else if (msgnbr == -0x12f) goto LAB_080681b0;
    pcVar1 = LoggerDefaultMessage(msgnbr);
    syslog(6,"../../common/main/EnetServer.c",0x157,0,
           "UNHANDLED CONNECTION ERR - %s (%s) @ %s running \'%s\'.  (%d: %s)",(client->id).username
           ,(client->id).fullname,&client->id,(client->id).procname,msgnbr,pcVar1);
    L2CfgMDeleteNode(&L2CfgLocal,client);
  }
  return;
}

int EnetServerConnect(char *host, int port)
{
  int iVar1;
  ulong ip;
  int server_process_id;
  
  server_process_id = 2;
  ip = 0;
  if (((port != IR_PORT_BIAS + 0x1f42) && (port != IR_PORT_BIAS + 0x1f43)) &&
     (port != IR_PORT_BIAS + 0x232c)) {
    syslog(6,"../../common/main/EnetServer.c",0x172,0,"attempting connection to %s:%d",host,port);
  }
  iVar1 = SocketGetAddr(host,&ip);
  if (iVar1 == 0) {
    iVar1 = enet_client_add(ip,port,NULL);
    if (iVar1 == 0) {
      RouterMakeConnection
                (host,port,server_process_id,300,0x100,enet_established,enet_request,enet_event,
                 enet_failure);
      iVar1 = 0;
    }
    else {
      iVar1 = -1;
    }
  }
  else {
    syslog(3,"../../common/main/EnetServer.c",0x179,0,"could not get IP value for host %s:%d",host);
    iVar1 = -1;
  }
  return iVar1;
}

int enet_established(RouterClient *client, int opcode, RouterArgument **arglistout)
{
  char *tstr;
  RouterArgument args [2];
  
  if (((client->port != IR_PORT_BIAS + 0x1f42) && (client->port != IR_PORT_BIAS + 0x1f43)) &&
     (client->port != IR_PORT_BIAS + 0x232c)) {
    syslog(6,"../../common/main/EnetServer.c",0x1a7,0,"connection to %s:%d established.",&client->id
           ,client->port);
  }
  if (client->port == IR_PORT_BIAS + 0x2329) {
    RouterClientSetBufferSize(client,0x400,0x400);
  }
  enet_client_add(0,0,client);
  if (enet_establish_cb != NULL) {
    (*enet_establish_cb)(client);
  }
  return 0;
}

void enet_failure(RouterClient *client, int msgnbr, char *host, int port, int retrys)
{
  char *pcVar1;
  L2CfgNode *node;
  
  if (msgnbr != -0x143) {
    pcVar1 = LoggerDefaultMessage(msgnbr);
    syslog(6,"../../common/main/EnetServer.c",0x1c5,0,"connection to %s:%d failed: %s",host,port,
           pcVar1);
  }
  node = L2CfgMFindNode(&L2CfgLocal,client->addr,0,NULL);
  if ((node != NULL) && (node->client == NULL)) {
    node->client = client;
  }
  L2CfgMDeleteNode(&L2CfgLocal,client);
  if (enet_disconnect_cb != NULL) {
    (*enet_disconnect_cb)(client);
  }
  return;
}

void enet_client_free(RouterClient *client)
{
  L2CfgNode *node;
  
  node = L2CfgMFindNode(&L2CfgLocal,client->addr,0,NULL);
  if (node != NULL) {
    if (node->client == NULL) {
      node->client = client;
    }
    L2CfgMDeleteNode(&L2CfgLocal,client);
    if (enet_disconnect_cb != NULL) {
      (*enet_disconnect_cb)(client);
    }
  }
  return;
}

int enet_request(RouterClient *client, int request, int argcountin, RouterArgument *arglistin, RouterArgument **arglistout)
{
  static RouterArgument arglist[10];
  int argcountout;
  
  syslog(4,"../../common/main/EnetServer.c",0x20c,0,
         "Router request %d (%d args) packet received from %s!",request,argcountin,&client->id);
  *arglistout = (RouterArgument *)&arglist;
  return 0;
}

void enet_event(RouterClient *client, int event, int argcountin, RouterArgument *arglistin)
{
  IRPacket *npkt;
  L2CfgNode *node;
  char *pcVar1;
  int status;
  
  npkt = IRouterPacketFromRouter(argcountin,arglistin);
  if (npkt == NULL) {
    syslog(4,"../../common/main/EnetServer.c",0x225,0,
           "Invalid Router event %d (%d args) received (not IRouter format) from %s",event,
           argcountin,&client->id);
  }
  else {
    if (client->port != IR_PORT_BIAS + 0x2329) {
      node = L2CfgMFindNode(&L2CfgLocal,0,0,client);
      if (node == NULL) {
        pcVar1 = SocketAddrStr(client->addr);
        syslog(4,"../../common/main/EnetServer.c",0x238,0,
               "Could not find L2 node for connected client (%s)",pcVar1);
        return;
      }
      if (npkt->_clas != '\x02') {
        npkt->_src = node->ir_addr;
      }
    }
    npkt->_external = 1;
    status = (*enet_packet_cb)(enet_id,npkt);
    if (status == -0x259) {
      syslog(4,"../../common/main/EnetServer.c",0x249,0,
             "Invalid IRouter packet class (%d) received from %s",(uint)npkt->_clas,&client->id);
    }
  }
  return;
}
