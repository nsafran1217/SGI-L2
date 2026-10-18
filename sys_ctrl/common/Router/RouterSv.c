/*
 * sys_ctrl/common/Router/RouterSv.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterSv.c
 */

#include "RouterSv.h"   /* needed by the reconstruction */
#include "../../l3/l2/discover.h"   /* needed by the reconstruction */
#include "Router.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "RouterInt.h"
#include "Event.h"
#include <time.h>
#include <sys/time.h>
#include "RouterMsg.h"
#include "../sys/Logger.h"
#include "../../l3/sys/LoggerMsg.h"
#include "Socket.h"
#include <signal.h>
#include <malloc.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static RouterServer *RouterMakeServer(int inet_socket, int unix_socket, int port, int (*validate_cb)(), void (*error_cb)());
static void RouterAddServer(RouterServer *server);
static void RouterRemoveServer(RouterServer *server);
static RouterFunc RouterAcceptInetConnection(RouterServer *server);
static RouterFunc RouterAcceptUnixConnection(RouterServer *server);
static void RouterValidateConnection(RouterServer *server, RouterClient *client);
static void RouterStartConnection(RouterClient *client, int class);
static int RouterGetConResponse(RouterClient *client);
static int RouterAcceptClient(RouterClient *client, int argcountin);
static int RouterCheckPassword(RouterClient *client, int argcountin);
static void RouterSendConRequest(RouterClient *client, int class);
static int RouterGetClientArguments(RouterClient *client);
static void RouterAddInetServer(RouterServer *server);
static void RouterRemoveInetServer(RouterServer *server);
static void RouterAddUnixServer(RouterServer *server);
static void RouterRemoveUnixServer(RouterServer *server);

RouterServer *RouterStartServer(int port, int (*validate_cb)(), void (*error_cb)())
{
  RouterServer *server_00;
  int inet_socket;
  int iVar1;
  RouterServer *server;
  int unix_socket;
  char *localhost;
  char *func_name;
  
  func_name = "RouterStartServer";
  unix_socket = -1;
  if (validate_cb == NULL) {
    LogError(-0x13d,"RouterStartServer",0,"");
    server_00 = NULL;
  }
  else {
    inet_socket = SocketGetHostName(&localhost);
    if (inet_socket == 0) {
      iVar1 = SocketMakeInetConnection(localhost,port,0);
      if (iVar1 < 0) {
        iVar1 = SocketExportInetConnection(port);
        if (iVar1 < 0) {
          server_00 = NULL;
        }
        else if ((UseUnix == 0) ||
                (unix_socket = SocketExportUnixConnection(port), -1 < unix_socket)) {
          server_00 = RouterMakeServer(iVar1,unix_socket,port,validate_cb,error_cb);
          RouterAddServer(server_00);
          RouterAddInetServer(server_00);
          if (UseUnix != 0) {
            RouterAddUnixServer(server_00);
          }
        }
        else {
          SocketClose(iVar1);
          server_00 = NULL;
        }
      }
      else {
        LogErrorHost(-0x135,"",0,localhost,port,"");
        SocketClose(iVar1);
        server_00 = NULL;
      }
    }
    else {
      server_00 = NULL;
    }
  }
  return server_00;
}

int RouterCheckServer(int port)
{
  int iVar1;
  char *localhost;
  int unix_socket;
  int inet_socket;
  char *func_name;
  
  func_name = "RouterCheckServer";
  inet_socket = -1;
  unix_socket = -1;
  iVar1 = SocketGetHostName(&localhost);
  if (iVar1 == 0) {
    inet_socket = SocketMakeInetConnection(localhost,port,0);
    if (inet_socket < 0) {
      unix_socket = SocketMakeUnixConnection(port,0);
      if (unix_socket < 0) {
        iVar1 = 0;
      }
      else {
        SocketClose(unix_socket);
        iVar1 = 1;
      }
    }
    else {
      SocketClose(inet_socket);
      iVar1 = 1;
    }
  }
  else {
    iVar1 = 1;
  }
  return iVar1;
}

void RouterStopServer(RouterServer *server)
{
  if (-1 < server->inet_socket) {
    RouterRemoveInetServer(server);
    SocketClose(server->inet_socket);
  }
  if (-1 < server->unix_socket) {
    RouterRemoveUnixServer(server);
    SocketCloseUnixServer(server->unix_socket,server->port);
  }
  RouterRemoveServer(server);
  return;
}

int RouterGetClients(RouterID **buf)
{
  int iVar1;
  
  iVar1 = RouterGetIDClients(-1,buf);
  return iVar1;
}

int RouterGetIDClients(int process_id, RouterID **buf)
{
  static RouterID *client_id_buf;
  int iVar1;
  RouterID *pRVar2;
  RouterID *pRVar3;
  int i;
  int clients;
  RouterClient *client_ptr;
  
  clients = 0;
  i = 0;
  if (client_id_buf != NULL) {
    free(client_id_buf);
    client_id_buf = NULL;
  }
  for (client_ptr = ClientList.head; client_ptr != NULL;
      client_ptr = client_ptr->next) {
    if (((((client_ptr->use & 2U) != 0) && ((client_ptr->use & 0xc0U) == 0x80)) &&
        ((client_ptr->use & 0x600U) == 0x200)) &&
       ((client_ptr->process_id == process_id || (process_id == -1)))) {
      clients = clients + 1;
    }
  }
  if (clients == 0) {
    *buf = NULL;
  }
  else {
    client_id_buf = calloc(clients,0x80);
    if (client_id_buf == NULL) {
      RouterMemError();
    }
    for (client_ptr = ClientList.head; client_ptr != NULL;
        client_ptr = client_ptr->next) {
      if ((((client_ptr->use & 2U) != 0) && ((client_ptr->use & 0xc0U) == 0x80)) &&
         (((client_ptr->use & 0x600U) == 0x200 &&
          ((client_ptr->process_id == process_id || (process_id == -1)))))) {
        pRVar2 = &client_ptr->id;
        pRVar3 = client_id_buf + i;
        for (iVar1 = 0x20; iVar1 != 0; iVar1 = iVar1 + -1) {
          *(undefined4 *)pRVar3->hostname = *(undefined4 *)pRVar2->hostname;
          pRVar2 = (RouterID *)(pRVar2->hostname + 4);
          pRVar3 = (RouterID *)(pRVar3->hostname + 4);
        }
        i = i + 1;
      }
    }
    *buf = client_id_buf;
  }
  return clients;
}

void RouterShutDownServers(void)
{
  while (ServerList.head != NULL) {
    RouterStopServer(ServerList.head);
  }
  return;
}

void RouterCloseOnlyServers(void)
{
  while (ServerList.head != NULL) {
    RouterCloseOnlyServer(ServerList.head);
  }
  return;
}

void RouterCloseOnlyServer(RouterServer *server)
{
  if (-1 < server->inet_socket) {
    RouterRemoveInetServer(server);
    SocketCloseOnly(server->inet_socket);
  }
  if (-1 < server->unix_socket) {
    RouterRemoveUnixServer(server);
    SocketCloseOnly(server->unix_socket);
  }
  RouterRemoveServer(server);
  return;
}

static RouterServer *RouterMakeServer(int inet_socket, int unix_socket, int port, int (*validate_cb)(), void (*error_cb)())
{
  RouterServer *pRVar1;
  RouterServer *server;
  
  pRVar1 = malloc(0x24);
  if (pRVar1 == NULL) {
    RouterMemError();
  }
  pRVar1->inet_socket = inet_socket;
  pRVar1->unix_socket = unix_socket;
  pRVar1->inet_id = 0;
  pRVar1->unix_id = 0;
  pRVar1->port = port;
  pRVar1->cpp_hook = NULL;
  pRVar1->validate_cb = validate_cb;
  pRVar1->error_cb = error_cb;
  pRVar1->next = NULL;
  return pRVar1;
}

static void RouterAddServer(RouterServer *server)
{
  if (ServerList.tail == NULL) {
    ServerList.head = server;
  }
  else {
    (ServerList.tail)->next = server;
  }
  ServerList.tail = server;
  server->next = NULL;
  ServerList.total = ServerList.total + 1;
  return;
}

static void RouterRemoveServer(RouterServer *server)
{
  RouterServer *last_server;
  RouterServer *server_ptr;
  
  server_ptr = ServerList.head;
  last_server = NULL;
  while( true ) {
    if (server_ptr == NULL) {
      return;
    }
    if (server_ptr == server) break;
    last_server = server_ptr;
    server_ptr = server_ptr->next;
  }
  if (server_ptr == ServerList.head) {
    if (server_ptr->next == NULL) {
      ServerList.head = NULL;
      ServerList.tail = NULL;
    }
    else {
      ServerList.head = server_ptr->next;
    }
  }
  else if (server_ptr == ServerList.tail) {
    ServerList.tail = last_server;
    last_server->next = NULL;
  }
  else {
    last_server->next = server_ptr->next;
  }
  free(server);
  ServerList.total = ServerList.total + -1;
  return;
}

RouterServer *RouterFindServer(RouterServer *server)
{
  RouterServer *last_server;
  RouterServer *server_ptr;
  
  server_ptr = ServerList.head;
  while( true ) {
    if (server_ptr == NULL) {
      return NULL;
    }
    if (server_ptr == server) break;
    server_ptr = server_ptr->next;
  }
  return server;
}

static RouterFunc RouterAcceptInetConnection(RouterServer *server)
{
  int iVar1;
  char *__src;
  RouterClient *client;
  int nodelay;
  int use;
  Hostname conn_host;
  ulong conn_addr;
  int conn_socket;
  
  conn_socket = SocketAcceptInetConnection(server->inet_socket,1);
  if (-1 < conn_socket) {
    if (((SocketSendBufsize == 0) && (SocketReceiveBufsize == 0)) ||
       (iVar1 = SocketSetBufferSize(conn_socket,SocketSendBufsize,SocketReceiveBufsize), -1 < iVar1)
       ) {
      iVar1 = SocketGetPeerAddr(conn_socket,&conn_addr);
      if (iVar1 == 0) {
        iVar1 = SocketGetName(conn_addr,conn_host,0x41);
        if (iVar1 != 0) {
          __src = SocketAddrStr(conn_addr);
          strcpy(conn_host,__src);
        }
        client = RouterMakeClient(conn_socket,conn_addr,server->port,0,0x9081,server,conn_host,
                                  RouterGetConResponse);
        RouterValidateConnection(server,client);
      }
      else {
        SocketClose(conn_socket);
      }
    }
    else {
      SocketCloseOnly(conn_socket);
    }
  }
  return;
}

static RouterFunc RouterAcceptUnixConnection(RouterServer *server)
{
  int iVar1;
  RouterClient *client;
  int nodelay;
  int use;
  ulong localaddr;
  char *localhost;
  int conn_socket;
  
  conn_socket = SocketAcceptUnixConnection(server->unix_socket,1);
  if (-1 < conn_socket) {
    if (((SocketSendBufsize == 0) && (SocketReceiveBufsize == 0)) ||
       (iVar1 = SocketSetBufferSize(conn_socket,SocketSendBufsize,SocketReceiveBufsize), -1 < iVar1)
       ) {
      iVar1 = SocketGetHostName(&localhost);
      if (iVar1 == 0) {
        iVar1 = SocketGetAddr(localhost,&localaddr);
        if (iVar1 == 0) {
          client = RouterMakeClient(conn_socket,localaddr,server->port,0,0x2081,server,localhost,
                                    RouterGetConResponse);
          RouterValidateConnection(server,client);
        }
        else {
          LogErrorHost(-0x13b,"",0,localhost,0,"");
          SocketClose(conn_socket);
        }
      }
      else {
        SocketClose(conn_socket);
      }
    }
    else {
      SocketCloseOnly(conn_socket);
    }
  }
  return;
}

static void RouterValidateConnection(RouterServer *server, RouterClient *client)
{
  int iVar1;
  int class;
  char *func_name;
  
  iVar1 = (*server->validate_cb)(client,client->addr,&client->id);
  if (iVar1 == 2) {
    if (client->connect_cb != NULL) {
      class = 1;
      goto LAB_0807a720;
    }
    LogError(-0x13d,"RouterValidateConnection",0,"");
  }
  else if (iVar1 < 3) {
    if (iVar1 == 1) {
      client->accepted = 1;
      class = 4;
LAB_0807a720:
      RouterStartConnection(client,class);
      return;
    }
  }
  else if (iVar1 == 3) {
    class = 0x22;
    goto LAB_0807a720;
  }
  SocketClose(client->socket);
  RouterFreeClient(client,1);
  return;
}

static void RouterStartConnection(RouterClient *client, int class)
{
  RouterAddClient(client);
  RouterStartInput(client);
  RouterSendConRequest(client,class);
  return;
}

static int RouterGetConResponse(RouterClient *client)
{
  byte bVar1;
  int iVar2;
  int rvalue;
  int argcountin;
  char *func_name;
  
  client->process_id = (uint)client->in_buf->opcode;
  bVar1 = client->in_buf->clas;
  if (bVar1 == 2) {
    argcountin = RouterUnpack(client,client->in_buf);
    rvalue = RouterCheckPassword(client,argcountin);
  }
  else {
    if (bVar1 != 8) {
      RouterBadClass(client,"RouterGetConResponse");
      return -1;
    }
    argcountin = RouterUnpack(client,client->in_buf);
    rvalue = RouterAcceptClient(client,argcountin);
  }
  RouterFreeArguments(argcountin,client->InArgList);
  if (rvalue == 0) {
    iVar2 = 0;
  }
  else {
    RouterClose(client);
    iVar2 = -1;
  }
  return iVar2;
}

static int RouterAcceptClient(RouterClient *client, int argcountin)
{
  int iVar1;
  char *func_name;
  
  if (client->accepted == 0) {
    LogError(-0x13d,"RouterAcceptClient",0,"");
    return -1;
  }
  if (argcountin == 2) {
    iVar1 = RouterGetClientArguments(client);
    if (iVar1 != 0) {
      return -1;
    }
  }
  else {
    if (argcountin != 3) {
      LogError(-0x13e,"RouterAcceptClient",0,"");
      return -1;
    }
    iVar1 = RouterGetClientArguments(client);
    if (iVar1 != 0) {
      return -1;
    }
    if (client->InArgList[2].clas != 1) {
      LogError(-0x13f,"RouterAcceptClient",0,"");
      return -1;
    }
    if (*(int *)(client->InArgList + 2) >> 8 != (client->groups).count + 7 >> 3) {
      LogError(-0x140,"RouterAcceptClient",0,"");
      return -1;
    }
    (client->groups).bits = (char *)client->InArgList[2].val;
    client->InArgList[2].clas = 0;
    client->InArgList[2].val = 0;
    client->InArgList[2].fre = 0;
    *(uint *)(client->InArgList + 2) = *(uint *)(client->InArgList + 2) & 0xff;
  }
  if ((client->use & 0x4000U) != 0) {
    RouterConfigure(client);
  }
  if (client->connect_cb != NULL) {
    (*client->connect_cb)(client,1,client->process_id,0,0,0);
  }
  client->in_handler = RouterProcessPacket;
  return 0;
}

static int RouterCheckPassword(RouterClient *client, int argcountin)
{
  int iVar1;
  int class;
  char *func_name;
  
  if (client->connect_cb == NULL) {
    LogError(-0x13d,"RouterCheckPassword",0,"");
    return -1;
  }
  iVar1 = (*client->connect_cb)
                    (client,2,client->process_id,client->retrys,argcountin,client->InArgList);
  if (iVar1 == 2) {
    client->retrys = client->retrys + 1;
    class = 1;
LAB_0807ab17:
    RouterSendConRequest(client,class);
    iVar1 = 0;
  }
  else {
    if (iVar1 < 3) {
      if (iVar1 == 1) {
        client->accepted = 1;
        class = 4;
        goto LAB_0807ab17;
      }
    }
    else if (iVar1 == 3) {
      class = 0x22;
      goto LAB_0807ab17;
    }
    iVar1 = -1;
  }
  return iVar1;
}

static void RouterSendConRequest(RouterClient *client, int class)
{
  uchar *__dest;
  size_t sVar1;
  uchar tbuf [128];
  RouterArgument arglist;
  RouterID client_id;
  uchar *tptr;
  
  if (class == 4) {
    RouterSetClientID(&client_id);
    sVar1 = strlen(client_id.procname);
    memcpy(tbuf,client_id.procname,sVar1 + 1);
    sVar1 = strlen(client_id.procname);
    tptr = tbuf + sVar1 + 1;
    sVar1 = strlen(client_id.username);
    memcpy(tptr,client_id.username,sVar1 + 1);
    sVar1 = strlen(client_id.username);
    __dest = tptr + sVar1 + 1;
    sVar1 = strlen(client_id.fullname);
    memcpy(__dest,client_id.fullname,sVar1 + 1);
    sVar1 = strlen(client_id.fullname);
    memcpy(__dest + sVar1 + 1,&client_id.ipaddr,4);
    arglist.val = (ulong)tbuf;
    arglist.fre = 1;
    arglist.clas = 1;
    arglist.size = (int)((__dest + sVar1 + 1 + 4) - (uchar *)tbuf);
    RouterDoOutput(client,ProcessID,4,1,&arglist,NULL,NULL,
                   NULL,NULL,0,NULL);
  }
  else {
    RouterDoOutput(client,ProcessID,class,0,NULL,NULL,NULL,
                   NULL,NULL,0,NULL);
  }
  return;
}

static int RouterGetClientArguments(RouterClient *client)
{
  uchar *__s;
  byte bVar1;
  byte bVar2;
  byte bVar3;
  ulong uVar4;
  char *__s_00;
  size_t sVar5;
  int iVar6;
  uint uVar7;
  int idsize;
  uchar *tptro;
  RouterClientType client_type;
  char *func_name;
  uchar *tptr;
  
  if ((client->InArgList->clas == 1) && (client->InArgList[1].clas == 1)) {
    uVar4 = client->InArgList->val;
    uVar7 = (uint)*(byte *)(uVar4 + 2) << 8;
    bVar1 = *(byte *)(uVar4 + 5);
    bVar2 = *(byte *)(uVar4 + 6);
    bVar3 = *(byte *)(uVar4 + 7);
    client->use = client->use & 0x3000U | uVar7 & 0x4000;
    if ((uVar7 & 0x600) == 0x200) {
      client->use = client->use | 0x286;
    }
    else {
      client->use = client->use | 0x482;
    }
    iVar6 = *(int *)(client->InArgList + 1);
    __s_00 = (char *)client->InArgList[1].val;
    sVar5 = strlen(__s_00);
    memcpy((client->id).procname,__s_00,sVar5 + 1);
    sVar5 = strlen(__s_00);
    tptr = (uchar *)(__s_00 + sVar5 + 1);
    sVar5 = strlen((char *)tptr);
    memcpy((client->id).username,tptr,sVar5 + 1);
    sVar5 = strlen((char *)tptr);
    __s = tptr + sVar5 + 1;
    sVar5 = strlen((char *)__s);
    memcpy((client->id).fullname,__s,sVar5 + 1);
    sVar5 = strlen((char *)__s);
    if ((int)(__s + sVar5 + 1) - (int)__s_00 < iVar6 >> 8) {
      memcpy(&(client->id).ipaddr,__s + sVar5 + 1,4);
    }
    (client->groups).count = (uint)bVar1 << 0x10 | (uint)bVar2 << 8 | (uint)bVar3;
    iVar6 = 0;
  }
  else {
    LogError(-0x13f,"RouterGetClientArguments",0,"");
    iVar6 = -1;
  }
  return iVar6;
}

void RouterConfigure(RouterClient *client)
{
  uchar *tptr;
  uchar tbuf [72];
  RouterArgument arglist;
  
  tbuf[0] = (uchar)(RouterLocalConfig.rev >> 0x18);
  tbuf[1] = (uchar)(RouterLocalConfig.rev >> 0x10);
  tbuf[2] = (uchar)(RouterLocalConfig.rev >> 8);
  tbuf[3] = (uchar)RouterLocalConfig.rev;
  tbuf[4] = (uchar)(RouterLocalConfig.flags >> 0x18);
  tbuf[5] = (uchar)(RouterLocalConfig.flags >> 0x10);
  tbuf[6] = (uchar)(RouterLocalConfig.flags >> 8);
  tbuf[7] = (uchar)RouterLocalConfig.flags;
  arglist.val = (ulong)tbuf;
  arglist.fre = 1;
  arglist.clas = 1;
  arglist.size = 8;
  RouterDoOutput(client,0,0x14,1,&arglist,NULL,NULL,NULL,
                 NULL,0,NULL);
  RouterFlushOutput(client,0);
  return;
}

static void RouterAddInetServer(RouterServer *server)
{
  EventID EVar1;
  
  EVar1 = EventAddInput(server->inet_socket,RouterAcceptInetConnection,(EventData)server,
                        "RouterAddInetServer");
  server->inet_id = EVar1;
  return;
}

static void RouterRemoveInetServer(RouterServer *server)
{
  EventRemoveInput(server->inet_id);
  return;
}

static void RouterAddUnixServer(RouterServer *server)
{
  EventID EVar1;
  
  EVar1 = EventAddInput(server->unix_socket,RouterAcceptUnixConnection,(EventData)server,
                        "RouterAddUnixServer");
  server->unix_id = EVar1;
  return;
}

static void RouterRemoveUnixServer(RouterServer *server)
{
  EventRemoveInput(server->unix_id);
  return;
}
