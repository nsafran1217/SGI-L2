/*
 * sys_ctrl/common/Router/RouterSv.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterSv.c
 *
 * The server side of Router connections (see Router.c): listen on a TCP
 * port (and its local socket), and run the handshake with each client.
 * validate_cb(client, addr, id) decides: 1 accept (RC_ACCEPT; the client
 * answers with RC_CLIENT_ID), 2 ask for a password (RC_PASSWORD_REQ; the
 * client's connect_cb(client, 2, process_id, retrys, argc, argv) judges the
 * answer the same way), 3 refuse (RC_DENIED), anything else drop.
 */

#include <stdlib.h>
#include <string.h>
#include "RouterSv.h"
#include "Router.h"
#include "RouterInt.h"
#include "RouterMsg.h"
#include "Event.h"
#include "Socket.h"

static RouterServer *RouterMakeServer(int inet_socket, int unix_socket, int port, int (*validate_cb)(), void (*error_cb)());
static void RouterAddServer(RouterServer *server);
static void RouterRemoveServer(RouterServer *server);
static RouterFunc RouterAcceptInetConnection(RouterServer *server);
static RouterFunc RouterAcceptUnixConnection(RouterServer *server);
static void RouterValidateConnection(RouterServer *server, RouterClient *client);
static void RouterStartConnection(RouterClient *client, int clas);
static int RouterGetConResponse(RouterClient *client);
static int RouterAcceptClient(RouterClient *client, int argcountin);
static int RouterCheckPassword(RouterClient *client, int argcountin);
static void RouterSendConRequest(RouterClient *client, int clas);
static int RouterGetClientArguments(RouterClient *client);
static void RouterAddInetServer(RouterServer *server);
static void RouterRemoveInetServer(RouterServer *server);
static void RouterAddUnixServer(RouterServer *server);
static void RouterRemoveUnixServer(RouterServer *server);

/* validate_cb's and connect_cb's verdicts */
enum { VERDICT_ACCEPT = 1, VERDICT_PASSWORD = 2, VERDICT_DENY = 3 };

/* serve port; NULL if a server already answers there (or on error) */
RouterServer *RouterStartServer(int port, int (*validate_cb)(), void (*error_cb)())
{
  RouterServer *server;
  char *localhost;
  int inet_socket;
  int unix_socket = -1;

  if (validate_cb == NULL) {
    LogError(ROUTER_ERR_PROTOCOL,"RouterStartServer",0,"");
    return NULL;
  }
  if (SocketGetHostName(&localhost) != 0)
    return NULL;
  inet_socket = SocketMakeInetConnection(localhost,port,0);
  if (inet_socket >= 0) {
    LogErrorHost(ROUTER_ERR_SERVER_RUNNING,"",0,localhost,port,"");
    SocketClose(inet_socket);
    return NULL;
  }
  inet_socket = SocketExportInetConnection(port);
  if (inet_socket < 0)
    return NULL;
  if (UseUnix) {
    unix_socket = SocketExportUnixConnection(port);
    if (unix_socket < 0) {
      SocketClose(inet_socket);
      return NULL;
    }
  }
  server = RouterMakeServer(inet_socket,unix_socket,port,validate_cb,error_cb);
  RouterAddServer(server);
  RouterAddInetServer(server);
  if (UseUnix)
    RouterAddUnixServer(server);
  return server;
}

/* does a server answer on port (TCP or local socket)? */
int RouterCheckServer(int port)
{
  char *localhost;
  int sock;

  if (SocketGetHostName(&localhost) != 0)
    return 1;
  sock = SocketMakeInetConnection(localhost,port,0);
  if (sock < 0)
    sock = SocketMakeUnixConnection(port,0);
  if (sock < 0)
    return 0;
  SocketClose(sock);
  return 1;
}

void RouterStopServer(RouterServer *server)
{
  if (server->inet_socket >= 0) {
    RouterRemoveInetServer(server);
    SocketClose(server->inet_socket);
  }
  if (server->unix_socket >= 0) {
    RouterRemoveUnixServer(server);
    SocketCloseUnixServer(server->unix_socket,server->port);
  }
  RouterRemoveServer(server);
}

int RouterGetClients(RouterID **buf)
{
  return RouterGetIDClients(-1,buf);
}

/* is client a persistent connection to our server, of process_id (-1: any)? */
static int listed_client(RouterClient *client, int process_id)
{
  return (client->use & RU_ACCEPTED) && (client->use & RU_SIDE) == RU_SERVER &&
         (client->use & RU_KIND) == RU_PERSISTENT &&
         (client->process_id == process_id || process_id == -1);
}

/* the RouterIDs of those clients, in a buffer valid until the next call */
int RouterGetIDClients(int process_id, RouterID **buf)
{
  static RouterID *client_id_buf;
  RouterClient *client;
  int clients = 0;
  int i = 0;

  free(client_id_buf);
  client_id_buf = NULL;
  for (client = ClientList.head; client != NULL; client = client->next)
    if (listed_client(client,process_id))
      clients++;
  if (clients == 0) {
    *buf = NULL;
    return 0;
  }
  client_id_buf = calloc(clients,sizeof(RouterID));
  if (client_id_buf == NULL)
    RouterMemError();
  for (client = ClientList.head; client != NULL; client = client->next)
    if (listed_client(client,process_id))
      client_id_buf[i++] = client->id;
  *buf = client_id_buf;
  return clients;
}

void RouterShutDownServers(void)
{
  while (ServerList.head != NULL)
    RouterStopServer(ServerList.head);
}

void RouterCloseOnlyServers(void)
{
  while (ServerList.head != NULL)
    RouterCloseOnlyServer(ServerList.head);
}

/* close without shutdown() or removing the local socket (for a forked child) */
void RouterCloseOnlyServer(RouterServer *server)
{
  if (server->inet_socket >= 0) {
    RouterRemoveInetServer(server);
    SocketCloseOnly(server->inet_socket);
  }
  if (server->unix_socket >= 0) {
    RouterRemoveUnixServer(server);
    SocketCloseOnly(server->unix_socket);
  }
  RouterRemoveServer(server);
}

static RouterServer *RouterMakeServer(int inet_socket, int unix_socket, int port, int (*validate_cb)(), void (*error_cb)())
{
  RouterServer *server;

  server = malloc(sizeof(RouterServer));
  if (server == NULL)
    RouterMemError();
  server->inet_socket = inet_socket;
  server->unix_socket = unix_socket;
  server->inet_id = 0;
  server->unix_id = 0;
  server->port = port;
  server->cpp_hook = NULL;
  server->validate_cb = validate_cb;
  server->error_cb = error_cb;
  server->next = NULL;
  return server;
}

static void RouterAddServer(RouterServer *server)
{
  if (ServerList.tail == NULL)
    ServerList.head = server;
  else
    ServerList.tail->next = server;
  ServerList.tail = server;
  server->next = NULL;
  ServerList.total++;
}

static void RouterRemoveServer(RouterServer *server)
{
  RouterServer *prev = NULL;
  RouterServer *s;

  for (s = ServerList.head; s != NULL && s != server; s = s->next)
    prev = s;
  if (s == NULL)
    return;
  if (prev == NULL)
    ServerList.head = s->next;
  else
    prev->next = s->next;
  if (ServerList.tail == s)
    ServerList.tail = prev;
  free(server);
  ServerList.total--;
}

/* server, if it still exists */
RouterServer *RouterFindServer(RouterServer *server)
{
  RouterServer *s;

  for (s = ServerList.head; s != NULL; s = s->next)
    if (s == server)
      return server;
  return NULL;
}

/* a client connected over TCP */
static RouterFunc RouterAcceptInetConnection(RouterServer *server)
{
  RouterClient *client;
  Hostname conn_host;
  uint32_t conn_addr;
  int conn_socket;

  conn_socket = SocketAcceptInetConnection(server->inet_socket,1);
  if (conn_socket < 0)
    return;
  if ((SocketSendBufsize != 0 || SocketReceiveBufsize != 0) &&
      SocketSetBufferSize(conn_socket,SocketSendBufsize,SocketReceiveBufsize) < 0) {
    SocketCloseOnly(conn_socket);
    return;
  }
  if (SocketGetPeerAddr(conn_socket,&conn_addr) != 0) {
    SocketClose(conn_socket);
    return;
  }
  if (SocketGetName(conn_addr,conn_host,sizeof(conn_host)) != 0)
    strcpy(conn_host,SocketAddrStr(conn_addr));
  client = RouterMakeClient(conn_socket,conn_addr,server->port,0,
                            RU_INORDER | RU_INET | RU_SERVER | RU_CONNECTING,server,conn_host,
                            RouterGetConResponse);
  RouterValidateConnection(server,client);
}

/* a client connected through the local socket */
static RouterFunc RouterAcceptUnixConnection(RouterServer *server)
{
  RouterClient *client;
  uint32_t localaddr;
  char *localhost;
  int conn_socket;

  conn_socket = SocketAcceptUnixConnection(server->unix_socket,1);
  if (conn_socket < 0)
    return;
  if ((SocketSendBufsize != 0 || SocketReceiveBufsize != 0) &&
      SocketSetBufferSize(conn_socket,SocketSendBufsize,SocketReceiveBufsize) < 0) {
    SocketCloseOnly(conn_socket);
    return;
  }
  if (SocketGetHostName(&localhost) != 0) {
    SocketClose(conn_socket);
    return;
  }
  if (SocketGetAddr(localhost,&localaddr) != 0) {
    LogErrorHost(ROUTER_ERR_HOST_ADDR,"",0,localhost,0,"");
    SocketClose(conn_socket);
    return;
  }
  client = RouterMakeClient(conn_socket,localaddr,server->port,0,
                            RU_UNIX | RU_SERVER | RU_CONNECTING,server,localhost,
                            RouterGetConResponse);
  RouterValidateConnection(server,client);
}

/* ask validate_cb what to do with a new client */
static void RouterValidateConnection(RouterServer *server, RouterClient *client)
{
  switch (server->validate_cb(client,client->addr,&client->id)) {
  case VERDICT_ACCEPT:
    client->accepted = 1;
    RouterStartConnection(client,RC_ACCEPT);
    return;
  case VERDICT_PASSWORD:
    if (client->connect_cb != NULL) {
      RouterStartConnection(client,RC_PASSWORD_REQ);
      return;
    }
    LogError(ROUTER_ERR_PROTOCOL,"RouterValidateConnection",0,"");
    break;
  case VERDICT_DENY:
    RouterStartConnection(client,RC_DENIED);
    return;
  }
  SocketClose(client->socket);
  RouterFreeClient(client,1);
}

static void RouterStartConnection(RouterClient *client, int clas)
{
  RouterAddClient(client);
  RouterStartInput(client);
  RouterSendConRequest(client,clas);
}

/* the input handler until the client is accepted: its password or its ID */
static int RouterGetConResponse(RouterClient *client)
{
  int argcountin;
  int rvalue;

  client->process_id = client->in_buf->opcode;
  switch (client->in_buf->clas) {
  case RC_PASSWORD:
    argcountin = RouterUnpack(client,client->in_buf);
    rvalue = RouterCheckPassword(client,argcountin);
    break;
  case RC_CLIENT_ID:
    argcountin = RouterUnpack(client,client->in_buf);
    rvalue = RouterAcceptClient(client,argcountin);
    break;
  default:
    RouterBadClass(client,"RouterGetConResponse");
    return -1;
  }
  RouterFreeArguments(argcountin,client->InArgList);
  if (rvalue != 0) {
    RouterClose(client);
    return -1;
  }
  return 0;
}

/* the accepted client's RC_CLIENT_ID: type, RouterID and maybe group bits */
static int RouterAcceptClient(RouterClient *client, int argcountin)
{
  RouterArgument *groups;

  if (!client->accepted) {
    LogError(ROUTER_ERR_PROTOCOL,"RouterAcceptClient",0,"");
    return -1;
  }
  if (argcountin != 2 && argcountin != 3) {
    LogError(ROUTER_ERR_ARG_COUNT,"RouterAcceptClient",0,"");
    return -1;
  }
  if (RouterGetClientArguments(client) != 0)
    return -1;
  if (argcountin == 3) {
    groups = &client->InArgList[2];
    if (groups->clas != 1) {
      LogError(ROUTER_ERR_ARG_CLASS,"RouterAcceptClient",0,"");
      return -1;
    }
    if ((unsigned int)groups->size != (client->groups.count + 7) >> 3) {
      LogError(ROUTER_ERR_ARG_SIZE,"RouterAcceptClient",0,"");
      return -1;
    }
    client->groups.bits = (char *)groups->val;  /* taken over */
    memset(groups,0,sizeof(*groups));
  }
  if (client->use & RU_CONFIGURE)
    RouterConfigure(client);
  if (client->connect_cb != NULL)
    client->connect_cb(client,1,client->process_id,0,0,0);
  client->in_handler = RouterProcessPacket;
  return 0;
}

/* the client's password, judged by its connect_cb */
static int RouterCheckPassword(RouterClient *client, int argcountin)
{
  if (client->connect_cb == NULL) {
    LogError(ROUTER_ERR_PROTOCOL,"RouterCheckPassword",0,"");
    return -1;
  }
  switch (client->connect_cb(client,2,client->process_id,client->retrys,argcountin,
                             client->InArgList)) {
  case VERDICT_ACCEPT:
    client->accepted = 1;
    RouterSendConRequest(client,RC_ACCEPT);
    return 0;
  case VERDICT_PASSWORD:        /* try again */
    client->retrys++;
    RouterSendConRequest(client,RC_PASSWORD_REQ);
    return 0;
  case VERDICT_DENY:
    RouterSendConRequest(client,RC_DENIED);
    return 0;
  default:
    return -1;
  }
}

/* RC_ACCEPT carries our RouterID; the others nothing */
static void RouterSendConRequest(RouterClient *client, int clas)
{
  RouterArgument arglist;
  RouterID server_id;
  unsigned char tbuf[128];

  if (clas != RC_ACCEPT) {
    RouterDoOutput(client,ProcessID,clas,0,NULL,NULL,NULL,NULL,NULL,0,NULL);
    return;
  }
  RouterSetClientID(&server_id);
  arglist.val = (uintptr_t)tbuf;
  arglist.fre = 1;
  arglist.clas = 1;
  arglist.size = RouterPackID(&server_id,tbuf);
  RouterDoOutput(client,ProcessID,RC_ACCEPT,1,&arglist,NULL,NULL,NULL,NULL,0,NULL);
}

/*
 * The client's type (RouterClientType, big-endian: use, group count) and
 * RouterID. Clients send only RU_CONFIGURE of their use (RouterCl.c), so the
 * kind test never finds RU_PERSISTENT: every accepted connection is set up as
 * a transaction connection.
 */
static int RouterGetClientArguments(RouterClient *client)
{
  unsigned char *type;
  unsigned int use;

  if (client->InArgList[0].clas != 1 || client->InArgList[1].clas != 1) {
    LogError(ROUTER_ERR_ARG_CLASS,"RouterGetClientArguments",0,"");
    return -1;
  }
  type = (unsigned char *)client->InArgList[0].val;
  use = type[2] << 8;
  client->use = (client->use & (RU_INET | RU_UNIX)) | (use & RU_CONFIGURE);
  if ((use & RU_KIND) == RU_PERSISTENT)
    client->use |= RU_PERSISTENT | RU_SERVER | RU_CONNECTED | RU_ACCEPTED;
  else
    client->use |= RU_TRANSACTION | RU_SERVER | RU_ACCEPTED;
  RouterUnpackID(&client->id,(char *)client->InArgList[1].val,client->InArgList[1].size);
  client->groups.count = type[5] << 16 | type[6] << 8 | type[7];
  return 0;
}

/* send our RouterConfig (8 bytes, big-endian: rev, flags) and flush it */
void RouterConfigure(RouterClient *client)
{
  RouterArgument arglist;
  unsigned char tbuf[8];

  tbuf[0] = RouterLocalConfig.rev >> 24;
  tbuf[1] = RouterLocalConfig.rev >> 16;
  tbuf[2] = RouterLocalConfig.rev >> 8;
  tbuf[3] = RouterLocalConfig.rev;
  tbuf[4] = RouterLocalConfig.flags >> 24;
  tbuf[5] = RouterLocalConfig.flags >> 16;
  tbuf[6] = RouterLocalConfig.flags >> 8;
  tbuf[7] = RouterLocalConfig.flags;
  arglist.val = (uintptr_t)tbuf;
  arglist.fre = 1;
  arglist.clas = 1;
  arglist.size = sizeof(tbuf);
  RouterDoOutput(client,0,RC_CONFIG_INIT,1,&arglist,NULL,NULL,NULL,NULL,0,NULL);
  RouterFlushOutput(client,0);
}

static void RouterAddInetServer(RouterServer *server)
{
  server->inet_id = EventAddInput(server->inet_socket,RouterAcceptInetConnection,
                                  (EventData)server,"RouterAddInetServer");
}

static void RouterRemoveInetServer(RouterServer *server)
{
  EventRemoveInput(server->inet_id);
}

static void RouterAddUnixServer(RouterServer *server)
{
  server->unix_id = EventAddInput(server->unix_socket,RouterAcceptUnixConnection,
                                  (EventData)server,"RouterAddUnixServer");
}

static void RouterRemoveUnixServer(RouterServer *server)
{
  EventRemoveInput(server->unix_id);
}
