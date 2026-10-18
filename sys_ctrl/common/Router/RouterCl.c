/*
 * sys_ctrl/common/Router/RouterCl.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterCl.c
 *
 * The client side of a Router connection (see Router.c): connect to a server
 * (locally through a local socket when UseUnix is set), then the handshake:
 * the server asks for a password (RC_PASSWORD_REQ), accepts us (RC_ACCEPT,
 * with its RouterID; we answer with RC_CLIENT_ID) or refuses (RC_DENIED).
 */

#include <stdlib.h>
#include <string.h>
#include "RouterCl.h"
#include "Router.h"
#include "RouterInt.h"
#include "RouterMsg.h"
#include "Socket.h"

static RouterClient *RouterConnect(char *host, int port, int process_id, int use, int timeout, int limit, RouterGroupSet *groups, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)(), int retrys);
static int RouterGetConRequest(RouterClient *client);
static int RouterProcessAccept(RouterClient *client, int argcountin);
static int RouterGetPassword(RouterClient *client);
static RouterFunc RouterConnectFailed(RouterClient *client);
static RouterFunc RouterConnectError(RouterClient *client);

/* how our connections start out */
#define RU_NEW  (RU_INORDER | RU_CONFIGURE | RU_CLIENT | RU_CONNECTING)

/* a connection that stays up */
RouterClient *RouterMakeConnection(char *host, int port, int process_id, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)())
{
  return RouterConnect(host,port,process_id,RU_NEW | RU_PERSISTENT,timeout,limit,NULL,connect_cb,
                       request_cb,event_cb,error_cb,0);
}

/* ... receiving the events of the given groups */
RouterClient *RouterMakeGroupConnection(char *host, int port, int process_id, RouterGroupSet *groups, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)())
{
  return RouterConnect(host,port,process_id,RU_NEW | RU_PERSISTENT,timeout,limit,groups,connect_cb,
                       request_cb,event_cb,error_cb,0);
}

/* a connection that disconnects once what was queued on it is sent */
RouterClient *RouterMakeTransConnection(char *host, int port, int process_id, int timeout, int limit, int (*connect_cb)(), void (*error_cb)())
{
  return RouterConnect(host,port,process_id,RU_NEW | RU_TRANSACTION,timeout,limit,NULL,connect_cb,
                       NULL,NULL,error_cb,0);
}

/* connect again, the same way (a new RouterClient; retrys counts up) */
void RouterRetryConnection(RouterClient *client)
{
  RouterConnect(client->id.hostname,client->port,client->process_id,
                (client->use & RU_KIND) | RU_INORDER | RU_CONFIGURE | RU_CLIENT | RU_CONNECTING,
                client->timeout,client->out_limit,&client->groups,client->connect_cb,
                client->request_cb,client->event_cb,client->error_cb,client->retrys + 1);
}

void RouterSetGroups(RouterClient *client, RouterGroupSet *groups)
{
  size_t len;

  RouterFreeGroups(client);
  if (groups == NULL || groups->count == 0)
    return;
  len = (groups->count + 7) >> 3;
  client->groups.count = groups->count;
  client->groups.bits = malloc(len);
  if (client->groups.bits == NULL)
    RouterMemError();
  memcpy(client->groups.bits,groups->bits,len);
}

/* make the connection; failures surface a second later through error_cb */
static RouterClient *RouterConnect(char *host, int port, int process_id, int use, int timeout, int limit, RouterGroupSet *groups, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)(), int retrys)
{
  RouterClient *client;
  uint32_t addr;
  int socket, rval;

  if (SocketGetAddr(host,&addr) != 0) {
    LogErrorHost(ROUTER_ERR_HOST_ADDR,"",0,host,0,"");
    socket = -1;
  }
  else if (UseUnix == 0 || !SocketIsLocalHost(host)) {
    socket = SocketMakeInetConnection(host,port,1);
    use |= RU_INET;
  }
  else {
    socket = SocketMakeUnixConnection(port,1);
    use |= RU_UNIX;
  }
  if (SocketSendBufsize != 0 || SocketReceiveBufsize != 0) {
    rval = SocketSetBufferSize(socket,SocketSendBufsize,SocketReceiveBufsize);
    if (rval < 0) {
      SocketCloseOnly(socket);
      socket = rval;
    }
  }
  client = RouterMakeClient(socket,addr,port,process_id,use,NULL,host,RouterGetConRequest);
  RouterInitClient(client,timeout,limit,connect_cb,request_cb,event_cb,error_cb);
  RouterSetGroups(client,groups);
  client->retrys = retrys;
  RouterAddClient(client);
  if (socket >= 0)
    RouterStartInput(client);
  else if (socket == -2)        /* nobody listening */
    RouterAddTimer(client,RouterConnectFailed,1);
  else
    RouterAddTimer(client,RouterConnectError,1);
  return client;
}

/* the input handler until the server has accepted us */
static int RouterGetConRequest(RouterClient *client)
{
  int argcountin;
  int rvalue;

  if (client->in_buf->opcode != client->process_id) {
    RouterLogError(ROUTER_ERR_PROCESS_ID,"",0,client,"ID = %d");
    RouterConnectionError(client);
    return -1;
  }
  switch (client->in_buf->clas) {
  case RC_ACCEPT:
    argcountin = RouterUnpack(client,client->in_buf);
    rvalue = RouterProcessAccept(client,argcountin);
    RouterFreeArguments(argcountin,client->InArgList);
    break;
  case RC_PASSWORD_REQ:
    rvalue = RouterGetPassword(client);
    break;
  case RC_DENIED:
    RouterClientError(client,ROUTER_ERR_DENIED);
    return -1;
  default:
    RouterBadClass(client,"RouterGetConRequest");
    return -1;
  }
  if (rvalue != 0) {
    RouterConnectionError(client);
    return -1;
  }
  return 0;
}

/*
 * Accepted: note the server's RouterID and send ours, with our type
 * (RouterClientType, big-endian: use, group count) and group bits. Only
 * RU_CONFIGURE of use goes over, so a server sees every connection as a
 * transaction connection (RouterSv.c).
 */
static int RouterProcessAccept(RouterClient *client, int argcountin)
{
  RouterArgument arglist[3];
  RouterArgument *nullarglist;
  RouterID client_id;
  unsigned char tbuf_a[8];      /* RouterClientType */
  unsigned char tbuf_b[128];    /* our RouterID */
  unsigned int use;
  int argcount;

  if (argcountin != 1) {
    LogError(ROUTER_ERR_ARG_COUNT,"RouterProcessAccept",0,"");
    return -1;
  }
  if (client->InArgList[0].clas != 1) {
    LogError(ROUTER_ERR_ARG_CLASS,"RouterProcessAccept",0,"");
    return -1;
  }
  RouterUnpackID(&client->id,(char *)client->InArgList[0].val,client->InArgList[0].size);

  use = client->use & RU_CONFIGURE;
  tbuf_a[0] = use >> 24;
  tbuf_a[1] = use >> 16;
  tbuf_a[2] = use >> 8;
  tbuf_a[3] = use;
  tbuf_a[4] = client->groups.count >> 24;
  tbuf_a[5] = client->groups.count >> 16;
  tbuf_a[6] = client->groups.count >> 8;
  tbuf_a[7] = client->groups.count;
  arglist[0].val = (uintptr_t)tbuf_a;
  arglist[0].fre = 1;
  arglist[0].clas = 1;
  arglist[0].size = sizeof(tbuf_a);
  RouterSetClientID(&client_id);
  arglist[1].val = (uintptr_t)tbuf_b;
  arglist[1].fre = 1;
  arglist[1].clas = 1;
  arglist[1].size = RouterPackID(&client_id,tbuf_b);
  argcount = 2;
  if (client->groups.count != 0) {
    arglist[2].val = (uintptr_t)client->groups.bits;
    arglist[2].fre = 1;
    arglist[2].clas = 1;
    arglist[2].size = (client->groups.count + 7) >> 3;
    argcount = 3;
  }
  RouterDoOutput(client,ProcessID,RC_CLIENT_ID,argcount,arglist,NULL,NULL,NULL,NULL,0,NULL);

  if ((client->use & RU_KIND) == RU_PERSISTENT)
    client->use = (client->use & ~RU_STATE) | RU_ACCEPTED | RU_CONNECTED;
  else
    client->use = (client->use & ~RU_STATE) | RU_CONNECTED;
  if (client->connect_cb != NULL)
    client->connect_cb(client,1,&nullarglist);
  client->in_handler = RouterProcessPacket;
  if ((client->use & RU_KIND) == RU_PERSISTENT)
    client->retrys = 0;
  else if (client->out_bytesleft < 1)
    RouterDisconnect(client,client->timeout);   /* a transaction with nothing to send */
  return 0;
}

/* the server wants a password: connect_cb(client, 2, &arglist) supplies it */
static int RouterGetPassword(RouterClient *client)
{
  RouterArgument *arglistout;
  int argcountout;

  if (client->connect_cb == NULL) {
    LogError(ROUTER_ERR_PROTOCOL,"RouterGetPassword",0,"");
    return -1;
  }
  argcountout = client->connect_cb(client,2,&arglistout);
  RouterDoOutput(client,ProcessID,RC_PASSWORD,argcountout,arglistout,NULL,NULL,NULL,NULL,0,NULL);
  return 0;
}

static RouterFunc RouterConnectFailed(RouterClient *client)
{
  client->timer_id = 0;
  RouterClientError(client,ROUTER_ERR_CONNECT_FAILED);
}

static RouterFunc RouterConnectError(RouterClient *client)
{
  client->timer_id = 0;
  RouterClientError(client,ROUTER_ERR_CONNECT_ERROR);
}
