/*
 * sys_ctrl/common/Router/RouterCl.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterCl.c
 */

#include <string.h>
#include "RouterCl.h"   /* needed by the reconstruction */
#include "../../l3/l2/discover.h"   /* needed by the reconstruction */
#include "Router.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "RouterInt.h"
#include "RouterMsg.h"
#include "../sys/Logger.h"
#include "../../l3/sys/LoggerMsg.h"
#include "Socket.h"
#include <signal.h>
#include <malloc.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static RouterClient *RouterConnect(char *host, int port, int process_id, int use, int timeout, int limit, RouterGroupSet *groups, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)(), int retrys);
static int RouterGetConRequest(RouterClient *client);
static int RouterProcessAccept(RouterClient *client, int argcountin);
static int RouterGetPassword(RouterClient *client);
static RouterFunc RouterConnectFailed(RouterClient *client);
static RouterFunc RouterConnectError(RouterClient *client);

RouterClient *RouterMakeConnection(char *host, int port, int process_id, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)())
{
  RouterClient *pRVar1;
  int use;
  
  pRVar1 = RouterConnect(host,port,process_id,0xc241,timeout,limit,NULL,connect_cb,
                         request_cb,event_cb,error_cb,0);
  return pRVar1;
}

RouterClient *RouterMakeGroupConnection(char *host, int port, int process_id, RouterGroupSet *groups, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)())
{
  RouterClient *pRVar1;
  int use;
  
  pRVar1 = RouterConnect(host,port,process_id,0xc241,timeout,limit,groups,connect_cb,request_cb,
                         event_cb,error_cb,0);
  return pRVar1;
}

RouterClient *RouterMakeTransConnection(char *host, int port, int process_id, int timeout, int limit, int (*connect_cb)(), void (*error_cb)())
{
  RouterClient *pRVar1;
  int use;
  
  pRVar1 = RouterConnect(host,port,process_id,0xc441,timeout,limit,NULL,connect_cb,
                         NULL,NULL,error_cb,0);
  return pRVar1;
}

void RouterRetryConnection(RouterClient *client)
{
  int use;
  
  RouterConnect((client->id).hostname,client->port,client->process_id,client->use & 0x600U | 0xc041,
                client->timeout,(int)client->out_limit,&client->groups,client->connect_cb,
                client->request_cb,client->event_cb,client->error_cb,client->retrys + 1);
  return;
}

void RouterSetGroups(RouterClient *client, RouterGroupSet *groups)
{
  char *pcVar1;
  
  RouterFreeGroups(client);
  if ((groups != NULL) && (groups->count != 0)) {
    (client->groups).count = groups->count;
    pcVar1 = malloc(groups->count + 7 >> 3);
    (client->groups).bits = pcVar1;
    if (pcVar1 == NULL) {
      RouterMemError();
    }
    memcpy((client->groups).bits,groups->bits,groups->count + 7 >> 3);
  }
  return;
}

static RouterClient *RouterConnect(char *host, int port, int process_id, int use, int timeout, int limit, RouterGroupSet *groups, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)(), int retrys)
{
  int rval;
  int iVar1;
  RouterClient *client;
  int nodelay;
  int socket;
  ulong addr;
  
  rval = SocketGetAddr(host,&addr);
  if (rval == 0) {
    if ((UseUnix == 0) || (iVar1 = SocketIsLocalHost(host), iVar1 == 0)) {
      socket = SocketMakeInetConnection(host,port,1);
      use = use | 0x1000;
    }
    else {
      socket = SocketMakeUnixConnection(port,1);
      use = use | 0x2000;
    }
  }
  else {
    LogErrorHost(-0x13b,"",0,host,0,"");
    socket = -1;
  }
  if (((SocketSendBufsize != 0) || (SocketReceiveBufsize != 0)) &&
     (iVar1 = SocketSetBufferSize(socket,SocketSendBufsize,SocketReceiveBufsize), iVar1 < 0)) {
    SocketCloseOnly(socket);
    socket = iVar1;
  }
  client = RouterMakeClient(socket,addr,port,process_id,use,NULL,host,
                            RouterGetConRequest);
  RouterInitClient(client,timeout,limit,connect_cb,request_cb,event_cb,error_cb);
  RouterSetGroups(client,groups);
  client->retrys = retrys;
  RouterAddClient(client);
  if (socket < 0) {
    if (socket == -2) {
      RouterAddTimer(client,RouterConnectFailed,1);
    }
    else {
      RouterAddTimer(client,RouterConnectError,1);
    }
  }
  else {
    RouterStartInput(client);
  }
  return client;
}

static int RouterGetConRequest(RouterClient *client)
{
  byte bVar1;
  int iVar2;
  int rvalue;
  int argcountin;
  char *func_name;
  
  if ((uint)client->in_buf->opcode != client->process_id) {
    RouterLogError(-0x142,"",0,client,"ID = %d");
    RouterConnectionError(client);
    return -1;
  }
  bVar1 = client->in_buf->clas;
  if (bVar1 == 4) {
    iVar2 = RouterUnpack(client,client->in_buf);
    rvalue = RouterProcessAccept(client,iVar2);
    RouterFreeArguments(iVar2,client->InArgList);
LAB_08079687:
    if (rvalue == 0) {
      iVar2 = 0;
    }
    else {
      RouterConnectionError(client);
      iVar2 = -1;
    }
  }
  else {
    if (bVar1 < 5) {
      if (bVar1 == 1) {
        rvalue = RouterGetPassword(client);
        goto LAB_08079687;
      }
    }
    else if (bVar1 == 0x22) {
      RouterClientError(client,-0x143);
      return -1;
    }
    RouterBadClass(client,"RouterGetConRequest");
    iVar2 = -1;
  }
  return iVar2;
}

static int RouterProcessAccept(RouterClient *client, int argcountin)
{
  char *pcVar1;
  uchar *__dest;
  char *__s;
  int iVar2;
  size_t sVar3;
  int idsize;
  uchar *tptro;
  uchar tbuf_b [128];
  uchar tbuf_a [8];
  int argcount;
  RouterArgument *nullarglist;
  RouterArgument arglist [3];
  RouterID client_id;
  RouterID *server_id;
  char *func_name;
  uchar *tptr;
  
  if (argcountin == 1) {
    if (client->InArgList->clas == 1) {
      iVar2 = client->InArgList->size;   /* original: *(int *) word >> 8 */
      __s = (char *)client->InArgList->val;
      sVar3 = strlen(__s);
      memcpy((client->id).procname,__s,sVar3 + 1);
      sVar3 = strlen(__s);
      pcVar1 = __s + sVar3 + 1;
      sVar3 = strlen(pcVar1);
      memcpy((client->id).username,pcVar1,sVar3 + 1);
      sVar3 = strlen(pcVar1);
      pcVar1 = pcVar1 + sVar3 + 1;
      sVar3 = strlen(pcVar1);
      memcpy((client->id).fullname,pcVar1,sVar3 + 1);
      sVar3 = strlen(pcVar1);
      if ((int)((pcVar1 + sVar3 + 1) - __s) < iVar2) {
        memcpy(&(client->id).ipaddr,pcVar1 + sVar3 + 1,4);
      }
      RouterSetClientID(&client_id);
      tbuf_a[0] = '\0';
      tbuf_a[1] = '\0';
      tbuf_a[2] = (byte)((uint)client->use >> 8) & 0x40;
      tbuf_a[3] = '\0';
      tbuf_a[4] = (uchar)((client->groups).count >> 0x18);
      tbuf_a[5] = (uchar)((client->groups).count >> 0x10);
      tbuf_a[6] = (uchar)((client->groups).count >> 8);
      tbuf_a[7] = (uchar)(client->groups).count;
      arglist[0].val = (ulong)tbuf_a;
      arglist[0].fre = 1;
      arglist[0].clas = 1;
      arglist[0].size = 8;
      sVar3 = strlen(client_id.procname);
      memcpy(tbuf_b,client_id.procname,sVar3 + 1);
      sVar3 = strlen(client_id.procname);
      tptr = tbuf_b + sVar3 + 1;
      sVar3 = strlen(client_id.username);
      memcpy(tptr,client_id.username,sVar3 + 1);
      sVar3 = strlen(client_id.username);
      __dest = tptr + sVar3 + 1;
      sVar3 = strlen(client_id.fullname);
      memcpy(__dest,client_id.fullname,sVar3 + 1);
      sVar3 = strlen(client_id.fullname);
      memcpy(__dest + sVar3 + 1,&client_id.ipaddr,4);
      arglist[1].val = (ulong)tbuf_b;
      arglist[1].fre = 1;
      arglist[1].clas = 1;
      arglist[1].size = (int)((__dest + sVar3 + 1 + 4) - (uchar *)tbuf_b);
      if ((client->groups).count == 0) {
        argcount = 2;
      }
      else {
        arglist[2].val = (ulong)(client->groups).bits;
        arglist[2].fre = 1;
        arglist[2].clas = 1;
        arglist[2].size = ((client->groups).count + 7) >> 3;
        argcount = 3;
      }
      RouterDoOutput(client,ProcessID,8,argcount,arglist,NULL,NULL,
                     NULL,NULL,0,NULL);
      if ((client->use & 0x600U) == 0x200) {
        client->use = client->use & 0xffffffc0U | 6;
      }
      else {
        client->use = client->use & 0xffffffc0U | 4;
      }
      if (client->connect_cb != NULL) {
        (*client->connect_cb)(client,1,&nullarglist);
      }
      client->in_handler = RouterProcessPacket;
      if ((client->use & 0x600U) == 0x200) {
        client->retrys = 0;
      }
      else if (client->out_bytesleft < 1) {
        RouterDisconnect(client,client->timeout);
      }
      iVar2 = 0;
    }
    else {
      LogError(-0x13f,"RouterProcessAccept",0,"");
      iVar2 = -1;
    }
  }
  else {
    LogError(-0x13e,"RouterProcessAccept",0,"");
    iVar2 = -1;
  }
  return iVar2;
}

static int RouterGetPassword(RouterClient *client)
{
  int iVar1;
  RouterArgument *arglistout;
  int argcountout;
  char *func_name;
  
  func_name = "RouterGetPassword";
  if (client->connect_cb == NULL) {
    LogError(-0x13d,"RouterGetPassword",0,"");
    iVar1 = -1;
  }
  else {
    argcountout = (*client->connect_cb)(client,2,&arglistout);
    RouterDoOutput(client,ProcessID,2,argcountout,arglistout,NULL,NULL,
                   NULL,NULL,0,NULL);
    iVar1 = 0;
  }
  return iVar1;
}

static RouterFunc RouterConnectFailed(RouterClient *client)
{
  client->timer_id = 0;
  RouterClientError(client,-300);
  return;
}

static RouterFunc RouterConnectError(RouterClient *client)
{
  client->timer_id = 0;
  RouterClientError(client,-0x12e);
  return;
}
