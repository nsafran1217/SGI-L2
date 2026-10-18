/*
 * sys_ctrl/common/Router/Router.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Router.c
 */

#include <stdlib.h>
#include <unistd.h>
#include "Buff.h"   /* needed by the reconstruction */
#include "../sys/MemUsage.h"   /* needed by the reconstruction */
#include "../../l3/l2/discover.h"   /* needed by the reconstruction */
#include "../../l3/l2/smp.h"   /* needed by the reconstruction */
#include "Router.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "RouterInt.h"
#include "RouterMsg.h"
#include "../sys/Logger.h"
#include "../../l3/sys/LoggerMsg.h"
#include "Socket.h"
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <errno.h>
struct bitbuf {
    unsigned int value;
};
#include <malloc.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void call_SocketSetBufferSize(RouterClient *client);
static int RouterProcessRequest(RouterClient *client, int argcountin);
static int RouterProcessResponse(RouterClient *client, int argcountin);
static int RouterProcessEvent(RouterClient *client, int argcountin);
static int RouterProcessDisRequest(RouterClient *client);
static int RouterProcessDisResponse(RouterClient *client);
static int RouterProcessConfigInit(RouterClient *client, int argcountin);
static int RouterProcessConfigRequest(RouterClient *client, int argcountin);
static int RouterProcessConfigResponse(RouterClient *client, int argcountin);
static void RouterStartOutput(RouterClient *client, RouterQEntry *entry);
static void RouterLoadOutput(RouterClient *client, RouterQEntry *entry);
static RouterFunc RouterOutput(RouterClient *client);
static void RouterReloadOutput(RouterClient *client);
static void RouterCheckOutputMonitor(RouterClient *client);
static void RouterPrintStats(FILE *fd, RouterCompressStats *s);
static void RouterQStore(RouterQ *queue, RouterQEntry *entry, int use_priority);
static RouterQEntry *RouterQRetrieve(RouterQ *queue);
static void RouterQRemoveRequests(RouterClient *client, RouterQ *queue);
static void RouterFreeQueue(RouterClient *client, RouterQ *queue, int return_rel_request);
static void RouterFreeEntry(RouterClient *client, RouterQEntry *entry, int return_rel_request);
static void RouterFreePacket(RouterQEntry *entry);
static void RouterAddInput(RouterClient *client);
static void RouterRemoveInput(RouterClient *client);
static void RouterAddOutput(RouterClient *client);
static void RouterRemoveOutput(RouterClient *client);

RouterClientList ClientList;
RouterServerList ServerList;
int MaxInArgs;
int UseUnix;
char *ProcessName = "";
int ProcessID;
void (*FatalCB)();
void (*ClientFreeCB)();
long unsigned int IPAddress;
RouterConfig RouterLocalConfig = { .rev = 2, .flags = 2147483648 };
int SocketSendBufsize;
int SocketReceiveBufsize;
int MonitorHighWaterEntries;
int MonitorHighWaterBytes;
int MonitorLowWaterEntries;
int MonitorLowWaterBytes;
int debug;
Username UserName;
Fullname FullName;
RouterCompressStats InputStats;
RouterCompressStats OutputStats;
void (*MonitorCB)();
void *MonitorCBData;
static struct bitbuf lbitbuf;
static struct bitbuf ubitbuf;
static int bufsize_rval;

int RouterInit(int max_in_args, int use_unix, char *process_name, int process_id, void (*fatal_cb)())
{
  char *pcVar1;
  __uid_t __uid;
  int iVar2;
  char *myhost;
  struct passwd *pw;
  
  MaxInArgs = max_in_args;
  if (max_in_args < 10) {
    MaxInArgs = 10;
  }
  ProcessID = process_id;
  FatalCB = fatal_cb;
  memset(&InputStats,0,sizeof(RouterCompressStats));
  memset(&OutputStats,0,sizeof(RouterCompressStats));
  pcVar1 = strrchr(process_name,0x2f);
  if (pcVar1 == NULL) {
    ProcessName = process_name;
  }
  else {
    ProcessName = pcVar1 + 1;
  }
  signal(0xd,SIG_IGN);
  memset(UserName,0,9);
  memset(FullName,0,0x21);
  __uid = getuid();
  pw = (struct passwd *)getpwuid(__uid);
  if (pw == NULL) {
    LogError(-0x141,"",0,"");
    iVar2 = -1;
  }
  else {
    strncpy(UserName,((struct passwd *)pw)->pw_name,8);
    strncpy(FullName,pw->pw_gecos,0x20);
    iVar2 = SocketGetHostName(&myhost);
    if (iVar2 == -1) {
      myhost = "localhost";
    }
    SocketGetAddr(myhost,&IPAddress);
    iVar2 = 0;
  }
  return iVar2;
}

int RouterSetFreeCB(void (*free_cb)())
{
  ClientFreeCB = free_cb;
  return 0;   /* the original left free_cb in %eax; no caller uses the result */
}

int RouterClientsConnected(void)
{
  int clients;
  RouterClient *client_ptr;
  
  clients = 0;
  for (client_ptr = ClientList.head; client_ptr != NULL;
      client_ptr = client_ptr->next) {
    if (((client_ptr->use & 2U) != 0) && ((client_ptr->use & 0xc0U) == 0x80)) {
      clients = clients + 1;
    }
  }
  return clients;
}

int RouterConnectionCount(void)
{
  int clients;
  RouterClient *client_ptr;
  
  clients = 0;
  for (client_ptr = ClientList.head; client_ptr != NULL;
      client_ptr = client_ptr->next) {
    if ((client_ptr->use & 2U) != 0) {
      clients = clients + 1;
    }
  }
  return clients;
}

int RouterHostConnected(char *host, int port, int process_id, RouterClient **client)
{
  int iVar1;
  uint uVar2;
  
  *client = ClientList.head;
  do {
    if (*client == NULL) {
      return 0;
    }
    iVar1 = strcmp(((*client)->id).hostname,host);
    if (((iVar1 == 0) && ((*client)->port == port)) && ((*client)->process_id == process_id)) {
      uVar2 = (*client)->use & 5;
      if (uVar2 == 1) {
        if (((*client)->use & 0xc0U) == 0x40) {
          return 1;
        }
      }
      else if (uVar2 == 4) {
        return 4;
      }
    }
    *client = (*client)->next;
  } while( true );
}

int RouterAddrConnected(long unsigned int addr, int port, int process_id, RouterClient **client)
{
  uint uVar1;
  
  *client = ClientList.head;
  do {
    if (*client == NULL) {
      return 0;
    }
    if ((((*client)->addr == addr) && ((*client)->port == port)) &&
       ((*client)->process_id == process_id)) {
      uVar1 = (*client)->use & 5;
      if (uVar1 == 1) {
        if (((*client)->use & 0xc0U) == 0x40) {
          return 1;
        }
      }
      else if (uVar1 == 4) {
        return 4;
      }
    }
    *client = (*client)->next;
  } while( true );
}

void RouterInitClient(RouterClient *client, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)())
{
  client->timeout = timeout;
  client->out_limit = (short)limit;
  client->connect_cb = connect_cb;
  client->request_cb = request_cb;
  client->event_cb = event_cb;
  client->error_cb = error_cb;
  return;
}

int RouterRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, int limit)
{
  int iVar1;
  
  iVar1 = RouterPriRequestOut(client,opcode,argcount,arglist,response_cb,response_data,limit,0,
                              NULL);
  return iVar1;
}

int RouterPriRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, int limit, int priority, void *purge_data)
{
  int iVar1;
  char *func_name;
  uchar priority_;
  
  iVar1 = RouterCheckOutput(client,"RouterRequestOut");
  if (iVar1 == 0) {
    if ((limit == 1) && ((int)client->out_limit <= (client->out_queue).total)) {
      iVar1 = -2;
    }
    else {
      RouterDoOutput(client,opcode,0x10,argcount,arglist,response_cb,response_data,
                     NULL,NULL,priority & 0xff,purge_data);
      iVar1 = 0;
    }
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

int RouterRelRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, void (*error_cb)(), void *error_data, int limit)
{
  int iVar1;
  
  iVar1 = RouterPriRelRequestOut
                    (client,opcode,argcount,arglist,response_cb,response_data,error_cb,error_data,
                     limit,0,NULL);
  return iVar1;
}

int RouterPriRelRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, void (*error_cb)(), void *error_data, int limit, int priority, void *purge_data)
{
  int iVar1;
  char *func_name;
  uchar priority_;
  
  iVar1 = RouterCheckOutput(client,"RouterRelRequestOut");
  if (iVar1 == 0) {
    if ((limit == 1) && ((int)client->out_limit <= (client->out_queue).total)) {
      iVar1 = -2;
    }
    else {
      RouterDoOutput(client,opcode,0x20,argcount,arglist,response_cb,response_data,error_cb,
                     error_data,priority & 0xff,purge_data);
      iVar1 = 0;
    }
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

void RouterResponseOut(RouterClient *client, int argcount, RouterArgument *arglist)
{
  RouterPriResponseOut(client,argcount,arglist,0,NULL);
  return;
}

void RouterPriResponseOut(RouterClient *client, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  uchar priority_;
  
  RouterDoOutput(client,0,0x40,argcount,arglist,NULL,NULL,
                 NULL,NULL,priority & 0xff,purge_data);
  client->ResponseSent = 1;
  return;
}

int RouterEventOut(int opcode, int argcount, RouterArgument *arglist)
{
  int iVar1;
  
  iVar1 = RouterPriEventOut(opcode,argcount,arglist,0,NULL);
  return iVar1;
}

int RouterPriEventOut(int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  int events_sent;
  RouterQEntry *entry;
  RouterClient *client_ptr;
  uchar priority_;
  
  events_sent = 0;
  for (client_ptr = ClientList.head; client_ptr != NULL;
      client_ptr = client_ptr->next) {
    if ((client_ptr->use & 4U) != 0) {
      RouterDoOutput(client_ptr,opcode,0x80,argcount,arglist,NULL,NULL,
                     NULL,NULL,priority & 0xff,purge_data);
      events_sent = events_sent + 1;
    }
  }
  return events_sent;
}

int RouterIDEventOut(int process_id, int opcode, int argcount, RouterArgument *arglist)
{
  int iVar1;
  
  iVar1 = RouterPriIDEventOut(process_id,opcode,argcount,arglist,0,NULL);
  return iVar1;
}

int RouterPriIDEventOut(int process_id, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  int events_sent;
  RouterQEntry *entry;
  RouterClient *client_ptr;
  uchar priority_;
  
  events_sent = 0;
  for (client_ptr = ClientList.head; client_ptr != NULL;
      client_ptr = client_ptr->next) {
    if ((client_ptr->process_id == process_id) && ((client_ptr->use & 4U) != 0)) {
      RouterDoOutput(client_ptr,opcode,0x80,argcount,arglist,NULL,NULL,
                     NULL,NULL,priority & 0xff,purge_data);
      events_sent = events_sent + 1;
    }
  }
  return events_sent;
}

int RouterGroupEventOut(int process_id, int group, int opcode, int argcount, RouterArgument *arglist)
{
  int iVar1;
  
  iVar1 = RouterPriGroupEventOut(process_id,group,opcode,argcount,arglist,0,NULL);
  return iVar1;
}

int RouterPriGroupEventOut(int process_id, int group, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  int group_index;
  int iVar1;
  char group_mask;
  int events_sent;
  RouterQEntry *entry;
  RouterClient *client_ptr;
  uchar priority_;
  
  client_ptr = ClientList.head;
  events_sent = 0;
  group_index = group;
  if (group < 0) {
    group_index = group + 7;
  }
  iVar1 = group;
  if (group < 0) {
    iVar1 = group + 7;
  }
  for (; client_ptr != NULL; client_ptr = client_ptr->next) {
    if (((client_ptr->process_id == process_id) && ((uint)group <= (client_ptr->groups).count)) &&
       ((byte)((client_ptr->groups).bits[group_index >> 3] &
              (byte)(1 << ((char)group + (char)(iVar1 >> 3) * -8 & 0x1fU))) != 0)) {
      RouterDoOutput(client_ptr,opcode,0x80,argcount,arglist,NULL,NULL,
                     NULL,NULL,priority & 0xff,purge_data);
      events_sent = events_sent + 1;
    }
  }
  return events_sent;
}

void RouterClientEventOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist)
{
  RouterPriClientEventOut(client,opcode,argcount,arglist,0,NULL);
  return;
}

void RouterPriClientEventOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  uchar priority_;
  
  RouterDoOutput(client,opcode,0x80,argcount,arglist,NULL,NULL,
                 NULL,NULL,priority & 0xff,purge_data);
  return;
}

void RouterFlushOutputs(int timeout)
{
  RouterClient *client_ptr;
  
  for (client_ptr = ClientList.head; client_ptr != NULL;
      client_ptr = client_ptr->next) {
    if ((client_ptr->use & 4U) != 0) {
      RouterFlushOutput(client_ptr,timeout);
    }
  }
  return;
}

void RouterFlushOutput(RouterClient *client, int timeout)
{
  byte bVar1;
  int *piVar2;
  int iVar3;
  RouterClient *client_00;
  char *format;
  int rvalue;
  int sleeps;
  
  sleeps = 0;
  if (client->out_bytesleft < 1) {
    RouterReloadOutput(client);
  }
LAB_08075a70:
  do {
    if (client->out_bytesleft < 1) {
      return;
    }
    rvalue = write(client->socket,client->out_bufptr,client->out_bytesleft);
    if (rvalue < 0) {
      piVar2 = __errno_location();
      iVar3 = *piVar2;
      if (iVar3 == 0x6b) {
LAB_08075b10:
        RouterConnectionLost(client);
        return;
      }
      if (0x6b < iVar3) {
        if ((0x6f < iVar3) || (iVar3 < 0x6e)) goto LAB_08075b21;
        goto LAB_08075b10;
      }
      if (iVar3 == 0x65) goto LAB_08075b10;
      if (0x65 < iVar3) {
        if (iVar3 != 0x68) {
LAB_08075b21:
          format = "";
          client_00 = client;
          piVar2 = __errno_location();
          RouterLogError(-0x131,"write",*piVar2,client_00,format);
          RouterConnectionError(client);
          return;
        }
        goto LAB_08075b10;
      }
      if (iVar3 != 0xb) {
        if (iVar3 != 0x20) goto LAB_08075b21;
        goto LAB_08075b10;
      }
      sleeps = sleeps + 1;
      if (timeout < sleeps) {
        return;
      }
      sleep(1);
      rvalue = 0;
    }
    iVar3 = client->out_bytesleft - rvalue;
    client->out_bytesleft = iVar3;
    if (iVar3 < 1) {
      bVar1 = (client->out_buf->header).clas;
      if (bVar1 == 0x10) {
        RouterFreePacket(client->out_buf);
LAB_08075bb2:
        RouterQStore(&client->in_queue,client->out_buf,0);
      }
      else {
        if (bVar1 == 0x20) goto LAB_08075bb2;
        RouterFreeEntry(client,client->out_buf,0);
      }
      RouterReloadOutput(client);
      goto LAB_08075a70;
    }
    client->out_bufptr = client->out_bufptr + rvalue;
  } while( true );
}

int RouterDisconnectClients(int timeout)
{
  int clients;
  RouterClient *client_ptr;
  
  clients = 0;
  for (client_ptr = ClientList.head; client_ptr != NULL;
      client_ptr = client_ptr->next) {
    if (((client_ptr->use & 2U) != 0) && ((client_ptr->use & 0xc0U) == 0x80)) {
      RouterDisconnect(client_ptr,timeout);
      clients = clients + 1;
    }
  }
  return clients;
}

void RouterDisconnect(RouterClient *client, int timeout)
{
  client->use = client->use & 0xffffffc0U | 8;
  if (timeout < 1) {
    timeout = 1;
  }
  client->timeout = timeout;
  RouterDoOutput(client,0,0x11,0,NULL,NULL,NULL,
                 NULL,NULL,0xff,NULL);
  return;
}

void RouterShutDownClients(void)
{
  while (ClientList.head != NULL) {
    RouterDoClose(ClientList.head,0);
  }
  return;
}

void RouterCloseOnlyClients(void)
{
  while (ClientList.head != NULL) {
    RouterCloseOnlyClient(ClientList.head);
  }
  return;
}

void RouterCloseOnlyClient(RouterClient *client)
{
  if (0 < client->socket) {
    RouterRemoveInput(client);
    if ((0 < client->out_bytesleft) && (client->out_stopped == '\0')) {
      RouterRemoveOutput(client);
    }
    SocketCloseOnly(client->socket);
  }
  RouterRemoveClient(client,0);
  return;
}

void RouterPing(RouterClient *client)
{
  RouterDoOutput(client,0,0x24,0,NULL,NULL,NULL,
                 NULL,NULL,0xff,NULL);
  RouterFlushOutput(client,0);
  return;
}

static void call_SocketSetBufferSize(RouterClient *client)
{
  int rval;
  
  rval = SocketSetBufferSize(client->socket,SocketSendBufsize,SocketReceiveBufsize);
  if ((rval != 0) && (bufsize_rval == 0)) {
    bufsize_rval = rval;
  }
  return;
}

int RouterSetBufferSize(int sendbuf, int recvbuf)
{
  SocketSendBufsize = sendbuf;
  SocketReceiveBufsize = recvbuf;
  bufsize_rval = 0;
  RouterListClients(call_SocketSetBufferSize);
  return bufsize_rval;
}

int RouterClientSetBufferSize(RouterClient *client, int sendbuf, int recvbuf)
{
  int iVar1;
  
  iVar1 = SocketSetBufferSize(client->socket,sendbuf,recvbuf);
  return iVar1;
}

RouterClient *RouterMakeClient(int socket, long unsigned int addr, int port, int process_id, int use, RouterServer *server, char *host, int (*in_handler)())
{
  RouterClient *__s;
  RouterArgument *pRVar1;
  int i;
  RouterClient *client;
  
  __s = malloc(sizeof(RouterClient));
  if (__s == NULL) {
    RouterMemError();
  }
  memset(__s,0,sizeof(RouterClient));
  __s->socket = socket;
  __s->addr = addr;
  __s->port = port;
  __s->process_id = process_id;
  __s->use = use;
  __s->server = server;
  strncpy((__s->id).hostname,host,0x40);
  __s->in_handler = in_handler;
  __s->InArgList = NULL;
  if (__s->InArgList == NULL) {
    pRVar1 = malloc(MaxInArgs * sizeof(RouterArgument));
    __s->InArgList = pRVar1;
    if (pRVar1 == NULL) {
      RouterMemError();
    }
    __s->InArgListSize = MaxInArgs;
    for (i = 0; i < __s->InArgListSize; i = i + 1) {
      __s->InArgList[i].clas = 0;
      __s->InArgList[i].val = 0;
      __s->InArgList[i].fre = 0;
      *(uint *)(__s->InArgList + i) = *(uint *)(__s->InArgList + i) & 0xff;
    }
  }
  return __s;
}

void RouterSetClientID(RouterID *client_id)
{
  memset(client_id,0,0x80);
  strncpy(client_id->procname,ProcessName,0x10);
  strncpy(client_id->username,UserName,8);
  strncpy(client_id->fullname,FullName,0x20);
  client_id->ipaddr = IPAddress;
  return;
}

void RouterAddClient(RouterClient *client)
{
  if (ClientList.tail == NULL) {
    ClientList.head = client;
  }
  else {
    (ClientList.tail)->next = client;
  }
  ClientList.tail = client;
  client->next = NULL;
  ClientList.total = ClientList.total + 1;
  return;
}

void RouterRemoveClient(RouterClient *client, int return_rel_request)
{
  RouterClient *last_client;
  RouterClient *client_ptr;
  
  client_ptr = ClientList.head;
  last_client = NULL;
  while( true ) {
    if (client_ptr == NULL) {
      return;
    }
    if (client_ptr == client) break;
    last_client = client_ptr;
    client_ptr = client_ptr->next;
  }
  if (client_ptr == ClientList.head) {
    if (client_ptr->next == NULL) {
      ClientList.head = NULL;
      ClientList.tail = NULL;
    }
    else {
      ClientList.head = client_ptr->next;
    }
  }
  else if (client_ptr == ClientList.tail) {
    ClientList.tail = last_client;
    last_client->next = NULL;
  }
  else {
    last_client->next = client_ptr->next;
  }
  RouterFreeClient(client,return_rel_request);
  ClientList.total = ClientList.total + -1;
  return;
}

RouterClient *RouterFindClient(RouterClient *client)
{
  RouterClient *client_ptr;
  
  client_ptr = ClientList.head;
  while( true ) {
    if (client_ptr == NULL) {
      return NULL;
    }
    if (client_ptr == client) break;
    client_ptr = client_ptr->next;
  }
  return client;
}

void RouterListClients(void (*cb_func)())
{
  RouterClient *last_client;
  RouterClient *client_ptr;
  
  for (client_ptr = ClientList.head; client_ptr != NULL;
      client_ptr = client_ptr->next) {
    (*cb_func)(client_ptr);
  }
  return;
}

void RouterStartInput(RouterClient *client)
{
  if (client->in_buf != NULL) {
    free(client->in_buf);
  }
  client->in_bufptr = NULL;
  client->in_buf = NULL;
  client->in_bufsize = 0;
  client->in_bytesneeded = 8;
  client->in_hostbyteorder = 0;
  RouterAddInput(client);
  return;
}

RouterFunc RouterInput(RouterClient *client)
{
  uint uVar1;
  uint uVar2;
  uchar *bptr;
  int rvalue;
  int *piVar3;
  RouterHeader *pRVar4;
  int iVar5;
  RouterClient *pRVar6;
  int buf_bytesneeded;
  char *format;
  RouterHeader thdr;
  int bytesread;
  
  if (client->in_buf == NULL) {
    client->in_bufsize = 8;
    bptr = malloc(client->in_bufsize);
    client->in_buf = (RouterHeader *)bptr;
    if (bptr == NULL) {
      RouterMemError();
    }
    client->in_bufptr = (char *)client->in_buf;
  }
  if (0 < client->in_bytesneeded) {
    rvalue = read(client->socket,client->in_bufptr,client->in_bytesneeded);
    if (rvalue < 0) {
      piVar3 = __errno_location();
      iVar5 = *piVar3;
      if (iVar5 != 0x6b) {
        if (iVar5 < 0x6c) {
          if (iVar5 != 0x65) {
            if (iVar5 < 0x66) {
              if (iVar5 == 0xb) {
                return;
              }
              if (iVar5 != 0x20) {
LAB_08076364:
                format = "";
                pRVar6 = client;
                piVar3 = __errno_location();
                RouterLogError(-0x131,"read",*piVar3,pRVar6,format);
                RouterConnectionError(client);
                return;
              }
            }
            else if (iVar5 != 0x68) goto LAB_08076364;
          }
        }
        else if ((0x6f < iVar5) || (iVar5 < 0x6e)) goto LAB_08076364;
      }
      RouterConnectionLost(client);
      return;
    }
    if (rvalue == 0) {
      RouterConnectionLost(client);
      return;
    }
    client->in_bufptr = client->in_bufptr + rvalue;
    client->in_bytesneeded = client->in_bytesneeded - rvalue;
  }
  if (client->in_bytesneeded < 1) {
    if (client->in_hostbyteorder == 0) {
      /* header arrives big-endian: opcode(2) clas(1) id(1) config(1) length(3) */
      uint8 *b = (uint8 *)client->in_buf;
      thdr.opcode = (b[0] << 8) | b[1];
      thdr.clas = b[2];
      thdr.id = b[3];
      thdr.config = b[4];
      thdr.length = (b[5] << 16) | (b[6] << 8) | b[7];
      memcpy(client->in_buf,&thdr,8);
      client->in_hostbyteorder = 1;
    }
    if ((uint)((int)(client->in_bufptr - (char *)client->in_buf)) < client->in_buf->length + 8) {
      client->in_bytesneeded = client->in_buf->length;
      buf_bytesneeded = client->in_bytesneeded + 8;
      if (client->in_bufsize < buf_bytesneeded) {
        pRVar4 = realloc(client->in_buf,buf_bytesneeded);
        client->in_buf = pRVar4;
        if (pRVar4 == NULL) {
          RouterMemError();
        }
        client->in_bufptr = (char *)(client->in_buf + 1);
        client->in_bufsize = buf_bytesneeded;
      }
    }
    else {
      client->in_pkts = client->in_pkts + 1;
      iVar5 = (*client->in_handler)(client);
      if ((iVar5 == 0) && (pRVar6 = RouterFindClient(client), pRVar6 != NULL)) {
        free(client->in_buf);
        client->in_buf = NULL;
        client->in_bufsize = 0;
        client->in_bufptr = NULL;
        client->in_bytesneeded = 8;
        client->in_sequence = 0;
        client->in_hostbyteorder = 0;
        if ((client->out_stopped != '\0') &&
           ((client->out_bytesleft != 0 && ((client->in_queue).total < 0xe7)))) {
          RouterAddOutput(client);
          client->out_stopped = '\0';
        }
      }
    }
  }
  return;
}

int RouterProcessPacket(RouterClient *client)
{
  byte bVar1;
  int argcountin;
  int rvalue;
  char *func_name;
  
  argcountin = RouterUnpack(client,client->in_buf);
  bVar1 = client->in_buf->clas;
  if (bVar1 == 0x18) {
    rvalue = RouterProcessConfigRequest(client,argcountin);
    goto LAB_08076830;
  }
  if (bVar1 < 0x19) {
    if (bVar1 == 0x11) {
      rvalue = RouterProcessDisRequest(client);
      goto LAB_08076830;
    }
    if (bVar1 < 0x12) {
      if (bVar1 == 0x10) {
LAB_08076732:
        rvalue = RouterProcessRequest(client,argcountin);
        goto LAB_08076830;
      }
    }
    else {
      if (bVar1 == 0x12) {
        rvalue = RouterProcessDisResponse(client);
        goto LAB_08076830;
      }
      if (bVar1 == 0x14) {
        rvalue = RouterProcessConfigInit(client,argcountin);
        goto LAB_08076830;
      }
    }
  }
  else {
    if (bVar1 == 0x24) {
      rvalue = 0;
      goto LAB_08076830;
    }
    if (bVar1 < 0x25) {
      if (bVar1 == 0x20) goto LAB_08076732;
      if (bVar1 == 0x21) {
        rvalue = RouterProcessConfigResponse(client,argcountin);
        goto LAB_08076830;
      }
    }
    else {
      if (bVar1 == 0x40) {
        rvalue = RouterProcessResponse(client,argcountin);
        goto LAB_08076830;
      }
      if (bVar1 == 0x80) {
        rvalue = RouterProcessEvent(client,argcountin);
        goto LAB_08076830;
      }
    }
  }
  RouterBadClass(client,"RouterProcessPacket");
  rvalue = -1;
LAB_08076830:
  RouterFreeArguments(argcountin,client->InArgList);
  return rvalue;
}

static int RouterProcessRequest(RouterClient *client, int argcountin)
{
  int iVar1;
  RouterArgument *arglistout;
  int argcountout;
  char *func_name;
  
  func_name = "RouterProcessRequest";
  if (client->request_cb == NULL) {
    LogError(-0x13d,"RouterProcessRequest",0,"");
    RouterConnectionError(client);
    iVar1 = -1;
  }
  else {
    client->in_sequence = (ushort)client->in_buf->id;
    client->ResponseSent = 0;
    argcountout = (*client->request_cb)
                            (client,(uint)client->in_buf->opcode,argcountin,client->InArgList,
                             &arglistout);
    if (client->ResponseSent == 0) {
      RouterResponseOut(client,argcountout,arglistout);
    }
    iVar1 = 0;
  }
  return iVar1;
}

static int RouterProcessResponse(RouterClient *client, int argcountin)
{
  int *piVar1;
  uint uVar2;
  RouterQEntry *prev;
  RouterQEntry *response;
  char *func_name;
  
  if ((client->use & 0x18000U) == 0x8000) {
    response = RouterQRetrieve(&client->in_queue);
    if (response == NULL) {
      LogError(-0x13d,"RouterProcessResponse",0,"");
      RouterConnectionError(client);
      return -1;
    }
    if (client->in_buf->id != (response->header).id) {
      LogError(-0x13a,"RouterProcessResponse",0,"");
      RouterFreeEntry(client,response,0);
      RouterConnectionError(client);
      return -1;
    }
  }
  else {
    prev = NULL;
    for (response = (client->in_queue).head;
        (response != NULL && (client->in_buf->id != (response->header).id));
        response = response->next) {
      prev = response;
    }
    if (response == NULL) {
      LogError(-0x13d,"RouterProcessResponse",0,"request not found");
      RouterConnectionError(client);
      return -1;
    }
    if ((client->in_queue).head == (client->in_queue).tail) {
      (client->in_queue).tail = NULL;
      (client->in_queue).head = NULL;
    }
    else if (prev == NULL) {
      (client->in_queue).head = response->next;
    }
    else {
      prev->next = response->next;
    }
    piVar1 = &(client->in_queue).total;
    *piVar1 = *piVar1 + -1;
    (client->in_queue).bytes = (client->in_queue).bytes - (response->header).length;
  }
  if (response->response_cb != NULL) {
    (*response->response_cb)(client,response->response_data,argcountin,client->InArgList);
  }
  RouterFreeEntry(client,response,0);
  return 0;
}

static int RouterProcessEvent(RouterClient *client, int argcountin)
{
  if (client->event_cb != NULL) {
    (*client->event_cb)(client,(uint)client->in_buf->opcode,argcountin,client->InArgList);
  }
  return 0;
}

static int RouterProcessDisRequest(RouterClient *client)
{
  RouterQRemoveRequests(client,&client->out_queue);
  RouterCheckOutputMonitor(client);
  client->use = client->use & 0xffffffc0U | 0x10;
  RouterDoOutput(client,0,0x12,0,NULL,NULL,NULL,
                 NULL,NULL,0xff,NULL);
  return 0;
}

static int RouterProcessDisResponse(RouterClient *client)
{
  char *func_name;
  
  if ((client->use & 0x3fU) == 8) {
    RouterConnectionLost(client);
  }
  else {
    LogError(-0x13d,"RouterProcessDisResponse",0,"");
    RouterConnectionError(client);
  }
  return -1;
}

static int RouterProcessConfigInit(RouterClient *client, int argcountin)
{
  ulong uVar1;
  int iVar2;
  RouterConfig *__s;
  uchar *tptr;
  RouterConfig *cfg;
  RouterArgument arglist;
  char *func_name;
  
  if (argcountin == 1) {
    uVar1 = client->InArgList->val;
    arglist.fre = 1;
    arglist.clas = 1;
    arglist.size = client->InArgList->size;
    arglist.val = uVar1;
    RouterDoOutput(client,0,0x18,1,&arglist,NULL,NULL,NULL,
                   NULL,0,NULL);
    RouterFlushOutput(client,0);
    __s = malloc(sizeof(RouterConfig));
    if (__s == NULL) {
      RouterMemError();
    }
    memset(__s,0,sizeof(RouterConfig));
    __s->rev = (uint)*(byte *)(uVar1 + 1) << 0x10 | (uint)*(byte *)(uVar1 + 2) << 8 |
               (uint)*(byte *)(uVar1 + 3);
    __s->flags = (uint)*(byte *)(uVar1 + 5) << 0x10 | (uint)*(byte *)(uVar1 + 6) << 8 |
                 (uint)*(byte *)(uVar1 + 7);
    if ((client->out_cfg != NULL) && (client->out_cfg != client->in_cfg)) {
      free(client->out_cfg);
    }
    client->out_cfg = __s;
    iVar2 = 0;
  }
  else {
    LogError(-0x13e,"RouterProcessConfigInit",0,"");
    iVar2 = -1;
  }
  return iVar2;
}

static int RouterProcessConfigRequest(RouterClient *client, int argcountin)
{
  ulong uVar1;
  int iVar2;
  RouterConfig *__s;
  uchar *tptr;
  RouterConfig *cfg;
  RouterArgument arglist;
  char *func_name;
  
  if (argcountin == 1) {
    uVar1 = client->InArgList->val;
    arglist.fre = 1;
    arglist.clas = 1;
    arglist.size = client->InArgList->size;
    arglist.val = uVar1;
    RouterDoOutput(client,0,0x21,1,&arglist,NULL,NULL,NULL,
                   NULL,0,NULL);
    RouterFlushOutput(client,0);
    __s = malloc(sizeof(RouterConfig));
    if (__s == NULL) {
      RouterMemError();
    }
    memset(__s,0,sizeof(RouterConfig));
    __s->rev = (uint)*(byte *)(uVar1 + 1) << 0x10 | (uint)*(byte *)(uVar1 + 2) << 8 |
               (uint)*(byte *)(uVar1 + 3);
    __s->flags = (uint)*(byte *)(uVar1 + 5) << 0x10 | (uint)*(byte *)(uVar1 + 6) << 8 |
                 (uint)*(byte *)(uVar1 + 7);
    if (client->in_cfg != NULL) {
      free(client->in_cfg);
    }
    if ((client->out_cfg != NULL) && (client->out_cfg != client->in_cfg)) {
      free(client->out_cfg);
    }
    client->out_cfg = __s;
    client->in_cfg = __s;
    iVar2 = 0;
  }
  else {
    LogError(-0x13e,"RouterProcessConfigRequest",0,"");
    iVar2 = -1;
  }
  return iVar2;
}

static int RouterProcessConfigResponse(RouterClient *client, int argcountin)
{
  ulong uVar1;
  RouterConfig *__s;
  int iVar2;
  uchar *tptr;
  RouterConfig *cfg;
  char *func_name;
  
  if (argcountin == 1) {
    uVar1 = client->InArgList->val;
    __s = malloc(sizeof(RouterConfig));
    if (__s == NULL) {
      RouterMemError();
    }
    memset(__s,0,sizeof(RouterConfig));
    __s->rev = (uint)*(byte *)(uVar1 + 1) << 0x10 | (uint)*(byte *)(uVar1 + 2) << 8 |
               (uint)*(byte *)(uVar1 + 3);
    __s->flags = (uint)*(byte *)(uVar1 + 5) << 0x10 | (uint)*(byte *)(uVar1 + 6) << 8 |
                 (uint)*(byte *)(uVar1 + 7);
    if ((client->in_cfg != NULL) && (client->in_cfg != client->out_cfg)) {
      free(client->in_cfg);
    }
    if ((client->out_cfg == NULL) ||
       (iVar2 = memcmp(__s,client->out_cfg,sizeof(RouterConfig)), iVar2 != 0)) {
      client->in_cfg = __s;
    }
    else {
      client->in_cfg = client->out_cfg;
      free(__s);
    }
    return 0;
  }
  LogError(-0x13e,"RouterProcessConfigResponse",0,"");
  return -1;
}

void RouterDoOutput(RouterClient *client, int opcode, int class, int argcount, RouterArgument *arglist, void (*response_cb)(), unsigned char *response_data, void (*error_cb)(), unsigned char *error_data, int priority, void *purge_data)
{
  byte bVar1;
  RouterHeader *pRVar2;
  RouterQEntry *entry;
  uchar priority_;
  
  priority_ = (uchar)priority;
  RouterPack(client,opcode,class,argcount,arglist,response_cb,response_data,error_cb,error_data,
             priority & 0xff,purge_data,&entry);
  if ((entry->header).clas == 0x40) {
    pRVar2 = entry->packet;
    bVar1 = (byte)client->in_sequence;
    (entry->header).id = bVar1;
    pRVar2->id = bVar1;
  }
  RouterStartOutput(client,entry);
  return;
}

void RouterPurge(RouterClient *client, int (*purge_cb)(), void *purge_data)
{
  int *piVar1;
  struct _RouterQEntry *p_Var2;
  uint uVar3;
  RouterQ *queue;
  int plen;
  int delete;
  RouterQEntry *dead_entry;
  RouterQEntry *last_entry;
  RouterQEntry *entry;
  
  queue = &client->out_queue;
  last_entry = NULL;
  entry = queue->head;
  while (entry != NULL) {
    if (purge_cb == NULL) {
      delete = (int)(entry->purge_data == purge_data);
    }
    else {
      delete = (*purge_cb)(entry->purge_data,purge_data);
    }
    if (delete == 0) {
      last_entry = entry;
      entry = entry->next;
    }
    else {
      if (entry == queue->head) {
        if (entry->next == NULL) {
          (client->out_queue).tail = NULL;
          queue->head = NULL;
        }
        else {
          queue->head = entry->next;
        }
      }
      else if (entry == (client->out_queue).tail) {
        (client->out_queue).tail = last_entry;
        ((client->out_queue).tail)->next = NULL;
      }
      else {
        last_entry->next = entry->next;
      }
      p_Var2 = entry->next;
      piVar1 = &(client->out_queue).total;
      *piVar1 = *piVar1 + -1;
      (client->out_queue).bytes = (client->out_queue).bytes - (entry->header).length;
      RouterFreeEntry(client,entry,1);
      entry = p_Var2;
    }
  }
  return;
}

static void RouterStartOutput(RouterClient *client, RouterQEntry *entry)
{
  if (client->out_bytesleft < 1) {
    RouterLoadOutput(client,entry);
    RouterAddOutput(client);
    client->out_stopped = '\0';
  }
  else {
    RouterQStore(&client->out_queue,entry,1);
    RouterCheckOutputMonitor(client);
  }
  return;
}

static void RouterLoadOutput(RouterClient *client, RouterQEntry *entry)
{
  byte bVar1;
  RouterHeader *pRVar2;
  undefined3 uVar3;
  undefined3 uVar4;
  undefined3 uVar5;
  uint uVar6;
  uchar *bptr;
  
  client->out_pkts = client->out_pkts + 1;
  client->out_buf = entry;
  client->out_bufptr = (char *)entry->packet;
  client->out_bytesleft = (entry->header).length + 8;
  if (((entry->header).clas == 0x10) || ((entry->header).clas == 0x20)) {
    client->out_sequence = client->out_sequence + 1;
    uVar6 = client->out_sequence & 0xff;
    client->out_sequence = uVar6;
    if (uVar6 == 0) {
      client->out_sequence = client->out_sequence + 1;
    }
    pRVar2 = entry->packet;
    bVar1 = (byte)client->out_sequence;
    (entry->header).id = bVar1;
    pRVar2->id = bVar1;
  }
  memcpy(&entry->header,entry->packet,8);
  bptr = (uchar *)entry->packet;
  *bptr = (uchar)((entry->header).opcode >> 8);
  bptr[1] = (uchar)(entry->header).opcode;
  bptr[2] = (entry->header).clas;
  bptr[3] = (entry->header).id;
  bptr[4] = (entry->header).config;
  uVar3 = (entry->header).length;
  bptr[5] = (uchar)(uVar3 >> 0x10);
  uVar4 = (entry->header).length;
  bptr[6] = (uchar)(uVar4 >> 8);
  uVar5 = (entry->header).length;
  bptr[7] = (uchar)uVar5;
  return;
}

static RouterFunc RouterOutput(RouterClient *client)
{
  byte bVar1;
  int rvalue;
  int *piVar2;
  int iVar3;
  RouterClient *client_00;
  char *format;
  
  if (client->out_bytesleft < 1) {
    RouterReloadOutput(client);
    return;
  }
  rvalue = write(client->socket,client->out_bufptr,client->out_bytesleft);
  if (rvalue < 0) {
    piVar2 = __errno_location();
    iVar3 = *piVar2;
    if (iVar3 != 0x6b) {
      if (iVar3 < 0x6c) {
        if (iVar3 != 0x65) {
          if (iVar3 < 0x66) {
            if (iVar3 == 0xb) {
              return;
            }
            if (iVar3 != 0x20) {
LAB_080774f3:
              format = "";
              client_00 = client;
              piVar2 = __errno_location();
              RouterLogError(-0x131,"write",*piVar2,client_00,format);
              RouterConnectionError(client);
              return;
            }
          }
          else if (iVar3 != 0x68) goto LAB_080774f3;
        }
      }
      else if ((0x6f < iVar3) || (iVar3 < 0x6e)) goto LAB_080774f3;
    }
    RouterConnectionLost(client);
    return;
  }
  iVar3 = client->out_bytesleft - rvalue;
  client->out_bytesleft = iVar3;
  if (0 < iVar3) {
    client->out_bufptr = client->out_bufptr + rvalue;
    return;
  }
  bVar1 = (client->out_buf->header).clas;
  if (bVar1 == 0x10) {
    RouterFreePacket(client->out_buf);
  }
  else if (bVar1 != 0x20) {
    RouterFreeEntry(client,client->out_buf,0);
    goto LAB_080775c0;
  }
  RouterQStore(&client->in_queue,client->out_buf,0);
LAB_080775c0:
  RouterReloadOutput(client);
  return;
}

static void RouterReloadOutput(RouterClient *client)
{
  RouterQEntry *entry;
  
  entry = RouterQRetrieve(&client->out_queue);
  if (entry == NULL) {
    client->out_buf = NULL;
    client->out_bufptr = NULL;
    client->out_bytesleft = 0;
    RouterRemoveOutput(client);
    if ((((client->use & 0x600U) == 0x400) && ((client->use & 0xc0U) == 0x40)) &&
       ((client->use & 4U) != 0)) {
      RouterDisconnect(client,client->timeout);
    }
  }
  else {
    RouterLoadOutput(client,entry);
    if (0xf9 < (client->in_queue).total) {
      RouterRemoveOutput(client);
      client->out_stopped = '\x01';
    }
  }
  RouterCheckOutputMonitor(client);
  return;
}

int RouterSetOutputMonitor(void (*output_monitor_cb)(), void *cb_data, int high_water_entries, int high_water_bytes, int low_water_entries, int low_water_bytes)
{
  MonitorCB = output_monitor_cb;
  MonitorCBData = cb_data;
  MonitorHighWaterEntries = high_water_entries;
  MonitorHighWaterBytes = high_water_bytes;
  MonitorLowWaterEntries = low_water_entries;
  MonitorLowWaterBytes = low_water_bytes;
  RouterListClients(RouterCheckOutputMonitor);
  return 0;
}

static void RouterCheckOutputMonitor(RouterClient *client)
{
  if (MonitorCB != NULL) {
    if (client->out_highwater == '\0') {
      if (((MonitorHighWaterEntries != 0) && (MonitorHighWaterEntries < (client->out_queue).total))
         || ((MonitorHighWaterBytes != 0 && (MonitorHighWaterBytes < (client->out_queue).bytes)))) {
        client->out_highwater = '\x01';
        (*MonitorCB)(MonitorCBData,client,1);
      }
    }
    else if (((MonitorLowWaterEntries == 0) || ((client->out_queue).total < MonitorLowWaterEntries))
            && ((MonitorLowWaterBytes == 0 || ((client->out_queue).bytes < MonitorLowWaterBytes))))
    {
      client->out_highwater = '\0';
      (*MonitorCB)(MonitorCBData,client,0);
    }
  }
  return;
}

void RouterPack(RouterClient *client, int opcode, int class, int argcount, RouterArgument *arglist, void (*response_cb)(), unsigned char *response_data, void (*error_cb)(), unsigned char *error_data, int priority, void *purge_data, RouterQEntry **entry)
{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  RouterQEntry *pRVar6;
  RouterHeader *pRVar7;
  int iVar8;
  ulong class_size;
  int i;
  uchar *cbuf_ptr;
  uchar *data_start;
  uchar *buf_ptr;
  int compress;
  int csize;
  int size;
  uchar priority_;
  
  priority_ = (uchar)priority;
  size = 0;
  csize = 0;
  compress = 0;
  if ((client->out_cfg != NULL) && ((client->out_cfg->flags & 0x80000000) != 0)) {
    compress = 1;
  }
  pRVar6 = malloc(sizeof(RouterQEntry));
  *entry = pRVar6;
  if (pRVar6 == NULL) {
    RouterMemError();
  }
  (*entry)->response_cb = response_cb;
  (*entry)->response_data = response_data;
  (*entry)->error_cb = error_cb;
  (*entry)->error_data = error_data;
  (*entry)->priority = priority_;
  (*entry)->purge_data = purge_data;
  (*entry)->next = NULL;
  for (i = 0; i < argcount; i = i + 1) {
    if (arglist[i].clas == 0) {
      size = size + 8;
    }
    else {
      size = size + 4 + ((arglist[i].size) + 3U & 0xfffffffc);
    }
  }
  pRVar7 = malloc(size + 8);
  (*entry)->packet = pRVar7;
  if (pRVar7 == NULL) {
    free(entry);
    RouterMemError();
  }
  pRVar7 = (*entry)->packet;
  pRVar7->length = 0;
  pRVar7->length = pRVar7->length | size;
  (*entry)->packet->opcode = (ushort)opcode;
  (*entry)->packet->clas = (byte)class;
  (*entry)->packet->id = 0;
  (*entry)->packet->config = 0;
  data_start = (uchar *)((*entry)->packet + 1);
  buf_ptr = data_start;
  for (i = 0; i < argcount; i = i + 1) {
    lbitbuf.value = htonl(arglist[i].clas << 0x18 | arglist[i].size);
    memcpy(buf_ptr,&lbitbuf,4);
    buf_ptr = buf_ptr + 4;
    if (arglist[i].clas == 0) {
      lbitbuf.value = arglist[i].val;
      memcpy(buf_ptr,&lbitbuf,4);
      buf_ptr = buf_ptr + 4;
    }
    else {
      memcpy(buf_ptr,(void *)arglist[i].val,arglist[i].size);
      buf_ptr = buf_ptr + ((arglist[i].size) + 3U & 0xfffffffc);
    }
  }
  if ((compress == 0) || (size < 1)) {
    OutputStats.notry_count = OutputStats.notry_count + 1;
    OutputStats.notry_bytes = OutputStats.notry_bytes + size;
    (client->out_stats).notry_count = (client->out_stats).notry_count + 1;
    (client->out_stats).notry_bytes = size + (client->out_stats).notry_bytes;
  }
  else {
    iVar8 = BuffCompress(data_start,size,&cbuf_ptr,(uint *)&csize);
    if (iVar8 == -1) {
      RouterMemError();
    }
    if (csize < size) {
      memcpy(data_start,cbuf_ptr,csize);
      pRVar7 = (*entry)->packet;
      pRVar7->length = 0;
      pRVar7->length = pRVar7->length | csize;
      (*entry)->packet->config = (*entry)->packet->config | 0x80;
      OutputStats.compress_count = OutputStats.compress_count + 1;
      OutputStats.compress_bytes = OutputStats.compress_bytes + csize;
      OutputStats.uncompressed_bytes = OutputStats.uncompressed_bytes + size;
      puVar1 = &(client->out_stats).compress_count;
      *puVar1 = *puVar1 + 1;
      (client->out_stats).compress_bytes = csize + (client->out_stats).compress_bytes;
      (client->out_stats).uncompressed_bytes = size + (client->out_stats).uncompressed_bytes;
    }
    else {
      OutputStats.nocompress_count = OutputStats.nocompress_count + 1;
      OutputStats.nocompress_bytes = OutputStats.nocompress_bytes + size;
      OutputStats.nocompress_compressed_bytes = OutputStats.nocompress_compressed_bytes + csize;
      puVar1 = &(client->out_stats).nocompress_count;
      *puVar1 = *puVar1 + 1;
      (client->out_stats).nocompress_bytes = size + (client->out_stats).nocompress_bytes;
      (client->out_stats).nocompress_compressed_bytes =
           csize + (client->out_stats).nocompress_compressed_bytes;
    }
    BuffFree(cbuf_ptr);
  }
  memcpy(&(*entry)->header,(*entry)->packet,8);
  return;
}

int RouterUnpack(RouterClient *client, RouterHeader *packet)
{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  RouterArgument *pRVar12;
  int iVar13;
  RouterArgument *pRVar14;
  ulong class_size;
  uint32_t uVar15;
  void *pvVar16;
  int j;
  int i;
  int usize;
  int size;
  uchar *buf_end;
  uchar *ubuf_ptr;
  uchar *buf_ptr;
  bool compress;
  
  compress = false;
  i = 0;
  if ((client->in_cfg != NULL) && ((client->in_cfg->flags & 0x80000000) != 0)) {
    compress = true;
  }
  size = packet->length - 8;
  buf_ptr = (uchar *)(packet + 1);
  buf_end = (uchar *)(buf_ptr + packet->length);
  if ((compress) && ((packet->config & 0x80) != 0)) {
    iVar13 = BuffUncompress(buf_ptr,packet->length,&ubuf_ptr,(uint *)&usize);
    if (iVar13 == -1) {
      RouterMemError();
    }
    buf_ptr = ubuf_ptr;
    buf_end = ubuf_ptr + usize;
    InputStats.compress_count = InputStats.compress_count + 1;
    InputStats.compress_bytes = InputStats.compress_bytes + packet->length;
    InputStats.uncompressed_bytes = InputStats.uncompressed_bytes + usize;
    puVar1 = &(client->in_stats).compress_count;
    *puVar1 = *puVar1 + 1;
    (client->in_stats).compress_bytes = (client->in_stats).compress_bytes + packet->length;
    (client->in_stats).uncompressed_bytes = usize + (client->in_stats).uncompressed_bytes;
  }
  else {
    buf_ptr = (uchar *)(packet + 1);
    buf_end = (uchar *)(buf_ptr + packet->length);
    if (compress) {
      InputStats.nocompress_count = InputStats.nocompress_count + 1;
      InputStats.nocompress_bytes = InputStats.nocompress_bytes + packet->length;
      puVar1 = &(client->in_stats).nocompress_count;
      *puVar1 = *puVar1 + 1;
      (client->in_stats).nocompress_bytes = (client->in_stats).nocompress_bytes + packet->length;
    }
    else {
      InputStats.notry_count = InputStats.notry_count + 1;
      InputStats.notry_bytes = InputStats.notry_bytes + packet->length;
      (client->in_stats).notry_count = (client->in_stats).notry_count + 1;
      (client->in_stats).notry_bytes = (client->in_stats).notry_bytes + packet->length;
    }
  }
  while (buf_ptr + 4 < buf_end) {
    if (client->InArgListSize <= i) {
      pRVar14 = realloc(client->InArgList, (MaxInArgs + client->InArgListSize) * sizeof(RouterArgument));
      client->InArgList = pRVar14;
      if (pRVar14 == NULL) {
        RouterMemError();
      }
      client->InArgListSize = MaxInArgs + client->InArgListSize;
      for (j = i; j < client->InArgListSize; j = j + 1) {
        client->InArgList[j].clas = 0;
        client->InArgList[j].val = 0;
        client->InArgList[j].fre = 0;
        *(uint *)(client->InArgList + j) = *(uint *)(client->InArgList + j) & 0xff;
      }
    }
    memcpy(&ubitbuf,buf_ptr,sizeof(struct bitbuf));
    buf_ptr = buf_ptr + 4;
    class_size = ntohl(ubitbuf.value);
    pRVar12 = client->InArgList;
    pRVar14 = pRVar12 + i;
    pRVar14->clas = 0;
    pRVar12 = pRVar12 + i;
    *(byte *)pRVar12 = *(byte *)pRVar12 | (char)(class_size >> 0x18) * '\x02';
    pRVar12 = client->InArgList;
    pRVar14 = pRVar12 + i;
    *(uint *)pRVar14 = *(uint *)pRVar14 & 0xff;
    pRVar12 = pRVar12 + i;
    *(uint *)pRVar12 = *(uint *)pRVar12 | class_size << 8;
    if (client->InArgList[i].clas == 0) {
      *(uint *)(client->InArgList + i) = *(uint *)(client->InArgList + i) & 0xff;
      memcpy(&ubitbuf,buf_ptr,sizeof(struct bitbuf));
      buf_ptr = buf_ptr + 4;
      uVar15 = ntohl(ubitbuf.value);
      client->InArgList[i].val = uVar15;
    }
    else {
      if (buf_end < buf_ptr + (*(int *)(client->InArgList + i) >> 8)) break;
      pvVar16 = malloc(*(int *)(client->InArgList + i) >> 8);
      client->InArgList[i].val = (ulong)pvVar16;
      if (pvVar16 == NULL) {
        RouterFreeArguments(i,client->InArgList);
        RouterMemError();
      }
      memcpy((void *)client->InArgList[i].val,buf_ptr,*(int *)(client->InArgList + i) >> 8);
      buf_ptr = buf_ptr + ((*(int *)(client->InArgList + i) >> 8) + 3U & 0xfffffffc);
      client->InArgList[i].fre = 1;
    }
    i = i + 1;
  }
  if ((compress) && ((packet->config & 0x80) != 0)) {
    BuffFree(ubuf_ptr);
  }
  return i;
}

char *RouterDumpQStats(char *buf, RouterClient *client)
{
  char *__s;
  size_t sVar1;
  char *rptr;
  RouterClient *lclient;
  
  if (client == NULL) {
    client = ClientList.head;
    lclient = NULL;
  }
  else {
    lclient = client->next;
  }
  if (buf == NULL) {
    buf = malloc(ClientList.total * 0x8c);
  }
  rptr = buf;
  if (client == NULL) {
    sprintf(buf,"RouterDumpQStats:  no clients!\n");
  }
  else {
    do {
      sprintf(rptr,"0x%08x    IN:    cur %d/%d    max %d/%d    total %d\n",client,
              (client->in_queue).total,(client->in_queue).bytes,(client->in_queue).total_max,
              (client->in_queue).bytes_max,client->in_pkts);
      sVar1 = strlen(rptr);
      __s = rptr + sVar1;
      sprintf(__s,"              OUT:   cur %d/%d    max %d/%d   total %d\n",
              (client->out_queue).total,(client->out_queue).bytes,(client->out_queue).total_max,
              (client->out_queue).bytes_max,client->out_pkts);
      sVar1 = strlen(__s);
      rptr = __s + sVar1;
      client = client->next;
    } while (client != lclient);
  }
  return buf;
}

void RouterResetQStats(RouterClient *client)
{
  RouterClient *lclient;
  
  if (client == NULL) {
    client = ClientList.head;
    lclient = NULL;
  }
  else {
    lclient = client->next;
  }
  if (client != NULL) {
    do {
      (client->in_queue).total_max = 0;
      (client->in_queue).bytes_max = 0;
      client->in_pkts = 0;
      (client->out_queue).total_max = 0;
      (client->out_queue).bytes_max = 0;
      client->out_pkts = 0;
      client = client->next;
    } while (client != lclient);
  }
  return;
}

void RouterDebugStats(int reset)
{
  RouterPrintProcessStats(stdout,reset);
  return;
}

void RouterPrintProcessStats(FILE *fd, int reset)
{
  if (fd != NULL) {
    fprintf(fd,"\nINPUT SIDE STATISTICS:\n");
    RouterPrintStats(fd,&InputStats);
    fprintf(fd,"\nOUTPUT SIDE STATISTICS:\n");
    RouterPrintStats(fd,&OutputStats);
  }
  if (reset != 0) {
    memset(&InputStats,0,sizeof(RouterCompressStats));
    memset(&OutputStats,0,sizeof(RouterCompressStats));
  }
  return;
}

void RouterPrintAllStats(FILE *fd, int reset)
{
  RouterClient *cptr;
  
  for (cptr = ClientList.head; cptr != NULL; cptr = cptr->next) {
    if (fd != NULL) {
      fprintf(fd,"*** Router Statistics for client %#x\n",cptr);
    }
    RouterPrintClientStats(cptr,fd,reset);
  }
  return;
}

void RouterPrintClientStats(RouterClient *client, FILE *fd, int reset)
{
  RouterCompressStats *s;
  
  if (fd != NULL) {
    fprintf(fd,"\nINPUT SIDE STATISTICS:\n");
    RouterPrintStats(fd,&client->in_stats);
    fprintf(fd,"\nOUTPUT SIDE STATISTICS:\n");
    RouterPrintStats(fd,&client->out_stats);
  }
  if (reset != 0) {
    memset(&client->in_stats,0,sizeof(client->in_stats));
    memset(&client->out_stats,0,sizeof(client->out_stats));
  }
  return;
}

static void RouterPrintStats(FILE *fd, RouterCompressStats *s)
{
  uint uVar1;
  int ratio;
  
  fprintf(fd,"                        transfers         bytes   \n");
  fprintf(fd,"                       -----------     -----------\n");
  fprintf(fd,"No compress attempted: %11d    %11d\n",s->notry_count,s->notry_bytes);
  fprintf(fd,"Too small to compress: %11d    %11d\n",s->toosmall_count,s->toosmall_bytes);
  fprintf(fd,"Larger after compress: %11d    %11d  (%d after compress)\n",s->nocompress_count,
          s->nocompress_bytes,s->nocompress_compressed_bytes);
  fprintf(fd,"Compressed:            %11d    %11d  (%d before compress)\n",s->compress_count,
          s->compress_bytes,s->uncompressed_bytes);
  if (s->compress_bytes != 0) {
    uVar1 = (s->uncompressed_bytes * 100) / s->compress_bytes;
    fprintf(fd,"*** Compression ratio is %d.%.2d:1\n",(int)uVar1 / 100,(int)uVar1 % 100);
  }
  return;
}

static void RouterQStore(RouterQ *queue, RouterQEntry *entry, int use_priority)
{
  uint uVar1;
  int cnt;
  RouterQEntry *e;
  RouterQEntry *pe;
  
  if (((queue->tail == NULL) || (use_priority == 0)) ||
     (entry->priority <= queue->tail->priority)) {
    pe = queue->tail;
    e = NULL;
  }
  else if ((queue->head == NULL) || (entry->priority <= queue->head->priority)) {
    e = queue->head;
    pe = NULL;
    for (; (e != NULL && (entry->priority <= e->priority)); e = e->next) {
      pe = e;
    }
  }
  else {
    pe = NULL;
    e = queue->head;
  }
  if ((pe == NULL) && (e == NULL)) {
    queue->head = entry;
    queue->tail = entry;
  }
  else if ((pe == NULL) || (e != NULL)) {
    if ((pe == NULL) && (e != NULL)) {
      entry->next = queue->head;
      queue->head = entry;
    }
    else {
      pe->next = entry;
      entry->next = e;
    }
  }
  else {
    queue->tail->next = entry;
    queue->tail = entry;
  }
  queue->total = queue->total + 1;
  if (queue->total_max < queue->total) {
    queue->total_max = queue->total;
  }
  queue->bytes = queue->bytes + (entry->header).length;
  if (queue->bytes_max < queue->bytes) {
    queue->bytes_max = queue->bytes;
  }
  return;
}

static RouterQEntry *RouterQRetrieve(RouterQ *queue)
{
  uint uVar1;
  RouterQEntry *pRVar2;
  RouterQEntry *entry;
  
  pRVar2 = queue->head;
  if (pRVar2 == NULL) {
    pRVar2 = NULL;
  }
  else {
    if (queue->head == queue->tail) {
      queue->tail = NULL;
      queue->head = NULL;
    }
    else {
      queue->head = pRVar2->next;
    }
    queue->total = queue->total + -1;
    queue->bytes = queue->bytes - (pRVar2->header).length;
  }
  return pRVar2;
}

static void RouterQRemoveRequests(RouterClient *client, RouterQ *queue)
{
  struct _RouterQEntry *p_Var1;
  uint uVar2;
  int plen;
  RouterQEntry *req_entry;
  RouterQEntry *last_entry;
  RouterQEntry *entry;
  
  last_entry = NULL;
  entry = queue->head;
  while (entry != NULL) {
    if (((entry->header).clas == 0x10) || ((entry->header).clas == 0x20)) {
      if (entry == queue->head) {
        if (entry->next == NULL) {
          queue->tail = NULL;
          queue->head = NULL;
        }
        else {
          queue->head = entry->next;
        }
      }
      else if (entry == queue->tail) {
        queue->tail = last_entry;
        queue->tail->next = NULL;
      }
      else {
        last_entry->next = entry->next;
      }
      p_Var1 = entry->next;
      queue->total = queue->total + -1;
      queue->bytes = queue->bytes - (entry->header).length;
      RouterFreeEntry(client,entry,1);
      entry = p_Var1;
    }
    else {
      last_entry = entry;
      entry = entry->next;
    }
  }
  return;
}

void RouterFreeArguments(int argcount, RouterArgument *arglist)
{
  int i;
  
  for (i = 0; i < argcount; i = i + 1) {
    if (((arglist[i].clas == 1) && (arglist[i].fre != 0)) && (arglist[i].val != 0)) {
      free((void *)arglist[i].val);
    }
  }
  return;
}

void RouterFreeClient(RouterClient *client, int return_rel_request)
{
  RouterFreeGroups(client);
  if (client->in_buf != NULL) {
    free(client->in_buf);
  }
  if (client->in_cfg != NULL) {
    free(client->in_cfg);
  }
  if ((client->out_cfg != NULL) && (client->out_cfg != client->in_cfg)) {
    free(client->out_cfg);
  }
  RouterFreeQueue(client,&client->in_queue,return_rel_request);
  RouterFreeEntry(client,client->out_buf,return_rel_request);
  RouterFreeQueue(client,&client->out_queue,return_rel_request);
  if (client->InArgList != NULL) {
    free(client->InArgList);
  }
  if ((client->error_cb == NULL) && (ClientFreeCB != NULL)) {
    (*ClientFreeCB)(client);
  }
  free(client);
  return;
}

void RouterFreeGroups(RouterClient *client)
{
  if ((client->groups).bits != NULL) {
    free((client->groups).bits);
  }
  (client->groups).count = 0;
  (client->groups).bits = NULL;
  return;
}

static void RouterFreeQueue(RouterClient *client, RouterQ *queue, int return_rel_request)
{
  struct _RouterQEntry *p_Var1;
  RouterQEntry *next;
  RouterQEntry *qptr;
  
  qptr = queue->head;
  while (qptr != NULL) {
    p_Var1 = qptr->next;
    RouterFreeEntry(client,qptr,return_rel_request);
    qptr = p_Var1;
  }
  return;
}

static void RouterFreeEntry(RouterClient *client, RouterQEntry *entry, int return_rel_request)
{
  int argcountin;
  
  if (entry != NULL) {
    if (entry->packet != NULL) {
      if (((return_rel_request != 0) && ((entry->header).clas == 0x20)) &&
         (entry->error_cb != NULL)) {
        argcountin = RouterUnpack(client,entry->packet);
        (*entry->error_cb)(client,entry->error_data,argcountin,client->InArgList);
        RouterFreeArguments(argcountin,client->InArgList);
      }
      free(entry->packet);
    }
    free(entry);
  }
  return;
}

static void RouterFreePacket(RouterQEntry *entry)
{
  if ((entry != NULL) && (entry->packet != NULL)) {
    free(entry->packet);
    entry->packet = NULL;
  }
  return;
}

static void RouterAddInput(RouterClient *client)
{
  EventID EVar1;
  
  EVar1 = EventAddInput(client->socket,RouterInput,(EventData)client,"RouterAddInput");
  client->input_id = EVar1;
  return;
}

static void RouterRemoveInput(RouterClient *client)
{
  EventRemoveInput(client->input_id);
  return;
}

static void RouterAddOutput(RouterClient *client)
{
  EventID EVar1;
  
  EVar1 = EventAddOutput(client->socket,RouterOutput,(EventData)client,"RouterAddOutput");
  client->output_id = EVar1;
  return;
}

static void RouterRemoveOutput(RouterClient *client)
{
  EventRemoveOutput(client->output_id);
  return;
}

void RouterAddTimer(RouterClient *client, RouterFunc (*timer_func)(), int timeout)
{
  EventID EVar1;
  
  if (client->timer_id != 0) {
    EventRemoveTimeOut(client->timer_id);
  }
  EVar1 = EventAddTimeOut(timeout,0,timer_func,(EventData)client,"RouterAddTimer");
  client->timer_id = EVar1;
  return;
}

void RouterRemoveTimer(RouterClient *client)
{
  EventRemoveTimeOut(client->timer_id);
  client->timer_id = 0;
  return;
}

void RouterLogError(int msgnbr, char *func_name, int errnbr, RouterClient *client, char *format)
{
  va_list args;
  
  LoggerLogMessage(msgnbr,func_name,errnbr,(client->id).hostname,client->port,(client->id).procname,
                   format);
  return;
}

int RouterCheckOutput(RouterClient *client, char *func_name)
{
  int iVar1;
  
  if ((client->use & 4U) == 0) {
    LogError(-0x136,func_name,0,"");
    iVar1 = -1;
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}

void RouterConnectionLost(RouterClient *client)
{
  uint uVar1;
  int msgnbr;
  
  uVar1 = client->use & 0x3f;
  if (uVar1 == 8) {
    msgnbr = -0x132;
  }
  else {
    if (uVar1 < 9) {
      if (uVar1 == 1) {
        if ((client->use & 0xc0U) == 0x80) {
          client->error_cb = NULL;
        }
        msgnbr = -300;
        goto LAB_08078ec0;
      }
    }
    else if (uVar1 == 0x10) {
      msgnbr = -0x133;
      goto LAB_08078ec0;
    }
    msgnbr = -0x12f;
  }
LAB_08078ec0:
  RouterClientError(client,msgnbr);
  return;
}

void RouterConnectionTimeout(RouterClient *client)
{
  uint uVar1;
  int msgnbr;
  
  uVar1 = client->use & 0x3f;
  if (uVar1 == 8) {
    msgnbr = -0x132;
  }
  else {
    if (uVar1 < 9) {
      if (uVar1 == 1) {
        if ((client->use & 0xc0U) == 0x80) {
          RouterClose(client);
          return;
        }
        msgnbr = -0x12d;
        goto LAB_08078f60;
      }
    }
    else if (uVar1 == 0x10) {
      msgnbr = -0x133;
      goto LAB_08078f60;
    }
    msgnbr = -0x130;
  }
LAB_08078f60:
  RouterClientError(client,msgnbr);
  return;
}

void RouterConnectionError(RouterClient *client)
{
  uint uVar1;
  int msgnbr;
  
  uVar1 = client->use & 0x3f;
  if (uVar1 == 8) {
LAB_08078fb0:
    msgnbr = -0x134;
  }
  else {
    if (uVar1 < 9) {
      if (uVar1 == 1) {
        msgnbr = -0x12e;
        goto LAB_08078fd0;
      }
    }
    else if (uVar1 == 0x10) goto LAB_08078fb0;
    msgnbr = -0x131;
  }
LAB_08078fd0:
  RouterClientError(client,msgnbr);
  return;
}

void RouterClientError(RouterClient *client, int msgnbr)
{
  client->use = client->use & 0xffffffc0;
  if (client->error_cb != NULL) {
    (*client->error_cb)(client,msgnbr,&client->id,client->port,client->retrys);
  }
  RouterClose(client);
  return;
}

void RouterBadClass(RouterClient *client, char *func_name)
{
  byte bVar1;
  
  bVar1 = client->in_buf->clas;
  if (bVar1 < 0x13) {
    if ((bVar1 < 0x10) && (bVar1 != 4)) {
      if (bVar1 < 5) {
        if ((2 < bVar1) || (bVar1 == 0)) {
LAB_080790c0:
          RouterLogError(-0x139,func_name,0,client,"");
          goto LAB_080790e0;
        }
      }
      else if (bVar1 != 8) goto LAB_080790c0;
    }
  }
  else if (bVar1 != 0x40) {
    if (bVar1 < 0x41) {
      if (bVar1 != 0x20) goto LAB_080790c0;
    }
    else if (bVar1 != 0x80) goto LAB_080790c0;
  }
  RouterLogError(-0x138,func_name,0,client,"");
LAB_080790e0:
  RouterConnectionError(client);
  return;
}

void RouterMemError(void)
{
  MemUsage();
  RouterShutDownClients();
  LogError(-0x137,"",0,"");
  if (FatalCB != NULL) {
    (*FatalCB)(0xfffffec9);
  }
                    /* WARNING: Subroutine does not return */
  abort();
}

int RouterClose(RouterClient *client)
{
  int iVar1;
  
  iVar1 = RouterDoClose(client,1);
  return iVar1;
}

int RouterDoClose(RouterClient *client, int return_rel_request)
{
  int rvalue;
  
  rvalue = 0;
  if (0 < client->socket) {
    RouterRemoveInput(client);
    if ((0 < client->out_bytesleft) && (client->out_stopped == '\0')) {
      RouterRemoveOutput(client);
    }
    rvalue = SocketClose(client->socket);
  }
  RouterRemoveClient(client,return_rel_request);
  return rvalue;
}
