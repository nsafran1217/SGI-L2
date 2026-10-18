/*
 * sys_ctrl/common/Router/Router.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Router.c
 *
 * The Router: SGI's message protocol between the controller processes (L2s,
 * and the L3 tools talking to an L2) over TCP or local sockets. RouterCl.c
 * opens connections, RouterSv.c accepts them; this file runs them.
 *
 * A packet is an 8-byte header (RouterHeader, big-endian on the wire: opcode
 * 16 bits, class 8, id 8, config 8, length 24) and the arguments. Each
 * argument is a big-endian word, class << 24 | size, then either an inline
 * 32-bit value (class 0) or size bytes of data padded to 4. Requests carry an
 * id (1..255) that their response repeats.
 *
 * Output goes through a per-connection queue ordered by priority; the packet
 * being written is out_buf. Sent requests wait in the input queue (in_queue)
 * for their responses. Errors go to the connection's error callback, which is
 * expected to drop the connection (RouterClose).
 */

#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "Router.h"
#include "RouterInt.h"
#include "RouterMsg.h"
#include "Buff.h"
#include "Socket.h"
#include "../sys/MemUsage.h"

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
uint32_t IPAddress;
RouterConfig RouterLocalConfig = { .rev = 2, .flags = RCF_COMPRESS };
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
static int bufsize_rval;

/* argument words on the wire, independent of the host's byte order */
static void put_be32(unsigned char *b, uint32_t v)
{
  b[0] = v >> 24;
  b[1] = v >> 16;
  b[2] = v >> 8;
  b[3] = v;
}

static void put_le32(unsigned char *b, uint32_t v)
{
  b[0] = v;
  b[1] = v >> 8;
  b[2] = v >> 16;
  b[3] = v >> 24;
}

static uint32_t get_be32(const unsigned char *b)
{
  return (uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 | b[3];
}

/* errno values that mean the other end is gone */
static int connection_lost(int err)
{
  return err == ENOTCONN || err == ENETUNREACH || err == ECONNRESET || err == EPIPE ||
         err == ETIMEDOUT || err == ECONNREFUSED;
}

static int is_request(RouterQEntry *entry)
{
  return entry->header.clas == RC_REQUEST || entry->header.clas == RC_REL_REQUEST;
}

/* ---- setup ---- */

int RouterInit(int max_in_args, int use_unix, char *process_name, int process_id, void (*fatal_cb)())
{
  struct passwd *pw;
  char *myhost;
  char *slash;

  MaxInArgs = max_in_args < 10 ? 10 : max_in_args;
  ProcessID = process_id;
  FatalCB = fatal_cb;
  memset(&InputStats,0,sizeof(InputStats));
  memset(&OutputStats,0,sizeof(OutputStats));
  slash = strrchr(process_name,'/');
  ProcessName = slash != NULL ? slash + 1 : process_name;
  signal(SIGPIPE,SIG_IGN);      /* write errors come back as EPIPE */
  memset(UserName,0,sizeof(UserName));
  memset(FullName,0,sizeof(FullName));
  pw = getpwuid(getuid());
  if (pw == NULL) {
    LogError(ROUTER_ERR_NO_PASSWD,"",0,"");
    return -1;
  }
  strncpy(UserName,pw->pw_name,sizeof(UserName) - 1);
  strncpy(FullName,pw->pw_gecos,sizeof(FullName) - 1);
  if (SocketGetHostName(&myhost) == -1)
    myhost = "localhost";
  SocketGetAddr(myhost,&IPAddress);
  return 0;
}

int RouterSetFreeCB(void (*free_cb)())
{
  ClientFreeCB = free_cb;
  return 0;   /* the original left free_cb in %eax; no caller uses the result */
}

/* clients connected to our servers */
int RouterClientsConnected(void)
{
  RouterClient *client;
  int clients = 0;

  for (client = ClientList.head; client != NULL; client = client->next)
    if ((client->use & RU_ACCEPTED) && (client->use & RU_SIDE) == RU_SERVER)
      clients++;
  return clients;
}

int RouterConnectionCount(void)
{
  RouterClient *client;
  int clients = 0;

  for (client = ClientList.head; client != NULL; client = client->next)
    if (client->use & RU_ACCEPTED)
      clients++;
  return clients;
}

/* is there a connection to that server? 1: our connection is still being
 * made, 4: connected, 0: none. *client is the connection (or NULL) */
static int connection_state(RouterClient *client)
{
  switch (client->use & (RU_CONNECTING | RU_CONNECTED)) {
  case RU_CONNECTING:
    return (client->use & RU_SIDE) == RU_CLIENT ? 1 : 0;
  case RU_CONNECTED:
    return 4;
  default:
    return 0;
  }
}

int RouterHostConnected(char *host, int port, int process_id, RouterClient **client)
{
  int state;

  for (*client = ClientList.head; *client != NULL; *client = (*client)->next) {
    if (strcmp((*client)->id.hostname,host) == 0 && (*client)->port == port &&
        (*client)->process_id == process_id && (state = connection_state(*client)) != 0)
      return state;
  }
  return 0;
}

int RouterAddrConnected(uint32_t addr, int port, int process_id, RouterClient **client)
{
  int state;

  for (*client = ClientList.head; *client != NULL; *client = (*client)->next) {
    if ((*client)->addr == addr && (*client)->port == port &&
        (*client)->process_id == process_id && (state = connection_state(*client)) != 0)
      return state;
  }
  return 0;
}

void RouterInitClient(RouterClient *client, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)())
{
  client->timeout = timeout;
  client->out_limit = limit;
  client->connect_cb = connect_cb;
  client->request_cb = request_cb;
  client->event_cb = event_cb;
  client->error_cb = error_cb;
}

/* ---- sending ---- */

int RouterRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, int limit)
{
  return RouterPriRequestOut(client,opcode,argcount,arglist,response_cb,response_data,limit,0,NULL);
}

/* send a request; response_cb gets the response. With limit, refuse (-2)
 * while out_limit packets are waiting to be sent. */
int RouterPriRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, int limit, int priority, void *purge_data)
{
  if (RouterCheckOutput(client,"RouterRequestOut") != 0)
    return -1;
  if (limit == 1 && client->out_queue.total >= client->out_limit)
    return -2;
  RouterDoOutput(client,opcode,RC_REQUEST,argcount,arglist,response_cb,response_data,NULL,NULL,
                 priority & 0xff,purge_data);
  return 0;
}

int RouterRelRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, void (*error_cb)(), void *error_data, int limit)
{
  return RouterPriRelRequestOut(client,opcode,argcount,arglist,response_cb,response_data,error_cb,
                                error_data,limit,0,NULL);
}

/* a "reliable" request: if it is never answered, error_cb gets its arguments back */
int RouterPriRelRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, void (*error_cb)(), void *error_data, int limit, int priority, void *purge_data)
{
  if (RouterCheckOutput(client,"RouterRelRequestOut") != 0)
    return -1;
  if (limit == 1 && client->out_queue.total >= client->out_limit)
    return -2;
  RouterDoOutput(client,opcode,RC_REL_REQUEST,argcount,arglist,response_cb,response_data,error_cb,
                 error_data,priority & 0xff,purge_data);
  return 0;
}

void RouterResponseOut(RouterClient *client, int argcount, RouterArgument *arglist)
{
  RouterPriResponseOut(client,argcount,arglist,0,NULL);
}

void RouterPriResponseOut(RouterClient *client, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  RouterDoOutput(client,0,RC_RESPONSE,argcount,arglist,NULL,NULL,NULL,NULL,priority & 0xff,
                 purge_data);
  client->ResponseSent = 1;
}

int RouterEventOut(int opcode, int argcount, RouterArgument *arglist)
{
  return RouterPriEventOut(opcode,argcount,arglist,0,NULL);
}

/* an event to every connected peer; returns how many got it */
int RouterPriEventOut(int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  RouterClient *client;
  int events_sent = 0;

  for (client = ClientList.head; client != NULL; client = client->next) {
    if (client->use & RU_CONNECTED) {
      RouterDoOutput(client,opcode,RC_EVENT,argcount,arglist,NULL,NULL,NULL,NULL,priority & 0xff,
                     purge_data);
      events_sent++;
    }
  }
  return events_sent;
}

int RouterIDEventOut(int process_id, int opcode, int argcount, RouterArgument *arglist)
{
  return RouterPriIDEventOut(process_id,opcode,argcount,arglist,0,NULL);
}

/* an event to every connected peer of one process type */
int RouterPriIDEventOut(int process_id, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  RouterClient *client;
  int events_sent = 0;

  for (client = ClientList.head; client != NULL; client = client->next) {
    if (client->process_id == process_id && (client->use & RU_CONNECTED)) {
      RouterDoOutput(client,opcode,RC_EVENT,argcount,arglist,NULL,NULL,NULL,NULL,priority & 0xff,
                     purge_data);
      events_sent++;
    }
  }
  return events_sent;
}

int RouterGroupEventOut(int process_id, int group, int opcode, int argcount, RouterArgument *arglist)
{
  return RouterPriGroupEventOut(process_id,group,opcode,argcount,arglist,0,NULL);
}

/* an event to the peers of one process type that joined group (their group
 * bit set; SGI's test lets group equal the group count) */
int RouterPriGroupEventOut(int process_id, int group, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  RouterClient *client;
  int events_sent = 0;

  for (client = ClientList.head; client != NULL; client = client->next) {
    if (client->process_id == process_id && (unsigned int)group <= client->groups.count &&
        (client->groups.bits[group / 8] & (1 << (group % 8)))) {
      RouterDoOutput(client,opcode,RC_EVENT,argcount,arglist,NULL,NULL,NULL,NULL,priority & 0xff,
                     purge_data);
      events_sent++;
    }
  }
  return events_sent;
}

void RouterClientEventOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist)
{
  RouterPriClientEventOut(client,opcode,argcount,arglist,0,NULL);
}

void RouterPriClientEventOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data)
{
  RouterDoOutput(client,opcode,RC_EVENT,argcount,arglist,NULL,NULL,NULL,NULL,priority & 0xff,
                 purge_data);
}

void RouterFlushOutputs(int timeout)
{
  RouterClient *client;

  for (client = ClientList.head; client != NULL; client = client->next)
    if (client->use & RU_CONNECTED)
      RouterFlushOutput(client,timeout);
}

/* a packet has been written out: keep requests for their responses */
static void output_done(RouterClient *client)
{
  switch (client->out_buf->header.clas) {
  case RC_REQUEST:
    RouterFreePacket(client->out_buf);  /* only the response callback is needed */
    RouterQStore(&client->in_queue,client->out_buf,0);
    break;
  case RC_REL_REQUEST:
    RouterQStore(&client->in_queue,client->out_buf,0);   /* kept for its error callback */
    break;
  default:
    RouterFreeEntry(client,client->out_buf,0);
    break;
  }
}

/* write out everything queued now, waiting up to timeout seconds (one sleep
 * at a time) while the socket is full */
void RouterFlushOutput(RouterClient *client, int timeout)
{
  int sleeps = 0;
  int written;

  if (client->out_bytesleft < 1)
    RouterReloadOutput(client);
  while (client->out_bytesleft > 0) {
    written = write(client->socket,client->out_bufptr,client->out_bytesleft);
    if (written < 0) {
      if (connection_lost(errno)) {
        RouterConnectionLost(client);
        return;
      }
      if (errno != EAGAIN) {
        RouterLogError(ROUTER_ERR_ERROR,"write",errno,client,"");
        RouterConnectionError(client);
        return;
      }
      if (++sleeps > timeout)
        return;
      sleep(1);
      written = 0;
    }
    client->out_bytesleft -= written;
    if (client->out_bytesleft < 1) {
      output_done(client);
      RouterReloadOutput(client);
    }
    else {
      client->out_bufptr += written;
    }
  }
}

/* ask every client of our servers to disconnect */
int RouterDisconnectClients(int timeout)
{
  RouterClient *client;
  int clients = 0;

  for (client = ClientList.head; client != NULL; client = client->next) {
    if ((client->use & RU_ACCEPTED) && (client->use & RU_SIDE) == RU_SERVER) {
      RouterDisconnect(client,timeout);
      clients++;
    }
  }
  return clients;
}

/* ask the other side to disconnect (it answers, then the connection closes) */
void RouterDisconnect(RouterClient *client, int timeout)
{
  client->use = (client->use & ~RU_STATE) | RU_DISCONNECTING;
  client->timeout = timeout < 1 ? 1 : timeout;
  RouterDoOutput(client,0,RC_DISCONNECT_REQ,0,NULL,NULL,NULL,NULL,NULL,0xff,NULL);
}

void RouterShutDownClients(void)
{
  while (ClientList.head != NULL)
    RouterDoClose(ClientList.head,0);
}

void RouterCloseOnlyClients(void)
{
  while (ClientList.head != NULL)
    RouterCloseOnlyClient(ClientList.head);
}

/* close without shutdown() (for a forked child: the parent keeps the connection) */
void RouterCloseOnlyClient(RouterClient *client)
{
  if (client->socket > 0) {
    RouterRemoveInput(client);
    if (client->out_bytesleft > 0 && !client->out_stopped)
      RouterRemoveOutput(client);
    SocketCloseOnly(client->socket);
  }
  RouterRemoveClient(client,0);
}

void RouterPing(RouterClient *client)
{
  RouterDoOutput(client,0,RC_PING,0,NULL,NULL,NULL,NULL,NULL,0xff,NULL);
  RouterFlushOutput(client,0);
}

static void call_SocketSetBufferSize(RouterClient *client)
{
  int rval;

  rval = SocketSetBufferSize(client->socket,SocketSendBufsize,SocketReceiveBufsize);
  if (rval != 0 && bufsize_rval == 0)
    bufsize_rval = rval;
}

/* buffer sizes for every connection, now and later; returns the first error */
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
  return SocketSetBufferSize(client->socket,sendbuf,recvbuf);
}

/* ---- connections ---- */

RouterClient *RouterMakeClient(int socket, uint32_t addr, int port, int process_id, int use, RouterServer *server, char *host, int (*in_handler)())
{
  RouterClient *client;

  client = calloc(1,sizeof(RouterClient));
  if (client == NULL)
    RouterMemError();
  client->socket = socket;
  client->addr = addr;
  client->port = port;
  client->process_id = process_id;
  client->use = use;
  client->server = server;
  strncpy(client->id.hostname,host,sizeof(client->id.hostname) - 1);
  client->in_handler = in_handler;
  client->InArgList = calloc(MaxInArgs,sizeof(RouterArgument));
  if (client->InArgList == NULL)
    RouterMemError();
  client->InArgListSize = MaxInArgs;
  return client;
}

/* this process's identity, as sent to the other side */
void RouterSetClientID(RouterID *client_id)
{
  memset(client_id,0,sizeof(*client_id));
  strncpy(client_id->procname,ProcessName,sizeof(client_id->procname) - 1);
  strncpy(client_id->username,UserName,sizeof(client_id->username) - 1);
  strncpy(client_id->fullname,FullName,sizeof(client_id->fullname) - 1);
  client_id->ipaddr = IPAddress;
}

int RouterPackID(RouterID *id, unsigned char *buf)
{
  unsigned char *p = buf;

  p = (unsigned char *)stpcpy((char *)p,id->procname) + 1;
  p = (unsigned char *)stpcpy((char *)p,id->username) + 1;
  p = (unsigned char *)stpcpy((char *)p,id->fullname) + 1;
  memcpy(p,&id->ipaddr,4);
  return p + 4 - buf;
}

/* copy a NUL-terminated string from the packet into a fixed-size field
 * (the original did not bound the copy); returns what follows it */
static char *unpack_string(char *field, size_t field_size, char *s)
{
  size_t len = strlen(s);

  memcpy(field,s,len < field_size ? len + 1 : field_size);
  field[field_size - 1] = '\0';
  return s + len + 1;
}

/* fill in procname, username, fullname (and the address, if present) */
void RouterUnpackID(RouterID *id, char *buf, int size)
{
  char *p = buf;

  p = unpack_string(id->procname,sizeof(id->procname),p);
  p = unpack_string(id->username,sizeof(id->username),p);
  p = unpack_string(id->fullname,sizeof(id->fullname),p);
  if (p - buf < size)
    memcpy(&id->ipaddr,p,4);
}

void RouterAddClient(RouterClient *client)
{
  if (ClientList.tail == NULL)
    ClientList.head = client;
  else
    ClientList.tail->next = client;
  ClientList.tail = client;
  client->next = NULL;
  ClientList.total++;
}

/* unlink and free a connection */
void RouterRemoveClient(RouterClient *client, int return_rel_request)
{
  RouterClient *prev = NULL;
  RouterClient *c;

  for (c = ClientList.head; c != NULL && c != client; c = c->next)
    prev = c;
  if (c == NULL)
    return;
  if (prev == NULL)
    ClientList.head = c->next;
  else
    prev->next = c->next;
  if (ClientList.tail == c)
    ClientList.tail = prev;
  RouterFreeClient(client,return_rel_request);
  ClientList.total--;
}

/* client, if it still exists */
RouterClient *RouterFindClient(RouterClient *client)
{
  RouterClient *c;

  for (c = ClientList.head; c != NULL; c = c->next)
    if (c == client)
      return client;
  return NULL;
}

void RouterListClients(void (*cb_func)())
{
  RouterClient *client;

  for (client = ClientList.head; client != NULL; client = client->next)
    cb_func(client);
}

/* ---- input ---- */

void RouterStartInput(RouterClient *client)
{
  free(client->in_buf);
  client->in_bufptr = NULL;
  client->in_buf = NULL;
  client->in_bufsize = 0;
  client->in_bytesneeded = sizeof(RouterHeader);
  client->in_hostbyteorder = 0;
  RouterAddInput(client);
}

/* the socket is readable: read the header, then the rest of the packet, and
 * hand the whole packet to the connection's handler */
RouterFunc RouterInput(RouterClient *client)
{
  RouterHeader hdr;
  unsigned char *b;
  int rvalue;
  int needed;

  if (client->in_buf == NULL) {
    client->in_bufsize = sizeof(RouterHeader);
    client->in_buf = malloc(client->in_bufsize);
    if (client->in_buf == NULL)
      RouterMemError();
    client->in_bufptr = (char *)client->in_buf;
  }
  if (client->in_bytesneeded > 0) {
    rvalue = read(client->socket,client->in_bufptr,client->in_bytesneeded);
    if (rvalue < 0) {
      if (errno == EAGAIN)
        return;
      if (!connection_lost(errno)) {
        RouterLogError(ROUTER_ERR_ERROR,"read",errno,client,"");
        RouterConnectionError(client);
        return;
      }
      RouterConnectionLost(client);
      return;
    }
    if (rvalue == 0) {
      RouterConnectionLost(client);
      return;
    }
    client->in_bufptr += rvalue;
    client->in_bytesneeded -= rvalue;
  }
  if (client->in_bytesneeded > 0)
    return;
  if (!client->in_hostbyteorder) {
    /* the header arrives big-endian: opcode(2) clas(1) id(1) config(1) length(3) */
    b = (unsigned char *)client->in_buf;
    hdr.opcode = b[0] << 8 | b[1];
    hdr.clas = b[2];
    hdr.id = b[3];
    hdr.config = b[4];
    hdr.length = b[5] << 16 | b[6] << 8 | b[7];
    memcpy(client->in_buf,&hdr,sizeof(hdr));
    client->in_hostbyteorder = 1;
  }
  if ((unsigned int)(client->in_bufptr - (char *)client->in_buf) <
      (unsigned int)(client->in_buf->length + sizeof(RouterHeader))) {
    /* header done: now the arguments */
    client->in_bytesneeded = client->in_buf->length;
    needed = client->in_bytesneeded + sizeof(RouterHeader);
    if (client->in_bufsize < needed) {
      client->in_buf = realloc(client->in_buf,needed);
      if (client->in_buf == NULL)
        RouterMemError();
      client->in_bufptr = (char *)(client->in_buf + 1);
      client->in_bufsize = needed;
    }
    return;
  }
  client->in_pkts++;
  if (client->in_handler(client) == 0 && RouterFindClient(client) != NULL) {
    free(client->in_buf);
    client->in_buf = NULL;
    client->in_bufsize = 0;
    client->in_bufptr = NULL;
    client->in_bytesneeded = sizeof(RouterHeader);
    client->in_sequence = 0;
    client->in_hostbyteorder = 0;
    /* resume output stopped by too many unanswered requests */
    if (client->out_stopped && client->out_bytesleft != 0 && client->in_queue.total < RQ_RESUME) {
      RouterAddOutput(client);
      client->out_stopped = 0;
    }
  }
}

/* the input handler of an established connection */
int RouterProcessPacket(RouterClient *client)
{
  int argcountin;
  int rvalue;

  argcountin = RouterUnpack(client,client->in_buf);
  switch (client->in_buf->clas) {
  case RC_REQUEST:
  case RC_REL_REQUEST:
    rvalue = RouterProcessRequest(client,argcountin);
    break;
  case RC_RESPONSE:
    rvalue = RouterProcessResponse(client,argcountin);
    break;
  case RC_EVENT:
    rvalue = RouterProcessEvent(client,argcountin);
    break;
  case RC_DISCONNECT_REQ:
    rvalue = RouterProcessDisRequest(client);
    break;
  case RC_DISCONNECT_RSP:
    rvalue = RouterProcessDisResponse(client);
    break;
  case RC_CONFIG_INIT:
    rvalue = RouterProcessConfigInit(client,argcountin);
    break;
  case RC_CONFIG_REQ:
    rvalue = RouterProcessConfigRequest(client,argcountin);
    break;
  case RC_CONFIG_RSP:
    rvalue = RouterProcessConfigResponse(client,argcountin);
    break;
  case RC_PING:
    rvalue = 0;
    break;
  default:
    RouterBadClass(client,"RouterProcessPacket");
    rvalue = -1;
    break;
  }
  RouterFreeArguments(argcountin,client->InArgList);
  return rvalue;
}

/* call the request callback; send its answer unless it responded itself */
static int RouterProcessRequest(RouterClient *client, int argcountin)
{
  RouterArgument *arglistout;
  int argcountout;

  if (client->request_cb == NULL) {
    LogError(ROUTER_ERR_PROTOCOL,"RouterProcessRequest",0,"");
    RouterConnectionError(client);
    return -1;
  }
  client->in_sequence = client->in_buf->id;
  client->ResponseSent = 0;
  argcountout = client->request_cb(client,client->in_buf->opcode,argcountin,client->InArgList,
                                   &arglistout);
  if (!client->ResponseSent)
    RouterResponseOut(client,argcountout,arglistout);
  return 0;
}

/* match a response to its request and call the request's response callback */
static int RouterProcessResponse(RouterClient *client, int argcountin)
{
  RouterQ *queue = &client->in_queue;
  RouterQEntry *response, *prev;

  if ((client->use & RU_ORDER) == RU_INORDER) {
    /* our connections: the first request waiting must be the one */
    response = RouterQRetrieve(queue);
    if (response == NULL) {
      LogError(ROUTER_ERR_PROTOCOL,"RouterProcessResponse",0,"");
      RouterConnectionError(client);
      return -1;
    }
    if (client->in_buf->id != response->header.id) {
      LogError(ROUTER_ERR_SEQUENCE,"RouterProcessResponse",0,"");
      RouterFreeEntry(client,response,0);
      RouterConnectionError(client);
      return -1;
    }
  }
  else {
    /* accepted connections: find the request by id */
    prev = NULL;
    for (response = queue->head; response != NULL && client->in_buf->id != response->header.id;
         response = response->next)
      prev = response;
    if (response == NULL) {
      LogError(ROUTER_ERR_PROTOCOL,"RouterProcessResponse",0,"request not found");
      RouterConnectionError(client);
      return -1;
    }
    if (prev == NULL)
      queue->head = response->next;
    else
      prev->next = response->next;
    /* (the original left tail on the removed entry when it was the last
     * of several) */
    if (queue->tail == response)
      queue->tail = prev;
    queue->total--;
    queue->bytes -= response->header.length;
  }
  if (response->response_cb != NULL)
    response->response_cb(client,response->response_data,argcountin,client->InArgList);
  RouterFreeEntry(client,response,0);
  return 0;
}

static int RouterProcessEvent(RouterClient *client, int argcountin)
{
  if (client->event_cb != NULL)
    client->event_cb(client,client->in_buf->opcode,argcountin,client->InArgList);
  return 0;
}

/* the other side wants to disconnect: drop our unsent requests and agree */
static int RouterProcessDisRequest(RouterClient *client)
{
  RouterQRemoveRequests(client,&client->out_queue);
  RouterCheckOutputMonitor(client);
  client->use = (client->use & ~RU_STATE) | RU_DISCONNECTED;
  RouterDoOutput(client,0,RC_DISCONNECT_RSP,0,NULL,NULL,NULL,NULL,NULL,0xff,NULL);
  return 0;
}

/* the other side agreed to our disconnect: close (always -1: the client is gone) */
static int RouterProcessDisResponse(RouterClient *client)
{
  if ((client->use & RU_STATE) == RU_DISCONNECTING) {
    RouterConnectionLost(client);
  }
  else {
    LogError(ROUTER_ERR_PROTOCOL,"RouterProcessDisResponse",0,"");
    RouterConnectionError(client);
  }
  return -1;
}

/*
 * A RouterConfig from the other side (8 bytes: rev, flags). ORIGINAL BUG:
 * only the low three bytes of each are read, so RCF_COMPRESS never arrives
 * and Router compression is never used (ORIGINAL_BUGS.md).
 */
static RouterConfig *read_config(RouterClient *client)
{
  unsigned char *b = (unsigned char *)client->InArgList[0].val;
  RouterConfig *cfg;

  cfg = calloc(1,sizeof(RouterConfig));
  if (cfg == NULL)
    RouterMemError();
  cfg->rev = b[1] << 16 | b[2] << 8 | b[3];
  cfg->flags = b[5] << 16 | b[6] << 8 | b[7];
  return cfg;
}

/* echo the config argument back with class clas, and send it now */
static void echo_config(RouterClient *client, int clas)
{
  RouterArgument arglist;

  arglist.fre = 1;
  arglist.clas = 1;
  arglist.size = client->InArgList[0].size;
  arglist.val = client->InArgList[0].val;
  RouterDoOutput(client,0,clas,1,&arglist,NULL,NULL,NULL,NULL,0,NULL);
  RouterFlushOutput(client,0);
}

/* the server's config (RouterConfigure): it applies to what we send */
static int RouterProcessConfigInit(RouterClient *client, int argcountin)
{
  RouterConfig *cfg;

  if (argcountin != 1) {
    LogError(ROUTER_ERR_ARG_COUNT,"RouterProcessConfigInit",0,"");
    return -1;
  }
  echo_config(client,RC_CONFIG_REQ);
  cfg = read_config(client);
  if (client->out_cfg != NULL && client->out_cfg != client->in_cfg)
    free(client->out_cfg);
  client->out_cfg = cfg;
  return 0;
}

/* our config echoed with the client's agreement: it applies both ways */
static int RouterProcessConfigRequest(RouterClient *client, int argcountin)
{
  RouterConfig *cfg;

  if (argcountin != 1) {
    LogError(ROUTER_ERR_ARG_COUNT,"RouterProcessConfigRequest",0,"");
    return -1;
  }
  echo_config(client,RC_CONFIG_RSP);
  cfg = read_config(client);
  free(client->in_cfg);
  if (client->out_cfg != NULL && client->out_cfg != client->in_cfg)
    free(client->out_cfg);
  client->out_cfg = cfg;
  client->in_cfg = cfg;
  return 0;
}

/* the final echo: it applies to what we receive */
static int RouterProcessConfigResponse(RouterClient *client, int argcountin)
{
  RouterConfig *cfg;

  if (argcountin != 1) {
    LogError(ROUTER_ERR_ARG_COUNT,"RouterProcessConfigResponse",0,"");
    return -1;
  }
  cfg = read_config(client);
  if (client->in_cfg != NULL && client->in_cfg != client->out_cfg)
    free(client->in_cfg);
  if (client->out_cfg != NULL && memcmp(cfg,client->out_cfg,sizeof(RouterConfig)) == 0) {
    client->in_cfg = client->out_cfg;
    free(cfg);
  }
  else {
    client->in_cfg = cfg;
  }
  return 0;
}

/* ---- output ---- */

/* queue a packet (a response gets the id of the request being answered) */
void RouterDoOutput(RouterClient *client, int opcode, int clas, int argcount, RouterArgument *arglist, void (*response_cb)(), unsigned char *response_data, void (*error_cb)(), unsigned char *error_data, int priority, void *purge_data)
{
  RouterQEntry *entry;

  RouterPack(client,opcode,clas,argcount,arglist,response_cb,response_data,error_cb,error_data,
             priority & 0xff,purge_data,&entry);
  if (entry->header.clas == RC_RESPONSE) {
    entry->header.id = client->in_sequence;
    entry->packet->id = client->in_sequence;
  }
  RouterStartOutput(client,entry);
}

/* drop queued output whose purge_data matches (purge_cb decides, if given);
 * reliable requests go back to their error callbacks */
void RouterPurge(RouterClient *client, int (*purge_cb)(), void *purge_data)
{
  RouterQ *queue = &client->out_queue;
  RouterQEntry **link = &queue->head;
  RouterQEntry *entry, *prev = NULL;
  int delete;

  while ((entry = *link) != NULL) {
    if (purge_cb == NULL)
      delete = entry->purge_data == purge_data;
    else
      delete = purge_cb(entry->purge_data,purge_data);
    if (!delete) {
      prev = entry;
      link = &entry->next;
      continue;
    }
    *link = entry->next;
    if (queue->tail == entry)
      queue->tail = prev;
    queue->total--;
    queue->bytes -= entry->header.length;
    RouterFreeEntry(client,entry,1);
  }
}

/* send now if nothing is being sent, else queue */
static void RouterStartOutput(RouterClient *client, RouterQEntry *entry)
{
  if (client->out_bytesleft < 1) {
    RouterLoadOutput(client,entry);
    RouterAddOutput(client);
    client->out_stopped = 0;
  }
  else {
    RouterQStore(&client->out_queue,entry,1);
    RouterCheckOutputMonitor(client);
  }
}

/* make entry the packet being written: requests get the next id (1..255),
 * and the header is put in wire order in place */
static void RouterLoadOutput(RouterClient *client, RouterQEntry *entry)
{
  unsigned char *b;

  client->out_pkts++;
  client->out_buf = entry;
  client->out_bufptr = (char *)entry->packet;
  client->out_bytesleft = entry->header.length + sizeof(RouterHeader);
  if (is_request(entry)) {
    client->out_sequence = (client->out_sequence + 1) & 0xff;
    if (client->out_sequence == 0)
      client->out_sequence = 1;
    entry->header.id = client->out_sequence;
    entry->packet->id = client->out_sequence;
  }
  memcpy(&entry->header,entry->packet,sizeof(RouterHeader));
  b = (unsigned char *)entry->packet;
  b[0] = entry->header.opcode >> 8;
  b[1] = entry->header.opcode;
  b[2] = entry->header.clas;
  b[3] = entry->header.id;
  b[4] = entry->header.config;
  b[5] = entry->header.length >> 16;
  b[6] = entry->header.length >> 8;
  b[7] = entry->header.length;
}

/* the socket is writable: write some more of out_buf */
static RouterFunc RouterOutput(RouterClient *client)
{
  int written;

  if (client->out_bytesleft < 1) {
    RouterReloadOutput(client);
    return;
  }
  written = write(client->socket,client->out_bufptr,client->out_bytesleft);
  if (written < 0) {
    if (errno == EAGAIN)
      return;
    if (!connection_lost(errno)) {
      RouterLogError(ROUTER_ERR_ERROR,"write",errno,client,"");
      RouterConnectionError(client);
      return;
    }
    RouterConnectionLost(client);
    return;
  }
  client->out_bytesleft -= written;
  if (client->out_bytesleft > 0) {
    client->out_bufptr += written;
    return;
  }
  output_done(client);
  RouterReloadOutput(client);
}

/* start on the next queued packet; with nothing left, stop watching for
 * writability (and end a transaction connection we made) */
static void RouterReloadOutput(RouterClient *client)
{
  RouterQEntry *entry;

  entry = RouterQRetrieve(&client->out_queue);
  if (entry == NULL) {
    client->out_buf = NULL;
    client->out_bufptr = NULL;
    client->out_bytesleft = 0;
    RouterRemoveOutput(client);
    if ((client->use & RU_KIND) == RU_TRANSACTION && (client->use & RU_SIDE) == RU_CLIENT &&
        (client->use & RU_CONNECTED))
      RouterDisconnect(client,client->timeout);
  }
  else {
    RouterLoadOutput(client,entry);
    if (client->in_queue.total >= RQ_STOP) {
      /* too many unanswered requests: wait (RouterInput resumes) */
      RouterRemoveOutput(client);
      client->out_stopped = 1;
    }
  }
  RouterCheckOutputMonitor(client);
}

/* output_monitor_cb(cb_data, client, 1) when a connection's output queue
 * passes a high water mark (entries or bytes; 0 means no limit), and
 * (cb_data, client, 0) when it falls below the low water marks */
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
  RouterQ *q = &client->out_queue;

  if (MonitorCB == NULL)
    return;
  if (!client->out_highwater) {
    if ((MonitorHighWaterEntries != 0 && q->total > MonitorHighWaterEntries) ||
        (MonitorHighWaterBytes != 0 && q->bytes > MonitorHighWaterBytes)) {
      client->out_highwater = 1;
      MonitorCB(MonitorCBData,client,1);
    }
  }
  else if ((MonitorLowWaterEntries == 0 || q->total < MonitorLowWaterEntries) &&
           (MonitorLowWaterBytes == 0 || q->bytes < MonitorLowWaterBytes)) {
    client->out_highwater = 0;
    MonitorCB(MonitorCBData,client,0);
  }
}

/* build a packet (header in host order until RouterLoadOutput) */
void RouterPack(RouterClient *client, int opcode, int clas, int argcount, RouterArgument *arglist, void (*response_cb)(), unsigned char *response_data, void (*error_cb)(), unsigned char *error_data, int priority, void *purge_data, RouterQEntry **entry)
{
  RouterQEntry *e;
  unsigned char *data_start, *p, *cbuf;
  unsigned int csize;
  int compress, size, i;

  compress = client->out_cfg != NULL && (client->out_cfg->flags & RCF_COMPRESS);
  e = malloc(sizeof(RouterQEntry));
  *entry = e;
  if (e == NULL)
    RouterMemError();
  e->response_cb = response_cb;
  e->response_data = response_data;
  e->error_cb = error_cb;
  e->error_data = error_data;
  e->priority = priority;
  e->purge_data = purge_data;
  e->next = NULL;

  size = 0;
  for (i = 0; i < argcount; i++)
    size += arglist[i].clas == 0 ? 8 : 4 + ((arglist[i].size + 3U) & ~3U);
  e->packet = malloc(size + sizeof(RouterHeader));
  if (e->packet == NULL) {
    free(e);
    RouterMemError();
  }
  e->packet->length = size;
  e->packet->opcode = opcode;
  e->packet->clas = clas;
  e->packet->id = 0;
  e->packet->config = 0;

  data_start = (unsigned char *)(e->packet + 1);
  p = data_start;
  for (i = 0; i < argcount; i++) {
    put_be32(p,arglist[i].clas << 24 | arglist[i].size);
    p += 4;
    if (arglist[i].clas == 0) {
      /* the original stored inline values unconverted, i.e. little-endian (i386) */
      put_le32(p,(uint32_t)arglist[i].val);
      p += 4;
    }
    else {
      memcpy(p,(void *)arglist[i].val,arglist[i].size);
      /* the original left the alignment padding uninitialized: heap bytes on the wire */
      memset(p + arglist[i].size,0,-arglist[i].size & 3U);
      p += (arglist[i].size + 3U) & ~3U;
    }
  }

  if (!compress || size < 1) {
    OutputStats.notry_count++;
    OutputStats.notry_bytes += size;
    client->out_stats.notry_count++;
    client->out_stats.notry_bytes += size;
  }
  else {
    if (BuffCompress(data_start,size,&cbuf,&csize) == -1)
      RouterMemError();
    if ((int)csize < size) {
      memcpy(data_start,cbuf,csize);
      e->packet->length = csize;
      e->packet->config |= RH_COMPRESSED;
      OutputStats.compress_count++;
      OutputStats.compress_bytes += csize;
      OutputStats.uncompressed_bytes += size;
      client->out_stats.compress_count++;
      client->out_stats.compress_bytes += csize;
      client->out_stats.uncompressed_bytes += size;
    }
    else {
      OutputStats.nocompress_count++;
      OutputStats.nocompress_bytes += size;
      OutputStats.nocompress_compressed_bytes += csize;
      client->out_stats.nocompress_count++;
      client->out_stats.nocompress_bytes += size;
      client->out_stats.nocompress_compressed_bytes += csize;
    }
    BuffFree(cbuf);
  }
  memcpy(&e->header,e->packet,sizeof(RouterHeader));
}

/* split a received packet into client->InArgList; returns the number of
 * arguments (data arguments are malloc()ed, freed by RouterFreeArguments) */
int RouterUnpack(RouterClient *client, RouterHeader *packet)
{
  unsigned char *p, *end, *ubuf = NULL;
  unsigned int usize;
  uint32_t class_size;
  RouterArgument *arg;
  int compressed, i, j;

  compressed = client->in_cfg != NULL && (client->in_cfg->flags & RCF_COMPRESS);
  p = (unsigned char *)(packet + 1);
  end = p + packet->length;
  if (compressed && (packet->config & RH_COMPRESSED)) {
    if (BuffUncompress(p,packet->length,&ubuf,&usize) == -1)
      RouterMemError();
    p = ubuf;
    end = ubuf + usize;
    InputStats.compress_count++;
    InputStats.compress_bytes += packet->length;
    InputStats.uncompressed_bytes += usize;
    client->in_stats.compress_count++;
    client->in_stats.compress_bytes += packet->length;
    client->in_stats.uncompressed_bytes += usize;
  }
  else if (compressed) {
    InputStats.nocompress_count++;
    InputStats.nocompress_bytes += packet->length;
    client->in_stats.nocompress_count++;
    client->in_stats.nocompress_bytes += packet->length;
  }
  else {
    InputStats.notry_count++;
    InputStats.notry_bytes += packet->length;
    client->in_stats.notry_count++;
    client->in_stats.notry_bytes += packet->length;
  }

  for (i = 0; p + 4 < end; i++) {
    if (i >= client->InArgListSize) {
      client->InArgList = realloc(client->InArgList,
                                  (client->InArgListSize + MaxInArgs) * sizeof(RouterArgument));
      if (client->InArgList == NULL)
        RouterMemError();
      client->InArgListSize += MaxInArgs;
      for (j = i; j < client->InArgListSize; j++)
        memset(&client->InArgList[j],0,sizeof(RouterArgument));
    }
    arg = &client->InArgList[i];
    class_size = get_be32(p);
    p += 4;
    arg->clas = class_size >> 24;
    arg->size = class_size & 0xffffff;
    if (arg->clas == 0) {
      arg->size = 0;
      /* the original read inline values with ntohl (so i386 peers see them byte-swapped) */
      arg->val = get_be32(p);
      p += 4;
    }
    else {
      if (p + arg->size > end)
        break;
      arg->val = (uintptr_t)malloc(arg->size);
      if (arg->val == 0) {
        RouterFreeArguments(i,client->InArgList);
        RouterMemError();
      }
      memcpy((void *)arg->val,p,arg->size);
      p += (arg->size + 3U) & ~3U;
      arg->fre = 1;
    }
  }
  if (ubuf != NULL)
    BuffFree(ubuf);
  return i;
}

/* ---- statistics ---- */

/* queue statistics for one connection, or all (client NULL); buf NULL: malloc()ed */
char *RouterDumpQStats(char *buf, RouterClient *client)
{
  RouterClient *stop;
  char *p;

  if (client == NULL) {
    client = ClientList.head;
    stop = NULL;
  }
  else {
    stop = client->next;
  }
  if (buf == NULL)
    buf = malloc(ClientList.total * 140);
  if (client == NULL) {
    sprintf(buf,"RouterDumpQStats:  no clients!\n");
    return buf;
  }
  p = buf;
  do {
    p += sprintf(p,"0x%08lx    IN:    cur %d/%d    max %d/%d    total %d\n",
                 (unsigned long)(uintptr_t)client,client->in_queue.total,client->in_queue.bytes,
                 client->in_queue.total_max,client->in_queue.bytes_max,client->in_pkts);
    p += sprintf(p,"              OUT:   cur %d/%d    max %d/%d   total %d\n",
                 client->out_queue.total,client->out_queue.bytes,client->out_queue.total_max,
                 client->out_queue.bytes_max,client->out_pkts);
    client = client->next;
  } while (client != stop);
  return buf;
}

void RouterResetQStats(RouterClient *client)
{
  RouterClient *stop;

  if (client == NULL) {
    client = ClientList.head;
    stop = NULL;
  }
  else {
    stop = client->next;
  }
  if (client == NULL)
    return;
  do {
    client->in_queue.total_max = 0;
    client->in_queue.bytes_max = 0;
    client->in_pkts = 0;
    client->out_queue.total_max = 0;
    client->out_queue.bytes_max = 0;
    client->out_pkts = 0;
    client = client->next;
  } while (client != stop);
}

void RouterDebugStats(int reset)
{
  RouterPrintProcessStats(stdout,reset);
}

void RouterPrintProcessStats(FILE *fd, int reset)
{
  if (fd != NULL) {
    fprintf(fd,"\nINPUT SIDE STATISTICS:\n");
    RouterPrintStats(fd,&InputStats);
    fprintf(fd,"\nOUTPUT SIDE STATISTICS:\n");
    RouterPrintStats(fd,&OutputStats);
  }
  if (reset) {
    memset(&InputStats,0,sizeof(InputStats));
    memset(&OutputStats,0,sizeof(OutputStats));
  }
}

void RouterPrintAllStats(FILE *fd, int reset)
{
  RouterClient *client;

  for (client = ClientList.head; client != NULL; client = client->next) {
    if (fd != NULL)
      fprintf(fd,"*** Router Statistics for client %#lx\n",(unsigned long)(uintptr_t)client);
    RouterPrintClientStats(client,fd,reset);
  }
}

void RouterPrintClientStats(RouterClient *client, FILE *fd, int reset)
{
  if (fd != NULL) {
    fprintf(fd,"\nINPUT SIDE STATISTICS:\n");
    RouterPrintStats(fd,&client->in_stats);
    fprintf(fd,"\nOUTPUT SIDE STATISTICS:\n");
    RouterPrintStats(fd,&client->out_stats);
  }
  if (reset) {
    memset(&client->in_stats,0,sizeof(client->in_stats));
    memset(&client->out_stats,0,sizeof(client->out_stats));
  }
}

static void RouterPrintStats(FILE *fd, RouterCompressStats *s)
{
  unsigned int ratio;

  fprintf(fd,"                        transfers         bytes   \n");
  fprintf(fd,"                       -----------     -----------\n");
  fprintf(fd,"No compress attempted: %11u    %11u\n",s->notry_count,s->notry_bytes);
  fprintf(fd,"Too small to compress: %11u    %11u\n",s->toosmall_count,s->toosmall_bytes);
  fprintf(fd,"Larger after compress: %11u    %11u  (%u after compress)\n",s->nocompress_count,
          s->nocompress_bytes,s->nocompress_compressed_bytes);
  fprintf(fd,"Compressed:            %11u    %11u  (%u before compress)\n",s->compress_count,
          s->compress_bytes,s->uncompressed_bytes);
  if (s->compress_bytes != 0) {
    ratio = s->uncompressed_bytes * 100 / s->compress_bytes;
    fprintf(fd,"*** Compression ratio is %d.%.2d:1\n",(int)ratio / 100,(int)ratio % 100);
  }
}

/* ---- queues ---- */

/* append entry; with use_priority, ahead of the entries of lower priority */
static void RouterQStore(RouterQ *queue, RouterQEntry *entry, int use_priority)
{
  RouterQEntry **link;

  if (queue->tail == NULL || !use_priority || entry->priority <= queue->tail->priority) {
    if (queue->tail == NULL)
      queue->head = entry;
    else
      queue->tail->next = entry;
    queue->tail = entry;
  }
  else {
    /* after the entries of the same or higher priority */
    for (link = &queue->head; *link != NULL && entry->priority <= (*link)->priority;
         link = &(*link)->next)
      ;
    entry->next = *link;
    *link = entry;
  }
  queue->total++;
  if (queue->total > queue->total_max)
    queue->total_max = queue->total;
  queue->bytes += entry->header.length;
  if (queue->bytes > queue->bytes_max)
    queue->bytes_max = queue->bytes;
}

static RouterQEntry *RouterQRetrieve(RouterQ *queue)
{
  RouterQEntry *entry = queue->head;

  if (entry == NULL)
    return NULL;
  if (queue->head == queue->tail) {
    queue->head = NULL;
    queue->tail = NULL;
  }
  else {
    queue->head = entry->next;
  }
  queue->total--;
  queue->bytes -= entry->header.length;
  /* (the original kept the stale link: a sent request moved to in_queue still
   * pointed into out_queue, and freeing both queues freed entries twice) */
  entry->next = NULL;
  return entry;
}

/* drop the requests in a queue (reliable ones go back to their error callbacks) */
static void RouterQRemoveRequests(RouterClient *client, RouterQ *queue)
{
  RouterQEntry **link = &queue->head;
  RouterQEntry *entry, *prev = NULL;

  while ((entry = *link) != NULL) {
    if (!is_request(entry)) {
      prev = entry;
      link = &entry->next;
      continue;
    }
    *link = entry->next;
    if (queue->tail == entry)
      queue->tail = prev;
    queue->total--;
    queue->bytes -= entry->header.length;
    RouterFreeEntry(client,entry,1);
  }
}

/* ---- freeing ---- */

void RouterFreeArguments(int argcount, RouterArgument *arglist)
{
  int i;

  for (i = 0; i < argcount; i++)
    if (arglist[i].clas == 1 && arglist[i].fre && arglist[i].val != 0)
      free((void *)arglist[i].val);
}

void RouterFreeClient(RouterClient *client, int return_rel_request)
{
  RouterFreeGroups(client);
  free(client->in_buf);
  free(client->in_cfg);
  if (client->out_cfg != client->in_cfg)
    free(client->out_cfg);
  RouterFreeQueue(client,&client->in_queue,return_rel_request);
  RouterFreeEntry(client,client->out_buf,return_rel_request);
  RouterFreeQueue(client,&client->out_queue,return_rel_request);
  free(client->InArgList);
  if (client->error_cb == NULL && ClientFreeCB != NULL)
    ClientFreeCB(client);
  free(client);
}

void RouterFreeGroups(RouterClient *client)
{
  free(client->groups.bits);
  client->groups.count = 0;
  client->groups.bits = NULL;
}

static void RouterFreeQueue(RouterClient *client, RouterQ *queue, int return_rel_request)
{
  RouterQEntry *entry, *next;

  for (entry = queue->head; entry != NULL; entry = next) {
    next = entry->next;
    RouterFreeEntry(client,entry,return_rel_request);
  }
}

/* free a queue entry; with return_rel_request a reliable request's arguments
 * go to its error callback first */
static void RouterFreeEntry(RouterClient *client, RouterQEntry *entry, int return_rel_request)
{
  int argcountin;

  if (entry == NULL)
    return;
  if (entry->packet != NULL) {
    if (return_rel_request && entry->header.clas == RC_REL_REQUEST && entry->error_cb != NULL) {
      /* (a sent packet's header is in wire order: RouterUnpack needs the host
       * order one. The original unpacked the wire header.) */
      memcpy(entry->packet,&entry->header,sizeof(RouterHeader));
      argcountin = RouterUnpack(client,entry->packet);
      entry->error_cb(client,entry->error_data,argcountin,client->InArgList);
      RouterFreeArguments(argcountin,client->InArgList);
    }
    free(entry->packet);
  }
  free(entry);
}

static void RouterFreePacket(RouterQEntry *entry)
{
  if (entry != NULL && entry->packet != NULL) {
    free(entry->packet);
    entry->packet = NULL;
  }
}

/* ---- event loop hooks ---- */

static void RouterAddInput(RouterClient *client)
{
  client->input_id = EventAddInput(client->socket,RouterInput,(EventData)client,"RouterAddInput");
}

static void RouterRemoveInput(RouterClient *client)
{
  EventRemoveInput(client->input_id);
}

static void RouterAddOutput(RouterClient *client)
{
  client->output_id = EventAddOutput(client->socket,RouterOutput,(EventData)client,
                                     "RouterAddOutput");
}

static void RouterRemoveOutput(RouterClient *client)
{
  EventRemoveOutput(client->output_id);
}

void RouterAddTimer(RouterClient *client, RouterFunc (*timer_func)(), int timeout)
{
  if (client->timer_id != 0)
    EventRemoveTimeOut(client->timer_id);
  client->timer_id = EventAddTimeOut(timeout,0,timer_func,(EventData)client,"RouterAddTimer");
}

void RouterRemoveTimer(RouterClient *client)
{
  EventRemoveTimeOut(client->timer_id);
  client->timer_id = 0;
}

/* ---- errors ---- */

/* LogError() with the connection's host, port and process */
void RouterLogError(int msgnbr, char *func_name, int errnbr, RouterClient *client, char *format, ...)
{
  va_list args;

  va_start(args,format);
  LoggerVLogMessage(msgnbr,func_name,errnbr,client->id.hostname,client->port,client->id.procname,
                    format,args);
  va_end(args);
}

int RouterCheckOutput(RouterClient *client, char *func_name)
{
  if (!(client->use & RU_CONNECTED)) {
    LogError(ROUTER_ERR_NO_OUTPUT,func_name,0,"");
    return -1;
  }
  return 0;
}

/* the connection's error number for a lost connection, a timeout and other
 * errors, by state */
static int state_error(RouterClient *client, int connecting, int other)
{
  switch (client->use & RU_STATE) {
  case RU_CONNECTING:
    return connecting;
  case RU_DISCONNECTING:
    return ROUTER_ERR_CLOSED_LOCAL;
  case RU_DISCONNECTED:
    return ROUTER_ERR_CLOSED_REMOTE;
  default:
    return other;
  }
}

void RouterConnectionLost(RouterClient *client)
{
  /* a client that drops during our server's handshake is no error */
  if ((client->use & RU_STATE) == RU_CONNECTING && (client->use & RU_SIDE) == RU_SERVER)
    client->error_cb = NULL;
  RouterClientError(client,state_error(client,ROUTER_ERR_CONNECT_FAILED,ROUTER_ERR_LOST));
}

void RouterConnectionTimeout(RouterClient *client)
{
  if ((client->use & RU_STATE) == RU_CONNECTING && (client->use & RU_SIDE) == RU_SERVER) {
    RouterClose(client);
    return;
  }
  RouterClientError(client,state_error(client,ROUTER_ERR_CONNECT_TIMEOUT,ROUTER_ERR_TIMEOUT));
}

void RouterConnectionError(RouterClient *client)
{
  int msgnbr;

  switch (client->use & RU_STATE) {
  case RU_CONNECTING:
    msgnbr = ROUTER_ERR_CONNECT_ERROR;
    break;
  case RU_DISCONNECTING:
  case RU_DISCONNECTED:
    msgnbr = ROUTER_ERR_CLOSE_ERROR;
    break;
  default:
    msgnbr = ROUTER_ERR_ERROR;
    break;
  }
  RouterClientError(client,msgnbr);
}

/* report to the error callback, then close */
void RouterClientError(RouterClient *client, int msgnbr)
{
  client->use &= ~RU_STATE;
  if (client->error_cb != NULL)
    client->error_cb(client,msgnbr,&client->id,client->port,client->retrys);
  RouterClose(client);
}

/* a packet of the wrong class: a known class at the wrong time is
 * "unexpected", anything else "invalid" */
void RouterBadClass(RouterClient *client, char *func_name)
{
  switch (client->in_buf->clas) {
  case RC_PASSWORD_REQ:
  case RC_PASSWORD:
  case RC_ACCEPT:
  case RC_CLIENT_ID:
  case RC_REQUEST:
  case RC_DISCONNECT_REQ:
  case RC_DISCONNECT_RSP:
  case RC_REL_REQUEST:
  case RC_RESPONSE:
  case RC_EVENT:
    RouterLogError(ROUTER_ERR_UNEXPECTED_CLASS,func_name,0,client,"");
    break;
  default:
    RouterLogError(ROUTER_ERR_BAD_CLASS,func_name,0,client,"");
    break;
  }
  RouterConnectionError(client);
}

/* out of memory: report, drop every connection, and stop */
void RouterMemError(void)
{
  MemUsage();
  RouterShutDownClients();
  LogError(ROUTER_ERR_MALLOC,"",0,"");
  if (FatalCB != NULL)
    FatalCB(ROUTER_ERR_MALLOC);
  abort();
}

int RouterClose(RouterClient *client)
{
  return RouterDoClose(client,1);
}

int RouterDoClose(RouterClient *client, int return_rel_request)
{
  int rvalue = 0;

  if (client->socket > 0) {
    RouterRemoveInput(client);
    if (client->out_bytesleft > 0 && !client->out_stopped)
      RouterRemoveOutput(client);
    rvalue = SocketClose(client->socket);
  }
  RouterRemoveClient(client,return_rel_request);
  return rvalue;
}
