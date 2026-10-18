/*
 * sys_ctrl/l3/IRouter/IRouterL3.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/IRouter/IRouterL3.c
 *
 * IRouter for the L3 tools: packets to and from an L2 as events of a Router
 * connection (IRouter2Router.c). Calls run the event loop until what they
 * wait for arrives (rtr_waiting_for), with the Router callbacks below
 * stopping it; responses that come while nobody waits are queued.
 */

#include <stdlib.h>
#include <string.h>
#include "IRouterL3.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../../common/Router/Event.h"
#include "../../common/Router/Router.h"
#include "../../common/Router/RouterCl.h"
#include "../../common/Router/RouterMsg.h"
#include "../../common/sys/Logger.h"
#include "../sys/syslogLib.h"
void pkt_timeout(EventData client_data);   /* defined below; not in a header (a static of this name exists elsewhere) */

#define L2_QUIET_PORT       8002        /* plus IR_PORT_BIAS: connections not logged */
#define SMP_PORT            8003
#define L2_APP_QUIET_PORT   9004
#define ROUTER_PROCESS_ID   2
#define CONNECT_TIMEOUT     300
#define CONNECT_LIMIT       0x100
#define PARTITIONS          256         /* the event groups: one per partition */
#define RSP_QUEUE_SIZE      100
#define TIMEOUT_ERR         IR_ERRNO(IRERR_TIMEOUT)

/* rtr_waiting_for */
#define WAIT_CONNECT        1
#define WAIT_PACKET         2

/* connect_cb's opcode (RouterCl.c) */
#define CONNECT_ACCEPTED    1
#define CONNECT_PASSWORD    2

static int send_packet(IRClient *client, IRIdent *id, IRPacket *pkt);
static void rtr_set_input_func(RouterClient *client);
static void rtr_restore_input_func(RouterClient *client);

int rtr_error;                  /* what the callbacks report */
int rtr_waiting_for;
int rtr_rsp_queue_rd;
int rtr_rsp_queue_wr;
int IRouterEventLoop = 1;       /* 0 while a call here runs the event loop */
EventID pkt_timeout_id;
char *(*get_password)();
RouterClient *rtr_server;       /* the connection the callbacks heard from */
IRPacket *rtr_pkt;              /* the packet rtr_event() got */
IRPacket *rtr_rsp_queue[RSP_QUEUE_SIZE];

/* the ports whose connections are not logged */
static int quiet_port(int port)
{
  return port == IR_PORT_BIAS + L2_QUIET_PORT || port == IR_PORT_BIAS + SMP_PORT ||
         port == IR_PORT_BIAS + L2_APP_QUIET_PORT;
}

/*
 * Connect to host:port as cname; events is our IRouter task, and its
 * bits 16-23 a partition whose events we want (0: all). pw_cb gives a
 * password if the L2 asks. Returns once the Router configuration has been
 * exchanged, or an error. (Exits if the Router cannot start.)
 */
int IRouterConnectL3(char *cname, char *host, int port, IRClient **client, int events, char *(*pw_cb)())
{
  static RouterGroupSet partitions;
  EventTimer cfg_timer;
  int partition;
  int saved_loop;

  if (cname == NULL)
    cname = "unknown";
  if (RouterInit(0x100,1,cname,events,NULL) < 0) {
    syslog(6,"IRouterL3.c",83,0,"Could not initialize Router");
    exit(-1);
  }
  if (!quiet_port(port))
    syslog(6,"IRouterL3.c",88,0,"attempting connection to %s:%d",host,port);
  get_password = pw_cb;
  partition = events >> 16 & 0xff;
  if (partition == 0) {
    *client = RouterMakeConnection(host,port,ROUTER_PROCESS_ID,CONNECT_TIMEOUT,CONNECT_LIMIT,
                                   rtr_connected,NULL,rtr_event,rtr_connect_failure);
    if (*client == NULL) {
      syslog(6,"IRouterL3.c",129,0,"could not establish connection");
      exit(-1);
    }
  }
  else {
    partitions.count = PARTITIONS;
    partitions.bits = malloc(PARTITIONS / 8);
    memset(partitions.bits,0,(partitions.count + 7) >> 3);
    partitions.bits[partition >> 3] |= 1 << (partition & 7);
    *client = RouterMakeGroupConnection(host,port,ROUTER_PROCESS_ID,&partitions,CONNECT_TIMEOUT,
                                        CONNECT_LIMIT,rtr_connected,NULL,rtr_event,
                                        rtr_connect_failure);
    if (*client == NULL) {
      syslog(6,"IRouterL3.c",116,0,"could not establish connection");
      exit(-1);
    }
  }

  /* until rtr_connected() or rtr_connect_failure() */
  saved_loop = IRouterEventLoop;
  IRouterEventLoop = 0;
  rtr_error = 0;
  rtr_server = NULL;
  rtr_waiting_for = WAIT_CONNECT;
  EventStart();
  rtr_waiting_for = 0;
  IRouterEventLoop = saved_loop;
  *client = rtr_server;
  if (rtr_error != 0)
    return rtr_error;

  /* then for the Router configuration exchange, half a second at a time */
  do {
    EventCreateTimeOut(&cfg_timer,0,500000,pkt_timeout,(EventData)0,"IRouterConnectL3");
    EventStartSubset(NULL,NULL,&cfg_timer,1);
    if (rtr_error == TIMEOUT_ERR && *client != NULL && (*client)->in_cfg != NULL &&
        (*client)->out_cfg != NULL) {
      rtr_error = 0;
      return 0;
    }
  } while (rtr_error == TIMEOUT_ERR);
  return rtr_error;
}

void IRouterDisconnectL3(IRClient *client)
{
  RouterClose(client);
}

static int send_packet(IRClient *client, IRIdent *id, IRPacket *pkt)
{
  int rval;

  rval = IRouterForwardPacket(client,id,pkt);
  if (rval == 0)
    EventDispatch();
  return rval;
}

/* send a request; *seqnum (if not NULL) is its sequence number */
int IRouterRequestL3(IRClient *client, IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum)
{
  IRPacket *pkt;

  if (RouterFindClient(client) == NULL)
    return ROUTER_ERR_LOST;
  if (seqnum != NULL)
    *seqnum = id->seqnum;
  pkt = IRouterMakePacket(id,toaddr,0,opcode,IR_REQ,2,argcount,arglist);
  if (pkt == NULL)
    return IR_ERRNO(IRERR_MALLOC_FAILED);
  return send_packet(client,id,pkt);
}

/* answer reqpkt; errcode is an IRouter error number (IR_ERRNO()) or 0 */
int IRouterResponseL3(IRClient *client, IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist)
{
  IRPacket *pkt;

  if (RouterFindClient(client) == NULL)
    return ROUTER_ERR_LOST;
  pkt = IRouterMakePacket(id,&reqpkt->_src,0,reqpkt->_opcode,IR_RSP,reqpkt->_rev,argcount,arglist);
  if (pkt == NULL)
    return IR_ERRNO(IRERR_MALLOC_FAILED);
  pkt->_err = (-errcode) % 100;
  pkt->_seqnum0 = reqpkt->_seqnum0;
  pkt->_seqnum1 = reqpkt->_seqnum1;
  return send_packet(client,id,pkt);
}

int IRouterEventL3(IRClient *client, IRIdent *id, int opcode, int argcount, IRArgument *arglist)
{
  IRPacket *pkt;

  if (RouterFindClient(client) == NULL)
    return ROUTER_ERR_LOST;
  pkt = IRouterMakePacket(id,NULL,0,opcode,IR_EVT,2,argcount,arglist);
  if (pkt == NULL)
    return IR_ERRNO(IRERR_MALLOC_FAILED);
  return send_packet(client,id,pkt);
}

/* waiting on one connection (*client), not all of them? */
static int one_client(IRClient **client)
{
  return client != NULL && *client != NULL;
}

/*
 * The next packet (a response, if response is set: others are dropped)
 * from *client, or from any connection if client or *client is NULL (then
 * *client is where it came from). wait: seconds, 0 for 10 ms, -1 forever.
 * A queued early response comes first.
 */
int IRouterGetPacketL3(IRIdent *id, IRPacket **pkt, IRClient **client, int wait, int response)
{
  EventTimer pkt_timer;
  fd_set evt_subset;
  int timed = 0;
  int saved_loop;
  int rval;

  if (!one_client(client)) {
    if (RouterConnectionCount() == 0)
      return ROUTER_ERR_LOST;
  }
  else {
    if (RouterFindClient(*client) == NULL)
      return ROUTER_ERR_LOST;
    FD_ZERO(&evt_subset);
    FD_SET((*client)->socket,&evt_subset);
  }
  RouterListClients(rtr_set_input_func);
  if (wait != -1) {
    timed = 1;
    if (!one_client(client))
      pkt_timeout_id = EventAddTimeOut(wait == 0 ? 0 : wait,wait == 0 ? 10000 : 0,pkt_timeout,
                                       (EventData)0,"IRouterGetPacketL3");
    else
      EventCreateTimeOut(&pkt_timer,wait == 0 ? 0 : wait,wait == 0 ? 10000 : 0,pkt_timeout,
                         (EventData)0,"IRouterGetPacketL3");
  }

  for (;;) {
    if (timed && (one_client(client) ? pkt_timer.next != EVENT_TIMER_ARMED : pkt_timeout_id == 0)) {
      *pkt = NULL;
      rval = TIMEOUT_ERR;
      break;
    }
    saved_loop = IRouterEventLoop;
    IRouterEventLoop = 0;
    rtr_error = 0;
    rtr_server = NULL;
    rtr_waiting_for = WAIT_PACKET;
    if (rtr_rsp_queue_rd == rtr_rsp_queue_wr) {
      if (!one_client(client))
        EventStart();
      else
        EventStartSubset(&evt_subset,&evt_subset,&pkt_timer,1);
    }
    else {
      rtr_pkt = rtr_rsp_queue[rtr_rsp_queue_rd++];
      if (rtr_rsp_queue_rd == rtr_rsp_queue_wr) {
        rtr_rsp_queue_wr = 0;
        rtr_rsp_queue_rd = 0;
      }
    }
    rtr_waiting_for = 0;
    IRouterEventLoop = saved_loop;
    if (rtr_error != 0) {
      *pkt = NULL;
      rval = rtr_error;
      break;
    }
    if (rtr_pkt == NULL) {
      *pkt = NULL;
      rval = TIMEOUT_ERR;
      break;
    }
    *pkt = rtr_pkt;
    rtr_pkt = NULL;
    if (client != NULL)
      *client = rtr_server;
    if (!response || (*pkt)->_clas == IR_RSP) {
      rval = 0;
      break;
    }
    /* (not a response: dropped, as in the original) */
  }
  if (pkt_timeout_id != 0) {
    EventRemoveTimeOut(pkt_timeout_id);
    pkt_timeout_id = 0;
  }
  RouterListClients(rtr_restore_input_func);
  return rval;
}

/* while a call here waits, the connections' input goes straight to the
 * Router (not to whatever the program has on them) */
static void rtr_set_input_func(RouterClient *client)
{
  EventReplaceInputTemp(client->socket,RouterInput,(EventData)client,"rtr_set_input_func");
}

static void rtr_restore_input_func(RouterClient *client)
{
  EventRestoreInputTemp(client->socket);
}

/* the Router's connect callback: a password for the L2, or connected */
int rtr_connected(RouterClient *client, int opcode, RouterArgument **arglistout)
{
  static RouterArgument pwarg[1];
  char *pw = "";

  if (opcode == CONNECT_PASSWORD) {
    memset(&pwarg[0],0,sizeof(pwarg[0]));
    if (get_password != NULL)
      pw = get_password(client);
    if (pw != NULL) {
      pwarg[0].clas = 1;
      pwarg[0].val = (uintptr_t)strdup(pw);
      pwarg[0].fre = 1;
      pwarg[0].size = strlen(pw) + 1;
    }
    *arglistout = pwarg;
    return 1;
  }
  rtr_server = client;
  rtr_error = 0;
  if (!quiet_port(client->port))
    syslog(6,"IRouterL3.c",496,0,"connection to %s:%d established.",client->id.hostname,client->port);
  if (!IRouterEventLoop && rtr_waiting_for == WAIT_CONNECT) {
    RouterFlushOutput(client,5);
    EventStop();
  }
  return 0;
}

void rtr_connect_failure(RouterClient *client, int msgnbr, char *host, int port, int retrys)
{
  syslog(6,"IRouterL3.c",531,0,"connection to %s:%d failed: %s",host,port,LoggerDefaultMessage(msgnbr));
  rtr_server = NULL;
  rtr_error = msgnbr;
  if (!IRouterEventLoop && rtr_waiting_for == WAIT_CONNECT) {
    RouterFlushOutput(client,5);
    EventStop();
  }
}

/* the Router's event callback: an IRouter packet. A response nobody waits
 * for is queued. */
void rtr_event(RouterClient *client, int opcode, int argcount, RouterArgument *arglistin)
{
  rtr_server = client;
  rtr_error = 0;
  rtr_pkt = IRouterPacketFromRouter(argcount,arglistin);
  if (rtr_pkt == NULL) {
    syslog(6,"IRouterL3.c",567,0,"invalid IRouter packet received!");
    rtr_error = IR_ERRNO(IRERR_BAD_PKT_TYPE);
    return;
  }
  if (!IRouterEventLoop && rtr_waiting_for == WAIT_PACKET) {
    RouterFlushOutput(client,5);
    EventStop();
  }
  if (rtr_waiting_for != WAIT_PACKET && rtr_pkt->_clas == IR_RSP) {
    if (rtr_rsp_queue_wr < RSP_QUEUE_SIZE)
      rtr_rsp_queue[rtr_rsp_queue_wr++] = rtr_pkt;
    else
      syslog(4,"IRouterL3.c",596,0,"Lost an early response (queue full)!");
    rtr_pkt = NULL;
  }
}

void pkt_timeout(EventData client_data)
{
  pkt_timeout_id = 0;
  rtr_server = NULL;
  rtr_error = TIMEOUT_ERR;
  EventStop();
}
