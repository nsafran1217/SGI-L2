/*
 * sys_ctrl/l3/IRouter/IRouterL3.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/IRouter/IRouterL3.c
 */

#include <stdlib.h>
#include <string.h>
#include "../../common/Router/RouterCl.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "../../common/Router/Event.h"
#include <time.h>
#include <sys/time.h>
#include "../../common/Router/Router.h"
#include "../../common/sys/Logger.h"
#include "../sys/LoggerMsg.h"
#include "IRouterL3.h"
#include "../../common/Router/RouterMsg.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/sys/brick_types.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/main/L1Cfg.h"
#include "../../common/sys/syslog.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */
void pkt_timeout(EventData client_data);   /* defined below; not in a header (a static of this name exists elsewhere) */

static int send_packet(IRClient *client, IRIdent *id, IRPacket *pkt);
static void rtr_set_input_func(RouterClient *client);
static void rtr_restore_input_func(RouterClient *client);

int rtr_error;
int rtr_waiting_for;
int rtr_rsp_queue_rd;
int rtr_rsp_queue_wr;
int IRouterEventLoop = 1;
EventID pkt_timeout_id;
char *(*get_password)();
RouterClient *rtr_server;
IRPacket *rtr_pkt;
IRPacket *rtr_rsp_queue[100];

int IRouterConnectL3(char *cname, char *host, int port, IRClient **client, int events, char *(*pw_cb)())
{
  static RouterGroupSet partitions;
  int iVar1;
  RouterClient *pRVar2;
  byte bVar3;
  int partition;
  EventTimer cfg_timer;
  int server_process_id;
  int irouter_event_loop;
  int limit;
  int timeout;
  
  if (cname == NULL) {
    cname = "unknown";
  }
  iVar1 = RouterInit(0x100,1,cname,events,NULL);
  if (iVar1 < 0) {
    syslog(6,"IRouterL3.c",0x53,0,"Could not initialize Router");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  if (((port != IR_PORT_BIAS + 0x1f42) && (port != IR_PORT_BIAS + 0x1f43)) &&
     (port != IR_PORT_BIAS + 0x232c)) {
    syslog(6,"IRouterL3.c",0x58,0,"attempting connection to %s:%d",host,port);
  }
  get_password = pw_cb;
  partition = events >> 0x10 & 0xff;
  if (partition == 0) {
    pRVar2 = RouterMakeConnection
                       (host,port,2,300,0x100,rtr_connected,NULL,rtr_event,
                        rtr_connect_failure);
    *client = pRVar2;
    if (pRVar2 == NULL) {
      syslog(6,"IRouterL3.c",0x81,0,"could not establish connection");
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
  }
  else {
    partitions.count = 0x100;
    partitions.bits = malloc(0x20);
    memset(partitions.bits,0,partitions.count + 7 >> 3);
    iVar1 = partition;
    if (false) {
      iVar1 = partition + 7;
    }
    bVar3 = partitions.bits[iVar1 >> 3];
    if ((uint)partition < partitions.count) {
      if (false) {
        partition = partition + 7;
      }
      bVar3 = bVar3 | (byte)(1 << ((char)((uint)events >> 0x10) + (char)(partition >> 3) * -8 &
                                  0x1fU));
    }
    partitions.bits[iVar1 >> 3] = bVar3;
    pRVar2 = RouterMakeGroupConnection
                       (host,port,2,(RouterGroupSet *)&partitions,300,0x100,rtr_connected,
                        NULL,rtr_event,rtr_connect_failure);
    *client = pRVar2;
    if (pRVar2 == NULL) {
      syslog(6,"IRouterL3.c",0x74,0,"could not establish connection");
                    /* WARNING: Subroutine does not return */
      exit(-1);
    }
  }
  iVar1 = IRouterEventLoop;
  IRouterEventLoop = 0;
  rtr_error = 0;
  rtr_server = NULL;
  rtr_waiting_for = 1;
  EventStart();
  rtr_waiting_for = 0;
  IRouterEventLoop = iVar1;
  *client = rtr_server;
  if (rtr_error == 0) {
    do {
      EventCreateTimeOut(&cfg_timer,0,500000,pkt_timeout,(EventData)0x0,"IRouterConnectL3");
      EventStartSubset(NULL,NULL,&cfg_timer,1);
      if (((rtr_error == -0x26c) && (*client != NULL)) &&
         (((*client)->in_cfg != NULL && ((*client)->out_cfg != NULL)))
         ) {
        rtr_error = 0;
        iVar1 = rtr_error;
        rtr_error = 0;
        return iVar1;
      }
    } while (rtr_error == -0x26c);
  }
  return rtr_error;
}

void IRouterDisconnectL3(IRClient *client)
{
  RouterClose(client);
  return;
}

static int send_packet(IRClient *client, IRIdent *id, IRPacket *pkt)
{
  int rval;
  
  rval = IRouterForwardPacket(client,id,pkt);
  if (rval == 0) {
    EventDispatch();
  }
  return rval;
}

int IRouterRequestL3(IRClient *client, IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum)
{
  RouterClient *pRVar1;
  int iVar2;
  IRPacket *pkt;
  int rval;
  
  pRVar1 = RouterFindClient(client);
  if (pRVar1 == NULL) {
    iVar2 = -0x12f;
  }
  else {
    if (seqnum != NULL) {
      *seqnum = (uint)id->seqnum;
    }
    pkt = IRouterMakePacket(id,toaddr,0,opcode,0,2,argcount,arglist);
    if (pkt == NULL) {
      iVar2 = -0x25c;
    }
    else {
      iVar2 = send_packet(client,id,pkt);
    }
  }
  return iVar2;
}

int IRouterResponseL3(IRClient *client, IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist)
{
  RouterClient *pRVar1;
  int iVar2;
  IRPacket *pkt;
  uint8 uStack_14;
  int rval;
  
  pRVar1 = RouterFindClient(client);
  if (pRVar1 == NULL) {
    iVar2 = -0x12f;
  }
  else {
    pkt = IRouterMakePacket(id,&reqpkt->_src,0,(uint)reqpkt->_opcode,1,(uint)reqpkt->_rev,argcount,
                            arglist);
    if (pkt == NULL) {
      iVar2 = -0x25c;
    }
    else {
      uStack_14 = (char)-errcode + (char)(-errcode / 100) * -100;
      pkt->_err = uStack_14;
      pkt->_seqnum0 = reqpkt->_seqnum0;
      pkt->_seqnum1 = reqpkt->_seqnum1;
      iVar2 = send_packet(client,id,pkt);
    }
  }
  return iVar2;
}

int IRouterEventL3(IRClient *client, IRIdent *id, int opcode, int argcount, IRArgument *arglist)
{
  RouterClient *pRVar1;
  int iVar2;
  IRPacket *pkt;
  int rval;
  
  pRVar1 = RouterFindClient(client);
  if (pRVar1 == NULL) {
    iVar2 = -0x12f;
  }
  else {
    pkt = IRouterMakePacket(id,NULL,0,opcode,2,2,argcount,arglist);
    if (pkt == NULL) {
      iVar2 = -0x25c;
    }
    else {
      iVar2 = send_packet(client,id,pkt);
    }
  }
  return iVar2;
}

int IRouterGetPacketL3(IRIdent *id, IRPacket **pkt, IRClient **client, int wait, int response)
{
  byte *pbVar1;
  bool bVar2;
  RouterClient *pRVar3;
  int iVar4;
  int waiting;
  int __d1;
  int __d0;
  EventData old_input_data;
  code *old_input_func;
  fd_set evt_subset;
  int rval;
  EventTimer pkt_timer;
  int irouter_event_loop;
  
  bVar2 = false;
  rval = 0;
  if ((client == NULL) || (*client == NULL)) {
    iVar4 = RouterConnectionCount();
    if (iVar4 == 0) {
      return -0x12f;
    }
  }
  else {
    pRVar3 = RouterFindClient(*client);
    if (pRVar3 == NULL) {
      return -0x12f;
    }
    FD_ZERO(&evt_subset);
    FD_SET((*client)->socket, &evt_subset);
  }
  RouterListClients(rtr_set_input_func);
  if (wait == 0) {
    bVar2 = true;
    if ((client == NULL) || (*client == NULL)) {
      pkt_timeout_id = EventAddTimeOut(0,10000,pkt_timeout,(EventData)0x0,"IRouterGetPacketL3");
    }
    else {
      EventCreateTimeOut(&pkt_timer,0,10000,pkt_timeout,(EventData)0x0,"IRouterGetPacketL3");
    }
  }
  else if (wait != -1) {
    bVar2 = true;
    if ((client == NULL) || (*client == NULL)) {
      pkt_timeout_id = EventAddTimeOut(wait,0,pkt_timeout,(EventData)0x0,"IRouterGetPacketL3");
    }
    else {
      EventCreateTimeOut(&pkt_timer,wait,0,pkt_timeout,(EventData)0x0,"IRouterGetPacketL3");
    }
  }
  do {
    iVar4 = IRouterEventLoop;
    if ((bVar2) &&
       ((((client == NULL || (*client == NULL)) && (pkt_timeout_id == 0)) ||
        (((client != NULL && (*client != NULL)) &&
         (pkt_timer.next != (struct _EventTimerEntry *)0xffffffff)))))) {
      *pkt = NULL;
      rval = -0x26c;
LAB_0807e270:
      if (pkt_timeout_id != 0) {
        EventRemoveTimeOut(pkt_timeout_id);
        pkt_timeout_id = 0;
      }
      RouterListClients(rtr_restore_input_func);
      return rval;
    }
    IRouterEventLoop = 0;
    rtr_error = 0;
    rtr_server = NULL;
    rtr_waiting_for = 2;
    if (rtr_rsp_queue_rd == rtr_rsp_queue_wr) {
      if ((client == NULL) || (*client == NULL)) {
        EventStart();
      }
      else {
        EventStartSubset(&evt_subset,&evt_subset,&pkt_timer,1);
      }
    }
    else {
      rtr_pkt = rtr_rsp_queue[rtr_rsp_queue_rd];
      rtr_rsp_queue_rd = rtr_rsp_queue_rd + 1;
      if (rtr_rsp_queue_rd == rtr_rsp_queue_wr) {
        rtr_rsp_queue_wr = 0;
        rtr_rsp_queue_rd = 0;
      }
    }
    rtr_waiting_for = 0;
    IRouterEventLoop = iVar4;
    if (rtr_error != 0) {
      rval = rtr_error;
      *pkt = NULL;
      goto LAB_0807e270;
    }
    if (rtr_pkt == NULL) {
      *pkt = NULL;
      rval = -0x26c;
      goto LAB_0807e270;
    }
    *pkt = rtr_pkt;
    rtr_pkt = NULL;
    if (client != NULL) {
      *client = rtr_server;
    }
    if ((response == 0) || ((*pkt)->_clas == '\x01')) goto LAB_0807e270;
  } while( true );
}

static void rtr_set_input_func(RouterClient *client)
{
  EventReplaceInputTemp(client->socket,RouterInput,(EventData)client,"rtr_set_input_func");
  return;
}

static void rtr_restore_input_func(RouterClient *client)
{
  EventRestoreInputTemp(client->socket);
  return;
}

int rtr_connected(RouterClient *client, int opcode, RouterArgument **arglistout)
{
  static RouterArgument pwarg[1];
  size_t sVar1;
  int iVar2;
  char *pw;
  char *tstr;
  RouterArgument args [2];
  
  if (opcode == 2) {
    pw = "";
    pwarg[0].val = 0;
    pwarg[0].clas = 0;
    pwarg[0].fre = 0;
    pwarg[0].size = 0;
    if (get_password != NULL) {
      pw = (*get_password)(client);
    }
    if (pw != NULL) {
      pwarg[0].clas = 1;
      pwarg[0].val = (ulong)strdup(pw);
      pwarg[0].fre = 1;
      pwarg[0].size = strlen(pw) + 1;
    }
    *arglistout = (RouterArgument *)&pwarg;
    iVar2 = 1;
  }
  else {
    rtr_server = client;
    rtr_error = 0;
    if (((client->port != IR_PORT_BIAS + 0x1f42) && (client->port != IR_PORT_BIAS + 0x1f43)) &&
       (client->port != IR_PORT_BIAS + 0x232c)) {
      syslog(6,"IRouterL3.c",0x1f0,0,"connection to %s:%d established.",&client->id,client->port);
    }
    if ((IRouterEventLoop == 0) && (rtr_waiting_for == 1)) {
      RouterFlushOutput(client,5);
      EventStop();
    }
    iVar2 = 0;
  }
  return iVar2;
}

void rtr_connect_failure(RouterClient *client, int msgnbr, char *host, int port, int retrys)
{
  char *pcVar1;
  
  pcVar1 = LoggerDefaultMessage(msgnbr);
  syslog(6,"IRouterL3.c",0x213,0,"connection to %s:%d failed: %s",host,port,pcVar1);
  rtr_server = NULL;
  rtr_error = msgnbr;
  if ((IRouterEventLoop == 0) && (rtr_waiting_for == 1)) {
    RouterFlushOutput(client,5);
    EventStop();
  }
  return;
}

void rtr_event(RouterClient *client, int opcode, int argcount, RouterArgument *arglistin)
{
  IRPacket *ppf;
  int i;
  int rval;
  
  rtr_server = client;
  rtr_error = 0;
  rtr_pkt = IRouterPacketFromRouter(argcount,arglistin);
  if (rtr_pkt == NULL) {
    syslog(6,"IRouterL3.c",0x237,0,"invalid IRouter packet received!");
    rtr_error = -0x259;
  }
  else {
    if ((IRouterEventLoop == 0) && (rtr_waiting_for == 2)) {
      RouterFlushOutput(client,5);
      EventStop();
    }
    if ((rtr_waiting_for != 2) && (rtr_pkt->_clas == '\x01')) {
      if (rtr_rsp_queue_wr < 100) {
        rtr_rsp_queue[rtr_rsp_queue_wr] = rtr_pkt;
        rtr_rsp_queue_wr = rtr_rsp_queue_wr + 1;
      }
      else {
        syslog(4,"IRouterL3.c",0x254,0,"Lost an early response (queue full)!");
      }
      rtr_pkt = NULL;
    }
  }
  return;
}

void pkt_timeout(EventData client_data)
{
  pkt_timeout_id = 0;
  rtr_server = NULL;
  rtr_error = -0x26c;
  EventStop();
  return;
}
