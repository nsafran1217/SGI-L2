/*
 * sys_ctrl/l3/l2/irtr.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/irtr.c
 *
 * The L2's IRouter switch: every packet, from an L1, a network client or
 * the L2 itself, goes through IRouterSendPacket(). A request or response
 * goes to its one target (IRouterSendTargetedPacket()): another L2 or an
 * L3 client over the network, an L1 port, or one of this L2's own tasks.
 * An event goes to every client that asked for its kind, to the other L2s
 * of the system, to this L2's own handlers and, for some L1 events, to the
 * other L1s (IRouterSendBroadcastPacket()).
 */

#include <stdio.h>
#include "l2.h"
#include "irtr.h"
#include "cfg.h"
#include "cmd.h"
#include "l1.h"
#include "lpbk.h"
#include "power.h"
#include "route.h"
#include "smp.h"

#define NO_RECEIVER     IR_ERRNO(IRERR_NO_RECEIVER)
#define LOCAL_RS        0xffff  /* (addr >> 12) & 0xffff: rack and slot all ones, the L2 itself */

/* L2CfgNode.events: the events a client gets */
#define EV_L1_BDR       0x01    /* an L1's IR_L1_BDR task (console output; by partition) */
#define EV_L1_ENV       0x02    /* an L1's IR_L1_ENV task */
#define EV_L2_CFG       0x04    /* an L2's configuration */
#define EV_L2_CONSOLE   0x08    /* an L2's console task, with an opcode */
#define EV_TYPE7        0x10    /* from address type 7 */

#define OP_PURGE        1       /* IR_L1_BDR: drop the client's queued output with this key */
#define OP_CFG_CHANGE   0x66    /* IR_L1_CFG: the configuration changed */

int irtr_debug;                 /* 1 requests, 2 responses, 4 events; 0x10, 0x20, 0x40 routing */

/* an event's first argument: the purge key or partition. (Read even when
 * the packet has no arguments, as the original did.) */
static uintptr_t arg0(IRPacket *pkt)
{
  if (IR_ARG_TYPE(pkt->_argv[0]) == IR_ARG_VALUE)
    return pkt->_argv[0]._val;
  return IRArg(pkt,0);
}

static int forward(L2CfgNode *node, IRPacket *pkt)
{
  pkt->_use_count++;
  return IRouterPacketToRouter(node->client,&l2_id,pkt);
}

static int to_l1(int fd, IRPacket *pkt)
{
  pkt->_use_count++;
  l1_write_packet(fd,pkt);
  return 0;
}

/* a request or response to one of this L2's tasks */
static int to_task(int task, IRPacket *pkt)
{
  L2CfgNode *node;
  void (*handler)(IRPacket *);
  int req = pkt->_clas == IR_REQ;

  switch (task) {
  case IR_L2_CONSOLE:
  case IR_L2_MODEM:
    handler = req ? NULL : smp_process_response;
    break;
  case IR_L2_CMD:
    handler = req ? cmd_process_request : cmd_process_response;
    break;
  case IR_L2_CFG:
    handler = req ? cfg_process_request : cfg_process_response;
    break;
  case IR_L2_LPBK:
    handler = req ? NULL : lpbk_process_response;
    break;
  case IR_L2_APWR:
    handler = req ? NULL : power_process_response;
    break;
  case IR_L2_CMDUSR:
    handler = req ? NULL : cmd_process_response_usr;
    break;
  case IR_L2_ROUTE:
    handler = req ? NULL : route_process_response;
    break;
  default:
    /* a client that registered as this task of the L2 */
    node = L2CfgMFindNode(&L2CfgLocal,0,(task & 0x1f) | 0x1ffff000,NULL);
    return node != NULL ? forward(node,pkt) : NO_RECEIVER;
  }
  if (handler == NULL)
    return NO_RECEIVER;
  pkt->_use_count++;
  handler(pkt);
  return 0;
}

int IRouterSendTargetedPacket(IRIdent *id, IRPacket *pkt)
{
  IRAddress dest = pkt->_dest;
  IRAddress src = pkt->_src;
  int type = IR_ADDR_TYPE(dest);
  L2CfgNode *node = NULL;
  int port = -1;
  int ip;
  int l1;
  int fd;

  if (type == IR_ADDR_IP_OTHER) {
    /* an L3 client: by its address, else by its L2's IP address */
    node = L2CfgMFindNode(&L2CfgLocal,0,dest,NULL);
    if (node == NULL)
      node = L2CfgMFindNode(&L2CfgLocal,IR_ADDR_TO_IP(dest),0,NULL);
    if (node == NULL)
      return NO_RECEIVER;
    if ((L2Cfg *)node != &L2CfgLocal)
      return forward(node,pkt);
    if (pkt->_clas != IR_RSP)
      return NO_RECEIVER;
    pkt->_use_count++;
    smp_process_response(pkt);
    return 0;
  }
  if (IR_ADDR_TASK(dest) == IR_L2_ROUTE || IR_ADDR_TASK(dest) == IR_L1_ROUTE)
    route_process(pkt);
  if (type == IR_ADDR_IP) {
    /* another L2; one this L2 does not know goes to its primary, if any */
    node = L2CfgMFindNode(&L2CfgLocal,IR_ADDR_TO_IP(dest),0,NULL);
    if (node == NULL) {
      if (L2CfgMFindNodeLocal(&L2CfgLocal,IR_ADDR_TO_IP(dest)) == NULL) {
        node = L2CfgLocal.net.msnode;
        if (node == NULL)
          return NO_RECEIVER;
      }
    }
    if (node != NULL && (L2Cfg *)node != &L2CfgLocal)
      return forward(node,pkt);
  }
  /* a secondary L2 passes its L1s' IR_L1_BDR packets for "this L2" to
   * the primary */
  if (IR_ADDR_TASK(src) == IR_L1_BDR && L2CfgLocal.net.msmode == 1 &&
      ((dest >> 12) & 0xffff) == LOCAL_RS && type == IR_ADDR_L2 && L2CfgLocal.net.msip != 0) {
    node = L2CfgMFindNode(&L2CfgLocal,L2CfgLocal.net.msip,0,NULL);
    if (node != NULL)
      return forward(node,pkt);
  }
  if (type != IR_ADDR_IP && ((dest >> 12) & 0xffff) != LOCAL_RS) {
    /* a rack and slot: the brick's L1 port, here or at its L2 */
    if (L2CfgMFindBrickIP(&L2CfgLocal,IR_ADDR_RACK(dest),IR_ADDR_SLOT(dest),&ip,&port,&l1) == -1) {
      if (L2CfgLocal.net.msmode != 1)
        return NO_RECEIVER;
      ip = L2CfgLocal.net.msip;
    }
    if ((uint32)ip != L2CfgLocal.net.ip_addr) {
      node = L2CfgMFindNode(&L2CfgLocal,ip,0,NULL);
      if (node != NULL)
        return forward(node,pkt);
      fprintf(stderr,"NR remote!\n");
      return NO_RECEIVER;
    }
    if (type == IR_ADDR_L2) {
      fprintf(stderr,"NR R.S+IR_L2!\n");
      return NO_RECEIVER;
    }
    if (port < 0 || port >= L2_L1_PORTS)
      return NO_RECEIVER;       /* (the original used the port unset) */
    return to_l1(l2_l1_ports[port].fd,pkt);
  }
  switch (type) {
  case IR_ADDR_L1:
  case IR_ADDR_C:
  case IR_ADDR_I:
  case IR_ADDR_CI:
    /* "the L1 on the link": only with a single L1 port */
    if (L2CfgLocal.port_count > 1)
      return NO_RECEIVER;
    for (fd = -1, port = 0; fd == -1 && port < L2_L1_PORTS; port++)
      fd = l2_l1_ports[port].fd;
    if (fd == -1)
      return NO_RECEIVER;
    return to_l1(fd,pkt);
  case IR_ADDR_L2:
  case IR_ADDR_IP:
    return to_task(IR_ADDR_TASK(dest),pkt);
  default:
    return NO_RECEIVER;
  }
}

/* whether a client (an L2 client or L3 tool) gets an event from a source
 * of type and task; a console purge is done instead */
static int client_wants(L2CfgNode *node, IRPacket *pkt, int type, int task)
{
  switch (type) {
  case IR_ADDR_L2:
  case IR_ADDR_IP:
    if (task == IR_L2_CONSOLE)
      return pkt->_opcode == 0 || (node->events & EV_L2_CONSOLE);
    if (task == IR_L2_CFG)
      return (node->events & EV_L2_CFG) != 0;
    return 1;
  case IR_ADDR_L1:
    if (task == IR_L1_ENV)
      return (node->events & EV_L1_ENV) != 0;
    if (task != IR_L1_BDR)
      return 0;
    if (pkt->_opcode == OP_PURGE) {
      RouterPurge(node->client,NULL,(void *)arg0(pkt));
      return 0;
    }
    return (node->events & EV_L1_BDR) != 0;
  case 7:
    return (node->events & EV_TYPE7) != 0;
  default:
    return 0;
  }
}

/* whether another L2 of the system gets it */
static int peer_wants(L2CfgNode *node, IRPacket *pkt, int type, int task)
{
  unsigned int part;

  switch (type) {
  case IR_ADDR_L2:
  case IR_ADDR_IP:
    return task != IR_L2_CONSOLE || pkt->_opcode == 0 || (node->events & EV_L2_CONSOLE);
  case 7:
    return (node->events & EV_TYPE7) != 0;
  case IR_ADDR_L1:
    if (task == IR_L1_BDR) {
      if (pkt->_opcode == OP_PURGE) {
        RouterPurge(node->client,NULL,(void *)arg0(pkt));
        return 0;
      }
      if (!(node->events & EV_L1_BDR))
        return 0;
      /* the partition (0: all); (the original indexed pselect with any) */
      part = arg0(pkt);
      return part == 0 || (part < sizeof(node->pselect) && node->pselect[part]);
    }
    return task != IR_L1_CFG || pkt->_opcode == OP_CFG_CHANGE;
  default:
    return 1;
  }
}

/* whether a brick on this L2 is at the event's source */
static int port_has_source(int port, IRAddress src)
{
  L2CfgPort *p = &L2CfgLocal.port_list[port];
  int rack;
  int slot;
  int l1;

  for (l1 = 0; l1 < p->l1count; l1++) {
    if (!p->l1cfg[l1].configured)
      continue;
    rack = p->l1cfg[l1].rack;
    slot = p->l1cfg[l1].slot;
    if (irtr_debug & 0x10)
      fprintf(stderr,"%d.%d %d.%d\n",rack,slot,IR_ADDR_RACK(src),IR_ADDR_SLOT(src));
    if (rack == IR_ADDR_RACK(src) && slot == IR_ADDR_SLOT(src))
      return 1;
  }
  return 0;
}

int IRouterSendBroadcastPacket(IRIdent *id, IRPacket *pkt)
{
  IRAddress src = pkt->_src;
  int type = IR_ADDR_TYPE(src);
  int task = IR_ADDR_TASK(src);
  L2CfgNode *snode = NULL;      /* a secondary L2 whose L1's event this is */
  L2CfgNode *node;
  char x[80];
  int local;
  int to_l1s;
  int port;
  int fd;
  int nl;

  pkt->_use_count++;
  if (type == IR_ADDR_IP || type == IR_ADDR_IP_OTHER) {
    node = L2CfgMFindNode(&L2CfgLocal,IR_ADDR_TO_IP(src),0,NULL);
    local = node != NULL && (L2Cfg *)node == &L2CfgLocal;
  }
  else {
    local = !pkt->_external;
    if (type == IR_ADDR_L1) {
      node = L2CfgMFindBrickL2(&L2CfgLocal,IR_ADDR_RACK(src),IR_ADDR_SLOT(src));
      if (node != NULL && L2CfgLocal.net.msmode == 2 && node->msmode == 1)
        snode = node;
    }
  }
  /* the clients: L2 clients, then L3 tools */
  for (nl = 0; nl < 2; nl++) {
    for (node = nl == 0 ? L2CfgLocal.l2_clients : L2CfgLocal.l3_clients; node != NULL; node = node->next) {
      if (node->client == NULL || node->events == 0 || !client_wants(node,pkt,type,task) ||
          node->ir_addr == src)
        continue;
      if (irtr_debug & 0x40) {
        IRFmtPkt("L2",pkt,x);
        fprintf(stderr,"%s\n",x);
      }
      forward(node,pkt);
    }
  }
  /* the other L2s, for events from here (or a secondary's L1s, to the
   * other L2s than that one) */
  if (local || snode != NULL) {
    for (node = L2CfgLocal.net.next; node != NULL; node = node->next) {
      if ((snode != NULL && node->msmode == 1 && node == snode) ||
          (node->msmode == 1 && type == IR_ADDR_L1 && task == IR_L1_BDR) ||
          node->client == NULL || node->events == 0 || !peer_wants(node,pkt,type,task) ||
          node->ir_addr == src)
        continue;
      forward(node,pkt);
    }
  }
  /* this L2's own handlers */
  if (type == IR_ADDR_L1) {
    if (task == IR_L1_ENV || task == IR_L1_IROUTER || task == IR_L1_BDR)
      smp_process_event(pkt);
    else if (task == IR_L1_CFG)
      cfg_process_event(pkt);
  }
  else if (type == IR_ADDR_L2 || type == IR_ADDR_IP) {
    if (task == IR_L2_CONSOLE && !local)
      smp_process_event(pkt);
    else if (task == IR_L2_CFG && !local)
      cfg_process_event(pkt);
  }
  /* L1 environment and configuration events also go to the L1s on the
   * other ports */
  to_l1s = type == IR_ADDR_L1 && (task == IR_L1_ENV ||
                                  (task == IR_L1_CFG && pkt->_opcode == OP_CFG_CHANGE));
  for (port = 0; to_l1s && port < L2CFG_PORTS; port++) {
    if (L2CfgLocal.port_list[port].state != L2CFG_PORT_CONFIGURED)
      continue;
    fd = l2_l1_ports[port].fd;
    if (fd == -1 || port_has_source(port,src))
      continue;
    if (irtr_debug & 0x10) {
      IRFmtPkt("L2 Write",pkt,x);
      fprintf(stderr,"%s\n",x);
    }
    to_l1(fd,pkt);
  }
  pkt->_use_count--;
  return 0;
}

/* an event to the clients only (L2 clients, then L3 tools) */
int IRouterSendBroadcastPacketToClients(IRIdent *id, IRPacket *pkt)
{
  IRAddress src = pkt->_src;
  int type = IR_ADDR_TYPE(src);
  int task = IR_ADDR_TASK(src);
  L2CfgNode *node;
  char x[80];
  int wants;
  int nl;

  pkt->_use_count++;
  for (nl = 0; nl < 2; nl++) {
    for (node = nl == 0 ? L2CfgLocal.l2_clients : L2CfgLocal.l3_clients; node != NULL; node = node->next) {
      if (node->client == NULL || node->events == 0)
        continue;
      switch (type) {
      case IR_ADDR_L2:
      case IR_ADDR_IP:
        wants = task != IR_L2_CFG || (node->events & EV_L2_CFG);
        break;
      case IR_ADDR_L1:
        wants = task == IR_L1_ENV ? node->events & EV_L1_ENV
              : task == IR_L1_BDR ? node->events & EV_L1_BDR : 0;
        break;
      default:
        wants = 0;
      }
      if (!wants || node->ir_addr == src)
        continue;
      if (irtr_debug & 0x20) {
        IRFmtPkt("L2",pkt,x);
        fprintf(stderr,"%s\n",x);
      }
      forward(node,pkt);
    }
  }
  pkt->_use_count--;
  return 0;
}

/* route a packet; a request that can't be delivered is answered with the
 * error. The packet is freed (one use). */
int IRouterSendPacket(IRIdent *id, IRPacket *pkt)
{
  IRPacket *rpkt;
  char x[80];
  int rval;

  if (irtr_debug != 0 && (unsigned int)pkt->_clas <= IR_EVT &&
      (irtr_debug & (1 << pkt->_clas))) {
    IRFmtPkt("L2",pkt,x);
    fprintf(stderr,"%s\n",x);
  }
  if (pkt->_clas == IR_REQ || pkt->_clas == IR_RSP)
    rval = IRouterSendTargetedPacket(id,pkt);
  else if (pkt->_clas == IR_EVT)
    rval = IRouterSendBroadcastPacket(id,pkt);
  else
    rval = IR_ERRNO(IRERR_BAD_PKT_TYPE);
  if (rval != 0) {
    if (rval == NO_RECEIVER) {
      IRFmtPkt("NO RECEIVER",pkt,x);
      fprintf(stderr,"%s\n",x);
    }
    if (pkt->_clas == IR_REQ) {
      rpkt = IRouterMakePacket(id != NULL ? id : &l2_id,&pkt->_src,pkt->_pdata_auth >> 3,
                               pkt->_opcode,IR_RSP,pkt->_rev,0,NULL);
      if (rpkt == NULL) {
        IRouterFreePacket(pkt);
        return rval;
      }
      rpkt->_err = -rval % 100;
      rpkt->_seqnum0 = pkt->_seqnum0;
      rpkt->_seqnum1 = pkt->_seqnum1;
      IRouterSendTargetedPacket(&l2_id,rpkt);
    }
  }
  IRouterFreePacket(pkt);
  return rval;
}
