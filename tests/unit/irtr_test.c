/*
 * Equivalence test of the L2's packet switch (l3/l2/irtr.c) against the main
 * branch's reconstruction (Orig*): random requests, responses and events
 * from and to L1s, L2s and L3 clients go through IRouterSendPacket() on
 * random configurations (clients and the events they want, other L2s and
 * their partitions, primary/secondary mode, L1 ports). Every delivery,
 * forward, L1 write, purge and error response must match. irtr_test.sh
 * builds it under ASan; everything irtr.c calls is a stub.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "irtr.h"
#include "orig_irtr.h"

L2Cfg L2CfgLocal;
L2L1Port l2_l1_ports[L2_L1_PORTS];
IRIdent l2_id;
int IRByteOrder;
static int side;
static char log_[2][1 << 15];
static unsigned int seed = 1;

static unsigned int rnd(unsigned int n)
{
  seed = seed * 1103515245 + 12345;
  return (seed >> 8) % n;
}

static void note(const char *fmt, ...)
{
  size_t len = strlen(log_[side]);
  va_list ap;

  va_start(ap,fmt);
  if (len < sizeof(log_[0]) - 200)
    vsnprintf(log_[side] + len,sizeof(log_[0]) - len,fmt,ap);
  va_end(ap);
}

/* --- the configuration --- */
#define LOCAL_IP 0x0a01020a     /* (as stored: network order, any value) */
#define NPEERS   3
#define NCLIENTS 6
static L2Cfg peers[NPEERS];
static L2CfgNode clients[NCLIENTS];
static L2CfgL1 l1cfg[L2CFG_PORTS][3];
static L2CfgNode *peer_by_rack[4];

static uint32 peer_ip(int i) { return 0x0b000000 + i; }

static void make_config(void)
{
  int i, p, l;

  memset(&L2CfgLocal,0,sizeof(L2CfgLocal));
  L2CfgLocal.net.ip_addr = LOCAL_IP;
  L2CfgLocal.net.msmode = rnd(3);
  L2CfgLocal.net.msip = rnd(3) == 0 ? 0 : rnd(2) ? peer_ip(rnd(NPEERS)) : 0x0c000001;
  L2CfgLocal.net.msnode = rnd(2) ? &peers[rnd(NPEERS)].net : NULL;
  L2CfgLocal.port_count = rnd(3);
  for (i = 0; i < NPEERS; i++) {
    memset(&peers[i],0,sizeof(peers[i]));
    peers[i].net.ip_addr = peer_ip(i);
    peers[i].net.ir_addr = 0x80000000 | i;
    peers[i].net.client = rnd(5) ? (RouterClient *)(uintptr_t)(0x100 + i) : NULL;
    peers[i].net.events = rnd(4) ? rnd(0x20) : 0;
    peers[i].net.msmode = rnd(3);
    for (p = 0; p < 256; p++)
      peers[i].net.pselect[p] = rnd(3) == 0;
    peers[i].net.next = i + 1 < NPEERS ? &peers[i + 1].net : NULL;
  }
  L2CfgLocal.net.next = rnd(4) ? &peers[0].net : NULL;
  L2CfgLocal.l2_clients = L2CfgLocal.l3_clients = NULL;
  for (i = 0; i < NCLIENTS; i++) {
    memset(&clients[i],0,sizeof(clients[i]));
    clients[i].client = rnd(6) ? (RouterClient *)(uintptr_t)(0x200 + i) : NULL;
    clients[i].events = rnd(5) ? rnd(0x20) : 0;
    clients[i].ir_addr = 0xc0000000 | i << 24 | (LOCAL_IP >> 8);
    if (rnd(2)) {
      clients[i].next = L2CfgLocal.l2_clients;
      L2CfgLocal.l2_clients = &clients[i];
    }
    else {
      clients[i].next = L2CfgLocal.l3_clients;
      L2CfgLocal.l3_clients = &clients[i];
    }
  }
  for (p = 0; p < L2CFG_PORTS; p++) {
    L2CfgLocal.port_list[p].state = rnd(4) == 0 ? rnd(3) : 0;
    L2CfgLocal.port_list[p].l1count = rnd(3);
    L2CfgLocal.port_list[p].l1cfg = l1cfg[p];
    for (l = 0; l < 3; l++) {
      l1cfg[p][l].configured = rnd(3) != 0;
      l1cfg[p][l].rack = rnd(3);
      l1cfg[p][l].slot = rnd(4);
    }
    l2_l1_ports[p].fd = rnd(5) == 0 ? 10 + p : -1;
  }
  for (i = 0; i < 4; i++)
    peer_by_rack[i] = rnd(2) ? &peers[rnd(NPEERS)].net : NULL;
}

/* --- stubs --- */
L2CfgNode *L2CfgMFindNode(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  L2CfgNode *n;
  int i;

  if (ir_addr != 0) {
    for (i = 0; i < NCLIENTS; i++)
      if (clients[i].ir_addr == ir_addr)
        return &clients[i];
    return (ir_addr & 0x1ffff000) == 0x1ffff000 && (ir_addr & 3) == 1 ? &clients[0] : NULL;
  }
  if (ip_addr == L2CfgLocal.net.ip_addr || (ip_addr & 0xffffff) == (htonl(LOCAL_IP) & 0xffffff))
    return &L2CfgLocal.net;
  for (n = L2CfgLocal.net.next; n != NULL; n = n->next)
    if (n->ip_addr == ip_addr || (ntohl(ip_addr) & 0xffffff) == (ntohl(n->ip_addr) & 0xffffff))
      return n;
  return NULL;
}

L2CfgNode *L2CfgMFindNodeLocal(L2Cfg *head, uint32 ip_addr)
{
  return ip_addr & 0x100 ? &L2CfgLocal.net : NULL;
}

int L2CfgMFindBrickIP(L2Cfg *head, int rack, int slot, int *ip, int *p, int *l)
{
  if (rack >= 3 || slot >= 8)
    return -1;
  *ip = rack == 0 ? LOCAL_IP : rack == 1 ? peer_ip(slot % NPEERS) : 0x0d000000;
  *p = (slot * 7) % L2_L1_PORTS;
  *l = 0;
  return 0;
}

L2CfgNode *L2CfgMFindBrickL2(L2Cfg *head, int rack, int slot)
{
  return rack < 4 ? peer_by_rack[rack] : NULL;
}

static void drop(IRPacket *pkt)
{
  if (pkt->_use_count == 0)
    note("double free\n");
  else if (--pkt->_use_count == 0)
    free(pkt);
}

int IRouterFreePacket(IRPacket *pkt)
{
  drop(pkt);
  return 0;
}

static void got(const char *who, IRPacket *pkt)
{
  note("%s clas %d err %d src %08x dest %08x op %d\n",who,pkt->_clas,pkt->_err,pkt->_src,
       pkt->_dest,pkt->_opcode);
}

int IRouterPacketToRouter(RouterClient *client, IRIdent *id, IRPacket *pkt)
{
  note("router %lx: ",(unsigned long)(uintptr_t)client);
  got("",pkt);
  drop(pkt);
  return 3;
}

#define HANDLER(name) void name(IRPacket *p) { got(#name,p); drop(p); }
HANDLER(smp_process_response)
HANDLER(cmd_process_request)
HANDLER(cmd_process_response)
HANDLER(cmd_process_response_usr)
HANDLER(cfg_process_request)
HANDLER(cfg_process_response)
HANDLER(lpbk_process_response)
HANDLER(power_process_response)
HANDLER(route_process_response)
void smp_process_event(IRPacket *p) { got("smp_process_event",p); }
void cfg_process_event(IRPacket *p) { got("cfg_process_event",p); }
void route_process(IRPacket *p) { got("route_process",p); }

void l1_write_packet(int fd, IRPacket *pkt)
{
  note("l1 fd %d: ",fd);
  got("",pkt);
  drop(pkt);
}

void RouterPurge(RouterClient *client, int (*purge_cb)(), void *purge_data)
{
  note("purge %lx %lx\n",(unsigned long)(uintptr_t)client,(unsigned long)(uintptr_t)purge_data);
}

char *IRFmtPkt(char *who, IRPacket *p, char *bptr)
{
  note("fmt %s\n",who);
  strcpy(bptr,who);
  return bptr;
}

IRPacket *IRouterMakePacket(IRIdent *id, IRAddress *toaddr, int pdata, int opcode, int clas,
                            int prev, int argcount, IRArgument *arglist)
{
  IRPacket *p = calloc(1,sizeof(IRPacket) + 4 * sizeof(IRArgument));

  note("make id %lx to %08x pdata %d op %d clas %d rev %d\n",
       (unsigned long)(id == &l2_id ? 1 : 2),*toaddr,pdata,opcode,clas,prev);
  p->_use_count = 1;
  p->_dest = *toaddr;
  p->_src = id->addr;
  p->_opcode = opcode;
  p->_clas = clas;
  p->_rev = prev;
  return p;
}

uintptr_t IRArg(IRPacket *pkt, int arg)
{
  return arg < pkt->_argc ? pkt->_argv[arg]._val : 0;
}

/* --- the test --- */
static IRAddress random_addr(void)
{
  switch (rnd(7)) {
  case 0:       /* an L1 (or C, I, ... brick), perhaps one of ours */
    return IR_ADDR_MAKE(rnd(2) ? IR_ADDR_L1 : rnd(8),rnd(4),rnd(9),rnd(3),rnd(25));
  case 1:       /* this or another L2, by rack and slot or "this L2" */
    return rnd(2) ? IR_ADDR_MAKE(IR_ADDR_L2,0x3ff,0x3f,0,rnd(16))
                  : IR_ADDR_MAKE(IR_ADDR_L2,rnd(4),rnd(9),0,rnd(16));
  case 2:       /* an L2 by IP: this one, a peer, an unknown one */
    return 0x80000000 | rnd(64) << 24 |
           (rnd(3) == 0 ? ntohl(LOCAL_IP) : rnd(2) ? ntohl(peer_ip(rnd(NPEERS))) : rnd(0x1000000)) & 0xffffff;
  case 3:       /* an L3 client: known, of this L2 or a peer, or unknown */
    switch (rnd(4)) {
    case 0: return clients[rnd(NCLIENTS)].ir_addr;
    case 1: return 0xc0000000 | rnd(64) << 24 | (ntohl(LOCAL_IP) & 0xffffff);
    case 2: return 0xc0000000 | rnd(64) << 24 | (ntohl(peer_ip(rnd(NPEERS))) & 0xffffff);
    default: return 0xc0000000 | rnd(0x40000000);
    }
  case 4:
    return IR_ADDR_MAKE(IR_ADDR_L1,rnd(3),rnd(4),0,rnd(2) ? IR_L1_BDR : IR_L1_ENV);
  case 5:
    return IR_ADDR_MAKE(IR_ADDR_L1,0x3ff,0x3f,0,rnd(25));
  default:
    return seed;
  }
}

int main(void)
{
  static const int opcodes[] = { 0, 1, 0x66, 5 };
  int trial;
  int ret[2];

  IRByteOrder = htonl(1) == 1 ? 1 : 2;
  l2_id.addr = 0x80000000 | (ntohl(LOCAL_IP) & 0xffffff);
  for (trial = 0; trial < 200000; trial++) {
    IRAddress src, dest;
    int clas, op, ext, argc, rev, pdata;
    uint32 arg0;
    IRIdent *idp;
    int to_clients;

    if (trial % 25 == 0)
      make_config();
    src = random_addr();
    dest = random_addr();
    clas = rnd(8) == 0 ? 3 : rnd(3);
    op = opcodes[rnd(4)];
    ext = rnd(2);
    argc = rnd(3);
    arg0 = rnd(3) ? rnd(4) : rnd(256);  /* (the original reads past pselect[] for more) */
    rev = rnd(3);
    pdata = rnd(4);
    irtr_debug = Origirtr_debug = rnd(10) == 0 ? rnd(0x80) : 0;
    idp = rnd(2) ? NULL : &l2_id;
    to_clients = rnd(8) == 0;
    for (side = 0; side < 2; side++) {
      IRPacket *p = calloc(1,sizeof(IRPacket) + 4 * sizeof(IRArgument));
      p->_use_count = 1;
      p->_src = src;
      p->_dest = dest;
      p->_clas = clas;
      p->_opcode = op;
      p->_external = ext;
      p->_argc = argc;
      p->_rev = rev;
      p->_pdata_auth = pdata << 3;
      p->_argv[0]._val = arg0;
      p->_seqnum0 = trial;
      if (to_clients) {         /* (an event to the clients only) */
        p->_use_count++;
        ret[side] = side == 0 ? OrigIRouterSendBroadcastPacketToClients(idp,p)
                              : IRouterSendBroadcastPacketToClients(idp,p);
        drop(p);
        drop(p);
      }
      else
        ret[side] = side == 0 ? OrigIRouterSendPacket(idp,p) : IRouterSendPacket(idp,p);
    }
    if (ret[0] != ret[1] || strcmp(log_[0],log_[1]) != 0) {
      printf("FAIL  irtr: trial %d src %08x dest %08x clas %d op %d: %d vs %d\n"
             "--- orig\n%s--- new\n%s",trial,src,dest,clas,op,ret[0],ret[1],log_[0],log_[1]);
      return 1;
    }
    log_[0][0] = log_[1][0] = '\0';
  }
  printf("PASS  irtr: %d packets routed as the original\n",trial);
  return 0;
}
