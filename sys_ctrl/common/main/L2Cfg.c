/*
 * sys_ctrl/common/main/L2Cfg.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/main/L2Cfg.c
 */

#include <stdlib.h>
#include "../../l3/l2/l2.h"   /* needed by the reconstruction */
#include "../../l3/l2/smp.h"   /* needed by the reconstruction */
#include "../../l3/sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <time.h>
#include <netinet/in.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "L2Cfg.h"
#include "../Router/Socket.h"
#include "../../l3/main/nvram.h"
#include "../sys/syslog.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

struct __anon_struct_50 {
    int state;
    int rack;
    int slot;
    int type;
    int attached_iirack;
    int attached_iislot;
    int attached_iitype;
    int attached_iiport;
    int attached_nnrack;
    int attached_nnslot;
    int attached_nntype;
    int router_type;
    int xtalk_speed;
    int power_state;
    char brick_sn[12];
    char system_sn[12];
};
struct __anon_struct_49 {
    int state;
    struct __anon_struct_50 l1[4];
};
typedef struct {
    int state;
    int ip;
    struct __anon_struct_49 port[40];
} L2CfgIRouter;
struct list_t {
    int rs;
    int type;
    int part;
    int l2;
};
struct __anon_struct_38 {
    int state;
    int rack;
    int slot;
    int type;
    int attached_iirack;
    int attached_iislot;
    int attached_iitype;
    int attached_iiport;
    int attached_nnrack;
    int attached_nnslot;
    int attached_nntype;
    int router_type;
    int xtalk_speed;
    int power_state;
    char brick_sn[12];
    char system_sn[12];
};
struct __anon_struct_37 {
    int state;
    struct __anon_struct_38 l1[4];
};

static int match_node(L2CfgNode *n, uint32 ip_addr, IRAddress ir_addr, RouterClient *client);
static void format_l1(char *rptr, L2CfgNode *l2node, int port, int l1, int mode);
static void format_l2(char *rptr, L2CfgNode *l2node, L2Cfg *head, int mode, int show_l1);
static int l1l2(L2CfgPort *l2port, int l1, int index, char *cfgp, int size);

int L2CfgDebug;
int L2CfgDebugX;
int L2CfgMode;
static char *cbuf;
static int clen;
static char *cptr;
L2Cfg L2CfgLocal;
static char b0[32];
static char b1[32];
static IRAddress addr0[256];
static IRAddress addr1[256];
static unsigned int rack0[256];
static unsigned int rack1[256];
static unsigned int slot0[256];
static unsigned int slot1[256];

int L2CfgInitLocal(uint32 ip_addr, RouterClient *client)
{
  int iVar1;
  IRAddress ir_addr;
  char *pcVar2;
  uint32 uVar3;
  char *ssn;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"InitLocal(ip %08x, c %08x)\n",ip_addr,client);
  }
  if (L2CfgMode == 0) {
    L2CfgMode = 1;
    ir_addr = ip_addr;
    if (IRByteOrder != 1) {
      ir_addr = ntohl(ip_addr);
    }
    L2CfgInitNode(&L2CfgLocal.net,1,ip_addr,(ir_addr & 0xffffff) | 0x80000000,client);
    L2CfgLocal.rack = nvramGet(1);
    L2CfgLocal.net.msmode = nvramGet(0x1a);
    if ((L2CfgLocal.net.msmode != 0) && (L2CfgLocal.net.msmode < 3)) {
      L2CfgLocal.net.msip = 0;
      L2CfgLocal.net.msnode = NULL;
    }
    pcVar2 = (char *)nvramGet(3);
    strcpy(L2CfgLocal.ssn,pcVar2);
    pcVar2 = (char *)nvramGet(4);
    strcpy(L2CfgLocal.sysname,pcVar2);
    uVar3 = nvramGet(9);
    L2CfgLocal.l2dsp_disabled = uVar3;
    L2CfgLocal.syscon = malloc(0x400);
    memset(L2CfgLocal.syscon,0,0x400);
    iVar1 = 0;
  }
  else {
    syslog(3,"../../common/main/L2Cfg.c",0x67,0,"L2CfgInitLocal:  L2Cfg already initialized!!");
    iVar1 = -1;
  }
  return iVar1;
}

int L2CfgMInitL3(L2Cfg *head, RouterClient *client)
{
  int iVar1;
  IRAddress ir_addr;
  L2CfgSysCon *pLVar2;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"InitL3(cfg %08x, c %08x)\n",head,client);
  }
  if (L2CfgMode == 1) {
    syslog(3,"../../common/main/L2Cfg.c",0xa5,0,
           "L2CfgInitL3:  L2Cfg already initialized in L2 mode!!");
    iVar1 = -1;
  }
  else {
    L2CfgMode = 2;
    if (IRByteOrder == 1) {
      ir_addr = client->addr;
    }
    else {
      ir_addr = ntohl(client->addr);
    }
    L2CfgInitNode(&head->net,1,client->addr,(ir_addr & 0xffffff) | 0x80000000,client);
    pLVar2 = malloc(0x400);
    head->syscon = pLVar2;
    memset(head->syscon,0,0x400);
    iVar1 = 0;
  }
  return iVar1;
}

int L2CfgMAddL2(L2Cfg *head, uint32 ip_addr, uint32 port, RouterClient *client, L2CfgNode **node)
{
  uint32_t uVar1;
  L2CfgNode *newl2;
  uint uVar2;
  L2CfgNode *oldl2;
  IRAddress ir_addr;
  
  ir_addr = 0;
  if (L2CfgDebug != 0) {
    fprintf(stderr,"\n------------------------\nAddL2(cfg %08x, ip %08x, c %08x)\n",head,ip_addr,
            client);
  }
  if (client != NULL) {
    port = client->port;
    ip_addr = client->addr;
  }
  if ((port == IR_PORT_BIAS + 0x232aU) || (port == IR_PORT_BIAS + 0x232cU)) {
    ir_addr = ((head->net).ir_addr & 0xc0ffffff) | (client->process_id & 0x3fU) << 0x18;
  }
  else if (port == IR_PORT_BIAS + 0x2329U) {
    uVar1 = ip_addr;
    if (IRByteOrder != 1) {
      uVar1 = ntohl(ip_addr);
    }
    ir_addr = (uVar1 & 0xffffff) | 0x80000000;
  }
  newl2 = L2CfgInitNode(NULL,1,ip_addr,ir_addr,client);
  if ((port != IR_PORT_BIAS + 0x232aU) && (port != IR_PORT_BIAS + 0x232cU)) goto LAB_08068be0;
  if ((ir_addr & 0x80000000) == 0) {
    uVar2 = ir_addr & 0x1f;
  }
  else {
    uVar2 = ir_addr >> 0x18 & 0x3f;
  }
  if (uVar2 != 8) {
    if (uVar2 < 9) {
      if (uVar2 == 6) {
        newl2->events = 0x16;
      }
      goto LAB_08068be0;
    }
    if (uVar2 != 0xe) goto LAB_08068be0;
  }
  newl2->events = 0;
LAB_08068be0:
  oldl2 = L2CfgMFindL2Node(head,newl2->ip_addr,newl2->ir_addr,NULL);
  if (oldl2 == NULL) {
    if ((port == IR_PORT_BIAS + 0x232aU) || (port == IR_PORT_BIAS + 0x232cU)) {
      newl2->next = head->l2_clients;
      head->l2_clients = newl2;
    }
    else {
      newl2->next = (head->net).next;
      (head->net).next = newl2;
    }
    if (node != NULL) {
      *node = newl2;
    }
  }
  else {
    if (oldl2->client != NULL) {
      free(newl2);
      return -1;
    }
    oldl2->client = newl2->client;
    if (node != NULL) {
      *node = oldl2;
    }
    free(newl2);
  }
  return 0;
}

int L2CfgMAddL3(L2Cfg *head, uint32 ip_addr, RouterClient *client)
{
  IRAddress ir_addr;
  L2CfgNode *newl3;
  L2CfgNode *oldl3;
  int bit;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"AddL3(cfg %08x, ip %08x, c %08x)\n",head,ip_addr,client);
  }
  if (IRByteOrder == 1) {
    ir_addr = (head->net).ip_addr;
  }
  else {
    ir_addr = ntohl((head->net).ip_addr);
  }
  newl3 = L2CfgInitNode(NULL,0,ip_addr,
                        (ir_addr & 0xffffff) | 0xc0000000 | (client->socket & 0x3fU) << 0x18,client);
  newl3->events = 0;
  for (bit = 0; (client->process_id != 0 && (bit < 0x10)); bit = bit + 1) {
    if (true) {
      switch(1 << ((byte)bit & 0x1f) & client->process_id) {
      case 1:
        newl3->events = newl3->events | 1;
        break;
      case 2:
        newl3->events = newl3->events | 2;
        break;
      case 4:
        newl3->events = newl3->events | 4;
        break;
      case 8:
        newl3->events = newl3->events | 8;
        break;
      case 0x10:
        newl3->events = newl3->events | 0x10;
      }
    }
  }
  oldl3 = L2CfgMFindL3Node(head,newl3->ip_addr,0,newl3->client);
  if (oldl3 == NULL) {
    newl3->next = head->l3_clients;
    head->l3_clients = newl3;
  }
  else {
    oldl3->ip_addr = newl3->ip_addr;
    oldl3->ir_addr = newl3->ir_addr;
    oldl3->client = newl3->client;
    free(newl3);
  }
  return 0;
}

int L2CfgMDeleteNode(L2Cfg *head, RouterClient *client)
{
  int iVar1;
  L2CfgNode *l3client;
  L2CfgNode *l2client;
  L2CfgNode *l2;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"DeleteNode(cfg %08x, c %08x)\n",head,client);
  }
  for (l2 = (head->net).next; l2 != NULL; l2 = l2->next) {
    iVar1 = match_node(l2,0,0,client);
    if (iVar1 != 0) {
      L2CfgMDeleteL2Peer(head,l2);
      return 0;
    }
  }
  for (l2client = head->l2_clients; l2client != NULL; l2client = l2client->next) {
    iVar1 = match_node(l2client,0,0,client);
    if (iVar1 != 0) {
      L2CfgDeleteL2Client(&head->l2_clients,l2client);
      return 0;
    }
  }
  l3client = head->l3_clients;
  while( true ) {
    if (l3client == NULL) {
      return 0;
    }
    iVar1 = match_node(l3client,0,0,client);
    if (iVar1 != 0) break;
    l3client = l3client->next;
  }
  L2CfgDeleteL2Client(&head->l3_clients,l3client);
  return 0;
}

L2CfgNode *L2CfgInitNode(L2CfgNode *node, int l2, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  int nsize;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"InitNode(n %08x, l2 %08d, ip %08x, ir %08x, c %08x)\n",node,l2,ip_addr,ir_addr,
            client);
  }
  if (node == NULL) {
    if (l2 == 0) {
      nsize = sizeof(L2CfgNode);
    }
    else {
      nsize = sizeof(L2Cfg);
    }
    node = malloc(nsize);
    if (node == NULL) {
      return NULL;
    }
    memset(node,0,nsize);
  }
  node->ip_addr = ip_addr;
  node->ir_addr = ir_addr;
  node->client = client;
  node->events = 0xffffffe6;
  node->heartbeat = 0xffffffff;
  return node;
}

static int match_node(L2CfgNode *n, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  uint32_t uVar1;
  uint32_t uVar2;
  uint uVar3;
  bool bVar4;
  int match_id_ip;
  int match_node_ip;
  int match;
  
  match = 1;
  if (L2CfgDebug != 0) {
    if (ip_addr != 0) {
      uVar1 = ntohl(ip_addr);
      uVar3 = uVar1 & 0xffffff;
      uVar1 = ntohl(n->ip_addr);
      fprintf(stderr,"checking IP %08x = %08x\n",uVar1 & 0xffffff,uVar3);
      if ((n->client != NULL) && ((n->client->id).ipaddr != 0)) {
        uVar1 = ntohl(ip_addr);
        uVar3 = uVar1 & 0xffffff;
        uVar1 = ntohl((n->client->id).ipaddr);
        fprintf(stderr,"checking client id IP %08x = %08x\n",uVar1 & 0xffffff,uVar3);
      }
    }
    if (ir_addr != 0) {
      fprintf(stderr,"checking IR %08x = %08x\n",n->ir_addr,ir_addr);
    }
    if (client != NULL) {
      fprintf(stderr,"checking C %08x = %08x\n",n->client,client);
    }
  }
  if ((true) && (ip_addr != 0)) {
    uVar1 = ntohl(n->ip_addr);
    uVar2 = ntohl(ip_addr);
    bVar4 = (uVar1 & 0xffffff) != (uVar2 & 0xffffff);
    if (n->client == NULL) {
      if (bVar4) {
        match = 0;
      }
    }
    else if ((bVar4) && (true)) {
      match = 0;
    }
  }
  if (((match != 0) && (ir_addr != 0)) && (n->ir_addr != ir_addr)) {
    match = 0;
  }
  if (((match != 0) && (client != NULL)) && (n->client != client)) {
    match = 0;
  }
  return match;
}

L2CfgNode *L2CfgMFindL2Node(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  int iVar1;
  L2CfgNode *l2;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"FindL2Node(cfg %08x, ip %08x, ir %08x, c %08x)\n",head,ip_addr,ir_addr,client);
  }
  for (l2 = &head->net; l2 != NULL; l2 = l2->next) {
    iVar1 = match_node(l2,ip_addr,ir_addr,client);
    if (iVar1 != 0) {
      return l2;
    }
  }
  l2 = head->l2_clients;
  while( true ) {
    if (l2 == NULL) {
      return NULL;
    }
    iVar1 = match_node(l2,ip_addr,ir_addr,client);
    if (iVar1 != 0) break;
    l2 = l2->next;
  }
  return l2;
}

L2CfgNode *L2CfgMFindL3Node(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  int iVar1;
  L2CfgNode *l3;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"FindL3Node(cfg %08x, ip %08x, ir %08x, c %08x)\n",head,ip_addr,ir_addr,client);
  }
  l3 = head->l3_clients;
  while( true ) {
    if (l3 == NULL) {
      return NULL;
    }
    iVar1 = match_node(l3,ip_addr,ir_addr,client);
    if (iVar1 != 0) break;
    l3 = l3->next;
  }
  return l3;
}

L2CfgNode *L2CfgMFindNodeLocal(L2Cfg *head, uint32 ip_addr)
{
  int iVar1;
  uint32_t uVar2;
  uint32_t uVar3;
  uint32 saddr;
  L2CfgNode *l2;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"FindNodeLocal(cfg %08x, ip %08x)\n",head,ip_addr);
  }
  for (l2 = &head->net; l2 != NULL; l2 = l2->next) {
    if ((l2->client != NULL) &&
       (iVar1 = SocketGetSockAddr(l2->client->socket,&saddr), iVar1 == 0)) {
      uVar2 = ntohl(saddr);
      uVar3 = ntohl(ip_addr);
      if ((uVar2 & 0xffffff) == (uVar3 & 0xffffff)) {
        return l2;
      }
    }
  }
  for (l2 = head->l2_clients; l2 != NULL; l2 = l2->next) {
    if ((l2->client != NULL) &&
       (iVar1 = SocketGetSockAddr(l2->client->socket,&saddr), iVar1 == 0)) {
      uVar2 = ntohl(saddr);
      uVar3 = ntohl(ip_addr);
      if ((uVar2 & 0xffffff) == (uVar3 & 0xffffff)) {
        return l2;
      }
    }
  }
  l2 = head->l3_clients;
  do {
    if (l2 == NULL) {
      return NULL;
    }
    if ((l2->client != NULL) &&
       (iVar1 = SocketGetSockAddr(l2->client->socket,&saddr), iVar1 == 0)) {
      uVar2 = ntohl(saddr);
      uVar3 = ntohl(ip_addr);
      if ((uVar2 & 0xffffff) == (uVar3 & 0xffffff)) {
        return l2;
      }
    }
    l2 = l2->next;
  } while( true );
}

L2CfgNode *L2CfgMFindNode(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  uint uVar1;
  int tsk;
  IRAddress ir_addr_00;
  L2CfgNode *n;
  
  if (L2CfgDebug != 0) {
    fprintf(stderr,"FindNode(cfg %08x, ip %08x, ir %08x, c %08x)\n",head,ip_addr,ir_addr,client);
  }
  n = L2CfgMFindL2Node(head,ip_addr,ir_addr,client);
  if (n == NULL) {
    n = L2CfgMFindL3Node(head,ip_addr,ir_addr,client);
  }
  if (((n == NULL) && (ip_addr == 0)) && (ir_addr >> 0xc == 0x1ffff)) {
    if ((ir_addr & 0x80000000) == 0) {
      tsk = ir_addr & 0x1f;
    }
    else {
      tsk = ir_addr >> 0x18 & 0x3f;
    }
    uVar1 = (head->net).ir_addr;
    if ((uVar1 & 0x80000000) == 0) {
      ir_addr_00 = (uVar1 & 0xffffffe0) | (tsk & 0x1fU);
    }
    else {
      ir_addr_00 = (uVar1 & 0xc0ffffff) | tsk << 0x18;
    }
    n = L2CfgMFindL2Node(head,0,ir_addr_00,client);
    if (n == NULL) {
      n = L2CfgMFindL3Node(head,0,ir_addr_00,client);
    }
  }
  return n;
}

char *L2CfgMFindDevice(L2Cfg *head, int fd)
{
  static char buff[80];
  int port;
  L2CfgNode *l2node;
  
  port = 0;
  while( true ) {
    if (0x27 < port) {
      sprintf((char *)&buff,"descriptor %d not found",fd);
      return (char *)&buff;
    }
    if (head->port_list[port].fd == fd) break;
    port = port + 1;
  }
  if (head->port_list[port].device == NULL) {
    return "unknown";
  }
  return head->port_list[port].device;
}

L2CfgPort *L2CfgMFindPort(L2Cfg *head, int fd)
{
  int port;
  L2CfgNode *l2node;
  
  port = 0;
  while( true ) {
    if (0x27 < port) {
      return NULL;
    }
    if ((head->port_list[port].fd == fd) && (head->port_list[port].state != 0)) break;
    port = port + 1;
  }
  return head->port_list + port;
}

L2CfgPort *L2CfgMGetPort(L2Cfg *head, int port)
{
  L2CfgNode *l2node;
  
  if ((port < 0) || (0x27 < port)) {
    l2node = NULL;
  }
  else {
    l2node = (L2CfgNode *)(head->port_list + port);
  }
  return (L2CfgPort *)l2node;
}

char *L2CfgMDeviceName(L2Cfg *head, int fd)
{
  int iVar1;
  static char buff[80];
  L2CfgPort *l2port;
  char *pcVar2;
  int port;
  IRAddress paddr;
  L2CfgNode *l2node;
  
  l2port = L2CfgMFindPort(head,fd);
  if (l2port == NULL) {
    sprintf((char *)&buff,"[fd %d, not an L1 device]",fd);
    pcVar2 = buff;
  }
  else {
    iVar1 = l2port->state;
    if (iVar1 == 1) {
      sprintf((char *)&buff,"L1 USB device %s [%s]",l2port->device,l2port->usbpath);
      pcVar2 = (char *)&buff;
    }
    else {
      if (iVar1 < 2) {
        if (iVar1 == 0) {
          sprintf((char *)&buff,"[fd %d, unconnected L1]",fd);
          return (char *)&buff;
        }
      }
      else if (iVar1 == 2) {
        pcVar2 = L2CfgMAddrStr(head,((uint)l2port->l1cfg->rack << 6 |
                                    (uint)(l2port->l1cfg->slot & 0x3f)) << 0xc,0);
        sprintf((char *)&buff,"connection to %s",pcVar2);
        return (char *)&buff;
      }
      pcVar2 = "no device";
    }
  }
  return pcVar2;
}

int L2CfgMDeleteL2Peer(L2Cfg *head, L2CfgNode *peer)
{
  struct _L2CfgNode *p_Var1;
  int iVar2;
  L2CfgPort *pptr;
  int port;
  L2CfgNode *node;
  L2CfgNode *next;
  L2CfgNode *prev;
  
  prev = &head->net;
  next = (head->net).next;
  while (next != NULL) {
    if (next == peer) {
      prev->next = next->next;
      p_Var1 = next->next;
      for (port = 0; port < 0x28; port = port + 1) {
        iVar2 = port * 0x1c;
        if (L2CFG_OF(next)->port_list[port].device != NULL) {
          free(L2CFG_OF(next)->port_list[port].device);
        }
        if (L2CFG_OF(next)->port_list[port].usbpath != NULL) {
          free(L2CFG_OF(next)->port_list[port].usbpath);
        }
        if (L2CFG_OF(next)->port_list[port].l1cfg != NULL) {
          free(L2CFG_OF(next)->port_list[port].l1cfg);
        }
      }
      free(next);
      next = p_Var1;
    }
    else {
      prev = next;
      next = next->next;
    }
  }
  if ((peer != NULL) && (L2CfgLocal.net.msnode == peer)) {
    L2CfgLocal.net.msip = 0;
    L2CfgLocal.net.msnode = NULL;
  }
  return 0;
}

int L2CfgDeleteL2Client(L2CfgNode **list, L2CfgNode *client)
{
  L2CfgNode *prev;
  L2CfgNode *next;
  
  next = *list;
  prev = NULL;
  while( true ) {
    if (next == NULL) {
      return 0;
    }
    if (next == client) break;
    prev = next;
    next = next->next;
  }
  if (prev == NULL) {
    *list = next->next;
  }
  else {
    prev->next = next->next;
  }
  free(client);
  return 0;
}

void L2CfgMEventRack(L2Cfg *head)
{
  uint32 uVar1;
  
  uVar1 = nvramGet(1);
  head->rack = uVar1;
  return;
}

void L2CfgMEventSystemSN(L2Cfg *head)
{
  char *__src;
  
  __src = (char *)nvramGet(3);
  strcpy(head->ssn,__src);
  return;
}

void L2CfgMEventSystemName(L2Cfg *head)
{
  char *__src;
  
  __src = (char *)nvramGet(4);
  strcpy(head->sysname,__src);
  return;
}

void L2CfgMEventDisplayDisable(L2Cfg *head)
{
  uint32 uVar1;
  
  uVar1 = nvramGet(9);
  head->l2dsp_disabled = uVar1;
  return;
}

void FmtBrick(char *bptr, int rack, int type, int slot)
{
  char cVar1;
  int iVar2;
  
  iVar2 = slot;
  cVar1 = brickTypeToChar(type);
  sprintf(bptr,"%03d%c%02d",rack,(int)cVar1,iVar2);
  if (rack == 0) {
    memset(bptr,0x2d,3);
  }
  if (slot == 0) {
    memset(bptr + 4,0x2d,2);
  }
  if ((rack == 0) && (slot == 0)) {
    strcat(bptr," (no rack and slot ID set)");
  }
  else if (rack == 0) {
    strcat(bptr," (no rack ID set)");
  }
  else if (slot == 0) {
    strcat(bptr," (no slot ID set)");
  }
  return;
}

static void format_l1(char *rptr, L2CfgNode *l2node, int port, int l1, int mode)
{
  byte bVar1;
  int iVar2;
  char *pcVar3;
  size_t sVar4;
  uint uVar5;
  L2CfgPort *l2port;
  char *sp;
  
  iVar2 = port * 0x1c;
  uVar5 = (uint)L2CFG_OF(l2node)->port_list[port].l1cfg[l1].index;
  pcVar3 = SocketAddrStr(l2node->ip_addr);
  sprintf(rptr,"L1 %s:%d:%d           ",pcVar3,port,uVar5);
  rptr[0x19] = '\0';
  strcat(rptr,"- ");
  sVar4 = strlen(rptr);
  rptr = rptr + sVar4;
  if (0 < l1) {
    strcat(rptr,"");
    sVar4 = strlen(rptr);
    rptr = rptr + sVar4;
  }
  if ((L2CFG_OF(l2node)->port_list[port].l1cfg[l1].configured == '\0') &&
     (L2CFG_OF(l2node)->port_list[port].l1cfg[l1].conn_state == '\x01')) {
    if (l1 == 0) {
      strcat(rptr,"C/R/G brick (USB connection)");
    }
    else {
      strcat(rptr,"C or I/O brick (422 connection)");
    }
    strcat(rptr," not configured\n");
    return;
  }
  FmtBrick(rptr,(uint)L2CFG_OF(l2node)->port_list[port].l1cfg[l1].rack,
           (uint)L2CFG_OF(l2node)->port_list[port].l1cfg[l1].type,
           (uint)L2CFG_OF(l2node)->port_list[port].l1cfg[l1].slot);
  bVar1 = L2CFG_OF(l2node)->port_list[port].l1cfg[l1].type;
  if (bVar1 != 0x44) {
    if (bVar1 < 0x45) {
      if (bVar1 != 0x2d) {
LAB_08069ef0:
        if (L2CFG_OF(l2node)->port_list[port].l1cfg[l1].partition != '\0') {
          uVar5 = (uint)L2CFG_OF(l2node)->port_list[port].l1cfg[l1].partition;
          pcVar3 = ".%-3d";
          sVar4 = strlen(rptr);
          rptr = rptr + sVar4;
          sprintf(rptr,pcVar3,uVar5);
          goto LAB_08069f63;
        }
      }
    }
    else if (bVar1 != 0x52) goto LAB_08069ef0;
  }
  strcat(rptr,"    ");
LAB_08069f63:
  sVar4 = strlen(rptr);
  if (mode == 2) {
    sprintf(rptr + sVar4," %s(%s %s)\n","",
            L2CFG_OF(l2node)->port_list[port].usbpath,
            L2CFG_OF(l2node)->port_list[port].device);
  }
  else {
    strcat(rptr + sVar4,"\n");
  }
  return;
}

static void format_l2(char *rptr, L2CfgNode *l2node, L2Cfg *head, int mode, int show_l1)
{
  char *pcVar1;
  size_t sVar2;
  char *pcVar3;
  L2CfgPort *l2port;
  int iVar4;
  uint32 rackslot;
  int l1cnt;
  int l1list [512];
  L2Cfg *l2;
  int l1slot;
  int l1rack;
  int i;
  int l1;
  int port;
  char ipstr [20];
  char rackstr [32];
  
  l1cnt = 0;
  pcVar1 = SocketAddrStr(l2node->ip_addr);
  strcpy(ipstr,pcVar1);
  if (L2CFG_OF(l2node)->rack == 0) {
    strcpy(rackstr,"---- (no rack ID set)");
  }
  else {
    sprintf(rackstr,"%04d",L2CFG_OF(l2node)->rack);
  }
  if (mode == 2) {
    sprintf(rptr,"L2 %s: - %s (IR %08x, C %08x)",ipstr,rackstr,l2node->ir_addr,l2node->client);
  }
  else {
    sprintf(rptr,"L2 %s: - %s",ipstr,rackstr);
  }
  sVar2 = strlen(rptr);
  pcVar1 = rptr + sVar2;
  if (l2node->msmode == 2) {
    sprintf(pcVar1,"-PRI");
  }
  else if (l2node->msmode == 1) {
    pcVar3 = SocketAddrStr(l2node->msip);
    sprintf(pcVar1,"-SEC (%s)",pcVar3);
  }
  if ((L2Cfg *)l2node == head) {
    strcat(pcVar1," (LOCAL)\n");
  }
  else {
    strcat(pcVar1,"\n");
  }
  sVar2 = strlen(pcVar1);
  rptr = pcVar1 + sVar2;
  if (show_l1 != 0) {
    for (port = 0; port < 0x28; port = port + 1) {
      rackslot = 0;
      if ((L2CFG_OF(l2node)->port_list[port].state != 0) &&
         (L2CFG_OF(l2node)->port_list[port].l1cfg != 0)) {
        if (L2CFG_OF(l2node)->port_list[port].state == 2) {
          rackslot = (uint)L2CFG_OF(l2node)->port_list[port].l1cfg->rack << 0x10 |
                     (uint)L2CFG_OF(l2node)->port_list[port].l1cfg->slot;
        }
        i = 0;
        while ((i < l1cnt &&
               (rackslot <=
                ((uint)L2CFG_OF(l2node)->port_list[l1list[i]].l1cfg->rack << 0x10
                | (uint)L2CFG_OF(l2node)->port_list[l1list[i]].l1cfg->slot)))) {
          i = i + 1;
        }
        if (i != l1cnt) {
          memmove(l1list + i + 1,l1list + i,(l1cnt - i) * 4);
        }
        l1list[i] = port;
        l1cnt = l1cnt + 1;
      }
    }
    for (i = 0; i < l1cnt; i = i + 1) {
      l2port = &L2CFG_OF(l2node)->port_list[l1list[i]];
      if (l2port->state == 2) {
        for (l1 = 0; l1 < l2port->l1count; l1 = l1 + 1) {
          if ((l2port->l1cfg[l1].configured != '\0') || (l2port->l1cfg[l1].conn_state != '\0')) {
            format_l1(rptr,l2node,l1list[i],l1,mode);
            sVar2 = strlen(rptr);
            rptr = rptr + sVar2;
          }
        }
      }
      else {
        iVar4 = l1list[i];
        pcVar1 = SocketAddrStr(l2node->ip_addr);
        sprintf(rptr,"L1 %s:%d              ",pcVar1,iVar4);
        rptr[0x19] = '\0';
        sVar2 = strlen(rptr);
        pcVar1 = rptr + sVar2;
        sprintf(pcVar1,"- USB not configured  (%s %s)\n",l2port->usbpath,l2port->device);
        sVar2 = strlen(pcVar1);
        rptr = pcVar1 + sVar2;
      }
    }
  }
  return;
}

void L2CfgMPrint(L2Cfg *head, char **rrptr, int mode, int show_l1)
{
  L2CfgL1 *l1c;   /* Ghidra kept this element pointer in an int */
  RouterClient *pRVar1;
  char *pcVar2;
  size_t sVar3;
  int iVar4;
  IRAddress IVar5;
  L2CfgL1 *l1cfg;
  int l1;
  L2Cfg *l2;
  int port;
  int ports_configured;
  int ports_connected;
  int noconfig;
  int others;
  int nbricks;
  int gbricks;
  int pebricks;
  int pbricks;
  int xbricks;
  int ibricks;
  int cbricks;
  int rbricks;
  int l1s;
  int l2s;
  char *rptr;
  int count;
  RouterClient *c;
  int i;
  int l2cnt;
  L2CfgNode *l2list [256];
  L2CfgNode *l3client;
  L2CfgNode *l2client;
  L2CfgNode *l2node;
  char tmp [8];
  char found [4096];
  
  l2cnt = 0;
  *rrptr = NULL;
  if (mode == 0) {
    l2s = 0;
    l1s = 0;
    rbricks = 0;
    cbricks = 0;
    ibricks = 0;
    xbricks = 0;
    pbricks = 0;
    pebricks = 0;
    gbricks = 0;
    nbricks = 0;
    others = 0;
    noconfig = 0;
    ports_connected = 0;
    ports_configured = 0;
    found[0] = '\0';
    for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
      l2s = l2s + 1;
      for (port = 0; port < 0x28; port = port + 1) {
        if ((L2CFG_OF(l2node)->port_list[port].state != 0) &&
           (ports_connected = ports_connected + 1,
           L2CFG_OF(l2node)->port_list[port].state == 2)) {
          ports_configured = ports_configured + 1;
          for (l1 = 0; l1 < L2CFG_OF(l2node)->port_list[port].l1count; l1 = l1 + 1) {
            l1c = &L2CFG_OF(l2node)->port_list[port].l1cfg[l1];
            if ((l1c->configured == '\0') && (l1c->conn_state == '\0'))
            goto LAB_0806a7f0;
            sVar3 = strlen(l1c->brick_sn);
            if (sVar3 != 0) {
              pcVar2 = strstr(found,l1c->brick_sn);
              if (pcVar2 != NULL) goto LAB_0806a7f0;
              sVar3 = strlen(found);
              if (sVar3 + 7 < 0x1000) {
                strcat(found,l1c->brick_sn);
                strcat(found,",");
              }
            }
            l1s = l1s + 1;
            if (false) {
switchD_0806a788_caseD_26:
              if (l1c->configured == '\0') {
                noconfig = noconfig + 1;
              }
              else {
                others = others + 1;
              }
            }
            else {
              switch(l1c->type) {
              case 0x23:
              case 0x4a:
              case 0x50:
                pbricks = pbricks + 1;
                break;
              case 0x24:
              case 0x2c:
              case 0x2e:
              case 0x30:
              case 0x33:
              case 0x34:
              case 0x35:
              case 0x36:
              case 0x37:
              case 0x38:
              case 0x39:
              case 0x40:
              case 0x41:
              case 0x42:
              case 0x43:
              case 0x46:
              case 0x4c:
              case 0x4d:
              case 0x4f:
              case 0x51:
              case 0x7b:
              case 0x7d:
                cbricks = cbricks + 1;
                break;
              case 0x25:
                pebricks = pebricks + 1;
                break;
              default:
                goto switchD_0806a788_caseD_26;
              case 0x2d:
              case 0x44:
              case 0x52:
                rbricks = rbricks + 1;
                break;
              case 0x3d:
              case 0x49:
              case 0x4b:
                ibricks = ibricks + 1;
                break;
              case 0x47:
                gbricks = gbricks + 1;
                break;
              case 0x4e:
                nbricks = nbricks + 1;
                break;
              case 0x58:
                xbricks = xbricks + 1;
              }
            }
LAB_0806a7f0:
          }
        }
      }
    }
    pcVar2 = malloc(800);
    *rrptr = pcVar2;
    if (pcVar2 != NULL) {
      *pcVar2 = '\0';
      sprintf(pcVar2,"L2s: %d\n",l2s);
      sVar3 = strlen(pcVar2);
      pcVar2 = pcVar2 + sVar3;
      sprintf(pcVar2,"L1s: %d",l1s);
      sVar3 = strlen(pcVar2);
      pcVar2 = pcVar2 + sVar3;
      if (ports_configured == ports_connected) {
        strcpy(pcVar2,"\n");
      }
      else {
        sprintf(pcVar2,"  (%d USB connections not configured)\n",ports_connected - ports_configured)
        ;
      }
      sVar3 = strlen(pcVar2);
      rptr = pcVar2 + sVar3;
      if (noconfig != 0) {
        sprintf(rptr,"  BRICKS NOT CONFIGURED: %d\n",noconfig);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (rbricks != 0) {
        sprintf(rptr,"  R Bricks: %d\n",rbricks);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (cbricks != 0) {
        sprintf(rptr,"  C Bricks: %d\n",cbricks);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (ibricks != 0) {
        sprintf(rptr,"  I Bricks: %d\n",ibricks);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (xbricks != 0) {
        sprintf(rptr,"  X Bricks: %d\n",xbricks);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (pbricks != 0) {
        sprintf(rptr,"  P Bricks: %d\n",pbricks);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (pebricks != 0) {
        sprintf(rptr,"  PE Bricks: %d\n",pebricks);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (gbricks != 0) {
        sprintf(rptr,"  G Bricks: %d\n",gbricks);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (nbricks != 0) {
        sprintf(rptr,"  N Bricks: %d\n",nbricks);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (others != 0) {
        sprintf(rptr,"  Other:    %d\n",others);
      }
    }
  }
  else {
    count = 0;
    for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
      count = count + 1;
      for (port = 0; port < 0x28; port = port + 1) {
        if ((L2CFG_OF(l2node)->port_list[port].state != 0) &&
           (L2CFG_OF(l2node)->port_list[port].state == 2)) {
          count = count + L2CFG_OF(l2node)->port_list[port].l1count;
        }
      }
    }
    if (mode == 2) {
      count = count + 2;
      for (l2client = head->l2_clients; l2client != NULL; l2client = l2client->next) {
        count = count + 1;
      }
      for (l3client = head->l3_clients; l3client != NULL; l3client = l3client->next) {
        count = count + 1;
      }
    }
    rptr = malloc(count * 0x4b);
    *rrptr = rptr;
    if (rptr != NULL) {
      *rptr = '\0';
      for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
        l1 = 0;
        while ((l1 < l2cnt && ((int)L2CFG_OF(l2list[l1])->rack <= L2CFG_OF(l2node)->rack))) {
          l1 = l1 + 1;
        }
        if (l1 != l2cnt) {
          memmove(l2list + l1 + 1,l2list + l1,(l2cnt - l1) * sizeof(*l2list));
        }
        l2list[l1] = l2node;
        l2cnt = l2cnt + 1;
      }
      for (i = 0; i < l2cnt; i = i + 1) {
        format_l2(rptr,l2list[i],head,mode,show_l1);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (mode != 1) {
        count = 0;
        for (l2client = head->l2_clients; l2client != NULL; l2client = l2client->next) {
          if (count == 0) {
            strcpy(rptr,"L2 Clients:\n");
            sVar3 = strlen(rptr);
            rptr = rptr + sVar3;
          }
          IVar5 = l2client->ir_addr;
          pcVar2 = SocketAddrStr(l2client->ip_addr);
          sprintf(rptr,"   %s: (IR %0x)",pcVar2,IVar5);
          sVar3 = strlen(rptr);
          pcVar2 = rptr + sVar3;
          pRVar1 = l2client->client;
          if (pRVar1 == NULL) {
            strcat(pcVar2,"\n");
          }
          else {
            sprintf(pcVar2," %s (%s) @ %s running \'%s\'\n",(pRVar1->id).username,
                    (pRVar1->id).fullname,&pRVar1->id,(pRVar1->id).procname);
          }
          sVar3 = strlen(pcVar2);
          rptr = pcVar2 + sVar3;
          count = count + 1;
        }
        count = 0;
        for (l3client = head->l3_clients; l3client != NULL; l3client = l3client->next) {
          if (count == 0) {
            strcpy(rptr,"L3 Clients:\n");
            sVar3 = strlen(rptr);
            rptr = rptr + sVar3;
          }
          IVar5 = l3client->ir_addr;
          pcVar2 = SocketAddrStr(l3client->ip_addr);
          sprintf(rptr,"   %s: (IR %0x)",pcVar2,IVar5);
          sVar3 = strlen(rptr);
          pcVar2 = rptr + sVar3;
          pRVar1 = l3client->client;
          if (pRVar1 == NULL) {
            strcat(pcVar2,"\n");
          }
          else {
            sprintf(pcVar2," %s (%s) @ %s running \'%s\'\n",(pRVar1->id).username,
                    (pRVar1->id).fullname,&pRVar1->id,(pRVar1->id).procname);
          }
          sVar3 = strlen(pcVar2);
          rptr = pcVar2 + sVar3;
          count = count + 1;
        }
      }
    }
  }
  return;
}

void L2CfgMPrintX(L2Cfg *head, char **rrptr)
{
  L2CfgL1 *l1c;   /* Ghidra kept this element pointer in an int */
  char cVar1;
  size_t sVar2;
  int iVar3;
  char *__format;
  int n;
  L2CfgL1 *l1cfg;
  L2Cfg *l2cfg;
  int lcount;
  int lrack;
  int count;
  int col;
  int l1;
  int port;
  L2CfgNode *l2node;
  char *rptr;
  RouterClient *c;
  struct list_t list [1024];
  int rs;
  bool found;
  
  *rrptr = NULL;
  count = 0;
  for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
    for (port = 0; port < 0x28; port = port + 1) {
      if ((L2CFG_OF(l2node)->port_list[port].state != 0) &&
         (L2CFG_OF(l2node)->port_list[port].state == 2)) {
        for (l1 = 0; l1 < L2CFG_OF(l2node)->port_list[port].l1count; l1 = l1 + 1) {
          l1c = &L2CFG_OF(l2node)->port_list[port].l1cfg[l1];
          if ((l1c->configured != '\0') || (l1c->conn_state != '\0')) {
            rs = (uint)l1c->slot + (uint)l1c->rack * 100;
            found = false;
            for (n = 0; (!found && (n < count)); n = n + 1) {
              if (list[n].rs == rs) {
                found = true;
              }
            }
            if (!found) {
              found = false;
              for (n = 0; (!found && (n < count)); n = n + 1) {
                if (list[n].rs < rs) {
                  memmove(list + n + 1,list + n,(count - n) * 0x10);
                  list[n].rs = rs;
                  list[n].type = (uint)l1c->type;
                  list[n].part = (uint)l1c->partition;
                  list[n].l2 = L2CFG_OF(l2node)->rack;
                  found = true;
                }
              }
              if (!found) {
                list[count].rs = rs;
                list[count].type = (uint)l1c->type;
                list[count].part = (uint)l1c->partition;
                list[count].l2 = L2CFG_OF(l2node)->rack;
              }
              count = count + 1;
            }
          }
        }
      }
    }
  }
  rptr = malloc(count * 0x50);
  *rrptr = rptr;
  if (rptr != NULL) {
    *rptr = '\0';
    col = 0;
    for (l1 = 0; l1 < count; l1 = l1 + 1) {
      if (((col != 0) && (list[l1].rs / 100 != lrack)) || (col == 8)) {
        strcat(rptr,"\n");
        sVar2 = strlen(rptr);
        rptr = rptr + sVar2;
        col = 0;
      }
      iVar3 = list[l1].rs % 100;
      cVar1 = brickTypeToChar(list[l1].type);
      sprintf(rptr,"%03d%c%02d",list[l1].rs / 100,(int)cVar1,iVar3);
      if (list[l1].part == 0) {
        strcat(rptr,"   ");
      }
      else {
        iVar3 = list[l1].part;
        __format = ".%-2d";
        sVar2 = strlen(rptr);
        sprintf(rptr + sVar2,__format,iVar3);
      }
      col = col + 1;
      if (col != 8) {
        strcat(rptr," ");
      }
      sVar2 = strlen(rptr);
      rptr = rptr + sVar2;
      lrack = list[l1].rs / 100;
    }
    sprintf(rptr,"\n%d bricks\n",count);
  }
  return;
}

void L2CfgMPrintY(L2Cfg *head, char **rrptr)
{
  L2CfgL1 *l1c;   /* Ghidra kept this element pointer in an int */
  char cVar1;
  size_t sVar2;
  int iVar3;
  int n;
  L2CfgL1 *l1cfg;
  L2Cfg *l2cfg;
  int lcount;
  int lrack;
  int count;
  int l1;
  int port;
  L2CfgNode *l2node;
  char *rptr;
  RouterClient *c;
  uint rsl [1024 * 3];   /* (rack*100+slot, type, partition) per L1; Ghidra split it in two */
  int rs;
  bool found;
  
  *rrptr = NULL;
  count = 0;
  for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
    for (port = 0; port < 0x28; port = port + 1) {
      if ((L2CFG_OF(l2node)->port_list[port].state != 0) &&
         (L2CFG_OF(l2node)->port_list[port].state == 2)) {
        for (l1 = 0; l1 < L2CFG_OF(l2node)->port_list[port].l1count; l1 = l1 + 1) {
          l1c = &L2CFG_OF(l2node)->port_list[port].l1cfg[l1];
          if ((l1c->configured != '\0') || (l1c->conn_state != '\0')) {
            rs = (uint)l1c->slot + (uint)l1c->rack * 100;
            found = false;
            for (n = 0; (!found && (n < count)); n = n + 1) {
              if (rsl[n * 3] == (uint)rs) {
                found = true;
              }
            }
            if (!found) {
              found = false;
              for (n = 0; (!found && (n < count)); n = n + 1) {
                if ((int)rsl[n * 3] < rs) {
                  memmove(rsl + (n + 1) * 3,rsl + n * 3,(count - n) * 3 * sizeof(*rsl));
                  rsl[n * 3] = rs;
                  rsl[n * 3 + 1] = (uint)l1c->type;
                  rsl[n * 3 + 2] = (uint)l1c->partition;
                  found = true;
                }
              }
              if (!found) {
                rsl[count * 3] = rs;
                rsl[count * 3 + 1] = (uint)l1c->type;
                rsl[count * 3 + 2] = (uint)l1c->partition;
              }
              count = count + 1;
            }
          }
        }
      }
    }
  }
  rptr = malloc(count << 4);
  *rrptr = rptr;
  if (rptr != NULL) {
    *rptr = '\0';
    for (l1 = 0; l1 < count; l1 = l1 + 1) {
      iVar3 = (int)rsl[l1 * 3] % 100;
      cVar1 = brickTypeToChar(rsl[l1 * 3 + 1]);
      sprintf(rptr,"%03d%c%02d,",(int)rsl[l1 * 3] / 100,(int)cVar1,iVar3);
      sVar2 = strlen(rptr);
      rptr = rptr + sVar2;
    }
    strcat(rptr,"\n");
  }
  return;
}

int L2CfgMAddPort(L2Cfg *head, int port, char *device, char *usbpath, int conn_type, int conn_fd)
{
  int iVar1;
  size_t sVar2;
  char *pcVar3;
  L2CfgPort *pptr;
  L2CfgNode *l2node;
  
  if (head->port_count < 0x28) {
    head->port_count = head->port_count + 1;
    pptr = head->port_list + port;
    if (pptr->state == 0) {
      pptr->state = 1;
      pptr->type = conn_type;
      pptr->fd = conn_fd;
      if (pptr->device != NULL) {
        free(pptr->device);
      }
      sVar2 = strlen(device);
      pcVar3 = malloc(sVar2 + 1);
      pptr->device = pcVar3;
      strcpy(pptr->device,device);
      if (pptr->usbpath != NULL) {
        free(pptr->usbpath);
      }
      sVar2 = strlen(usbpath);
      pcVar3 = malloc(sVar2 + 1);
      pptr->usbpath = pcVar3;
      strcpy(pptr->usbpath,usbpath);
      if (pptr->l1cfg != NULL) {
        free(pptr->l1cfg);
      }
      pptr->l1cfg = NULL;
      pptr->l1count = 0;
      iVar1 = 0;
    }
    else {
      iVar1 = -1;
    }
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

int L2CfgMDeletePort(L2Cfg *head, int conn_fd)
{
  static char buff[32];
  L2CfgPort *port;
  int iVar1;
  
  port = L2CfgMFindPort(head,conn_fd);
  if (port == NULL) {
    iVar1 = -1;
  }
  else {
    if (head->port_count != 0) {
      head->port_count = head->port_count + -1;
    }
    if (port->device != NULL) {
      free(port->device);
    }
    port->device = NULL;
    if (port->usbpath != NULL) {
      free(port->usbpath);
    }
    port->usbpath = NULL;
    if (port->l1cfg != NULL) {
      free(port->l1cfg);
    }
    port->l1cfg = NULL;
    port->l1count = 0;
    port->fd = -1;
    port->state = 0;
    iVar1 = 0;
  }
  return iVar1;
}

void L2CfgMCfgL2_rev1(L2Cfg *head, IRPacket *pkt)
{
  IRArgument *pIVar1;
  int l2s;
  int ports;
  L2CfgIRouter *l2cfg;
  uint32_t uVar2;
  L2CfgL1 *pLVar3;
  L2CfgL1 *l1cfg;
  int l1;
  L2Cfg *l2;
  uchar local_ip [4];
  int port;
  int l2i;
  int rev;
  int status;
  
  if ((pkt->_argv[0]._clas & 7) != 0) {
    IRArg(pkt,0);
  }
  if ((pkt->_argv[1]._clas & 7) != 0) {
    IRArg(pkt,1);
  }
  if ((pkt->_argv[2]._clas & 7) == 0) {
    l2s = (int)pkt->_argv[2]._val;
  }
  else {
    l2s = IRArg(pkt,2);
  }
  for (l2i = 0; l2i < l2s; l2i = l2i + 1) {
    if ((pkt->_argv[l2i * 2 + 3]._clas & 7) == 0) {
      ports = pkt->_argv[l2i * 2 + 3]._val;
    }
    else {
      ports = IRArg(pkt,l2i * 2 + 3);
    }
    if ((pkt->_argv[l2i * 2 + 4]._clas & 7) == 0) {
      l2cfg = (L2CfgIRouter *)IR_VAL_PTR(pkt->_argv[l2i * 2 + 4]._val);
    }
    else {
      l2cfg = (L2CfgIRouter *)IRArg(pkt,l2i * 2 + 4);
    }
    for (port = 0; port < ports; port = port + 1) {
      uVar2 = ntohl(l2cfg->port[port].state);
      head->port_list[port].state = uVar2;
      if (head->port_list[port].state == 2) {
        if (head->port_list[port].l1cfg != NULL) {
          free(head->port_list[port].l1cfg);
        }
        pLVar3 = malloc(4 * sizeof(L2CfgL1));
        head->port_list[port].l1cfg = pLVar3;
        memset(head->port_list[port].l1cfg,0,0xc0);
        head->port_list[port].l1count = 4;
        for (l1 = 0; l1 < 4; l1 = l1 + 1) {
          pLVar3 = head->port_list[port].l1cfg;
          uVar2 = ntohl(l2cfg->port[port].l1[l1].state);
          pLVar3[l1].configured = (uint8)uVar2;
          if (head->port_list[port].l1cfg[l1].configured != '\0') {
            uVar2 = ntohl(l2cfg->port[port].l1[l1].rack);
            pLVar3[l1].rack = (uint8)uVar2;
            uVar2 = ntohl(l2cfg->port[port].l1[l1].slot);
            pLVar3[l1].slot = (uint8)uVar2;
            uVar2 = ntohl(l2cfg->port[port].l1[l1].type);
            pLVar3[l1].type = (uint8)uVar2;
            uVar2 = ntohl(l2cfg->port[port].l1[l1].router_type);
            pLVar3[l1].router_type = (uint8)uVar2;
            strcpy(pLVar3[l1].brick_sn,l2cfg->port[port].l1[l1].brick_sn);
            strcpy(pLVar3[l1].system_sn,l2cfg->port[port].l1[l1].system_sn);
          }
        }
      }
    }
  }
  return;
}

void L2CfgMCfgL2(L2Cfg *head, IRPacket *p)
{
  L2CfgNode *peer;
  L2CfgNode *next_peer;
  int *piVar1;
  byte bVar2;
  int rev;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  int iVar6;
  uint ip;
  ulong uVar7;
  in_addr_t iVar8;
  L2CfgNode *pLVar9;
  size_t sVar10;
  L2CfgL1 *pLVar11;
  uint32 uVar12;
  IRAddress ir_addr;
  RouterClient *client;
  char *c;
  char *ccptr;
  char *cptr;
  int clen;
  int slot;
  int rack;
  IRAddress addr;
  int part;
  uint l1;
  uint port;
  char *vptr;
  char *aptr;
  char *avptr;
  int a;
  int argc;
  L2Cfg *l2;
  L2CfgNode *l2node;
  
  l2node = NULL;
  l2 = NULL;
  bVar2 = p->_argc;
  if ((p->_argv[1]._clas & 7) == 0) {
    rev = (int)p->_argv[1]._val;
  }
  else {
    rev = IRArg(p,1);
  }
  if (rev == 1) {
    if (L2CfgDebug != 0) {
      fprintf(stderr,"L2CfgCfgL2:  rev 1 config\n");
    }
    L2CfgMCfgL2_rev1(head,p);
  }
  else {
    clen = 0;
    for (a = 2; a < (int)(uint)bVar2; a = a + 1) {
      if ((p->_argv[a]._clas & 7) == 0) {
        pcVar3 = (char *)IR_VAL_PTR(p->_argv[a]._val);
      }
      else {
        pcVar3 = (char *)IRArg(p,a);
      }
      if (pcVar3 != NULL) {
        sVar10 = strlen(pcVar3);
        clen = clen + sVar10;
      }
    }
    pcVar3 = malloc(clen + 1);
    memset(pcVar3,0,clen + 1);
    cptr = pcVar3;
    for (a = 2; pcVar4 = pcVar3, a < (int)(uint)bVar2; a = a + 1) {
      if ((p->_argv[a]._clas & 7) == 0) {
        pcVar4 = (char *)IR_VAL_PTR(p->_argv[a]._val);
      }
      else {
        pcVar4 = (char *)IRArg(p,a);
      }
      if (pcVar4 != NULL) {
        sVar10 = strlen(pcVar4);
        memcpy(cptr,pcVar4,sVar10);
        cptr = cptr + sVar10;
      }
    }
    while ((cptr = pcVar4, pcVar4 = cptr, cptr != NULL && (*cptr != '\0'))) {
      pcVar5 = strchr(cptr,0x2c);
      if (pcVar5 == NULL) {
        cptr = NULL;
      }
      else {
        *pcVar5 = '\0';
        cptr = pcVar5 + 1;
      }
      pcVar5 = strtok(pcVar4,":");
      vptr = strtok(NULL,":");
      if (vptr == NULL) {
        vptr = "";
      }
      iVar6 = strcmp(pcVar5,"l2");
      pcVar4 = cptr;
      if (iVar6 == 0) {
        client = NULL;
        ir_addr = 0;
        ip = inet_addr(vptr);
        l2node = L2CfgMFindNode(head,ip,ir_addr,client);
        if ((L2Cfg *)l2node == NULL) {
          if ((L2CfgMode == 2) || ((head->net).msmode == 2)) {
            iVar6 = L2CfgMAddL2(head,ip,IR_PORT_BIAS + 0x2329,NULL,&l2node);
            if (iVar6 < 0) {
              l2node = NULL;
            }
            if ((L2CfgMode == 2) && (l2node != NULL)) {
              l2node->client = (RouterClient *)l2node;
            }
          }
          else {
            l2node = NULL;
          }
        }
        else if ((L2CfgMode != 2) && ((L2Cfg *)l2node == &L2CfgLocal)) {
          l2node = NULL;
        }
        l2 = (L2Cfg *)l2node;
      }
      else {
        iVar6 = strcmp(pcVar5,"DELETE_L2");
        if (iVar6 == 0) {
          L2CfgMDeleteNode(head,l2node->client);
          l2node = NULL;
        }
        else {
          iVar6 = strcmp(pcVar5,"l2events");
          if (iVar6 == 0) {
            if ((l2 != NULL) && (vptr != NULL)) {
              uVar7 = strtoul(vptr,NULL,0x10);
              l2node->events = uVar7;
              memset(l2node->pselect,0,0x100);
            }
          }
          else {
            iVar6 = strncmp(pcVar5,"pselect",7);
            if (iVar6 == 0) {
              if ((l2 != NULL) && (vptr != NULL)) {
                if (*vptr == '*') {
                  memset(l2node->pselect,0xff,0x100);
                }
                else {
                  c = strtok(vptr,".");
                  while (c != NULL) {
                    uVar7 = strtoul(c,NULL,10);
                    if ((int)uVar7 < 0x100) {
                      l2node->pselect[uVar7] = '\x01';
                    }
                    c = strtok(NULL,".");
                  }
                }
              }
            }
            else {
              iVar6 = strcmp(pcVar5,"l2rack");
              if (iVar6 == 0) {
                if (l2 != NULL) {
                  memset(&l2->rack,0,0x30);
                  iVar6 = atoi(vptr);
                  l2->rack = iVar6;
                  (l2->net).os = 0;
                }
              }
              else {
                iVar6 = strcmp(pcVar5,"l2ssn");
                if (iVar6 == 0) {
                  if ((l2 != NULL) && (vptr != NULL)) {
                    strcpy(l2->ssn,vptr);
                  }
                }
                else {
                  iVar6 = strcmp(pcVar5,"l2name");
                  if (iVar6 == 0) {
                    if ((l2 != NULL) && (vptr != NULL)) {
                      strcpy(l2->sysname,vptr);
                    }
                  }
                  else {
                    iVar6 = strcmp(pcVar5,"l2dspdis");
                    if (iVar6 == 0) {
                      if ((l2 != NULL) && (vptr != NULL)) {
                        iVar6 = atoi(vptr);
                        l2->l2dsp_disabled = iVar6;
                      }
                    }
                    else {
                      iVar6 = strcmp(pcVar5,"l2os");
                      if (iVar6 == 0) {
                        if ((l2 != NULL) && (vptr != NULL)) {
                          iVar6 = strcmp(vptr,"linux");
                          if (iVar6 == 0) {
                            (l2->net).os = 1;
                          }
                          else {
                            iVar6 = strcmp(vptr,"ppclinux");
                            if (iVar6 == 0) {
                              (l2->net).os = 2;
                            }
                            else {
                              iVar6 = strcmp(vptr,"armlinux");
                              if (iVar6 == 0) {
                                (l2->net).os = 3;
                              }
                              else {
                                iVar6 = strcmp(vptr,"irix");
                                if (iVar6 == 0) {
                                  (l2->net).os = 4;
                                }
                                else {
                                  (l2->net).os = 0;
                                }
                              }
                            }
                          }
                        }
                      }
                      else {
                        iVar6 = strcmp(pcVar5,"l2sec");
                        if (iVar6 == 0) {
                          if (l2 != NULL) {
                            (l2->net).msmode = 1;
                            iVar8 = inet_addr(vptr);
                            (l2->net).msip = iVar8;
                            pLVar9 = L2CfgMFindL2Node(head,(l2->net).msip,0,NULL);
                            (l2->net).msnode = pLVar9;
                          }
                        }
                        else {
                          iVar6 = strcmp(pcVar5,"l2pri");
                          if (iVar6 == 0) {
                            if (l2 != NULL) {
                              (l2->net).msmode = 2;
                              (l2->net).msip = 0;
                              (l2->net).msnode = NULL;
                              /* the original read peer->next after freeing the peer */
                              for (peer = (head->net).next; peer != NULL; peer = next_peer) {
                                next_peer = peer->next;
                                if (peer->msmode == 1) {
                                  L2CfgMDeleteL2Peer(head,peer);
                                }
                              }
                            }
                          }
                          else {
                            iVar6 = strcmp(pcVar5,"port");
                            if (iVar6 == 0) {
                              port = atoi(vptr);
                              if ((l2 != NULL) && (port == 0)) {
                                for (port = 0; port < 0x28; port = port + 1) {
                                  if (l2->port_list[port].device != NULL) {
                                    free(l2->port_list[port].device);
                                  }
                                  if (l2->port_list[port].usbpath != NULL) {
                                    free(l2->port_list[port].usbpath);
                                  }
                                  if (l2->port_list[port].l1cfg != NULL) {
                                    free(l2->port_list[port].l1cfg);
                                  }
                                  l2->port_list[port].l1count = 0;
                                }
                                port = 0;
                                memset(l2->port_list,0,sizeof(l2->port_list));
                                l2->port_count = 0;
                                if (((l2->net).msmode == 2) && ((head->net).msmode == 1)) {
                                  l2 = NULL;
                                }
                              }
                              if (l2 != NULL) {
                                l2->port_count = l2->port_count + 1;
                              }
                            }
                            else {
                              iVar6 = strcmp(pcVar5,"state");
                              if (iVar6 == 0) {
                                if (l2 != NULL) {
                                  iVar6 = atoi(vptr);
                                  l2->port_list[port].state = iVar6;
                                }
                              }
                              else {
                                iVar6 = strcmp(pcVar5,"device");
                                if (iVar6 == 0) {
                                  if (l2 != NULL) {
                                    if (vptr == NULL) {
                                      sVar10 = 1;
                                    }
                                    else {
                                      sVar10 = strlen(vptr);
                                      sVar10 = sVar10 + 1;
                                    }
                                    pcVar5 = malloc(sVar10);
                                    l2->port_list[port].device = pcVar5;
                                    if (vptr == NULL) {
                                      vptr = "";
                                    }
                                    strcpy(l2->port_list[port].device,vptr);
                                  }
                                }
                                else {
                                  iVar6 = strcmp(pcVar5,"usbp");
                                  if (iVar6 == 0) {
                                    if (l2 != NULL) {
                                      if (vptr == NULL) {
                                        sVar10 = 1;
                                      }
                                      else {
                                        sVar10 = strlen(vptr);
                                        sVar10 = sVar10 + 1;
                                      }
                                      pcVar5 = malloc(sVar10);
                                      l2->port_list[port].usbpath = pcVar5;
                                      if (vptr == NULL) {
                                        vptr = "";
                                      }
                                      strcpy(l2->port_list[port].usbpath,vptr);
                                    }
                                  }
                                  else {
                                    iVar6 = strcasecmp(pcVar5,"l1");
                                    if (iVar6 == 0) {
                                      l1 = atoi(vptr);
                                      if (l2 != NULL) {
                                        iVar6 = l2->port_list[port].l1count;
                                        if (iVar6 == 0) {
                                          pLVar11 = malloc(sizeof(L2CfgL1));
                                          l2->port_list[port].l1cfg = pLVar11;
                                        }
                                        else {
                                          pLVar11 = realloc(l2->port_list[port].l1cfg, (iVar6 + 1) * sizeof(L2CfgL1));
                                          l2->port_list[port].l1cfg = pLVar11;
                                        }
                                        memset(l2->port_list[port].l1cfg + iVar6,0,0x30);
                                        l2->port_list[port].l1cfg[iVar6].index = (uint8)l1;
                                        l1 = l2->port_list[port].l1count;
                                        piVar1 = &l2->port_list[port].l1count;
                                        *piVar1 = *piVar1 + 1;
                                        l2->port_list[port].l1cfg[l1].configured = '\x01';
                                        l2->port_list[port].l1cfg[l1].conn_state = '\x02';
                                      }
                                    }
                                    else {
                                      iVar6 = strcasecmp(pcVar5,"rack");
                                      if (iVar6 == 0) {
                                        if (l2 != NULL) {
                                          iVar6 = atoi(vptr);
                                          l2->port_list[port].l1cfg[l1].rack = (uint8)iVar6;
                                        }
                                      }
                                      else {
                                        iVar6 = strcasecmp(pcVar5,"slot");
                                        if (iVar6 == 0) {
                                          if (l2 != NULL) {
                                            iVar6 = atoi(vptr);
                                            l2->port_list[port].l1cfg[l1].slot = (uint8)iVar6;
                                          }
                                        }
                                        else {
                                          iVar6 = strcasecmp(pcVar5,"conena");
                                          if (iVar6 == 0) {
                                            if (l2 != NULL) {
                                              iVar6 = atoi(vptr);
                                              l2->port_list[port].l1cfg[l1].console_enabled =
                                                   (uint8)iVar6;
                                            }
                                          }
                                          else {
                                            iVar6 = strcasecmp(pcVar5,"consub");
                                            if (iVar6 == 0) {
                                              if (l2 != NULL) {
                                                uVar12 = atoi(vptr);
                                                l2->port_list[port].l1cfg[l1].console_subchannel =
                                                     uVar12;
                                              }
                                            }
                                            else {
                                              iVar6 = strcasecmp(pcVar5,"type");
                                              if (iVar6 == 0) {
                                                if (l2 != NULL) {
                                                  iVar6 = atoi(vptr);
                                                  l2->port_list[port].l1cfg[l1].type = (uint8)iVar6;
                                                }
                                              }
                                              else {
                                                iVar6 = strcasecmp(pcVar5,"sh_amode");
                                                if (iVar6 == 0) {
                                                  if (l2 != NULL) {
                                                    iVar6 = atoi(vptr);
                                                    l2->port_list[port].l1cfg[l1].shub_addrmode =
                                                         (uint8)iVar6;
                                                  }
                                                }
                                                else {
                                                  iVar6 = strcasecmp(pcVar5,"sh_shrmode");
                                                  if (iVar6 == 0) {
                                                    if (l2 != NULL) {
                                                      iVar6 = atoi(vptr);
                                                      l2->port_list[port].l1cfg[l1].shub_shrmode =
                                                           (uint8)iVar6;
                                                    }
                                                  }
                                                  else {
                                                    iVar6 = strcasecmp(pcVar5,"rtype");
                                                    if (iVar6 == 0) {
                                                      if (l2 != NULL) {
                                                        iVar6 = atoi(vptr);
                                                        l2->port_list[port].l1cfg[l1].router_type =
                                                             (uint8)iVar6;
                                                      }
                                                    }
                                                    else {
                                                      iVar6 = strcasecmp(pcVar5,"pstate");
                                                      if (iVar6 == 0) {
                                                        if (l2 != NULL) {
                                                          iVar6 = atoi(vptr);
                                                          l2->port_list[port].l1cfg[l1].power_state
                                                               = (uint8)iVar6;
                                                        }
                                                      }
                                                      else {
                                                        iVar6 = strcasecmp(pcVar5,"mstate");
                                                        if (iVar6 == 0) {
                                                          if (l2 != NULL) {
                                                            iVar6 = atoi(vptr);
                                                            l2->port_list[port].l1cfg[l1].
                                                            margin_state = (uint8)iVar6;
                                                          }
                                                        }
                                                        else {
                                                          iVar6 = strcasecmp(pcVar5,"estate");
                                                          if (iVar6 == 0) {
                                                            if (l2 != NULL) {
                                                              uVar12 = atoi(vptr);
                                                              l2->port_list[port].l1cfg[l1].
                                                              env_state = uVar12;
                                                            }
                                                          }
                                                          else {
                                                            iVar6 = strcasecmp(pcVar5,"cstate");
                                                            if (iVar6 == 0) {
                                                              if (l2 != NULL) {
                                                                iVar6 = atoi(vptr);
                                                                l2->port_list[port].l1cfg[l1].
                                                                conn_state = (uint8)iVar6;
                                                                if (l2->port_list[port].l1cfg[l1].
                                                                    conn_state == '\x01') {
                                                                  l2->port_list[port].l1cfg[l1].
                                                                  configured = '\0';
                                                                }
                                                              }
                                                            }
                                                            else {
                                                              iVar6 = strcasecmp(pcVar5,"part");
                                                              if (iVar6 == 0) {
                                                                if (l2 != NULL) {
                                                                  iVar6 = atoi(vptr);
                                                                  l2->port_list[port].l1cfg[l1].
                                                                  partition = (uint8)iVar6;
                                                                }
                                                              }
                                                              else {
                                                                iVar6 = strcasecmp(pcVar5,"bsn");
                                                                if (iVar6 == 0) {
                                                                  if (l2 != NULL) {
                                                                    if (vptr == NULL) {
                                                                      vptr = "";
                                                                    }
                                                                    strcpy(l2->port_list[port].l1cfg
                                                                           [l1].brick_sn,vptr);
                                                                  }
                                                                }
                                                                else {
                                                                  iVar6 = strcasecmp(pcVar5,"ssn");
                                                                  if ((iVar6 == 0) &&
                                                                     (l2 != NULL)) {
                                                                    if (vptr == NULL) {
                                                                      vptr = "";
                                                                    }
                                                                    strcpy(l2->port_list[port].l1cfg
                                                                           [l1].system_sn,vptr);
                                                                  }
                                                                }
                                                              }
                                                            }
                                                          }
                                                        }
                                                      }
                                                    }
                                                  }
                                                }
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
    free(pcVar3);
    L2CfgMGetConsole(head,-1);
  }
  return;
}

static int l1l2(L2CfgPort *l2port, int l1, int index, char *cfgp, int size)
{
  uint32_t uVar1;
  L2CfgL1 *pLVar2;
  L2CfgL1 l2_l1cfg;
  L1CfgL1 l1_l1cfg;
  
  if (0x70 < (uint)size) {
    size = 0x70;
  }
  memset(&l1_l1cfg,0,sizeof(L1CfgL1));
  memset(&l2_l1cfg,0,sizeof(L2CfgL1));
  memcpy(&l1_l1cfg,cfgp,size);
  l2_l1cfg.index = (uint8)index;
  if ((((l1_l1cfg.revision < 0x100) && (l1_l1cfg.configured < 0x100)) && (l1_l1cfg.type < 0x100)) &&
     ((l1_l1cfg.rack < 0x100 && (l1_l1cfg.slot < 0x100)))) {
    l2_l1cfg.revision = (uint8)l1_l1cfg.revision;
    l2_l1cfg.configured = (uint8)l1_l1cfg.configured;
    l2_l1cfg.type = (uint8)l1_l1cfg.type;
    l2_l1cfg.rack = (uint8)l1_l1cfg.rack;
    l2_l1cfg.slot = (uint8)l1_l1cfg.slot;
    l2_l1cfg.partition = (uint8)l1_l1cfg.partition;
    l2_l1cfg.console_subchannel = l1_l1cfg.console_subchannel;
    l2_l1cfg.console_enabled = (uint8)l1_l1cfg.console_enabled;
    l2_l1cfg.shub_addrmode = l1_l1cfg.shub_addrmode;
    l2_l1cfg.shub_shrmode = l1_l1cfg.shub_shrmode;
    l2_l1cfg.router_type = (uint8)l1_l1cfg.router_type;
    l2_l1cfg.power_state = (uint8)l1_l1cfg.power_state;
    l2_l1cfg.margin_state = (uint8)l1_l1cfg.margin_state;
    l2_l1cfg.env_state = l1_l1cfg.env_state;
    l2_l1cfg.conn_state = (uint8)l1_l1cfg.conn_state;
  }
  else {
    uVar1 = ntohl(l1_l1cfg.revision);
    l2_l1cfg.revision = (uint8)uVar1;
    uVar1 = ntohl(l1_l1cfg.configured);
    l2_l1cfg.configured = (uint8)uVar1;
    uVar1 = ntohl(l1_l1cfg.type);
    l2_l1cfg.type = (uint8)uVar1;
    uVar1 = ntohl(l1_l1cfg.rack);
    l2_l1cfg.rack = (uint8)uVar1;
    uVar1 = ntohl(l1_l1cfg.slot);
    l2_l1cfg.slot = (uint8)uVar1;
    uVar1 = ntohl(l1_l1cfg.partition);
    l2_l1cfg.partition = (uint8)uVar1;
    l2_l1cfg.console_subchannel = ntohl(l1_l1cfg.console_subchannel);
    uVar1 = ntohl(l1_l1cfg.console_enabled);
    l2_l1cfg.console_enabled = (uint8)uVar1;
    l2_l1cfg.shub_addrmode = l1_l1cfg.shub_addrmode;
    l2_l1cfg.shub_shrmode = l1_l1cfg.shub_shrmode;
    uVar1 = ntohl(l1_l1cfg.router_type);
    l2_l1cfg.router_type = (uint8)uVar1;
    uVar1 = ntohl(l1_l1cfg.power_state);
    l2_l1cfg.power_state = (uint8)uVar1;
    uVar1 = ntohl(l1_l1cfg.margin_state);
    l2_l1cfg.margin_state = (uint8)uVar1;
    l2_l1cfg.env_state = ntohl(l1_l1cfg.env_state);
    uVar1 = ntohl(l1_l1cfg.conn_state);
    l2_l1cfg.conn_state = (uint8)uVar1;
  }
  strcpy(l2_l1cfg.brick_sn,l1_l1cfg.brick_sn);
  strcpy(l2_l1cfg.system_sn,l1_l1cfg.system_sn);
  if ((l2_l1cfg.conn_state == '\0') && (l2_l1cfg.configured != '\0')) {
    l2_l1cfg.conn_state = '\x02';
  }
  if (l2port->l1count == 0) {
    pLVar2 = malloc(sizeof(L2CfgL1));
    l2port->l1cfg = pLVar2;
  }
  else {
    pLVar2 = realloc(l2port->l1cfg, (l2port->l1count + 1) * sizeof(L2CfgL1));
    l2port->l1cfg = pLVar2;
  }
  l2port->l1count = l2port->l1count + 1;
  memcpy(l2port->l1cfg + l1,&l2_l1cfg,0x30);
  return 0;
}

int L2CfgMCfgPort(L2Cfg *head, int port, IRPacket *p)
{
  L2CfgPort *l2port_00;
  ushort uVar1;
  static int cvt[4] = { 0, 1, 5, 6 };
  char *cfgp;
  int count;
  int rsp;
  char *idxp;
  uint uVar2;
  int iVar3;
  char *cfgp_;
  int size_;
  int size;
  int l1;
  int old_l1count;
  int cfg_changed;
  L2CfgPort *l2port;
  L2CfgNode *l2node;
  L2CfgL1 *old_l1cfg;
  
  l2port_00 = L2CfgLocal.port_list + port;
  if (p == NULL) {
    cfg_changed = (int)(l2port_00->state != 0);
    l2port_00->state = 0;
    if (L2CfgLocal.port_list[port].device != NULL) {
      free(L2CfgLocal.port_list[port].device);
    }
    L2CfgLocal.port_list[port].device = NULL;
    if (L2CfgLocal.port_list[port].usbpath != NULL) {
      free(L2CfgLocal.port_list[port].usbpath);
    }
    L2CfgLocal.port_list[port].usbpath = NULL;
    if (L2CfgLocal.port_list[port].l1cfg != NULL) {
      free(L2CfgLocal.port_list[port].l1cfg);
    }
    L2CfgLocal.port_list[port].l1count = 0;
    L2CfgLocal.port_list[port].l1cfg = NULL;
    if (head->port_count != 0) {
      head->port_count = head->port_count + -1;
    }
  }
  else {
    if ((p->_argv[0]._clas & 7) == 0) {
      uVar2 = p->_argv[0]._val;
    }
    else {
      uVar2 = IRArg(p,0);
    }
    iVar3 = L2CfgLocal.port_list[port].l1count;
    old_l1cfg = L2CfgLocal.port_list[port].l1cfg;
    L2CfgLocal.port_list[port].l1cfg = NULL;
    L2CfgLocal.port_list[port].l1count = 0;
    l2port_00->state = 2;
    if (uVar2 == 6) {
      for (l1 = 0; l1 < 4; l1 = l1 + 1) {
        uVar1 = p->_argv[l1 + 1]._size;
        if ((p->_argv[l1 + 1]._clas & 7) == 0) {
          cfgp = (char *)IR_VAL_PTR(p->_argv[l1 + 1]._val);
        }
        else {
          cfgp = (char *)IRArg(p,l1 + 1);
        }
        l1l2(l2port_00,l1,((int *)&cvt)[l1],cfgp,(uint)uVar1);
      }
    }
    else if (uVar2 == 7) {
      if ((p->_argv[1]._clas & 7) != 0) {
        IRArg(p,1);
      }
      if ((p->_argv[2]._clas & 7) == 0) {
        count = (int)p->_argv[2]._val;
      }
      else {
        count = IRArg(p,2);
      }
      if ((p->_argv[3]._clas & 7) == 0) {
        rsp = p->_argv[3]._val;
      }
      else {
        rsp = IRArg(p,3);
      }
      if ((p->_argv[4]._clas & 7) == 0) {
        idxp = (char *)IR_VAL_PTR(p->_argv[4]._val);
      }
      else {
        idxp = (char *)IRArg(p,4);
      }
      if ((p->_argv[5]._clas & 7) == 0) {
        cfgp = (char *)IR_VAL_PTR(p->_argv[5]._val);
      }
      else {
        cfgp = (char *)IRArg(p,5);
      }
      for (l1 = 0; l1 < count; l1 = l1 + 1) {
        l1l2(l2port_00,l1,(int)idxp[l1],cfgp + l1 * rsp,rsp);
      }
    }
    if (iVar3 == L2CfgLocal.port_list[port].l1count) {
      iVar3 = memcmp(old_l1cfg,L2CfgLocal.port_list[port].l1cfg,iVar3 * 0x30);
      cfg_changed = (int)(iVar3 != 0);
    }
    else {
      cfg_changed = 1;
    }
    if (old_l1cfg != NULL) {
      free(old_l1cfg);
    }
  }
  if (cfg_changed != 0) {
    L2CfgMGetConsole(head,-1);
  }
  return cfg_changed;
}

int L2CfgMFindBrickRS(L2Cfg *head, int ip, int port, int index, int *rack, int *slot)
{
  L2CfgPort *l2port;
  int l1;
  L2CfgNode *l2node;
  
  l2node = &head->net;
  do {
    if (l2node == NULL) {
      return -1;
    }
    if ((l2node->ip_addr == (uint32)ip) && (port < 0x28)) {
      l2port = &L2CFG_OF(l2node)->port_list[port];
      if (l2port->state != 2) {
        return -1;
      }
      for (l1 = 0; l1 < l2port->l1count; l1 = l1 + 1) {
        if ((l2port->l1cfg[l1].index == index) && (l2port->l1cfg[l1].configured != '\0')) {
          *rack = (uint)L2CFG_OF(l2node)->port_list[port].l1cfg[l1].rack;
          *slot = (uint)L2CFG_OF(l2node)->port_list[port].l1cfg[l1].slot;
          return 0;
        }
      }
    }
    l2node = l2node->next;
  } while( true );
}

int L2CfgMFindBrickIP(L2Cfg *head, int rack, int slot, int *ip, int *p, int *l)
{
  L2CfgPort *l2port;
  int l1;
  int port;
  L2CfgNode *l2node;
  
  *ip = -1;
  *p = -1;
  *l = -1;
  for (l2node = &head->net; (*p == -1 && (l2node != NULL)); l2node = l2node->next) {
    for (port = 0; port < 0x28; port = port + 1) {
      l2port = &L2CFG_OF(l2node)->port_list[port];
      if (l2port->state == 2) {
        for (l1 = 0; l1 < l2port->l1count; l1 = l1 + 1) {
          if ((((l2port->l1cfg[l1].configured != '\0') && (l2port->l1cfg[l1].rack == rack)) &&
              (l2port->l1cfg[l1].slot == slot)) &&
             ((*l == -1 || ((int)(uint)l2port->l1cfg[l1].index < *l)))) {
            *ip = l2node->ip_addr;
            *p = port;
            *l = (uint)l2port->l1cfg[l1].index;
          }
        }
      }
    }
  }
  return *p;
}

L2CfgNode *L2CfgMFindBrickL2(L2Cfg *head, int rack, int slot)
{
  L2CfgPort *l2port;
  int l1;
  int port;
  L2CfgNode *l2node;
  
  l2node = &head->net;
  do {
    if (l2node == NULL) {
      return NULL;
    }
    for (port = 0; port < 0x28; port = port + 1) {
      l2port = &L2CFG_OF(l2node)->port_list[port];
      if (l2port->state == 2) {
        for (l1 = 0; l1 < l2port->l1count; l1 = l1 + 1) {
          if (((l2port->l1cfg[l1].configured != '\0') && (l2port->l1cfg[l1].rack == rack)) &&
             (l2port->l1cfg[l1].slot == slot)) {
            return l2node;
          }
        }
      }
    }
    l2node = l2node->next;
  } while( true );
}

L2CfgL1 *L2CfgMFindBrickCfg(L2Cfg *head, int rack, int slot, int local)
{
  L2CfgNode *l2end;
  L2CfgPort *l2port;
  int l1;
  int port;
  L2CfgNode *l2node;
  
  if ((rack != 0) && (slot != 0)) {
    if ((local == 0) || (head == NULL)) {
      l2end = NULL;
    }
    else {
      l2end = (head->net).next;
    }
    for (l2node = &head->net; l2node != l2end; l2node = l2node->next) {
      for (port = 0; port < 0x28; port = port + 1) {
        l2port = &L2CFG_OF(l2node)->port_list[port];
        if (l2port->state == 2) {
          for (l1 = 0; l1 < l2port->l1count; l1 = l1 + 1) {
            if ((l2port->l1cfg[l1].rack == rack) && (l2port->l1cfg[l1].slot == slot)) {
              return l2port->l1cfg + l1;
            }
          }
        }
      }
    }
  }
  return NULL;
}

int L2CfgMFindBrickType(L2Cfg *head, int rack, int slot)
{
  L2CfgPort *l2port;
  int l1;
  int port;
  L2CfgNode *l2node;
  
  l2node = &head->net;
  do {
    if (l2node == NULL) {
      return 0x3f;
    }
    for (port = 0; port < 0x28; port = port + 1) {
      l2port = &L2CFG_OF(l2node)->port_list[port];
      if (l2port->state == 2) {
        for (l1 = 0; l1 < l2port->l1count; l1 = l1 + 1) {
          if ((l2port->l1cfg[l1].rack == rack) && (l2port->l1cfg[l1].slot == slot)) {
            return (uint)l2port->l1cfg[l1].type;
          }
        }
      }
    }
    l2node = l2node->next;
  } while( true );
}

char *L2CfgMQuery(L2Cfg *head, int mode, int format)
{
  uint uVar1;
  int block;
  size_t sVar2;
  char *pcVar3;
  undefined *puVar4;
  L2CfgPort *port;
  int iVar5;
  char sel [1024];
  int part;
  int l1_index;
  int port_index;
  int l2_index;
  L2CfgPort *l2port;
  L2CfgNode *l2node;
  
  if (clen == 0) {
    clen = 0x2000;
    cbuf = malloc(0x2000);
  }
  cptr = cbuf;
  *cbuf = '\0';
  l2_index = 0;
  for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
    block = strlen(cbuf);
    if ((uint)clen < block + 0x2000U) {
      clen = clen + 0x2000;
      cbuf = realloc(cbuf,clen);
      sVar2 = strlen(cbuf);
      cptr = cbuf + sVar2;
    }
    if (((l2_index == 0) || (l2node->client != NULL)) &&
       (((mode & 1U) != 0 || ((L2Cfg *)l2node == &L2CfgLocal)))) {
      if ((format != 0) && ((L2Cfg *)l2node != head)) {
        strcat(cptr,"\n");
        sVar2 = strlen(cptr);
        cptr = cptr + sVar2;
      }
      pcVar3 = inet_ntoa(*(struct in_addr *)&l2node->ip_addr);
      sprintf(cptr,"%s:%s,","l2",pcVar3);
      sVar2 = strlen(cptr);
      cptr = cptr + sVar2;
      if ((mode & 2U) == 0) {
        sprintf(cptr,"%s:%u,","l2rack",L2CFG_OF(l2node)->rack);
        sVar2 = strlen(cptr);
        cptr = cptr + sVar2;
        if (L2CFG_OF(l2node)->ssn[0] != '\0') {
          sprintf(cptr,"%s:%s,","l2ssn",L2CFG_OF(l2node)->ssn);
          sVar2 = strlen(cptr);
          cptr = cptr + sVar2;
        }
        if (L2CFG_OF(l2node)->sysname[0] != '\0') {
          sprintf(cptr,"%s:%s,","l2name",L2CFG_OF(l2node)->sysname);
          sVar2 = strlen(cptr);
          cptr = cptr + sVar2;
        }
        if (L2CFG_OF(l2node)->l2dsp_disabled != 0) {
          sprintf(cptr,"%s:%u,","l2dspdis",L2CFG_OF(l2node)->l2dsp_disabled);
          sVar2 = strlen(cptr);
          cptr = cptr + sVar2;
        }
        if ((L2Cfg *)l2node == &L2CfgLocal) {
          sprintf(cptr,"%s:%s,","l2os","linux");
          sVar2 = strlen(cptr);
          cptr = cptr + sVar2;
        }
        else {
          uVar1 = l2node->os;
          if (uVar1 == 2) {
            sprintf(cptr,"%s:%s,","l2os","ppclinux");
            sVar2 = strlen(cptr);
            cptr = cptr + sVar2;
          }
          else if (uVar1 < 3) {
            if (uVar1 == 1) {
              sprintf(cptr,"%s:%s,","l2os","linux");
              sVar2 = strlen(cptr);
              cptr = cptr + sVar2;
            }
          }
          else if (uVar1 == 3) {
            sprintf(cptr,"%s:%s,","l2os","armlinux");
            sVar2 = strlen(cptr);
            cptr = cptr + sVar2;
          }
          else if (uVar1 == 4) {
            sprintf(cptr,"%s:%s,","l2os","irix");
            sVar2 = strlen(cptr);
            cptr = cptr + sVar2;
          }
        }
        if (l2node->msmode == 2) {
          pcVar3 = inet_ntoa(*(struct in_addr *)&l2node->ip_addr);
          sprintf(cptr,"%s:%s,","l2pri",pcVar3);
          sVar2 = strlen(cptr);
          cptr = cptr + sVar2;
        }
        if (l2node->msmode == 1) {
          pcVar3 = inet_ntoa(*(struct in_addr *)&l2node->msip);
          sprintf(cptr,"%s:%s,","l2sec",pcVar3);
          sVar2 = strlen(cptr);
          cptr = cptr + sVar2;
        }
        for (port_index = 0; port_index < 0x28; port_index = port_index + 1) {
          port = &L2CFG_OF(l2node)->port_list[port_index];
          if (format != 0) {
            strcat(cptr,"\n  ");
            sVar2 = strlen(cptr);
            cptr = cptr + sVar2;
          }
          sprintf(cptr,"%s:%u,","port",port_index);
          sVar2 = strlen(cptr);
          cptr = cptr + sVar2;
          if (port->state != 0) {
            sprintf(cptr,"%s:%u,","state",port->state);
            sVar2 = strlen(cptr);
            cptr = cptr + sVar2;
            sprintf(cptr,"%s:%s,","device",port->device);
            sVar2 = strlen(cptr);
            cptr = cptr + sVar2;
            sprintf(cptr,"%s:%s,","usbp",port->usbpath);
            sVar2 = strlen(cptr);
            cptr = cptr + sVar2;
            if (port->state == 2) {
              for (l1_index = 0; l1_index < port->l1count; l1_index = l1_index + 1) {
                if ((port->l1cfg[l1_index].configured != '\0') ||
                   (port->l1cfg[l1_index].conn_state != '\0')) {
                  if (format != 0) {
                    strcat(cptr,"\n    ");
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (l1_index == 0) {
                    puVar4 = "l1";
                  }
                  else {
                    puVar4 = "L1";
                  }
                  sprintf(cptr,"%s:%u,",puVar4,l1_index);
                  sVar2 = strlen(cptr);
                  cptr = cptr + sVar2;
                  if (l1_index == 0) {
                    puVar4 = "rack";
                  }
                  else {
                    puVar4 = "RACK";
                  }
                  sprintf(cptr,"%s:%u,",puVar4,(uint)port->l1cfg[l1_index].rack);
                  sVar2 = strlen(cptr);
                  cptr = cptr + sVar2;
                  if (l1_index == 0) {
                    puVar4 = "slot";
                  }
                  else {
                    puVar4 = "SLOT";
                  }
                  sprintf(cptr,"%s:%u,",puVar4,(uint)port->l1cfg[l1_index].slot);
                  sVar2 = strlen(cptr);
                  cptr = cptr + sVar2;
                  if (l1_index == 0) {
                    puVar4 = "type";
                  }
                  else {
                    puVar4 = "TYPE";
                  }
                  sprintf(cptr,"%s:%u,",puVar4,(uint)port->l1cfg[l1_index].type);
                  sVar2 = strlen(cptr);
                  cptr = cptr + sVar2;
                  if (port->l1cfg[l1_index].console_enabled != '\0') {
                    if (l1_index == 0) {
                      pcVar3 = "conena";
                    }
                    else {
                      pcVar3 = "CONENA";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,(uint)port->l1cfg[l1_index].console_enabled);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].console_subchannel != 0) {
                    if (l1_index == 0) {
                      pcVar3 = "consub";
                    }
                    else {
                      pcVar3 = "CONSUB";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,port->l1cfg[l1_index].console_subchannel);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].router_type != '\0') {
                    if (l1_index == 0) {
                      pcVar3 = "rtype";
                    }
                    else {
                      pcVar3 = "RTYPE";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,(uint)port->l1cfg[l1_index].router_type);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].shub_addrmode != '\0') {
                    if (l1_index == 0) {
                      pcVar3 = "sh_amode";
                    }
                    else {
                      pcVar3 = "SH_AMODE";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,(uint)port->l1cfg[l1_index].shub_addrmode);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].shub_shrmode != '\0') {
                    if (l1_index == 0) {
                      pcVar3 = "sh_shrmode";
                    }
                    else {
                      pcVar3 = "SH_SHRMODE";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,(uint)port->l1cfg[l1_index].shub_shrmode);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].power_state != '\0') {
                    if (l1_index == 0) {
                      pcVar3 = "pstate";
                    }
                    else {
                      pcVar3 = "PSTATE";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,(uint)port->l1cfg[l1_index].power_state);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].margin_state != '\0') {
                    if (l1_index == 0) {
                      pcVar3 = "mstate";
                    }
                    else {
                      pcVar3 = "MSTATE";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,(uint)port->l1cfg[l1_index].margin_state);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].env_state != 0) {
                    if (l1_index == 0) {
                      pcVar3 = "estate";
                    }
                    else {
                      pcVar3 = "ESTATE";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,port->l1cfg[l1_index].env_state);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].conn_state != '\0') {
                    if (l1_index == 0) {
                      pcVar3 = "cstate";
                    }
                    else {
                      pcVar3 = "CSTATE";
                    }
                    sprintf(cptr,"%s:%u,",pcVar3,(uint)port->l1cfg[l1_index].conn_state);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (port->l1cfg[l1_index].partition != '\0') {
                    if (l1_index == 0) {
                      puVar4 = "part";
                    }
                    else {
                      puVar4 = "PART";
                    }
                    sprintf(cptr,"%s:%u,",puVar4,(uint)port->l1cfg[l1_index].partition);
                    sVar2 = strlen(cptr);
                    cptr = cptr + sVar2;
                  }
                  if (l1_index == 0) {
                    puVar4 = "bsn";
                  }
                  else {
                    puVar4 = "BSN";
                  }
                  sprintf(cptr,"%s:%s,",puVar4,port->l1cfg[l1_index].brick_sn);
                  sVar2 = strlen(cptr);
                  cptr = cptr + sVar2;
                  if (l1_index == 0) {
                    puVar4 = "ssn";
                  }
                  else {
                    puVar4 = "SSN";
                  }
                  sprintf(cptr,"%s:%s,",puVar4,port->l1cfg[l1_index].system_sn);
                  sVar2 = strlen(cptr);
                  cptr = cptr + sVar2;
                }
              }
            }
          }
        }
      }
      else {
        sprintf(cptr,"%s:%x,","l2events",l2node->events);
        sVar2 = strlen(cptr);
        cptr = cptr + sVar2;
        if (l2node->pselect[0] == 0xff) {
          sprintf(cptr,"%s:%s,","pselect","*");
          sVar2 = strlen(cptr);
          cptr = cptr + sVar2;
        }
        else {
          sel[0] = '\0';
          for (part = 0; part < 0x100; part = part + 1) {
            if (l2node->pselect[part] != '\0') {
              sVar2 = strlen(sel);
              if (sVar2 != 0) {
                strcat(sel,".");
              }
              pcVar3 = "%d";
              iVar5 = part;
              sVar2 = strlen(sel);
              sprintf(sel + sVar2,pcVar3,iVar5);
            }
          }
          sVar2 = strlen(sel);
          if (sVar2 != 0) {
            sprintf(cptr,"%s:%s,","pselect",sel);
            sVar2 = strlen(cptr);
            cptr = cptr + sVar2;
          }
        }
      }
    }
    l2_index = l2_index + 1;
  }
  return cbuf;
}

char *L2CfgMAddrStr(L2Cfg *head, IRAddress addr, int verbose)
{
  IRAddress IVar1;
  static char buff[80];
  char brick;
  int type;
  size_t sVar2;
  uint type_00;
  L2CfgNode *pLVar3;
  char *pcVar4;
  uint32_t uVar5;
  int rack;
  int slot;
  int task;
  int ip;
  L2Cfg *l2node;
  char *bptr;
  
  IVar1 = addr;
  bptr = (char *)&buff;
  if ((addr & 0x80000000) == 0) {
    type = addr >> 0x1c;
  }
  else if (addr >> 0x1e == 2) {
    type = 0xe;
  }
  else {
    type = 0xf;
  }
  if (false) {
switchD_0806fc1f_caseD_6:
    sprintf((char *)&buff,"invalid address (IR 0x%08x)",addr);
  }
  else {
    switch(type) {
    case 1:
    case 2:
      if (type == 1) {
        pcVar4 = "L2 ";
      }
      else {
        pcVar4 = "L3 ";
      }
      strcpy((char *)&buff,pcVar4);
      sVar2 = strlen((char *)&buff);
      bptr = buff + sVar2;
      /* fall through */
    case 0:
      rack = addr >> 0x12 & 0x3ff;
      slot = addr >> 0xc & 0x3f;
      type_00 = L2CfgMFindBrickType(head,rack,slot);
      brick = brickTypeToChar(type_00);
      if (addr >> 0xc == 0xffff) {
        sprintf(bptr,"local");
      }
      else if (type == 0) {
        sprintf(bptr,"%03d%c%02d",rack,(int)brick,slot);
      }
      else {
        sprintf(bptr,"(%03d%c%02d)",rack,(int)brick,slot);
      }
      break;
    case 3:
      strcpy((char *)&buff,"local attached C");
      break;
    case 4:
      strcpy((char *)&buff,"local attached I/O");
      break;
    case 5:
      strcpy((char *)&buff,"local attached C\'s I/O");
      break;
    default:
      goto switchD_0806fc1f_caseD_6;
    case 0xe:
      addr = addr & 0xc0ffffff;
      pLVar3 = L2CfgMFindL2Node(head,0,addr,NULL);
      if (pLVar3 == NULL) {
        if (IRByteOrder == 1) {
          uVar5 = IVar1 & 0xffffff;
        }
        else {
          uVar5 = htonl(IVar1 & 0xffffff);
        }
        uVar5 = ntohl(uVar5);
        sprintf((char *)&buff,"X.%d.%d.%d-L2",(int)uVar5 >> 0x10 & 0xff,(int)uVar5 >> 8 & 0xff,
                uVar5 & 0xff);
      }
      else if (L2CFG_OF(pLVar3)->rack < 1) {
        pcVar4 = SocketAddrStr(pLVar3->ip_addr);
        sprintf((char *)&buff,"%s-L2",pcVar4);
      }
      else {
        sprintf((char *)&buff,"%03d-L2",L2CFG_OF(pLVar3)->rack);
      }
      break;
    case 0xf:
      task = addr >> 0x18 & 0x3f;
      addr = addr & 0xc0ffffff;
      pLVar3 = L2CfgMFindL2Node(head,0,addr,NULL);
      if (pLVar3 == NULL) {
        if (IRByteOrder == 1) {
          ip = IVar1 & 0xffffff;
        }
        else {
          ip = htonl(IVar1 & 0xffffff);
        }
        uVar5 = ntohl(ip);
        sprintf((char *)&buff,"L3 Client %d [X.%d.%d.%d-L2]",task,(int)uVar5 >> 0x10 & 0xff,
                (int)uVar5 >> 8 & 0xff,uVar5 & 0xff);
      }
      else if (L2CFG_OF(pLVar3)->rack < 1) {
        pcVar4 = SocketAddrStr(pLVar3->ip_addr);
        sprintf((char *)&buff,"L3 Client %d [%s-L2]",task,pcVar4);
      }
      else {
        sprintf((char *)&buff,"L3 Client %d [%03d-L2]",task,L2CFG_OF(pLVar3)->rack);
      }
    }
  }
  return buff;
}

IRAddress L2CfgMGetConsole(L2Cfg *head, int partition)
{
  IRAddress detected;
  int subc;
  L2CfgPort *l2port;
  int rack;
  int slot;
  int type;
  uint uVar1;
  IRAddress IVar2;
  int part;
  int l1;
  int port;
  L2CfgNode *l2node;
  
  if (L2CfgDebugX != 0) {
    fprintf(stderr,"L2CfgGetConsole(%x, %d)\n",head,partition);
  }
  if ((partition == -1) || (partition < 0x100)) {
    if ((partition == -1) || (detected = head->syscon[partition].detected, detected == 0)) {
      memset(addr0,0,0x400);
      memset(addr1,0,0x400);
      memset(rack0,-1,0x400);
      memset(rack1,-1,0x400);
      memset(slot0,-1,0x400);
      memset(slot1,-1,0x400);
      for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
        for (port = 0; port < 0x28; port = port + 1) {
          l2port = &L2CFG_OF(l2node)->port_list[port];
          if (l2port->state == 2) {
            for (l1 = 0; l1 < l2port->l1count; l1 = l1 + 1) {
              if (l2port->l1cfg[l1].configured != '\0') {
                rack = (int)l2port->l1cfg[l1].rack;
                slot = (int)l2port->l1cfg[l1].slot;
                type = (int)l2port->l1cfg[l1].type;
                subc = BRICK_TASKNUM_SUBCHAN(type,l2port->l1cfg[l1].console_subchannel);
                uVar1 = (uint)l2port->l1cfg[l1].partition;
                if ((((rack != 0) && (slot != 0)) &&
                    (((((type == 0x43 ||
                        (((((type == 0x33 || (type == 0x35)) || (type == 0x34)) ||
                          ((type == 0x41 || (type == 0x36)))) || (type == 0x39)))) ||
                       (((type == 0x37 || (type == 0x38)) || (type == 0x30)))) ||
                      (((((type == 0x51 || (type == 0x40)) || (type == 0x4f)) ||
                        ((type == 0x42 || (type == 0x46)))) ||
                       ((type == 0x4c || ((type == 0x4d || (type == 0x24)))))))) ||
                     ((type == 0x2c || (((type == 0x7d || (type == 0x2e)) || (type == 0x7b))))))))
                   && ((partition == -1 || ((int)uVar1 == partition)))) {
                  if (((uint)rack <= rack0[uVar1]) && (((uint)slot <= slot0[uVar1] && (subc == 4))))
                  {
                    rack0[uVar1] = rack;
                    slot0[uVar1] = slot;
                    addr0[uVar1] = (rack << 6 | (slot & 0x3fU)) << 0xc;
                    addr0[uVar1] = (l2port->l1cfg[l1].console_subchannel & 0x7f) << 5 |
                                   (addr0[uVar1] & 0xfffff01f);
                    if ((addr0[uVar1] & 0x80000000) == 0) {
                      IVar2 = (addr0[uVar1] & 0xffffffe0) |
                              (l2port->l1cfg[l1].console_subchannel >> 8 & 0x1f);
                      addr0[uVar1] = IVar2;
                    }
                    else {
                      IVar2 = (addr0[uVar1] & 0xc0ffffff) |
                              (l2port->l1cfg[l1].console_subchannel >> 8 & 0x3f) << 0x18;
                      addr0[uVar1] = IVar2;
                    }
                    addr0[uVar1] = IVar2;
                  }
                  if (((uint)rack <= rack1[uVar1]) && ((uint)slot <= slot1[uVar1])) {
                    rack1[uVar1] = rack;
                    slot1[uVar1] = slot;
                    addr1[uVar1] = (rack << 6 | (slot & 0x3fU)) << 0xc;
                    addr1[uVar1] = (l2port->l1cfg[l1].console_subchannel & 0x7f) << 5 |
                                   (addr1[uVar1] & 0xfffff01f);
                    if ((addr1[uVar1] & 0x80000000) == 0) {
                      IVar2 = (addr1[uVar1] & 0xffffffe0) |
                              (l2port->l1cfg[l1].console_subchannel >> 8 & 0x1f);
                      addr1[uVar1] = IVar2;
                    }
                    else {
                      IVar2 = (addr1[uVar1] & 0xc0ffffff) |
                              (l2port->l1cfg[l1].console_subchannel >> 8 & 0x3f) << 0x18;
                      addr1[uVar1] = IVar2;
                    }
                    addr1[uVar1] = IVar2;
                  }
                }
              }
            }
          }
        }
      }
      for (part = 0; part < 0x100; part = part + 1) {
        IVar2 = addr0[part];
        if (addr0[part] == 0) {
          IVar2 = addr1[part];
        }
        head->syscon[part].detected = IVar2;
        if ((L2CfgDebugX != 0) && ((addr0[part] != 0 || (addr1[part] != 0)))) {
          fprintf(stderr,"detecting %d - %x %x\n",part,addr0[part],addr1[part]);
        }
      }
      if (partition == -1) {
        detected = 0;
      }
      else {
        detected = head->syscon[partition].detected;
      }
    }
    else if (L2CfgDebugX != 0) {
      fprintf(stderr,"console detected: %x\n",detected);
    }
  }
  else {
    if (L2CfgDebugX != 0) {
      fprintf(stderr,"bad partition\n");
    }
    detected = 0;
  }
  return detected;
}

int L2CfgMCount(L2Cfg *head)
{
  int count;
  L2CfgNode *l2node;
  
  count = 1;
  for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
    count = count + 1;
  }
  return count;
}

int L2CfgMAdviseConsole(L2Cfg *head, char *rptr, int partition, IRAddress addr)
{
  int count;
  int iVar1;
  L2CfgNode *l2node;
  char *pcVar2;
  int rack;
  int slot;
  L2Cfg *l2;
  
  rack = addr >> 0x12 & 0x3ff;
  slot = addr >> 0xc & 0x3f;
  count = L2CfgMCount(head);
  if (count < 0x11) {
    iVar1 = 0;
  }
  else if (addr == 0) {
    iVar1 = 0;
  }
  else {
    l2node = L2CfgMFindBrickL2(head,rack,slot);
    if (l2node == NULL) {
      iVar1 = 0;
    }
    else if ((L2Cfg *)l2node == head) {
      iVar1 = 0;
    }
    else {
      if (partition == 0) {
        pcVar2 = inet_ntoa(*(struct in_addr *)&l2node->ip_addr);
        sprintf(rptr,
                "\nWARNING: accessing the system console at %03d.%02d from this L2 is not\nadvised!  Suggested access point is the L2 at rack ID %04d (%s)\n\n"
                ,rack,slot,L2CFG_OF(l2node)->rack,pcVar2);
      }
      else {
        pcVar2 = inet_ntoa(*(struct in_addr *)&l2node->ip_addr);
        sprintf(rptr,
                "\nWARNING: accessing partition %d of the system at %03d.%02d from this\nL2 is not advised!  Suggested access point for partition %d is\nthe L2 at rack ID %04d (%s)\n\n"
                ,partition,rack,slot,partition,L2CFG_OF(l2node)->rack,pcVar2);
      }
      iVar1 = -1;
    }
  }
  return iVar1;
}

