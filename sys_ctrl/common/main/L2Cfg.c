/*
 * sys_ctrl/common/main/L2Cfg.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/main/L2Cfg.c
 *
 * The system configuration: the L2s (this one, L2CfgLocal, first; then the
 * peers it hears about) with the L1s on each of their ports, plus the L3
 * and L2 application clients connected here. l2 keeps it up to date from
 * its L1s (L2CfgMCfgPort()) and peers; it travels between L2s, and to L3
 * tools (SysCfg.c), as a "key:value," text (L2CfgMQuery(), L2CfgMCfgL2()).
 *
 * An L2 node is an L2Cfg, which begins with its L2CfgNode (L2CFG_OF());
 * clients are plain L2CfgNodes. IRouter addresses of IP-type: an L2 is
 * 0x80000000 | the low 24 bits of its IP address, an L3 client 0xc0000000 |
 * those of its L2's, with the client's socket as the task.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "L2Cfg.h"
#include "../IRouter/IRouter.h"
#include "../Router/Socket.h"
#include "../sys/brick_types.h"
#include "../../l3/main/nvram.h"
#include "../../l3/sys/syslogLib.h"

/* the ports, plus IR_PORT_BIAS */
#define L2_PEER_PORT        9001
#define L2_APP_PORT         9002
#define L2_APP_QUIET_PORT   9004

#define IR_IP_L2            0x80000000  /* an L2's IRouter address: | 24 bits of its IP */
#define IR_IP_L3            0xc0000000  /* an L3 client's: | its L2's, task = socket */
#define IR_IP_TASK_MASK     0xc0ffffff
#define LOCAL_L2_ADDR       0x1ffff     /* addr >> 12 of an L2 address with rack and slot all ones */

#define NODE_EVENTS         0xffffffe6  /* the events a new node gets */
#define DSP_EVENTS          0x16        /* ... an L2 display client */

#define L1S_PER_PORT_REV1   4
#define MAX_PARTITIONS      256
#define CONSOLE_SUBCHAN     4           /* the subchannel a system console prefers */

/* an L2's configuration as the revision 1 event carried it (big-endian ints) */
typedef struct {
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
} L2CfgIRouterL1;
typedef struct {
    int state;
    L2CfgIRouterL1 l1[4];
} L2CfgIRouterPort;
typedef struct {
    int state;
    int ip;
    L2CfgIRouterPort port[40];
} L2CfgIRouter;

/* a brick in L2CfgMPrintX()'s list */
struct list_t {
    int rs;                     /* rack * 100 + slot */
    int type;
    int part;
    int l2;
};

static int match_node(L2CfgNode *n, uint32 ip_addr, IRAddress ir_addr, RouterClient *client);
static void format_l1(char *rptr, L2CfgNode *l2node, int port, int l1, int mode);
static void format_l2(char *rptr, L2CfgNode *l2node, L2Cfg *head, int mode, int show_l1);
static int l1l2(L2CfgPort *l2port, int l1, int index, char *cfgp, int size);

int L2CfgDebug;
int L2CfgDebugX;
int L2CfgMode;                  /* 1: in l2; 2: in an L3 tool */
static char *cbuf;              /* L2CfgMQuery()'s text */
static int clen;
static char *cptr;
L2Cfg L2CfgLocal;
/* L2CfgMGetConsole()'s candidates per partition: the first brick with
 * the console subchannel, and the first brick at all */
static IRAddress addr0[MAX_PARTITIONS];
static IRAddress addr1[MAX_PARTITIONS];
static unsigned int rack0[MAX_PARTITIONS];
static unsigned int rack1[MAX_PARTITIONS];
static unsigned int slot0[MAX_PARTITIONS];
static unsigned int slot1[MAX_PARTITIONS];

/* copy a string into a field, truncated (the original strcpy()ed) */
static void set_field(char *field, size_t size, const char *value)
{
  snprintf(field,size,"%s",value);
}

/* the low 24 bits of an IP address (network order) as a number */
static uint32 ip_low24(uint32 ip_addr)
{
  return ntohl(ip_addr) & 0xffffff;
}

static unsigned long ptr_bits(const void *p)
{
  return (unsigned long)(uintptr_t)p;
}

/* l2: this L2's configuration */
int L2CfgInitLocal(uint32 ip_addr, RouterClient *client)
{
  if (L2CfgDebug)
    fprintf(stderr,"InitLocal(ip %08x, c %08lx)\n",ip_addr,ptr_bits(client));
  if (L2CfgMode != 0) {
    syslog(3,"../../common/main/L2Cfg.c",103,0,"L2CfgInitLocal:  L2Cfg already initialized!!");
    return -1;
  }
  L2CfgMode = 1;
  L2CfgInitNode(&L2CfgLocal.net,1,ip_addr,ip_low24(ip_addr) | IR_IP_L2,client);
  L2CfgLocal.rack = nvramGet(NVRAM_RACK);
  L2CfgLocal.net.msmode = nvramGet(NVRAM_MASTER_SLAVE);
  if (L2CfgLocal.net.msmode != 0 && L2CfgLocal.net.msmode < 3) {
    L2CfgLocal.net.msip = 0;
    L2CfgLocal.net.msnode = NULL;
  }
  /* (the system name is up to 31 characters, the field 20: the original
   * overflowed it) */
  set_field(L2CfgLocal.ssn,sizeof(L2CfgLocal.ssn),(char *)nvramGet(NVRAM_SERIAL));
  set_field(L2CfgLocal.sysname,sizeof(L2CfgLocal.sysname),(char *)nvramGet(NVRAM_SYSNAME));
  L2CfgLocal.l2dsp_disabled = nvramGet(NVRAM_L2DSP_DISABLED);
  L2CfgLocal.syscon = calloc(MAX_PARTITIONS,sizeof(L2CfgSysCon));
  return 0;
}

/* an L3 tool: head is the configuration of the L2 it is connected to */
int L2CfgMInitL3(L2Cfg *head, RouterClient *client)
{
  if (L2CfgDebug)
    fprintf(stderr,"InitL3(cfg %08lx, c %08lx)\n",ptr_bits(head),ptr_bits(client));
  if (L2CfgMode == 1) {
    syslog(3,"../../common/main/L2Cfg.c",165,0,"L2CfgInitL3:  L2Cfg already initialized in L2 mode!!");
    return -1;
  }
  L2CfgMode = 2;
  L2CfgInitNode(&head->net,1,client->addr,ip_low24(client->addr) | IR_IP_L2,client);
  head->syscon = calloc(MAX_PARTITIONS,sizeof(L2CfgSysCon));
  return 0;
}

static int app_port(uint32 port)
{
  return port == IR_PORT_BIAS + (uint32)L2_APP_PORT || port == IR_PORT_BIAS + (uint32)L2_APP_QUIET_PORT;
}

/*
 * A peer L2 (on the peer port) or an L2 application client (on the
 * application ports; its process ID is its task) at ip_addr:port, or of
 * client. *node (if not NULL) is its node. -1 if it is there and connected
 * already.
 */
int L2CfgMAddL2(L2Cfg *head, uint32 ip_addr, uint32 port, RouterClient *client, L2CfgNode **node)
{
  L2CfgNode *newl2, *oldl2;
  IRAddress ir_addr = 0;
  int task;

  if (L2CfgDebug)
    fprintf(stderr,"\n------------------------\nAddL2(cfg %08lx, ip %08x, c %08lx)\n",ptr_bits(head),
            ip_addr,ptr_bits(client));
  if (client != NULL) {
    port = client->port;
    ip_addr = client->addr;
  }
  if (app_port(port))
    ir_addr = (head->net.ir_addr & IR_IP_TASK_MASK) | (client->process_id & 0x3f) << 24;
  else if (port == IR_PORT_BIAS + (uint32)L2_PEER_PORT)
    ir_addr = ip_low24(ip_addr) | IR_IP_L2;
  newl2 = L2CfgInitNode(NULL,1,ip_addr,ir_addr,client);
  if (app_port(port)) {
    task = IR_ADDR_TASK(ir_addr);
    if (task == IR_L2_DSP)
      newl2->events = DSP_EVENTS;
    else if (task == IR_L2_FLASH || task == IR_L2_WEBS)
      newl2->events = 0;
  }

  oldl2 = L2CfgMFindL2Node(head,newl2->ip_addr,newl2->ir_addr,NULL);
  if (oldl2 == NULL) {
    if (app_port(port)) {
      newl2->next = head->l2_clients;
      head->l2_clients = newl2;
    }
    else {
      newl2->next = head->net.next;
      head->net.next = newl2;
    }
    if (node != NULL)
      *node = newl2;
    return 0;
  }
  if (oldl2->client != NULL) {
    free(newl2);
    return -1;
  }
  oldl2->client = newl2->client;
  if (node != NULL)
    *node = oldl2;
  free(newl2);
  return 0;
}

/* an L3 client; its process ID's low 5 bits are the events it wants */
int L2CfgMAddL3(L2Cfg *head, uint32 ip_addr, RouterClient *client)
{
  L2CfgNode *newl3, *oldl3;

  if (L2CfgDebug)
    fprintf(stderr,"AddL3(cfg %08lx, ip %08x, c %08lx)\n",ptr_bits(head),ip_addr,ptr_bits(client));
  newl3 = L2CfgInitNode(NULL,0,ip_addr,
                        ip_low24(head->net.ip_addr) | IR_IP_L3 | (client->socket & 0x3f) << 24,client);
  newl3->events = client->process_id & 0x1f;
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

/* drop the node of client (a peer, an application or an L3 client) */
int L2CfgMDeleteNode(L2Cfg *head, RouterClient *client)
{
  L2CfgNode *n;

  if (L2CfgDebug)
    fprintf(stderr,"DeleteNode(cfg %08lx, c %08lx)\n",ptr_bits(head),ptr_bits(client));
  for (n = head->net.next; n != NULL; n = n->next) {
    if (match_node(n,0,0,client)) {
      L2CfgMDeleteL2Peer(head,n);
      return 0;
    }
  }
  for (n = head->l2_clients; n != NULL; n = n->next) {
    if (match_node(n,0,0,client)) {
      L2CfgDeleteL2Client(&head->l2_clients,n);
      return 0;
    }
  }
  for (n = head->l3_clients; n != NULL; n = n->next) {
    if (match_node(n,0,0,client)) {
      L2CfgDeleteL2Client(&head->l3_clients,n);
      return 0;
    }
  }
  return 0;
}

/* set up node (a new one, an L2Cfg if l2, when NULL) */
L2CfgNode *L2CfgInitNode(L2CfgNode *node, int l2, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  size_t nsize;

  if (L2CfgDebug)
    fprintf(stderr,"InitNode(n %08lx, l2 %08d, ip %08x, ir %08x, c %08lx)\n",ptr_bits(node),l2,
            ip_addr,ir_addr,ptr_bits(client));
  if (node == NULL) {
    nsize = l2 ? sizeof(L2Cfg) : sizeof(L2CfgNode);
    node = calloc(1,nsize);
    if (node == NULL)
      return NULL;
  }
  node->ip_addr = ip_addr;
  node->ir_addr = ir_addr;
  node->client = client;
  node->events = NODE_EVENTS;
  node->heartbeat = 0xffffffff;
  return node;
}

/* does the node match (each of ip_addr, ir_addr and client if given)? IP
 * addresses compare in their low 24 bits */
static int match_node(L2CfgNode *n, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  if (L2CfgDebug) {
    if (ip_addr != 0) {
      fprintf(stderr,"checking IP %08x = %08x\n",ip_low24(n->ip_addr),ip_low24(ip_addr));
      if (n->client != NULL && n->client->id.ipaddr != 0)
        fprintf(stderr,"checking client id IP %08x = %08x\n",ip_low24(n->client->id.ipaddr),
                ip_low24(ip_addr));
    }
    if (ir_addr != 0)
      fprintf(stderr,"checking IR %08x = %08x\n",n->ir_addr,ir_addr);
    if (client != NULL)
      fprintf(stderr,"checking C %08lx = %08lx\n",ptr_bits(n->client),ptr_bits(client));
  }
  if (ip_addr != 0 && ip_low24(n->ip_addr) != ip_low24(ip_addr))
    return 0;
  if (ir_addr != 0 && n->ir_addr != ir_addr)
    return 0;
  if (client != NULL && n->client != client)
    return 0;
  return 1;
}

/* an L2 (this one, a peer, or an application client) */
L2CfgNode *L2CfgMFindL2Node(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  L2CfgNode *l2;

  if (L2CfgDebug)
    fprintf(stderr,"FindL2Node(cfg %08lx, ip %08x, ir %08x, c %08lx)\n",ptr_bits(head),ip_addr,ir_addr,
            ptr_bits(client));
  for (l2 = &head->net; l2 != NULL; l2 = l2->next)
    if (match_node(l2,ip_addr,ir_addr,client))
      return l2;
  for (l2 = head->l2_clients; l2 != NULL; l2 = l2->next)
    if (match_node(l2,ip_addr,ir_addr,client))
      return l2;
  return NULL;
}

L2CfgNode *L2CfgMFindL3Node(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  L2CfgNode *l3;

  if (L2CfgDebug)
    fprintf(stderr,"FindL3Node(cfg %08lx, ip %08x, ir %08x, c %08lx)\n",ptr_bits(head),ip_addr,ir_addr,
            ptr_bits(client));
  for (l3 = head->l3_clients; l3 != NULL; l3 = l3->next)
    if (match_node(l3,ip_addr,ir_addr,client))
      return l3;
  return NULL;
}

/* the first node in the list whose connection's local address is on
 * ip_addr's network (its low 24 bits) */
static L2CfgNode *node_on_net(L2CfgNode *l2, uint32 ip_addr)
{
  uint32 saddr;

  for (; l2 != NULL; l2 = l2->next)
    if (l2->client != NULL && SocketGetSockAddr(l2->client->socket,&saddr) == 0 &&
        ip_low24(saddr) == ip_low24(ip_addr))
      return l2;
  return NULL;
}

/* a node reached through our interface with address ip_addr */
L2CfgNode *L2CfgMFindNodeLocal(L2Cfg *head, uint32 ip_addr)
{
  L2CfgNode *n;

  if (L2CfgDebug)
    fprintf(stderr,"FindNodeLocal(cfg %08lx, ip %08x)\n",ptr_bits(head),ip_addr);
  if ((n = node_on_net(&head->net,ip_addr)) != NULL)
    return n;
  if ((n = node_on_net(head->l2_clients,ip_addr)) != NULL)
    return n;
  return node_on_net(head->l3_clients,ip_addr);
}

/*
 * Any node. An L2 address with rack and slot all ones means this L2: it
 * finds the node with this L2's address and that task.
 */
L2CfgNode *L2CfgMFindNode(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  IRAddress local;
  L2CfgNode *n;
  int tsk;

  if (L2CfgDebug)
    fprintf(stderr,"FindNode(cfg %08lx, ip %08x, ir %08x, c %08lx)\n",ptr_bits(head),ip_addr,ir_addr,
            ptr_bits(client));
  n = L2CfgMFindL2Node(head,ip_addr,ir_addr,client);
  if (n == NULL)
    n = L2CfgMFindL3Node(head,ip_addr,ir_addr,client);
  if (n == NULL && ip_addr == 0 && ir_addr >> 12 == LOCAL_L2_ADDR) {
    tsk = IR_ADDR_TASK(ir_addr);
    local = head->net.ir_addr;
    if (!IR_ADDR_IS_IP(local))
      local = (local & 0xffffffe0) | (tsk & 0x1f);
    else
      local = (local & IR_IP_TASK_MASK) | tsk << 24;
    n = L2CfgMFindL2Node(head,0,local,client);
    if (n == NULL)
      n = L2CfgMFindL3Node(head,0,local,client);
  }
  return n;
}

/* the device of the port open on fd (a static buffer when there is none) */
char *L2CfgMFindDevice(L2Cfg *head, int fd)
{
  static char buff[80];
  int port;

  for (port = 0; port < L2CFG_PORTS; port++) {
    if (head->port_list[port].fd == fd)
      return head->port_list[port].device != NULL ? head->port_list[port].device : "unknown";
  }
  sprintf(buff,"descriptor %d not found",fd);
  return buff;
}

/* the port in use on fd */
L2CfgPort *L2CfgMFindPort(L2Cfg *head, int fd)
{
  int port;

  for (port = 0; port < L2CFG_PORTS; port++)
    if (head->port_list[port].fd == fd && head->port_list[port].state != L2CFG_PORT_FREE)
      return &head->port_list[port];
  return NULL;
}

L2CfgPort *L2CfgMGetPort(L2Cfg *head, int port)
{
  if (port < 0 || port >= L2CFG_PORTS)
    return NULL;
  return &head->port_list[port];
}

/* what fd is, for messages (a static buffer) */
char *L2CfgMDeviceName(L2Cfg *head, int fd)
{
  static char buff[80];
  L2CfgPort *l2port;

  l2port = L2CfgMFindPort(head,fd);
  if (l2port == NULL) {
    sprintf(buff,"[fd %d, not an L1 device]",fd);
    return buff;
  }
  switch (l2port->state) {
  case L2CFG_PORT_FREE:
    sprintf(buff,"[fd %d, unconnected L1]",fd);
    return buff;
  case L2CFG_PORT_OPEN:
    sprintf(buff,"L1 USB device %s [%s]",l2port->device,l2port->usbpath);
    return buff;
  case L2CFG_PORT_CONFIGURED:
    sprintf(buff,"connection to %s",
            L2CfgMAddrStr(head,IR_ADDR_MAKE(IR_ADDR_L1,l2port->l1cfg->rack,l2port->l1cfg->slot & 0x3f,0,0),0));
    return buff;
  default:
    return "no device";
  }
}

/* free what a port holds */
static void free_port(L2CfgPort *port)
{
  free(port->device);
  free(port->usbpath);
  free(port->l1cfg);
}

/* drop a peer L2 from the list (and as our primary) */
int L2CfgMDeleteL2Peer(L2Cfg *head, L2CfgNode *peer)
{
  L2CfgNode *prev = &head->net;
  L2CfgNode *next = head->net.next;
  L2CfgNode *after;
  int port;

  while (next != NULL) {
    if (next != peer) {
      prev = next;
      next = next->next;
      continue;
    }
    prev->next = next->next;
    after = next->next;
    for (port = 0; port < L2CFG_PORTS; port++)
      free_port(&L2CFG_OF(next)->port_list[port]);
    free(next);
    next = after;
  }
  if (peer != NULL && L2CfgLocal.net.msnode == peer) {
    L2CfgLocal.net.msip = 0;
    L2CfgLocal.net.msnode = NULL;
  }
  return 0;
}

/* drop a client node from a list */
int L2CfgDeleteL2Client(L2CfgNode **list, L2CfgNode *client)
{
  L2CfgNode *prev = NULL, *next;

  for (next = *list; next != NULL && next != client; next = next->next)
    prev = next;
  if (next == NULL)
    return 0;
  if (prev == NULL)
    *list = next->next;
  else
    prev->next = next->next;
  free(client);
  return 0;
}

/* NVRAM settings changed */
void L2CfgMEventRack(L2Cfg *head)
{
  head->rack = nvramGet(NVRAM_RACK);
}

void L2CfgMEventSystemSN(L2Cfg *head)
{
  set_field(head->ssn,sizeof(head->ssn),(char *)nvramGet(NVRAM_SERIAL));
}

void L2CfgMEventSystemName(L2Cfg *head)
{
  set_field(head->sysname,sizeof(head->sysname),(char *)nvramGet(NVRAM_SYSNAME));
}

void L2CfgMEventDisplayDisable(L2Cfg *head)
{
  head->l2dsp_disabled = nvramGet(NVRAM_L2DSP_DISABLED);
}

/* "001c05", with "---" or "--" for a missing rack or slot and a note */
void FmtBrick(char *bptr, int rack, int type, int slot)
{
  sprintf(bptr,"%03d%c%02d",rack,brickTypeToChar(type),slot);
  if (rack == 0)
    memset(bptr,'-',3);
  if (slot == 0)
    memset(bptr + 4,'-',2);
  if (rack == 0 && slot == 0)
    strcat(bptr," (no rack and slot ID set)");
  else if (rack == 0)
    strcat(bptr," (no rack ID set)");
  else if (slot == 0)
    strcat(bptr," (no slot ID set)");
}

/* is the brick type a router's (no partition shown)? */
static int router_type(unsigned char type)
{
  return type == '-' || type == 'D' || type == 'R';
}

/* "L1 <ip>:<port>:<index>  - <brick>.<partition>" */
static void format_l1(char *rptr, L2CfgNode *l2node, int port, int l1, int mode)
{
  L2CfgPort *l2port = &L2CFG_OF(l2node)->port_list[port];
  L2CfgL1 *cfg = &l2port->l1cfg[l1];

  sprintf(rptr,"L1 %s:%d:%d           ",SocketAddrStr(l2node->ip_addr),port,(unsigned int)cfg->index);
  rptr[25] = '\0';
  strcat(rptr,"- ");
  rptr += strlen(rptr);
  if (!cfg->configured && cfg->conn_state == 1) {
    strcat(rptr,l1 == 0 ? "C/R/G brick (USB connection)" : "C or I/O brick (422 connection)");
    strcat(rptr," not configured\n");
    return;
  }
  FmtBrick(rptr,cfg->rack,cfg->type,cfg->slot);
  if (!router_type(cfg->type) && cfg->partition != 0)
    sprintf(rptr + strlen(rptr),".%-3d",(unsigned int)cfg->partition);
  else
    strcat(rptr,"    ");
  if (mode == 2)
    sprintf(rptr + strlen(rptr)," %s(%s %s)\n","",l2port->usbpath,l2port->device);
  else
    strcat(rptr,"\n");
}

/* the rack and slot of a port's first L1, for sorting */
static uint32 port_rackslot(L2CfgPort *port)
{
  return (uint32)port->l1cfg->rack << 16 | port->l1cfg->slot;
}

/* "L2 <ip>: - <rack>[-PRI|-SEC (<ip>)][ (LOCAL)]", then (show_l1) its
 * L1s, the ports by rack and slot, highest first */
static void format_l2(char *rptr, L2CfgNode *l2node, L2Cfg *head, int mode, int show_l1)
{
  L2Cfg *l2 = L2CFG_OF(l2node);
  L2CfgPort *l2port;
  char ipstr[20];
  char rackstr[32];
  int l1list[L2CFG_PORTS];
  int l1cnt = 0;
  uint32 rackslot;
  int port, i, l1;

  set_field(ipstr,sizeof(ipstr),SocketAddrStr(l2node->ip_addr));
  if (l2->rack == 0)
    strcpy(rackstr,"---- (no rack ID set)");
  else
    sprintf(rackstr,"%04d",l2->rack);
  if (mode == 2)
    sprintf(rptr,"L2 %s: - %s (IR %08x, C %08lx)",ipstr,rackstr,l2node->ir_addr,ptr_bits(l2node->client));
  else
    sprintf(rptr,"L2 %s: - %s",ipstr,rackstr);
  rptr += strlen(rptr);
  if (l2node->msmode == 2)
    sprintf(rptr,"-PRI");
  else if (l2node->msmode == 1)
    sprintf(rptr,"-SEC (%s)",SocketAddrStr(l2node->msip));
  strcat(rptr,(L2Cfg *)l2node == head ? " (LOCAL)\n" : "\n");
  rptr += strlen(rptr);
  if (!show_l1)
    return;

  for (port = 0; port < L2CFG_PORTS; port++) {
    l2port = &l2->port_list[port];
    if (l2port->state == L2CFG_PORT_FREE || l2port->l1cfg == NULL)
      continue;
    /* (a port not yet configured sorts as 0; the ones listed by their
     * first L1 in any case) */
    rackslot = l2port->state == L2CFG_PORT_CONFIGURED ? port_rackslot(l2port) : 0;
    for (i = 0; i < l1cnt && rackslot <= port_rackslot(&l2->port_list[l1list[i]]); i++)
      ;
    memmove(l1list + i + 1,l1list + i,(l1cnt - i) * sizeof(l1list[0]));
    l1list[i] = port;
    l1cnt++;
  }
  for (i = 0; i < l1cnt; i++) {
    l2port = &l2->port_list[l1list[i]];
    if (l2port->state == L2CFG_PORT_CONFIGURED) {
      for (l1 = 0; l1 < l2port->l1count; l1++) {
        if (l2port->l1cfg[l1].configured || l2port->l1cfg[l1].conn_state) {
          format_l1(rptr,l2node,l1list[i],l1,mode);
          rptr += strlen(rptr);
        }
      }
    }
    else {
      sprintf(rptr,"L1 %s:%d              ",SocketAddrStr(l2node->ip_addr),l1list[i]);
      rptr[25] = '\0';
      rptr += strlen(rptr);
      sprintf(rptr,"- USB not configured  (%s %s)\n",l2port->usbpath,l2port->device);
      rptr += strlen(rptr);
    }
  }
}

/* count a brick of the summary by its class */
struct brick_counts {
  int r, c, i, x, p, pe, g, n, others, noconfig;
};

static void count_brick(struct brick_counts *n, L2CfgL1 *l1c)
{
  switch (l1c->type) {
  case '#': case 'J': case 'P':
    n->p++;
    return;
  case '%':
    n->pe++;
    return;
  case '-': case 'D': case 'R':
    n->r++;
    return;
  case '=': case 'I': case 'K':
    n->i++;
    return;
  case 'G':
    n->g++;
    return;
  case 'N':
    n->n++;
    return;
  case 'X':
    n->x++;
    return;
  }
  if (brickIsCompute(l1c->type))
    n->c++;
  else if (!l1c->configured)
    n->noconfig++;
  else
    n->others++;
}

/* append the count's line if n is not zero */
static char *put_count(char *rptr, const char *fmt, int n) __attribute__((format(printf, 2, 0)));
static char *put_count(char *rptr, const char *fmt, int n)
{
  if (n != 0)
    rptr += sprintf(rptr,fmt,n);
  return rptr;
}

/* "   <ip>: (IR <addr>) user (name) @ host running 'proc'" for each client */
static char *format_clients(char *rptr, L2CfgNode *list, const char *title)
{
  RouterClient *c;
  L2CfgNode *n;

  for (n = list; n != NULL; n = n->next) {
    if (n == list) {
      strcpy(rptr,title);
      rptr += strlen(rptr);
    }
    sprintf(rptr,"   %s: (IR %0x)",SocketAddrStr(n->ip_addr),n->ir_addr);
    rptr += strlen(rptr);
    c = n->client;
    if (c == NULL)
      strcat(rptr,"\n");
    else
      sprintf(rptr," %s (%s) @ %s running \'%s\'\n",c->id.username,c->id.fullname,c->id.hostname,
              c->id.procname);
    rptr += strlen(rptr);
  }
  return rptr;
}

#define LINE_SIZE   160         /* a line of L2CfgMPrint() (75 in the original: too few) */
#define CLIENT_LINE 200         /* ... a client's */

/*
 * The configuration as text (malloc()ed into *rrptr): mode 0 a summary of
 * the L2s and bricks; 1 the L2s (sorted by rack) with, if show_l1, their
 * L1s; 2 the same in more detail, with the clients.
 */
void L2CfgMPrint(L2Cfg *head, char **rrptr, int mode, int show_l1)
{
  L2CfgNode *l2list[256];
  L2CfgNode *l2node, *n;
  L2CfgPort *pp;
  L2CfgL1 *l1c;
  struct brick_counts counts;
  char found[4096];             /* brick serial numbers counted, "sn,sn," */
  int l2s = 0, l1s = 0, ports_connected = 0, ports_configured = 0;
  int l2cnt = 0, count, port, l1, i;
  char *rptr;

  *rrptr = NULL;
  if (mode == 0) {
    memset(&counts,0,sizeof(counts));
    found[0] = '\0';
    for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
      l2s++;
      for (port = 0; port < L2CFG_PORTS; port++) {
        pp = &L2CFG_OF(l2node)->port_list[port];
        if (pp->state == L2CFG_PORT_FREE)
          continue;
        ports_connected++;
        if (pp->state != L2CFG_PORT_CONFIGURED)
          continue;
        ports_configured++;
        for (l1 = 0; l1 < pp->l1count; l1++) {
          l1c = &pp->l1cfg[l1];
          if (!l1c->configured && !l1c->conn_state)
            continue;
          if (l1c->brick_sn[0] != '\0') {
            if (strstr(found,l1c->brick_sn) != NULL)
              continue;         /* (seen through another L2) */
            /* (the original's check of 7 bytes did not cover the serial number) */
            if (strlen(found) + strlen(l1c->brick_sn) + 2 < sizeof(found)) {
              strcat(found,l1c->brick_sn);
              strcat(found,",");
            }
          }
          l1s++;
          count_brick(&counts,l1c);
        }
      }
    }
    rptr = malloc(800);
    *rrptr = rptr;
    if (rptr == NULL)
      return;
    rptr += sprintf(rptr,"L2s: %d\n",l2s);
    rptr += sprintf(rptr,"L1s: %d",l1s);
    if (ports_configured == ports_connected)
      rptr += sprintf(rptr,"\n");
    else
      rptr += sprintf(rptr,"  (%d USB connections not configured)\n",ports_connected - ports_configured);
    rptr = put_count(rptr,"  BRICKS NOT CONFIGURED: %d\n",counts.noconfig);
    rptr = put_count(rptr,"  R Bricks: %d\n",counts.r);
    rptr = put_count(rptr,"  C Bricks: %d\n",counts.c);
    rptr = put_count(rptr,"  I Bricks: %d\n",counts.i);
    rptr = put_count(rptr,"  X Bricks: %d\n",counts.x);
    rptr = put_count(rptr,"  P Bricks: %d\n",counts.p);
    rptr = put_count(rptr,"  PE Bricks: %d\n",counts.pe);
    rptr = put_count(rptr,"  G Bricks: %d\n",counts.g);
    rptr = put_count(rptr,"  N Bricks: %d\n",counts.n);
    put_count(rptr,"  Other:    %d\n",counts.others);
    return;
  }

  /* (the original counted only the L1 lines of configured ports, at 75
   * bytes each: unconfigured ports' lines, and long names, overran it) */
  count = 0;
  for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
    count += LINE_SIZE;
    for (port = 0; port < L2CFG_PORTS; port++) {
      pp = &L2CFG_OF(l2node)->port_list[port];
      if (pp->state == L2CFG_PORT_FREE || pp->l1cfg == NULL)
        continue;
      count += (pp->state == L2CFG_PORT_CONFIGURED ? pp->l1count : 1) *
               (LINE_SIZE + (pp->device ? strlen(pp->device) : 6) + (pp->usbpath ? strlen(pp->usbpath) : 6));
    }
  }
  if (mode == 2) {
    count += 2 * LINE_SIZE;
    for (n = head->l2_clients; n != NULL; n = n->next)
      count += CLIENT_LINE;
    for (n = head->l3_clients; n != NULL; n = n->next)
      count += CLIENT_LINE;
  }
  rptr = malloc(count + 1);
  *rrptr = rptr;
  if (rptr == NULL)
    return;
  *rptr = '\0';
  /* the L2s by rack (among equal racks, as found) */
  for (l2node = &head->net; l2node != NULL && l2cnt < 256; l2node = l2node->next) {
    for (i = 0; i < l2cnt && L2CFG_OF(l2list[i])->rack <= L2CFG_OF(l2node)->rack; i++)
      ;
    memmove(l2list + i + 1,l2list + i,(l2cnt - i) * sizeof(*l2list));
    l2list[i] = l2node;
    l2cnt++;
  }
  for (i = 0; i < l2cnt; i++) {
    format_l2(rptr,l2list[i],head,mode,show_l1);
    rptr += strlen(rptr);
  }
  if (mode != 1) {
    rptr = format_clients(rptr,head->l2_clients,"L2 Clients:\n");
    format_clients(rptr,head->l3_clients,"L3 Clients:\n");
  }
}

/* add a brick to a list sorted by rack * 100 + slot, highest first;
 * returns the new count */
static int add_brick(struct list_t *list, int count, int max, L2CfgL1 *l1c, int l2rack)
{
  int rs = l1c->slot + l1c->rack * 100;
  int n;

  for (n = 0; n < count; n++)
    if (list[n].rs == rs)
      return count;             /* (seen through another L2) */
  if (count == max)
    return count;               /* (the original did not stop) */
  for (n = 0; n < count && list[n].rs >= rs; n++)
    ;
  memmove(list + n + 1,list + n,(count - n) * sizeof(*list));
  list[n].rs = rs;
  list[n].type = l1c->type;
  list[n].part = l1c->partition;
  list[n].l2 = l2rack;
  return count + 1;
}

/* every brick once, sorted (into list, at most max) */
static int collect_bricks(L2Cfg *head, struct list_t *list, int max)
{
  L2CfgNode *l2node;
  L2CfgPort *pp;
  int count = 0;
  int port, l1;

  for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
    for (port = 0; port < L2CFG_PORTS; port++) {
      pp = &L2CFG_OF(l2node)->port_list[port];
      if (pp->state != L2CFG_PORT_CONFIGURED)
        continue;
      for (l1 = 0; l1 < pp->l1count; l1++)
        if (pp->l1cfg[l1].configured || pp->l1cfg[l1].conn_state)
          count = add_brick(list,count,max,&pp->l1cfg[l1],L2CFG_OF(l2node)->rack);
    }
  }
  return count;
}

#define MAX_BRICKS  1024

/* "config list": the bricks, eight to a line, a line per rack */
void L2CfgMPrintX(L2Cfg *head, char **rrptr)
{
  static struct list_t list[MAX_BRICKS];
  int count, col = 0, lrack = 0, i;
  char *rptr;

  count = collect_bricks(head,list,MAX_BRICKS);
  /* (the original had no room for its "\n0 bricks\n" with no bricks) */
  rptr = malloc(count * 0x50 + 32);
  *rrptr = rptr;
  if (rptr == NULL)
    return;
  *rptr = '\0';
  for (i = 0; i < count; i++) {
    if ((col != 0 && list[i].rs / 100 != lrack) || col == 8) {
      strcat(rptr,"\n");
      rptr += strlen(rptr);
      col = 0;
    }
    sprintf(rptr,"%03d%c%02d",list[i].rs / 100,brickTypeToChar(list[i].type),list[i].rs % 100);
    if (list[i].part == 0)
      strcat(rptr,"   ");
    else
      sprintf(rptr + strlen(rptr),".%-2d",list[i].part);
    if (++col != 8)
      strcat(rptr," ");
    rptr += strlen(rptr);
    lrack = list[i].rs / 100;
  }
  sprintf(rptr,"\n%d bricks\n",count);
}

/* the bricks as "001c05,001c08,..." */
void L2CfgMPrintY(L2Cfg *head, char **rrptr)
{
  static struct list_t list[MAX_BRICKS];
  int count, i;
  char *rptr;

  count = collect_bricks(head,list,MAX_BRICKS);
  rptr = malloc(count * 16 + 2);        /* (malloc(0) and two bytes in the original) */
  *rrptr = rptr;
  if (rptr == NULL)
    return;
  *rptr = '\0';
  for (i = 0; i < count; i++) {
    sprintf(rptr,"%03d%c%02d,",list[i].rs / 100,brickTypeToChar(list[i].type),list[i].rs % 100);
    rptr += strlen(rptr);       /* (a type 0 brick's '\0' cuts the text there: as the original) */
  }
  strcat(rptr,"\n");
}

/* l2: an L1 port opened on conn_fd (no configuration yet) */
int L2CfgMAddPort(L2Cfg *head, int port, char *device, char *usbpath, int conn_type, int conn_fd)
{
  L2CfgPort *pptr;

  if (head->port_count >= L2CFG_PORTS)
    return -1;
  head->port_count++;           /* (counted even when the port is in use: as the original) */
  pptr = &head->port_list[port];
  if (pptr->state != L2CFG_PORT_FREE)
    return -1;
  pptr->state = L2CFG_PORT_OPEN;
  pptr->type = conn_type;
  pptr->fd = conn_fd;
  free(pptr->device);
  pptr->device = strdup(device);
  free(pptr->usbpath);
  pptr->usbpath = strdup(usbpath);
  free(pptr->l1cfg);
  pptr->l1cfg = NULL;
  pptr->l1count = 0;
  return 0;
}

/* the port on conn_fd closed */
int L2CfgMDeletePort(L2Cfg *head, int conn_fd)
{
  L2CfgPort *port;

  port = L2CfgMFindPort(head,conn_fd);
  if (port == NULL)
    return -1;
  if (head->port_count != 0)
    head->port_count--;
  free_port(port);
  port->device = NULL;
  port->usbpath = NULL;
  port->l1cfg = NULL;
  port->l1count = 0;
  port->fd = -1;
  port->state = L2CFG_PORT_FREE;
  return 0;
}

/* an argument that is a string (or data) */
static char *arg_ptr(IRPacket *p, int arg)
{
  if (IR_ARG_TYPE(p->_argv[arg]) == IR_ARG_VALUE)
    return (char *)IR_VAL_PTR(p->_argv[arg]._val);
  return (char *)IRArg(p,arg);
}

/* copy a serial number field (12 bytes, perhaps unterminated) */
static void set_sn(char *dst, const char *src)
{
  /* (the original strcpy()ed, running on when all 12 bytes were used) */
  snprintf(dst,12,"%.*s",11,src);
}

/*
 * A revision 1 configuration event: the number of L2s, then for each its
 * port count and an L2CfgIRouter (big-endian). (Every L2's ports go into
 * head's, as in the original.)
 */
void L2CfgMCfgL2_rev1(L2Cfg *head, IRPacket *pkt)
{
  L2CfgIRouter *l2cfg;
  L2CfgPort *pp;
  L2CfgL1 *l1cfg;
  int l2s, ports, l2i, port, l1;

  if (IR_ARG_TYPE(pkt->_argv[0]) != IR_ARG_VALUE)
    IRArg(pkt,0);               /* (fetched and not looked at, as the revision) */
  if (IR_ARG_TYPE(pkt->_argv[1]) != IR_ARG_VALUE)
    IRArg(pkt,1);
  l2s = IR_ARG_TYPE(pkt->_argv[2]) == IR_ARG_VALUE ? (int)pkt->_argv[2]._val : (int)IRArg(pkt,2);
  for (l2i = 0; l2i < l2s; l2i++) {
    ports = IR_ARG_TYPE(pkt->_argv[l2i * 2 + 3]) == IR_ARG_VALUE ? (int)pkt->_argv[l2i * 2 + 3]._val
                                                                 : (int)IRArg(pkt,l2i * 2 + 3);
    l2cfg = (L2CfgIRouter *)arg_ptr(pkt,l2i * 2 + 4);
    if (ports > L2CFG_PORTS)
      ports = L2CFG_PORTS;      /* (the original did not check) */
    for (port = 0; port < ports; port++) {
      pp = &head->port_list[port];
      pp->state = ntohl(l2cfg->port[port].state);
      if (pp->state != L2CFG_PORT_CONFIGURED)
        continue;
      free(pp->l1cfg);
      pp->l1cfg = calloc(L1S_PER_PORT_REV1,sizeof(L2CfgL1));
      pp->l1count = L1S_PER_PORT_REV1;
      for (l1 = 0; l1 < L1S_PER_PORT_REV1; l1++) {
        l1cfg = &pp->l1cfg[l1];
        l1cfg->configured = ntohl(l2cfg->port[port].l1[l1].state);
        if (!l1cfg->configured)
          continue;
        l1cfg->rack = ntohl(l2cfg->port[port].l1[l1].rack);
        l1cfg->slot = ntohl(l2cfg->port[port].l1[l1].slot);
        l1cfg->type = ntohl(l2cfg->port[port].l1[l1].type);
        l1cfg->router_type = ntohl(l2cfg->port[port].l1[l1].router_type);
        set_sn(l1cfg->brick_sn,l2cfg->port[port].l1[l1].brick_sn);
        set_sn(l1cfg->system_sn,l2cfg->port[port].l1[l1].system_sn);
      }
    }
  }
}

/* the os codes of "l2os" */
static const char *const os_names[] = { NULL, "linux", "ppclinux", "armlinux", "irix" };

static unsigned int os_code(const char *name)
{
  unsigned int os;

  for (os = 1; os < sizeof(os_names) / sizeof(os_names[0]); os++)
    if (strcmp(name,os_names[os]) == 0)
      return os;
  return 0;
}

/* copy a string into a newly allocated port field */
static void set_port_string(char **field, const char *value)
{
  free(*field);                 /* (the original leaked the old one) */
  *field = strdup(value);
}

/* an L1 setting of "key:value" (keys of either case); 0 if key is not one */
static int set_l1_field(L2CfgL1 *l1, const char *key, const char *val)
{
  if (strcasecmp(key,"rack") == 0)
    l1->rack = atoi(val);
  else if (strcasecmp(key,"slot") == 0)
    l1->slot = atoi(val);
  else if (strcasecmp(key,"conena") == 0)
    l1->console_enabled = atoi(val);
  else if (strcasecmp(key,"consub") == 0)
    l1->console_subchannel = atoi(val);
  else if (strcasecmp(key,"type") == 0)
    l1->type = atoi(val);
  else if (strcasecmp(key,"sh_amode") == 0)
    l1->shub_addrmode = atoi(val);
  else if (strcasecmp(key,"sh_shrmode") == 0)
    l1->shub_shrmode = atoi(val);
  else if (strcasecmp(key,"rtype") == 0)
    l1->router_type = atoi(val);
  else if (strcasecmp(key,"pstate") == 0)
    l1->power_state = atoi(val);
  else if (strcasecmp(key,"mstate") == 0)
    l1->margin_state = atoi(val);
  else if (strcasecmp(key,"estate") == 0)
    l1->env_state = atoi(val);
  else if (strcasecmp(key,"cstate") == 0) {
    l1->conn_state = atoi(val);
    if (l1->conn_state == 1)
      l1->configured = 0;
  }
  else if (strcasecmp(key,"part") == 0)
    l1->partition = atoi(val);
  else if (strcasecmp(key,"bsn") == 0)
    set_sn(l1->brick_sn,val);
  else if (strcasecmp(key,"ssn") == 0)
    set_sn(l1->system_sn,val);
  else
    return 0;
  return 1;
}

/*
 * A configuration event (L2CfgMQuery()'s text in its string arguments
 * from the third on: "key:value," pairs) from another L2 or, in an L3
 * tool, from ours. "l2:<ip>" selects an L2 (added if new, when we keep
 * the whole system: in an L3 tool, or as a primary), "port:<n>" one of
 * its ports, "l1:<index>" adds an L1 there; the other keys set what they
 * name. In l2, our own entry is never changed. (Out-of-range ports and
 * L1s, empty pairs and long values are ignored or cut short here; the
 * original wrote past its arrays.)
 */
void L2CfgMCfgL2(L2Cfg *head, IRPacket *p)
{
  L2CfgNode *l2node = NULL;     /* the L2 selected by "l2" */
  L2Cfg *l2 = NULL;             /* ... if its entry may change */
  L2CfgNode *peer, *next_peer;
  L2CfgPort *pp;
  L2CfgL1 *l1c;
  unsigned int port = 0;
  int l1 = -1;                  /* the L1 "l1" last added (the original left it unset) */
  int argc = p->_argc;
  int rev, a, n;
  size_t len = 0;
  char *text, *seg, *next, *comma, *key, *val, *c;
  unsigned long part;
  uint32 ip;

  rev = IR_ARG_TYPE(p->_argv[1]) == IR_ARG_VALUE ? (int)p->_argv[1]._val : (int)IRArg(p,1);
  if (rev == 1) {
    if (L2CfgDebug)
      fprintf(stderr,"L2CfgCfgL2:  rev 1 config\n");
    L2CfgMCfgL2_rev1(head,p);
    return;
  }

  /* the text: the string arguments end to end */
  for (a = 2; a < argc; a++)
    if ((c = arg_ptr(p,a)) != NULL)
      len += strlen(c);
  text = calloc(1,len + 1);
  for (a = 2, len = 0; a < argc; a++) {
    if ((c = arg_ptr(p,a)) != NULL) {
      memcpy(text + len,c,strlen(c));
      len += strlen(c);
    }
  }

  for (seg = text; seg != NULL && *seg != '\0'; seg = next) {
    comma = strchr(seg,',');
    next = NULL;
    if (comma != NULL) {
      *comma = '\0';
      next = comma + 1;
    }
    key = strtok(seg,":");
    val = strtok(NULL,":");
    if (val == NULL)
      val = "";
    if (key == NULL)
      continue;                 /* (an empty pair) */
    pp = l2 != NULL && port < L2CFG_PORTS ? &l2->port_list[port] : NULL;

    if (strcmp(key,"l2") == 0) {
      ip = inet_addr(val);
      l2node = L2CfgMFindNode(head,ip,0,NULL);
      if (l2node == NULL) {
        if (L2CfgMode == 2 || head->net.msmode == 2) {
          if (L2CfgMAddL2(head,ip,IR_PORT_BIAS + L2_PEER_PORT,NULL,&l2node) < 0)
            l2node = NULL;
          if (L2CfgMode == 2 && l2node != NULL)
            l2node->client = (RouterClient *)l2node;    /* (connected, for an L3 tool) */
        }
      }
      else if (L2CfgMode != 2 && (L2Cfg *)l2node == &L2CfgLocal) {
        l2node = NULL;
      }
      l2 = (L2Cfg *)l2node;
    }
    else if (strcmp(key,"DELETE_L2") == 0) {
      if (l2node != NULL) {     /* (the original went ahead) */
        L2CfgMDeleteNode(head,l2node->client);
        if ((L2Cfg *)l2node != head)
          l2 = NULL;            /* (freed: the original went on writing to it) */
      }
      l2node = NULL;
    }
    else if (strcmp(key,"l2events") == 0) {
      if (l2 != NULL) {
        l2node->events = strtoul(val,NULL,16);
        memset(l2node->pselect,0,sizeof(l2node->pselect));
      }
    }
    else if (strncmp(key,"pselect",7) == 0) {
      if (l2 == NULL)
        continue;
      if (*val == '*') {
        memset(l2node->pselect,0xff,sizeof(l2node->pselect));
        continue;
      }
      for (c = strtok(val,"."); c != NULL; c = strtok(NULL,".")) {
        part = strtoul(c,NULL,10);
        if (part < sizeof(l2node->pselect))
          l2node->pselect[part] = 1;
      }
    }
    else if (strcmp(key,"l2rack") == 0) {
      if (l2 != NULL) {
        /* (clears rack, ssn, sysname and the display flag) */
        memset(&l2->rack,0,offsetof(L2Cfg,port_count) - offsetof(L2Cfg,rack));
        l2->rack = atoi(val);
        l2->net.os = 0;
      }
    }
    else if (strcmp(key,"l2ssn") == 0) {
      if (l2 != NULL)
        set_field(l2->ssn,sizeof(l2->ssn),val);
    }
    else if (strcmp(key,"l2name") == 0) {
      if (l2 != NULL)
        set_field(l2->sysname,sizeof(l2->sysname),val);
    }
    else if (strcmp(key,"l2dspdis") == 0) {
      if (l2 != NULL)
        l2->l2dsp_disabled = atoi(val);
    }
    else if (strcmp(key,"l2os") == 0) {
      if (l2 != NULL)
        l2->net.os = os_code(val);
    }
    else if (strcmp(key,"l2sec") == 0) {
      if (l2 != NULL) {
        l2->net.msmode = 1;
        l2->net.msip = inet_addr(val);
        l2->net.msnode = L2CfgMFindL2Node(head,l2->net.msip,0,NULL);
      }
    }
    else if (strcmp(key,"l2pri") == 0) {
      if (l2 != NULL) {
        l2->net.msmode = 2;
        l2->net.msip = 0;
        l2->net.msnode = NULL;
        /* drop the secondaries (the original read peer->next after freeing the peer) */
        for (peer = head->net.next; peer != NULL; peer = next_peer) {
          next_peer = peer->next;
          if (peer->msmode == 1)
            L2CfgMDeleteL2Peer(head,peer);
        }
      }
    }
    else if (strcmp(key,"port") == 0) {
      port = atoi(val);
      if (l2 != NULL && port == 0) {
        /* the first port: the L2's ports start over */
        for (n = 0; n < L2CFG_PORTS; n++)
          free_port(&l2->port_list[n]);
        memset(l2->port_list,0,sizeof(l2->port_list));
        l2->port_count = 0;
        if (l2->net.msmode == 2 && head->net.msmode == 1)
          l2 = NULL;            /* (a secondary takes no ports from its primary) */
      }
      if (l2 != NULL)
        l2->port_count++;
    }
    else if (strcmp(key,"state") == 0) {
      if (pp != NULL)
        pp->state = atoi(val);
    }
    else if (strcmp(key,"device") == 0) {
      if (pp != NULL)
        set_port_string(&pp->device,val);
    }
    else if (strcmp(key,"usbp") == 0) {
      if (pp != NULL)
        set_port_string(&pp->usbpath,val);
    }
    else if (strcasecmp(key,"l1") == 0) {
      if (pp == NULL) {
        l1 = atoi(val);         /* (as the original: then the index of nothing) */
        continue;
      }
      pp->l1cfg = realloc(pp->l1cfg,(pp->l1count + 1) * sizeof(L2CfgL1));
      l1c = &pp->l1cfg[pp->l1count];
      memset(l1c,0,sizeof(*l1c));
      l1c->index = atoi(val);
      l1c->configured = 1;
      l1c->conn_state = 2;
      l1 = pp->l1count++;
    }
    else if (pp != NULL && l1 >= 0 && l1 < pp->l1count) {
      set_l1_field(&pp->l1cfg[l1],key,val);
    }
  }
  free(text);
  L2CfgMGetConsole(head,-1);
}

/*
 * Add an L1's configuration (an L1CfgL1 of up to 112 bytes, size of them
 * at cfgp: in the L1's byte order, recognized by its small fields) to a
 * port, as L1 l1 with index index.
 */
static int l1l2(L2CfgPort *l2port, int l1, int index, char *cfgp, int size)
{
  L2CfgL1 l2_l1cfg;
  L1CfgL1 l1_l1cfg;

  if ((unsigned int)size > sizeof(L1CfgL1))
    size = sizeof(L1CfgL1);
  memset(&l1_l1cfg,0,sizeof(l1_l1cfg));
  memset(&l2_l1cfg,0,sizeof(l2_l1cfg));
  memcpy(&l1_l1cfg,cfgp,size);
  l2_l1cfg.index = index;
  if (l1_l1cfg.revision < 0x100 && l1_l1cfg.configured < 0x100 && l1_l1cfg.type < 0x100 &&
      l1_l1cfg.rack < 0x100 && l1_l1cfg.slot < 0x100) {
    /* in our byte order */
    l2_l1cfg.revision = l1_l1cfg.revision;
    l2_l1cfg.configured = l1_l1cfg.configured;
    l2_l1cfg.type = l1_l1cfg.type;
    l2_l1cfg.rack = l1_l1cfg.rack;
    l2_l1cfg.slot = l1_l1cfg.slot;
    l2_l1cfg.partition = l1_l1cfg.partition;
    l2_l1cfg.console_subchannel = l1_l1cfg.console_subchannel;
    l2_l1cfg.console_enabled = l1_l1cfg.console_enabled;
    l2_l1cfg.router_type = l1_l1cfg.router_type;
    l2_l1cfg.power_state = l1_l1cfg.power_state;
    l2_l1cfg.margin_state = l1_l1cfg.margin_state;
    l2_l1cfg.env_state = l1_l1cfg.env_state;
    l2_l1cfg.conn_state = l1_l1cfg.conn_state;
  }
  else {
    /* big-endian */
    l2_l1cfg.revision = ntohl(l1_l1cfg.revision);
    l2_l1cfg.configured = ntohl(l1_l1cfg.configured);
    l2_l1cfg.type = ntohl(l1_l1cfg.type);
    l2_l1cfg.rack = ntohl(l1_l1cfg.rack);
    l2_l1cfg.slot = ntohl(l1_l1cfg.slot);
    l2_l1cfg.partition = ntohl(l1_l1cfg.partition);
    l2_l1cfg.console_subchannel = ntohl(l1_l1cfg.console_subchannel);
    l2_l1cfg.console_enabled = ntohl(l1_l1cfg.console_enabled);
    l2_l1cfg.router_type = ntohl(l1_l1cfg.router_type);
    l2_l1cfg.power_state = ntohl(l1_l1cfg.power_state);
    l2_l1cfg.margin_state = ntohl(l1_l1cfg.margin_state);
    l2_l1cfg.env_state = ntohl(l1_l1cfg.env_state);
    l2_l1cfg.conn_state = ntohl(l1_l1cfg.conn_state);
  }
  l2_l1cfg.shub_addrmode = l1_l1cfg.shub_addrmode;
  l2_l1cfg.shub_shrmode = l1_l1cfg.shub_shrmode;
  set_sn(l2_l1cfg.brick_sn,l1_l1cfg.brick_sn);
  set_sn(l2_l1cfg.system_sn,l1_l1cfg.system_sn);
  if (l2_l1cfg.conn_state == 0 && l2_l1cfg.configured)
    l2_l1cfg.conn_state = 2;
  l2port->l1cfg = realloc(l2port->l1cfg,(l2port->l1count + 1) * sizeof(L2CfgL1));
  l2port->l1count++;
  l2port->l1cfg[l1] = l2_l1cfg;
  return 0;
}

/*
 * l2: an L1 port's configuration response p (NULL: the port closed).
 * Its first argument says the form: 6, four L1CfgL1s (indexes 0, 1, 5,
 * 6); 7, a count, the size of each, their indexes and the L1CfgL1s.
 * Returns whether the port's configuration changed.
 */
int L2CfgMCfgPort(L2Cfg *head, int port, IRPacket *p)
{
  static int cvt[4] = { 0, 1, 5, 6 };
  L2CfgPort *l2port = &L2CfgLocal.port_list[port];
  L2CfgL1 *old_l1cfg;
  int old_l1count, cfg_changed, form, count, rsp, l1;
  char *idxp, *cfgp;

  if (p == NULL) {
    cfg_changed = l2port->state != L2CFG_PORT_FREE;
    l2port->state = L2CFG_PORT_FREE;
    free_port(l2port);
    l2port->device = NULL;
    l2port->usbpath = NULL;
    l2port->l1count = 0;
    l2port->l1cfg = NULL;
    if (head->port_count != 0)
      head->port_count--;
  }
  else {
    form = IR_ARG_TYPE(p->_argv[0]) == IR_ARG_VALUE ? (int)p->_argv[0]._val : (int)IRArg(p,0);
    old_l1count = l2port->l1count;
    old_l1cfg = l2port->l1cfg;
    l2port->l1cfg = NULL;
    l2port->l1count = 0;
    l2port->state = L2CFG_PORT_CONFIGURED;
    if (form == 6) {
      for (l1 = 0; l1 < 4; l1++)
        l1l2(l2port,l1,cvt[l1],arg_ptr(p,l1 + 1),p->_argv[l1 + 1]._size);
    }
    else if (form == 7) {
      if (IR_ARG_TYPE(p->_argv[1]) != IR_ARG_VALUE)
        IRArg(p,1);
      count = IR_ARG_TYPE(p->_argv[2]) == IR_ARG_VALUE ? (int)p->_argv[2]._val : (int)IRArg(p,2);
      rsp = IR_ARG_TYPE(p->_argv[3]) == IR_ARG_VALUE ? (int)p->_argv[3]._val : (int)IRArg(p,3);
      idxp = arg_ptr(p,4);
      cfgp = arg_ptr(p,5);
      for (l1 = 0; l1 < count; l1++)
        l1l2(l2port,l1,idxp[l1],cfgp + l1 * rsp,rsp);
    }
    if (old_l1count == l2port->l1count)
      cfg_changed = old_l1count != 0 &&
                    memcmp(old_l1cfg,l2port->l1cfg,old_l1count * sizeof(L2CfgL1)) != 0;
    else
      cfg_changed = 1;
    free(old_l1cfg);
  }
  if (cfg_changed)
    L2CfgMGetConsole(head,-1);
  return cfg_changed;
}

/* the rack and slot of the configured L1 with this index on ip's port */
int L2CfgMFindBrickRS(L2Cfg *head, int ip, int port, int index, int *rack, int *slot)
{
  L2CfgNode *l2node;
  L2CfgPort *l2port;
  int l1;

  for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
    if (l2node->ip_addr != (uint32)ip || port >= L2CFG_PORTS)
      continue;
    l2port = &L2CFG_OF(l2node)->port_list[port];
    if (l2port->state != L2CFG_PORT_CONFIGURED)
      return -1;
    for (l1 = 0; l1 < l2port->l1count; l1++) {
      if (l2port->l1cfg[l1].index == index && l2port->l1cfg[l1].configured) {
        *rack = l2port->l1cfg[l1].rack;
        *slot = l2port->l1cfg[l1].slot;
        return 0;
      }
    }
  }
  return -1;
}

/* where the brick at rack.slot is: its L2's address, port and L1 index
 * (the lowest index, on the first L2 that has it); the port, or -1 */
int L2CfgMFindBrickIP(L2Cfg *head, int rack, int slot, int *ip, int *p, int *l)
{
  L2CfgNode *l2node;
  L2CfgPort *l2port;
  L2CfgL1 *c;
  int port, l1;

  *ip = -1;
  *p = -1;
  *l = -1;
  for (l2node = &head->net; *p == -1 && l2node != NULL; l2node = l2node->next) {
    for (port = 0; port < L2CFG_PORTS; port++) {
      l2port = &L2CFG_OF(l2node)->port_list[port];
      if (l2port->state != L2CFG_PORT_CONFIGURED)
        continue;
      for (l1 = 0; l1 < l2port->l1count; l1++) {
        c = &l2port->l1cfg[l1];
        if (c->configured && c->rack == rack && c->slot == slot && (*l == -1 || c->index < *l)) {
          *ip = l2node->ip_addr;
          *p = port;
          *l = c->index;
        }
      }
    }
  }
  return *p;
}

/* the first configured L1 at rack.slot (configured only, if configured) */
static L2CfgL1 *find_l1(L2CfgNode *l2node, int rack, int slot, int configured)
{
  L2CfgPort *l2port;
  int port, l1;

  for (port = 0; port < L2CFG_PORTS; port++) {
    l2port = &L2CFG_OF(l2node)->port_list[port];
    if (l2port->state != L2CFG_PORT_CONFIGURED)
      continue;
    for (l1 = 0; l1 < l2port->l1count; l1++)
      if ((!configured || l2port->l1cfg[l1].configured) && l2port->l1cfg[l1].rack == rack &&
          l2port->l1cfg[l1].slot == slot)
        return &l2port->l1cfg[l1];
  }
  return NULL;
}

/* the L2 of the brick at rack.slot */
L2CfgNode *L2CfgMFindBrickL2(L2Cfg *head, int rack, int slot)
{
  L2CfgNode *l2node;

  for (l2node = &head->net; l2node != NULL; l2node = l2node->next)
    if (find_l1(l2node,rack,slot,1) != NULL)
      return l2node;
  return NULL;
}

/* the configuration of the brick at rack.slot (on this L2 only, if local) */
L2CfgL1 *L2CfgMFindBrickCfg(L2Cfg *head, int rack, int slot, int local)
{
  L2CfgNode *l2node, *l2end;
  L2CfgL1 *c;

  if (rack == 0 || slot == 0)
    return NULL;
  l2end = local && head != NULL ? head->net.next : NULL;
  for (l2node = &head->net; l2node != l2end; l2node = l2node->next)
    if ((c = find_l1(l2node,rack,slot,0)) != NULL)
      return c;
  return NULL;
}

/* the type of the brick at rack.slot, '?' if unknown */
int L2CfgMFindBrickType(L2Cfg *head, int rack, int slot)
{
  L2CfgNode *l2node;
  L2CfgL1 *c;

  for (l2node = &head->net; l2node != NULL; l2node = l2node->next)
    if ((c = find_l1(l2node,rack,slot,0)) != NULL)
      return c->type;
  return '?';
}

/* append "key:value," to the query text, growing it as needed (the
 * original grew it only between L2s: an L2 with many L1s overran it) */
static void qput(const char *key, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void qput(const char *key, const char *fmt, ...)
{
  size_t used = cptr - cbuf;
  size_t keylen = key != NULL ? strlen(key) : 0;
  va_list ap;
  int len;

  va_start(ap,fmt);
  len = vsnprintf(NULL,0,fmt,ap);
  va_end(ap);
  while (used + keylen + len + 3 >= (size_t)clen) {
    clen += 0x2000;
    cbuf = realloc(cbuf,clen);
    cptr = cbuf + used;
  }
  if (key != NULL)
    cptr += sprintf(cptr,"%s:",key);
  va_start(ap,fmt);
  cptr += vsprintf(cptr,fmt,ap);
  va_end(ap);
  if (key != NULL)
    *cptr++ = ',';
  *cptr = '\0';
}

/* an L1 key: lower case for the first L1 of a port, upper for the rest */
static const char *l1key(const char *lower, const char *upper, int l1_index)
{
  return l1_index == 0 ? lower : upper;
}

/* the query text of one L1 */
static void query_l1(L2CfgL1 *c, int i, int format)
{
  if (format)
    qput(NULL,"\n    ");
  qput(l1key("l1","L1",i),"%u",i);
  qput(l1key("rack","RACK",i),"%u",c->rack);
  qput(l1key("slot","SLOT",i),"%u",c->slot);
  qput(l1key("type","TYPE",i),"%u",c->type);
  if (c->console_enabled)
    qput(l1key("conena","CONENA",i),"%u",c->console_enabled);
  if (c->console_subchannel)
    qput(l1key("consub","CONSUB",i),"%u",c->console_subchannel);
  if (c->router_type)
    qput(l1key("rtype","RTYPE",i),"%u",c->router_type);
  if (c->shub_addrmode)
    qput(l1key("sh_amode","SH_AMODE",i),"%u",c->shub_addrmode);
  if (c->shub_shrmode)
    qput(l1key("sh_shrmode","SH_SHRMODE",i),"%u",c->shub_shrmode);
  if (c->power_state)
    qput(l1key("pstate","PSTATE",i),"%u",c->power_state);
  if (c->margin_state)
    qput(l1key("mstate","MSTATE",i),"%u",c->margin_state);
  if (c->env_state)
    qput(l1key("estate","ESTATE",i),"%u",c->env_state);
  if (c->conn_state)
    qput(l1key("cstate","CSTATE",i),"%u",c->conn_state);
  if (c->partition)
    qput(l1key("part","PART",i),"%u",c->partition);
  qput(l1key("bsn","BSN",i),"%s",c->brick_sn);
  qput(l1key("ssn","SSN",i),"%s",c->system_sn);
}

/*
 * The configuration as L2CfgMCfgL2()'s "key:value," text (a static
 * buffer): this L2 (and with mode bit 0 the connected peers) with its
 * ports and L1s, or with mode bit 1 only the events and partitions each
 * L2 wants. format adds newlines and indents.
 */
char *L2CfgMQuery(L2Cfg *head, int mode, int format)
{
  L2CfgNode *l2node;
  L2CfgPort *port;
  L2Cfg *l2;
  char sel[1024];
  int l2_index = 0, port_index, l1_index, part;

  if (clen == 0) {
    clen = 0x2000;
    cbuf = malloc(clen);
  }
  cptr = cbuf;
  *cbuf = '\0';
  for (l2node = &head->net; l2node != NULL; l2node = l2node->next, l2_index++) {
    l2 = L2CFG_OF(l2node);
    if (l2_index != 0 && l2node->client == NULL)
      continue;                 /* (a peer not connected) */
    if (!(mode & 1) && (L2Cfg *)l2node != &L2CfgLocal)
      continue;
    if (format && (L2Cfg *)l2node != head)
      qput(NULL,"\n");
    qput("l2","%s",inet_ntoa(*(struct in_addr *)&l2node->ip_addr));
    if (mode & 2) {
      qput("l2events","%x",l2node->events);
      if (l2node->pselect[0] == 0xff) {
        qput("pselect","%s","*");
        continue;
      }
      sel[0] = '\0';
      for (part = 0; part < MAX_PARTITIONS; part++) {
        if (l2node->pselect[part] != 0) {
          if (sel[0] != '\0')
            strcat(sel,".");
          sprintf(sel + strlen(sel),"%d",part);
        }
      }
      if (sel[0] != '\0')
        qput("pselect","%s",sel);
      continue;
    }

    qput("l2rack","%u",l2->rack);
    if (l2->ssn[0] != '\0')
      qput("l2ssn","%s",l2->ssn);
    if (l2->sysname[0] != '\0')
      qput("l2name","%s",l2->sysname);
    if (l2->l2dsp_disabled)
      qput("l2dspdis","%u",l2->l2dsp_disabled);
    if ((L2Cfg *)l2node == &L2CfgLocal)
      qput("l2os","%s","linux");
    else if (l2node->os != 0 && l2node->os < sizeof(os_names) / sizeof(os_names[0]))
      qput("l2os","%s",os_names[l2node->os]);
    if (l2node->msmode == 2)
      qput("l2pri","%s",inet_ntoa(*(struct in_addr *)&l2node->ip_addr));
    if (l2node->msmode == 1)
      qput("l2sec","%s",inet_ntoa(*(struct in_addr *)&l2node->msip));
    for (port_index = 0; port_index < L2CFG_PORTS; port_index++) {
      port = &l2->port_list[port_index];
      if (format)
        qput(NULL,"\n  ");
      qput("port","%u",port_index);
      if (port->state == L2CFG_PORT_FREE)
        continue;
      qput("state","%u",port->state);
      qput("device","%s",port->device);
      qput("usbp","%s",port->usbpath);
      if (port->state != L2CFG_PORT_CONFIGURED)
        continue;
      for (l1_index = 0; l1_index < port->l1count; l1_index++)
        if (port->l1cfg[l1_index].configured || port->l1cfg[l1_index].conn_state)
          query_l1(&port->l1cfg[l1_index],l1_index,format);
    }
  }
  return cbuf;
}

/*
 * An IRouter address for messages (a static buffer): "001c05" (an L1),
 * "L2 (001c05)", "local", "local attached C", "005-L2", "L3 Client 3
 * [005-L2]", ...
 */
char *L2CfgMAddrStr(L2Cfg *head, IRAddress addr, int verbose)
{
  static char buff[80];
  char *bptr = buff;
  L2CfgNode *l2;
  int type = IR_ADDR_TYPE(addr);
  int rack, slot, task;
  uint32 low;

  switch (type) {
  case IR_ADDR_L2:
  case IR_ADDR_L3:
    strcpy(buff,type == IR_ADDR_L2 ? "L2 " : "L3 ");
    bptr = buff + strlen(buff);
    /* fall through */
  case IR_ADDR_L1:
    rack = IR_ADDR_RACK(addr);
    slot = IR_ADDR_SLOT(addr);
    if (addr >> 12 == 0xffff)
      sprintf(bptr,"local");
    else if (type == IR_ADDR_L1)
      sprintf(bptr,"%03d%c%02d",rack,brickTypeToChar(L2CfgMFindBrickType(head,rack,slot)),slot);
    else
      sprintf(bptr,"(%03d%c%02d)",rack,brickTypeToChar(L2CfgMFindBrickType(head,rack,slot)),slot);
    break;
  case IR_ADDR_C:
    strcpy(buff,"local attached C");
    break;
  case IR_ADDR_I:
    strcpy(buff,"local attached I/O");
    break;
  case IR_ADDR_CI:
    strcpy(buff,"local attached C\'s I/O");
    break;
  case IR_ADDR_IP:
  case IR_ADDR_IP_OTHER:
    /* an L2, or an L3 client (its task) of an L2: by rack, or IP address */
    task = (addr >> 24) & 0x3f;
    l2 = L2CfgMFindL2Node(head,0,addr & IR_IP_TASK_MASK,NULL);
    low = addr & 0xffffff;
    if (l2 == NULL) {
      if (type == IR_ADDR_IP)
        sprintf(buff,"X.%d.%d.%d-L2",low >> 16 & 0xff,low >> 8 & 0xff,low & 0xff);
      else
        sprintf(buff,"L3 Client %d [X.%d.%d.%d-L2]",task,low >> 16 & 0xff,low >> 8 & 0xff,low & 0xff);
    }
    else if (L2CFG_OF(l2)->rack < 1) {
      if (type == IR_ADDR_IP)
        sprintf(buff,"%s-L2",SocketAddrStr(l2->ip_addr));
      else
        sprintf(buff,"L3 Client %d [%s-L2]",task,SocketAddrStr(l2->ip_addr));
    }
    else {
      if (type == IR_ADDR_IP)
        sprintf(buff,"%03d-L2",L2CFG_OF(l2)->rack);
      else
        sprintf(buff,"L3 Client %d [%03d-L2]",task,L2CFG_OF(l2)->rack);
    }
    break;
  default:
    sprintf(buff,"invalid address (IR 0x%08x)",addr);
    break;
  }
  return buff;
}

/* an L1's console address: rack.slot, the subchannel's number and task */
static IRAddress console_addr(int rack, int slot, uint32 subchannel)
{
  return IR_ADDR_MAKE(IR_ADDR_L1,rack,slot & 0x3f,subchannel & 0x7f,(subchannel >> 8) & 0x1f);
}

/*
 * The system console of a partition: the lowest compute brick (rack and
 * slot each, as compared separately) whose console subchannel is
 * CONSOLE_SUBCHAN, else the lowest compute brick. -1 recomputes every
 * partition's (and returns 0); a partition's is computed when not known.
 */
IRAddress L2CfgMGetConsole(L2Cfg *head, int partition)
{
  IRAddress detected;
  L2CfgNode *l2node;
  L2CfgPort *l2port;
  L2CfgL1 *c;
  int port, l1, part, rack, slot, subc;
  unsigned int p;

  if (L2CfgDebugX)
    fprintf(stderr,"L2CfgGetConsole(%lx, %d)\n",ptr_bits(head),partition);
  /* (the original took partitions below -1 as indexes) */
  if (partition < -1 || partition >= MAX_PARTITIONS) {
    if (L2CfgDebugX)
      fprintf(stderr,"bad partition\n");
    return 0;
  }
  if (partition != -1 && (detected = head->syscon[partition].detected) != 0) {
    if (L2CfgDebugX)
      fprintf(stderr,"console detected: %x\n",detected);
    return detected;
  }

  memset(addr0,0,sizeof(addr0));
  memset(addr1,0,sizeof(addr1));
  memset(rack0,0xff,sizeof(rack0));
  memset(rack1,0xff,sizeof(rack1));
  memset(slot0,0xff,sizeof(slot0));
  memset(slot1,0xff,sizeof(slot1));
  for (l2node = &head->net; l2node != NULL; l2node = l2node->next) {
    for (port = 0; port < L2CFG_PORTS; port++) {
      l2port = &L2CFG_OF(l2node)->port_list[port];
      if (l2port->state != L2CFG_PORT_CONFIGURED)
        continue;
      for (l1 = 0; l1 < l2port->l1count; l1++) {
        c = &l2port->l1cfg[l1];
        if (!c->configured)
          continue;
        rack = c->rack;
        slot = c->slot;
        p = c->partition;
        subc = BRICK_TASKNUM_SUBCHAN(c->type,c->console_subchannel);
        if (rack == 0 || slot == 0 || !brickIsCompute(c->type) || (partition != -1 && (int)p != partition))
          continue;
        if ((unsigned int)rack <= rack0[p] && (unsigned int)slot <= slot0[p] && subc == CONSOLE_SUBCHAN) {
          rack0[p] = rack;
          slot0[p] = slot;
          addr0[p] = console_addr(rack,slot,c->console_subchannel);
        }
        if ((unsigned int)rack <= rack1[p] && (unsigned int)slot <= slot1[p]) {
          rack1[p] = rack;
          slot1[p] = slot;
          addr1[p] = console_addr(rack,slot,c->console_subchannel);
        }
      }
    }
  }
  for (part = 0; part < MAX_PARTITIONS; part++) {
    head->syscon[part].detected = addr0[part] != 0 ? addr0[part] : addr1[part];
    if (L2CfgDebugX && (addr0[part] != 0 || addr1[part] != 0))
      fprintf(stderr,"detecting %d - %x %x\n",part,addr0[part],addr1[part]);
  }
  return partition == -1 ? 0 : head->syscon[partition].detected;
}

/* the number of L2s, plus one */
int L2CfgMCount(L2Cfg *head)
{
  L2CfgNode *l2node;
  int count = 1;

  for (l2node = &head->net; l2node != NULL; l2node = l2node->next)
    count++;
  return count;
}

/*
 * In a large system (16 L2s or more), a warning into rptr (and -1) when
 * the console at addr is on another L2: that L2 should be used for it.
 */
int L2CfgMAdviseConsole(L2Cfg *head, char *rptr, int partition, IRAddress addr)
{
  int rack = IR_ADDR_RACK(addr);
  int slot = IR_ADDR_SLOT(addr);
  L2CfgNode *l2node;

  if (L2CfgMCount(head) <= 16 || addr == 0)
    return 0;
  l2node = L2CfgMFindBrickL2(head,rack,slot);
  if (l2node == NULL || (L2Cfg *)l2node == head)
    return 0;
  if (partition == 0)
    sprintf(rptr,"\nWARNING: accessing the system console at %03d.%02d from this L2 is not\n"
            "advised!  Suggested access point is the L2 at rack ID %04d (%s)\n\n",
            rack,slot,L2CFG_OF(l2node)->rack,inet_ntoa(*(struct in_addr *)&l2node->ip_addr));
  else
    sprintf(rptr,"\nWARNING: accessing partition %d of the system at %03d.%02d from this\n"
            "L2 is not advised!  Suggested access point for partition %d is\n"
            "the L2 at rack ID %04d (%s)\n\n",
            partition,rack,slot,partition,L2CFG_OF(l2node)->rack,
            inet_ntoa(*(struct in_addr *)&l2node->ip_addr));
  return -1;
}
