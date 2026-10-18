/*
 * Equivalence test of the configuration upkeep (l3/l2/cfg.c) against the
 * main branch's reconstruction (Orig*): random L1 events, configuration
 * requests and responses, L2 pings, configuration checks and timers on a
 * random world (bricks, L1 ports, other L2s, L3 clients). Each side has its
 * own copy of the world; every call cfg.c makes is a logged stub, and the
 * logs and the worlds must match. cfg_test.sh builds it under ASan.
 */
#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "cfg.h"
#include "../api/SCapiL2.h"
#include "../main/nvram.h"
#include "orig_cfg.h"

/* --- the world --- */
#define NBRICKS 12
#define NPEERS  4
#define NL3     3
typedef struct {
  L2Cfg local;
  L2L1Port ports[L2_L1_PORTS];
  L2CfgL1 bricks[NBRICKS];
  L2Cfg peers[NPEERS];
  L2CfgNode l3[NL3];
  RouterClient rclients[NPEERS];
} World;
static World w[2];
static int side;

L2Cfg L2CfgLocal;
L2L1Port l2_l1_ports[L2_L1_PORTS];
int l2_l1_conn_mode, l2_discover, IR_PORT_BIAS, irtr_debug, l1usb_debug, discover_debug, IRByteOrder;
IRIdent l2_cfg_id;

static char log_[2][1 << 16];
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
  if (len < sizeof(log_[0]) - 300)
    vsnprintf(log_[side] + len,sizeof(log_[0]) - len,fmt,ap);
  va_end(ap);
}

/* a description without the original's renamed function names */
static const char *plain(const char *s)
{
  static char buf[200];
  const char *o = strstr(s,"Orig");
  if (o == NULL)
    return s;
  snprintf(buf,sizeof(buf),"%.*s%s",(int)(o - s),s,o + 4);
  return buf;
}

static void build_world(World *x, unsigned int s0)
{
  unsigned int keep = seed;
  int i, p, b = 0;

  seed = s0;
  memset(x,0,sizeof(*x));
  x->local.net.ip_addr = htonl(0x0a000001);
  x->local.net.msmode = rnd(3);
  x->local.net.events = rnd(4) == 0 ? rnd(16) : 0;
  for (i = 0; i < 256; i++)
    x->local.net.pselect[i] = rnd(20) == 0;
  for (p = 0; p < L2CFG_PORTS; p++) {
    x->ports[p].fd = rnd(4) == 0 ? 20 + p : -1;
    x->ports[p].timer = rnd(2) ? 100 + p : 0;
    snprintf(x->ports[p].device,sizeof(x->ports[p].device),"dev%d",p);
    x->local.port_list[p].state = rnd(3) == 0 ? rnd(3) : 0;
    if (b < NBRICKS && rnd(5) == 0) {
      int n = 1 + rnd(2);
      if (b + n > NBRICKS)
        n = NBRICKS - b;
      x->local.port_list[p].l1count = n;
      x->local.port_list[p].l1cfg = &x->bricks[b];
      for (i = 0; i < n; i++, b++) {
        x->bricks[b].configured = rnd(4) != 0;
        x->bricks[b].rack = rnd(3);
        x->bricks[b].slot = rnd(4);
      }
    }
  }
  for (i = 0; i < NPEERS; i++) {
    x->peers[i].net.ip_addr = htonl(0x0b000000 + i);
    x->peers[i].net.heartbeat = rnd(4) == 0 ? 0xffffffff : rnd(4);
    x->rclients[i].addr = x->peers[i].net.ip_addr;
    x->rclients[i].port = 9001;
    snprintf(x->rclients[i].id.hostname,sizeof(x->rclients[i].id.hostname),"peer%d",i);
    x->peers[i].net.client = rnd(2) ? &x->rclients[i] : NULL;
    x->peers[i].net.next = i + 1 < NPEERS ? &x->peers[i + 1].net : NULL;
  }
  x->local.net.next = rnd(5) ? &x->peers[0].net : NULL;
  for (i = 0; i < NL3; i++) {
    x->l3[i].events = rnd(16);
    for (p = 0; p < 256; p++)
      x->l3[i].pselect[p] = rnd(30) == 0;
    x->l3[i].next = i + 1 < NL3 ? &x->l3[i + 1] : NULL;
  }
  x->local.l3_clients = rnd(3) ? &x->l3[0] : NULL;
  seed = keep;
}

static void enter(int s)
{
  side = s;
  L2CfgLocal = w[s].local;
  memcpy(l2_l1_ports,w[s].ports,sizeof(l2_l1_ports));
}

static void leave(void)
{
  w[side].local = L2CfgLocal;
  memcpy(w[side].ports,l2_l1_ports,sizeof(l2_l1_ports));
}

static int peer_index(L2CfgNode *n)
{
  int i;
  for (i = 0; i < NPEERS; i++)
    if (n == &w[side].peers[i].net)
      return i;
  return n == &L2CfgLocal.net ? 9 : -1;
}

static int same_worlds(void)
{
  L2CfgNode *a, *b;
  int i;

  if (memcmp(w[0].bricks,w[1].bricks,sizeof(w[0].bricks)) != 0 ||
      w[0].local.net.events != w[1].local.net.events ||
      memcmp(w[0].local.net.pselect,w[1].local.net.pselect,256) != 0)
    return 0;
  for (i = 0; i < L2_L1_PORTS; i++)
    if (w[0].ports[i].timer != w[1].ports[i].timer)
      return 0;
  for (i = 0; i < NPEERS; i++)
    if (w[0].peers[i].net.heartbeat != w[1].peers[i].net.heartbeat ||
        (w[0].peers[i].net.client == NULL) != (w[1].peers[i].net.client == NULL))
      return 0;
  for (a = w[0].local.net.next, b = w[1].local.net.next; a != NULL && b != NULL; a = a->next, b = b->next)
    if ((char *)a - (char *)w[0].peers != (char *)b - (char *)w[1].peers)
      return 0;
  return a == NULL && b == NULL;
}

/* --- stubs: NVRAM, configuration --- */
static char serial[20] = "SSN1";
static uintptr_t nv[2][32];     /* each side's */
static char password[20];

uintptr_t nvramGet(int32 location)
{
  if (location == NVRAM_SERIAL)
    return (uintptr_t)serial;
  if (location == NVRAM_PASSWORD)
    return (uintptr_t)password;
  return nv[side][location & 31];
}

void nvramSet(int32 location, uintptr_t value)
{
  note("nvramSet %d %lu\n",location,(unsigned long)value);
  nv[side][location & 31] = value;
}

static char query_text[3][0x20000];

char *L2CfgMQuery(L2Cfg *head, int format, int verbose)
{
  static char buf[0x20000];
  strcpy(buf,query_text[format % 3]);
  return buf;
}

void L2CfgMCfgL2(L2Cfg *head, IRPacket *p) { note("CfgL2 argc %d\n",p->_argc); }
static int cfgport_rval;
int L2CfgMCfgPort(L2Cfg *head, int port, IRPacket *p)
{
  note("CfgPort %d\n",port);
  if (cfgport_rval && port >= 0 && port < L2CFG_PORTS)
    head->port_list[port].state = L2CFG_PORT_CONFIGURED;
  return cfgport_rval;
}
L2CfgPort *L2CfgMGetPort(L2Cfg *head, int port) { return &head->port_list[port]; }
char *L2CfgMDeviceName(L2Cfg *head, int fd) { return "devname"; }
L2CfgL1 *L2CfgMFindBrickCfg(L2Cfg *head, int rack, int slot, int local)
{
  int i;
  for (i = 0; i < NBRICKS; i++)
    if (w[side].bricks[i].rack == rack && w[side].bricks[i].slot == slot)
      return &w[side].bricks[i];
  return NULL;
}
IRAddress L2CfgMGetConsole(L2Cfg *head, int partition) { note("GetConsole %d\n",partition); return 0; }
L2CfgNode *L2CfgMFindNode(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  L2CfgNode *n;
  for (n = head->net.next; n != NULL; n = n->next)
    if (n->ip_addr == ip_addr)
      return n;
  return NULL;
}
int L2CfgMDeleteNode(L2Cfg *head, RouterClient *client)
{
  L2CfgNode **link;
  for (link = &head->net.next; *link != NULL; link = &(*link)->next)
    if ((*link)->client == client) {
      note("DeleteNode %d\n",peer_index(*link));
      *link = (*link)->next;
      return 0;
    }
  note("DeleteNode none\n");
  return -1;
}

/* --- stubs: packets --- */
/* a packet's data arguments are kept as copies, their pointers in argument
 * slots DATA and up */
#define DATA 20
static void drop(IRPacket *p)
{
  if (p->_use_count == 0)
    note("double free\n");
  else if (--p->_use_count == 0) {
    int i;
    for (i = 0; i < p->_argc; i++)
      if (IR_ARG_TYPE(p->_argv[i]) != IR_ARG_VALUE)
        free(*(char **)&p->_argv[DATA + i]);
    free(p);
  }
}

int IRouterFreePacket(IRPacket *p) { drop(p); return 0; }

static void show(const char *who, IRPacket *p)
{
  int i;
  note("%s clas %d dest %08x op %d err %d argc %d:",who,p->_clas,p->_dest,p->_opcode,p->_err,p->_argc);
  for (i = 0; i < p->_argc; i++) {
    if (IR_ARG_TYPE(p->_argv[i]) == IR_ARG_VALUE)
      note(" %u",p->_argv[i]._val);
    else {
      char *t = *(char **)&p->_argv[DATA + i];
      note(" [%d/%d \"%.40s\" len %zu]",p->_argv[i]._clas,p->_argv[i]._size,t,strlen(t));
    }
  }
  note("\n");
}

IRPacket *IRouterMakePacket(IRIdent *id, IRAddress *toaddr, int pdata, int opcode, int clas,
                            int prev, int argcount, IRArgument *arglist)
{
  IRPacket *p = calloc(1,sizeof(IRPacket) + 40 * sizeof(IRArgument));
  int i;

  p->_use_count = 1;
  p->_dest = toaddr != NULL ? *toaddr : 0;
  p->_opcode = opcode;
  p->_clas = clas;
  p->_rev = prev;
  p->_argc = argcount;
  note("make pdata %d rev %d\n",pdata,prev);
  for (i = 0; i < argcount; i++) {
    p->_argv[i] = arglist[i];
    if (IR_ARG_TYPE(arglist[i]) != IR_ARG_VALUE) {
      /* (the data, kept past the arguments) */
      char *d = (char *)IR_VAL_PTR(arglist[i]._val);
      *(char **)&p->_argv[DATA + i] = strdup(d);
      if (arglist[i]._clas & IR_ARG_FREE)
        free(d);
    }
  }
  return p;
}

int IRouterSendPacket(IRIdent *id, IRPacket *pkt) { show("send",pkt); drop(pkt); return 0; }
int IRouterSendBroadcastPacketToClients(IRIdent *id, IRPacket *pkt) { show("to clients",pkt); return 0; }
void l1_write_packet(int fd, IRPacket *pkt) { note("l1 fd %d: ",fd); show("",pkt); drop(pkt); }
char *IRFmtPkt(char *who, IRPacket *p, char *bptr) { strcpy(bptr,who); return bptr; }
uintptr_t IRArg(IRPacket *pkt, int arg)
{
  if (arg >= pkt->_argc)
    return 0;
  if (IR_ARG_TYPE(pkt->_argv[arg]) == IR_ARG_VALUE)
    return pkt->_argv[arg]._val;
  return (uintptr_t)*(char **)&pkt->_argv[DATA + arg];
}
#if UINTPTR_MAX != 0xffffffffu
static const void *handles[64];
static unsigned int nhandles;
uint32 IRPtrToVal(const void *p) { handles[nhandles % 64] = p; return nhandles++ % 64; }
void *IRValToPtr(uint32 v) { return (void *)handles[v % 64]; }
#endif

/* --- stubs: events, consoles, discovery, Router --- */
static struct { void (*f)(); EventData d; char desc[40]; } timers[2][256];
static unsigned int ntimers[2];

EventID EventAddTimeOut(long unsigned int seconds, long unsigned int microseconds,
                        void (*timer_func)(), EventData client_data, char *desc)
{
  unsigned int n = ntimers[side]++ % 256;
  timers[side][n].f = timer_func;
  timers[side][n].d = client_data;
  snprintf(timers[side][n].desc,sizeof(timers[side][n].desc),"%s",plain(desc));
  note("timer %u: %lu s data %ld \"%s\"\n",n + 1,seconds,(long)(intptr_t)client_data,plain(desc));
  return n + 1;
}
void EventRemoveTimeOut(EventID id) { note("remove timer %lu\n",(unsigned long)id); }
EventID EventAddInput(int fd, void (*input_func)(), EventData client_data, char *desc) { note("input %d\n",fd); return 1; }
void smp_chkcon_changes(int get_check) { note("chkcon %d\n",get_check); }
static int console_count;
int smp_console_count(unsigned char *pselect) { if (console_count) pselect[3] = 1; return console_count; }
int l2_console_printf(const char *format, ...) { note("console printf %s",format); return 0; }

/* l2's fprintf (smp.c): a NULL stream is a console event */
int fprintf(FILE *restrict stream, const char *restrict format, ...)
{
  va_list ap;
  int rval;

  if (*(FILE *volatile *)&stream == NULL) {
    note("console printf %s",format);
    return 0;
  }
  va_start(ap,format);
  rval = vfprintf(stream,format,ap);
  va_end(ap);
  return rval;
}
int SocketGetHostAddr(uint32_t *addr) { *addr = htonl(0x7f000001); return 0; }
void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...) { note("syslog %d\n",ln); }
static int discover_start_rval;
int sn1SCDiscoverL2Start(int sd, char *dev, char *client_info) { note("discover %d \"%s\"\n",sd,client_info); return discover_start_rval; }
static int discover_rval;
static uint32 discover_ip;
int sn1SCDiscoverL2Response(int sd, sn1SC_L2 *l2, int wait) { l2->ip_addr = discover_ip; return discover_rval; }
int EnetServerConnect(char *host, int port) { note("connect %s %d\n",host,port); return port & 1 ? 0 : -1001; }
char *LoggerDefaultMessage(int msgnbr) { return "msg"; }
static int lost_client = -1;
void RouterListClients(void (*cb_func)())
{
  int i;
  for (i = 0; i < NPEERS; i++)
    if (i != lost_client)       /* (the original loops for ever on one never found) */
      cb_func(&w[side].rclients[i]);
}
int RouterClose(RouterClient *client) { note("close %s\n",client->id.hostname); return 0; }

/* --- the test --- */
#define BOTH(o, n) do { enter(0); o; leave(); enter(1); n; leave(); } while (0)

static IRPacket *event(int opcode, int err, IRAddress src)
{
  IRArgument argv[4];
  IRPacket *p;
  static char sn[40];

  memset(argv,0,sizeof(argv));
  argv[1]._val = rnd(3);
  argv[2]._val = rnd(5);
  argv[3]._val = rnd(300);
  if (opcode == 7) {
    snprintf(sn,sizeof(sn),"SN%.*s",(int)rnd(9),"123456789");
    argv[3]._clas = IR_ARG_STRING;
    argv[3]._val = IR_PTR_VAL(sn);
    argv[3]._size = strlen(sn) + 1;
  }
  side = 0;
  p = IRouterMakePacket(&l2_cfg_id,&src,0,opcode,IR_EVT,2,opcode == 7 ? 4 : 1 + (int)rnd(4),argv);
  p->_src = src;
  p->_err = err;
  log_[0][0] = '\0';
  return p;
}

static IRPacket *copy(IRPacket *p)
{
  IRPacket *c = calloc(1,sizeof(IRPacket) + 40 * sizeof(IRArgument));
  int i;
  memcpy(c,p,sizeof(IRPacket) + 40 * sizeof(IRArgument));
  for (i = 0; i < p->_argc; i++)
    if (IR_ARG_TYPE(p->_argv[i]) != IR_ARG_VALUE)
      *(char **)&c->_argv[DATA + i] = strdup(*(char **)&p->_argv[DATA + i]);
  return c;
}

static IRAddress l1_src(void)
{
  return IR_ADDR_MAKE(IR_ADDR_L1,rnd(3),rnd(5),0,rnd(2) ? IR_L1_CFG : rnd(25));
}

int main(void)
{
  static const int opcodes[] = { 2, 3, 4, 5, 6, 7, 8, 100, 1000, 1, 9 };
  int trial;
  int i;

  IRByteOrder = htonl(1) == 1 ? 1 : 2;
  for (trial = 0; trial < 100000; trial++) {
    IRPacket *p, *q;

    if (trial % 40 == 0) {
      unsigned int s0 = seed;
      build_world(&w[0],s0);
      build_world(&w[1],s0);
      for (i = 0; i < 32; i++)
        nv[0][i] = nv[1][i] = rnd(3) ? rnd(6) : 0;
      strcpy(password,rnd(2) ? "" : "pw");
    }
    for (i = 0; i < 3; i++)
      if (trial % 20 == 0 || rnd(6) == 0) {
        int len = rnd(5) == 0 ? 0xf800 * (int)rnd(3) + (int)rnd(3) - 1 : (int)rnd(200);
        if (len < 0)
          len = 0;
        memset(query_text[i],'a' + rnd(26),len);
        query_text[i][len] = '\0';
      }
    l2_l1_conn_mode = rnd(6);
    l2_discover = rnd(2);
    l1usb_debug = rnd(4) == 0 ? 2 : 0;
    discover_start_rval = rnd(4) ? 7 : -1;
    cfgport_rval = rnd(2);
    console_count = rnd(2);
    switch (rnd(16)) {
    case 14: {
      /* "config auto"/"config manual" */
      int d1 = rnd(2) ? 0 : 7, d2 = rnd(2) ? 0 : 5;
      BOTH((Origcfg_setup_configcheck(d1),Origcfg_setup_l2ping(d2)),
           (cfg_setup_configcheck(d1),cfg_setup_l2ping(d2)));
      break;
    }
    case 15:
      /* the latest configuration check or hold timer fires */
      for (i = 0; i < 2; i++) {
        int n;
        enter(i);
        for (n = (int)ntimers[i] - 1; n >= 0 && n > (int)ntimers[i] - 256; n--) {
          int k = n % 256;
          if (timers[i][k].f != NULL && (strstr(timers[i][k].desc,"configcheck_throttle") != NULL ||
                                         strstr(timers[i][k].desc,"config_check") != NULL)) {
            void (*f)() = timers[i][k].f;
            timers[i][k].f = NULL;
            f(timers[i][k].d);
            break;
          }
        }
        leave();
      }
      break;
    case 0: case 1: case 2:
      p = event(opcodes[rnd(11)],rnd(5) == 0,l1_src());
      q = copy(p);
      BOTH(Origcfg_process_event(p),cfg_process_event(q));
      drop(p);
      drop(q);
      break;
    case 3: {
      int start = rnd(2);
      cfg_ping_response_minimum = Origcfg_ping_response_minimum = 1 + rnd(2);
      cfg_ping_response_maximum = Origcfg_ping_response_maximum = 1 + rnd(3);
      BOTH(Origcfg_l2ping(start),cfg_l2ping(start));
      break;
    }
    case 4: {
      int start = rnd(2);
      BOTH(Origcfg_configcheck(start),cfg_configcheck(start));
      break;
    }
    case 5: case 6: {
      IRArgument argv[4];
      memset(argv,0,sizeof(argv));
      argv[0]._val = rnd(2);
      argv[1]._val = 2;
      argv[2]._clas = IR_ARG_STRING;
      argv[2]._val = IR_PTR_VAL("cfg text");
      argv[2]._size = 9;
      side = 0;
      p = IRouterMakePacket(&l2_cfg_id,NULL,rnd(4),0,IR_REQ,rnd(3),1 + rnd(4),argv);
      p->_src = rnd(2) ? IR_ADDR_MAKE(IR_ADDR_L2,rnd(3),rnd(3),0,rnd(2) ? IR_L2_CFG : 3)
                       : 0x80000000 | rnd(2) << 30 | rnd(8) << 24 | rnd(0x1000000);
      log_[0][0] = '\0';
      q = copy(p);
      BOTH(Origcfg_process_request(p),cfg_process_request(q));
      break;
    }
    case 7: {
      side = 0;
      p = IRouterMakePacket(&l2_cfg_id,NULL,0,0,IR_RSP,2,rnd(3),(IRArgument[3]){ { 0 } });
      log_[0][0] = '\0';
      p->_err = rnd(4) == 0;
      p->_src = rnd(3) ? l1_src() : rnd(2) ? 0x84000000 | rnd(0x1000000)
                                          : IR_ADDR_MAKE(IR_ADDR_L2,1,1,0,IR_L2_CFG);
      p->_client_data = (uint8 *)(intptr_t)rnd(L2CFG_PORTS);
      q = copy(p);
      BOTH(Origcfg_process_response(p),cfg_process_response(q));
      break;
    }
    case 8: {
      int dev = rnd(L2CFG_PORTS);
      /* (with rescans off the original uses an unset port) */
      cfg_auto_rescan = Origcfg_auto_rescan = 1;
      BOTH(Origcfg_ping_l1(dev),cfg_ping_l1(dev));
      break;
    }
    case 9: {
      RouterClient c;
      int r[2];
      memset(&c,0,sizeof(c));
      c.port = rnd(2) ? 8000 + rnd(4) : 9001;
      const char *guess = rnd(3) == 0 ? NULL : rnd(2) ? "pw" : "x";
      BOTH(r[0] = Origcfg_password(&c,(char *)guess),r[1] = cfg_password(&c,(char *)guess));
      if (r[0] != r[1])
        note("password %d %d\n",r[0],r[1]);
      break;
    }
    case 10:
      switch (rnd(4)) {
      case 0: BOTH(Origcfg_check_console_events(),cfg_check_console_events()); break;
      case 1: BOTH(Origcfg_check_smp_events(),cfg_check_smp_events()); break;
      case 2: {
        RouterClient c;
        memset(&c,0,sizeof(c));
        c.port = rnd(2) ? 9001 : 8000;
        c.addr = htonl(0x0b000001);
        BOTH(Origcfg_disconnect(&c),cfg_disconnect(&c));
        break;
      }
      default: {
        RouterClient c;
        memset(&c,0,sizeof(c));
        c.addr = htonl(0x0b000000 + rnd(NPEERS));
        BOTH(Origcfg_establish(&c),cfg_establish(&c));
      }
      }
      break;
    case 11:
      discover_rval = rnd(3) == 0 ? -1 : 0;
      discover_ip = htonl(0x0b000000 + rnd(6));
      BOTH(Origcfg_recv_l2ping(NULL,3),cfg_recv_l2ping(NULL,3));
      break;
    case 12:
      switch (rnd(3)) {
      case 0: BOTH(Origcfg_ping_init(),cfg_ping_init()); break;
      case 1: BOTH(Origcfg_ping_reset(),cfg_ping_reset()); break;
      default: BOTH(Origcfg_init(),cfg_init());
      }
      break;
    default:
      /* the last timer fires */
      for (i = 0; i < 2; i++) {
        unsigned int n = (ntimers[i] - 1) % 256;
        enter(i);
        if (ntimers[i] != 0 && timers[i][n].f != NULL) {
          void (*f)() = timers[i][n].f;
          timers[i][n].f = NULL;
          /* (cfg_ping_l1 with rescans off: the original's unset port) */
          if (!((f == (void (*)())Origcfg_ping_l1 || f == (void (*)())cfg_ping_l1) &&
                (Origcfg_auto_rescan == 0 || cfg_auto_rescan == 0)))
            f(timers[i][n].d);
        }
        leave();
      }
    }
    if (strcmp(log_[0],log_[1]) != 0 || !same_worlds() || cfg_auto_rescan != Origcfg_auto_rescan ||
        memcmp(nv[0],nv[1],sizeof(nv[0])) != 0) {
      printf("FAIL  cfg: trial %d\n--- orig\n%s--- new\n%s",trial,log_[0],log_[1]);
      return 1;
    }
    log_[0][0] = log_[1][0] = '\0';
  }
  /* the new side alone: an L2 that never finished connecting and whose
   * client is not found is reported, and the ping goes on */
  build_world(&w[1],12345);
  for (i = 0; i < NPEERS; i++) {
    w[1].peers[i].net.client = NULL;
    w[1].peers[i].net.heartbeat = 0;
  }
  w[1].local.net.next = &w[1].peers[0].net;
  lost_client = 2;
  cfg_ping_response_minimum = 1;
  cfg_ping_response_maximum = 1;
  log_[1][0] = '\0';
  enter(1);
  cfg_l2ping(0);
  cfg_l2ping(0);
  leave();
  if (strstr(log_[1],"DeleteNode 2") != NULL || strstr(log_[1],"DeleteNode 3") == NULL) {
    printf("FAIL  cfg: lost L2 client\n%s",log_[1]);
    return 1;
  }
  printf("PASS  cfg: %d configuration operations compared with the original\n",trial);
  return 0;
}
