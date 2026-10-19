/*
 * sys_ctrl/l3/l2/cfg.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/cfg.c
 *
 * Keeping the system configuration (L2Cfg.c) current:
 *  - each L1 port is asked for its bricks' configuration every
 *    cfg_ping_l1_frequency seconds (cfg_ping_l1()), and L1 events update
 *    single fields (cfg_process_event());
 *  - L2s find each other by discovery broadcasts (cfg_l2ping()), connect,
 *    and exchange configurations (cfg_ping_l2(), cfg_process_request()); an
 *    L2 that stops answering is dropped;
 *  - every few seconds the configuration is compared with the last one
 *    sent, and a change goes to every client as an event
 *    (cfg_configcheck()), at most every cfg_throttle_frequency seconds.
 * Also the network server's callbacks: connect, disconnect.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "l2.h"
#include "cfg.h"
#include "discover.h"
#include "irtr.h"
#include "l1.h"
#include "smp.h"
#include "../api/SCapiL2.h"
#include "../main/settings.h"
#include "../main/l2log.h"
#include "../sys/syslogLib.h"
#include "../../common/sys/Logger.h"

#define CONFIGCHECK_DELAY   7       /* seconds between configuration checks */
#define L2_PEER_PORT        9001    /* plus IR_PORT_BIAS */
#define L3_CMD_PORT         8000
#define L3_QUIET_PORT       8002
#define CFG_BLOCK           0xf800  /* configuration text in one response argument */
#define CFG_ARGS            16

/* the configuration request to the L1 at the far end of a port */
#define L1_LOCAL_CFG        IR_ADDR_MAKE(IR_ADDR_L1,0x3ff,0x3f,0,IR_L1_CFG)
#define CFG_QUERY_L1        6       /* its first argument */

/* configuration request types (argument 0) and response format (1) */
enum { CFG_REQ_QUERY = 0, CFG_REQ_EXCHANGE = 1 };
#define CFG_FORMAT          2

/* L1 configuration events (opcodes) */
enum {
    EV_SUBCHANNEL = 2, EV_CONSOLE_ENABLE = 3, EV_POWER = 4, EV_MARGIN = 5,
    EV_PARTITION = 6, EV_SYSTEM_SN = 7, EV_ENVIRONMENT = 8,
    EV_IGNORED = 100,
    EV_L2_CONFIG = 1000,            /* an L2's configuration (cfg_configcheck()) */
};

static void cfg_configcheck_throttle(int start_timer);
static void find_client_to_delete(RouterClient *client);

int cfg_start_time;
int cfg_auto_rescan = 1;            /* "config auto" (0: "config manual") */
int cfg_l2ping_sd = -1;
static int cfg_configcheck_hold;    /* sent one recently */
static int cfg_configcheck_pending; /* ... and another is due */
int cfg_ping_response_minimum;      /* heartbeats an L2 must give per check */
int cfg_ping_response_maximum;      /* pings between checks */
int cfg_ping_l2_frequency;
int cfg_ping_l1_frequency;
int cfg_throttle_frequency;
int cfg_ping_sender_valid;          /* a discovery request counts as a heartbeat */
char cfg_client_id[30];             /* "clientid:<ip>.<pid>" */
RouterClient *del_client;
uint32 del_addr;

void cfg_ping_reset(void)
{
  cfg_ping_response_minimum = 1;
  settingsSet(SET_PING_MIN,1);
  cfg_ping_response_maximum = 3;
  settingsSet(SET_PING_MAX,3);
  cfg_ping_l2_frequency = 5;
  settingsSet(SET_PING_L2FREQ,5);
  cfg_ping_l1_frequency = 5;
  settingsSet(SET_PING_L1FREQ,5);
  cfg_throttle_frequency = 2;
  cfg_ping_sender_valid = 2;
  settingsSet(SET_PING_SENDER,2);
}

/* the ping settings from NVRAM; the defaults if any is unset */
void cfg_ping_init(void)
{
  if (settingsGet(SET_PING_MIN) == 0 || settingsGet(SET_PING_MAX) == 0 ||
      settingsGet(SET_PING_SENDER) == 0 || settingsGet(SET_PING_L2FREQ) == 0 ||
      settingsGet(SET_PING_L1FREQ) == 0)
    cfg_ping_reset();
  cfg_ping_response_minimum = settingsGet(SET_PING_MIN);
  cfg_ping_response_maximum = settingsGet(SET_PING_MAX);
  cfg_ping_l2_frequency = settingsGet(SET_PING_L2FREQ);
  cfg_ping_l1_frequency = settingsGet(SET_PING_L1FREQ);
  cfg_ping_sender_valid = settingsGet(SET_PING_SENDER);
  cfg_throttle_frequency = 2;
}

/* this L2's discovery request: its id, the system serial number in
 * multi-system mode, and its role */
static void discovery_request(char *client_data, int with_secondary)
{
  if (settingsGet(SET_MULTISYS) == 1)
    sprintf(client_data,"%s,ssn:%s",cfg_client_id,(char *)settingsGet(SET_SERIAL));
  else
    strcpy(client_data,cfg_client_id);
  if (L2CfgLocal.net.msmode == 2)
    strcat(client_data,",l2pri:0");
  else if (with_secondary && L2CfgLocal.net.msmode == 1)
    strcat(client_data,",l2sec:0");
  else
    strcat(client_data,",l2:1");
  if (discover_debug & 1)
    fprintf(stderr,"sending L2 discover request: client_data=[%s]\n",client_data);
}

void cfg_init(void)
{
  char client_data[200];
  uint32 cfg_ip;

  cfg_start_time = time(NULL);
  cfg_ping_init();
  if (SocketGetHostAddr(&cfg_ip) != 0) {
    syslog(2,"cfg.c",108,0,"cfg_init: couldn\'t get IP address for local host\n");
    return;
  }
  sprintf(cfg_client_id,"clientid:%s.%d",inet_ntoa(*(struct in_addr *)&cfg_ip),getpid());
  cfg_setup_configcheck(CONFIGCHECK_DELAY);
  if (!l2_discover || L2CfgLocal.net.msmode == 1)
    return;
  discovery_request(client_data,1);
  cfg_l2ping_sd = sn1SCDiscoverL2Start(-1,NULL,client_data);
  if (cfg_l2ping_sd < 0) {
    fprintf(stderr,"ERROR: can\'t attempt to find other L2\'s\n");
    return;
  }
  EventAddInput(cfg_l2ping_sd,cfg_recv_l2ping,NULL,"cfg_init");
  cfg_setup_l2ping(cfg_ping_l2_frequency);
}

/* ask the L1(s) on a port for their configuration (with auto rescans on),
 * and come back in cfg_ping_l1_frequency seconds (2 until the port is
 * configured) */
void cfg_ping_l1(int device)
{
  IRArgument argv[3];
  IRAddress toaddr = L1_LOCAL_CFG;
  char desc[48];
  char x[80];
  IRPacket *p;
  char *ssn;
  int port;

  switch (l2_l1_conn_mode) {
  case L2_CONN_NET:
  case L2_CONN_USB:
    port = device;
    break;
  default:
    return;
  }
  /* (with rescans off the original rescheduled on a port it had not set) */
  if (cfg_auto_rescan) {
    if (l2_l1_ports[port].fd == -1)
      return;
    memset(argv,0,sizeof(argv));
    argv[0]._val = CFG_QUERY_L1;
    ssn = (char *)settingsGet(SET_SERIAL);
    if (*ssn != '\0') {
      argv[1]._clas = IR_ARG_BYTES | IR_ARG_FREE;
      argv[1]._val = IR_PTR_VAL(strdup(ssn));
      argv[1]._size = strlen(ssn) + 1;
    }
    p = IRouterMakePacket(&l2_cfg_id,&toaddr,0,0,IR_REQ,2,3,argv);
    if (p == NULL) {
      fprintf(stderr,"ERROR: can\'t create packet for configuration request.\n");
      return;
    }
    if (irtr_debug & 8) {
      IRFmtPkt("L2",p,x);
      fprintf(stderr,"%s (port %d)\n",x,port);
    }
    l1_write_packet(l2_l1_ports[port].fd,p);
  }
  if (l2_l1_ports[port].fd > 0) {
    sprintf(desc,"cfg_ping_l1 (%s)",l2_l1_ports[port].device);
    l2_l1_ports[port].timer =
        EventAddTimeOut(L2CfgLocal.port_list[port].state == L2CFG_PORT_CONFIGURED ? cfg_ping_l1_frequency : 2,
                        0,cfg_ping_l1,(EventData)(intptr_t)device,desc);
  }
}

/* a packet's argument as a number (data arguments: their address) */
static uintptr_t arg_value(IRPacket *p, int arg)
{
  if (IR_ARG_TYPE(p->_argv[arg]) == IR_ARG_VALUE)
    return p->_argv[arg]._val;
  return IRArg(p,arg);
}

/* a copy of L2CfgMQuery()'s text, as a string argument freed once sent */
static void query_arg(IRArgument *arg, int format)
{
  char *text = strdup(L2CfgMQuery(&L2CfgLocal,format,0));

  arg->_clas = IR_ARG_STRING | IR_ARG_FREE;
  arg->_frame = 0;
  arg->_val = IR_PTR_VAL(text);
  arg->_size = strlen(text) + 1;
}

/* send a newly connected L2 our configuration, and ask for its */
void cfg_ping_l2(RouterClient *client)
{
  IRArgument argv[4];
  IRAddress dst;
  IRPacket *p;

  memset(argv,0,sizeof(argv));
  argv[0]._val = CFG_REQ_EXCHANGE;
  argv[1]._val = CFG_FORMAT;
  query_arg(&argv[2],0);
  query_arg(&argv[3],2);
  dst = IR_ADDR_WITH_TASK(IR_ADDR_FROM_IP(client->addr),IR_L2_CFG);
  p = IRouterMakePacket(&l2_cfg_id,&dst,0,0,IR_REQ,2,4,argv);
  if (p == NULL)
    fprintf(stderr,"ERROR: can\'t create packet for configuration request.\n");
  else
    IRouterSendPacket(NULL,p);
}

/* whether a packet is from an L2's configuration task */
static int from_l2_cfg(IRAddress src)
{
  return (IR_ADDR_TYPE(src) == IR_ADDR_L2 || IR_ADDR_TYPE(src) == IR_ADDR_IP) &&
         IR_ADDR_TASK(src) == IR_L2_CFG;
}

/*
 * A configuration request: CFG_REQ_QUERY for this L2's configuration (as
 * L3 tools ask), CFG_REQ_EXCHANGE from another L2 with its own. The answer
 * carries the configuration in CFG_BLOCK pieces, then the events part. A
 * request from an L2 goes on to the clients as an event.
 */
void cfg_process_request(IRPacket *req_p)
{
  IRArgument argv[CFG_ARGS];
  IRPacket *rsp_p;
  char *cfg;
  char *evt;
  int argc = 2;
  int blks;
  int clen;
  int blk;

  memset(argv,0,sizeof(argv));
  argv[1]._val = CFG_FORMAT;
  switch (arg_value(req_p,0)) {
  case CFG_REQ_QUERY:
    cfg = strdup(L2CfgMQuery(&L2CfgLocal,1,0));
    evt = strdup(L2CfgMQuery(&L2CfgLocal,2,0));
    break;
  case CFG_REQ_EXCHANGE:
    cfg = strdup(L2CfgMQuery(&L2CfgLocal,0,0));
    evt = strdup(L2CfgMQuery(&L2CfgLocal,2,0));
    if (req_p->_argc > 2) {
      smp_chkcon_changes(0);
      L2CfgMCfgL2(&L2CfgLocal,req_p);
      smp_chkcon_changes(1);
    }
    break;
  default:
    IRouterFreePacket(req_p);   /* (the original went on with no text) */
    return;
  }
  clen = strlen(cfg);
  /* (one more block than full ones, perhaps empty; the original had room
   * for 13) */
  blks = clen / CFG_BLOCK + 1;
  if (blks > CFG_ARGS - 3)
    blks = CFG_ARGS - 3;
  for (blk = 0; blk < blks; blk++) {
    char *text = strndup(cfg + blk * CFG_BLOCK,CFG_BLOCK);
    argv[argc]._clas = IR_ARG_STRING | IR_ARG_FREE;
    argv[argc]._frame = 0;
    argv[argc]._val = IR_PTR_VAL(text);
    argv[argc]._size = strlen(text) + 1;
    argc++;
  }
  free(cfg);
  argv[argc]._clas = IR_ARG_STRING | IR_ARG_FREE;
  argv[argc]._frame = 0;
  argv[argc]._val = IR_PTR_VAL(evt);
  argv[argc]._size = strlen(evt) + 1;
  rsp_p = IRouterMakePacket(&l2_cfg_id,&req_p->_src,req_p->_pdata_auth >> 3,0,IR_RSP,req_p->_rev,
                            argc + 1,argv);
  if (rsp_p == NULL)
    fprintf(stderr,"ERROR: can\'t create packet for configuration response.\n");
  else {
    rsp_p->_seqnum0 = req_p->_seqnum0;
    rsp_p->_seqnum1 = req_p->_seqnum1;
    IRouterSendPacket(NULL,rsp_p);
  }
  if (from_l2_cfg(req_p->_src)) {
    req_p->_clas = IR_EVT;
    IRouterSendBroadcastPacketToClients(&l2_cfg_id,req_p);
  }
  IRouterFreePacket(req_p);
}

/* a configuration response: an L1 port's bricks (the port in
 * _client_data), or another L2's configuration */
void cfg_process_response(IRPacket *p)
{
  int port = (int)(intptr_t)p->_client_data;
  L2CfgPort *l2port = NULL;
  char odname[60];
  int ostate = 0;
  int changed;

  if (p->_err == 0 && IR_ADDR_TYPE(p->_src) == IR_ADDR_L1) {
    if (l1usb_debug > 1) {
      l2port = L2CfgMGetPort(&L2CfgLocal,port);
      ostate = l2port->state;
      strcpy(odname,L2CfgMDeviceName(&L2CfgLocal,l2port->fd));
    }
    smp_chkcon_changes(0);
    changed = L2CfgMCfgPort(&L2CfgLocal,port,p);
    smp_chkcon_changes(1);
    /* (as a console event: the original's fprintf() to a NULL stream) */
    if (l1usb_debug > 1 && ostate != L2CFG_PORT_CONFIGURED && l2port->state == L2CFG_PORT_CONFIGURED)
      l2_console_printf("INFO: USB device %s configured: %s\n",odname,
                        L2CfgMDeviceName(&L2CfgLocal,l2port->fd));
    if (changed) {
      /* ask again in a second */
      EventRemoveTimeOut(l2_l1_ports[port].timer);
      l2_l1_ports[port].timer = EventAddTimeOut(1,0,cfg_ping_l1,(EventData)(intptr_t)port,"extra cfg_ping_l1");
      cfg_configcheck(1);
    }
  }
  else if (p->_err == 0 && IR_ADDR_TYPE(p->_src) == IR_ADDR_IP) {
    smp_chkcon_changes(0);
    L2CfgMCfgL2(&L2CfgLocal,p);
    smp_chkcon_changes(1);
  }
  if (from_l2_cfg(p->_src)) {
    p->_clas = IR_EVT;
    IRouterSendBroadcastPacketToClients(&l2_cfg_id,p);
  }
  IRouterFreePacket(p);
}

/* (debugging) a packet's data arguments */
void pp(IRPacket *p)
{
  int arg;

  for (arg = 0; arg < p->_argc; arg++)
    if (IR_ARG_TYPE(p->_argv[arg]) == IR_ARG_BYTES)
      fprintf(stderr,"%s\n",(char *)IRArg(p,arg));
}

/* an L1 configuration event (or an L2's, EV_L2_CONFIG); after one from an
 * L1's configuration task, that L1's port is asked again in a second */
void cfg_process_event(IRPacket *p)
{
  IRAddress src = p->_src;
  L2CfgPort *l2port;
  int ping_port = -1;
  int port;
  int l1;

  if (p->_err == 0) {
    switch (p->_opcode) {
    case EV_SUBCHANNEL:
      smp_chkcon_changes(0);
      cfg_console_subchannel(p);
      smp_chkcon_changes(1);
      break;
    case EV_CONSOLE_ENABLE:
      cfg_console_enable(p);
      break;
    case EV_POWER:
      cfg_power_state(p);
      break;
    case EV_MARGIN:
      cfg_margin_state(p);
      break;
    case EV_PARTITION:
      smp_chkcon_changes(0);
      cfg_partition(p);
      smp_chkcon_changes(1);
      break;
    case EV_SYSTEM_SN:
      cfg_system_sn(p);
      break;
    case EV_ENVIRONMENT:
      cfg_environmental(p);
      break;
    case EV_IGNORED:
      return;
    case EV_L2_CONFIG:
      smp_chkcon_changes(0);
      L2CfgMCfgL2(&L2CfgLocal,p);
      smp_chkcon_changes(1);
      break;
    }
  }
  if (IR_ADDR_TASK(src) != IR_L1_CFG)
    return;
  for (port = 0; port < L2CFG_PORTS && ping_port < 0; port++) {
    l2port = &L2CfgLocal.port_list[port];
    if (l2port->state != L2CFG_PORT_CONFIGURED)
      continue;
    for (l1 = 0; l1 < l2port->l1count && ping_port < 0; l1++)
      if (l2port->l1cfg[l1].configured && l2port->l1cfg[l1].rack == (unsigned int)IR_ADDR_RACK(src) &&
          l2port->l1cfg[l1].slot == (unsigned int)IR_ADDR_SLOT(src))
        ping_port = port;
  }
  if (ping_port >= 0) {
    EventRemoveTimeOut(l2_l1_ports[ping_port].timer);
    l2_l1_ports[ping_port].timer =
        EventAddTimeOut(1,0,cfg_ping_l1,(EventData)(intptr_t)ping_port,"extra cfg_ping_l1");
  }
}

/* the brick an event (rack in argument 1, slot in 2) is about */
static L2CfgL1 *event_brick(IRPacket *p)
{
  return L2CfgMFindBrickCfg(&L2CfgLocal,arg_value(p,1),arg_value(p,2),0);
}

void cfg_console_subchannel(IRPacket *p)
{
  L2CfgL1 *cfg = event_brick(p);

  if (cfg != NULL) {
    cfg->console_subchannel = arg_value(p,3);
    L2CfgMGetConsole(&L2CfgLocal,-1);
  }
}

void cfg_console_enable(IRPacket *p)
{
  L2CfgL1 *cfg = event_brick(p);

  if (cfg != NULL)
    cfg->console_enabled = arg_value(p,3);
}

void cfg_power_state(IRPacket *p)
{
  L2CfgL1 *cfg = event_brick(p);

  if (cfg != NULL)
    cfg->power_state = arg_value(p,3);
}

void cfg_margin_state(IRPacket *p)
{
  L2CfgL1 *cfg = event_brick(p);

  if (cfg != NULL)
    cfg->margin_state = arg_value(p,3);
}

void cfg_partition(IRPacket *p)
{
  uint8 new_part = arg_value(p,3);
  L2CfgL1 *cfg = event_brick(p);

  if (cfg != NULL)
    cfg->partition = new_part;
}

void cfg_system_sn(IRPacket *p)
{
  L2CfgL1 *cfg = event_brick(p);
  const char *sn;

  if (cfg == NULL)
    return;
  sn = IR_ARG_TYPE(p->_argv[3]) == IR_ARG_VALUE ? (const char *)IR_VAL_PTR(p->_argv[3]._val)
                                                 : (const char *)IRArg(p,3);
  /* (the original strcpy()ed into the 12 bytes) */
  snprintf(cfg->system_sn,sizeof(cfg->system_sn),"%s",sn);
}

void cfg_environmental(IRPacket *p)
{
  int state = arg_value(p,3);
  L2CfgL1 *cfg = event_brick(p);

  if (cfg != NULL)
    cfg->env_state = state;
}

/* the length of the common start of two strings */
int strdiff(char *s1, char *s2)
{
  int index;

  for (index = 0; s1[index] != '\0' && s2[index] != '\0' && s1[index] == s2[index]; index++)
    ;
  return index;
}

/* check the configuration every delay seconds (0: never, which turns the
 * automatic rescans off) */
void cfg_setup_configcheck(int delay)
{
  static EventID timerid;

  if (timerid != 0)
    EventRemoveTimeOut(timerid);
  timerid = delay == 0 ? 0 : EventAddTimeOut(delay,0,cfg_configcheck,(EventData)1,"cfg_setup_config_check");
  cfg_auto_rescan = delay != 0;
}

/* look for other L2s every delay seconds (0: never; also sets the rescans) */
void cfg_setup_l2ping(int delay)
{
  static EventID timerid;

  if (timerid != 0)
    EventRemoveTimeOut(timerid);
  timerid = delay == 0 ? 0 : EventAddTimeOut(delay,0,cfg_l2ping,(EventData)1,"cfg_setup_l2ping");
  cfg_auto_rescan = delay != 0;
}

/* start_timer: hold configuration events for cfg_throttle_frequency
 * seconds; 0 (the timer): send one that was held */
static void cfg_configcheck_throttle(int start_timer)
{
  static EventID timerid;

  if (start_timer == 0) {
    timerid = 0;
    cfg_configcheck_hold = 0;
    if (cfg_configcheck_pending) {
      cfg_configcheck_pending = 0;
      cfg_configcheck(1);
    }
    return;
  }
  cfg_configcheck_hold = 1;
  if (timerid != 0)
    EventRemoveTimeOut(timerid);
  timerid = EventAddTimeOut(cfg_throttle_frequency,0,cfg_configcheck_throttle,NULL,"cfg_configcheck_throttle");
}

/* a string argument, or an empty value argument when s is NULL */
static void bytes_arg(IRArgument *arg, const char *s)
{
  memset(arg,0,sizeof(*arg));
  if (s == NULL)
    return;
  arg->_clas = IR_ARG_BYTES | IR_ARG_FREE;
  arg->_val = IR_PTR_VAL(strdup(s));
  arg->_size = strlen(s) + 1;
}

/* if the configuration or its events part changed since the last check,
 * send the changed part(s) to every client as an EV_L2_CONFIG event;
 * start_timer: check again in CONFIGCHECK_DELAY seconds */
void cfg_configcheck(int start_timer)
{
  static char *cfg_last;
  static char *evt_last;
  IRArgument argv[4];
  IRPacket *p;
  char *cfg_curr;
  char *evt_curr;
  int cfg_change;
  int evt_change;

  if (cfg_configcheck_hold) {
    cfg_configcheck_pending = 1;
    return;
  }
  cfg_curr = strdup(L2CfgMQuery(&L2CfgLocal,0,0));
  evt_curr = strdup(L2CfgMQuery(&L2CfgLocal,2,0));
  if (cfg_last == NULL) {
    cfg_change = evt_change = 1;
    cfg_last = cfg_curr;
    evt_last = evt_curr;
  }
  else {
    cfg_change = strcmp(cfg_last,cfg_curr) != 0;
    if (cfg_change) {
      free(cfg_last);
      cfg_last = cfg_curr;
    }
    else
      free(cfg_curr);
    evt_change = strcmp(evt_last,evt_curr) != 0;
    if (evt_change) {
      free(evt_last);
      evt_last = evt_curr;
    }
    else
      free(evt_curr);
  }
  if (cfg_change || evt_change) {
    memset(argv,0,sizeof(argv));
    argv[1]._val = CFG_FORMAT;
    bytes_arg(&argv[2],cfg_change ? cfg_last : NULL);
    bytes_arg(&argv[3],evt_change ? evt_last : NULL);
    p = IRouterMakePacket(&l2_cfg_id,NULL,0,EV_L2_CONFIG,IR_EVT,2,4,argv);
    if (p == NULL)
      fprintf(stderr,"ERROR: can\'t create packet for configuration event.\n");
    else {
      IRouterSendPacket(&l2_cfg_id,p);
      cfg_configcheck_throttle(1);
    }
  }
  if (cfg_auto_rescan && start_timer)
    cfg_setup_configcheck(CONFIGCHECK_DELAY);
}

/* the console output this L2 wants from other L2s: the partitions its
 * consoles and its L3 tools follow */
void cfg_check_console_events(void)
{
  L2CfgPSelect pselect;
  unsigned int emsk = L2CfgLocal.net.events;
  L2CfgNode *node;
  int p;

  memcpy(pselect,L2CfgLocal.net.pselect,sizeof(pselect));
  if (smp_console_count(pselect) > 0)
    emsk |= 1;
  for (node = L2CfgLocal.l3_clients; node != NULL; node = node->next) {
    if (!(node->events & 1))
      continue;
    emsk |= 1;
    for (p = 0; p < (int)sizeof(pselect); p++)
      pselect[p] |= node->pselect[p];
  }
  if (emsk != L2CfgLocal.net.events || memcmp(pselect,L2CfgLocal.net.pselect,sizeof(pselect)) != 0) {
    L2CfgLocal.net.events = emsk;
    memcpy(L2CfgLocal.net.pselect,pselect,sizeof(pselect));
    cfg_configcheck(1);
  }
}

/* ... and L2 console events, if an L3 tool follows them */
void cfg_check_smp_events(void)
{
  unsigned int emsk = L2CfgLocal.net.events;
  L2CfgNode *node;

  for (node = L2CfgLocal.l3_clients; node != NULL; node = node->next)
    if (node->events & 8)
      emsk |= 8;
  if (emsk != L2CfgLocal.net.events) {
    L2CfgLocal.net.events = emsk;
    cfg_configcheck(1);
  }
}

void cfg_connect(RouterClient *client)
{
  cfg_check_console_events();
  cfg_check_smp_events();
}

/* a client went: an L2 is gone from the clients' configurations too */
void cfg_disconnect(RouterClient *client)
{
  IRArgument rarg[3];
  char qbuf[100];
  IRPacket *pkt;

  if (client->port == IR_PORT_BIAS + L2_PEER_PORT) {
    sprintf(qbuf,"l2:%s,DELETE_L2:1",inet_ntoa(*(struct in_addr *)&client->addr));
    memset(rarg,0,sizeof(rarg));
    rarg[0]._val = CFG_REQ_EXCHANGE;
    rarg[1]._val = CFG_FORMAT;
    rarg[2]._clas = IR_ARG_STRING;
    rarg[2]._val = IR_PTR_VAL(qbuf);
    rarg[2]._size = strlen(qbuf) + 1;
    pkt = IRouterMakePacket(&l2_cfg_id,NULL,0,EV_L2_CONFIG,IR_EVT,2,3,rarg);
    if (pkt == NULL)
      fprintf(stderr,"ERROR: can\'t create packet to update L2/L3 client configs.\n");
    else {
      IRouterSendBroadcastPacketToClients(&l2_cfg_id,pkt);
      IRouterFreePacket(pkt);   /* (the original freed it when NULL, too) */
    }
  }
  cfg_check_console_events();
  cfg_check_smp_events();
  smp_chkcon_changes(0);
  L2CfgMGetConsole(&L2CfgLocal,-1);
  smp_chkcon_changes(1);
}

void cfg_establish(RouterClient *client)
{
  cfg_ping_l2(client);
}

/* an answer to our discovery request: connect to an L2 we don't know;
 * one we know has given a heartbeat */
void cfg_recv_l2ping(void *cd, int sd)
{
  sn1SC_L2 l2cfg;
  L2CfgNode *l2node;
  char *ip;
  int msgnbr;

  if (sn1SCDiscoverL2Response(sd,&l2cfg,1) != 0)
    return;
  ip = inet_ntoa(*(struct in_addr *)&l2cfg.ip_addr);
  l2node = L2CfgMFindNode(&L2CfgLocal,l2cfg.ip_addr,0,NULL);
  if (l2node == NULL) {
    msgnbr = EnetServerConnect(ip,IR_PORT_BIAS + L2_PEER_PORT);
    if (msgnbr == 0)
      fprintf(stderr,"INFO: connection to %s initiated\n",ip);
    else
      fprintf(stderr,"INFO: can\'t connect to %s, %s\n",ip,LoggerDefaultMessage(msgnbr));
  }
  else if (l2node->heartbeat != 0xffffffff)
    l2node->heartbeat++;
}

static void find_client_to_delete(RouterClient *client)
{
  if (client->addr == del_addr && client->port == IR_PORT_BIAS + L2_PEER_PORT)
    del_client = client;
}

/*
 * The L2 ping: every cfg_ping_response_maximum calls, drop the L2s that
 * gave fewer than cfg_ping_response_minimum heartbeats since the last time
 * (those that never finished connecting, and connected ones); then send a
 * discovery request (whose answers are the heartbeats). start_timer: again
 * in cfg_ping_l2_frequency seconds.
 */
void cfg_l2ping(int start_timer)
{
  static int initial = 1;
  static int check;
  char client_data[200];
  L2CfgNode *next;
  L2CfgNode *node;

  if (!initial && check >= cfg_ping_response_maximum - 1) {
    for (node = L2CfgLocal.net.next; node != NULL; node = next) {
      next = node->next;
      if (node->client == NULL && node->heartbeat < (unsigned int)cfg_ping_response_minimum) {
        fprintf(stderr,"INFO: L2 %s failed to complete connection\n",
                inet_ntoa(*(struct in_addr *)&node->ip_addr));
        del_addr = node->ip_addr;
        del_client = NULL;
        RouterListClients(find_client_to_delete);
        if (del_client == NULL) {
          /* (the original tried this node again, without end) */
          fprintf(stderr,"ERROR: couldn\'t find L2 client to delete!\n");
          continue;
        }
        node->client = del_client;
        L2CfgMDeleteNode(&L2CfgLocal,del_client);
        RouterClose(del_client);
      }
      else if (node->client == NULL || node->heartbeat >= (unsigned int)cfg_ping_response_minimum)
        node->heartbeat = 0;
      else {
        del_client = node->client;
        fprintf(stderr,"INFO: L2 %s not responding, closing connection\n",node->client->id.hostname);
        L2CfgMDeleteNode(&L2CfgLocal,del_client);
        RouterClose(del_client);
      }
    }
    check = 0;
  }
  else
    check++;
  discovery_request(client_data,0);
  cfg_l2ping_sd = sn1SCDiscoverL2Start(cfg_l2ping_sd,NULL,client_data);
  if (cfg_l2ping_sd < 0)
    fprintf(stderr,"ERROR: can\'t attempt to ping other L2\'s\n");
  else if (cfg_auto_rescan && start_timer)
    cfg_setup_l2ping(cfg_ping_l2_frequency);
  initial = 0;
}
