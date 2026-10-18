/*
 * sys_ctrl/l3/l2/cfg.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/cfg.c
 */

#include "../api/SCapiL2.h"   /* needed by the reconstruction */
#include "discover.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "l2.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
#include <stddef.h>
#include <getopt.h>
#include <string.h>
#include "../../common/Router/Socket.h"
#include "../../common/Router/Event.h"
#include <sys/time.h>
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/sysctl_types.h"
#include "../../common/sys/sysutils.h"
#include <pthread.h>
#include "../../common/sys/Logger.h"
#include "../sys/LoggerMsg.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../../common/Router/Router.h"
#include "../../common/sys/PPP.h"
#include "../../common/sys/brick_types.h"
#include "../../common/main/EnetServer.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/main/L1Cfg.h"
#include "l2_rev.h"
#include "l1.h"
#include "smp.h"
#include "l2cmd.h"
#include "dest.h"
#include "format.h"
#include "irtr.h"
#include "../main/nvram.h"
#include "../../common/sys/ipmi.h"
#include "../../common/sys/syslog.h"
#include "../api/SCapi.h"
#include "cfg.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void cfg_configcheck_throttle(int start_timer);
static void find_client_to_delete(RouterClient *client);

int cfg_start_time;
int cfg_auto_rescan = 1;
int cfg_l2ping_sd = -1;
static int cfg_configcheck_hold;
static int cfg_configcheck_pending;
int cfg_ping_response_minimum;
int cfg_ping_response_maximum;
int cfg_ping_l2_frequency;
int cfg_ping_l1_frequency;
int cfg_throttle_frequency;
int cfg_ping_sender_valid;
char cfg_client_id[30];
RouterClient *del_client;
uint32 del_addr;

void cfg_ping_reset(void)
{
  cfg_ping_response_minimum = 1;
  nvramSet(0xb,1);
  cfg_ping_response_maximum = 3;
  nvramSet(0xc,3);
  cfg_ping_l2_frequency = 5;
  nvramSet(0xe,5);
  cfg_ping_l1_frequency = 5;
  nvramSet(0xf,5);
  cfg_throttle_frequency = 2;
  cfg_ping_sender_valid = 2;
  nvramSet(0xd,2);
  return;
}

void cfg_ping_init(void)
{
  uint32 uVar1;
  
  uVar1 = nvramGet(0xb);
  if ((((uVar1 == 0) || (uVar1 = nvramGet(0xc), uVar1 == 0)) || (uVar1 = nvramGet(0xd), uVar1 == 0))
     || ((uVar1 = nvramGet(0xe), uVar1 == 0 || (uVar1 = nvramGet(0xf), uVar1 == 0)))) {
    cfg_ping_reset();
  }
  cfg_ping_response_minimum = nvramGet(0xb);
  cfg_ping_response_maximum = nvramGet(0xc);
  cfg_ping_l2_frequency = nvramGet(0xe);
  cfg_ping_l1_frequency = nvramGet(0xf);
  cfg_ping_sender_valid = nvramGet(0xd);
  cfg_throttle_frequency = 2;
  return;
}

void cfg_init(void)
{
  int iVar1;
  __pid_t _Var2;
  char *pcVar3;
  uint32 uVar4;
  size_t sVar5;
  char client_data [200];
  uint32 cfg_ip;
  int sd;
  
  cfg_start_time = time(NULL);
  cfg_ping_init();
  iVar1 = SocketGetHostAddr(&cfg_ip);
  if (iVar1 == 0) {
    _Var2 = getpid();
    pcVar3 = inet_ntoa(*(struct in_addr *)&cfg_ip);
    sprintf(cfg_client_id,"clientid:%s.%d",pcVar3,_Var2);
    cfg_setup_configcheck(7);
    if ((l2_discover != 0) && (L2CfgLocal.net.msmode != 1)) {
      uVar4 = nvramGet(5);
      if (uVar4 == 1) {
        uVar4 = nvramGet(3);
        sprintf(client_data,"%s,ssn:%s",cfg_client_id,uVar4);
      }
      else {
        strcpy(client_data,cfg_client_id);
      }
      if (L2CfgLocal.net.msmode == 2) {
        pcVar3 = ",l2pri:0";
        sVar5 = strlen(client_data);
        sprintf(client_data + sVar5,pcVar3);
      }
      else if (L2CfgLocal.net.msmode == 1) {
        pcVar3 = ",l2sec:0";
        sVar5 = strlen(client_data);
        sprintf(client_data + sVar5,pcVar3);
      }
      else {
        strcat(client_data,",l2:1");
      }
      if ((discover_debug & 1U) != 0) {
        fprintf(stderr,"sending L2 discover request: client_data=[%s]\n",client_data);
      }
      cfg_l2ping_sd = sn1SCDiscoverL2Start(-1,NULL,client_data);
      if (cfg_l2ping_sd < 0) {
        fprintf(stderr,"ERROR: can\'t attempt to find other L2\'s\n");
      }
      else {
        EventAddInput(cfg_l2ping_sd,cfg_recv_l2ping,(EventData)0x0,"cfg_init");
        cfg_setup_l2ping(cfg_ping_l2_frequency);
      }
    }
  }
  else {
    syslog(2,"cfg.c",0x6c,0,"cfg_init: couldn\'t get IP address for local host\n");
  }
  return;
}

void cfg_ping_l1(int device)
{
  size_t sVar1;
  char *__dest;
  IRPacket *p;
  EventID EVar2;
  char *__src;
  char desc [48];
  int ping_delay;
  char x [80];
  IRAddress toaddr;
  int fd;
  char *ssn;
  int port;
  IRArgument argv [3];
  
  fd = -1;
  toaddr = 0xffff00e;
  if (cfg_auto_rescan == 0) goto LAB_0805270c;
  switch(l2_l1_conn_mode) {
  case 1:
  case 2:
  case 5:
    fd = l2_l1_ports[device].fd;
    port = device;
    break;
  case 3:
  case 4:
    port = 0;
    fd = l2_l1_ports[0].fd;
    break;
  default:
    goto switchD_08052562_default;
  }
  if (fd == -1) {
    return;
  }
switchD_08052562_default:
  if (fd == -1) {
    return;
  }
  argv[0]._clas = '\0';
  argv[0]._frame = '\0';
  argv[0]._val = 6;
  argv[0]._size = 0;
  ssn = (char *)nvramGet(3);
  sVar1 = strlen(ssn);
  if (sVar1 == 0) {
    argv[1]._clas = '\0';
    argv[1]._frame = '\0';
    argv[1]._val = 0;
    argv[1]._size = 0;
  }
  else {
    argv[1]._clas = '\t';
    argv[1]._frame = '\0';
    __src = ssn;
    sVar1 = strlen(ssn);
    __dest = malloc(sVar1 + 1);
    argv[1]._val = IR_PTR_VAL(strcpy(__dest,__src));
    sVar1 = strlen(ssn);
    argv[1]._size = (short)sVar1 + 1;
  }
  argv[2]._clas = '\0';
  argv[2]._frame = '\0';
  argv[2]._val = 0;
  argv[2]._size = 0;
  p = IRouterMakePacket(&l2_cfg_id,&toaddr,0,0,0,2,3,argv);
  if (p == NULL) {
    fprintf(stderr,"ERROR: can\'t create packet for configuration request.\n");
    return;
  }
  if ((irtr_debug & 8U) != 0) {
    IRFmtPkt("L2",p,x);
    fprintf(stderr,"%s (port %d)\n",x,port);
  }
  l1_write_packet(fd,p);
LAB_0805270c:
  if (0 < l2_l1_ports[port].fd) {
    ping_delay = cfg_ping_l1_frequency;
    if (L2CfgLocal.port_list[port].state != 2) {
      ping_delay = 2;
    }
    sprintf(desc,"cfg_ping_l1 (%s)",l2_l1_ports[port].device);
    EVar2 = EventAddTimeOut(ping_delay,0,cfg_ping_l1,(EventData)(intptr_t)device,desc);
    l2_l1_ports[port].timer = EVar2;
  }
  return;
}

void cfg_ping_l2(RouterClient *client)
{
  char *pcVar1;
  char *pcVar2;
  size_t sVar3;
  uint32_t uVar4;
  IRPacket *p;
  int x;
  IRAddress dst;
  IRArgument argv [4];
  char *s;
  
  dst = 0;
  argv[0]._clas = '\0';
  argv[0]._frame = '\0';
  argv[0]._val = 1;
  argv[0]._size = 0;
  argv[1]._clas = '\0';
  argv[1]._frame = '\0';
  argv[1]._val = 2;
  argv[1]._size = 0;
  pcVar1 = L2CfgMQuery(&L2CfgLocal,0,0);
  pcVar2 = L2CfgMQuery(&L2CfgLocal,0,0);
  sVar3 = strlen(pcVar2);
  pcVar2 = malloc(sVar3 + 1);
  argv[2]._val = IR_PTR_VAL(strcpy(pcVar2,pcVar1));
  argv[2]._clas = '\n';
  argv[2]._frame = '\0';
  sVar3 = strlen((char *)IR_VAL_PTR(argv[2]._val));
  argv[2]._size = (short)sVar3 + 1;
  pcVar1 = L2CfgMQuery(&L2CfgLocal,2,0);
  pcVar2 = L2CfgMQuery(&L2CfgLocal,2,0);
  sVar3 = strlen(pcVar2);
  pcVar2 = malloc(sVar3 + 1);
  argv[3]._val = IR_PTR_VAL(strcpy(pcVar2,pcVar1));
  argv[3]._clas = '\n';
  argv[3]._frame = '\0';
  sVar3 = strlen((char *)IR_VAL_PTR(argv[3]._val));
  argv[3]._size = (short)sVar3 + 1;
  dst = (dst & 0xffffff) | 0x84000000;
  if (IRByteOrder == 1) {
    dst = (client->addr & 0xffffff) | 0x84000000;
  }
  else {
    uVar4 = ntohl(client->addr);
    dst = (dst & 0xff000000) | (uVar4 & 0xffffff);
  }
  p = IRouterMakePacket(&l2_cfg_id,&dst,0,0,0,2,4,argv);
  if (p == NULL) {
    fprintf(stderr,"ERROR: can\'t create packet for configuration request.\n");
  }
  else {
    IRouterSendPacket(NULL,p);
  }
  return;
}

void cfg_process_request(IRPacket *req_p)
{
  int iVar1;
  char *pcVar2;
  char *local_EAX_1156;
  size_t sVar3;
  IRPacket *rsp_p;
  unsigned int uVar4;
  size_t sStack_f8b0;
  char *bptr;
  char buff [63489];
  int blk;
  int blks;
  int clen;
  IRAddress src;
  char *evt;
  char *cfg;
  int argc;
  IRArgument argv [16];
  
  argv[0]._clas = '\0';
  argv[0]._frame = '\0';
  argv[0]._val = 0;
  argv[0]._size = 0;
  argv[1]._clas = '\0';
  argv[1]._frame = '\0';
  argv[1]._val = 2;
  argv[1]._size = 0;
  argc = 2;
  if ((req_p->_argv[0]._clas & 7) == 0) {
    uVar4 = req_p->_argv[0]._val;
  }
  else {
    uVar4 = IRArg(req_p,0);
  }
  if (uVar4 == 0) {
    local_EAX_1156 = L2CfgMQuery(&L2CfgLocal,1,0);
    pcVar2 = L2CfgMQuery(&L2CfgLocal,1,0);
    sVar3 = strlen(pcVar2);
    pcVar2 = malloc(sVar3 + 1);
    cfg = strcpy(pcVar2,local_EAX_1156);
    local_EAX_1156 = L2CfgMQuery(&L2CfgLocal,2,0);
    pcVar2 = L2CfgMQuery(&L2CfgLocal,2,0);
    sVar3 = strlen(pcVar2);
    pcVar2 = malloc(sVar3 + 1);
    evt = strcpy(pcVar2,local_EAX_1156);
  }
  else if (uVar4 == 1) {
    local_EAX_1156 = L2CfgMQuery(&L2CfgLocal,0,0);
    pcVar2 = L2CfgMQuery(&L2CfgLocal,0,0);
    sVar3 = strlen(pcVar2);
    pcVar2 = malloc(sVar3 + 1);
    cfg = strcpy(pcVar2,local_EAX_1156);
    local_EAX_1156 = L2CfgMQuery(&L2CfgLocal,2,0);
    pcVar2 = L2CfgMQuery(&L2CfgLocal,2,0);
    sVar3 = strlen(pcVar2);
    pcVar2 = malloc(sVar3 + 1);
    evt = strcpy(pcVar2,local_EAX_1156);
    if (2 < req_p->_argc) {
      smp_chkcon_changes(0);
      L2CfgMCfgL2(&L2CfgLocal,req_p);
      smp_chkcon_changes(1);
    }
  }
  clen = strlen(cfg);
  iVar1 = clen / 0xf800;
  for (blk = 0; blk < iVar1 + 1; blk = blk + 1) {
    memset(buff,0,0xf801);
    if (clen < 0xf801) {
      sStack_f8b0 = clen;
    }
    else {
      sStack_f8b0 = 0xf800;
    }
    memcpy(buff,cfg + blk * 0xf800,sStack_f8b0);
    clen = clen + -0xf800;
    local_EAX_1156 = buff;
    sVar3 = strlen(buff);
    pcVar2 = malloc(sVar3 + 1);
    local_EAX_1156 = strcpy(pcVar2,local_EAX_1156);
    argv[argc]._clas = '\n';
    argv[argc]._frame = '\0';
    argv[argc]._val = IR_PTR_VAL(local_EAX_1156);
    sVar3 = strlen(local_EAX_1156);
    argv[argc]._size = (short)sVar3 + 1;
    argc = argc + 1;
  }
  free(cfg);
  argv[argc]._clas = '\n';
  argv[argc]._frame = '\0';
  argv[argc]._val = IR_PTR_VAL(evt);
  sVar3 = strlen(evt);
  argv[argc]._size = (short)sVar3 + 1;
  rsp_p = IRouterMakePacket(&l2_cfg_id,&req_p->_src,(unsigned int)(req_p->_pdata_auth >> 3),0,1,
                            (unsigned int)req_p->_rev,argc + 1,argv);
  if (rsp_p == NULL) {
    fprintf(stderr,"ERROR: can\'t create packet for configuration response.\n");
  }
  else {
    rsp_p->_seqnum0 = req_p->_seqnum0;
    rsp_p->_seqnum1 = req_p->_seqnum1;
    IRouterSendPacket(NULL,rsp_p);
  }
  uVar4 = req_p->_src;
  if (((uVar4 & 0x80000000) != 0) || (uVar4 >> 0x1c != 1)) {
    if ((uVar4 & 0x80000000) == 0) {
      if (uVar4 >> 0x1c != 0xe) goto LAB_080532b0;
    }
    else if (uVar4 >> 0x1e != 2) goto LAB_080532b0;
  }
  if ((uVar4 & 0x80000000) == 0) {
    uVar4 = uVar4 & 0x1f;
  }
  else {
    uVar4 = uVar4 >> 0x18 & 0x3f;
  }
  if (uVar4 == 4) {
    req_p->_clas = '\x02';
    IRouterSendBroadcastPacketToClients(&l2_cfg_id,req_p);
  }
LAB_080532b0:
  IRouterFreePacket(req_p);
  return;
}

void cfg_process_response(IRPacket *p)
{
  uint8 *client_data;
  unsigned int uVar1;
  char *pcVar2;
  int config_changed;
  FILE *stream;
  EventID EVar3;
  IRAddress paddr;
  char odname [60];
  L2CfgPort *l2port;
  int ostate;
  int port;
  IRAddress src;
  
  if (p->_err == '\0') {
    if ((p->_src & 0x80000000) == 0) {
      uVar1 = p->_src >> 0x1c;
    }
    else if (p->_src >> 0x1e == 2) {
      uVar1 = 0xe;
    }
    else {
      uVar1 = 0xf;
    }
    if (uVar1 == 0) {
      if (1 < l1usb_debug) {
        l2port = L2CfgMGetPort(&L2CfgLocal,(int)(intptr_t)p->_client_data);
        ostate = l2port->state;
        pcVar2 = L2CfgMDeviceName(&L2CfgLocal,l2port->fd);
        strcpy(odname,pcVar2);
      }
      smp_chkcon_changes(0);
      config_changed = L2CfgMCfgPort(&L2CfgLocal,(int)(intptr_t)p->_client_data,p);
      smp_chkcon_changes(1);
      if (((1 < l1usb_debug) && (ostate != 2)) && (l2port->state == 2)) {
        pcVar2 = L2CfgMDeviceName(&L2CfgLocal,l2port->fd);
        stream = stderr;
        if (l1usb_debug != 0) {
          stream = NULL;
        }
        fprintf(stream,"INFO: USB device %s configured: %s\n",odname,pcVar2);
      }
      if (config_changed != 0) {
        client_data = p->_client_data;
        EventRemoveTimeOut(l2_l1_ports[(int)(intptr_t)client_data].timer);
        EVar3 = EventAddTimeOut(1,0,cfg_ping_l1,(EventData)client_data,"extra cfg_ping_l1");
        l2_l1_ports[(int)(intptr_t)client_data].timer = EVar3;
        cfg_configcheck(1);
      }
    }
    else if (uVar1 == 0xe) {
      smp_chkcon_changes(0);
      L2CfgMCfgL2(&L2CfgLocal,p);
      smp_chkcon_changes(1);
    }
  }
  uVar1 = p->_src;
  if (((uVar1 & 0x80000000) != 0) || (uVar1 >> 0x1c != 1)) {
    if ((uVar1 & 0x80000000) == 0) {
      if (uVar1 >> 0x1c != 0xe) goto LAB_08053588;
    }
    else if (uVar1 >> 0x1e != 2) goto LAB_08053588;
  }
  if ((uVar1 & 0x80000000) == 0) {
    uVar1 = uVar1 & 0x1f;
  }
  else {
    uVar1 = uVar1 >> 0x18 & 0x3f;
  }
  if (uVar1 == 4) {
    p->_clas = '\x02';
    IRouterSendBroadcastPacketToClients(&l2_cfg_id,p);
  }
LAB_08053588:
  IRouterFreePacket(p);
  return;
}

void pp(IRPacket *p)
{
  char *sptr;
  int slen_;
  char *sptr_;
  int slen;
  int arg;
  
  for (arg = 0; arg < (int)(unsigned int)p->_argc; arg = arg + 1) {
    if ((p->_argv[arg]._clas & 7) == 1) {
      if ((p->_argv[arg]._clas & 7) == 0) {
        sptr = (char *)IR_VAL_PTR(p->_argv[arg]._val);
      }
      else {
        sptr = (char *)IRArg(p,arg);
      }
      fprintf(stderr,"%s\n",sptr);
    }
  }
  return;
}

void cfg_process_event(IRPacket *p)
{
  unsigned short uVar1;
  unsigned int uVar2;
  L2CfgL1 *pLVar3;
  EventID EVar4;
  unsigned int uVar5;
  L2CfgL1 *cfg;
  L2CfgPort *l2port;
  int ping_port;
  int l1;
  int port;
  int slot;
  int rack;
  IRAddress src;
  
  uVar2 = p->_src;
  if (p->_err == '\0') {
    uVar1 = p->_opcode;
    if (uVar1 == 6) {
      smp_chkcon_changes(0);
      cfg_partition(p);
      smp_chkcon_changes(1);
    }
    else if (uVar1 < 7) {
      if (uVar1 == 3) {
        cfg_console_enable(p);
      }
      else if (uVar1 < 4) {
        if (uVar1 == 2) {
          smp_chkcon_changes(0);
          cfg_console_subchannel(p);
          smp_chkcon_changes(1);
        }
      }
      else if (uVar1 == 4) {
        cfg_power_state(p);
      }
      else if (uVar1 == 5) {
        cfg_margin_state(p);
      }
    }
    else if (uVar1 == 8) {
      cfg_environmental(p);
    }
    else if (uVar1 < 8) {
      cfg_system_sn(p);
    }
    else {
      if (uVar1 == 100) {
        return;
      }
      if (uVar1 == 1000) {
        smp_chkcon_changes(0);
        L2CfgMCfgL2(&L2CfgLocal,p);
        smp_chkcon_changes(1);
      }
    }
  }
  if ((uVar2 & 0x80000000) == 0) {
    uVar5 = uVar2 & 0x1f;
  }
  else {
    uVar5 = uVar2 >> 0x18 & 0x3f;
  }
  if (uVar5 == 0xe) {
    ping_port = -1;
    port = 0;
    while ((port < 0x28 && (ping_port < 0))) {
      if (L2CfgLocal.port_list[port].state == 2) {
        l1 = 0;
        while ((l1 < L2CfgLocal.port_list[port].l1count && (ping_port < 0))) {
          pLVar3 = L2CfgLocal.port_list[port].l1cfg;
          if ((pLVar3[l1].configured != '\0') &&
             (((unsigned int)pLVar3[l1].rack == (uVar2 >> 0x12 & 0x3ff) &&
              ((unsigned int)pLVar3[l1].slot == (uVar2 >> 0xc & 0x3f))))) {
            ping_port = port;
          }
          l1 = l1 + 1;
        }
      }
      port = port + 1;
    }
    if (-1 < ping_port) {
      EventRemoveTimeOut(l2_l1_ports[ping_port].timer);
      EVar4 = EventAddTimeOut(1,0,cfg_ping_l1,(EventData)(intptr_t)ping_port,"extra cfg_ping_l1");
      l2_l1_ports[ping_port].timer = EVar4;
    }
  }
  return;
}

void cfg_console_subchannel(IRPacket *p)
{
  int rack;
  int slot;
  L2CfgL1 *cfg;
  uint32 uVar1;
  IRAddress addr;
  int part;
  
  if ((p->_argv[1]._clas & 7) == 0) {
    rack = (int)p->_argv[1]._val;
  }
  else {
    rack = IRArg(p,1);
  }
  if ((p->_argv[2]._clas & 7) == 0) {
    slot = (int)p->_argv[2]._val;
  }
  else {
    slot = IRArg(p,2);
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
  if (cfg != NULL) {
    if ((p->_argv[3]._clas & 7) == 0) {
      uVar1 = p->_argv[3]._val;   /* bytes 64..67 of the packet */
    }
    else {
      uVar1 = IRArg(p,3);
    }
    cfg->console_subchannel = uVar1;
    L2CfgMGetConsole(&L2CfgLocal,-1);
  }
  return;
}

void cfg_console_enable(IRPacket *p)
{
  unsigned int rack_00;
  int slot;
  L2CfgL1 *cfg;
  int rack;
  uint8 uStack_11;
  
  if ((p->_argv[1]._clas & 7) == 0) {
    rack_00 = (unsigned int)p->_argv[1]._val;
  }
  else {
    rack_00 = IRArg(p,1);
  }
  if ((p->_argv[2]._clas & 7) == 0) {
    slot = (int)p->_argv[2]._val;
  }
  else {
    slot = IRArg(p,2);
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack_00,slot,0);
  if (cfg != NULL) {
    if ((p->_argv[3]._clas & 7) == 0) {
      uStack_11 = (uint8)p->_argv[3]._val;
    }
    else {
      rack = IRArg(p,3);
      uStack_11 = (uint8)rack;
    }
    cfg->console_enabled = uStack_11;
  }
  return;
}

void cfg_power_state(IRPacket *p)
{
  unsigned int rack_00;
  int slot;
  L2CfgL1 *cfg;
  int rack;
  uint8 uStack_11;
  
  if ((p->_argv[1]._clas & 7) == 0) {
    rack_00 = (unsigned int)p->_argv[1]._val;
  }
  else {
    rack_00 = IRArg(p,1);
  }
  if ((p->_argv[2]._clas & 7) == 0) {
    slot = (int)p->_argv[2]._val;
  }
  else {
    slot = IRArg(p,2);
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack_00,slot,0);
  if (cfg != NULL) {
    if ((p->_argv[3]._clas & 7) == 0) {
      uStack_11 = (uint8)p->_argv[3]._val;
    }
    else {
      rack = IRArg(p,3);
      uStack_11 = (uint8)rack;
    }
    cfg->power_state = uStack_11;
  }
  return;
}

void cfg_margin_state(IRPacket *p)
{
  unsigned int rack_00;
  int slot;
  L2CfgL1 *cfg;
  int rack;
  uint8 uStack_11;
  
  if ((p->_argv[1]._clas & 7) == 0) {
    rack_00 = (unsigned int)p->_argv[1]._val;
  }
  else {
    rack_00 = IRArg(p,1);
  }
  if ((p->_argv[2]._clas & 7) == 0) {
    slot = (int)p->_argv[2]._val;
  }
  else {
    slot = IRArg(p,2);
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack_00,slot,0);
  if (cfg != NULL) {
    if ((p->_argv[3]._clas & 7) == 0) {
      uStack_11 = (uint8)p->_argv[3]._val;
    }
    else {
      rack = IRArg(p,3);
      uStack_11 = (uint8)rack;
    }
    cfg->margin_state = uStack_11;
  }
  return;
}

void cfg_partition(IRPacket *p)
{
  int rack;
  int slot;
  unsigned int uVar1;
  L2CfgL1 *cfg;
  int old_part;
  IRAddress addr;
  uint8 new_part;
  
  if ((p->_argv[1]._clas & 7) == 0) {
    rack = (int)p->_argv[1]._val;
  }
  else {
    rack = IRArg(p,1);
  }
  if ((p->_argv[2]._clas & 7) == 0) {
    slot = (int)p->_argv[2]._val;
  }
  else {
    slot = IRArg(p,2);
  }
  if ((p->_argv[3]._clas & 7) == 0) {
    new_part = (uint8)p->_argv[3]._val;
  }
  else {
    uVar1 = IRArg(p,3);
    new_part = (uint8)uVar1;
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
  if (cfg != NULL) {
    cfg->partition = new_part;
  }
  return;
}

void cfg_system_sn(IRPacket *p)
{
  int rack;
  int slot;
  L2CfgL1 *cfg;
  char *__src;
  
  if ((p->_argv[1]._clas & 7) == 0) {
    rack = (int)p->_argv[1]._val;
  }
  else {
    rack = IRArg(p,1);
  }
  if ((p->_argv[2]._clas & 7) == 0) {
    slot = (int)p->_argv[2]._val;
  }
  else {
    slot = IRArg(p,2);
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
  if (cfg != NULL) {
    if ((p->_argv[3]._clas & 7) == 0) {
      __src = (char *)IR_VAL_PTR(p->_argv[3]._val);
    }
    else {
      __src = (char *)IRArg(p,3);
    }
    strcpy(cfg->system_sn,__src);
  }
  return;
}

void cfg_environmental(IRPacket *p)
{
  int rack;
  int slot;
  int state;
  L2CfgL1 *cfg;
  IRAddress addr;
  
  if ((p->_argv[1]._clas & 7) == 0) {
    rack = (int)p->_argv[1]._val;
  }
  else {
    rack = IRArg(p,1);
  }
  if ((p->_argv[2]._clas & 7) == 0) {
    slot = (int)p->_argv[2]._val;
  }
  else {
    slot = IRArg(p,2);
  }
  if ((p->_argv[3]._clas & 7) == 0) {
    state = p->_argv[3]._val;   /* bytes 64..67 of the packet */
  }
  else {
    state = IRArg(p,3);
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
  if (cfg != NULL) {
    cfg->env_state = state;
  }
  return;
}

int strdiff(char *s1, char *s2)
{
  int index;
  
  for (index = 0; ((s1[index] != '\0' && (s2[index] != '\0')) && (s1[index] == s2[index]));
      index = index + 1) {
  }
  return index;
}

void cfg_setup_configcheck(int delay)
{
  static EventID timerid;
  
  if (timerid != 0) {
    EventRemoveTimeOut(timerid);
  }
  if (delay == 0) {
    timerid = 0;
  }
  else {
    timerid = EventAddTimeOut(delay,0,cfg_configcheck,(EventData)0x1,"cfg_setup_config_check");
  }
  cfg_auto_rescan = (int)(delay != 0);
  return;
}

void cfg_setup_l2ping(int delay)
{
  static EventID timerid;
  
  if (timerid != 0) {
    EventRemoveTimeOut(timerid);
  }
  if (delay == 0) {
    timerid = 0;
  }
  else {
    timerid = EventAddTimeOut(delay,0,cfg_l2ping,(EventData)0x1,"cfg_setup_l2ping");
  }
  cfg_auto_rescan = (int)(delay != 0);
  return;
}

static void cfg_configcheck_throttle(int start_timer)
{
  static EventID timerid;
  
  if (start_timer == 0) {
    timerid = 0;
    cfg_configcheck_hold = 0;
    if (cfg_configcheck_pending != 0) {
      cfg_configcheck_pending = 0;
      cfg_configcheck(1);
    }
  }
  else {
    cfg_configcheck_hold = 1;
    if (timerid != 0) {
      EventRemoveTimeOut(timerid);
    }
    timerid = EventAddTimeOut(cfg_throttle_frequency,0,cfg_configcheck_throttle,(EventData)0x0,
                              "cfg_configcheck_throttle");
  }
  return;
}

void cfg_configcheck(int start_timer)
{
  static char *cfg_last;
  static char *evt_last;
  char *pcVar1;
  char *pcVar2;
  size_t sVar3;
  char *pcVar4;
  int iVar5;
  char *__dest;
  IRPacket *p;
  char *evt_curr;
  char *cfg_curr;
  IRArgument argv [4];
  bool cfg_change;
  bool evt_change;
  
  evt_change = false;
  if (cfg_configcheck_hold == 0) {
    pcVar1 = L2CfgMQuery(&L2CfgLocal,0,0);
    pcVar2 = L2CfgMQuery(&L2CfgLocal,0,0);
    sVar3 = strlen(pcVar2);
    pcVar2 = malloc(sVar3 + 1);
    pcVar1 = strcpy(pcVar2,pcVar1);
    pcVar2 = L2CfgMQuery(&L2CfgLocal,2,0);
    pcVar4 = L2CfgMQuery(&L2CfgLocal,2,0);
    sVar3 = strlen(pcVar4);
    pcVar4 = malloc(sVar3 + 1);
    pcVar2 = strcpy(pcVar4,pcVar2);
    if (cfg_last == NULL) {
      cfg_change = true;
      evt_change = true;
      cfg_last = pcVar1;
      evt_last = pcVar2;
    }
    else {
      iVar5 = strcmp(cfg_last,pcVar1);
      if (iVar5 == 0) {
        free(pcVar1);
      }
      else {
        free(cfg_last);
        cfg_last = pcVar1;
      }
      cfg_change = iVar5 != 0;
      iVar5 = strcmp(evt_last,pcVar2);
      if (iVar5 == 0) {
        free(pcVar2);
      }
      else {
        free(evt_last);
        evt_change = true;
        evt_last = pcVar2;
      }
    }
    if ((cfg_change) || (evt_change)) {
      argv[0]._clas = '\0';
      argv[0]._frame = '\0';
      argv[0]._val = 0;
      argv[0]._size = 0;
      argv[1]._clas = '\0';
      argv[1]._frame = '\0';
      argv[1]._val = 2;
      argv[1]._size = 0;
      if (cfg_change) {
        argv[2]._clas = '\t';
        argv[2]._frame = '\0';
        pcVar4 = pcVar1;
        sVar3 = strlen(pcVar1);
        __dest = malloc(sVar3 + 1);
        argv[2]._val = IR_PTR_VAL(strcpy(__dest,pcVar4));
        sVar3 = strlen(pcVar1);
        argv[2]._size = (short)sVar3 + 1;
      }
      else {
        argv[2]._clas = '\0';
        argv[2]._frame = '\0';
        argv[2]._val = 0;
        argv[2]._size = 0;
      }
      if (evt_change) {
        argv[3]._clas = '\t';
        argv[3]._frame = '\0';
        pcVar1 = pcVar2;
        sVar3 = strlen(pcVar2);
        pcVar4 = malloc(sVar3 + 1);
        argv[3]._val = IR_PTR_VAL(strcpy(pcVar4,pcVar1));
        sVar3 = strlen(pcVar2);
        argv[3]._size = (short)sVar3 + 1;
      }
      else {
        argv[3]._clas = '\0';
        argv[3]._frame = '\0';
        argv[3]._val = 0;
        argv[3]._size = 0;
      }
      p = IRouterMakePacket(&l2_cfg_id,NULL,0,1000,2,2,4,argv);
      if (p == NULL) {
        fprintf(stderr,"ERROR: can\'t create packet for configuration event.\n");
      }
      else {
        IRouterSendPacket(&l2_cfg_id,p);
        cfg_configcheck_throttle(1);
      }
    }
    if ((cfg_auto_rescan != 0) && (start_timer != 0)) {
      cfg_setup_configcheck(7);
    }
  }
  else {
    cfg_configcheck_pending = 1;
  }
  return;
}

void cfg_check_console_events(void)
{
  unsigned int uVar1;
  int iVar2;
  int p;
  L2CfgNode *node;
  L2CfgPSelect pselect;
  SMP *smp;
  int emsk;
  
  uVar1 = L2CfgLocal.net.events;
  emsk = L2CfgLocal.net.events;
  memcpy(pselect,L2CfgLocal.net.pselect,0x100);
  iVar2 = smp_console_count(pselect);
  if (0 < iVar2) {
    emsk = uVar1 | 1;
  }
  if (L2CfgLocal.l3_clients != NULL) {
    for (node = L2CfgLocal.l3_clients; node != NULL; node = node->next) {
      if ((node->events & 1) != 0) {
        emsk = emsk | 1;
        for (p = 0; p < 0x100; p = p + 1) {
          pselect[p] = pselect[p] | node->pselect[p];
        }
      }
    }
  }
  if (((unsigned int)emsk != L2CfgLocal.net.events) ||
     (iVar2 = memcmp(pselect,L2CfgLocal.net.pselect,0x100), iVar2 != 0)) {
    L2CfgLocal.net.events = emsk;
    memcpy(L2CfgLocal.net.pselect,pselect,0x100);
    cfg_configcheck(1);
  }
  return;
}

void cfg_check_smp_events(void)
{
  L2CfgNode *node;
  L2CfgPSelect pselect;
  int emsk;
  
  emsk = L2CfgLocal.net.events;
  if (L2CfgLocal.l3_clients != NULL) {
    for (node = L2CfgLocal.l3_clients; node != NULL; node = node->next) {
      if ((node->events & 8) != 0) {
        emsk = emsk | 8;
      }
    }
  }
  if ((unsigned int)emsk != L2CfgLocal.net.events) {
    L2CfgLocal.net.events = emsk;
    cfg_configcheck(1);
  }
  return;
}

int cfg_password(RouterClient *client, char *pwguess)
{
  int iVar1;
  char *pw;
  
  if ((client->port == IR_PORT_BIAS + 8000) || (client->port == IR_PORT_BIAS + 0x1f42)) {
    pw = (char *)nvramGet(0x13);
    if ((pw == NULL) || (*pw == '\0')) {
      iVar1 = 0;
    }
    else if ((pwguess == NULL) || (*pwguess == '\0')) {
      iVar1 = -1;
    }
    else {
      iVar1 = strcmp(pw,pwguess);
      if (iVar1 == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = -1;
      }
    }
  }
  else {
    iVar1 = 0;
  }
  return iVar1;
}

void cfg_connect(RouterClient *client)
{
  cfg_check_console_events();
  cfg_check_smp_events();
  return;
}

void cfg_disconnect(RouterClient *client)
{
  char *pcVar1;
  size_t sVar2;
  IRPacket *pkt;
  char qbuf [100];
  IRArgument rarg [3];
  
  if (client->port == IR_PORT_BIAS + 0x2329) {
    pcVar1 = inet_ntoa(*(struct in_addr *)&client->addr);
    sprintf(qbuf,"l2:%s,DELETE_L2:1",pcVar1);
    rarg[0]._clas = '\0';
    rarg[0]._frame = '\0';
    rarg[0]._val = 1;
    rarg[0]._size = 0;
    rarg[1]._clas = '\0';
    rarg[1]._frame = '\0';
    rarg[1]._val = 2;
    rarg[1]._size = 0;
    rarg[2]._clas = '\x02';
    rarg[2]._frame = '\0';
    rarg[2]._val = IR_PTR_VAL(qbuf);
    sVar2 = strlen(qbuf);
    rarg[2]._size = (short)sVar2 + 1;
    pkt = IRouterMakePacket(&l2_cfg_id,NULL,0,1000,2,2,3,rarg);
    if (pkt == NULL) {
      fprintf(stderr,"ERROR: can\'t create packet to update L2/L3 client configs.\n");
    }
    else {
      IRouterSendBroadcastPacketToClients(&l2_cfg_id,pkt);
    }
    IRouterFreePacket(pkt);
  }
  cfg_check_console_events();
  cfg_check_smp_events();
  smp_chkcon_changes(0);
  L2CfgMGetConsole(&L2CfgLocal,-1);
  smp_chkcon_changes(1);
  return;
}

void cfg_establish(RouterClient *client)
{
  cfg_ping_l2(client);
  return;
}

void cfg_recv_l2ping(void *cd, int sd)
{
  int rval;
  char *ip;
  L2CfgNode *l2node;
  int msgnbr;
  char *pcVar1;
  sn1SC_L2 l2cfg;
  
  rval = sn1SCDiscoverL2Response(sd,&l2cfg,1);
  if (rval == 0) {
    ip = inet_ntoa(*(struct in_addr *)&l2cfg.ip_addr);
    l2node = L2CfgMFindNode(&L2CfgLocal,l2cfg.ip_addr,0,NULL);
    if (l2node == NULL) {
      msgnbr = EnetServerConnect(ip,IR_PORT_BIAS + 0x2329);
      if (msgnbr == 0) {
        fprintf(stderr,"INFO: connection to %s initiated\n",ip);
      }
      else {
        pcVar1 = LoggerDefaultMessage(msgnbr);
        fprintf(stderr,"INFO: can\'t connect to %s, %s\n",ip,pcVar1);
      }
    }
    else if (l2node->heartbeat != 0xffffffff) {
      l2node->heartbeat = l2node->heartbeat + 1;
    }
  }
  return;
}

static void find_client_to_delete(RouterClient *client)
{
  if ((client->addr == del_addr) && (client->port == IR_PORT_BIAS + 0x2329)) {
    del_client = client;
  }
  return;
}

void cfg_l2ping(int start_timer)
{
  struct _L2CfgNode *p_Var1;
  static int initial = 1;
  static int check;
  uint32 uVar2;
  size_t sVar3;
  char *pcVar4;
  L2CfgNode *next;
  L2CfgNode *node;
  char client_data [200];
  
  if ((initial == 0) && (cfg_ping_response_maximum + -1 <= check)) {
    node = L2CfgLocal.net.next;
    while (node != NULL) {
      if ((node->client == NULL) &&
         (node->heartbeat < (unsigned int)cfg_ping_response_minimum)) {
        pcVar4 = inet_ntoa(*(struct in_addr *)&node->ip_addr);
        fprintf(stderr,"INFO: L2 %s failed to complete connection\n",pcVar4);
        p_Var1 = node->next;
        del_addr = node->ip_addr;
        del_client = NULL;
        RouterListClients(find_client_to_delete);
        if (del_client == NULL) {
          fprintf(stderr,"ERROR: couldn\'t find L2 client to delete!\n");
        }
        else {
          node->client = del_client;
          L2CfgMDeleteNode(&L2CfgLocal,del_client);
          RouterClose(del_client);
          node = p_Var1;
        }
      }
      else if ((node->client == NULL) ||
              ((unsigned int)cfg_ping_response_minimum <= node->heartbeat)) {
        node->heartbeat = 0;
        node = node->next;
      }
      else {
        del_client = node->client;
        fprintf(stderr,"INFO: L2 %s not responding, closing connection\n",&node->client->id);
        node = node->next;
        L2CfgMDeleteNode(&L2CfgLocal,del_client);
        RouterClose(del_client);
      }
    }
    check = 0;
  }
  else {
    check = check + 1;
  }
  uVar2 = nvramGet(5);
  if (uVar2 == 1) {
    uVar2 = nvramGet(3);
    sprintf(client_data,"%s,ssn:%s",cfg_client_id,uVar2);
  }
  else {
    strcpy(client_data,cfg_client_id);
  }
  if (L2CfgLocal.net.msmode == 2) {
    pcVar4 = ",l2pri:0";
    sVar3 = strlen(client_data);
    sprintf(client_data + sVar3,pcVar4);
  }
  else {
    strcat(client_data,",l2:1");
  }
  if ((discover_debug & 1U) != 0) {
    fprintf(stderr,"sending L2 discover request: client_data=[%s]\n",client_data);
  }
  cfg_l2ping_sd = sn1SCDiscoverL2Start(cfg_l2ping_sd,NULL,client_data);
  if (cfg_l2ping_sd < 0) {
    fprintf(stderr,"ERROR: can\'t attempt to ping other L2\'s\n");
  }
  else if ((cfg_auto_rescan != 0) && (start_timer != 0)) {
    cfg_setup_l2ping(cfg_ping_l2_frequency);
  }
  initial = 0;
  return;
}
