/*
 * sys_ctrl/l3/l2/irtr.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/irtr.c
 */

#include "cfg.h"   /* needed by the reconstruction */
#include "cmd.h"   /* needed by the reconstruction */
#include "l1.h"   /* needed by the reconstruction */
#include "lpbk.h"   /* needed by the reconstruction */
#include "power.h"   /* needed by the reconstruction */
#include "route.h"   /* needed by the reconstruction */
#include "smp.h"   /* needed by the reconstruction */
#include "l2.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "../../common/Router/Socket.h"
#include "../../common/Router/Event.h"
#include <sys/time.h>
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../../common/sys/sysutils.h"
#include <pthread.h>
#include <sched.h>
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
#include "irtr.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int irtr_debug;

int IRouterSendTargetedPacket(IRIdent *id, IRPacket *pkt)
{
  undefined2 uVar1;
  int iVar2;
  L2CfgNode *pLVar3;
  uint uVar4;
  uint32_t uVar5;
  IRAddress IVar6;
  RouterClient *pRVar7;
  int rval;
  int l1;
  int port;
  int ip;
  int task;
  IRAddress src;
  IRAddress dest;
  int type;
  int fd;
  L2CfgNode *node;
  
  fd = -1;
  dest = pkt->_dest;
  src = pkt->_src;
  if ((dest & 0x80000000) == 0) {
    type = dest >> 0x1c;
  }
  else if (dest >> 0x1e == 2) {
    type = 0xe;
  }
  else {
    type = 0xf;
  }
  if (type == 0xf) {
    node = L2CfgMFindNode(&L2CfgLocal,0,dest,NULL);
    if (node == NULL) {
      pRVar7 = NULL;
      IVar6 = 0;
      if (IRByteOrder == 1) {
        uVar5 = dest & 0xffffff;
      }
      else {
        uVar5 = htonl(dest & 0xffffff);
      }
      node = L2CfgMFindNode(&L2CfgLocal,uVar5,IVar6,pRVar7);
      if (node == NULL) {
        return -0x260;
      }
    }
    if ((L2Cfg *)node != &L2CfgLocal) {
      pkt->_use_count = 0;
      *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
      iVar2 = IRouterPacketToRouter(node->client,&l2_id,pkt);
      return iVar2;
    }
    if (pkt->_clas == '\x01') {
      pkt->_use_count = 0;
      *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
      smp_process_response(pkt);
      return 0;
    }
    return -0x260;
  }
  if ((dest & 0x80000000) == 0) {
    task = dest & 0x1f;
  }
  else {
    task = dest >> 0x18 & 0x3f;
  }
  if ((task == 0xd) || (task == 0x17)) {
    route_process(pkt);
  }
  if (type == 0xe) {
    pRVar7 = NULL;
    IVar6 = 0;
    if (IRByteOrder == 1) {
      uVar5 = dest & 0xffffff;
    }
    else {
      uVar5 = htonl(dest & 0xffffff);
    }
    node = L2CfgMFindNode(&L2CfgLocal,uVar5,IVar6,pRVar7);
    if (node == NULL) {
      if (IRByteOrder == 1) {
        uVar5 = dest & 0xffffff;
      }
      else {
        uVar5 = htonl(dest & 0xffffff);
      }
      pLVar3 = L2CfgMFindNodeLocal(&L2CfgLocal,uVar5);
      if (pLVar3 == NULL) {
        node = L2CfgLocal.net.msnode;
        if (L2CfgLocal.net.msnode == NULL) {
          return -0x260;
        }
      }
      else {
        node = NULL;
      }
    }
    if ((node != NULL) && ((L2Cfg *)node != &L2CfgLocal)) {
      pkt->_use_count = 0;
      *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
      iVar2 = IRouterPacketToRouter(node->client,&l2_id,pkt);
      return iVar2;
    }
  }
  if ((src & 0x80000000) == 0) {
    uVar4 = src & 0x1f;
  }
  else {
    uVar4 = src >> 0x18 & 0x3f;
  }
  if (((((uVar4 == 5) && (L2CfgLocal.net.msmode == 1)) && ((dest >> 0xc & 0xffff) == 0xffff)) &&
      ((type == 1 && (L2CfgLocal.net.msip != 0)))) &&
     (node = L2CfgMFindNode(&L2CfgLocal,L2CfgLocal.net.msip,0,NULL),
     node != NULL)) {
    pkt->_use_count = 0;
    *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
    iVar2 = IRouterPacketToRouter(node->client,&l2_id,pkt);
    return iVar2;
  }
  if ((type != 0xe) && ((dest >> 0xc & 0xffff) != 0xffff)) {
    iVar2 = L2CfgMFindBrickIP(&L2CfgLocal,dest >> 0x12 & 0x3ff,dest >> 0xc & 0x3f,&ip,&port,&l1);
    if (iVar2 == -1) {
      if (L2CfgLocal.net.msmode != 1) {
        return -0x260;
      }
      ip = L2CfgLocal.net.msip;
    }
    if (ip != L2CfgLocal.net.ip_addr) {
      node = L2CfgMFindNode(&L2CfgLocal,ip,0,NULL);
      if (node != NULL) {
        pkt->_use_count = 0;
        *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
        iVar2 = IRouterPacketToRouter(node->client,&l2_id,pkt);
        return iVar2;
      }
      fprintf(stderr,"NR remote!\n");
      return -0x260;
    }
    if (type == 1) {
      fprintf(stderr,"NR R.S+IR_L2!\n");
      return -0x260;
    }
    fd = l2_l1_ports[port].fd;
    pkt->_use_count = 0;
    *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
    l1_write_packet(fd,pkt);
    return 0;
  }
  if (true) {
    switch(type) {
    case 0:
    case 3:
    case 4:
    case 5:
      if (1 < L2CfgLocal.port_count) {
        return -0x260;
      }
      for (port = 0; (fd == -1 && (port < 0x28)); port = port + 1) {
        fd = l2_l1_ports[port].fd;
      }
      if (fd == -1) {
        return -0x260;
      }
      pkt->_use_count = 0;
      *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
      l1_write_packet(fd,pkt);
      return 0;
    case 1:
    case 0xe:
      if (type == 0xe) {
        task = dest >> 0x18 & 0x3f;
      }
      else if ((dest & 0x80000000) == 0) {
        task = dest & 0x1f;
      }
      else {
        task = dest >> 0x18 & 0x3f;
      }
      if (true) {
        switch(task) {
        case 2:
        case 7:
          if (pkt->_clas == '\0') {
            return -0x260;
          }
          pkt->_use_count = 0;
          *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
          smp_process_response(pkt);
          return 0;
        case 3:
          if (pkt->_clas == '\0') {
            pkt->_use_count = 0;
            *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
            cmd_process_request(pkt);
          }
          else {
            pkt->_use_count = 0;
            *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
            cmd_process_response(pkt);
          }
          return 0;
        case 4:
          if (pkt->_clas == '\0') {
            pkt->_use_count = 0;
            *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
            cfg_process_request(pkt);
          }
          else {
            pkt->_use_count = 0;
            *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
            cfg_process_response(pkt);
          }
          return 0;
        case 5:
          if (pkt->_clas == '\0') {
            return -0x260;
          }
          pkt->_use_count = 0;
          *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
          lpbk_process_response(pkt);
          return 0;
        case 9:
          if (pkt->_clas == '\0') {
            return -0x260;
          }
          pkt->_use_count = 0;
          *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
          power_process_response(pkt);
          return 0;
        case 0xc:
          if (pkt->_clas == '\0') {
            return -0x260;
          }
          pkt->_use_count = 0;
          *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
          cmd_process_response_usr(pkt);
          return 0;
        case 0xd:
          if (pkt->_clas == '\0') {
            return -0x260;
          }
          pkt->_use_count = 0;
          *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
          route_process_response(pkt);
          return 0;
        }
      }
      node = L2CfgMFindNode(&L2CfgLocal,0,task & 0x1fU | 0x1ffff000,NULL);
      if (node != NULL) {
        pkt->_use_count = 0;
        *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
        iVar2 = IRouterPacketToRouter(node->client,&l2_id,pkt);
        return iVar2;
      }
      return -0x260;
    }
  }
  return -0x260;
}

int IRouterSendBroadcastPacket(IRIdent *id, IRPacket *pkt)
{
  undefined2 uVar1;
  int fd;
  int type;
  int task;
  L2Cfg *pLVar2;
  L2CfgNode *pLVar3;
  void *pvVar4;
  int part;
  uint uVar5;
  int rack;
  int slot;
  uint32_t ip_addr;
  bool bVar6;
  IRAddress ir_addr;
  RouterClient *client;
  char x_ [80];
  int l1_;
  char x [80];
  L2CfgNode *nlist;
  int l1;
  int port;
  int ip;
  int slave;
  int local;
  int nl;
  L2CfgNode *snode;
  L2CfgNode *node;
  IRAddress src;
  bool found;
  
  pkt->_use_count = 0;
  *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
  src = pkt->_src;
  if ((src & 0x80000000) == 0) {
    type = src >> 0x1c;
  }
  else if (src >> 0x1e == 2) {
    type = 0xe;
  }
  else {
    type = 0xf;
  }
  if ((src & 0x80000000) == 0) {
    task = src & 0x1f;
  }
  else {
    task = src >> 0x18 & 0x3f;
  }
  local = 0;
  bVar6 = false;
  if (((uint)type < 0x10) && (0xd < (uint)type)) {
    client = NULL;
    ir_addr = 0;
    if (IRByteOrder == 1) {
      ip_addr = src & 0xffffff;
    }
    else {
      ip_addr = htonl(src & 0xffffff);
    }
    pLVar2 = (L2Cfg *)L2CfgMFindNode(&L2CfgLocal,ip_addr,ir_addr,client);
    if ((pLVar2 != NULL) && (pLVar2 == &L2CfgLocal)) {
      local = 1;
    }
  }
  else {
    local = (byte)(pkt->_external ^ 1) & 1;
    if ((type == 0) &&
       (((pLVar3 = L2CfgMFindBrickL2(&L2CfgLocal,src >> 0x12 & 0x3ff,src >> 0xc & 0x3f),
         pLVar3 != NULL && (L2CfgLocal.net.msmode == 2)) && (pLVar3->msmode == 1)))) {
      bVar6 = true;
      snode = pLVar3;
    }
  }
  for (nl = 0; nl < 2; nl = nl + 1) {
    node = L2CfgLocal.l3_clients;
    if (nl == 0) {
      node = L2CfgLocal.l2_clients;
    }
    for (; node != NULL; node = node->next) {
      if ((node->client != NULL) && (node->events != 0)) {
        if (type == 1) {
LAB_08063bb2:
          if (task == 2) {
            if (pkt->_opcode != 0) {
              uVar5 = node->events & 8;
              goto joined_r0x08063bcc;
            }
          }
          else if (task == 4) {
            uVar5 = node->events & 4;
joined_r0x08063bcc:
            if (uVar5 == 0) goto LAB_08063c90;
          }
LAB_08063c00:
          if (node->ir_addr != src) {
            if ((irtr_debug & 0x40U) != 0) {
              IRFmtPkt("L2",pkt,x);
              fprintf(stderr,"%s\n",x);
            }
            pkt->_use_count = 0;
            *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
            IRouterPacketToRouter(node->client,&l2_id,pkt);
          }
        }
        else if ((uint)type < 2) {
          if (type == 0) {
            if (task == 4) {
              uVar5 = node->events & 2;
              goto joined_r0x08063bcc;
            }
            if (task == 5) {
              if (pkt->_opcode != 1) {
                uVar5 = node->events & 1;
                goto joined_r0x08063b0e;
              }
              if ((pkt->_argv[0]._clas & 7) == 0) {
                pvVar4 = (void *)pkt->_argv[0]._val;
              }
              else {
                pvVar4 = (void *)IRArg(pkt,0);
              }
              RouterPurge(node->client,NULL,pvVar4);
            }
          }
        }
        else if (type == 7) {
          uVar5 = node->events & 0x10;
joined_r0x08063b0e:
          if (uVar5 != 0) goto LAB_08063c00;
        }
        else if (type == 0xe) goto LAB_08063bb2;
      }
LAB_08063c90:
    }
  }
  if ((local != 0) || (bVar6)) {
    for (node = L2CfgLocal.net.next; node != NULL; node = node->next) {
      if (((((bVar6) && (node->msmode == 1)) && (node == snode)) ||
          (((node->msmode == 1 && (type == 0)) && (task == 5)))) ||
         ((node->client == NULL || (node->events == 0)))) goto LAB_08063ee6;
      if (type == 1) {
LAB_08063e62:
        if ((task == 2) && (pkt->_opcode != 0)) {
          uVar5 = node->events & 8;
joined_r0x08063e85:
          if (uVar5 == 0) goto LAB_08063ee6;
        }
code_r0x08063e97:
        if (node->ir_addr != src) {
          pkt->_use_count = 0;
          *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
          IRouterPacketToRouter(node->client,&l2_id,pkt);
        }
      }
      else {
        if (1 < (uint)type) {
          if (type == 7) {
            uVar5 = node->events & 0x10;
            goto joined_r0x08063e85;
          }
          if (type == 0xe) goto LAB_08063e62;
          goto code_r0x08063e97;
        }
        if (type != 0) goto code_r0x08063e97;
        if (task == 5) {
          if (pkt->_opcode == 1) {
            if ((pkt->_argv[0]._clas & 7) == 0) {
              pvVar4 = (void *)pkt->_argv[0]._val;
            }
            else {
              pvVar4 = (void *)IRArg(pkt,0);
            }
            RouterPurge(node->client,NULL,pvVar4);
          }
          else if ((node->events & 1) != 0) {
            if ((pkt->_argv[0]._clas & 7) == 0) {
              part = pkt->_argv[0]._val;
            }
            else {
              part = IRArg(pkt,0);
            }
            if ((part == 0) || (node->pselect[part] != '\0')) goto code_r0x08063e97;
          }
        }
        else if ((task != 0xe) || (pkt->_opcode == 0x66)) goto code_r0x08063e97;
      }
LAB_08063ee6:
    }
  }
  if (type != 1) {
    if ((uint)type < 2) {
      if (type == 0) {
        if (task == 4) {
          smp_process_event(pkt);
        }
        else if ((uint)task < 5) {
          if (task == 1) {
            smp_process_event(pkt);
          }
        }
        else if (task == 5) {
          smp_process_event(pkt);
        }
        else if (task == 0xe) {
          cfg_process_event(pkt);
        }
      }
      goto LAB_08063fc2;
    }
    if (type != 0xe) goto LAB_08063fc2;
  }
  if (task == 2) {
    if (local == 0) {
      smp_process_event(pkt);
    }
  }
  else if ((task == 4) && (local == 0)) {
    cfg_process_event(pkt);
  }
LAB_08063fc2:
  bVar6 = false;
  if (type == 0) {
    if (task == 4) {
      bVar6 = true;
    }
    else if (task == 0xe) {
      bVar6 = pkt->_opcode == 0x66;
    }
  }
  for (port = 0; (bVar6 && (port < 0x28)); port = port + 1) {
    if ((L2CfgLocal.port_list[port].state == 2) && (fd = l2_l1_ports[port].fd, fd != -1)) {
      found = false;
      for (l1_ = 0; (!found && (l1_ < L2CfgLocal.port_list[port].l1count)); l1_ = l1_ + 1) {
        if (L2CfgLocal.port_list[port].l1cfg[l1_].configured != '\0') {
          rack = (int)L2CfgLocal.port_list[port].l1cfg[l1_].rack;
          slot = (int)L2CfgLocal.port_list[port].l1cfg[l1_].slot;
          if ((irtr_debug & 0x10U) != 0) {
            fprintf(stderr,"%d.%d %d.%d\n",rack,slot,src >> 0x12 & 0x3ff,src >> 0xc & 0x3f);
          }
          if ((rack == (src >> 0x12 & 0x3ff)) && (slot == (src >> 0xc & 0x3f))) {
            found = true;
          }
        }
      }
      if (!found) {
        if ((irtr_debug & 0x10U) != 0) {
          IRFmtPkt("L2 Write",pkt,x_);
          fprintf(stderr,"%s\n",x_);
        }
        pkt->_use_count = 0;
        *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
        l1_write_packet(fd,pkt);
      }
    }
  }
  pkt->_use_count = 0;
  *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count - 1) * 2;
  return 0;
}

int IRouterSendBroadcastPacketToClients(IRIdent *id, IRPacket *pkt)
{
  undefined2 uVar1;
  int type;
  int task;
  uint uVar2;
  char x [80];
  L2CfgNode *nlist;
  int nl;
  L2CfgNode *node;
  IRAddress src;
  
  pkt->_use_count = 0;
  *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
  src = pkt->_src;
  if ((src & 0x80000000) == 0) {
    type = src >> 0x1c;
  }
  else if (src >> 0x1e == 2) {
    type = 0xe;
  }
  else {
    type = 0xf;
  }
  if ((src & 0x80000000) == 0) {
    task = src & 0x1f;
  }
  else {
    task = src >> 0x18 & 0x3f;
  }
  nl = 0;
  do {
    if (1 < nl) {
      pkt->_use_count = 0;
      *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count - 1) * 2;
      return 0;
    }
    node = L2CfgLocal.l3_clients;
    if (nl == 0) {
      node = L2CfgLocal.l2_clients;
    }
    for (; node != NULL; node = node->next) {
      if ((node->client == NULL) || (node->events == 0)) goto LAB_080644ba;
      if (type == 1) {
LAB_08064402:
        if (task == 4) {
          uVar2 = node->events & 4;
joined_r0x0806441b:
          if (uVar2 == 0) goto LAB_080644ba;
        }
        if (node->ir_addr != src) {
          if ((irtr_debug & 0x20U) != 0) {
            IRFmtPkt("L2",pkt,x);
            fprintf(stderr,"%s\n",x);
          }
          pkt->_use_count = 0;
          *(ushort *)&pkt->field_0x4 = *(ushort *)&pkt->field_0x4 | (pkt->_use_count + 1) * 2;
          IRouterPacketToRouter(node->client,&l2_id,pkt);
        }
      }
      else if ((uint)type < 2) {
        if (type == 0) {
          if (task == 4) {
            uVar2 = node->events & 2;
          }
          else {
            if (task != 5) goto LAB_080644ba;
            uVar2 = node->events & 1;
          }
          goto joined_r0x0806441b;
        }
      }
      else if (type == 0xe) goto LAB_08064402;
LAB_080644ba:
    }
    nl = nl + 1;
  } while( true );
}

int IRouterSendPacket(IRIdent *id, IRPacket *pkt)
{
  IRPacket *rpkt;
  uint8 uStack_108;
  IRIdent *pIStack_104;
  char x__ [80];
  char x_ [80];
  char x [80];
  int rval;
  byte clas;
  
  clas = pkt->_clas;
  if (irtr_debug != 0) {
    if (((irtr_debug & 1U) != 0) && (clas == 0)) {
      IRFmtPkt("L2",pkt,x);
      fprintf(stderr,"%s\n",x);
    }
    if (((irtr_debug & 2U) != 0) && (clas == 1)) {
      IRFmtPkt("L2",pkt,x_);
      fprintf(stderr,"%s\n",x_);
    }
    if (((irtr_debug & 4U) != 0) && (clas == 2)) {
      IRFmtPkt("L2",pkt,x__);
      fprintf(stderr,"%s\n",x__);
    }
  }
  if (true) {
    if (clas < 2) {
      rval = IRouterSendTargetedPacket(id,pkt);
      goto LAB_08064770;
    }
    if (clas == 2) {
      rval = IRouterSendBroadcastPacket(id,pkt);
      goto LAB_08064770;
    }
  }
  rval = -0x259;
LAB_08064770:
  if (rval != 0) {
    if (rval == -0x260) {
      IRFmtPkt("NO RECEIVER",pkt,x__);
      fprintf(stderr,"%s\n",x__);
    }
    if (pkt->_clas == '\0') {
      pIStack_104 = id;
      if (id == NULL) {
        pIStack_104 = &l2_id;
      }
      rpkt = IRouterMakePacket(pIStack_104,&pkt->_src,(uint)(pkt->_pdata_auth >> 3),
                               (uint)pkt->_opcode,1,(uint)pkt->_rev,0,NULL);
      if (rpkt == NULL) {
        IRouterFreePacket(pkt);
        return rval;
      }
      uStack_108 = (char)-rval + (char)(-rval / 100) * -100;
      rpkt->_err = uStack_108;
      rpkt->_seqnum0 = pkt->_seqnum0;
      rpkt->_seqnum1 = pkt->_seqnum1;
      IRouterSendTargetedPacket(&l2_id,rpkt);
    }
  }
  IRouterFreePacket(pkt);
  return rval;
}
