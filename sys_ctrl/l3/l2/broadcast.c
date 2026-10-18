/*
 * sys_ctrl/l3/l2/broadcast.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/broadcast.c
 */

#include "irtr.h"   /* needed by the reconstruction */
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
#include "l2cmd.h"
#include "reqrspq.h"
#include "dest.h"
#include "../../common/sys/Cmd.h"
#include "broadcast.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int broadcast_debug;
int broadcast_response_timeout = 15;

int broadcast(REQRSPQ *q, IRIdent *id)
{
  static int active;
  static int pcount;
  int iVar1;
  int delay;
  int response;
  IRPacket *pkt;
  
  pkt = NULL;
  response = 0;
  delay = 0;
  if (active == 0) {
    pcount = 0;
    active = 1;
    do {
      while( true ) {
        do {
          iVar1 = reqq_get(q,&pkt,&response,&delay);
          if (iVar1 != 0) {
            if ((broadcast_debug & 1U) != 0) {
              fprintf(stderr,"broadcast returning (3)\n");
            }
            active = 0;
            return 0;
          }
          if (pkt != NULL) {
            if ((broadcast_debug & 1U) != 0) {
              fprintf(stderr,"%d.%d ",pkt->_dest >> 0x12 & 0x3ff,pkt->_dest >> 0xc & 0x3f);
            }
            if (response != 0) {
              rspq_put(q,(uint)CONCAT11(pkt->_seqnum1,pkt->_seqnum0),pkt->_dest);
              rspq_timeout_set(q,broadcast_response_timeout);
            }
            pcount = pcount + 1;
            IRouterSendPacket(id,pkt);
          }
        } while (delay == 0);
        if (delay == -1) break;
        if ((broadcast_debug & 1U) != 0) {
          fprintf(stderr,"sleep %d ",delay);
        }
        usleep(delay * 1000);
        pcount = 0;
      }
    } while (q->rspq_pending == 0);
    if ((broadcast_debug & 1U) != 0) {
      fprintf(stderr,"broadcast returning (2)\n");
    }
    active = 0;
  }
  else {
    if ((broadcast_debug & 1U) != 0) {
      fprintf(stderr,"broadcast returning (1)\n");
    }
    pcount = pcount + -1;
  }
  return -1;
}

int broadcast_l2(L2CMD *c, char **results, char *cmd, int response, int delay, int final)
{
  L2Cfg *pLVar1;
  int iVar2;
  size_t sVar3;
  uint32_t ip_addr;
  IRAddress ir_addr;
  RouterClient *client;
  char *cptr;
  IRAddress l2_addr;
  int addr;
  IRPacket *p;
  IRArgument argv [2];
  
  if ((final != 0) && (c->dest->count == 1)) {
    client = NULL;
    ir_addr = 0;
    if (IRByteOrder == 1) {
      ip_addr = c->dest->list[0] & 0xffffff;
    }
    else {
      ip_addr = htonl(c->dest->list[0] & 0xffffff);
    }
    pLVar1 = (L2Cfg *)L2CfgMFindNode(&L2CfgLocal,ip_addr,ir_addr,client);
    if (pLVar1 == &L2CfgLocal) {
      iVar2 = l2cmd_process(NULL,cmd,results,NULL);
      return iVar2;
    }
  }
  iVar2 = c->dest->count;
  while (addr = iVar2 + -1, -1 < addr) {
    l2_addr = c->dest->list[iVar2 + -1];
    argv[1]._val = IR_PTR_VAL(strdup(cmd));
    l2_addr = (l2_addr & 0xc0ffffff) | 0x3000000;
    argv[0]._clas = '\0';
    argv[0]._frame = '\0';
    argv[0]._val = 0;
    argv[0]._size = 0;
    argv[1]._clas = '\n';
    argv[1]._frame = '\0';
    sVar3 = strlen((char *)IR_VAL_PTR(argv[1]._val));
    argv[1]._size = (short)sVar3 + 1;
    p = IRouterMakePacket(c->id,&l2_addr,0,0,0,2,2,argv);
    reqq_put(c->q,p,response,0);
    iVar2 = addr;
  }
  if (response != 0) {
    reqq_put(c->q,NULL,0,-1);
    if (final == 0) {
      reqq_put(c->q,NULL,0,delay);
    }
    c->busy = c->busy | 1;
  }
  if (final != 0) {
    rspq_timeout_set(c->q,broadcast_response_timeout);
    broadcast(c->q,c->id);
  }
  return 0;
}

int broadcast_l1(L2CMD *c, int method, char *cmd, int response, int delay, int type, int *slots, int final)
{
  int iVar1;
  L2CfgL1 *l1;
  size_t sVar2;
  char *pcVar3;
  L2CfgL1 *pLVar4;
  int brick_rack;
  int brick_slot;
  uint rack;
  uint slot_00;
  L2CfgL1 *l1_;
  int flags;
  char *cptr;
  int last_type;
  int first_type;
  int brick_type;
  IRAddress brick_addr;
  int slot;
  int addr;
  int pcount;
  IRPacket *p;
  IRArgument argv [2];
  
  iVar1 = type;
  pcount = 0;
  type = type & 0xffff;
  if (type == 0xff) {
    first_type = 1;
    last_type = 0x80;
  }
  else {
    first_type = type;
    last_type = type;
  }
  if (slots == NULL) {
    for (type = first_type; type <= last_type; type = type << 1) {
      for (addr = 0; addr < c->dest->count; addr = addr + 1) {
        brick_addr = c->dest->list[addr];
        rack = brick_addr >> 0x12 & 0x3ff;
        slot_00 = brick_addr >> 0xc & 0x3f;
        pLVar4 = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot_00,0);
        if (pLVar4 != NULL) {
          if (false) {
switchD_0805f8b9_caseD_25:
            brick_type = 0x80;
          }
          else {
            switch(pLVar4->type) {
            case '#':
            case '&':
            case '=':
            case 'E':
            case 'G':
            case 'I':
            case 'N':
            case 'P':
            case 'V':
            case 'X':
            case 'Y':
              brick_type = 2;
              break;
            case '$':
            case ',':
            case '.':
            case '0':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
            case '@':
            case 'A':
            case 'B':
            case 'C':
            case 'F':
            case 'L':
            case 'M':
            case 'O':
            case 'Q':
            case '{':
            case '}':
              brick_type = 4;
              break;
            default:
              goto switchD_0805f8b9_caseD_25;
            case '-':
            case 'D':
            case 'R':
              brick_type = 1;
            }
          }
          if ((((brick_type & type) != 0) &&
              (((iVar1 & 0x10000U) == 0 || (pLVar4->power_state == '\0')))) &&
             (((iVar1 & 0x20000U) == 0 || (pLVar4->power_state != '\0')))) {
            argv[1]._val = IR_PTR_VAL(strdup(cmd));
            if ((brick_addr & 0x80000000) == 0) {
              brick_addr = (brick_addr & 0xffffffe0) | 3;
            }
            else {
              brick_addr = (brick_addr & 0xc0ffffff) | 0x3000000;
            }
            argv[0]._clas = '\0';
            argv[0]._frame = '\0';
            argv[0]._val = 0;
            argv[0]._size = 0;
            argv[1]._clas = '\n';
            argv[1]._frame = '\0';
            sVar2 = strlen((char *)IR_VAL_PTR(argv[1]._val));
            argv[1]._size = (short)sVar2 + 1;
            p = IRouterMakePacket(c->id,&brick_addr,0,0,0,2,2,argv);
            if (((broadcast_debug & 2U) != 0) && (pcount == 0)) {
              if (method == 2) {
                pcVar3 = "serial";
              }
              else {
                pcVar3 = "parallel";
              }
              fprintf(stderr,"sending \'%s\' %s, %d\n",cmd,pcVar3,type);
            }
            pcount = pcount + 1;
            if ((broadcast_debug & 4U) != 0) {
              fprintf(stderr,"%d.%d ",rack,slot_00);
            }
            reqq_put(c->q,p,response,0);
            if ((response != 0) && (c->busy = c->busy | 1, method == 2)) {
              reqq_put(c->q,NULL,0,-1);
              reqq_put(c->q,NULL,0,delay);
              if ((broadcast_debug & 2U) != 0) {
                fprintf(stderr,"serial %d\n",delay);
              }
            }
          }
        }
      }
    }
  }
  else {
    for (type = first_type; type <= last_type; type = type << 1) {
      for (slot = 0; slots[slot] != -1; slot = slot + 1) {
        for (addr = 0; addr < c->dest->count; addr = addr + 1) {
          brick_addr = c->dest->list[addr];
          brick_rack = brick_addr >> 0x12 & 0x3ff;
          brick_slot = brick_addr >> 0xc & 0x3f;
          if ((brick_slot == slots[slot]) &&
             (l1 = L2CfgMFindBrickCfg(&L2CfgLocal,brick_rack,brick_slot,0), l1 != NULL)) {
            if (false) {
switchD_0805f5b6_caseD_25:
              brick_type = 0x80;
            }
            else {
              switch(l1->type) {
              case '#':
              case '&':
              case '=':
              case 'E':
              case 'G':
              case 'I':
              case 'N':
              case 'P':
              case 'V':
              case 'X':
              case 'Y':
                brick_type = 2;
                break;
              case '$':
              case ',':
              case '.':
              case '0':
              case '3':
              case '4':
              case '5':
              case '6':
              case '7':
              case '8':
              case '9':
              case '@':
              case 'A':
              case 'B':
              case 'C':
              case 'F':
              case 'L':
              case 'M':
              case 'O':
              case 'Q':
              case '{':
              case '}':
                brick_type = 4;
                break;
              default:
                goto switchD_0805f5b6_caseD_25;
              case '-':
              case 'D':
              case 'R':
                brick_type = 1;
              }
            }
            if ((((brick_type & type) != 0) &&
                (((iVar1 & 0x10000U) == 0 || (l1->power_state == '\0')))) &&
               (((iVar1 & 0x20000U) == 0 || (l1->power_state != '\0')))) {
              argv[1]._val = IR_PTR_VAL(strdup(cmd));
              if ((brick_addr & 0x80000000) == 0) {
                brick_addr = (brick_addr & 0xffffffe0) | 3;
              }
              else {
                brick_addr = (brick_addr & 0xc0ffffff) | 0x3000000;
              }
              argv[0]._clas = '\0';
              argv[0]._frame = '\0';
              argv[0]._val = 0;
              argv[0]._size = 0;
              argv[1]._clas = '\n';
              argv[1]._frame = '\0';
              sVar2 = strlen((char *)IR_VAL_PTR(argv[1]._val));
              argv[1]._size = (short)sVar2 + 1;
              p = IRouterMakePacket(c->id,&brick_addr,0,0,0,2,2,argv);
              if (((broadcast_debug & 2U) != 0) && (pcount == 0)) {
                if (method == 2) {
                  pcVar3 = "serial";
                }
                else {
                  pcVar3 = "parallel";
                }
                fprintf(stderr,"sending \'%s\' %s, %d\n",cmd,pcVar3,type);
              }
              pcount = pcount + 1;
              if ((broadcast_debug & 4U) != 0) {
                fprintf(stderr,"%d.%d ",brick_rack,brick_slot);
              }
              reqq_put(c->q,p,response,0);
              if ((response != 0) && (c->busy = c->busy | 1, method == 2)) {
                reqq_put(c->q,NULL,0,-1);
                reqq_put(c->q,NULL,0,delay);
                if ((broadcast_debug & 2U) != 0) {
                  fprintf(stderr,"serial %d\n",delay);
                }
              }
            }
          }
        }
      }
    }
  }
  if (((pcount != 0) && (response != 0)) && (method == 1)) {
    reqq_put(c->q,NULL,0,-1);
    if (final == 0) {
      reqq_put(c->q,NULL,0,delay);
    }
    if ((broadcast_debug & 2U) != 0) {
      fprintf(stderr,"parallel %d\n",delay);
    }
  }
  if (final != 0) {
    if ((broadcast_debug & 1U) != 0) {
      fprintf(stderr,"starting broadcast\n");
    }
    rspq_timeout_set(c->q,broadcast_response_timeout);
    broadcast(c->q,c->id);
  }
  return 0;
}
