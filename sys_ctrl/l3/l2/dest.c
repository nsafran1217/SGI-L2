/*
 * sys_ctrl/l3/l2/dest.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/dest.c
 */

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
#include "dest.h"
#include "../../common/sys/Cmd.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static int pop(char *s, int slen);
static int exp(char *dptr, int dlen, char *sptr);

DEST *dest_init(void)
{
  DEST *d;
  
  d = malloc(0x1188);
  dest_reset(d);
  return d;
}

void dest_free(DEST *d)
{
  free(d);
  return;
}

void dest_reset(DEST *d)
{
  memset(d,0,0x1188);
  memset(d->rlist,1,0x100);
  memset(d->slist,1,0x40);
  return;
}

void dest_default(DEST *d, CmdData *cptr)
{
  memcpy(d,cptr->plist,0x40);
  memcpy(d->rlist,cptr->rlist,0x100);
  memcpy(d->slist,cptr->slist,0x40);
  return;
}

int dest_l1(DEST *d, CmdData *cptr)
{
  char cVar1;
  int iVar2;
  int rack;
  int slot;
  L2CfgPort *l2port;
  IRAddress addr;
  bool found;
  int index;
  int part;
  char *plist;
  char *slist;
  char *rlist;
  int l1;
  int port;
  L2CfgNode *l2node;
  uint8 type;
  
  if ((cptr == NULL) ||
     (((iVar2 = pop(cptr->plist,0x40), iVar2 == 0 && (iVar2 = pop(cptr->rlist,0x100), iVar2 == 0))
      && (iVar2 = pop(cptr->slist,0x40), iVar2 == 0)))) {
    plist = d->plist;
    rlist = d->rlist;
    slist = d->slist;
  }
  else {
    plist = cptr->plist;
    rlist = cptr->rlist;
    slist = cptr->slist;
  }
  d->count = 0;
  iVar2 = pop(plist,0x40);
  if (iVar2 == 0) {
    iVar2 = 1;
  }
  else {
    iVar2 = 2;
  }
  d->type = iVar2;
  l2node = &L2CfgLocal.net;
  do {
    if (l2node == NULL) {
      return d->count;
    }
    for (port = 0; port < 0x28; port = port + 1) {
      l2port = (L2CfgPort *)(l2node[1].pselect + port * 0x1c + 0x18);
      if (l2port->state == 2) {
        l1 = l2port->l1count;
LAB_08060f80:
        l1 = l1 + -1;
        if (-1 < l1) {
          if (l2port->l1cfg[l1].configured != '\0') {
            rack = (int)l2port->l1cfg[l1].rack;
            slot = (int)l2port->l1cfg[l1].slot;
            type = l2port->l1cfg[l1].type;
            if (((rack != 0) && (slot != 0)) && (((uint)rack < 0x100 && ((uint)slot < 0x40)))) {
              if (d->type == 2) {
                if (*plist != '\x05') {
                  if (((type != 'R') && (type != 'D')) && (type != '-')) {
                    cVar1 = plist[l2port->l1cfg[l1].partition];
                    goto joined_r0x080610aa;
                  }
                  goto LAB_08060f80;
                }
              }
              else {
                if (rlist[rack] == '\0') goto LAB_08060f80;
                cVar1 = slist[slot];
joined_r0x080610aa:
                if (cVar1 == '\0') goto LAB_08060f80;
              }
              addr = (rack << 6 | slot & 0x3fU) << 0xc;
              found = false;
              for (index = 0; (!found && (index < d->count)); index = index + 1) {
                found = d->list[index] == addr;
              }
              if (!found) {
                if ((((l2port->l1cfg[l1].type == 'C') || (l2port->l1cfg[l1].type == '3')) ||
                    (l2port->l1cfg[l1].type == '5')) ||
                   (((((l2port->l1cfg[l1].type == '4' || (l2port->l1cfg[l1].type == 'A')) ||
                      ((l2port->l1cfg[l1].type == '6' ||
                       ((l2port->l1cfg[l1].type == '9' || (l2port->l1cfg[l1].type == '7')))))) ||
                     ((l2port->l1cfg[l1].type == '8' ||
                      ((((l2port->l1cfg[l1].type == '0' || (l2port->l1cfg[l1].type == 'Q')) ||
                        (l2port->l1cfg[l1].type == '@')) ||
                       ((l2port->l1cfg[l1].type == 'O' || (l2port->l1cfg[l1].type == 'B')))))))) ||
                    ((((l2port->l1cfg[l1].type == 'F' ||
                       ((l2port->l1cfg[l1].type == 'L' || (l2port->l1cfg[l1].type == 'M')))) ||
                      (l2port->l1cfg[l1].type == '$')) ||
                     ((((l2port->l1cfg[l1].type == ',' || (l2port->l1cfg[l1].type == '}')) ||
                       (l2port->l1cfg[l1].type == '.')) || (l2port->l1cfg[l1].type == '{')))))))) {
                  d->list[d->count] = addr;
                  d->count = d->count + 1;
                }
                else {
                  memmove(d->list + 1,d->list,d->count * 4);
                  d->list[0] = addr;
                  d->count = d->count + 1;
                }
              }
            }
          }
          goto LAB_08060f80;
        }
      }
    }
    l2node = l2node->next;
  } while( true );
}

int dest_l2(DEST *d, CmdData *cptr)
{
  int iVar1;
  IRAddress addr;
  int slot;
  int rack;
  char *slist;
  char *rlist;
  char all_slist [64];
  char all_rlist [256];
  L2CfgNode *l2node;
  
  if ((cptr == NULL) || (iVar1 = pop(cptr->rlist,0x100), iVar1 == 0)) {
    iVar1 = pop(d->rlist,0x100);
    if (iVar1 == 0) {
      memset(all_rlist,1,0x100);
      rlist = all_rlist;
      memset(all_slist,1,0x40);
    }
    else {
      rlist = d->rlist;
    }
  }
  else {
    rlist = cptr->rlist;
  }
  d->count = 0;
  d->type = 1;
  for (l2node = &L2CfgLocal.net; l2node != NULL; l2node = l2node->next) {
    if (((int)l2node[1].ip_addr < 0x100) && (rlist[l2node[1].ip_addr] != '\0')) {
      if (IRByteOrder == 1) {
        addr = l2node->ip_addr;
      }
      else {
        addr = ntohl(l2node->ip_addr);
      }
      d->list[d->count] = addr & 0xffffff | 0x83000000;
      d->count = d->count + 1;
    }
  }
  return d->count;
}

static int pop(char *s, int slen)
{
  char *pcVar1;
  char cVar2;
  int c;
  
  c = 0;
  while (slen = slen + -1, slen != -1) {
    pcVar1 = s + 1;
    cVar2 = *s;
    s = pcVar1;
    if (cVar2 != '\0') {
      c = c + 1;
    }
  }
  return c;
}

static int exp(char *dptr, int dlen, char *sptr)
{
  size_t sVar1;
  char *__format;
  int iVar2;
  int n;
  bool all;
  
  all = true;
  for (n = 0; (all && (n < dlen)); n = n + 1) {
    if (dptr[n] == '\0') {
      all = false;
    }
  }
  if (all) {
    strcat(sptr,"all");
  }
  else {
    for (n = 0; n < dlen; n = n + 1) {
      if (dptr[n] != '\0') {
        sVar1 = strlen(sptr);
        if (sVar1 != 0) {
          strcat(sptr,",");
        }
        __format = "%d";
        iVar2 = n;
        sVar1 = strlen(sptr);
        sprintf(sptr + sVar1,__format,iVar2);
      }
    }
  }
  return 0;
}

int dest_pcheck(DEST *d, CmdData *cptr, char *rptr)
{
  int iVar1;
  L2CfgL1 *cfg;
  int partition;
  int brick_slot;
  int brick_rack;
  int brick_addr;
  int addr;
  bool all_current;
  
  partition = -1;
  all_current = false;
  iVar1 = pop(cptr->rlist,0x100);
  if (((iVar1 != 0) || (iVar1 = pop(cptr->slist,0x40), iVar1 != 0)) ||
     (iVar1 = pop(cptr->plist,0x40), iVar1 != 0)) {
    if (((cptr->rlist[0] != '\x05') && (cptr->rlist[0] != '\x06')) ||
       ((cptr->slist[0] != '\x05' && (cptr->slist[0] != '\x06')))) {
      return 0;
    }
    all_current = true;
  }
  if (!all_current) {
    cptr = NULL;
  }
  dest_l1(d,cptr);
  addr = 0;
  do {
    if (d->count <= addr) {
      return 0;
    }
    cfg = L2CfgMFindBrickCfg(&L2CfgLocal,(int)d->list[addr] >> 0x12 & 0x3ff,
                             (int)d->list[addr] >> 0xc & 0x3f,0);
    if (cfg != NULL) {
      if (partition == -1) {
        partition = (int)cfg->partition;
      }
      else if ((uint)cfg->partition != partition) {
        if (rptr != NULL) {
          if (all_current) {
            strcpy(rptr,"current destination spans partitions, explicit target required.\n");
          }
          else {
            strcpy(rptr,"default destination spans partitions, explicit target required.\n");
          }
        }
        return -1;
      }
    }
    addr = addr + 1;
  } while( true );
}

void dest_print(DEST *d, char *sptr)
{
  char *__dest;
  int iVar1;
  size_t sVar2;
  
  iVar1 = pop(d->plist,0x40);
  if (iVar1 == 0) {
    strcpy(sptr,"rack ");
    sVar2 = strlen(sptr);
    exp(d->rlist,0x100,sptr + sVar2);
    sVar2 = strlen(sptr);
    __dest = sptr + sVar2;
    strcat(__dest," slot ");
    sVar2 = strlen(__dest);
    exp(d->slist,0x40,__dest + sVar2);
  }
  else {
    strcpy(sptr,"partition ");
    sVar2 = strlen(sptr);
    exp(d->plist,0x40,sptr + sVar2);
  }
  return;
}
