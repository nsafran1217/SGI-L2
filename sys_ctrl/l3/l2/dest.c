/*
 * sys_ctrl/l3/l2/dest.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/dest.c
 *
 * Destinations: which bricks (or L2s) a console command goes to. A DEST
 * keeps a default selection (the "destination" command) as Cmd range lists
 * of racks and slots, or of partitions, and the addresses it last resolved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "dest.h"

DEST *dest_init(void)
{
  DEST *d;

  d = malloc(sizeof(DEST));
  dest_reset(d);
  return d;
}

void dest_free(DEST *d)
{
  free(d);
}

/* the default: every rack and slot */
void dest_reset(DEST *d)
{
  memset(d,0,sizeof(DEST));
  memset(d->rlist,1,sizeof(d->rlist));
  memset(d->slist,1,sizeof(d->slist));
}

/* make the command's selection the default */
void dest_default(DEST *d, CmdData *cptr)
{
  memcpy(d->plist,cptr->plist,sizeof(d->plist));
  memcpy(d->rlist,cptr->rlist,sizeof(d->rlist));
  memcpy(d->slist,cptr->slist,sizeof(d->slist));
}

/* the number of entries selected */
static int pop(const char *s, int slen)
{
  int c = 0;

  while (slen-- > 0)
    if (*s++ != 0)
      c++;
  return c;
}

/* the L1s (bricks) that cptr's selection names, or the default's if it
 * names none, into d->list: compute bricks in the order found, the others
 * (routers, I/O) ahead of them, last found first. Returns how many. */
int dest_l1(DEST *d, CmdData *cptr)
{
  L2CfgNode *l2node;
  L2CfgPort *l2port;
  L2CfgL1 *l1cfg;
  const char *plist;
  const char *rlist;
  const char *slist;
  IRAddress addr;
  int port;
  int index;
  int l1;

  if (cptr == NULL || (pop(cptr->plist,sizeof(cptr->plist)) == 0 &&
                       pop(cptr->rlist,sizeof(cptr->rlist)) == 0 &&
                       pop(cptr->slist,sizeof(cptr->slist)) == 0)) {
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
  d->type = pop(plist,sizeof(d->plist)) == 0 ? 1 : 2;     /* racks/slots, or partitions */
  for (l2node = &L2CfgLocal.net; l2node != NULL; l2node = l2node->next) {
    for (port = 0; port < L2CFG_PORTS; port++) {
      l2port = &L2CFG_OF(l2node)->port_list[port];
      if (l2port->state != L2CFG_PORT_CONFIGURED)
        continue;
      for (l1 = l2port->l1count - 1; l1 >= 0; l1--) {
        l1cfg = &l2port->l1cfg[l1];
        if (!l1cfg->configured || l1cfg->rack == 0 || l1cfg->slot == 0 ||
            l1cfg->slot >= sizeof(d->slist))
          continue;
        if (d->type == 2) {
          /* "partition *" takes every brick; a partition list takes the
           * bricks in those partitions, routers being in none. (The
           * original indexed plist with partitions past its 64 entries.) */
          if (plist[0] != CMD_RANGE_ALL &&
              (l1cfg->type == 'R' || l1cfg->type == 'D' || l1cfg->type == '-' ||
               l1cfg->partition >= sizeof(d->plist) || plist[l1cfg->partition] == 0))
            continue;
        }
        else if (rlist[l1cfg->rack] == 0 || slist[l1cfg->slot] == 0)
          continue;
        addr = IR_ADDR_MAKE(IR_ADDR_L1,l1cfg->rack,l1cfg->slot,0,0);
        for (index = 0; index < d->count && d->list[index] != addr; index++)
          ;
        if (index < d->count)
          continue;
        if (d->count == (int)(sizeof(d->list) / sizeof(d->list[0])))
          return d->count;          /* (the original wrote past the list) */
        if (brickIsCompute(l1cfg->type))
          d->list[d->count] = addr;
        else {
          memmove(d->list + 1,d->list,d->count * sizeof(d->list[0]));
          d->list[0] = addr;
        }
        d->count++;
      }
    }
  }
  return d->count;
}

/* the L2s in the racks cptr's selection names, or the default's, or all,
 * into d->list as their command tasks. Returns how many. */
int dest_l2(DEST *d, CmdData *cptr)
{
  char all_rlist[256];
  L2CfgNode *l2node;
  const char *rlist;
  int rack;

  if (cptr != NULL && pop(cptr->rlist,sizeof(cptr->rlist)) != 0)
    rlist = cptr->rlist;
  else if (pop(d->rlist,sizeof(d->rlist)) != 0)
    rlist = d->rlist;
  else {
    memset(all_rlist,1,sizeof(all_rlist));
    rlist = all_rlist;
  }
  d->count = 0;
  d->type = 1;
  for (l2node = &L2CfgLocal.net; l2node != NULL; l2node = l2node->next) {
    rack = L2CFG_OF(l2node)->rack;
    /* (the original also took negative racks, indexing before rlist) */
    if (rack < 0 || rack >= (int)sizeof(d->rlist) || rlist[rack] == 0)
      continue;
    if (d->count == (int)(sizeof(d->list) / sizeof(d->list[0])))
      break;
    d->list[d->count++] = IR_ADDR_WITH_TASK(IR_ADDR_FROM_IP(l2node->ip_addr),IR_L2_CMD);
  }
  return d->count;
}

/* append a range list to sptr: "all", or the selected numbers */
static void expand_range(const char *dptr, int dlen, char *sptr)
{
  int n;

  if (pop(dptr,dlen) == dlen) {
    strcat(sptr,"all");
    return;
  }
  for (n = 0; n < dlen; n++) {
    if (dptr[n] == 0)
      continue;
    if (*sptr != '\0')
      strcat(sptr,",");
    sprintf(sptr + strlen(sptr),"%d",n);
  }
}

/*
 * Whether a command without an explicit target may go to the default
 * destination (or, given "**"-style all-current lists, to the current
 * one): 0 if its bricks are all in one partition, else -1 with a message
 * in rptr. An explicit target always passes.
 */
int dest_pcheck(DEST *d, CmdData *cptr, char *rptr)
{
  L2CfgL1 *cfg;
  int partition = -1;
  int all_current = 0;
  int i;

  if (pop(cptr->rlist,sizeof(cptr->rlist)) != 0 || pop(cptr->slist,sizeof(cptr->slist)) != 0 ||
      pop(cptr->plist,sizeof(cptr->plist)) != 0) {
    if ((cptr->rlist[0] != CMD_RANGE_ALL && cptr->rlist[0] != CMD_RANGE_ANY) ||
        (cptr->slist[0] != CMD_RANGE_ALL && cptr->slist[0] != CMD_RANGE_ANY))
      return 0;
    all_current = 1;
  }
  dest_l1(d,all_current ? cptr : NULL);
  for (i = 0; i < d->count; i++) {
    cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(d->list[i]),IR_ADDR_SLOT(d->list[i]),0);
    if (cfg == NULL)
      continue;
    if (partition == -1)
      partition = cfg->partition;
    else if (cfg->partition != partition) {
      if (rptr != NULL)
        strcpy(rptr,all_current ? "current destination spans partitions, explicit target required.\n"
                                : "default destination spans partitions, explicit target required.\n");
      return -1;
    }
  }
  return 0;
}

/* the default selection as text: "rack <list> slot <list>" or
 * "partition <list>" */
void dest_print(DEST *d, char *sptr)
{
  if (pop(d->plist,sizeof(d->plist)) != 0) {
    strcpy(sptr,"partition ");
    expand_range(d->plist,sizeof(d->plist),sptr + strlen(sptr));
    return;
  }
  strcpy(sptr,"rack ");
  expand_range(d->rlist,sizeof(d->rlist),sptr + strlen(sptr));
  sptr += strlen(sptr);
  strcat(sptr," slot ");
  expand_range(d->slist,sizeof(d->slist),sptr + strlen(sptr));
}
