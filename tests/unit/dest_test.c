/*
 * Equivalence test of the destination selection (l3/l2/dest.c) against the
 * main branch's reconstruction (Origdest_*), on random configurations of
 * L2s, ports and bricks and random rack/slot/partition selections.
 * dest_test.sh builds it under ASan; L2CfgMFindBrickCfg() is a stub over
 * the same configuration.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "dest.h"

DEST *Origdest_init(void);
void Origdest_default(DEST *d, CmdData *cptr);
int Origdest_l1(DEST *d, CmdData *cptr);
int Origdest_l2(DEST *d, CmdData *cptr);
int Origdest_pcheck(DEST *d, CmdData *cptr, char *rptr);
void Origdest_print(DEST *d, char *sptr);

L2Cfg L2CfgLocal;
int IRByteOrder;                /* (the original's dest_l2() tests it) */
static unsigned int seed = 1;

static unsigned int rnd(unsigned int n)
{
  seed = seed * 1103515245 + 12345;
  return (seed >> 8) % n;
}

L2CfgL1 *L2CfgMFindBrickCfg(L2Cfg *head, int rack, int slot, int local)
{
  L2CfgNode *node;
  int p, l;

  for (node = &head->net; node != NULL; node = node->next)
    for (p = 0; p < L2CFG_PORTS; p++) {
      L2CfgPort *port = &L2CFG_OF(node)->port_list[p];
      for (l = 0; port->state != 0 && l < port->l1count; l++)
        if (port->l1cfg[l].rack == rack && port->l1cfg[l].slot == slot)
          return &port->l1cfg[l];
    }
  return NULL;
}

static const char brick_types[] = "CRD-IPX345A69780Q@OBFLM$,}.{N";

static void make_config(void)
{
  L2CfgNode *node, *next;
  int nodes = 1 + rnd(4);
  int n, p, l;

  for (node = L2CfgLocal.net.next; node != NULL; node = next) {   /* free the last one */
    next = node->next;
    for (p = 0; p < L2CFG_PORTS; p++)
      free(L2CFG_OF(node)->port_list[p].l1cfg);
    free(node);
  }
  for (p = 0; p < L2CFG_PORTS; p++)
    free(L2CfgLocal.port_list[p].l1cfg);
  memset(&L2CfgLocal,0,sizeof(L2CfgLocal));
  for (n = 0; n < nodes; n++) {
    L2Cfg *cfg = n == 0 ? &L2CfgLocal : calloc(1,sizeof(L2Cfg));
    if (n > 0) {
      cfg->net.next = L2CfgLocal.net.next;
      L2CfgLocal.net.next = &cfg->net;
    }
    cfg->net.ip_addr = seed;
    cfg->rack = rnd(5) == 0 ? rnd(300) : rnd(8);
    for (p = 0; p < L2CFG_PORTS; p++) {
      L2CfgPort *port = &cfg->port_list[p];
      if (rnd(4) != 0)
        continue;
      port->state = rnd(3);
      port->l1count = rnd(5);
      port->l1cfg = calloc(port->l1count + 1,sizeof(L2CfgL1));
      for (l = 0; l < port->l1count; l++) {
        L2CfgL1 *b = &port->l1cfg[l];
        b->configured = rnd(6) != 0;
        b->rack = rnd(6) == 0 ? rnd(256) : rnd(5);
        b->slot = rnd(6) == 0 ? rnd(80) : rnd(10);
        b->type = brick_types[rnd(sizeof(brick_types) - 1)];
        b->partition = rnd(4) == 0 ? rnd(64) : rnd(3);
      }
    }
  }
}

static void make_list(char *list, int len)
{
  int i;

  switch (rnd(6)) {
  case 0:
    memset(list,0,len);
    break;
  case 1:
    memset(list,CMD_RANGE_ALL,len);
    break;
  case 2:
    memset(list,CMD_RANGE_ANY,len);
    break;
  default:
    memset(list,0,len);
    for (i = rnd(6); i > 0; i--)
      list[rnd(rnd(2) ? 8 : len)] = 1 + rnd(4);
  }
}

static void make_cmd(CmdData *c)
{
  memset(c,0,sizeof(*c));
  if (rnd(3) == 0)
    return;                     /* nothing given */
  if (rnd(3) == 0)
    make_list(c->plist,sizeof(c->plist));
  else {
    make_list(c->rlist,sizeof(c->rlist));
    make_list(c->slist,sizeof(c->slist));
  }
}

static int same(DEST *a, DEST *b, const char *what, int step)
{
  if (a->count == b->count && a->type == b->type &&
      memcmp(a->list,b->list,a->count * sizeof(a->list[0])) == 0)
    return 1;
  printf("FAIL  dest: step %d %s: count %d/%d type %d/%d\n",step,what,a->count,b->count,
         a->type,b->type);
  return 0;
}

int main(void)
{
  static char ptext[8192], ntext[8192];
  DEST *od = Origdest_init(), *nd = dest_init();
  CmdData *cmd = calloc(1,sizeof(CmdData));
  int steps = 0;
  int step;

  IRByteOrder = htonl(1) == 1 ? 1 : 2;
  for (step = 0; step < 20000; step++) {
    if (step % 20 == 0)
      make_config();
    make_cmd(cmd);
    switch (rnd(5)) {
    case 0:
      Origdest_l1(od,cmd);
      dest_l1(nd,cmd);
      if (!same(od,nd,"dest_l1",step))
        return 1;
      break;
    case 1:
      Origdest_l2(od,cmd);
      dest_l2(nd,cmd);
      if (!same(od,nd,"dest_l2",step))
        return 1;
      break;
    case 2: {
      int r1, r2;
      ptext[0] = ntext[0] = '\0';
      r1 = Origdest_pcheck(od,cmd,ptext);
      r2 = dest_pcheck(nd,cmd,ntext);
      if (r1 != r2 || strcmp(ptext,ntext) != 0 || !same(od,nd,"dest_pcheck",step)) {
        printf("FAIL  dest: step %d pcheck %d/%d \"%s\" \"%s\"\n",step,r1,r2,ptext,ntext);
        return 1;
      }
      break;
    }
    case 3:
      Origdest_default(od,cmd);
      dest_default(nd,cmd);
      if (memcmp(od,nd,offsetof(DEST,type)) != 0) {
        printf("FAIL  dest: step %d dest_default\n",step);
        return 1;
      }
      break;
    case 4:
      Origdest_print(od,ptext);
      dest_print(nd,ntext);
      if (strcmp(ptext,ntext) != 0) {
        printf("FAIL  dest: step %d dest_print \"%s\" \"%s\"\n",step,ptext,ntext);
        return 1;
      }
      break;
    }
    if (rnd(50) == 0) {
      dest_reset(od);           /* (the same in both: memsets) */
      dest_reset(nd);
    }
    steps++;
  }
  printf("PASS  dest: %d selections compared with the original\n",steps);
  return 0;
}
