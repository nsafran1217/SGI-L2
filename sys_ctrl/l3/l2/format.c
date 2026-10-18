/*
 * sys_ctrl/l3/l2/format.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/format.c
 *
 * IRouter addresses as text for the consoles: the brick, and for a console
 * address which CPU (or slab/slot and subchannel) of it.
 */

#include <stdio.h>
#include <string.h>
#include "l2.h"
#include "format.h"
#include "../../common/sys/brick_types.h"

/* a console address's number -> slab (a group of CPUs) within the brick;
 * the counterpart of BRICK_TASKNUM_SUBCHAN() */
static int BRICK_TASKNUM_SLAB(int btype, int tasknum)
{
  switch (btype) {
  case '6':                     /* Twister */
    return tasknum / 24;
  case '@':                     /* Vortix */
    return tasknum / 20;
  default:                      /* includes '.', which the original tested separately */
    return tasknum / 32;
  }
}

/* chassis bricks (1932, 1955, 191010) */
static int is_chassis(int type)
{
  return type == ',' || type == '}' || type == '.';
}

/* bricks whose CPUs are grouped in slabs: IP41, Vortix, Twister, IP69, and
 * the chassis (which is_chassis() catches first) */
static int has_slabs(int type)
{
  return type == '5' || type == '@' || type == '6' || type == '$' || is_chassis(type);
}

char *format_address(IRAddress addr)
{
  return L2CfgMAddrStr(&L2CfgLocal,addr,0);
}

/* addr, then ".<partition>" if one is given, then the console's CPU or
 * subchannel when the brick is known; in a static buffer */
char *format_caddress(IRAddress addr, int partition)
{
  static char buff[80];
  L2CfgL1 *cfg;
  int num = IR_ADDR_NUM(addr);  /* -1 for an IP address */
  int len;
  int slab;
  int subc;

  /* (the original strcpy()ed and sprintf()ed into the 80 bytes unbounded) */
  len = snprintf(buff,sizeof(buff),"%s",format_address(addr));
  if (partition != 0 && len < (int)sizeof(buff))
    len += snprintf(buff + len,sizeof(buff) - len,".%d",partition);
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(addr),IR_ADDR_SLOT(addr),0);
  if (cfg == NULL || len >= (int)sizeof(buff))
    return buff;
  slab = BRICK_TASKNUM_SLAB(cfg->type,num);
  subc = BRICK_TASKNUM_SUBCHAN(cfg->type,num);
  if (is_chassis(cfg->type)) {
    /* (these print the address's task where the others print the slab) */
    if (subc < 4)
      snprintf(buff + len,sizeof(buff) - len," CPU %d%c",IR_ADDR_TASK(addr),'A' + subc);
    else if (subc == 4)
      snprintf(buff + len,sizeof(buff) - len," console%d",IR_ADDR_TASK(addr));
    else
      snprintf(buff + len,sizeof(buff) - len," slot %d, subchannel %d",IR_ADDR_TASK(addr),subc);
  }
  else if (has_slabs(cfg->type)) {
    if (subc < 4)
      snprintf(buff + len,sizeof(buff) - len," CPU %d%c",slab,'A' + subc);
    else if (subc == 4)
      snprintf(buff + len,sizeof(buff) - len," console%d",slab);
    else
      snprintf(buff + len,sizeof(buff) - len," slab %d, subchannel %d",slab,subc);
  }
  else if (num >= 0 && num <= 3)
    snprintf(buff + len,sizeof(buff) - len," CPU%d",num);
  else if (num == 4)
    snprintf(buff + len,sizeof(buff) - len," console");
  else
    snprintf(buff + len,sizeof(buff) - len," subchannel %d",num);
  return buff;
}
