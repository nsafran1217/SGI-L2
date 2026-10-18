/*
 * sys_ctrl/l3/l2/power.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/power.c
 *
 * Auto power up: when NVRAM says so and every known brick is off, count
 * down (AUTOPOWER_DELAY seconds, at least 30, in 5-second steps), then have
 * this L2 run "* power up". If another L2 of the same system has a lower IP
 * address, it is left to that one. Also power_status() for the consoles.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "power.h"
#include "irtr.h"
#include "../main/nvram.h"

#define STEP            5       /* seconds per countdown step */
#define MIN_DELAY       30      /* ... and at least this many in all */
/* this L2's command task: rack and slot all ones */
#define LOCAL_L2_CMD    IR_ADDR_MAKE(IR_ADDR_L2,0x3ff,0x3f,0,IR_L2_CMD)

int power_check;                /* -nopwrchk: power_status() always says on */
int power_abort;                /* "autopower abort": stop at the next step */
static int powerup;             /* steps left */
static char buff[128];

/* to stderr and the NVRAM log */
static void info(const char *msg)
{
  fputs(msg,stderr);
  nvramLogInsert((char *)msg);
}

void power_init(void)
{
  if (nvramGet(NVRAM_AUTO_POWERUP) == 0 || power_query() != 0)
    return;
  info("\nINFO: auto power up appears enabled\n");
  powerup = nvramGet(NVRAM_AUTOPOWER_DELAY);
  if (powerup <= MIN_DELAY)
    powerup = MIN_DELAY;
  powerup /= STEP;
  EventAddTimeOut(STEP,0,power_timer,NULL,"power_init");
  sprintf(buff,"INFO: auto power up in %2d seconds...\n",powerup * STEP);
  info(buff);
}

/* one countdown step */
void power_timer(void)
{
  uint32 ip_addr = L2CfgLocal.net.ip_addr;
  L2CfgNode *node;

  if (power_abort) {
    power_abort = 0;
    info("INFO: auto power up aborted!\n");
    return;
  }
  if (nvramGet(NVRAM_AUTO_POWERUP) == 0) {
    info("INFO: auto power up disabled!\n");
    return;
  }
  if (power_query() != 0) {
    info("INFO: power appears on, auto power up disabled.\n");
    return;
  }
  if (--powerup < 1) {
    power_process_request();
    return;
  }
  for (node = L2CfgLocal.net.next; node != NULL; node = node->next) {
    /* (compares the addresses as host numbers in network byte order: on a
     * little-endian host by the last byte first) */
    if (strcmp(L2CfgLocal.ssn,L2CFG_OF(node)->ssn) != 0 || node->ip_addr >= ip_addr)
      continue;
    if (L2CFG_OF(node)->rack == 0)
      sprintf(buff,"INFO: auto power up control transfered to %s (rack number not set).\n",
              SocketAddrStr(node->ip_addr));
    else
      sprintf(buff,"INFO: auto power up control transfered to rack %d (%s).\n",
              L2CFG_OF(node)->rack,SocketAddrStr(node->ip_addr));
    info(buff);
    return;
  }
  sprintf(buff,"INFO: auto power up in %2d seconds...\n",powerup * STEP);
  info(buff);
  EventAddTimeOut(STEP,0,power_timer,NULL,"power_timer");
}

/* 1 if any configured brick of any known L2 is powered */
int power_query(void)
{
  L2CfgNode *node;
  L2CfgPort *port;
  int l1;
  int i;

  for (node = &L2CfgLocal.net; node != NULL; node = node->next) {
    for (i = 0; i < L2CFG_PORTS; i++) {
      port = &L2CFG_OF(node)->port_list[i];
      if (port->state == L2CFG_PORT_FREE)
        continue;
      for (l1 = 0; l1 < port->l1count; l1++)
        if (port->l1cfg[l1].configured && port->l1cfg[l1].power_state)
          return 1;
    }
  }
  return 0;
}

/* this L2 runs "* power up" */
void power_process_request(void)
{
  IRArgument argv[2];
  IRAddress a = LOCAL_L2_CMD;
  char *cmd = strdup("* power up");
  IRPacket *p;

  info("INFO: initiating auto power up.\n");
  argv[0]._clas = IR_ARG_VALUE;
  argv[0]._frame = 0;
  argv[0]._val = 0;
  argv[0]._size = 0;
  argv[1]._clas = IR_ARG_STRING | IR_ARG_FREE;
  argv[1]._frame = 0;
  argv[1]._val = IR_PTR_VAL(cmd);
  argv[1]._size = strlen(cmd) + 1;
  p = IRouterMakePacket(&l2_apwr_id,&a,0,0,IR_REQ,2,2,argv);
  IRouterSendPacket(NULL,p);
}

/* its response: a status, and the command's output */
void power_process_response(IRPacket *p)
{
  char *text;

  if (p->_err != 0) {
    sprintf(buff,"ERROR: auto power up error, %s\n",IRFmtError(p->_err));
    info(buff);
    IRouterFreePacket(p);
    return;
  }
  if (IRArg(p,0) != 0)
    info("ERROR: auto power up error.\n");
  if (p->_argc > 1 && IR_ARG_TYPE(p->_argv[1]) == IR_ARG_STRING) {
    text = (char *)IRArg(p,1);
    info(text);                 /* (the original used it as a printf format) */
  }
  IRouterFreePacket(p);
}

/* a brick's power state as its L1 last reported it (always on with -nopwrchk) */
int power_status(int rack, int slot)
{
  L2CfgL1 *cfg;

  if (power_check)
    return 1;
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
  return cfg == NULL ? 0 : cfg->power_state;
}
