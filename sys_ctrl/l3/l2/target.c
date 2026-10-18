/*
 * sys_ctrl/l3/l2/target.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/target.c
 *
 * Sending one command to one target: another L2 (or this one), an L1, or a
 * prepared request. The response, if wanted, is queued on the L2CMD and
 * awaited for target_response_timeout seconds once the final request of a
 * command is out.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "l2.h"
#include "target.h"
#include "l1.h"
#include "irtr.h"

/* the L1 at the far end of an L1 port: rack and slot all ones */
#define L1_LOCAL_CMD    IR_ADDR_MAKE(IR_ADDR_L1,0x3ff,0x3f,0,L2_TASK_CMD)

int target_response_timeout = 10;

/* a command request to addr, its response queued if wanted */
static IRPacket *command_packet(L2CMD *c, IRAddress *addr, char *cmd, int response)
{
  IRArgument argv[2];
  IRPacket *p;

  argv[0]._clas = IR_ARG_VALUE;
  argv[0]._frame = 0;
  argv[0]._val = 0;
  argv[0]._size = 0;
  argv[1]._clas = IR_ARG_STRING;
  argv[1]._frame = 0;
  argv[1]._val = IR_PTR_VAL(cmd);
  argv[1]._size = strlen(cmd) + 1;
  p = IRouterMakePacket(c->id,addr,0,0,IR_REQ,2,2,argv);
  if (response)
    l2cmd_queue_response(c,c->id->seqnum - 1,*addr,0);
  return p;
}

/* after a request is sent: pause delay ms; after the last, start the timeout */
static void sent(L2CMD *c, int delay, int final)
{
  if (delay)
    usleep(delay * 1000);
  if (final)
    rspq_timeout_set(c->q,target_response_timeout);
}

/* the L2 with IP address ip runs cptr: this one at once (into results),
 * another through its command task */
int target_l2(L2CMD *c, char **results, int ip, char *cptr, int response, int delay, int final)
{
  L2CfgNode *node;
  IRAddress addr;
  IRPacket *p;

  node = L2CfgMFindNode(&L2CfgLocal,ip,0,NULL);
  if (node == NULL)
    return -1;
  if ((L2Cfg *)node == &L2CfgLocal)
    return l2cmd_process(c,cptr,results,NULL);
  addr = IR_ADDR_WITH_TASK(IR_ADDR_FROM_IP(ip),L2_TASK_CMD);
  p = command_packet(c,&addr,cptr,response);
  IRouterSendPacket(NULL,p);
  sent(c,delay,final);
  return 0;
}

/* L1 number l1 on port of the L2 at ip runs cptr: directly if the L2 is
 * this one, else through that L2 (":<port>:<l1> <command>") */
int target_l1(L2CMD *c, int ip, int port, int l1, char *cptr, int response, int delay, int final)
{
  char cmd[256 + 32];
  IRAddress addr;
  IRPacket *p;
  int rack;
  int slot;

  if (L2CfgMFindBrickRS(&L2CfgLocal,ip,port,l1,&rack,&slot) != 0)
    return -1;
  if ((uint32)ip != L2CfgLocal.net.ip_addr) {
    /* (the original sprintf()ed into 256 bytes) */
    snprintf(cmd,sizeof(cmd),":%d:%d %s",port,l1,cptr);
    return target_l2(c,NULL,ip,cmd,response,delay,final);
  }
  addr = L1_LOCAL_CMD;
  p = command_packet(c,&addr,cptr,response);
  l1_write_packet(l2_l1_ports[port].fd,p);
  sent(c,delay,final);
  return 0;
}

/* a prepared request to addr */
int target_pkt(L2CMD *c, IRAddress addr, int opcode, int argc, IRArgument *argv, int response, int delay, int final)
{
  IRPacket *p;

  p = IRouterMakePacket(c->id,&addr,0,opcode,IR_REQ,2,argc,argv);
  if (response)
    l2cmd_queue_response(c,c->id->seqnum - 1,addr,0);
  IRouterSendPacket(NULL,p);
  sent(c,delay,final);
  return 0;
}
