/*
 * sys_ctrl/l3/l2/cmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/cmd.c
 */

#include "broadcast.h"   /* needed by the reconstruction */
#include "discover.h"   /* needed by the reconstruction */
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
#include "cmd.h"
#include "l2cmd.h"
#include "reqrspq.h"
#include "dest.h"
#include "../../common/sys/Cmd.h"
#include "format.h"
#include "../main/nvram.h"
#include "../../common/sys/ipmi.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */
char *format_address(IRAddress addr);   /* defined in format's module; not in a header (name clash with a static elsewhere) */

static void cmd_timeout(L2CMD *c, int to, void *data);
static void cmd_etimeout(L2CMD *c, char *msg, void *data);
static void cmd_send_response(L2CMD *c, void *data, char *sptr, int rval);
static void cmd_process_queue_int(L2CMD *c, cmd_packet_cb *pktcb, void *data, cmd_response *cmd_rsp, int process_rsp);
static void cmd_process_queue(L2CMD *c);
static void cmd_process_queue_usr(L2CMD *c);

static int cmd_argc;
static L2CMD *cmd_l2cmd;
static L2CMD *cmd_l2cmd_usr;
static int cmd_usr_avail = 1;
static cmd_packet_cb *cmd_usr_cb;
static void *cmd_usr_data;
static IRArgument cmd_argv[256];
static cmd_response cmd_rsp;
static cmd_response cmd_rsp_usr;
static IRAddress cmd_src_addr;
static int cmd_src_seqn;
static int cmd_src_prev;
static int cmd_src_pdata;

void cmd_init(void)
{
  cmd_l2cmd = l2cmd_init(&l2_cmd_id,cmd_timeout,cmd_etimeout,cmd_send_response,NULL);
  cmd_l2cmd_usr =
       l2cmd_init(&l2_cmdusr_id,cmd_timeout,NULL,NULL,NULL);
  memset(&cmd_rsp,0,sizeof(cmd_response));
  cmd_rsp.size = 0x400;
  cmd_rsp.sptr = malloc(0x400);
  cmd_rsp.eptr = cmd_rsp.sptr;
  *cmd_rsp.sptr = '\0';
  memset(&cmd_rsp_usr,0,sizeof(cmd_response));
  cmd_rsp_usr.size = 0x400;
  cmd_rsp_usr.sptr = malloc(0x400);
  cmd_rsp_usr.eptr = cmd_rsp_usr.sptr;
  *cmd_rsp_usr.sptr = '\0';
  return;
}

L2CMD *cmd_setup_usr_response(cmd_packet_cb *rsp_cb, void *data)
{
  L2CMD *pLVar1;
  
  if (cmd_usr_avail == 0) {
    pLVar1 = NULL;
  }
  else {
    cmd_usr_cb = rsp_cb;
    cmd_usr_data = data;
    cmd_usr_avail = 0;
    dest_reset(cmd_l2cmd_usr->dest);
    cmd_rsp_usr.slen = 0;
    cmd_rsp_usr.status = 0;
    *cmd_rsp_usr.sptr = '\0';
    cmd_rsp_usr.eptr = cmd_rsp_usr.sptr;
    pLVar1 = cmd_l2cmd_usr;
  }
  return pLVar1;
}

void cmd_process_request(IRPacket *req)
{
  size_t sVar1;
  char *__s;
  int iVar2;
  int prev;
  IRAddress addr;
  IRPacket *rsp;
  int argc;
  IRArgument argv [2];
  char *rptr;
  char *pw;
  char *cmd;
  int status;
  
  rptr = NULL;
  if ((req->_argv[1]._clas & 7) == 0) {
    cmd = (char *)IR_VAL_PTR(req->_argv[1]._val);
  }
  else {
    cmd = (char *)IRArg(req,1);
  }
  if (cmd_l2cmd->busy == 0) {
    dest_reset(cmd_l2cmd->dest);
    cmd_src_seqn = (int)IR_SEQNUM(req);
    cmd_src_addr = req->_src;
    cmd_src_prev = (int)req->_rev;
    cmd_src_pdata = (int)(req->_pdata_auth >> 3);
    cmd_argv[0]._clas = '\0';
    cmd_argv[0]._frame = '\0';
    cmd_argv[0]._val = 0;
    cmd_argv[0]._size = 0;
    cmd_argc = 1;
    cmd_rsp.status = 0;
    cmd_rsp.slen = 0;
    *cmd_rsp.sptr = '\0';
    cmd_rsp.eptr = cmd_rsp.sptr;
    status = l2cmd_process(cmd_l2cmd,cmd,&rptr,NULL);
    if (status != 0) {
      cmd_argv[0]._clas = '\0';
      cmd_argv[0]._frame = '\0';
      cmd_argv[0]._val = 0xffffffff;
      cmd_argv[0]._size = 0;
    }
    if (rptr != NULL) {
      __s = cmd_rsp.eptr;
      if (cmd_rsp.eptr == NULL) {
        __s = "";
      }
      sVar1 = strlen(__s);
      iVar2 = sVar1 + cmd_rsp.slen;
      cmd_rsp.slen = iVar2;
      sVar1 = strlen(rptr);
      if ((unsigned int)cmd_rsp.size <= sVar1 + iVar2 + 0x10) {
        iVar2 = cmd_rsp.size + 0x200;
        sVar1 = strlen(rptr);
        cmd_rsp.size = sVar1 + iVar2;
        cmd_rsp.sptr = realloc(cmd_rsp.sptr,cmd_rsp.size);
      }
      cmd_rsp.eptr = cmd_rsp.sptr + cmd_rsp.slen;
      strcat(cmd_rsp.eptr,rptr);
      free(rptr);
    }
    IRouterFreePacket(req);
    if (cmd_l2cmd->busy == 0) {
      l2cmd_process_response(cmd_l2cmd,cmd_rsp.sptr,cmd_rsp.status);
    }
  }
  else {
    status = l2cmd_process(NULL,cmd,&rptr,NULL);
    if (status == 0) {
      argv[0]._clas = '\0';
      argv[0]._frame = '\0';
      argv[0]._val = 0;
      argv[0]._size = 0;
      argv[1]._clas = '\0';
      argv[1]._frame = '\0';
      argv[1]._val = 0;
      argv[1]._size = 0;
      if (rptr != NULL) {
        sVar1 = strlen(rptr);
        if (sVar1 == 0) {
          free(rptr);
        }
        else {
          argv[1]._clas = '\n';
          argv[1]._frame = '\0';
          argv[1]._val = IR_PTR_VAL(rptr);
          sVar1 = strlen(rptr);
          argv[1]._size = (short)sVar1 + 1;
        }
      }
    }
    else {
      argv[0]._clas = '\0';
      argv[0]._frame = '\0';
      argv[0]._val = 0xffffffff;
      argv[0]._size = 0;
      argv[1]._val = IR_PTR_VAL(strdup("ERROR: command library is busy\n"));
      argv[1]._clas = '\n';
      argv[1]._frame = '\0';
      rptr = (char *)IR_VAL_PTR(argv[1]._val);
      sVar1 = strlen((char *)IR_VAL_PTR(argv[1]._val));
      argv[1]._size = (short)sVar1 + 1;
    }
    argc = 2;
    addr = req->_src;
    rsp = IRouterMakePacket(&l2_cmd_id,&addr,(unsigned int)(req->_pdata_auth >> 3),0,1,(unsigned int)req->_rev,2,
                            argv);
    if (rsp == NULL) {
      fprintf(stderr,"ERROR: can\'t create packet for command response.\n");
    }
    else {
      rsp->_seqnum0 = req->_seqnum0;
      rsp->_seqnum1 = req->_seqnum1;
      IRouterSendPacket(NULL,rsp);
    }
    IRouterFreePacket(req);
  }
  return;
}

static void cmd_timeout(L2CMD *c, int to, void *data)
{
  if (c == cmd_l2cmd) {
    cmd_process_queue(c);
  }
  else {
    cmd_process_queue_usr(c);
  }
  return;
}

static void cmd_etimeout(L2CMD *c, char *msg, void *data)
{
  return;
}

static void cmd_send_response(L2CMD *c, void *data, char *sptr, int rval)
{
  int rsplen;
  int iVar1;
  char *pcVar2;
  size_t sVar3;
  IRPacket *rsp;
  char *nptr;
  int slen;
  char *eptr;
  char *aptr;
  
  rsplen = strlen(sptr);
  iVar1 = reqq_empty(c->q);
  if ((iVar1 == 0) || (iVar1 = rspq_empty(c->q), iVar1 == 0)) {
    pcVar2 = cmd_rsp.eptr;
    if (cmd_rsp.eptr == NULL) {
      pcVar2 = "";
    }
    sVar3 = strlen(pcVar2);
    iVar1 = sVar3 + cmd_rsp.slen;
    cmd_rsp.slen = iVar1;
    sVar3 = strlen(sptr);
    if ((unsigned int)cmd_rsp.size <= sVar3 + iVar1 + 0x10) {
      iVar1 = cmd_rsp.size + 0x200;
      sVar3 = strlen(sptr);
      cmd_rsp.size = sVar3 + iVar1;
      cmd_rsp.sptr = realloc(cmd_rsp.sptr,cmd_rsp.size);
    }
    cmd_rsp.eptr = cmd_rsp.sptr + cmd_rsp.slen;
    strcat(cmd_rsp.sptr,sptr);
  }
  else {
    c->busy = 0;
    cmd_argv[0]._clas = '\0';
    cmd_argv[0]._frame = '\0';
    cmd_argv[0]._val = rval;
    cmd_argv[0]._size = 0;
    if (rsplen != 0) {
      aptr = sptr;
      eptr = sptr;
      while (*aptr != '\0') {
        pcVar2 = strchr(eptr,10);
        if (pcVar2 == NULL) {
          sVar3 = strlen(eptr);
          nptr = eptr + sVar3;
        }
        else {
          nptr = pcVar2 + 1;
        }
        if ((0xfffe < (int)(nptr - aptr)) || (eptr = nptr, *nptr == '\0')) {
          sVar3 = (int)(eptr - aptr);
          pcVar2 = malloc(sVar3 + 1);
          memcpy(pcVar2,aptr,sVar3);
          pcVar2[sVar3] = '\0';
          cmd_argv[cmd_argc]._clas = '\n';
          cmd_argv[cmd_argc]._frame = '\0';
          cmd_argv[cmd_argc]._val = IR_PTR_VAL(pcVar2);
          iVar1 = cmd_argc;
          sVar3 = strlen(pcVar2);
          cmd_argv[iVar1]._size = (short)sVar3 + 1;
          cmd_argc = cmd_argc + 1;
          aptr = eptr;
        }
      }
    }
    rsp = IRouterMakePacket(c->id,&cmd_src_addr,cmd_src_pdata,0,1,cmd_src_prev,cmd_argc,cmd_argv);
    if (rsp == NULL) {
      fprintf(stderr,"ERROR: can\'t create packet for command response.\n");
    }
    else {
      rsp->_seqnum0 = (uint8)cmd_src_seqn;
      rsp->_seqnum1 = (uint8)((unsigned int)cmd_src_seqn >> 8);
      IRouterSendPacket(NULL,rsp);
    }
    cmd_argc = 0;
  }
  return;
}

static void cmd_process_queue_int(L2CMD *c, cmd_packet_cb *pktcb, void *data, cmd_response *cmd_rsp, int process_rsp)
{
  char *pcVar1;
  size_t sVar2;
  int iVar3;
  int lastpkt;
  char *sptr;
  int pktcnt;
  int rsplen;
  void *qe;
  IRPacket *rsp;
  IRAddress dest;
  unsigned int seqn;
  
  qe = NULL;
  rsplen = 0;
  rspq_timeout_clr(c->q);
  while (qe = rspq_peek(c->q,qe,&seqn,&dest,&rsp), qe != NULL) {
    iVar3 = cmd_estimate_packet_rsplen(rsp,c,&dest,c->q->rspq_length,cmd_rsp,data);
    rsplen = rsplen + iVar3;
  }
  pcVar1 = cmd_rsp->eptr;
  if (cmd_rsp->eptr == NULL) {
    pcVar1 = "";
  }
  sVar2 = strlen(pcVar1);
  iVar3 = sVar2 + cmd_rsp->slen;
  cmd_rsp->slen = iVar3;
  if (cmd_rsp->size <= iVar3 + rsplen + 0x10) {
    sVar2 = cmd_rsp->size + 0x200 + rsplen;
    cmd_rsp->size = sVar2;
    pcVar1 = realloc(cmd_rsp->sptr,sVar2);
    cmd_rsp->sptr = pcVar1;
  }
  cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
  do {
    iVar3 = rspq_get(c->q,&seqn,&dest,&rsp);
    if (iVar3 == -1) break;
    iVar3 = c->q->rspq_length;
    (*pktcb)(rsp,c,&dest,c->q->rspq_length,cmd_rsp,data);
    if (rsp != NULL) {
      IRouterFreePacket(rsp);
    }
    discover_service();
  } while (iVar3 != 0);
  sVar2 = strlen(cmd_rsp->sptr);
  cmd_rsp->slen = sVar2;
  cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
  if (c->q->rspq_length == 0) {
    rspq_reset(c->q);
  }
  iVar3 = broadcast(c->q,c->id);
  if ((iVar3 == 0) && (reqq_reset(c->q), process_rsp != 0)) {
    l2cmd_process_response(c,cmd_rsp->sptr,cmd_rsp->status);
  }
  return;
}

static void cmd_process_queue(L2CMD *c)
{
  cmd_process_queue_int(c,cmd_process_packet_default,NULL,&cmd_rsp,1);
  return;
}

static void cmd_process_queue_usr(L2CMD *c)
{
  int iVar1;
  
  cmd_process_queue_int(c,cmd_usr_cb,cmd_usr_data,&cmd_rsp_usr,0);
  iVar1 = reqq_empty(c->q);
  if (iVar1 != 0) {
    iVar1 = rspq_empty(c->q);
    if (iVar1 != 0) {
      cmd_usr_avail = 1;
      *cmd_rsp_usr.sptr = '\0';
      cmd_rsp_usr.eptr = cmd_rsp_usr.sptr;
      cmd_rsp_usr.slen = 0;
    }
  }
  return;
}

void cmd_process_response(IRPacket *rsp)
{
  int rpend;
  
  rpend = rspq_update(cmd_l2cmd->q,rsp);
  if (rpend == -1) {
    IRouterFreePacket(rsp);
  }
  else if (rpend == 0) {
    cmd_process_queue(cmd_l2cmd);
  }
  return;
}

void cmd_process_response_usr(IRPacket *rsp)
{
  int rpend;
  
  if (cmd_usr_avail == 0) {
    rpend = rspq_update(cmd_l2cmd_usr->q,rsp);
    if (rpend == -1) {
      IRouterFreePacket(rsp);
    }
    else if (rpend == 0) {
      cmd_process_queue_usr(cmd_l2cmd_usr);
    }
  }
  return;
}

int cmd_process_packet_default(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data)
{
  char *pcVar1;
  size_t sVar2;
  int iVar3;
  int arg;
  int print_source;
  
  print_source = c->q->rspq_max_length;
  if (rsp == NULL) {
    cmd_rsp->status = -1;
    pcVar1 = cmd_rsp->eptr;
    if (cmd_rsp->eptr == NULL) {
      pcVar1 = "";
    }
    sVar2 = strlen(pcVar1);
    iVar3 = sVar2 + cmd_rsp->slen;
    cmd_rsp->slen = iVar3;
    if (cmd_rsp->size <= iVar3 + 0x74) {
      sVar2 = cmd_rsp->size + 0x264;
      cmd_rsp->size = sVar2;
      pcVar1 = realloc(cmd_rsp->sptr,sVar2);
      cmd_rsp->sptr = pcVar1;
    }
    cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
    strcat(cmd_rsp->eptr,"\n");
    if (print_source != 0) {
      pcVar1 = format_address(c->id->addr);
      strcat(cmd_rsp->eptr,pcVar1);
      strcat(cmd_rsp->eptr,":\n");
    }
    strcat(cmd_rsp->eptr,"ERROR: no response from ");
    pcVar1 = format_address(*dest);
    strcat(cmd_rsp->eptr,pcVar1);
    strcat(cmd_rsp->eptr,"\n");
  }
  else if (rsp->_err == '\0') {
    cmd_process_packet_args(rsp,c,dest,cmd_rsp,print_source);
  }
  else {
    cmd_rsp->status = -1;
    pcVar1 = cmd_rsp->eptr;
    if (cmd_rsp->eptr == NULL) {
      pcVar1 = "";
    }
    sVar2 = strlen(pcVar1);
    iVar3 = sVar2 + cmd_rsp->slen;
    cmd_rsp->slen = iVar3;
    if (cmd_rsp->size <= iVar3 + 0xd8) {
      sVar2 = cmd_rsp->size + 0x2c8;
      cmd_rsp->size = sVar2;
      pcVar1 = realloc(cmd_rsp->sptr,sVar2);
      cmd_rsp->sptr = pcVar1;
    }
    cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
    if (print_source != 0) {
      pcVar1 = format_address(rsp->_src);
      strcat(cmd_rsp->eptr,pcVar1);
      strcat(cmd_rsp->eptr," ");
    }
    strcat(cmd_rsp->eptr,"ERROR: couldn\'t send packet to ");
    pcVar1 = format_address(*dest);
    strcat(cmd_rsp->eptr,pcVar1);
    strcat(cmd_rsp->eptr,", ");
    pcVar1 = IRFmtError((unsigned int)rsp->_err);
    strcat(cmd_rsp->eptr,pcVar1);
    strcat(cmd_rsp->eptr,"\n");
    IRouterFreePacket(rsp);
  }
  return 0;
}

int cmd_process_packet_args(IRPacket *rsp, L2CMD *c, IRAddress *dest, cmd_response *cmd_rsp, int print_source)
{
  char *pcVar1;
  size_t sVar2;
  unsigned int uVar3;
  int iVar4;
  char *pcStack_c;
  int arg;
  
  if ((rsp->_argv[0]._clas & 7) == 0) {
    uVar3 = rsp->_argv[0]._val;
  }
  else {
    uVar3 = IRArg(rsp,0);
  }
  if (uVar3 != 0) {
    cmd_rsp->status = -1;
  }
  for (arg = 0; arg < (int)(unsigned int)rsp->_argc; arg = arg + 1) {
    if ((rsp->_argv[arg]._clas & 7) == 2) {
      if ((print_source != 0) && (dest != NULL)) {
        pcVar1 = cmd_rsp->eptr;
        if (cmd_rsp->eptr == NULL) {
          pcVar1 = "";
        }
        sVar2 = strlen(pcVar1);
        iVar4 = sVar2 + cmd_rsp->slen;
        cmd_rsp->slen = iVar4;
        if (cmd_rsp->size <= iVar4 + 0x24) {
          sVar2 = cmd_rsp->size + 0x214;
          cmd_rsp->size = sVar2;
          pcVar1 = realloc(cmd_rsp->sptr,sVar2);
          cmd_rsp->sptr = pcVar1;
        }
        cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
        pcVar1 = format_address(*dest);
        strcat(cmd_rsp->eptr,pcVar1);
        if ((rsp->_argv[0]._clas & 7) == 0) {
          uVar3 = rsp->_argv[0]._val;
        }
        else {
          uVar3 = IRArg(rsp,0);
        }
        if (uVar3 == 0) {
          strcat(cmd_rsp->eptr,":\n");
        }
        dest = NULL;
      }
      pcVar1 = cmd_rsp->eptr;
      if (cmd_rsp->eptr == NULL) {
        pcVar1 = "";
      }
      sVar2 = strlen(pcVar1);
      iVar4 = sVar2 + cmd_rsp->slen;
      cmd_rsp->slen = iVar4;
      if ((rsp->_argv[arg]._clas & 7) == 0) {
        pcVar1 = (char *)IR_VAL_PTR(rsp->_argv[arg]._val);
      }
      else {
        pcVar1 = (char *)IRArg(rsp,arg);
      }
      sVar2 = strlen(pcVar1);
      if ((unsigned int)cmd_rsp->size <= sVar2 + iVar4 + 0x10) {
        iVar4 = cmd_rsp->size;
        if ((rsp->_argv[arg]._clas & 7) == 0) {
          pcStack_c = (char *)IR_VAL_PTR(rsp->_argv[arg]._val);
        }
        else {
          pcStack_c = (char *)IRArg(rsp,arg);
        }
        sVar2 = strlen(pcStack_c);
        sVar2 = sVar2 + iVar4 + 0x200;
        cmd_rsp->size = sVar2;
        pcVar1 = realloc(cmd_rsp->sptr,sVar2);
        cmd_rsp->sptr = pcVar1;
      }
      cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
      if ((rsp->_argv[arg]._clas & 7) == 0) {
        pcVar1 = (char *)IR_VAL_PTR(rsp->_argv[arg]._val);
      }
      else {
        pcVar1 = (char *)IRArg(rsp,arg);
      }
      strcat(cmd_rsp->eptr,pcVar1);
    }
  }
  return 0;
}

int cmd_estimate_packet_rsplen(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data)
{
  int print_source;
  int arglen;
  int arg;
  
  arglen = 0;
  if (rsp == NULL) {
    arglen = 100;
  }
  else if (rsp->_err == '\0') {
    for (arg = 0; arg < (int)(unsigned int)rsp->_argc; arg = arg + 1) {
      if ((rsp->_argv[arg]._clas & 7) == 2) {
        if ((c->q->rspq_max_length != 0) && (dest != NULL)) {
          arglen = arglen + 0x14;
        }
        arglen = arglen + (unsigned int)rsp->_argv[arg]._size;
      }
    }
  }
  else {
    arglen = 200;
  }
  return arglen;
}
