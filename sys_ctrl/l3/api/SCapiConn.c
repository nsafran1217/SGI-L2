/*
 * sys_ctrl/l3/api/SCapiConn.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapiConn.c
 */

#include <unistd.h>
#include "SCapiL2.h"   /* needed by the reconstruction */
#include "../l2/l2cmd.h"   /* needed by the reconstruction */
#include "../l2/smp.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <mcheck.h>
#include "SCapi.h"
#include "../IRouter/IRouterL3.h"
#include "../../common/Router/Router.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/sysctl_types.h"
#include "../../common/sys/sysutils.h"
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <errno.h>
#include "../../common/sys/Logger.h"
#include "../sys/LoggerMsg.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../IRouter/IRouterOS.h"
#include "SCapiConn.h"
#include "../../common/sys/syslog.h"
#include "../../common/Router/RouterMsg.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static char *get_password(IRClient *client);

static int sn1SCCount;
static char l2_cname[128];
static int l2_port;
static char *myname;
sn1SCConn *conn_in_progress;

int sn1SCConnInit(char *cname)
{
  int iVar1;
  int rval;
  
  if (sn1SCCount < 1) {
    sn1SCCount = sn1SCCount + 1;
    IRouterInit(0xffffffff);
    iVar1 = sn1SCIsQuiet();
    if (iVar1 == 0) {
      l2_port = IR_PORT_BIAS + 8000;
    }
    else {
      l2_port = IR_PORT_BIAS + 0x1f42;
    }
    strncpy(l2_cname,cname,0x7f);
  }
  else {
    syslog(4,"SCapiConn.c",0x42,0,"sn1SCConnLib already initialized!!");
  }
  return 0;
}

int sn1SCConnInitConn(sn1SCConn *conn, int id, char *host, char *iface, char *sysname, char *ssn, char *passwd)
{
  int rval;
  int iVar1;
  
  if (sn1SCCount == 0) {
    syslog(3,"SCapiConn.c",0x62,0,"sn1SCConnInitConn: system controller library not initialized!\n")
    ;
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  memset(conn,0,0x1868);
  (conn->ir_id).addr = 0x2ffff000;
  if ((host == NULL) || (*host == '\0')) {
    rval = sn1SCConnFindL2(conn->host,iface,sysname,ssn);
    if (rval < 0) {
      return -300;
    }
  }
  else {
    strcpy(conn->host,host);
  }
  if ((passwd == NULL) || (*passwd == '\0')) {
    conn->passwd_prompt = '\x01';
  }
  else {
    strcpy(conn->passwd,passwd);
    conn->passwd_prompt = '\0';
  }
  conn->task_id = id;
  conn->passwd_retrys = '\0';
  iVar1 = sn1SCConnReconnect(conn);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  return iVar1;
}

int sn1SCConnReconnect(sn1SCConn *conn)
{
  int rval;
  char *pcVar1;
  
  conn_in_progress = conn;
  rval = (*IRouterConnect)(l2_cname,conn,l2_port,&conn->client,conn->task_id,get_password);
  if (rval == 0) {
    conn->passwd_retrys = '\0';
    conn->client->cpp_hook = conn->host;
    conn_in_progress = NULL;
  }
  else {
    pcVar1 = LoggerDefaultMessage(rval);
    syslog(3,"SCapiConn.c",0xad,0,"IRouterConnect to %s failed: %s",conn,pcVar1);
  }
  return rval;
}

int sn1SCConnFindL2(char *host, char *iface, char *sysname, char *ssn)
{
  int iVar1;
  char *__src;
  int l2_cnt;
  sn1SC_L2 *l2;
  sn1SC_L2 *l2_list;
  int rval;
  int i;
  
  l2_cnt = 0;
  iVar1 = sn1SCDiscoverL2(iface,NULL,&l2_list,&l2_cnt,1);
  if (iVar1 < 0) {
    syslog(3,"SCapiConn.c",0xdc,0,"error discovering L2 controllers!");
    iVar1 = -1;
  }
  else if (l2_cnt == 0) {
    syslog(3,"SCapiConn.c",0xe2,0,"could not find an L2 controller to connect to!");
    iVar1 = -1;
  }
  else {
    if (((ssn == NULL) || ((ssn != NULL && (*ssn == '\0')))) &&
       ((sysname == NULL || ((sysname != NULL && (*sysname == '\0')))))) {
      l2 = l2_list;
      i = 0;
    }
    else {
      l2 = l2_list;
      i = 0;
      while ((i < l2_cnt &&
             ((((ssn != NULL && (*ssn != '\0')) && (iVar1 = strcmp(ssn,l2->ssn), iVar1 != 0))
              || (((sysname != NULL && (*sysname != '\0')) &&
                  (iVar1 = strcmp(sysname,l2->sysname), iVar1 != 0))))))) {
        l2 = l2 + 1;
        i = i + 1;
      }
    }
    if (i == l2_cnt) {
      if ((ssn == NULL) || (*ssn == '\0')) {
        if ((sysname != NULL) && (*sysname != '\0')) {
          syslog(3,"SCapiConn.c",0x101,0,"no L2 controllers found with system name \'%s\'!",sysname)
          ;
        }
      }
      else {
        syslog(3,"SCapiConn.c",0xff,0,"no L2 controllers found with serial number \'%s\'!",ssn);
      }
      iVar1 = -2;
    }
    else {
      __src = inet_ntoa(*(struct in_addr *)&l2->ip_addr);
      strcpy(host,__src);
      iVar1 = 0;
    }
  }
  return iVar1;
}

void sn1SCConnDisconnect(sn1SCConn *conn)
{
  (*IRouterDisconnect)(conn->client);
  conn->client = NULL;
  return;
}

int sn1SCConnSocket(sn1SCConn *conn)
{
  int iVar1;
  
  if (conn->client == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = conn->client->socket;
  }
  return iVar1;
}

char *sn1SCConnHost(sn1SCConn *conn)
{
  if (conn->client == NULL) {
    conn = NULL;
  }
  return conn->host;
}

IRClient *sn1SCConnClient(sn1SCConn *conn)
{
  RouterClient *pRVar1;
  
  if (conn->client != NULL) {
    pRVar1 = RouterFindClient(conn->client);
    if (pRVar1 == NULL) {
      conn->client = NULL;
    }
  }
  return conn->client;
}

int sn1SCConnReq(sn1SCConn *conn, IRAddress *toaddr, int opcode, int argc, IRArgument *argv, uint32 *id)
{
  ushort uVar1;
  IRClient *pIVar2;
  int rval;
  char *pcVar3;
  char x [80];
  int seqnum;
  
  if (sn1SCCount == 0) {
    syslog(3,"SCapiConn.c",0x13f,0,"sn1SCConnReq: system controller library not initialized!\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pIVar2 = sn1SCConnClient(conn);
  if (pIVar2 == NULL) {
    rval = -0x12f;
  }
  else {
    uVar1 = (conn->ir_id).seqnum;
    rval = (*IRouterRequest)(conn->client,&conn->ir_id,toaddr,opcode,argc,argv,id);
    if (rval == 0) {
      if (ir_show != 0) {
        pcVar3 = SCFmtPkt((uint)uVar1,0,argc,0,toaddr,&(conn->ir_id).addr,x);
        fprintf(stderr,"%s\n",pcVar3);
      }
      rval = 0;
    }
    else {
      pcVar3 = LoggerDefaultMessage(rval);
      syslog(3,"SCapiConn.c",0x14f,0,"IRouterRequest failed: %s",pcVar3);
    }
  }
  return rval;
}

int sn1SCConnRsp(sn1SCConn *conn, IRPacket **pkt, uint32 *id, int wait)
{
  IRClient *pIVar1;
  char *pcVar2;
  char x [80];
  IRClient *client;
  int rval;
  
  if (((sn1SCCount == 0) || (conn == NULL)) || (conn->client == NULL)) {
    rval = -1;
  }
  else {
    pIVar1 = sn1SCConnClient(conn);
    if (pIVar1 == NULL) {
      rval = -0x12f;
    }
    else {
      client = NULL;
      if (conn != NULL) {
        if ((conn != NULL) && (conn->client == NULL)) {
          return -1;
        }
        client = conn->client;
      }
      rval = (*IRouterGetPacket)(&conn->ir_id,pkt,&client,wait,1);
      if (rval == 0) {
        if (ir_show != 0) {
          pcVar2 = IRFmtPkt("PKT recv:",*pkt,x);
          fprintf(stderr,"%s\n",pcVar2);
        }
        if (id != NULL) {
          *id = (uint)CONCAT11((*pkt)->_seqnum1,(*pkt)->_seqnum0);
        }
        rval = 0;
      }
      else {
        pcVar2 = LoggerDefaultMessage(rval);
        syslog(3,"SCapiConn.c",0x186,0,"IRouterGetPacket failed: %s",pcVar2);
        if (conn != NULL) {
          sn1SCConnClient(conn);
        }
      }
    }
  }
  return rval;
}

int sn1SCConnPkt(sn1SCConn *conn, IRPacket **pkt, sn1SCConn **pktconn, int wait)
{
  IRClient *pIVar1;
  char *pcVar2;
  char x [80];
  IRClient *client;
  int rval;
  
  if (sn1SCCount == 0) {
    rval = -1;
  }
  else if ((conn == NULL) || (pIVar1 = sn1SCConnClient(conn), pIVar1 != NULL)
          ) {
    client = NULL;
    if (conn != NULL) {
      if ((conn != NULL) && (conn->client == NULL)) {
        return -1;
      }
      client = conn->client;
    }
    rval = (*IRouterGetPacket)(&conn->ir_id,pkt,&client,wait,0);
    if (rval == 0) {
      *pktconn = (sn1SCConn *)client->cpp_hook;
      if (ir_show != 0) {
        pcVar2 = IRFmtPkt("PKT recv:",*pkt,x);
        fprintf(stderr,"%s\n",pcVar2);
      }
      rval = 0;
    }
    else {
      if (rval != -0x26c) {
        pcVar2 = LoggerDefaultMessage(rval);
        syslog(3,"SCapiConn.c",0x1d2,0,"IRouterGetPacket failed: %s",pcVar2);
      }
      if (conn != NULL) {
        sn1SCConnClient(conn);
      }
    }
  }
  else {
    rval = -0x12f;
  }
  return rval;
}

int sn1SCConnSendRsp(sn1SCConn *conn, int errcode, IRPacket *reqpkt, int argc, IRArgument *argv)
{
  ushort uVar1;
  IRClient *pIVar2;
  int rval;
  char *pcVar3;
  char x [80];
  int seqnum;
  
  if (sn1SCCount == 0) {
    syslog(3,"SCapiConn.c",0x200,0,"sn1SCConnSendRsp: system controller library not initialized!\n")
    ;
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  pIVar2 = sn1SCConnClient(conn);
  if (pIVar2 == NULL) {
    rval = -0x12f;
  }
  else {
    uVar1 = (conn->ir_id).seqnum;
    rval = (*IRouterResponse)(conn->client,&conn->ir_id,errcode,reqpkt,argc,argv);
    if (rval == 0) {
      if (ir_show != 0) {
        pcVar3 = SCFmtPkt((uint)uVar1,1,argc,0,&reqpkt->_src,&(conn->ir_id).addr,x);
        fprintf(stderr,"%s\n",pcVar3);
      }
      rval = 0;
    }
    else {
      pcVar3 = LoggerDefaultMessage(rval);
      syslog(3,"SCapiConn.c",0x210,0,"IRouterResponse failed: %s",pcVar3);
    }
  }
  return rval;
}

int sn1SCConnCmd(sn1SCConn *conn, IRAddress *toaddr, int opcode, int argc, IRArgument *argv, IRPacket **rpkt, int wait)
{
  char *pcVar1;
  uint uVar2;
  uint32 rspid;
  uint32 reqid;
  int rval;
  
  rval = sn1SCConnReq(conn,toaddr,opcode,argc,argv,&reqid);
  if (rval == 0) {
    while (rval = sn1SCConnRsp(conn,rpkt,&rspid,wait), rval == 0) {
      if ((*rpkt)->_rev == '\0') {
        uVar2 = reqid & 0xff;
      }
      else {
        uVar2 = reqid & 0xffff;
      }
      if (uVar2 == rspid) {
        return 0;
      }
      syslog(4,"SCapiConn.c",0x23f,0,
             "sn1SCConnCmd: unexpected response (request ID did not match response ID!!)\n");
    }
    pcVar1 = LoggerDefaultMessage(rval);
    syslog(3,"SCapiConn.c",0x237,0,"sn1SCConnCmd: sn1SCConnRsp: %s\n",pcVar1);
  }
  else {
    pcVar1 = LoggerDefaultMessage(rval);
    syslog(3,"SCapiConn.c",0x22f,0,"sn1SCConnCmd: sn1SCConnReq: %s\n",pcVar1);
  }
  return rval;
}

/* Reconstructed by hand: the original uses variable-length arrays, which threw
 * off Ghidra's stack tracking for the whole function. Logic and syslog line
 * numbers checked against the machine code. */
int sn1SCConnCmdParallel(sn1SCConn *conn, IRAddress *toaddr, int ntargets, int opcode, int argc, IRArgument *argv, int share_args, IRPacket **rpkt, int *errlist, int *nerrs, int wait)
{
  IRAddress tmpaddr[ntargets];
  uint32 reqid[ntargets];
  IRPacket *rp;
  uint32 rspid;
  uint32 id;
  int offset;
  int errval = 0;
  int rerrcnt;
  int nrequests = 0;
  int rval;
  int t;

  memcpy(tmpaddr, toaddr, ntargets * sizeof(IRAddress));
  memset(errlist, 0, ntargets * sizeof(int));
  *nerrs = 0;
  for (t = 0; t < ntargets; t++) {
    offset = (share_args == 0 && argv != NULL) ? t * argc : 0;
    if (tmpaddr[t] != 0) {
      rval = sn1SCConnReq(conn, &tmpaddr[t], opcode, argc, argv + offset, &reqid[t]);
      if (rval == 0) {
        nrequests++;
      }
      else {
        tmpaddr[t] = 0;
        errlist[t] = rval;
      }
    }
  }
  rerrcnt = 0;
  while (nrequests > 0) {
    rval = sn1SCConnRsp(conn, &rp, &rspid, wait);
    if (rval != 0) {
      if (rval == -0x26c || rval == -0x12f) {
        errval = rval;
        break;
      }
      syslog(3, "SCapiConn.c", 655, 0, "sn1SCConnCmdParallel: sn1SCConnRsp: %s\n", LoggerDefaultMessage(rval));
      if (rerrcnt++ >= 4) {
        errval = rval;
        break;
      }
      continue;
    }
    rerrcnt = 0;
    for (t = 0; t < ntargets; t++) {
      if (tmpaddr[t] != 0) {
        id = (rp->_rev == 0) ? (reqid[t] & 0xff) : (reqid[t] & 0xffff);
        if (id == rspid) {
          rpkt[t] = rp;
          tmpaddr[t] = 0;
          nrequests--;
          break;
        }
      }
    }
    if (t == ntargets) {
      syslog(3, "SCapiConn.c", 701, 0, "sn1SCConnCmdParallel: response ID did not match any request ID!!\n");
    }
  }
  if (nrequests > 0) {
    for (t = 0; t < ntargets; t++) {
      if (tmpaddr[t] != 0 && errlist[t] == 0) {
        errlist[t] = errval;
      }
    }
  }
  if (errval == -0x26c) {
    errval = 0;
  }
  return errval;
}

static char *get_password(IRClient *client)
{
  uchar uVar1;
  char *__src;
  sn1SCConn *conn;
  char *pw;
  
  conn = (sn1SCConn *)client->cpp_hook;
  if ((conn_in_progress != NULL) && (conn == NULL)) {
    conn = conn_in_progress;
    client->cpp_hook = conn_in_progress->host;
    conn_in_progress = NULL;
  }
  if (conn->passwd_prompt == '\0') {
    __src = conn->passwd;
  }
  else {
    uVar1 = conn->passwd_retrys;
    conn->passwd_retrys = conn->passwd_retrys + '\x01';
    if (uVar1 != '\0') {
      conn->passwd[0] = '\0';
      printf("incorrect password\n");
    }
    if (conn->passwd[0] == '\0') {
      __src = getpass("L2 Password:");
      if (__src == NULL) {
        __src = NULL;
      }
      else if (conn->passwd[0] == '\0') {
        strcpy(conn->passwd,__src);
      }
    }
    else {
      __src = conn->passwd;
    }
  }
  return __src;
}
