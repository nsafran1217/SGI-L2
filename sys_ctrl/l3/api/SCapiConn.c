/*
 * sys_ctrl/l3/api/SCapiConn.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapiConn.c
 *
 * The system controller API for tools with several L2 connections at once
 * (l2term, l2gui): SCapi.c's calls with an sn1SCConn each. A connection
 * is an IRouter client of an L2's command port, found by discovery when no
 * host is given, with a password asked for on the terminal if the L2 wants
 * one and none was given.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "SCapiConn.h"
#include "SCapi.h"
#include "SCapiL2.h"
#include "../IRouter/IRouterL3.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/Router/Router.h"
#include "../../common/Router/RouterMsg.h"
#include "../../common/sys/Logger.h"
#include "../sys/syslogLib.h"

#define L2_CMD_PORT     8000    /* plus IR_PORT_BIAS */
#define L2_QUIET_PORT   8002    /* ... for a quiet client (sn1SCIsQuiet()) */
#define TIMEOUT_ERR     IR_ERRNO(IRERR_TIMEOUT)

/* our IRouter address: an L3 (rack and slot all ones) */
#define L3_ADDR IR_ADDR_MAKE(IR_ADDR_L3, 0x3ff, 0x3f, 0, 0)

static char *get_password(IRClient *client);

static int sn1SCCount;
static char l2_cname[128];      /* our client name */
static int l2_port;
sn1SCConn *conn_in_progress;    /* the connection being made, for get_password() */

/* once per process */
int sn1SCConnInit(char *cname)
{
  if (sn1SCCount > 0) {
    syslog(4,"SCapiConn.c",66,0,"sn1SCConnLib already initialized!!");
    return 0;
  }
  sn1SCCount++;
  IRouterInit(0xffffffff);
  l2_port = IR_PORT_BIAS + (sn1SCIsQuiet() ? L2_QUIET_PORT : L2_CMD_PORT);
  strncpy(l2_cname,cname,sizeof(l2_cname) - 1);
  return 0;
}

/* copy a string into a field, truncated */
static void set_field(char *field, size_t size, const char *value)
{
  snprintf(field,size,"%s",value);
}

/*
 * Connect conn to host, or to the L2 discovery finds on iface (matching
 * sysname and ssn, if given). id is our IRouter task. With no passwd, one
 * is asked for if the L2 wants it.
 */
int sn1SCConnInitConn(sn1SCConn *conn, int id, char *host, char *iface, char *sysname, char *ssn, char *passwd)
{
  if (sn1SCCount == 0) {
    syslog(3,"SCapiConn.c",98,0,"sn1SCConnInitConn: system controller library not initialized!\n");
    exit(1);
  }
  memset(conn,0,sizeof(sn1SCConn));
  conn->ir_id.addr = L3_ADDR;
  if (host == NULL || *host == '\0') {
    if (sn1SCConnFindL2(conn->host,iface,sysname,ssn) < 0)
      return ROUTER_ERR_CONNECT_FAILED;
  }
  else {
    set_field(conn->host,sizeof(conn->host),host);      /* (the original strcpy()ed) */
  }
  if (passwd == NULL || *passwd == '\0') {
    conn->passwd_prompt = 1;
  }
  else {
    set_field(conn->passwd,sizeof(conn->passwd),passwd);
    conn->passwd_prompt = 0;
  }
  conn->task_id = id;
  conn->passwd_retrys = 0;
  return sn1SCConnReconnect(conn);
}

int sn1SCConnReconnect(sn1SCConn *conn)
{
  int rval;

  conn_in_progress = conn;
  rval = IRouterConnect(l2_cname,conn,l2_port,&conn->client,conn->task_id,get_password);
  if (rval != 0) {
    syslog(3,"SCapiConn.c",173,0,"IRouterConnect to %s failed: %s",conn->host,LoggerDefaultMessage(rval));
    return rval;
  }
  conn->passwd_retrys = 0;
  /* the client points back at its connection (host is its first field) */
  conn->client->cpp_hook = conn->host;
  conn_in_progress = NULL;
  return 0;
}

/* does the L2 match the system serial number and name (each if given)? */
static int l2_matches(sn1SC_L2 *l2, char *ssn, char *sysname)
{
  if (ssn != NULL && *ssn != '\0' && strcmp(ssn,l2->ssn) != 0)
    return 0;
  if (sysname != NULL && *sysname != '\0' && strcmp(sysname,l2->sysname) != 0)
    return 0;
  return 1;
}

/* the address (dotted, into host) of the first L2 on iface that matches;
 * -1 if there are none, -2 if none matches */
int sn1SCConnFindL2(char *host, char *iface, char *sysname, char *ssn)
{
  sn1SC_L2 *l2_list;
  int l2_cnt = 0;
  int i;

  if (sn1SCDiscoverL2(iface,NULL,&l2_list,&l2_cnt,1) < 0) {
    syslog(3,"SCapiConn.c",220,0,"error discovering L2 controllers!");
    return -1;
  }
  if (l2_cnt == 0) {
    syslog(3,"SCapiConn.c",226,0,"could not find an L2 controller to connect to!");
    return -1;
  }
  for (i = 0; i < l2_cnt && !l2_matches(&l2_list[i],ssn,sysname); i++)
    ;
  if (i == l2_cnt) {
    if (ssn != NULL && *ssn != '\0')
      syslog(3,"SCapiConn.c",255,0,"no L2 controllers found with serial number \'%s\'!",ssn);
    else if (sysname != NULL && *sysname != '\0')
      syslog(3,"SCapiConn.c",257,0,"no L2 controllers found with system name \'%s\'!",sysname);
    return -2;
  }
  strcpy(host,inet_ntoa(*(struct in_addr *)&l2_list[i].ip_addr));
  return 0;
}

void sn1SCConnDisconnect(sn1SCConn *conn)
{
  IRouterDisconnect(conn->client);
  conn->client = NULL;
}

int sn1SCConnSocket(sn1SCConn *conn)
{
  return conn->client == NULL ? -1 : conn->client->socket;
}

/* the L2 host, while connected */
char *sn1SCConnHost(sn1SCConn *conn)
{
  return conn->client == NULL ? NULL : conn->host;
}

/* the connection's client, NULL if it has gone */
IRClient *sn1SCConnClient(sn1SCConn *conn)
{
  if (conn->client != NULL && RouterFindClient(conn->client) == NULL)
    conn->client = NULL;
  return conn->client;
}

/* send a request; *id (if not NULL) is its sequence number */
int sn1SCConnReq(sn1SCConn *conn, IRAddress *toaddr, int opcode, int argc, IRArgument *argv, uint32 *id)
{
  char x[80];
  int seqnum;
  int rval;

  if (sn1SCCount == 0) {
    syslog(3,"SCapiConn.c",319,0,"sn1SCConnReq: system controller library not initialized!\n");
    exit(1);
  }
  if (sn1SCConnClient(conn) == NULL)
    return ROUTER_ERR_LOST;
  seqnum = conn->ir_id.seqnum;
  rval = IRouterRequest(conn->client,&conn->ir_id,toaddr,opcode,argc,argv,id);
  if (rval != 0) {
    syslog(3,"SCapiConn.c",335,0,"IRouterRequest failed: %s",LoggerDefaultMessage(rval));
    return rval;
  }
  if (ir_show)
    fprintf(stderr,"%s\n",SCFmtPkt(seqnum,0,argc,0,toaddr,&conn->ir_id.addr,x));
  return 0;
}

/* wait for a response on the connection; *id (if not NULL) its sequence number */
int sn1SCConnRsp(sn1SCConn *conn, IRPacket **pkt, uint32 *id, int wait)
{
  IRClient *client;
  char x[80];
  int rval;

  if (sn1SCCount == 0 || conn == NULL || conn->client == NULL)
    return -1;
  if (sn1SCConnClient(conn) == NULL)
    return ROUTER_ERR_LOST;
  client = conn->client;
  rval = IRouterGetPacket(&conn->ir_id,pkt,&client,wait,1);
  if (rval != 0) {
    syslog(3,"SCapiConn.c",390,0,"IRouterGetPacket failed: %s",LoggerDefaultMessage(rval));
    sn1SCConnClient(conn);      /* (drops a client that has gone) */
    return rval;
  }
  if (ir_show)
    fprintf(stderr,"%s\n",IRFmtPkt("PKT recv:",*pkt,x));
  if (id != NULL)
    *id = IR_SEQNUM(*pkt);
  return 0;
}

/*
 * Wait for any packet, on conn or (conn NULL) on any connection;
 * *pktconn is the connection it came on. (With conn NULL the original
 * passed an address computed from the NULL pointer as the ident, which the
 * L3 IRouter does not use.)
 */
int sn1SCConnPkt(sn1SCConn *conn, IRPacket **pkt, sn1SCConn **pktconn, int wait)
{
  IRClient *client = NULL;
  char x[80];
  int rval;

  if (sn1SCCount == 0)
    return -1;
  if (conn != NULL) {
    if (sn1SCConnClient(conn) == NULL)
      return ROUTER_ERR_LOST;
    client = conn->client;
  }
  rval = IRouterGetPacket(conn != NULL ? &conn->ir_id : NULL,pkt,&client,wait,0);
  if (rval != 0) {
    if (rval != TIMEOUT_ERR)
      syslog(3,"SCapiConn.c",466,0,"IRouterGetPacket failed: %s",LoggerDefaultMessage(rval));
    if (conn != NULL)
      sn1SCConnClient(conn);
    return rval;
  }
  *pktconn = (sn1SCConn *)client->cpp_hook;
  if (ir_show)
    fprintf(stderr,"%s\n",IRFmtPkt("PKT recv:",*pkt,x));
  return 0;
}

/* answer a request that came on the connection */
int sn1SCConnSendRsp(sn1SCConn *conn, int errcode, IRPacket *reqpkt, int argc, IRArgument *argv)
{
  char x[80];
  int seqnum;
  int rval;

  if (sn1SCCount == 0) {
    syslog(3,"SCapiConn.c",512,0,"sn1SCConnSendRsp: system controller library not initialized!\n");
    exit(1);
  }
  if (sn1SCConnClient(conn) == NULL)
    return ROUTER_ERR_LOST;
  seqnum = conn->ir_id.seqnum;
  rval = IRouterResponse(conn->client,&conn->ir_id,errcode,reqpkt,argc,argv);
  if (rval != 0) {
    syslog(3,"SCapiConn.c",528,0,"IRouterResponse failed: %s",LoggerDefaultMessage(rval));
    return rval;
  }
  if (ir_show)
    fprintf(stderr,"%s\n",SCFmtPkt(seqnum,1,argc,0,&reqpkt->_src,&conn->ir_id.addr,x));
  return 0;
}

/* does a response's sequence number (8 bits in revision 0 packets) match
 * the request's? */
static int response_matches(IRPacket *rsp, uint32 reqid, uint32 rspid)
{
  return (rsp->_rev == 0 ? (reqid & 0xff) : (reqid & 0xffff)) == rspid;
}

/* a request and its response, skipping responses to other requests */
int sn1SCConnCmd(sn1SCConn *conn, IRAddress *toaddr, int opcode, int argc, IRArgument *argv, IRPacket **rpkt, int wait)
{
  uint32 reqid, rspid;
  int rval;

  rval = sn1SCConnReq(conn,toaddr,opcode,argc,argv,&reqid);
  if (rval != 0) {
    syslog(3,"SCapiConn.c",559,0,"sn1SCConnCmd: sn1SCConnReq: %s\n",LoggerDefaultMessage(rval));
    return rval;
  }
  while ((rval = sn1SCConnRsp(conn,rpkt,&rspid,wait)) == 0) {
    if (response_matches(*rpkt,reqid,rspid))
      return 0;
    syslog(4,"SCapiConn.c",575,0,
           "sn1SCConnCmd: unexpected response (request ID did not match response ID!!)\n");
  }
  syslog(3,"SCapiConn.c",567,0,"sn1SCConnCmd: sn1SCConnRsp: %s\n",LoggerDefaultMessage(rval));
  return rval;
}

/*
 * The same request to ntargets addresses (0 to skip one) at once, with
 * argc arguments each (the same ones if share_args); rpkt[t] gets each
 * response, errlist[t] each error. Gives up after five response errors in
 * a row, or at a timeout or a lost connection (a timeout is not an error).
 *
 * Reconstructed by hand: the original uses variable-length arrays, which threw
 * off Ghidra's stack tracking for the whole function. Logic and syslog line
 * numbers checked against the machine code.
 */
int sn1SCConnCmdParallel(sn1SCConn *conn, IRAddress *toaddr, int ntargets, int opcode, int argc, IRArgument *argv, int share_args, IRPacket **rpkt, int *errlist, int *nerrs, int wait)
{
  IRAddress tmpaddr[ntargets];  /* the targets still waiting */
  uint32 reqid[ntargets];
  IRPacket *rp;
  uint32 rspid;
  int offset;
  int errval = 0;
  int rerrcnt = 0;
  int nrequests = 0;
  int rval;
  int t;

  memcpy(tmpaddr,toaddr,ntargets * sizeof(IRAddress));
  memset(errlist,0,ntargets * sizeof(int));
  *nerrs = 0;
  for (t = 0; t < ntargets; t++) {
    offset = (share_args == 0 && argv != NULL) ? t * argc : 0;
    if (tmpaddr[t] == 0)
      continue;
    rval = sn1SCConnReq(conn,&tmpaddr[t],opcode,argc,argv + offset,&reqid[t]);
    if (rval == 0) {
      nrequests++;
    }
    else {
      tmpaddr[t] = 0;
      errlist[t] = rval;
    }
  }
  while (nrequests > 0) {
    rval = sn1SCConnRsp(conn,&rp,&rspid,wait);
    if (rval != 0) {
      if (rval == TIMEOUT_ERR || rval == ROUTER_ERR_LOST) {
        errval = rval;
        break;
      }
      syslog(3,"SCapiConn.c",655,0,"sn1SCConnCmdParallel: sn1SCConnRsp: %s\n",LoggerDefaultMessage(rval));
      if (rerrcnt++ >= 4) {
        errval = rval;
        break;
      }
      continue;
    }
    rerrcnt = 0;
    for (t = 0; t < ntargets; t++) {
      if (tmpaddr[t] != 0 && response_matches(rp,reqid[t],rspid)) {
        rpkt[t] = rp;
        tmpaddr[t] = 0;
        nrequests--;
        break;
      }
    }
    if (t == ntargets)
      syslog(3,"SCapiConn.c",701,0,"sn1SCConnCmdParallel: response ID did not match any request ID!!\n");
  }
  if (nrequests > 0) {
    for (t = 0; t < ntargets; t++)
      if (tmpaddr[t] != 0 && errlist[t] == 0)
        errlist[t] = errval;
  }
  return errval == TIMEOUT_ERR ? 0 : errval;
}

/*
 * IRouterConnect()'s password callback: the given password, or one read
 * from the terminal (again, after "incorrect password", on a retry).
 */
static char *get_password(IRClient *client)
{
  sn1SCConn *conn = (sn1SCConn *)client->cpp_hook;
  char *pw;

  if (conn_in_progress != NULL && conn == NULL) {
    conn = conn_in_progress;
    client->cpp_hook = conn_in_progress->host;
    conn_in_progress = NULL;
  }
  if (!conn->passwd_prompt)
    return conn->passwd;
  if (conn->passwd_retrys++ != 0) {
    conn->passwd[0] = '\0';
    printf("incorrect password\n");
  }
  if (conn->passwd[0] != '\0')
    return conn->passwd;
  pw = getpass("L2 Password:");
  if (pw != NULL)
    set_field(conn->passwd,sizeof(conn->passwd),pw);
  return pw;
}
