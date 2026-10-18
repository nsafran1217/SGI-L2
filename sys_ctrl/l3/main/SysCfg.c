/*
 * sys_ctrl/l3/main/SysCfg.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/main/SysCfg.c
 *
 * The system configuration as an L3 tool sees it: the L2's configuration
 * event (L2CfgMCfgL2()) gives every L2 and the L1s behind them, kept as
 * lists for printing and addressing. With conn NULL the functions use the
 * process' one connection (SCapi.c) and the globals here; otherwise the
 * connection's own copies (SCapiConn.c).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "SysCfg.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/Router/Socket.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/sys/Logger.h"
#include "../api/SCapi.h"
#include "../api/SCapiConn.h"
#include "../sys/syslogLib.h"

#define SYSCFG_REV          2   /* the newest configuration event we understand */
#define SYSCFG_TIMEOUT      30  /* seconds, for the configuration command */
#define SYSCFG_L1_MAX       1024        /* SysCfgL1List */
#define SYSCFG_L2_MAX       128         /* SysCfgL2List */

/* the L2's configuration task (rack and slot all ones) */
#define L2_CFG_ADDR IR_ADDR_MAKE(IR_ADDR_L2, 0x3ff, 0x3f, 0, IR_L2_CFG)

SysCfgL2 *SysCfgFull = &L2CfgLocal;
int SysCfgL1Count;
int SysCfgL2Count;
SysCfgL1 *SysCfgL1List[SYSCFG_L1_MAX];
SysCfgL2 *SysCfgL2List[SYSCFG_L2_MAX];
static char *SysCfgQuery;       /* the last configuration's query string (rev 2) */

/* the IRouter client of the connection */
static IRClient *conn_client(sn1SCConn *conn)
{
  return conn == NULL ? sn1SCClient() : sn1SCConnClient(conn);
}

/* fetch the configuration from the L2 now */
void SysCfgConnInit(sn1SCConn *conn, char *user)
{
  IRClient *client = conn_client(conn);
  IRAddress addr = L2_CFG_ADDR;
  IRArgument av[3];
  IRPacket *pkt;
  int rval;

  if (client == NULL) {
    syslog(3,"SysCfg.c",38,0,"%s: SysCfgConnInit: no connection to system controller network!\n",
           user);
    return;
  }
  L2CfgMInitL3(conn == NULL ? &L2CfgLocal : &conn->SysCfgFull,client);
  memset(&av[0],0,sizeof(av[0]));
  if (conn == NULL)
    rval = sn1SCCmd(&addr,0,1,av,&pkt,SYSCFG_TIMEOUT);
  else
    rval = sn1SCConnCmd(conn,&addr,0,1,av,&pkt,SYSCFG_TIMEOUT);
  if (rval != 0) {
    syslog(3,"SysCfg.c",58,0,"%s: config command failed: %s\n",user,LoggerDefaultMessage(rval));
    return;
  }
  if (SysCfgConnProcessEvent(conn,user,pkt) < 0)
    syslog(3,"SysCfg.c",89,0,"%s: SysCfgConnInit: error updating System Configuration!\n",user);
}

/* ask for the configuration; it comes as an event */
void SysCfgConnRequest(sn1SCConn *conn, char *user)
{
  IRAddress addr = L2_CFG_ADDR;
  IRArgument av[2];
  int rval;

  memset(&av[0],0,sizeof(av[0]));
  if (conn == NULL) {
    rval = sn1SCReq(&addr,0,1,av,NULL);
    if (rval != 0)
      syslog(3,"SysCfg.c",104,0,"%s: config request failed: %s\n",user,LoggerDefaultMessage(rval));
  }
  else {
    rval = sn1SCConnReq(conn,&addr,0,1,av,NULL);
    if (rval != 0)
      syslog(3,"SysCfg.c",107,0,"%s: config request failed: %s\n",user,LoggerDefaultMessage(rval));
  }
}

/* has the list an L1 with this one's rack, slot and type? */
static int listed_l1(L2CfgL1 **l1list, int l1cnt, L2CfgL1 *l1cfg)
{
  int s;

  for (s = 0; s < l1cnt; s++)
    if (l1list[s]->rack == l1cfg->rack && l1list[s]->slot == l1cfg->slot &&
        l1list[s]->type == l1cfg->type)
      return 1;
  return 0;
}

/*
 * A configuration (the response to SysCfgConnInit(), or an event): its
 * arguments are a (skipped) argument, the revision and, from rev 2, a query
 * string that is the same while nothing changed. Rebuilds the lists of L2s
 * and of the configured L1s (each rack, slot and type once).
 */
int SysCfgConnProcessEvent(sn1SCConn *conn, char *user, IRPacket *pkt)
{
  char **query;
  int *l1cnt, *l2cnt;
  L2CfgL1 **l1list;
  L2Cfg **l2list;
  L2Cfg *l2;
  L2CfgPort *port;
  int rev, p, l1;
  char *cptr;

  if (conn == NULL) {
    query = &SysCfgQuery;
    l1cnt = &SysCfgL1Count;
    l2cnt = &SysCfgL2Count;
    l1list = SysCfgL1List;
    l2list = SysCfgL2List;
    l2 = SysCfgFull;
  }
  else {
    query = &conn->SysCfgQuery;
    l1cnt = &conn->SysCfgL1Count;
    l2cnt = &conn->SysCfgL2Count;
    l1list = conn->SysCfgL1List;
    l2list = conn->SysCfgL2List;
    l2 = &conn->SysCfgFull;
  }
  if (pkt->_err != 0) {
    syslog(3,"SysCfg.c",132,0,"%s: SysCfgConnProcessEvent: packet error - %s\n",user,
           IRFmtError((unsigned int)pkt->_err));
    return -1;
  }
  if (pkt->_argv[0]._clas & 7)
    IRArg(pkt,0);               /* (the original fetched it and did not look) */
  rev = (pkt->_argv[1]._clas & 7) == 0 ? (int)pkt->_argv[1]._val : (int)IRArg(pkt,1);
  cptr = (pkt->_argv[2]._clas & 7) == 0 ? (char *)IR_VAL_PTR(pkt->_argv[2]._val)
                                        : (char *)IRArg(pkt,2);
  if (rev > SYSCFG_REV) {
    syslog(3,"SysCfg.c",160,0,
           "%s: SysCfgConnProcessEvent: revision mismatch, L3 client is older that L2 server\n",
           user);
    return -1;
  }
  if (rev == SYSCFG_REV) {
    if (cptr == NULL)
      return 0;
    if (*query != NULL) {
      if (strcmp(*query,cptr) == 0)
        return 0;               /* unchanged */
      free(*query);
    }
    *query = strdup(cptr);
  }

  L2CfgMCfgL2(l2,pkt);
  *l1cnt = 0;
  *l2cnt = 0;
  /* (the original did not bound the lists) */
  for (; l2 != NULL && *l2cnt < SYSCFG_L2_MAX - 1; l2 = (L2Cfg *)l2->net.next) {
    l2list[(*l2cnt)++] = l2;
    for (p = 0; p < L2CFG_PORTS; p++) {
      port = &l2->port_list[p];
      if (port->state != L2CFG_PORT_CONFIGURED)
        continue;
      for (l1 = 0; l1 < port->l1count; l1++) {
        if (port->l1cfg[l1].configured && !listed_l1(l1list,*l1cnt,&port->l1cfg[l1]) &&
            *l1cnt < SYSCFG_L1_MAX - 1)
          l1list[(*l1cnt)++] = &port->l1cfg[l1];
      }
    }
  }
  l1list[*l1cnt] = NULL;
  l2list[*l2cnt] = NULL;
  return 0;
}

/* "001.05.1   BSN: ... SSN: ..." for each L1, to fd */
void SysCfgConnPrintL1(sn1SCConn *conn, int fd)
{
  L2CfgL1 **l1 = conn == NULL ? SysCfgL1List : conn->SysCfgL1List;
  char part[16];
  char buff[256];

  for (; *l1 != NULL; l1++) {
    if ((*l1)->partition == 0)
      strcpy(part,"    ");
    else
      sprintf(part,".%-3d",(unsigned int)(*l1)->partition);
    snprintf(buff,sizeof(buff),"%03d.%02d%s BSN: %s SSN: %s\n",(unsigned int)(*l1)->rack,
             (unsigned int)(*l1)->slot,part,
             (*l1)->brick_sn[0] != '\0' ? (*l1)->brick_sn : "unknown",
             (*l1)->system_sn[0] != '\0' ? (*l1)->system_sn : "unknown");
    write(fd,buff,strlen(buff));
  }
}

/* "Rack n IP: a.b.c.d SSN: ..." for each L2, to fd */
void SysCfgConnPrintL2(sn1SCConn *conn, int fd)
{
  L2Cfg **l2 = conn == NULL ? SysCfgL2List : conn->SysCfgL2List;
  char buff[256];

  for (; *l2 != NULL; l2++) {
    snprintf(buff,sizeof(buff),"Rack %-6d IP: %-15s SSN: %s\n",(*l2)->rack,
             SocketAddrStr((*l2)->net.ip_addr),(*l2)->ssn[0] != '\0' ? (*l2)->ssn : "unknown");
    write(fd,buff,strlen(buff));
  }
}

char *SysCfgConnAddrStr(sn1SCConn *conn, IRAddress addr, int verbose)
{
  return L2CfgMAddrStr(conn == NULL ? SysCfgFull : &conn->SysCfgFull,addr,verbose);
}

/* the system console of a partition */
IRAddress SysCfgConsole(sn1SCConn *conn, int partition)
{
  return L2CfgMGetConsole(conn == NULL ? SysCfgFull : &conn->SysCfgFull,partition);
}
