/*
 * sys_ctrl/l3/main/SysCfg.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/main/SysCfg.c
 */

#include "../../common/Router/Socket.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include "../../common/sys/syslog.h"
#include <string.h>
#include <stddef.h>
#include "../api/SCapi.h"
#include "../IRouter/IRouterL3.h"
#include "../../common/Router/Router.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/sysutils.h"
#include <pthread.h>
#include <errno.h>
#include "../../common/sys/Logger.h"
#include "../sys/LoggerMsg.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../IRouter/IRouterOS.h"
#include "../api/SCapiConn.h"
#include "../../common/main/L1Cfg.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/sys/brick_types.h"
#include "SysCfg.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

SysCfgL2 *SysCfgFull = &L2CfgLocal;
int SysCfgL1Count;
int SysCfgL2Count;
SysCfgL1 *SysCfgL1List[1024];
SysCfgL2 *SysCfgL2List[128];
static char *SysCfgQuery;

void SysCfgConnInit(sn1SCConn *conn, char *user)
{
  IRClient *pIVar1;
  char *pcVar2;
  int iVar3;
  IRPacket *pkt;
  IRAddress addr;
  IRArgument av [3];
  int rval;
  int serial;
  
  if (((conn == NULL) && (pIVar1 = sn1SCClient(), pIVar1 == NULL)) ||
     ((conn != NULL && (pIVar1 = sn1SCConnClient(conn), pIVar1 == NULL)))) {
    syslog(3,"SysCfg.c",0x26,0,"%s: SysCfgConnInit: no connection to system controller network!\n",
           user);
  }
  else {
    if (conn == NULL) {
      pIVar1 = sn1SCClient();
      L2CfgMInitL3(&L2CfgLocal,pIVar1);
    }
    else {
      pIVar1 = sn1SCConnClient(conn);
      L2CfgMInitL3(&conn->SysCfgFull,pIVar1);
    }
    addr = 0x1ffff004;
    av[0]._clas = '\0';
    av[0]._frame = '\0';
    av[0]._val = 0;
    av[0]._size = 0;
    if (conn == NULL) {
      rval = sn1SCCmd(&addr,0,1,av,&pkt,0x1e);
    }
    else {
      rval = sn1SCConnCmd(conn,&addr,0,1,av,&pkt,0x1e);
    }
    if (rval == 0) {
      iVar3 = SysCfgConnProcessEvent(conn,user,pkt);
      if (iVar3 < 0) {
        syslog(3,"SysCfg.c",0x59,0,"%s: SysCfgConnInit: error updating System Configuration!\n",user
              );
      }
    }
    else {
      pcVar2 = LoggerDefaultMessage(rval);
      syslog(3,"SysCfg.c",0x3a,0,"%s: config command failed: %s\n",user,pcVar2);
    }
  }
  return;
}

void SysCfgConnRequest(sn1SCConn *conn, char *user)
{
  int rval;
  char *pcVar1;
  int msgnbr;
  IRAddress addr;
  IRArgument av [2];
  
  addr = 0x1ffff004;
  av[0]._clas = '\0';
  av[0]._frame = '\0';
  av[0]._val = 0;
  av[0]._size = 0;
  if ((conn == NULL) && (rval = sn1SCReq(&addr,0,1,av,NULL), rval != 0)) {
    pcVar1 = LoggerDefaultMessage(rval);
    syslog(3,"SysCfg.c",0x68,0,"%s: config request failed: %s\n",user,pcVar1);
    return;
  }
  if ((conn != NULL) &&
     (msgnbr = sn1SCConnReq(conn,&addr,0,1,av,NULL), msgnbr != 0)) {
    pcVar1 = LoggerDefaultMessage(msgnbr);
    syslog(3,"SysCfg.c",0x6b,0,"%s: config request failed: %s\n",user,pcVar1);
  }
  return;
}

int SysCfgConnProcessEvent(sn1SCConn *conn, char *user, IRPacket *pkt)
{
  char **query;
  int *l1cnt;
  int *l2cnt;
  L2CfgL1 **l1list;
  L2Cfg **l2list;
  char *pcVar1;
  int rev;
  char *cptr;
  int iVar2;
  L2CfgL1 *l1cfg;
  int s;
  int l1;
  int port;
  L2Cfg *cfghead;
  int err;
  int status;
  L2Cfg *l2;
  
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
    l2 = &conn->SysCfgFull;
    l1cnt = &conn->SysCfgL1Count;
    l2cnt = &conn->SysCfgL2Count;
    l1list = conn->SysCfgL1List;
    l2list = conn->SysCfgL2List;
  }
  if (pkt->_err != 0) {
    pcVar1 = IRFmtError((uint)pkt->_err);
    syslog(3,"SysCfg.c",0x84,0,"%s: SysCfgConnProcessEvent: packet error - %s\n",user,pcVar1);
    return -1;
  }
  if ((pkt->_argv[0]._clas & 7) != 0) {
    IRArg(pkt,0);
  }
  if (((uint)pkt[1]._next_frame & 7) == 0) {
    rev = *(int *)&pkt[1].field_0x4;
  }
  else {
    rev = IRArg(pkt,1);
  }
  if (((uint)pkt[1]._arg_data & 7) == 0) {
    cptr = (char *)pkt[1]._client_data;
  }
  else {
    cptr = (char *)IRArg(pkt,2);
  }
  if (1 < rev) {
    if (2 < rev) {
      syslog(3,"SysCfg.c",0xa0,0,
             "%s: SysCfgConnProcessEvent: revision mismatch, L3 client is older that L2 server\n",
             user);
      return -1;
    }
    if ((uint8 *)cptr == NULL) {
      return 0;
    }
    if (*query != NULL) {
      iVar2 = strcmp(*query,cptr);
      if (iVar2 == 0) {
        return 0;
      }
      free(*query);
    }
    pcVar1 = strdup(cptr);
    *query = pcVar1;
  }
  L2CfgMCfgL2(l2,pkt);
  *l1cnt = 0;
  *l2cnt = 0;
  for (; l2 != NULL; l2 = (L2Cfg *)(l2->net).next) {
    l2list[*l2cnt] = l2;
    *l2cnt = *l2cnt + 1;
    for (port = 0; port < 0x28; port = port + 1) {
      if ((l2->port_list[port].state != 0) && (l2->port_list[port].state == 2)) {
        for (l1 = 0; l1 < l2->port_list[port].l1count; l1 = l1 + 1) {
          if (l2->port_list[port].l1cfg[l1].configured != '\0') {
            l1cfg = l2->port_list[port].l1cfg + l1;
            s = 0;
            while ((s < *l1cnt &&
                   (((l1list[s]->rack != l1cfg->rack || (l1list[s]->slot != l1cfg->slot)) ||
                    (l1list[s]->type != l1cfg->type))))) {
              s = s + 1;
            }
            if (*l1cnt <= s) {
              l1list[*l1cnt] = l1cfg;
              *l1cnt = *l1cnt + 1;
            }
          }
        }
      }
    }
  }
  l1list[*l1cnt] = NULL;
  l2list[*l2cnt] = NULL;
  return 0;
}

void SysCfgConnPrintL1(sn1SCConn *conn, int fd)
{
  size_t sVar1;
  char *pcVar2;
  char *pcVar3;
  L2CfgL1 **l1;
  char part [16];
  char buff [256];
  
  if (conn == NULL) {
    l1 = SysCfgL1List;
  }
  else {
    l1 = conn->SysCfgL1List;
  }
  for (; *l1 != NULL; l1 = l1 + 1) {
    if ((*l1)->partition == '\0') {
      strcpy(part,"    ");
    }
    else {
      sprintf(part,".%-3d",(uint)(*l1)->partition);
    }
    sVar1 = strlen((*l1)->system_sn);
    if (sVar1 == 0) {
      pcVar2 = "unknown";
    }
    else {
      pcVar2 = (*l1)->system_sn;
    }
    sVar1 = strlen((*l1)->brick_sn);
    if (sVar1 == 0) {
      pcVar3 = "unknown";
    }
    else {
      pcVar3 = (*l1)->brick_sn;
    }
    sprintf(buff,"%03d.%02d%s BSN: %s SSN: %s\n",(uint)(*l1)->rack,(uint)(*l1)->slot,part,pcVar3,
            pcVar2);
    sVar1 = strlen(buff);
    write(fd,buff,sVar1);
  }
  return;
}

void SysCfgConnPrintL2(sn1SCConn *conn, int fd)
{
  char *pcVar1;
  char *pcVar2;
  size_t __n;
  L2Cfg **l2;
  char buff [256];
  
  if (conn == NULL) {
    l2 = SysCfgL2List;
  }
  else {
    l2 = conn->SysCfgL2List;
  }
  for (; *l2 != NULL; l2 = l2 + 1) {
    if ((*l2)->ssn[0] == '\0') {
      pcVar1 = "unknown";
    }
    else {
      pcVar1 = (*l2)->ssn;
    }
    pcVar2 = SocketAddrStr(((*l2)->net).ip_addr);
    sprintf(buff,"Rack %-6d IP: %-15s SSN: %s\n",(*l2)->rack,pcVar2,pcVar1);
    __n = strlen(buff);
    write(fd,buff,__n);
  }
  return;
}

char *SysCfgConnAddrStr(sn1SCConn *conn, IRAddress addr, int verbose)
{
  L2Cfg *cfghead;
  char *pcVar1;
  
  cfghead = SysCfgFull;
  if (conn != NULL) {
    cfghead = &conn->SysCfgFull;
  }
  pcVar1 = L2CfgMAddrStr(cfghead,addr,verbose);
  return pcVar1;
}

IRAddress SysCfgConsole(sn1SCConn *conn, int partition)
{
  SysCfgL2 *head;
  IRAddress IVar1;
  
  head = SysCfgFull;
  if (conn != NULL) {
    head = &conn->SysCfgFull;
  }
  IVar1 = L2CfgMGetConsole(head,partition);
  return IVar1;
}
