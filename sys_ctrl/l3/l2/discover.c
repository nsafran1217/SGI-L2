/*
 * sys_ctrl/l3/l2/discover.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/discover.c
 */

#include "discover.h"   /* needed by the reconstruction */
#include "smp.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <sys/socket.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "../../common/sys/syslog.h"
#include "../../common/sys/sysctl_types.h"
#include "../main/nvram.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/IRouter/IRouter.h"
#include "cfg.h"
#include "l2.h"
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <getopt.h>
#include "../../common/Router/Socket.h"
#include "../../common/Router/Event.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../../common/sys/PPP.h"
#include "../../common/main/EnetServer.h"
#include "l2_rev.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int discover_debug;
char version_attr[30];
char client_id[30];
int discover_sd;
static char haystack[2048];

int discover_init(void)
{
  int status;
  __pid_t _Var1;
  char *pcVar2;
  int iVar3;
  char *ver;
  ulong discover_ip;
  char *name;
  int o;
  int i;
  int addrlen;
  struct sockaddr_in *p;
  struct ifreq ifr;
  struct sockaddr_in myaddr;
  
  p = (struct sockaddr_in *)&ifr.ifr_ifru;
  addrlen = 0x10;
  o = 1;
  name = "eth0";
  status = SocketGetHostAddr(&discover_ip);
  if (status == 0) {
    _Var1 = getpid();
    pcVar2 = inet_ntoa((in_addr)discover_ip);
    sprintf(client_id,"%s.%d",pcVar2,_Var1);
    memset(&ifr,0,0x20);
    strcpy((char *)&ifr,name);
    discover_sd = socket(2,2,0x11);
    if (discover_sd < 0) {
      syslog(3,"discover.c",0x90,0,"discover_init: socket: %m\n");
      iVar3 = -1;
    }
    else {
      iVar3 = setsockopt(discover_sd,1,6,&o,4);
      if (iVar3 < 0) {
        syslog(3,"discover.c",0x96,0,"discover_init: setsockopt: %m\n");
        close(discover_sd);
        iVar3 = -1;
      }
      else {
        myaddr.sin_family = 2;
        myaddr.sin_port = htons((short)IR_PORT_BIAS + 10000);
        myaddr.sin_addr.s_addr = 0;
        memset(myaddr.sin_zero,0,8);
        iVar3 = bind(discover_sd,(struct sockaddr *)&myaddr,0x10);
        if (iVar3 < 0) {
          syslog(3,"discover.c",0xb0,0,"discover_init: server bind: %m\n");
          close(discover_sd);
          iVar3 = -1;
        }
        else {
          pcVar2 = l2_firmware_version();
          if (*pcVar2 == '\0') {
            pcVar2 = "INVALID";
          }
          sprintf(version_attr,"version:%s (SW),",pcVar2);
          EventAddInput(discover_sd,discover_service,(EventData)0x0,"discover_init");
          iVar3 = discover_sd;
        }
      }
    }
  }
  else {
    syslog(2,"discover.c",0x7f,0,"discover_init: couldn\'t get IP address for local host\n");
    iVar3 = -1;
  }
  return iVar3;
}

void discover_response(void *cd, int sd)
{
  static int errcnt;
  int status;
  int *piVar1;
  char *src;
  char *pcVar2;
  char *pcVar3;
  uint32 uVar4;
  char *pcVar5;
  size_t sVar6;
  ssize_t sVar7;
  uint32_t uVar8;
  L2CfgNode *l2node;
  int iVar9;
  undefined **ppuVar10;
  char **ppcVar11;
  struct sockaddr_in *__addr;
  socklen_t __addr_len;
  char msg [128];
  int ip;
  int nips;
  char *ips [18];
  int debug;
  char *vptr;
  char *aptr;
  char *avptr;
  char *ccptr;
  char *cptr;
  int asize;
  int retry;
  int first;
  int i;
  char *optr;
  uint8 outpkt [8192];
  uint8 inpkt [8192];
  struct sockaddr_in cliaddr;
  bool from_l2;
  bool from_master;
  bool match;
  bool ssn_matched;
  
  asize = 0x10;
  ssn_matched = false;
  from_l2 = false;
  from_master = false;
  debug = 0;
  cliaddr.sin_family = 2;
  cliaddr.sin_port = htons((short)IR_PORT_BIAS + 10000);
  cliaddr.sin_addr.s_addr = 0;
  status = recvfrom(sd,inpkt,0x2000,0,(struct sockaddr *)&cliaddr,(socklen_t *)&asize);
  if (status < 0) {
    piVar1 = __errno_location();
    if (*piVar1 == 0x6f) {
      return;
    }
    piVar1 = __errno_location();
    if (*piVar1 == 0xb) {
      return;
    }
    syslog(3,"discover.c",0x10c,0,"discover_response: recvfrom: %m\n");
    iVar9 = errcnt;
    errcnt = errcnt + 1;
    if (iVar9 < 0xb) {
      return;
    }
    syslog(3,"discover.c",0x10e,0,"discover_response: too many RECV errors. Disabling");
    EventRemoveInput(sd);
    return;
  }
  errcnt = 0;
  inpkt[status] = '\0';
  if ((discover_debug & 0xc0000000U) == 0) {
    debug = discover_debug;
  }
  else {
    src = inet_ntoa((in_addr)cliaddr.sin_addr.s_addr);
    ppuVar10 = &PTR_s_128_162_241_129_0808c050;
    ppcVar11 = ips;
    for (iVar9 = 0x12; iVar9 != 0; iVar9 = iVar9 + -1) {
      *ppcVar11 = *ppuVar10;
      ppuVar10 = ppuVar10 + 1;
      ppcVar11 = ppcVar11 + 1;
    }
    match = false;
    for (ip = 0; (!match && (ip < 0x12)); ip = ip + 1) {
      iVar9 = strcmp(src,ips[ip]);
      if (iVar9 == 0) {
        match = true;
      }
    }
    if ((match) && ((discover_debug & 0x80000000U) != 0)) {
      debug = -1;
    }
    if ((match) && ((discover_debug & 0x40000000U) != 0)) {
      debug = -0x207;
    }
  }
  if ((debug & 2U) != 0) {
    fprintf(stderr,"received discover request: %s\n",inpkt);
  }
  pcVar2 = strdup((char *)inpkt);
  cptr = pcVar2;
  while ((pcVar5 = cptr, cptr != NULL && (*cptr != '\0'))) {
    pcVar3 = strchr(cptr,0x2c);
    if (pcVar3 == NULL) {
      cptr = NULL;
    }
    else {
      *pcVar3 = '\0';
      cptr = pcVar3 + 1;
    }
    pcVar5 = strtok(pcVar5,":");
    vptr = strtok(NULL,":");
    if (vptr == NULL) {
      vptr = "";
    }
    iVar9 = strcmp(pcVar5,"clientid");
    if (iVar9 == 0) {
      iVar9 = strcmp(client_id,vptr);
      if (iVar9 == 0) {
        if ((debug & 4U) != 0) {
          fprintf(stderr,"discover: client ID matches, not responding\n");
        }
        free(pcVar2);
        return;
      }
    }
    else {
      iVar9 = strcmp(pcVar5,"ssn");
      if (iVar9 == 0) {
        pcVar5 = (char *)nvramGet(3);
        iVar9 = strcmp(vptr,pcVar5);
        if (iVar9 != 0) {
          if ((debug & 8U) != 0) {
            fprintf(stderr,"discover: ssn doesn\'t match match, not responding\n");
          }
          free(pcVar2);
          return;
        }
        ssn_matched = true;
      }
      else {
        iVar9 = strcmp(pcVar5,"name");
        if (iVar9 == 0) {
          pcVar5 = (char *)nvramGet(4);
          iVar9 = strcmp(vptr,pcVar5);
          if (iVar9 != 0) {
            if ((debug & 0x10U) != 0) {
              fprintf(stderr,"discover: name doesn\'t match match, not responding\n");
            }
            free(pcVar2);
            return;
          }
        }
        else {
          iVar9 = strcmp(pcVar5,"l2");
          if (iVar9 == 0) {
            from_l2 = true;
            if (l2_discover == 0) {
              if ((debug & 0x20U) != 0) {
                fprintf(stderr,"discover: l2_discover is disabled, not responding\n");
              }
              free(pcVar2);
              return;
            }
          }
          else {
            iVar9 = strcmp(pcVar5,"l2pri");
            if (iVar9 == 0) {
              from_l2 = true;
              from_master = true;
              if (l2_discover == 0) {
                if ((debug & 0x20U) != 0) {
                  fprintf(stderr,"discover: l2_discover is disabled, not responding\n");
                }
                free(pcVar2);
                return;
              }
            }
          }
        }
      }
    }
  }
  free(pcVar2);
  if ((from_l2) && ((uVar4 = nvramGet(5), uVar4 != 0 && (!ssn_matched)))) {
    if ((debug & 0x80U) == 0) {
      return;
    }
    fprintf(stderr,"discover: multi system mode, but no SSN passed from client, not responding\n");
    return;
  }
  if (((from_l2) && (L2CfgLocal.net.msmode == 1)) && (!from_master)) {
    if ((debug & 0x100U) == 0) {
      return;
    }
    fprintf(stderr,"discover: master/slave mode, client not a master, not responding\n");
    return;
  }
  if ((L2CfgLocal.net.msmode == 1) && (from_master)) {
    L2CfgLocal.net.msip = cliaddr.sin_addr.s_addr;
  }
  if ((from_l2) && (L2CfgLocal.net.msmode == 2)) {
    pcVar2 = SocketAddrStr(cliaddr.sin_addr.s_addr);
    pcVar5 = strstr(haystack,pcVar2);
    if (pcVar5 == NULL) {
      sprintf(msg,"WARNING: primary L2 replying to non-primary-secondary L2 at %s\n",pcVar2);
      nvramLogInsert(msg);
      strcat(haystack,pcVar2);
      strcat(haystack,":");
    }
  }
  if (((from_l2) && (L2CfgLocal.net.msmode == 0)) && (from_master)) {
    pcVar2 = SocketAddrStr(cliaddr.sin_addr.s_addr);
    pcVar5 = strstr(haystack,pcVar2);
    if (pcVar5 == NULL) {
      sprintf(msg,"WARNING: non-primary-secondry L2 replying to primary L2 at %s\n",pcVar2);
      nvramLogInsert(msg);
      strcat(haystack,pcVar2);
      strcat(haystack,":");
    }
  }
  cliaddr.sin_family = 2;
  optr = (char *)outpkt;
  outpkt[0] = '\0';
  strcpy(optr,version_attr);
  sVar6 = strlen(optr);
  optr = optr + sVar6;
  pcVar2 = (char *)nvramGet(3);
  if (((pcVar2 != NULL) && (pcVar2 != (char *)0xffffffff)) && (*pcVar2 != '\0')) {
    sprintf(optr,"ssn:%s,",pcVar2);
    sVar6 = strlen(optr);
    optr = optr + sVar6;
  }
  pcVar2 = (char *)nvramGet(4);
  if (((pcVar2 != NULL) && (pcVar2 != (char *)0xffffffff)) && (*pcVar2 != '\0')) {
    sprintf(optr,"name:%s,",pcVar2);
    sVar6 = strlen(optr);
    optr = optr + sVar6;
  }
  sprintf(optr,"rack:%d,",L2CfgLocal.rack);
  sVar6 = strlen(optr);
  optr = optr + sVar6;
  if (L2CfgLocal.net.msmode == 1) {
    sprintf(optr,"l2sec:0");
  }
  else if ((L2CfgLocal.net.msmode != 0) && (L2CfgLocal.net.msmode == 2)) {
    sprintf(optr,"l2pri:0");
  }
  sVar6 = strlen(optr);
  optr = optr + sVar6;
  *optr = '\0';
  if ((debug & 0x200U) != 0) {
    fprintf(stderr,"sending discover response: %s\n",outpkt);
  }
  retry = 0;
  do {
    __addr_len = 0x10;
    __addr = &cliaddr;
    iVar9 = 0;
    sVar6 = strlen((char *)outpkt);
    sVar7 = sendto(sd,outpkt,sVar6 + 1,iVar9,(struct sockaddr *)__addr,__addr_len);
    uVar8 = htonl(0xffffffff);
    if (((cliaddr.sin_addr.s_addr != uVar8) || (-1 < sVar7)) ||
       ((piVar1 = __errno_location(), *piVar1 != 0x71 &&
        (piVar1 = __errno_location(), *piVar1 != 0x6f)))) break;
    iVar9 = retry + 1;
    from_l2 = retry < 10;
    retry = iVar9;
  } while (from_l2);
  if (sVar7 < 0) {
    syslog(3,"discover.c",0x24c,0,"discover_response: sendto: %m\n");
    iVar9 = retry;
    piVar1 = __errno_location();
    fprintf(stderr,"errno=%d retry=%d status=%d\n",*piVar1,iVar9,sVar7);
  }
  else if (((cfg_ping_sender_valid != 0) &&
           (l2node = L2CfgMFindNode(&L2CfgLocal,cliaddr.sin_addr.s_addr,0,NULL),
           l2node != NULL)) && (l2node->heartbeat != 0xffffffff)) {
    l2node->heartbeat = l2node->heartbeat + 1;
  }
  return;
}

void discover_service(void)
{
  byte *pbVar1;
  static struct timeval to;
  int iVar2;
  int __d1;
  char __result;
  int __d0;
  fd_set rfd;
  
  __d1 = (int)&rfd;
  for (iVar2 = 0x20; iVar2 != 0; iVar2 = iVar2 + -1) {
    *(undefined4 *)__d1 = 0;
    __d1 = __d1 + 4;
  }
  pbVar1 = (byte *)((int)rfd.fds_bits +
                   ((int)(discover_sd & 0x1fU) >> 3) + ((uint)discover_sd >> 5) * 4);
  *pbVar1 = *pbVar1 | '\x01' << (discover_sd & 7U);
  to.tv_sec = 0;
  to.tv_usec = 10;
  iVar2 = select(discover_sd + 1,(fd_set *)&rfd,NULL,NULL,(struct timeval *)0x80a26e0);
  if (iVar2 == 1) {
    if ((*(byte *)((int)rfd.fds_bits +
                  ((int)(discover_sd & 0x1fU) >> 3) + ((uint)discover_sd >> 5) * 4) >>
         (discover_sd & 7U) & 1) != 0) {
      discover_response(NULL,discover_sd);
    }
  }
  return;
}
