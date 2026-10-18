/*
 * sys_ctrl/l3/api/SCapiL2.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapiL2.c
 */

#include <unistd.h>
#include "SCapiL2.h"   /* needed by the reconstruction */
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
#include <stdint.h>
#include <netinet/if_ether.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include "SCapi.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/sys/syslog.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static char **find_interfaces(uint32 **addrlist_ptr);

static uint32 *addrlist;

int sn1SCDiscoverL2(char *dev, char *client_info, sn1SC_L2 **l2_return_list, int *l2_cnt, int wait)
{
  int iVar1;
  sn1SC_L2 *nl2;
  int l2;
  sn1SC_L2 l2ent;
  uint32 *aptr;
  int l2_local;
  int l2_list_size;
  sn1SC_L2 *l2_list;
  int i;
  int sd;
  int rval;
  bool local;
  
  sd = -1;
  l2_local = 0;
  *l2_cnt = 0;
  l2_list_size = 10;
  l2_list = malloc(10 * sizeof(sn1SC_L2));
  if (l2_list == NULL) {
    iVar1 = -1;
  }
  else {
    *l2_return_list = l2_list;
    for (i = 0; i < 2; i = i + 1) {
      sd = sn1SCDiscoverL2Start(sd,dev,client_info);
      if (sd < 0) {
        return -1;
      }
      while ((rval = sn1SCDiscoverL2Response(sd,&l2ent,wait), -1 < rval && (rval != 1))) {
        local = false;
        aptr = addrlist;
        while( true ) {
          if ((aptr == NULL) || (*aptr == 0)) goto LAB_08070f46;
          if (*aptr == l2ent.ip_addr) break;
          aptr = aptr + 1;
        }
        local = true;
LAB_08070f46:
        if (local) {
          l2 = find_l2_slot(&l2ent,l2_list,0,l2_local);
        }
        else {
          l2 = find_l2_slot(&l2ent,l2_list,l2_local,*l2_cnt);
        }
        if (l2 != -1) {
          if (l2 < *l2_cnt) {
            memmove(l2_list + l2 + 1,l2_list + l2,(*l2_cnt - l2) * 0x124);
          }
          memcpy(l2_list + l2,&l2ent,0x124);
          if (local) {
            l2_local = l2_local + 1;
          }
          *l2_cnt = *l2_cnt + 1;
          if (*l2_cnt == l2_list_size) {
            l2_list_size = l2_list_size + 10;
            l2_list = realloc(l2_list, l2_list_size * sizeof(sn1SC_L2));
            if (l2_list == NULL) {
              return -1;
            }
            *l2_return_list = l2_list;
          }
        }
      }
    }
    sn1SCDiscoverL2Done(sd);
    if (rval < 0) {
      iVar1 = -1;
    }
    else {
      iVar1 = 0;
    }
  }
  return iVar1;
}

int sn1SCDiscoverL2Start(int sd, char *dev, char *client_info)
{
  uint32 uVar1;
  bool bVar2;
  int *piVar3;
  char *pcVar4;
  int iVar5;
  size_t __n;
  int status;
  struct sockaddr_in *__addr;
  socklen_t __addr_len;
  char *istr;
  int icmd;
  struct sockaddr_in *p;
  struct ifreq ifr;
  int retry;
  uint8 pkt [8192];
  struct sockaddr_in cliaddr;
  struct sockaddr_in myaddr;
  uint8 broadcast_addr [4];
  int o;
  char **nlptr;
  char **namelist;
  char *dflt_namelist [2];
  uint32_t temp_3f98bd2185;
  
  dflt_namelist[0] = "eth0";
  dflt_namelist[1] = NULL;
  namelist = dflt_namelist;
  o = 1;
  if ((dev == NULL) || (*dev == '\0')) {
    namelist = find_interfaces(&addrlist);
    if (namelist == NULL) {
      return -1;
    }
  }
  else {
    dflt_namelist[0] = dev;
  }
  if (sd == -1) {
    sd = socket(2,2,0x11);
    if (sd < 0) {
      piVar3 = __errno_location();
      iVar5 = *piVar3;
      piVar3 = __errno_location();
      pcVar4 = strerror(*piVar3);
      syslog(3,"SCapiL2.c",0xd2,0,"sn1SCDiscoverL2Start: socket: %s [%d]\n",pcVar4,iVar5);
      close(sd);
      return -1;
    }
    iVar5 = setsockopt(sd,1,6,&o,4);
    if (iVar5 < 0) {
      piVar3 = __errno_location();
      iVar5 = *piVar3;
      piVar3 = __errno_location();
      pcVar4 = strerror(*piVar3);
      syslog(3,"SCapiL2.c",0xd9,0,"sn1SCDiscoverL2Start: setsockopt: %s [%d]\n",pcVar4,iVar5);
      close(sd);
      return -1;
    }
    myaddr.sin_family = 2;
    myaddr.sin_port = 0;
    myaddr.sin_addr.s_addr = 0;
    memset(myaddr.sin_zero,0,8);
    iVar5 = bind(sd,(struct sockaddr *)&myaddr,0x10);
    if (iVar5 < 0) {
      piVar3 = __errno_location();
      iVar5 = *piVar3;
      piVar3 = __errno_location();
      pcVar4 = strerror(*piVar3);
      syslog(3,"SCapiL2.c",0xe8,0,"sn1SCDiscoverL2Start: server bind: %s [%d]\n",pcVar4,iVar5);
      close(sd);
      return -1;
    }
  }
  nlptr = namelist;
  do {
    if (*nlptr == NULL) {
      return sd;
    }
    memset(&ifr,0,sizeof(struct ifreq));
    strcpy((char *)&ifr,*nlptr);
    strcpy((char *)&ifr,*nlptr);
                    /* WARNING: Ignoring partial resolution of indirect */
    ifr.ifr_ifru.ifru_addr.sa_family = 2;
    ioctl(sd,0x8915,&ifr);
    iVar5 = ioctl(sd,0x8915,&ifr);
    if (iVar5 < 0) {
      piVar3 = __errno_location();
      iVar5 = *piVar3;
      piVar3 = __errno_location();
      pcVar4 = strerror(*piVar3);
      syslog(3,"SCapiL2.c",0x106,0,"sn1SCDiscoverL2Start: ioctl %s SIOCGIFADDR: %s [%d]\n",*nlptr,
             pcVar4,iVar5);
      close(sd);
      return -1;
    }
    strcpy((char *)&ifr,*nlptr);
                    /* WARNING: Ignoring partial resolution of indirect */
    ifr.ifr_ifru.ifru_addr.sa_family = 2;
    iVar5 = ioctl(sd,0x8913,&ifr);
    if (iVar5 < 0) {
      piVar3 = __errno_location();
      iVar5 = *piVar3;
      piVar3 = __errno_location();
      pcVar4 = strerror(*piVar3);
      syslog(3,"SCapiL2.c",0x110,0,"l2find find_if: ioctl %s SIOCGIFFLAGS: %s [%d]\n",*nlptr,pcVar4,
             iVar5);
      close(sd);
      return -1;
    }
    if ((ifr.ifr_flags & 0x10) == 0) {
      icmd = 0x8919;
      istr = "SIOCGIFBRDADDR";
    }
    else {
      icmd = 0x8917;
      istr = "SIOCGIFDSTADDR";
    }
    strcpy((char *)&ifr,*nlptr);
                    /* WARNING: Ignoring partial resolution of indirect */
    ifr.ifr_ifru.ifru_addr.sa_family = 2;
    iVar5 = ioctl(sd,icmd,&ifr);
    temp_3f98bd2185 = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    if (iVar5 < 0) {
      piVar3 = __errno_location();
      iVar5 = *piVar3;
      piVar3 = __errno_location();
      pcVar4 = strerror(*piVar3);
      syslog(3,"SCapiL2.c",0x122,0,"sn1SCDiscoverL2Start: ioctl %s %s: %s [%d]\n",*nlptr,istr,pcVar4
             ,iVar5);
    }
    else {
      uVar1 = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
      cliaddr.sin_family = 2;
      cliaddr.sin_port = htons((short)IR_PORT_BIAS + 10000);
      cliaddr.sin_addr.s_addr = uVar1;
      if ((client_info == NULL) || (*client_info == '\0')) {
        pkt[0] = '\0';
      }
      else {
        strcpy((char *)pkt,client_info);
      }
      retry = 0;
      do {
        __addr_len = 0x10;
        __addr = &cliaddr;
        iVar5 = 0;
        __n = strlen((char *)pkt);
        status = sendto(sd,pkt,__n,iVar5,(struct sockaddr *)__addr,__addr_len);
        if (((cliaddr.sin_addr.s_addr != temp_3f98bd2185) || (-1 < status)) ||
           ((piVar3 = __errno_location(), *piVar3 != 0x71 &&
            (piVar3 = __errno_location(), *piVar3 != 0x6f)))) break;
        bVar2 = retry < 10;
        retry = retry + 1;
      } while (bVar2);
      if (status < 0) {
        piVar3 = __errno_location();
        iVar5 = *piVar3;
        piVar3 = __errno_location();
        pcVar4 = strerror(*piVar3);
        syslog(4,"SCapiL2.c",0x14b,0,"sn1SCDiscoverL2Start: sendto %s: %s [%d]\n",*nlptr,pcVar4,
               iVar5);
      }
    }
    nlptr = nlptr + 1;
  } while( true );
}

int sn1SCDiscoverL2Response(int sd, sn1SC_L2 *l2, int wait)
{
  unsigned char *pbVar1;
  int iVar2;
  int *piVar3;
  char *ccptr;
  ssize_t sVar4;
  char *pcVar5;
  char *pcVar6;
  char *pcVar7;
  int status;
  int __d1;
  char __result;
  int __d0;
  char *vptr;
  char *aptr;
  char *avptr;
  char *cptr;
  uint8 pkt [8192];
  fd_set rfd;
  struct timeval maxwait;
  int asize;
  struct sockaddr_in cliaddr;
  bool response_valid;
  
  asize = 0x10;
  maxwait.tv_usec = 0;
  response_valid = false;
  cliaddr.sin_family = 2;
  cliaddr.sin_port = 0;
  cliaddr.sin_addr.s_addr = 0;
  while( true ) {
    if (response_valid) {
      return 0;
    }
    maxwait.tv_sec = wait;
    FD_ZERO(&rfd);
    FD_SET(sd, &rfd);
    iVar2 = select(sd + 1,(fd_set *)&rfd,NULL,NULL,wait == 0 ? NULL : &maxwait);
    if (iVar2 < 0) {
      piVar3 = __errno_location();
      iVar2 = *piVar3;
      piVar3 = __errno_location();
      ccptr = strerror(*piVar3);
      syslog(3,"SCapiL2.c",0x180,0,"sn1SCDiscoverL2Response: select: %s [%d]\n",ccptr,iVar2);
      return -1;
    }
    cliaddr.sin_family = 2;
    if (FD_ISSET(sd, &rfd) == 0) {
      return 1;
    }
    sVar4 = recvfrom(sd,pkt,0x2000,0,(struct sockaddr *)&cliaddr,(socklen_t *)&asize);
    if (sVar4 < 0) break;
    pkt[sVar4] = '\0';
    memset(l2,0,0x124);
    l2->ip_addr = cliaddr.sin_addr.s_addr;
    strncpy(l2->raw,(char *)pkt,199);
    pcVar5 = strdup((char *)pkt);
    cptr = pcVar5;
    while ((pcVar7 = cptr, cptr != NULL && (*cptr != '\0'))) {
      pcVar6 = strchr(cptr,0x2c);
      if (pcVar6 == NULL) {
        cptr = NULL;
      }
      else {
        *pcVar6 = '\0';
        cptr = pcVar6 + 1;
      }
      pcVar7 = strtok(pcVar7,":");
      vptr = strtok(NULL,":");
      if (vptr == NULL) {
        vptr = "";
      }
      iVar2 = strcmp(pcVar7,"version");
      if (iVar2 == 0) {
        response_valid = true;
        strncpy(l2->version,vptr,0x13);
      }
      else {
        iVar2 = strcmp(pcVar7,"ssn");
        if (iVar2 == 0) {
          response_valid = true;
          strncpy(l2->ssn,vptr,0x13);
        }
        else {
          iVar2 = strcmp(pcVar7,"name");
          if (iVar2 == 0) {
            response_valid = true;
            strncpy(l2->sysname,vptr,0x1f);
          }
          else {
            iVar2 = strcmp(pcVar7,"rack");
            if (iVar2 == 0) {
              response_valid = true;
              iVar2 = atoi(vptr);
              l2->rack = iVar2;
            }
            else {
              iVar2 = strcmp(pcVar7,"l2pri");
              if (iVar2 == 0) {
                response_valid = true;
                l2->ms = 2;
                sscanf(vptr,"%d",&l2->group);
              }
              else {
                iVar2 = strcmp(pcVar7,"l2sec");
                if (iVar2 == 0) {
                  response_valid = true;
                  l2->ms = 1;
                  sscanf(vptr,"%d",&l2->group);
                }
              }
            }
          }
        }
      }
    }
    free(pcVar5);
  }
  piVar3 = __errno_location();
  if (*piVar3 == 0xb) {
    return 1;
  }
  piVar3 = __errno_location();
  iVar2 = *piVar3;
  piVar3 = __errno_location();
  pcVar5 = strerror(*piVar3);
  syslog(3,"SCapiL2.c",0x194,0,"l2find: recvfrom: %s [%d]\n",pcVar5,iVar2);
  return -1;
}

int sn1SCDiscoverL2Done(int sd)
{
  close(sd);
  return 0;
}

int find_l2_slot(sn1SC_L2 *l2ent, sn1SC_L2 *l2_list, int beg, int end)
{
  int iVar1;
  uint32_t uVar2;
  int l2;
  
  l2 = beg;
  do {
    if (end <= l2) {
      return l2;
    }
    iVar1 = strcmp(l2ent->sysname,l2_list[l2].sysname);
    if (iVar1 < 0) {
      return l2;
    }
    iVar1 = strcmp(l2ent->sysname,l2_list[l2].sysname);
    if (iVar1 == 0) {
      if (l2ent->ip_addr == l2_list[l2].ip_addr) {
        return -1;
      }
      if (l2ent->rack != 0) {
        if (l2_list[l2].rack < l2ent->rack) goto LAB_08072050;
        if (l2ent->rack < l2_list[l2].rack) {
          return l2;
        }
      }
      uVar2 = ntohl(l2ent->ip_addr);
      if (uVar2 == 0x7f000001) {
        return l2;
      }
      if (l2ent->ip_addr <= l2_list[l2].ip_addr) {
        return l2;
      }
    }
LAB_08072050:
    l2 = l2 + 1;
  } while( true );
}

static char **find_interfaces(uint32 **addrlist_ptr)
{
  static char *namelist[20];
  static uint32 addrlist[20];
  static struct ifreq ifrbuf[50];
  int sd;
  int *piVar1;
  char *pcVar2;
  char **ppcVar3;
  int status;
  int iVar4;
  char *s;
  struct ifreq ifr;
  struct sockaddr_in *p;
  struct ifreq *ifp_;
  uint32 *altmp;
  char **nltmp;
  int j;
  uint32 lb_addr;
  struct ifreq *ifp;
  struct ifconf ic;
  int i;
  char **nlptr;
  
  inet_addr("127.0.0.1");
  if (addrlist_ptr != NULL) {
    *addrlist_ptr = NULL;
  }
  sd = socket(2,2,0x11);
  if (sd < 0) {
    piVar1 = __errno_location();
    iVar4 = *piVar1;
    piVar1 = __errno_location();
    pcVar2 = strerror(*piVar1);
    syslog(3,"SCapiL2.c",0x226,0,"l2find find_if: socket: %s [%d]\n",pcVar2,iVar4);
    ppcVar3 = NULL;
  }
  else {
    ic.ifc_len = sizeof(ifrbuf);
    ic.ifc_ifcu.ifcu_buf = (char *)ifrbuf;
    status = ioctl(sd,0x8912,&ic);
    if (status < 0) {
      piVar1 = __errno_location();
      iVar4 = *piVar1;
      piVar1 = __errno_location();
      pcVar2 = strerror(*piVar1);
      syslog(3,"SCapiL2.c",0x22e,0,"l2find find_if: ioctl SIOCGIFCONF: %s [%d]\n",pcVar2,iVar4);
      ppcVar3 = NULL;
    }
    else {
      for (nlptr = (char **)&namelist; *nlptr != NULL; nlptr = nlptr + 1) {
        free(*nlptr);
        *nlptr = NULL;
      }
      memset(addrlist,0,sizeof(addrlist));
      for (i = 0; i < ic.ifc_len; i = i + sizeof(struct ifreq)) {
        pcVar2 = ic.ifc_ifcu.ifcu_buf + i;
        p = (struct sockaddr_in *)&((struct ifreq *)pcVar2)->ifr_addr;
        iVar4 = strncmp(pcVar2,"dummy",5);
        if (iVar4 != 0) {
          nltmp = (char **)&namelist;
          altmp = addrlist;
          while ((*nltmp != NULL && (iVar4 = strcmp(*nltmp,pcVar2), iVar4 != 0))) {
            nltmp = nltmp + 1;
            altmp = altmp + 1;
          }
          if (*nltmp == NULL) {
            strcpy((char *)&ifr,pcVar2);
            iVar4 = ioctl(sd,0x8913,&ifr);
            if (iVar4 < 0) {
              piVar1 = __errno_location();
              iVar4 = *piVar1;
              piVar1 = __errno_location();
              pcVar2 = strerror(*piVar1);
              syslog(3,"SCapiL2.c",0x259,0,"l2find find_if: ioctl SIOCGIFFLAGS: %s [%d]\n",pcVar2,
                     iVar4);
              return NULL;
            }
            if ((ifr.ifr_flags & 1) != 0) {
              if ((ifr.ifr_flags & 0x10) != 0) {
                strcpy((char *)&ifr,pcVar2);
                iVar4 = ioctl(sd,0x8917,&ifr);
                if (iVar4 < 0) {
                  piVar1 = __errno_location();
                  iVar4 = *piVar1;
                  piVar1 = __errno_location();
                  pcVar2 = strerror(*piVar1);
                  syslog(3,"SCapiL2.c",0x26e,0,"l2find find_if: ioctl SIOCGIFDSTADDR: %s [%d]\n",
                         pcVar2,iVar4);
                  return NULL;
                }
                p = (struct sockaddr_in *)&ifr.ifr_ifru;
              }
              pcVar2 = strdup(pcVar2);
              *nltmp = pcVar2;
              *altmp = (p->sin_addr).s_addr;
            }
          }
        }
      }
      close(sd);
      *addrlist_ptr = addrlist;
      ppcVar3 = (char **)&namelist;
    }
  }
  return ppcVar3;
}
