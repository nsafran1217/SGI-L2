/*
 * sys_ctrl/l3/api/SCapiL2.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapiL2.c
 *
 * L2 discovery (l2find, and tools started without an L2 host): a UDP
 * datagram (client_info, often empty) is broadcast to the discovery port on
 * each interface, and every L2 answers with "key:value,key:value,...":
 * version, ssn, name, rack, and l2pri or l2sec with its group. The list is
 * sorted by system name and then rack, address; L2s on this host come
 * first. (l3/l2/discover.c is the L2's side.)
 */

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include "SCapiL2.h"
#include "SCapi.h"
#include "../../common/IRouter/IRouter.h"
#include "../sys/syslogLib.h"

#define DISCOVER_PORT   10000   /* plus IR_PORT_BIAS */
#define DISCOVER_ROUNDS 2       /* broadcasts per discovery */
#define SEND_RETRIES    10
#define MAX_IFACES      20      /* find_interfaces()'s lists, NULL/0 ended */
#define MAX_IFCONF      50
#define L2_LIST_STEP    10

/* sn1SC_L2.ms */
#define L2_MS_SECONDARY 1
#define L2_MS_PRIMARY   2

static char **find_interfaces(uint32 **addrlist_ptr);

static uint32 *addrlist;        /* this host's addresses (find_interfaces()) */

/* is addr one of this host's? */
static int local_address(uint32 addr)
{
  uint32 *aptr;

  for (aptr = addrlist; aptr != NULL && *aptr != 0; aptr++)
    if (*aptr == addr)
      return 1;
  return 0;
}

/*
 * Discover the L2s on dev (every interface if NULL or ""), waiting wait
 * seconds for answers (forever if 0) in each of two rounds. *l2_return_list
 * (malloc()ed) gets *l2_cnt of them.
 */
int sn1SCDiscoverL2(char *dev, char *client_info, sn1SC_L2 **l2_return_list, int *l2_cnt, int wait)
{
  sn1SC_L2 *l2_list;
  sn1SC_L2 l2ent;
  int l2_list_size = L2_LIST_STEP;
  int l2_local = 0;             /* the local L2s, at the front */
  int sd = -1;
  int round, l2, local;
  int rval = 0;

  *l2_cnt = 0;
  l2_list = malloc(l2_list_size * sizeof(sn1SC_L2));
  if (l2_list == NULL)
    return -1;
  *l2_return_list = l2_list;
  for (round = 0; round < DISCOVER_ROUNDS; round++) {
    sd = sn1SCDiscoverL2Start(sd,dev,client_info);
    if (sd < 0)
      return -1;
    while ((rval = sn1SCDiscoverL2Response(sd,&l2ent,wait)) == 0) {
      local = local_address(l2ent.ip_addr);
      l2 = local ? find_l2_slot(&l2ent,l2_list,0,l2_local)
                 : find_l2_slot(&l2ent,l2_list,l2_local,*l2_cnt);
      if (l2 == -1)
        continue;               /* (seen it already) */
      if (l2 < *l2_cnt)
        memmove(l2_list + l2 + 1,l2_list + l2,(*l2_cnt - l2) * sizeof(sn1SC_L2));
      l2_list[l2] = l2ent;
      if (local)
        l2_local++;
      if (++*l2_cnt == l2_list_size) {
        l2_list_size += L2_LIST_STEP;
        l2_list = realloc(l2_list,l2_list_size * sizeof(sn1SC_L2));
        if (l2_list == NULL)
          return -1;
        *l2_return_list = l2_list;
      }
    }
  }
  sn1SCDiscoverL2Done(sd);
  return rval < 0 ? -1 : 0;
}

/* syslog() an error with errno's text and number after the other arguments */
#define LOG_ERRNO(ln, ...) do { \
    int err_ = errno; \
    syslog(3,"SCapiL2.c",ln,0,__VA_ARGS__,strerror(err_),err_); \
  } while (0)

/* an interface request for name, family AF_INET */
static void ifreq_for(struct ifreq *ifr, const char *name)
{
  strncpy(ifr->ifr_name,name,sizeof(ifr->ifr_name) - 1);
  ifr->ifr_addr.sa_family = AF_INET;
}

/*
 * Broadcast the discovery datagram on dev, or every interface (on sd, or a
 * new broadcast socket if sd is -1). Returns the socket, or -1.
 */
int sn1SCDiscoverL2Start(int sd, char *dev, char *client_info)
{
  char *dflt_namelist[2] = { "eth0", NULL };
  char **namelist = dflt_namelist;
  char **nlptr;
  struct sockaddr_in myaddr, cliaddr;
  struct ifreq ifr;
  uint8 pkt[8192];
  unsigned long icmd;
  char *istr;
  int o = 1;
  int retry, status;

  if (dev == NULL || *dev == '\0') {
    namelist = find_interfaces(&addrlist);
    if (namelist == NULL)
      return -1;
  }
  else {
    dflt_namelist[0] = dev;
  }
  if (sd == -1) {
    sd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if (sd < 0) {
      LOG_ERRNO(210,"sn1SCDiscoverL2Start: socket: %s [%d]\n");
      return -1;
    }
    if (setsockopt(sd,SOL_SOCKET,SO_BROADCAST,&o,sizeof(o)) < 0) {
      LOG_ERRNO(217,"sn1SCDiscoverL2Start: setsockopt: %s [%d]\n");
      close(sd);
      return -1;
    }
    memset(&myaddr,0,sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    if (bind(sd,(struct sockaddr *)&myaddr,sizeof(myaddr)) < 0) {
      LOG_ERRNO(232,"sn1SCDiscoverL2Start: server bind: %s [%d]\n");
      close(sd);
      return -1;
    }
  }

  for (nlptr = namelist; *nlptr != NULL; nlptr++) {
    /* (the original asked for the address twice and did not use it) */
    memset(&ifr,0,sizeof(ifr));
    ifreq_for(&ifr,*nlptr);
    if (ioctl(sd,SIOCGIFADDR,&ifr) < 0) {
      LOG_ERRNO(262,"sn1SCDiscoverL2Start: ioctl %s SIOCGIFADDR: %s [%d]\n",*nlptr);
      close(sd);
      return -1;
    }
    ifreq_for(&ifr,*nlptr);
    if (ioctl(sd,SIOCGIFFLAGS,&ifr) < 0) {
      LOG_ERRNO(272,"l2find find_if: ioctl %s SIOCGIFFLAGS: %s [%d]\n",*nlptr);
      close(sd);
      return -1;
    }
    /* a point-to-point link's other end, else the broadcast address */
    if (ifr.ifr_flags & IFF_POINTOPOINT) {
      icmd = SIOCGIFDSTADDR;
      istr = "SIOCGIFDSTADDR";
    }
    else {
      icmd = SIOCGIFBRDADDR;
      istr = "SIOCGIFBRDADDR";
    }
    ifreq_for(&ifr,*nlptr);
    if (ioctl(sd,icmd,&ifr) < 0) {
      LOG_ERRNO(290,"sn1SCDiscoverL2Start: ioctl %s %s: %s [%d]\n",*nlptr,istr);
      continue;
    }
    memset(&cliaddr,0,sizeof(cliaddr));
    cliaddr.sin_family = AF_INET;
    cliaddr.sin_port = htons(IR_PORT_BIAS + DISCOVER_PORT);
    cliaddr.sin_addr.s_addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    if (client_info == NULL || *client_info == '\0')
      pkt[0] = '\0';
    else
      snprintf((char *)pkt,sizeof(pkt),"%s",client_info);
    /* (an interface just coming up may refuse at first) */
    for (retry = 0; ; retry++) {
      status = sendto(sd,pkt,strlen((char *)pkt),0,(struct sockaddr *)&cliaddr,sizeof(cliaddr));
      if (status >= 0 || (errno != EHOSTUNREACH && errno != ECONNREFUSED) || retry >= SEND_RETRIES)
        break;
    }
    if (status < 0) {
      int err = errno;

      syslog(4,"SCapiL2.c",331,0,"sn1SCDiscoverL2Start: sendto %s: %s [%d]\n",*nlptr,strerror(err),err);
    }
  }
  return sd;
}

/* copy a value into a field, as strncpy() with one byte kept for the end */
static void set_value(char *field, size_t size, const char *value)
{
  strncpy(field,value,size - 1);
}

/*
 * The next answer into *l2: 0, or 1 when wait seconds pass without one
 * (wait 0: forever), -1 on an error. Datagrams with none of the keys are
 * skipped.
 */
int sn1SCDiscoverL2Response(int sd, sn1SC_L2 *l2, int wait)
{
  uint8 pkt[8192];
  struct sockaddr_in cliaddr;
  socklen_t asize = sizeof(cliaddr);
  struct timeval maxwait;
  fd_set rfd;
  ssize_t len;
  int valid = 0;
  char *copy, *cptr, *comma, *key, *val;

  memset(&cliaddr,0,sizeof(cliaddr));
  cliaddr.sin_family = AF_INET;
  while (!valid) {
    maxwait.tv_sec = wait;
    maxwait.tv_usec = 0;
    FD_ZERO(&rfd);
    FD_SET(sd,&rfd);
    if (select(sd + 1,&rfd,NULL,NULL,wait == 0 ? NULL : &maxwait) < 0) {
      LOG_ERRNO(384,"sn1SCDiscoverL2Response: select: %s [%d]\n");
      return -1;
    }
    if (!FD_ISSET(sd,&rfd))
      return 1;
    /* (the original read up to 8192 bytes into 8192 and added a NUL) */
    len = recvfrom(sd,pkt,sizeof(pkt) - 1,0,(struct sockaddr *)&cliaddr,&asize);
    if (len < 0) {
      if (errno == EAGAIN)
        return 1;
      LOG_ERRNO(404,"l2find: recvfrom: %s [%d]\n");
      return -1;
    }
    pkt[len] = '\0';
    memset(l2,0,sizeof(*l2));
    l2->ip_addr = cliaddr.sin_addr.s_addr;
    set_value(l2->raw,sizeof(l2->raw),(char *)pkt);
    copy = strdup((char *)pkt);
    /* "key:value" pairs separated by commas (a value ends at a ':' too) */
    for (cptr = copy; cptr != NULL && *cptr != '\0'; cptr = comma) {
      comma = strchr(cptr,',');
      if (comma != NULL)
        *comma++ = '\0';
      key = strtok(cptr,":");
      val = strtok(NULL,":");
      if (val == NULL)
        val = "";
      if (key == NULL)
        continue;               /* (an empty pair, as ",,": the original passed NULL to strcmp) */
      if (strcmp(key,"version") == 0) {
        valid = 1;
        set_value(l2->version,sizeof(l2->version),val);
      }
      else if (strcmp(key,"ssn") == 0) {
        valid = 1;
        set_value(l2->ssn,sizeof(l2->ssn),val);
      }
      else if (strcmp(key,"name") == 0) {
        valid = 1;
        set_value(l2->sysname,sizeof(l2->sysname),val);
      }
      else if (strcmp(key,"rack") == 0) {
        valid = 1;
        l2->rack = atoi(val);
      }
      else if (strcmp(key,"l2pri") == 0) {
        valid = 1;
        l2->ms = L2_MS_PRIMARY;
        sscanf(val,"%d",&l2->group);
      }
      else if (strcmp(key,"l2sec") == 0) {
        valid = 1;
        l2->ms = L2_MS_SECONDARY;
        sscanf(val,"%d",&l2->group);
      }
    }
    free(copy);
  }
  return 0;
}

int sn1SCDiscoverL2Done(int sd)
{
  close(sd);
  return 0;
}

/*
 * Where l2ent goes in l2_list[beg..end): by system name, then (if l2ent has
 * a rack) rack, then this host's loopback first and address (compared as
 * the network-order word); -1 if it is there already.
 */
int find_l2_slot(sn1SC_L2 *l2ent, sn1SC_L2 *l2_list, int beg, int end)
{
  int l2, c;

  for (l2 = beg; l2 < end; l2++) {
    c = strcmp(l2ent->sysname,l2_list[l2].sysname);
    if (c < 0)
      return l2;
    if (c > 0)
      continue;
    if (l2ent->ip_addr == l2_list[l2].ip_addr)
      return -1;
    if (l2ent->rack != 0) {
      if (l2_list[l2].rack < l2ent->rack)
        continue;
      if (l2ent->rack < l2_list[l2].rack)
        return l2;
    }
    if (ntohl(l2ent->ip_addr) == INADDR_LOOPBACK || l2ent->ip_addr <= l2_list[l2].ip_addr)
      return l2;
  }
  return end;
}

/*
 * The interfaces that are up (not "dummy*"), each once, with their
 * addresses (a point-to-point link's other end) in *addrlist_ptr; both
 * lists are static and end with NULL and 0.
 */
static char **find_interfaces(uint32 **addrlist_ptr)
{
  static char *namelist[MAX_IFACES];
  static uint32 addrlist[MAX_IFACES];
  static struct ifreq ifrbuf[MAX_IFCONF];
  struct ifconf ic;
  struct ifreq ifr, *ifp;
  struct sockaddr_in *p;
  int sd, i, n;

  if (addrlist_ptr != NULL)
    *addrlist_ptr = NULL;
  sd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
  if (sd < 0) {
    LOG_ERRNO(550,"l2find find_if: socket: %s [%d]\n");
    return NULL;
  }
  ic.ifc_len = sizeof(ifrbuf);
  ic.ifc_buf = (char *)ifrbuf;
  if (ioctl(sd,SIOCGIFCONF,&ic) < 0) {
    LOG_ERRNO(558,"l2find find_if: ioctl SIOCGIFCONF: %s [%d]\n");
    close(sd);                  /* (the original kept it open) */
    return NULL;
  }
  for (n = 0; namelist[n] != NULL; n++) {
    free(namelist[n]);
    namelist[n] = NULL;
  }
  memset(addrlist,0,sizeof(addrlist));

  for (i = 0; i < ic.ifc_len / (int)sizeof(struct ifreq); i++) {
    ifp = &ifrbuf[i];
    p = (struct sockaddr_in *)&ifp->ifr_addr;
    if (strncmp(ifp->ifr_name,"dummy",5) == 0)
      continue;
    for (n = 0; namelist[n] != NULL && strcmp(namelist[n],ifp->ifr_name) != 0; n++)
      ;
    if (namelist[n] != NULL)
      continue;                 /* (an interface with several addresses) */
    if (n == MAX_IFACES - 1)
      break;                    /* (the original did not stop) */
    memset(&ifr,0,sizeof(ifr));
    strncpy(ifr.ifr_name,ifp->ifr_name,sizeof(ifr.ifr_name) - 1);
    if (ioctl(sd,SIOCGIFFLAGS,&ifr) < 0) {
      LOG_ERRNO(601,"l2find find_if: ioctl SIOCGIFFLAGS: %s [%d]\n");
      close(sd);
      return NULL;
    }
    if (!(ifr.ifr_flags & IFF_UP))
      continue;
    if (ifr.ifr_flags & IFF_POINTOPOINT) {
      strncpy(ifr.ifr_name,ifp->ifr_name,sizeof(ifr.ifr_name) - 1);
      if (ioctl(sd,SIOCGIFDSTADDR,&ifr) < 0) {
        LOG_ERRNO(622,"l2find find_if: ioctl SIOCGIFDSTADDR: %s [%d]\n");
        close(sd);
        return NULL;
      }
      p = (struct sockaddr_in *)&ifr.ifr_dstaddr;
    }
    namelist[n] = strdup(ifp->ifr_name);
    addrlist[n] = p->sin_addr.s_addr;
  }
  close(sd);
  *addrlist_ptr = addrlist;
  return namelist;
}
