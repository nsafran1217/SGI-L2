/*
 * sys_ctrl/l3/l2/discover.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/discover.c
 *
 * The L2's side of discovery: L3 tools and other L2s broadcast a
 * "key:value,..." request to DISCOVER_PORT (SCapiL2.c), and every L2 that
 * matches it (system serial number, system name, ...) answers with its
 * version, serial number, name, rack and primary/secondary role.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include "l2.h"
#include "discover.h"
#include "cfg.h"
#include "../main/settings.h"
#include "../main/l2log.h"
#include "../sys/syslogLib.h"

#define DISCOVER_PORT   10000   /* plus IR_PORT_BIAS */
#define RETRIES         10      /* resends of a broadcast reply while the network is down */

/* L2CfgLocal.net.msmode: primary/secondary ("psmode") */
enum { MS_NONE = 0, MS_SECONDARY = 1, MS_PRIMARY = 2 };

/* discover_debug: bits for the messages below; with the top two bits set,
 * only for requests from SGI's own test hosts (all messages, or 0x207) */
int discover_debug;
char version_attr[30];          /* "version:<firmware> (SW)," */
char client_id[30];             /* this l2's own requests: "<ip>.<pid>" */
int discover_sd;
static char haystack[2048];     /* "<ip>:..." L2s warned about once */

int discover_init(void)
{
  struct sockaddr_in myaddr;
  uint32 discover_ip;
  const char *ver;
  int o = 1;

  if (SocketGetHostAddr(&discover_ip) != 0) {
    syslog(2,"discover.c",127,0,"discover_init: couldn\'t get IP address for local host\n");
    return -1;
  }
  sprintf(client_id,"%s.%d",inet_ntoa(*(struct in_addr *)&discover_ip),getpid());
  discover_sd = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
  if (discover_sd < 0) {
    syslog(3,"discover.c",144,0,"discover_init: socket: %m\n");
    return -1;
  }
  if (setsockopt(discover_sd,SOL_SOCKET,SO_BROADCAST,&o,sizeof(o)) < 0) {
    syslog(3,"discover.c",150,0,"discover_init: setsockopt: %m\n");
    close(discover_sd);
    return -1;
  }
  memset(&myaddr,0,sizeof(myaddr));
  myaddr.sin_family = AF_INET;
  myaddr.sin_port = htons(IR_PORT_BIAS + DISCOVER_PORT);
  myaddr.sin_addr.s_addr = INADDR_ANY;
  if (bind(discover_sd,(struct sockaddr *)&myaddr,sizeof(myaddr)) < 0) {
    syslog(3,"discover.c",176,0,"discover_init: server bind: %m\n");
    close(discover_sd);
    return -1;
  }
  ver = l2_firmware_version();
  sprintf(version_attr,"version:%s (SW),",*ver != '\0' ? ver : "INVALID");
  EventAddInput(discover_sd,discover_service,NULL,"discover_init");
  return discover_sd;
}

/* the debug flags for a request from src (see discover_debug) */
static int debug_flags(const char *src)
{
  static const char *const ips[] = {
    "128.162.241.129", "128.162.241.140", "128.162.241.139", "128.162.241.130",
    "128.162.241.133", "128.162.241.134", "128.162.241.131", "128.162.241.132",
    "128.162.241.135", "128.162.241.136", "128.162.241.137", "128.162.241.138",
    "128.162.241.142", "128.162.241.141", "128.162.241.143", "128.162.241.154",
    "137.38.82.14", "137.38.82.15",
  };
  int debug = 0;
  size_t i;

  if ((discover_debug & 0xc0000000) == 0)
    return discover_debug;
  for (i = 0; i < sizeof(ips) / sizeof(ips[0]); i++)
    if (strcmp(src,ips[i]) == 0)
      break;
  if (i == sizeof(ips) / sizeof(ips[0]))
    return 0;
  if (discover_debug & 0x80000000)
    debug = -1;
  if (discover_debug & 0x40000000)
    debug = -0x207;
  return debug;
}

/* log once that the L2 at addr is answered across primary/secondary modes */
static void warn_once(const char *fmt, uint32 addr)
{
  char msg[128];
  const char *ip = SocketAddrStr(addr);

  if (strstr(haystack,ip) != NULL)
    return;
  sprintf(msg,fmt,ip);
  l2logInsert(msg);
  /* (the original appended without bound) */
  if (strlen(haystack) + strlen(ip) + 2 <= sizeof(haystack)) {
    strcat(haystack,ip);
    strcat(haystack,":");
  }
}

/* a request on the discovery socket: answer it if it matches this L2 */
void discover_response(void *cd, int sd)
{
  static int errcnt;
  uint8 outpkt[8192];
  uint8 inpkt[8192];
  struct sockaddr_in cliaddr;
  socklen_t asize = sizeof(cliaddr);
  int from_l2 = 0;
  int from_master = 0;
  int ssn_matched = 0;
  L2CfgNode *l2node;
  char *request;
  char *next;
  char *key;
  char *value;
  char *optr;
  char *s;
  ssize_t status;
  int debug;
  int retry;

  memset(&cliaddr,0,sizeof(cliaddr));
  cliaddr.sin_family = AF_INET;
  cliaddr.sin_port = htons(IR_PORT_BIAS + DISCOVER_PORT);
  /* (the original took 8192 bytes and wrote the NUL one past them) */
  status = recvfrom(sd,inpkt,sizeof(inpkt) - 1,0,(struct sockaddr *)&cliaddr,&asize);
  if (status < 0) {
    if (errno == ECONNREFUSED || errno == EAGAIN)
      return;
    syslog(3,"discover.c",268,0,"discover_response: recvfrom: %m\n");
    if (errcnt++ < 11)
      return;
    syslog(3,"discover.c",270,0,"discover_response: too many RECV errors. Disabling");
    EventRemoveInput(sd);
    return;
  }
  errcnt = 0;
  inpkt[status] = '\0';
  debug = debug_flags(inet_ntoa(cliaddr.sin_addr));
  if (debug & 2)
    fprintf(stderr,"received discover request: %s\n",inpkt);

  request = strdup((char *)inpkt);
  for (next = request; next != NULL && *next != '\0'; ) {
    key = next;
    next = strchr(key,',');
    if (next != NULL)
      *next++ = '\0';
    key = strtok(key,":");
    value = strtok(NULL,":");
    if (key == NULL)            /* (an empty pair: the original crashed) */
      continue;
    if (value == NULL)
      value = "";
    if (strcmp(key,"clientid") == 0) {
      if (strcmp(client_id,value) == 0) {     /* our own request */
        if (debug & 4)
          fprintf(stderr,"discover: client ID matches, not responding\n");
        free(request);
        return;
      }
    }
    else if (strcmp(key,"ssn") == 0) {
      if (strcmp(value,(char *)settingsGet(SET_SERIAL)) != 0) {
        if (debug & 8)
          fprintf(stderr,"discover: ssn doesn\'t match match, not responding\n");
        free(request);
        return;
      }
      ssn_matched = 1;
    }
    else if (strcmp(key,"name") == 0) {
      if (strcmp(value,(char *)settingsGet(SET_SYSNAME)) != 0) {
        if (debug & 0x10)
          fprintf(stderr,"discover: name doesn\'t match match, not responding\n");
        free(request);
        return;
      }
    }
    else if (strcmp(key,"l2") == 0 || strcmp(key,"l2pri") == 0) {
      from_l2 = 1;
      if (strcmp(key,"l2pri") == 0)
        from_master = 1;
      if (!l2_discover) {
        if (debug & 0x20)
          fprintf(stderr,"discover: l2_discover is disabled, not responding\n");
        free(request);
        return;
      }
    }
  }
  free(request);

  if (from_l2 && settingsGet(SET_MULTISYS) != 0 && !ssn_matched) {
    if (debug & 0x80)
      fprintf(stderr,"discover: multi system mode, but no SSN passed from client, not responding\n");
    return;
  }
  if (from_l2 && L2CfgLocal.net.msmode == MS_SECONDARY && !from_master) {
    if (debug & 0x100)
      fprintf(stderr,"discover: master/slave mode, client not a master, not responding\n");
    return;
  }
  if (L2CfgLocal.net.msmode == MS_SECONDARY && from_master)
    L2CfgLocal.net.msip = cliaddr.sin_addr.s_addr;
  if (from_l2 && L2CfgLocal.net.msmode == MS_PRIMARY)
    warn_once("WARNING: primary L2 replying to non-primary-secondary L2 at %s\n",
              cliaddr.sin_addr.s_addr);
  if (from_l2 && L2CfgLocal.net.msmode == MS_NONE && from_master)
    warn_once("WARNING: non-primary-secondry L2 replying to primary L2 at %s\n",
              cliaddr.sin_addr.s_addr);

  /* the answer */
  cliaddr.sin_family = AF_INET;
  optr = (char *)outpkt;
  strcpy(optr,version_attr);
  optr += strlen(optr);
  s = (char *)settingsGet(SET_SERIAL);
  if (s != NULL && s != (char *)-1 && *s != '\0') {
    sprintf(optr,"ssn:%s,",s);
    optr += strlen(optr);
  }
  s = (char *)settingsGet(SET_SYSNAME);
  if (s != NULL && s != (char *)-1 && *s != '\0') {
    sprintf(optr,"name:%s,",s);
    optr += strlen(optr);
  }
  sprintf(optr,"rack:%d,",L2CfgLocal.rack);
  optr += strlen(optr);
  if (L2CfgLocal.net.msmode == MS_SECONDARY)
    strcpy(optr,"l2sec:0");
  else if (L2CfgLocal.net.msmode == MS_PRIMARY)
    strcpy(optr,"l2pri:0");
  if (debug & 0x200)
    fprintf(stderr,"sending discover response: %s\n",outpkt);
  /* a broadcast reply is retried while the network is unreachable */
  for (retry = 0; ; ) {
    status = sendto(sd,outpkt,strlen((char *)outpkt) + 1,0,(struct sockaddr *)&cliaddr,
                    sizeof(cliaddr));
    if (cliaddr.sin_addr.s_addr != htonl(INADDR_BROADCAST) || status >= 0 ||
        (errno != EHOSTUNREACH && errno != ECONNREFUSED))
      break;
    if (retry++ >= RETRIES)     /* (11 sends; "retry=11" below) */
      break;
  }
  if (status < 0) {
    syslog(3,"discover.c",588,0,"discover_response: sendto: %m\n");
    fprintf(stderr,"errno=%d retry=%d status=%d\n",errno,retry,(int)status);
    return;
  }
  /* (a reply to an L2 counts as its heartbeat) */
  if (cfg_ping_sender_valid) {
    l2node = L2CfgMFindNode(&L2CfgLocal,cliaddr.sin_addr.s_addr,0,NULL);
    if (l2node != NULL && l2node->heartbeat != 0xffffffff)
      l2node->heartbeat++;
  }
}

/* poll the discovery socket once */
void discover_service(void)
{
  static struct timeval to;
  fd_set rfd;

  FD_ZERO(&rfd);
  FD_SET(discover_sd,&rfd);
  to.tv_sec = 0;
  to.tv_usec = 10;
  if (select(discover_sd + 1,&rfd,NULL,NULL,&to) == 1 && FD_ISSET(discover_sd,&rfd))
    discover_response(NULL,discover_sd);
}
