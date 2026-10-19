/*
 * Equivalence test of the L2's discovery responder (discover_response() in
 * l3/l2/discover.c) against the main branch's reconstruction (Orig*): random
 * requests (keys, matching and other values) sent on lo to a socket each
 * side answers on, with random settings (serial number, name, multisys,
 * primary/secondary mode). The answers, log messages and heartbeats must
 * match; malformed requests (which crash the original) only the new side
 * gets. l2discover_test.sh builds it under ASan, with stubs.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "l2.h"
#include "discover.h"
#include "../main/nvram.h"     /* (the original's; from RECON_REF) */
#include "../main/settings.h"
#include "../main/l2log.h"
#include "orig_discover.h"

L2Cfg L2CfgLocal;
int IR_PORT_BIAS;
int l2_discover;
int cfg_ping_sender_valid;
static L2CfgNode peer;
static char serial[20], sysname[32];
static int multisys;
static char log_[2][4096];
static int side;

static unsigned int seed = 1;
static unsigned int rnd(unsigned int n)
{
  seed = seed * 1103515245 + 12345;
  return (seed >> 8) % n;
}

static void note(const char *fmt, ...)
{
  size_t len = strlen(log_[side]);
  va_list ap;

  va_start(ap,fmt);
  vsnprintf(log_[side] + len,sizeof(log_[0]) - len,fmt,ap);
  va_end(ap);
}

uintptr_t nvramGet(int32 location)
{
  switch (location) {
  case SET_SERIAL: return (uintptr_t)serial;
  case SET_SYSNAME: return (uintptr_t)sysname;
  case SET_MULTISYS: return multisys;
  }
  return 0;
}

void nvramLogInsert(char *message) { note("log %s",message); }

/* the new code's settings and log: the same (the ids are NVRAM's) */
uintptr_t settingsGet(int id) { return nvramGet(id); }
void l2logInsert(char *message) { nvramLogInsert(message); }
char *SocketAddrStr(uint32_t addr) { return inet_ntoa(*(struct in_addr *)&addr); }
L2CfgNode *L2CfgMFindNode(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client)
{
  return rnd(2) ? &peer : NULL;
}
void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...) { note("syslog %d %s\n",ln,fmt); }
char *l2_firmware_version(void) { return "1.62.0"; }
EventID EventAddInput(int fd, void (*input_func)(), EventData client_data, char *desc) { return 1; }
void EventRemoveInput(EventID id) { }
int SocketGetHostAddr(uint32_t *addr) { *addr = htonl(0x7f000001); return 0; }

static const char *const keys[] = { "clientid", "ssn", "name", "l2", "l2pri", "version", "x" };

/* a request: key:value pairs; malformed ones only if bad */
static void make_request(char *buf, size_t size, int bad)
{
  int n = rnd(5), i;

  buf[0] = '\0';
  for (i = 0; i < n; i++) {
    const char *k = keys[rnd(7)];
    const char *v = rnd(3) == 0 ? "other" : strcmp(k,"ssn") == 0 ? serial
                  : strcmp(k,"name") == 0 ? sysname : strcmp(k,"clientid") == 0 ? client_id : "1";
    size_t len = strlen(buf);
    if (bad && rnd(3) == 0)
      snprintf(buf + len,size - len,"%s",rnd(2) ? ",," : ":,");
    else if (rnd(8) == 0)
      snprintf(buf + len,size - len,"%s,",k);                 /* no value */
    else
      snprintf(buf + len,size - len,"%s:%s%s",k,v,i < n - 1 || rnd(2) ? "," : "");
  }
}

int main(void)
{
  struct sockaddr_in a = { .sin_family = AF_INET };
  socklen_t alen = sizeof(a);
  char req[256], rsp[2][9000];
  int srv, cli, trial, i;
  ssize_t n[2];

  srv = socket(AF_INET,SOCK_DGRAM,0);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(srv,(struct sockaddr *)&a,sizeof(a)) < 0 || getsockname(srv,(struct sockaddr *)&a,&alen) < 0) {
    perror("bind");
    return 1;
  }
  strcpy(client_id,"127.0.0.1.4242");
  strcpy(Origclient_id,client_id);
  strcpy(version_attr,"version:1.62.0 (SW),");
  strcpy(Origversion_attr,version_attr);
  for (trial = 0; trial < 20000; trial++) {
    int bad = rnd(4) == 0;
    unsigned int heartbeat;

    if (trial % 50 == 0) {
      snprintf(serial,sizeof(serial),"%s",rnd(3) ? "SSN123" : "");
      snprintf(sysname,sizeof(sysname),"%s",rnd(3) ? "sysA" : "");
      multisys = rnd(2);
      L2CfgLocal.rack = rnd(4);
    }
    /* (a malformed request goes to the new side only: in secondary mode it
     * adds no address to the warned-about list, which must stay in step) */
    L2CfgLocal.net.msmode = bad ? 1 : rnd(3);
    L2CfgLocal.net.msip = 0;
    l2_discover = rnd(4) != 0;
    cfg_ping_sender_valid = rnd(2);
    make_request(req,sizeof(req),bad);
    {
      /* from one of many addresses: L2s are warned about once each. (Up
       * to 100: the original's list of them overflows at about 150.) */
      struct sockaddr_in c = { .sin_family = AF_INET };
      c.sin_addr.s_addr = htonl(0x7f000001 + rnd(trial < 10000 ? 40 : 100));
      cli = socket(AF_INET,SOCK_DGRAM,0);
      if (bind(cli,(struct sockaddr *)&c,sizeof(c)) < 0) {
        perror("bind client");
        return 1;
      }
    }
    heartbeat = peer.heartbeat = rnd(3) == 0 ? 0xffffffff : rnd(100);
    for (side = bad; side < 2; side++) {
      unsigned int s = seed;
      peer.heartbeat = heartbeat;
      L2CfgLocal.net.msip = 0;
      sendto(cli,req,strlen(req) + 1,0,(struct sockaddr *)&a,sizeof(a));
      if (side == 0)
        Origdiscover_response(NULL,srv);
      else
        discover_response(NULL,srv);
      n[side] = recv(cli,rsp[side],sizeof(rsp[0]),MSG_DONTWAIT);
      note("reply %zd %s; heartbeat %u msip %x\n",n[side],n[side] > 0 ? rsp[side] : "",
           peer.heartbeat,L2CfgLocal.net.msip);
      if (side == 0)
        seed = s;               /* (the same L2CfgMFindNode() answers for both) */
    }
    close(cli);
    if (!bad && strcmp(log_[0],log_[1]) != 0) {
      printf("FAIL  l2discover: trial %d request \"%s\"\n--- orig\n%s--- new\n%s",trial,req,
             log_[0],log_[1]);
      return 1;
    }
    log_[0][0] = log_[1][0] = '\0';
  }
  /* the new side alone: primary mode warns about thousands of L2s */
  side = 1;
  L2CfgLocal.net.msmode = 2;
  l2_discover = 1;
  for (i = 0; i < 4000; i++) {
    struct sockaddr_in c = { .sin_family = AF_INET };
    c.sin_addr.s_addr = htonl(0x7f000101 + i);
    cli = socket(AF_INET,SOCK_DGRAM,0);
    if (bind(cli,(struct sockaddr *)&c,sizeof(c)) < 0)
      return 1;
    sendto(cli,"l2:1",5,0,(struct sockaddr *)&a,sizeof(a));
    discover_response(NULL,srv);
    close(cli);
    log_[1][0] = '\0';
  }
  printf("PASS  l2discover: %d discovery requests answered as the original\n",trial);
  return 0;
}
