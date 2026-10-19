/*
 * Equivalence test for L2 discovery (l3/api/SCapiL2.c): the rewritten
 * functions against the original reconstruction (decomp branch), both built
 * by tests/unit/discover_wrap.c. Run by tests/unit/discover_test.sh.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include "../../sys_ctrl/l3/api/SCapi.h"

#define DECL(p) \
  int p##_DiscoverL2(char *, char *, sn1SC_L2 **, int *, int); \
  int p##_DiscoverL2Response(int, sn1SC_L2 *, int); \
  int p##_find_l2_slot(sn1SC_L2 *, sn1SC_L2 *, int, int); \
  char **p##_find_interfaces(uint32 **);
DECL(new)
DECL(orig)

int IR_PORT_BIAS = 4321;        /* discovery on port 14321 */

void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...)
{
}

static int failures, compared;

static void fail(const char *what, int n)
{
  printf("FAIL  %s %d\n", what, n);
  failures++;
}

/* ---- find_l2_slot ---- */

static void random_l2(sn1SC_L2 *l2, unsigned int *seed)
{
  static const char *names[] = { "", "alpha", "beta", "gamma" };
  static const uint32 ips[] = { 0x0100007f, 0x0200000a, 0x0100000a, 0x0300000a, 0x01020304, 0xfe01a8c0 };

  memset(l2, 0, sizeof(*l2));
  strcpy(l2->sysname, names[rand_r(seed) % 4]);
  l2->rack = rand_r(seed) % 4;
  l2->ip_addr = ips[rand_r(seed) % 6];
}

static void check_slots(void)
{
  sn1SC_L2 list[60], ent;
  unsigned int seed = 7;
  int run, n, slot, slot2, beg;

  for (run = 0; run < 2000; run++) {
    n = 0;
    while (n < 50) {
      random_l2(&ent, &seed);
      beg = n > 0 ? rand_r(&seed) % n : 0;
      slot = new_find_l2_slot(&ent, list, beg, n);
      slot2 = orig_find_l2_slot(&ent, list, beg, n);
      compared++;
      if (slot != slot2) {
        fail("find_l2_slot", run);
        return;
      }
      if (slot < 0)
        break;
      memmove(list + slot + 1, list + slot, (n - slot) * sizeof(sn1SC_L2));
      list[slot] = ent;
      n++;
    }
  }
}

/* ---- responses ---- */

static int rx, tx;
static struct sockaddr_in rxaddr;

static void udp_pair(void)
{
  socklen_t len = sizeof(rxaddr);

  rx = socket(AF_INET, SOCK_DGRAM, 0);
  tx = socket(AF_INET, SOCK_DGRAM, 0);
  memset(&rxaddr, 0, sizeof(rxaddr));
  rxaddr.sin_family = AF_INET;
  rxaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(rx, (struct sockaddr *)&rxaddr, sizeof(rxaddr));
  getsockname(rx, (struct sockaddr *)&rxaddr, &len);
}

static void send_pkt(const char *pkt, size_t len)
{
  sendto(tx, pkt, len, 0, (struct sockaddr *)&rxaddr, sizeof(rxaddr));
}

/* the packets the original survives: under 8 KB, and no pair that is
 * empty or only colons (strtok() finds no key: strcmp(NULL, ...)) */
static int orig_safe(const char *pkt, size_t len)
{
  const char *p = pkt, *end;
  size_t n;

  if (len >= 8192)
    return 0;
  if (*p == '\0')
    return 1;
  for (;;) {
    end = strchr(p, ',');
    n = end != NULL ? (size_t)(end - p) : strlen(p);
    if (strspn(p, ":") >= n)
      return 0;
    if (end == NULL)
      return 1;
    p = end + 1;
    if (*p == '\0')
      return 1;
  }
}

static void check_responses(void)
{
  static const char *keys[] = { "version", "ssn", "name", "rack", "l2pri", "l2sec", "junk", "" };
  static const char *vals[] = { "1.62.0", "N0000123", "my system", "001", "3", "x:y",
    "a value that is much longer than any of the fields it could be copied into, by far", "" };
  static char pkt[9000], junk[9000];
  sn1SC_L2 a, b;
  unsigned int seed = 3;
  int run, i, n, ra, rb;
  size_t len;

  udp_pair();
  for (run = 0; run < 3000; run++) {
    pkt[0] = '\0';
    n = rand_r(&seed) % 6;
    for (i = 0; i < n; i++) {
      if (i > 0)
        strcat(pkt, ",");
      strcat(pkt, keys[rand_r(&seed) % 8]);
      if (rand_r(&seed) % 5) {
        strcat(pkt, ":");
        strcat(pkt, vals[rand_r(&seed) % 8]);
      }
    }
    len = strlen(pkt);
    if (run % 500 == 7) {        /* a full-size datagram */
      memset(pkt, 'v', 8192);
      memcpy(pkt, "name:", 5);
      len = 8192;
    }
    /* a packet with no keys is skipped: follow each with a valid one */
    if (orig_safe(pkt, len)) {
      send_pkt(pkt, len);
      send_pkt("rack:9", 6);
      memset(&b, 0x77, sizeof(b));
      rb = orig_DiscoverL2Response(rx, &b, 1);
      while (recv(rx, junk, sizeof(junk), MSG_DONTWAIT) > 0)
        ;
    }
    send_pkt(pkt, len);
    send_pkt("rack:9", 6);
    memset(&a, 0x77, sizeof(a));
    ra = new_DiscoverL2Response(rx, &a, 1);
    if (orig_safe(pkt, len)) {
      compared++;
      if (ra != rb || memcmp(&a, &b, sizeof(a)) != 0)
        fail("response", run);
    }
    else if (ra != 0) {
      fail("response (new only)", run);
    }
    /* (drop the "rack:9" left when the first packet was valid) */
    while (recv(rx, junk, sizeof(junk), MSG_DONTWAIT) > 0)
      ;
  }
  close(rx);
  close(tx);
}

/* ---- interfaces ---- */

static void check_interfaces(void)
{
  uint32 *aa, *ab;
  char **na, **nb;
  int i;

  na = new_find_interfaces(&aa);
  nb = orig_find_interfaces(&ab);
  compared++;
  for (i = 0; na[i] != NULL || nb[i] != NULL; i++) {
    if (na[i] == NULL || nb[i] == NULL || strcmp(na[i], nb[i]) != 0 || aa[i] != ab[i]) {
      fail("find_interfaces", i);
      return;
    }
  }
}

/* ---- a whole discovery against a fake L2 responder ---- */

static pid_t responder(void)
{
  static const char *answers[] = { "version:1.62.0,ssn:S1,name:sysb,rack:2,l2pri:1",
    "version:1.62.0,ssn:S2,name:sysa,rack:1,l2sec:1", "version:1.61.0,ssn:S3,name:sysa,rack:3",
    "ssn:S4,name:sysb,rack:1", "junk:1",
    "version:1.62.0,ssn:S5,name:zzz,rack:4" };       /* (from 127.0.0.1: local, so first) */
  struct sockaddr_in addr, from;
  socklen_t flen;
  char buf[100];
  int sd, out[6], i, o = 1;
  pid_t pid;

  sd = socket(AF_INET, SOCK_DGRAM, 0);
  setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &o, sizeof(o));
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(10000 + IR_PORT_BIAS);
  bind(sd, (struct sockaddr *)&addr, sizeof(addr));
  for (i = 0; i < 6; i++) {     /* answer from 127.0.0.2 .. 127.0.0.6, then 127.0.0.1 */
    out[i] = socket(AF_INET, SOCK_DGRAM, 0);
    addr.sin_port = 0;
    addr.sin_addr.s_addr = htonl(i < 5 ? INADDR_LOOPBACK + 1 + i : INADDR_LOOPBACK);
    bind(out[i], (struct sockaddr *)&addr, sizeof(addr));
  }
  pid = fork();
  if (pid != 0) {
    close(sd);
    for (i = 0; i < 6; i++)
      close(out[i]);
    return pid;
  }
  for (;;) {
    flen = sizeof(from);
    if (recvfrom(sd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen) < 0)
      _exit(0);
    for (i = 0; i < 6; i++)
      sendto(out[i], answers[i], strlen(answers[i]), 0, (struct sockaddr *)&from, flen);
  }
}

static void check_discovery(void)
{
  sn1SC_L2 *la, *lb;
  int ca, cb, ra, rb;
  pid_t pid = responder();

  usleep(100000);
  ra = new_DiscoverL2("lo", "", &la, &ca, 1);
  rb = orig_DiscoverL2("lo", "", &lb, &cb, 1);
  kill(pid, SIGKILL);
  waitpid(pid, NULL, 0);
  compared++;
  if (ra != rb || ca != cb || memcmp(la, lb, ca * sizeof(sn1SC_L2)) != 0) {
    printf("FAIL  discovery: %d/%d L2s, rval %d/%d\n", ca, cb, ra, rb);
    failures++;
  }
  if (ca != 5 || strcmp(la[0].sysname, "zzz") != 0) {
    printf("FAIL  discovery found %d L2s, not 5 with the local one first\n", ca);
    failures++;
  }
  free(la);
  free(lb);
}

int main(void)
{
  check_slots();
  check_responses();
  check_interfaces();
  check_discovery();
  if (failures == 0)
    printf("PASS  discover: %d slot searches, responses, interfaces, discoveries compared with the original\n",
           compared);
  return failures != 0;
}
