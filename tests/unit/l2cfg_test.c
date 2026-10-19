/*
 * Equivalence test for the system configuration (common/main/L2Cfg.c):
 * random configuration texts (as L2CfgMQuery() writes and L2CfgMCfgL2()
 * reads) and L1 port configurations (L2CfgMCfgPort()) through the
 * rewritten code and the original reconstruction (decomp branch, compiled in
 * as Orig*), each into its own configuration; then every printer, query
 * and lookup must give the same. Inputs that crash the original go to the
 * new code alone. Built and run by tests/unit/l2cfg_test.sh.
 */
#include <arpa/inet.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../sys_ctrl/common/main/L2Cfg.h"
#include "../../sys_ctrl/common/main/L1Cfg.h"
#include "../../sys_ctrl/common/IRouter/IRouter.h"
#include "orig_protos.h"
#include "../../sys_ctrl/l3/main/settings.h"

/* the original's NVRAM settings: the new code's (the ids are NVRAM's) */
uintptr_t nvramGet(int location) { return settingsGet(location); }
void nvramSet(int location, uintptr_t value) { settingsSet(location, value); }

static int failures, compared;
static unsigned int seed = 11;

static int rnd(int n)
{
  return rand_r(&seed) % n;
}

/* the client pointers L2CfgMPrint() mode 2 shows differ: masked */
static void mask_pointers(char *s)
{
  char *p;

  char *q;

  /* (decomp prints them in 8 digits, the rewrite in full) */
  for (p = s; (p = strstr(p, ", C ")) != NULL; p += 4) {
    for (q = p + 4; *q != ')' && *q != '\0'; q++)
      ;
    memmove(p + 5, q, strlen(q) + 1);
    p[4] = '#';
  }
}

static void same(const char *what, int n, char *a, char *b, int free_them)
{
  if (a == NULL || b == NULL ? a != b : strcmp(a, b) != 0) {
    printf("FAIL  %s (case %d)\n--- new\n%.600s\n--- orig\n%.600s\n", what, n, a ? a : "(NULL)",
           b ? b : "(NULL)");
    failures++;
  }
  compared++;
  if (free_them) {
    free(a);
    free(b);
  }
}

static IRIdent ident;

/* a configuration event: rev 2 (or 1), the text in string arguments */
static IRPacket *cfg_packet(int rev, char *text)
{
  IRArgument av[8];
  size_t len = strlen(text), off = 0;
  int argc = 2;

  memset(av, 0, sizeof(av));
  av[1]._val = rev;
  /* (split into pieces: L2CfgMCfgL2() puts the string arguments together) */
  while (off < len && argc < 7) {
    size_t piece = len - off < 700 || argc == 6 ? len - off : 300 + rnd(300);
    char *s = malloc(piece + 1);
    memcpy(s, text + off, piece);
    s[piece] = '\0';
    av[argc]._clas = IR_ARG_FREE | IR_ARG_STRING;
    av[argc]._val = IR_PTR_VAL(s);
    av[argc]._size = piece + 1;
    argc++;
    off += piece;
  }
  return IRouterMakePacket(&ident, NULL, 0, 0, IR_EVT, 2, argc, av);
}

static char *rand_ip(char *buf)
{
  static const char *ips[] = { "10.0.0.1", "10.0.0.2", "10.0.1.3", "192.168.1.5", "127.0.0.1", "10.0.0.9" };
  return strcpy(buf, ips[rnd(6)]);
}

/* a random, well-formed configuration text */
static void gen_text(char *t, int safe)
{
  static const char *keys1[] = { "rack", "slot", "type", "conena", "consub", "sh_amode", "sh_shrmode",
    "rtype", "pstate", "mstate", "estate", "cstate", "part", "bsn", "ssn" };
  static const char brick_types[] = "CRIPXNG#%=-D3456789@ABLOQ$,.{}J?";
  char ip[20];
  int nl2 = 1 + rnd(4), l2, port, nports, l1, nl1, k;

  t[0] = '\0';
  for (l2 = 0; l2 < nl2; l2++) {
    t += sprintf(t, "l2:%s,", rand_ip(ip));
    if (rnd(3))
      t += sprintf(t, "l2rack:%d,", rnd(4) * 10 + rnd(3));
    if (rnd(2))
      t += sprintf(t, "l2ssn:SN%d,", rnd(5));
    if (rnd(2))
      t += sprintf(t, "l2name:sys%d,", rnd(3));
    if (rnd(4) == 0)
      t += sprintf(t, "l2dspdis:1,");
    if (rnd(2))
      t += sprintf(t, "l2os:%s,", (const char *[]){ "linux", "ppclinux", "armlinux", "irix", "beos" }[rnd(5)]);
    if (rnd(5) == 0)
      t += sprintf(t, "l2sec:%s,", rand_ip(ip));
    if (rnd(6) == 0)
      t += sprintf(t, "l2pri:%s,", rand_ip(ip));
    if (rnd(3) == 0)
      t += sprintf(t, "l2events:%x,", rnd(0x10000));
    if (rnd(3) == 0)
      t += rnd(2) ? sprintf(t, "pselect:*,") : sprintf(t, "pselect:%d.%d.%d,", rnd(9), rnd(9), rnd(255));
    nports = rnd(5);
    for (port = 0; port < nports; port++) {
      t += sprintf(t, "port:%d,", port == 0 ? 0 : rnd(40));
      if (rnd(4) == 0)
        continue;
      t += sprintf(t, "state:%d,device:/dev/sgil1_%d,usbp:b%d;p%d,", 1 + rnd(2), rnd(8), rnd(3), rnd(5));
      nl1 = rnd(4);
      for (l1 = 0; l1 < nl1; l1++) {
        t += sprintf(t, "%s:%d,", l1 ? "L1" : "l1", rnd(7));
        for (k = 0; k < 15; k++) {
          if (rnd(3) == 0)
            continue;
          if (k == 13 || k == 14)
            t += sprintf(t, "%s:%s%d,", keys1[k], k == 13 ? "MDJ" : "L0", rnd(100000));
          else if (k == 2)
            t += sprintf(t, "%s:%d,", keys1[k], brick_types[rnd(sizeof(brick_types) - 1)]);
          else if (k == 0 || k == 1)
            t += sprintf(t, "%s:%d,", l1 ? "RACK" : keys1[k], 1 + rnd(30));
          else
            t += sprintf(t, "%s:%d,", keys1[k], rnd(k == 4 ? 0x2000 : 6));
        }
      }
    }
    if (rnd(5) == 0)
      t += sprintf(t, "junk:%d,", rnd(9));
  }
  if (!safe) {                  /* what the original cannot take */
    switch (rnd(6)) {
    case 0: strcat(t, "l2:10.0.0.1,port:77,state:2,l1:1,rack:3,"); break;
    case 1: strcat(t, ",,:,l2:10.0.0.2,,"); break;
    case 2: strcat(t, "DELETE_L2,l2rack:5,"); break;
    case 3: strcat(t, "l2:10.0.0.1,l2name:a-system-name-much-longer-than-twenty-bytes,"); break;
    case 4: strcat(t, "l2:10.0.0.1,port:0,state:2,rack:9,slot:9,"); break;
    case 5: strcat(t, "l2:10.0.0.1,pselect:-1.300.7,"); break;
    }
  }
}

/* an L1CfgL1, in our byte order or (big) the L1's */
static void gen_l1cfg(L1CfgL1 *c, int big)
{
  static const char brick_types[] = "CRIPXI3B@-";

  memset(c, 0, sizeof(*c));
  c->configured = rnd(5) != 0;
  c->revision = 2;
  c->rack = 1 + rnd(12);
  c->slot = 1 + rnd(30);
  c->type = brick_types[rnd(sizeof(brick_types) - 1)];
  c->console_subchannel = rnd(3) == 0 ? 4 : rnd(64) | rnd(4) << 8;
  c->console_enabled = rnd(2);
  c->shub_addrmode = rnd(3);
  c->router_type = rnd(3);
  c->power_state = rnd(3);
  c->partition = rnd(4);
  c->env_state = rnd(3);
  c->conn_state = rnd(3);
  snprintf(c->brick_sn, sizeof(c->brick_sn), "MDJ%d", rnd(99999));
  snprintf(c->system_sn, sizeof(c->system_sn), "L0%d", rnd(9999));
  if (big) {
    int *w = (int *)c;
    for (size_t i = 0; i < offsetof(L1CfgL1, brick_sn) / 4; i++)
      if (i != offsetof(L1CfgL1, shub_addrmode) / 4)
        w[i] = htonl(w[i]);
    c->env_state = htonl(c->env_state);
    c->conn_state = htonl(c->conn_state);
  }
}

/* an L1 port's configuration response, form 6 or 7 */
static IRPacket *port_packet(int form)
{
  static L1CfgL1 cfgs[8];
  static unsigned char idx[8];
  IRArgument av[6];
  int big = rnd(2), n, i;

  memset(av, 0, sizeof(av));
  av[0]._val = form;
  if (form == 6) {
    for (i = 0; i < 4; i++) {
      gen_l1cfg(&cfgs[i], big);
      av[i + 1]._clas = IR_ARG_BYTES;
      av[i + 1]._val = IR_PTR_VAL(&cfgs[i]);
      av[i + 1]._size = sizeof(L1CfgL1);
    }
    return IRouterMakePacket(&ident, NULL, 0, 0, IR_RSP, 2, 5, av);
  }
  n = rnd(5);
  for (i = 0; i < n; i++) {
    gen_l1cfg(&cfgs[i], big);
    idx[i] = rnd(8);
  }
  av[2]._val = n;
  av[3]._val = sizeof(L1CfgL1);
  av[4]._clas = IR_ARG_BYTES;
  av[4]._val = IR_PTR_VAL(idx);
  av[4]._size = n ? n : 1;
  av[5]._clas = IR_ARG_BYTES;
  av[5]._val = IR_PTR_VAL(cfgs);
  av[5]._size = n ? n * sizeof(L1CfgL1) : 1;
  return IRouterMakePacket(&ident, NULL, 0, 0, IR_RSP, 2, 6, av);
}

/* compare everything that reads a configuration */
static void compare_all(L2Cfg *a, L2Cfg *b, int n)
{
  static const IRAddress addrs[] = { 0, 0x00104000, 0x0010c000, 0x1ffff003, 0x10108005, 0x2ffff000,
    0x30000000, 0x40000000, 0x50000000, 0x60000000, 0x8000000a, 0x8a000001, 0xc3000102, 0xc0000209,
    0x0000c000, 0x7fffffff };
  char *ra, *rb;
  int mode, i, ia, pa, la, ib, pb, lb, r1, s1, r2, s2;
  char buf[200];

  for (mode = 0; mode <= 2; mode++) {
    for (i = 0; i <= 1; i++) {
      L2CfgMPrint(a, &ra, mode, i);
      OrigL2CfgMPrint(b, &rb, mode, i);
      if (ra && rb && mode == 2) {
        mask_pointers(ra);
        mask_pointers(rb);
      }
      snprintf(buf, sizeof(buf), "L2CfgMPrint mode %d show_l1 %d", mode, i);
      same(buf, n, ra, rb, 1);
    }
  }
  L2CfgMPrintX(a, &ra);
  OrigL2CfgMPrintX(b, &rb);
  same("L2CfgMPrintX", n, ra, rb, 1);
  L2CfgMPrintY(a, &ra);
  OrigL2CfgMPrintY(b, &rb);
  same("L2CfgMPrintY", n, ra, rb, 1);
  for (mode = 0; mode < 4; mode++) {
    for (i = 0; i <= 1; i++) {
      ra = strdup(L2CfgMQuery(a, mode, i));
      rb = OrigL2CfgMQuery(b, mode, i);
      snprintf(buf, sizeof(buf), "L2CfgMQuery mode %d format %d", mode, i);
      same(buf, n, ra, rb, 0);
      free(ra);
    }
  }
  for (i = 0; i < (int)(sizeof(addrs) / sizeof(addrs[0])); i++) {
    ra = strdup(L2CfgMAddrStr(a, addrs[i], 0));
    snprintf(buf, sizeof(buf), "L2CfgMAddrStr %08x", addrs[i]);
    same(buf, n, ra, OrigL2CfgMAddrStr(b, addrs[i], 0), 0);
    free(ra);
  }
  for (i = -1; i < 6; i++) {
    compared++;
    if (L2CfgMGetConsole(a, i) != OrigL2CfgMGetConsole(b, i)) {
      printf("FAIL  L2CfgMGetConsole(%d) (case %d)\n", i, n);
      failures++;
    }
  }
  for (i = 0; i < 40; i++) {
    int rack = 1 + rnd(12), slot = 1 + rnd(30);
    compared++;
    ia = L2CfgMFindBrickIP(a, rack, slot, &ia, &pa, &la);
    ib = OrigL2CfgMFindBrickIP(b, rack, slot, &ib, &pb, &lb);
    r1 = L2CfgMFindBrickType(a, rack, slot);
    r2 = OrigL2CfgMFindBrickType(b, rack, slot);
    s1 = L2CfgMFindBrickCfg(a, rack, slot, 0) != NULL;
    s2 = OrigL2CfgMFindBrickCfg(b, rack, slot, 0) != NULL;
    if (ia != ib || pa != pb || la != lb || r1 != r2 || s1 != s2 ||
        (L2CfgMFindBrickL2(a, rack, slot) == NULL) != (OrigL2CfgMFindBrickL2(b, rack, slot) == NULL)) {
      printf("FAIL  brick lookups %d.%d (case %d)\n", rack, slot, n);
      failures++;
    }
  }
}

/* a fresh configuration as an L3 tool's (its L2 at 10.0.0.1) */
static void init_l3(L2Cfg *a, L2Cfg *b, RouterClient *c)
{
  memset(a, 0, sizeof(*a));
  memset(b, 0, sizeof(*b));
  L2CfgMode = 0;
  OrigL2CfgMode = 0;
  L2CfgMInitL3(a, c);
  OrigL2CfgMInitL3(b, c);
}

int main(void)
{
  static char text[60000];
  static L2Cfg a, b;
  RouterClient client;
  IRPacket *pa, *pb;
  int run, step, port, i, fmt;
  char *out;

  IRouterInit(0xffffffff);
  IRouterInitID(&ident, 0, 0);
  memset(&client, 0, sizeof(client));
  client.addr = inet_addr("10.0.0.1");

  /* configuration texts, as an L3 tool gets them */
  for (run = 0; run < 400; run++) {
    init_l3(&a, &b, &client);
    for (step = 0; step < 1 + rnd(3); step++) {
      gen_text(text, 1);
      pa = cfg_packet(2, text);
      pb = cfg_packet(2, text);
      L2CfgMCfgL2(&a, pa);
      OrigL2CfgMCfgL2(&b, pb);
      IRouterFreePacket(pa);
      IRouterFreePacket(pb);
    }
    compare_all(&a, &b, run);
    /* the query text read back gives the same again (unformatted: the
     * formatted text's keys start with newlines and indents) */
    fmt = 0;
    strcpy(text, L2CfgMQuery(&a, 1, fmt));
    pa = cfg_packet(2, text);
    L2CfgMCfgL2(&a, pa);
    IRouterFreePacket(pa);
    strcpy(text, OrigL2CfgMQuery(&b, 1, fmt));
    pb = cfg_packet(2, text);
    OrigL2CfgMCfgL2(&b, pb);
    IRouterFreePacket(pb);
    compare_all(&a, &b, run + 10000);
  }

  /* L1 port configurations, as l2 gets them (into L2CfgLocal) */
  L2CfgLocal.syscon = calloc(256, sizeof(L2CfgSysCon));
  OrigL2CfgLocal.syscon = calloc(256, sizeof(L2CfgSysCon));
  L2CfgLocal.net.ip_addr = OrigL2CfgLocal.net.ip_addr = inet_addr("10.0.0.7");
  for (run = 0; run < 400; run++) {
    port = rnd(6);
    if (rnd(5) == 0) {
      compared++;
      if (L2CfgMCfgPort(&L2CfgLocal, port, NULL) != OrigL2CfgMCfgPort(&OrigL2CfgLocal, port, NULL)) {
        printf("FAIL  L2CfgMCfgPort(NULL) (case %d)\n", run);
        failures++;
      }
    }
    else {
      unsigned int s = seed;
      pa = port_packet(6 + rnd(2));
      seed = s;
      pb = port_packet(6 + rnd(2));
      compared++;
      if (L2CfgMCfgPort(&L2CfgLocal, port, pa) != OrigL2CfgMCfgPort(&OrigL2CfgLocal, port, pb)) {
        printf("FAIL  L2CfgMCfgPort (case %d)\n", run);
        failures++;
      }
      IRouterFreePacket(pa);
      IRouterFreePacket(pb);
    }
    if (run % 10 == 0)
      compare_all(&L2CfgLocal, &OrigL2CfgLocal, 20000 + run);
  }

  /* new only: what the original could not take */
  for (run = 0; run < 300; run++) {
    init_l3(&a, &b, &client);
    gen_text(text, 0);
    pa = cfg_packet(2, text);
    L2CfgMCfgL2(&a, pa);
    IRouterFreePacket(pa);
    L2CfgMPrint(&a, &out, 2, 1);
    free(out);
    for (i = 0; i < 4; i++)
      L2CfgMQuery(&a, i, i & 1);
  }

  if (failures == 0)
    printf("PASS  l2cfg: %d printouts, queries and lookups compared with the original\n", compared);
  return failures != 0;
}
