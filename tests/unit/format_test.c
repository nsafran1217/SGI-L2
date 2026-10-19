/*
 * Equivalence test of format_caddress() (l3/l2/format.c) against the decomp
 * branch's reconstruction (Origformat_caddress), for every brick type and
 * many addresses and partitions. format_test.sh builds it under ASan; the
 * L2 configuration lookups are stubs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "format.h"

char *Origformat_caddress(IRAddress addr, int partition);

L2Cfg L2CfgLocal;
static L2CfgL1 brick;
static int have_brick;
static char addr_text[64];

char *L2CfgMAddrStr(L2Cfg *head, IRAddress addr, int verbose)
{
  return addr_text;
}

L2CfgL1 *L2CfgMFindBrickCfg(L2Cfg *head, int rack, int slot, int local)
{
  return have_brick ? &brick : NULL;
}

int main(void)
{
  static const int partitions[] = { 0, 1, 7, -1, 12345 };
  char want[128];
  unsigned int seed = 1;
  int count = 0;
  int type;
  int i;
  int p;

  for (type = -1; type < 256; type++) {
    have_brick = type >= 0;
    brick.type = type;
    for (i = 0; i < 400; i++) {
      IRAddress addr;
      if (i < 256)              /* every number (and task) */
        addr = IR_ADDR_MAKE(IR_ADDR_C,1,2,i & 0x7f,i >> 3);
      else {
        seed = seed * 1103515245 + 12345;
        addr = seed ^ (seed << 13);
      }
      snprintf(addr_text,sizeof(addr_text),"%03dc%02d%.*s",i % 1000,i % 64,i % 30,
               "................................");
      for (p = 0; p < (int)(sizeof(partitions) / sizeof(partitions[0])); p++) {
        strcpy(want,Origformat_caddress(addr,partitions[p]));
        if (strcmp(want,format_caddress(addr,partitions[p])) != 0) {
          printf("FAIL  format: type %d addr %08x partition %d: \"%s\" vs \"%s\"\n",type,addr,
                 partitions[p],want,format_caddress(addr,partitions[p]));
          return 1;
        }
        count++;
      }
    }
  }
  printf("PASS  format: %d console addresses compared with the original\n",count);
  return 0;
}
