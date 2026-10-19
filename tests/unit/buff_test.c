/*
 * Equivalence test for the Router compression (common/Router/Buff.c):
 * the rewritten functions against the original reconstruction (decomp
 * branch), compiled in as Orig*. Built and run by tests/unit/buff_test.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../sys_ctrl/common/Router/Buff.h"

int OrigBuffCompress(unsigned char *ibuf, unsigned int ilen, unsigned char **obuf, unsigned int *olen);
int OrigBuffUncompress(unsigned char *ibuf, unsigned int ilen, unsigned char **obuf, unsigned int *olen);

static int failures, compared, new_only;

/* what the original allocated for its output (too little for escape bytes) */
static unsigned int orig_room(unsigned int ilen)
{
  return (ilen >> 1) * 4 + (ilen >> 1) + 8;
}

static void check(const char *what, unsigned char *in, unsigned int len)
{
  unsigned char *c1, *c2, *u1, *u2;
  unsigned int c1len, c2len, u1len, u2len;

  if (BuffCompress(in, len, &c1, &c1len) != 0 ||
      BuffUncompress(c1, c1len, &u1, &u1len) != 0 || u1len != len || memcmp(u1, in, len)) {
    printf("FAIL  %s (%u bytes): new round trip\n", what, len);
    failures++;
    return;
  }
  if (c1len <= orig_room(len)) {
    OrigBuffCompress(in, len, &c2, &c2len);
    if (c2len != c1len || memcmp(c1, c2, c1len)) {
      printf("FAIL  %s (%u bytes): compressed data differs (%u vs %u bytes)\n", what, len, c1len, c2len);
      failures++;
    }
    if (len > 0) {      /* (the original mallocs 0 bytes for empty data) */
      OrigBuffUncompress(c1, c1len, &u2, &u2len);
      if (u2len != len || memcmp(u2, in, len)) {
        printf("FAIL  %s (%u bytes): original uncompress differs\n", what, len);
        failures++;
      }
      free(u2);
    }
    free(c2);
    compared++;
  }
  else {
    new_only++;
  }
  free(c1);
  free(u1);
}

int main(void)
{
  static unsigned char buf[200000];
  static const int runs[] = { 1, 2, 3, 4, 5, 254, 255, 256, 257, 65534, 65535, 65536, 65537, 131071, 131072 };
  static const unsigned char bytes[] = { 0, 'a', 0xfc, 0xfd, 0xfe, 0xff };
  unsigned int i, j, k, len;

  srand(1);
  check("empty", buf, 0);
  for (i = 0; i < sizeof(runs) / sizeof(runs[0]); i++)
    for (j = 0; j < sizeof(bytes); j++) {
      memset(buf, bytes[j], runs[i]);
      buf[runs[i]] = 'z';
      check("run", buf, runs[i]);
      check("run+1", buf, runs[i] + 1);
    }
  for (k = 0; k < 3000; k++) {
    len = rand() % 3000;
    for (i = 0; i < len; i++) {
      switch (rand() % 4) {
      case 0: buf[i] = rand(); break;                         /* noise */
      case 1: buf[i] = bytes[rand() % sizeof(bytes)]; break;  /* escapes */
      default: buf[i] = i ? buf[i - 1] : 0; break;            /* runs */
      }
    }
    check("random", buf, len);
  }
  for (len = 1; len <= 5000; len = len * 3 + 1) {     /* lone escape bytes: 3 bytes each */
    for (i = 0; i < len; i++)
      buf[i] = i & 1 ? 0xfd : 0xfe;
    check("escapes", buf, len);
  }
  for (k = 0; k < 20; k++) {    /* long runs mixed in */
    len = 0;
    while (len < 150000) {
      j = rand() % 70000 + 1;
      memset(buf + len, bytes[rand() % sizeof(bytes)], j);
      len += j;
    }
    check("long runs", buf, len);
  }
  printf("%s  buff: %d inputs compared with the original, %d checked against the new code only\n",
         failures ? "FAIL" : "PASS", compared, new_only);
  return failures != 0;
}
