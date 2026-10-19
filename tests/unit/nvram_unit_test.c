/*
 * Equivalence test for the NVRAM image (l3/main/nvram.c): the same
 * settings, log messages and resets through the rewritten code and the
 * original reconstruction (decomp branch, compiled in as Orignvram*), each
 * with its own file; after every step the files and the log text must
 * match. The clock is faked so the log times agree. Built and run by
 * tests/unit/nvram_unit_test.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "../../sys_ctrl/l3/main/nvram.h"

int OrignvramInit(int mode);
int OrignvramReset(void);
void OrignvramSet(int32 location, uintptr_t value);
uintptr_t OrignvramGet(int32 location);
void OrignvramLogReset(void);
void OrignvramLogInsert(char *message);
char *OrignvramLogFetch(void);

int IR_PORT_BIAS;
static time_t fake_now = 1000000000;

time_t time(time_t *t)
{
  if (t != NULL)
    *t = fake_now;
  return fake_now;
}

void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...)
{
}

char *LoggerDefaultMessage(int msgnbr)
{
  return "error";
}

static int failures, compared;

static void compare(const char *what, int step)
{
  static unsigned char a[NVRAM_SIZE], b[NVRAM_SIZE];
  char *la, *lb;
  FILE *f;

  memset(a, 0, sizeof(a));
  memset(b, 0, sizeof(b));
  f = fopen("new.nv", "rb"); fread(a, 1, sizeof(a), f); fclose(f);
  f = fopen("orig.nv", "rb"); fread(b, 1, sizeof(b), f); fclose(f);
  if (memcmp(a, b, sizeof(a)) != 0) {
    printf("FAIL  %s %d: files differ\n", what, step);
    failures++;
  }
  la = nvramLogFetch();
  lb = OrignvramLogFetch();
  if (strcmp(la, lb) != 0) {
    printf("FAIL  %s %d: log differs\n--- new\n%.300s\n--- orig\n%.300s\n", what, step, la, lb);
    failures++;
  }
  free(la);
  free(lb);
  compared++;
}

int main(void)
{
  static const char *strings[] = { "", "x", "SN123456789012345678", "a system name that is far too long for it",
    "CST6CDT", NULL };
  char msg[400];
  unsigned int seed = 1;
  int step, loc, len, i, k;
  uintptr_t v;

  setenv("SGI_L2_NVRAM", "orig.nv", 1);
  OrignvramInit(NVRAM_READWRITE);
  setenv("SGI_L2_NVRAM", "new.nv", 1);
  nvramInit(NVRAM_READWRITE);
  compare("init", 0);

  for (step = 0; step < 4000; step++) {
    fake_now += rand_r(&seed) % 100000;
    switch (rand_r(&seed) % 10) {
    case 0: case 1: case 2:     /* a setting */
      loc = rand_r(&seed) % 28;
      if (loc == NVRAM_SERIAL || loc == NVRAM_SYSNAME || loc == NVRAM_TIMEZONE || loc == NVRAM_PASSWORD) {
        k = rand_r(&seed) % 6;
        v = strings[k] == NULL ? 0 : (uintptr_t)strings[k];
      }
      else
        v = rand_r(&seed);
      nvramSet(loc, v);
      OrignvramSet(loc, v);
      for (k = 0; k < 28; k++) {
        uintptr_t a = nvramGet(k), b = OrignvramGet(k);
        int str = k == NVRAM_SERIAL || k == NVRAM_SYSNAME || k == NVRAM_TIMEZONE || k == NVRAM_PASSWORD;
        if (str ? strcmp((char *)a, (char *)b) != 0 : a != b) {
          printf("FAIL  get %d after set %d\n", k, loc);
          failures++;
        }
      }
      break;
    case 9:
      if (rand_r(&seed) % 40 == 0) {
        nvramLogReset();
        OrignvramLogReset();
        break;
      }
      /* fall through */
    default:                    /* a log message */
      len = 1 + rand_r(&seed) % (rand_r(&seed) % 5 ? 60 : 300);
      for (i = 0; i < len; i++)
        msg[i] = 'a' + rand_r(&seed) % 26;
      if (rand_r(&seed) % 3 == 0)
        msg[len - 1] = '\n';
      msg[len] = '\0';
      nvramLogInsert(msg);
      OrignvramLogInsert(msg);
      break;
    }
    compare("step", step);
  }
  /* last: the original cannot log after a reset (its ring is all zero) */
  nvramReset();
  OrignvramReset();
  compare("reset", 0);
  nvramLogInsert("after reset");        /* (dropped; the original crashed) */
  if (failures == 0)
    printf("PASS  nvram: %d steps compared with the original (files and log)\n", compared);
  return failures != 0;
}
