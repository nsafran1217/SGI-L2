/*
 * Equivalence test for the malloc profiler (common/sys/minfo.c): the same
 * blocks added to and removed from the rewritten and the original
 * (decomp branch) bookkeeping; the "l2dbg mstat" and "mmap" reports must
 * match. Built and run by tests/unit/minfo_test.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DECL(p) \
  void p##_add(char *, size_t, size_t); void p##_del(char *, size_t); \
  void p##_stat(char **); void p##_map(char **); void p##_enable(void); \
  void p##_disable(void); void p##_reset(void);
DECL(new)
DECL(orig)

static int failures, compared;

/* stat: whether to compare the stat reports too (the original's is too
 * small for its fixed text with under three blocks) */
static void compare(const char *what, int step, int stat)
{
  char *a, *b;

  if (!stat)
    goto map;
  new_stat(&a);
  orig_stat(&b);
  if (strcmp(a, b) != 0) {
    printf("FAIL  %s %d: stat\n--- new\n%s--- orig\n%s", what, step, a, b);
    failures++;
  }
  free(a);
  free(b);
 map:
  new_map(&a);
  orig_map(&b);
  if (strcmp(a, b) != 0) {
    printf("FAIL  %s %d: map\n", what, step);
    failures++;
  }
  free(a);
  free(b);
  compared++;
}

int main(void)
{
  static char arena[1 << 24];   /* fake addresses */
  static size_t sizes[1 << 13];
  unsigned int seed = 1;
  int run, i, slot;

  compare("disabled", 0, 1);
  new_enable();
  orig_enable();
  compare("empty", 0, 0);
  for (run = 0; run < 3; run++) {
    memset(sizes, 0, sizeof(sizes));
    for (i = 0; i < 12000; i++) {
      slot = rand_r(&seed) % 8192;      /* a block at arena + slot * 2048 */
      if (sizes[slot] == 0) {
        sizes[slot] = rand_r(&seed) % 4 == 0 ? 2044 :          /* (adjacent: no hole) */
                      1 + rand_r(&seed) % (rand_r(&seed) % 8 ? 2000 : 0x180000);
        new_add(arena + slot * 2048 + 4, sizes[slot] / 2, sizes[slot]);
        orig_add(arena + slot * 2048 + 4, sizes[slot] / 2, sizes[slot]);
      }
      else {
        new_del(arena + slot * 2048 + 4, sizes[slot]);
        orig_del(arena + slot * 2048 + 4, sizes[slot]);
        sizes[slot] = 0;
      }
      if (i % 1500 == 0)
        compare("run", run * 100 + i / 1500, i > 0);
    }
    /* not in the list */
    new_del(arena + 3, 10);
    orig_del(arena + 3, 10);
    compare("end", run, 1);
    new_reset();
    orig_reset();
    compare("reset", run, 0);
  }
  new_disable();
  orig_disable();
  compare("disabled", 1, 1);
  if (failures == 0)
    printf("PASS  minfo: %d reports compared with the original\n", compared);
  return failures != 0;
}
