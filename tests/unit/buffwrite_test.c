/*
 * Test of the growing string buffer (common/sys/BuffWrite.c): random
 * appends, including ones that fill the buffer exactly, against plain
 * concatenation. Built and run by tests/unit/buffwrite_test.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../sys_ctrl/common/sys/BuffWrite.h"

int main(void)
{
  static char want[200000], piece[5000];
  int run, i, n, len, total, failures = 0;
  BuffWrite_t *bw;
  char *got;

  srand(1);
  for (run = 0; run < 200; run++) {
    bw = BuffWriteInit();
    total = 0;
    n = rand() % 40;
    for (i = 0; i < n; i++) {
      /* exact fits: up to the next multiple of 1024 */
      len = rand() % 3 == 0 ? (1024 - total % 1024) : rand() % (rand() % 2 ? 50 : 3000);
      memset(piece, 'a' + i % 26, len);
      piece[len] = '\0';
      if (rand() % 2)
        BuffWrite(bw, piece, -1);
      else {
        piece[len] = 'X';       /* len bounds the copy */
        piece[len + 1] = '\0';
        BuffWrite(bw, piece, len);
      }
      memcpy(want + total, piece, len);
      total += len;
    }
    want[total] = '\0';
    got = BuffWriteDone(bw, 0);
    if (n == 0 ? got != NULL : (got == NULL || strcmp(got, want) != 0)) {
      printf("FAIL  buffwrite: run %d (%d appends, %d bytes)\n", run, n, total);
      failures++;
    }
    free(got);
  }
  if (failures == 0)
    printf("PASS  buffwrite: 200 runs of appends\n");
  return failures != 0;
}
