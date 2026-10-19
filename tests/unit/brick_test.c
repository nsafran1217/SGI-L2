/*
 * Equivalence test for the brick type conversions (common/sys/
 * brick_types.c): every type value and every one-letter and known name,
 * through the rewritten functions and the original reconstruction (decomp
 * branch, compiled in as Orig*). Built and run by tests/unit/brick_test.sh.
 */
#include <stdio.h>
#include <string.h>
#include "../../sys_ctrl/common/sys/brick_types.h"

unsigned int OrigbrickConvertString(char *sptr);
char *OrigbrickConvertType(unsigned int type);
char OrigbrickTypeToChar(unsigned int type);
int OrigbrickIsCompute(unsigned int type);

int main(void)
{
  static const char *names[] = { "ip35", "ip37", "ip45", "ip41", "twister", "vortix", "opus",
    "gemini", "dorado", "ip69", "191010", "1932", "1955", "drouter", "ip71", "nl4r", "nl4s",
    "T1", "T2", "T", "", "IP35", "ip3", "ip355", "t", "x2", NULL };
  char s[2], name[32];
  int failures = 0, compared = 0;
  unsigned int t;
  int i;

  for (t = 0; t < 0x200; t++) {
    if (brickIsCompute(t) != OrigbrickIsCompute(t)) {
      printf("FAIL  brickIsCompute(0x%x)\n", t);
      failures++;
    }
    if (t < 0x100 && brickTypeToChar(t) != OrigbrickTypeToChar(t)) {
      printf("FAIL  brickTypeToChar(0x%x): %c vs %c\n", t, brickTypeToChar(t), OrigbrickTypeToChar(t));
      failures++;
    }
    /* (the original's 16-byte buffer overflowed with the longer names) */
    strcpy(name, brickConvertType(t));
    if (strlen(name) < 16) {
      if (strcmp(name, OrigbrickConvertType(t)) != 0) {
        printf("FAIL  brickConvertType(0x%x): %s vs %s\n", t, name, OrigbrickConvertType(t));
        failures++;
      }
    }
    compared += 3;
  }
  if (strcmp(brickConvertType('$'), "C (IP69 HACK, 1932 Chassis)") != 0 ||
      strcmp(brickConvertType('-'), "Quad Dense Router") != 0) {
    printf("FAIL  brickConvertType('$' or '-')\n");
    failures++;
  }
  for (t = 1; t < 0x100; t++) {
    s[0] = t;
    s[1] = '\0';
    if (brickConvertString(s) != OrigbrickConvertString(s)) {
      printf("FAIL  brickConvertString(\"\\x%02x\")\n", t);
      failures++;
    }
    compared++;
  }
  for (i = 0; names[i] != NULL; i++) {
    if (brickConvertString((char *)names[i]) != OrigbrickConvertString((char *)names[i])) {
      printf("FAIL  brickConvertString(\"%s\")\n", names[i]);
      failures++;
    }
    compared++;
  }
  if (failures == 0)
    printf("PASS  brick: %d conversions compared with the original\n", compared);
  return failures != 0;
}
