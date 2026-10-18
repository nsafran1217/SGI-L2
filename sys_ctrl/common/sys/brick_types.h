/*
 * sys_ctrl/common/sys/brick_types.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/brick_types.h
 */

#ifndef SYS_CTRL_COMMON_SYS_BRICK_TYPES_H
#define SYS_CTRL_COMMON_SYS_BRICK_TYPES_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* brick_types.c */
unsigned int brickConvertString(char *sptr);
char *brickConvertType(unsigned int type);
char brickTypeToChar(unsigned int type);
int brickIsCompute(unsigned int type);

#include "decomp.h"

/* function definitions this header contained */
static int BRICK_TASKNUM_SUBCHAN(int btype, int tasknum)
{
  int iVar1;
  int iStack_8;
  
  if (btype == 0x36) {
    iVar1 = ((tasknum / 6 + (tasknum >> 0x1f) >> 2) - (tasknum >> 0x1f)) * -0x18;
  }
  else {
    if (btype < 0x37) {
      if (btype == 0x2e) {
        iStack_8 = tasknum;
        if (tasknum < 0) {
          iStack_8 = tasknum + 0x1f;
        }
        return tasknum + (iStack_8 >> 5) * -0x20;
      }
    }
    else if (btype == 0x40) {
      return tasknum % 0x14;
    }
    iStack_8 = tasknum;
    if (tasknum < 0) {
      iStack_8 = tasknum + 0x1f;
    }
    iVar1 = (iStack_8 >> 5) * -0x20;
  }
  return tasknum + iVar1;
}


#endif /* SYS_CTRL_COMMON_SYS_BRICK_TYPES_H */
