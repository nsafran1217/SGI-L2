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

/* Task number -> sub-channel within its brick. The original header defined
 * this function (STABS places its code in brick_types.h); Ghidra showed the
 * divisions as shift sequences. */
static inline int BRICK_TASKNUM_SUBCHAN(int btype, int tasknum)
{
    switch (btype) {
    case 0x36:
        return tasknum % 24;
    case 0x40:
        return tasknum % 20;
    default:                /* includes 0x2e, which the original tested separately */
        return tasknum % 32;
    }
}

#endif /* SYS_CTRL_COMMON_SYS_BRICK_TYPES_H */
