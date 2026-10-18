/*
 * sys_ctrl/l3/l2/sgil1.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/sgil1.h
 */

#ifndef SYS_CTRL_L3_L2_SGIL1_H
#define SYS_CTRL_L3_L2_SGIL1_H

#include <linux/ioctl.h>
typedef struct {
    unsigned char bus;
    unsigned char level;
    unsigned char dev;
    unsigned char path[6];
} sgil1_cfg_t;

#endif /* SYS_CTRL_L3_L2_SGIL1_H */
