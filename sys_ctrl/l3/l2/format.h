/*
 * sys_ctrl/l3/l2/format.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/format.h
 */

#ifndef SYS_CTRL_L3_L2_FORMAT_H
#define SYS_CTRL_L3_L2_FORMAT_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "../../common/IRouter/IRouter.h"   /* for the prototypes */
#include "../../common/sys/sysctl_types.h"   /* for the prototypes */
/* format.c */

char *format_caddress(IRAddress addr, int partition);

#endif /* SYS_CTRL_L3_L2_FORMAT_H */
