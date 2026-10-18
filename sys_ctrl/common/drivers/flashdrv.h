/*
 * sys_ctrl/common/drivers/flashdrv.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/drivers/flashdrv.h
 */

#ifndef SYS_CTRL_COMMON_DRIVERS_FLASHDRV_H
#define SYS_CTRL_COMMON_DRIVERS_FLASHDRV_H

struct _flashInfo_t {
    uint32 boot;
    uint32 end;
    uint32 image[2];
    uint32 image_current;
    uint32 image_type;
    uint32 image_blksize;
    uint32 imagetab;
    uint32 wblksize;
    uint32 eblksize;
    uint32 *bootrev_p;
};
typedef struct _flashInfo_t flashInfo_t;
#include "../sys/Logger.h"

#endif /* SYS_CTRL_COMMON_DRIVERS_FLASHDRV_H */
