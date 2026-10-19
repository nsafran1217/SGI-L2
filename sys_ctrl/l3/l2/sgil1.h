/*
 * sys_ctrl/l3/l2/sgil1.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/sgil1.h
 *
 * The sgil1 USB driver's interface: /dev/sgil1_cs (the control device:
 * read one status byte per device, readable when one changes) and
 * /dev/sgil1_<n> (one L1 each: a read or write is one frame). The ioctl
 * names are the driver's (its sgil1.h); STABS kept only the struct.
 */

#ifndef SYS_CTRL_L3_L2_SGIL1_H
#define SYS_CTRL_L3_L2_SGIL1_H

#include <linux/ioctl.h>
typedef struct {
    unsigned char bus;
    unsigned char level;        /* hubs on the way: path[0..level-1] */
    unsigned char dev;
    unsigned char path[6];
} sgil1_cfg_t;

#define SGIL1_IOCTL_BASE        'S'
#define SGIL1_RESET_READ        _IO(SGIL1_IOCTL_BASE, 1)
#define SGIL1_RESET_WRITE       _IO(SGIL1_IOCTL_BASE, 2)
#define SGIL1_RESET_DEVICE      _IO(SGIL1_IOCTL_BASE, 3)
#define SGIL1_READ_CFG          _IOR(SGIL1_IOCTL_BASE, 4, sgil1_cfg_t)
#define SGIL1_RESET_PIPES       _IO(SGIL1_IOCTL_BASE, 5)
/* on the control device */
#define SGIL1_ST_READ_REV       _IOR(SGIL1_IOCTL_BASE, 6, int)
#define SGIL1_ST_READ_DEV_CFG   _IOWR(SGIL1_IOCTL_BASE, 7, sgil1_cfg_t)

#define SGIL1_MAX               40      /* devices (status bytes) */

#endif /* SYS_CTRL_L3_L2_SGIL1_H */
