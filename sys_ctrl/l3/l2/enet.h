/*
 * sys_ctrl/l3/l2/enet.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/enet.h
 */

#ifndef SYS_CTRL_L3_L2_ENET_H
#define SYS_CTRL_L3_L2_ENET_H

#include "smp.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* enet.c */
extern int enet_only;
extern SMP *enet_smp;
void enet_init(void);
void enet_export(int port);
void enet_accept(int port, int sd);
void enet_reset(int sd);

#endif /* SYS_CTRL_L3_L2_ENET_H */
