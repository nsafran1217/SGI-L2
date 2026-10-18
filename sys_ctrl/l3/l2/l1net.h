/*
 * sys_ctrl/l3/l2/l1net.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l1net.h
 */

#ifndef SYS_CTRL_L3_L2_L1NET_H
#define SYS_CTRL_L3_L2_L1NET_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* l1net.c */
void l1net_accept(void *cd, int sd);
int l1net_export(void);
void l1net_close(int fd);

#endif /* SYS_CTRL_L3_L2_L1NET_H */
