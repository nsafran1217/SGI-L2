/*
 * sys_ctrl/l3/l2/pty.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/pty.h
 */

#ifndef SYS_CTRL_L3_L2_PTY_H
#define SYS_CTRL_L3_L2_PTY_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* pty.c */
int pty_master(void);
int pty_slave(int master_fd);

#endif /* SYS_CTRL_L3_L2_PTY_H */
