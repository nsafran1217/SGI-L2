/*
 * sys_ctrl/l3/utils/l2term.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * (No such header existed; this holds the module's prototypes.)
 * Module: /data/cf/sysco/scs123.patch/sys_ctrl/l3/utils/l2term.h
 */

#ifndef SYS_CTRL_L3_UTILS_L2TERM_H
#define SYS_CTRL_L3_UTILS_L2TERM_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "../../common/Router/Event.h"   /* for the prototypes */
/* l2term.c */
void input_l2(EventData data, int fd);
void read_n_write(int *wfd, int rfd);
void syntax(char *opt);
void tty_debug(void);
int tty_config(void);
void tty_reconfig(void);
void cleanup(void);

#endif /* SYS_CTRL_L3_UTILS_L2TERM_H */
