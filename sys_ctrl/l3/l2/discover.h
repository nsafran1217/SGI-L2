/*
 * sys_ctrl/l3/l2/discover.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * (No such header existed; this holds the module's prototypes.)
 * Module: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/discover.h
 */

#ifndef SYS_CTRL_L3_L2_DISCOVER_H
#define SYS_CTRL_L3_L2_DISCOVER_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* discover.c */
extern int discover_debug;
extern char version_attr[30];
extern char client_id[30];
extern int discover_sd;
int discover_init(void);
void discover_response(void *cd, int sd);
void discover_service(void);

#endif /* SYS_CTRL_L3_L2_DISCOVER_H */
