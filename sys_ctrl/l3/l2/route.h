/*
 * sys_ctrl/l3/l2/route.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/route.h
 */

#ifndef SYS_CTRL_L3_L2_ROUTE_H
#define SYS_CTRL_L3_L2_ROUTE_H

#include "smp.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* route.c */
extern int route_pending;
void route_process_request(IRAddress addr, SMP *smp);
char *pstr(int type, int port);
void route_process_response(IRPacket *p);
void route_process(IRPacket *p);

#endif /* SYS_CTRL_L3_L2_ROUTE_H */
