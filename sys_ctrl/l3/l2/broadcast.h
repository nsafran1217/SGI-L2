/*
 * sys_ctrl/l3/l2/broadcast.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/broadcast.h
 */

#ifndef SYS_CTRL_L3_L2_BROADCAST_H
#define SYS_CTRL_L3_L2_BROADCAST_H

#include "../../common/IRouter/IRouter.h"
#include "reqrspq.h"
#include "l2cmd.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* broadcast.c */
extern int broadcast_debug;
extern int broadcast_response_timeout;
int broadcast(REQRSPQ *q, IRIdent *id);
int broadcast_l2(L2CMD *c, char **results, char *cmd, int response, int delay, int final);
int broadcast_l1(L2CMD *c, int method, char *cmd, int response, int delay, int type, int *slots, int final);

#endif /* SYS_CTRL_L3_L2_BROADCAST_H */
