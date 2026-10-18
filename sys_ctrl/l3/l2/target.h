/*
 * sys_ctrl/l3/l2/target.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/target.h
 */

#ifndef SYS_CTRL_L3_L2_TARGET_H
#define SYS_CTRL_L3_L2_TARGET_H

#include "../../common/IRouter/IRouter.h"
#include "reqrspq.h"
#include "l2cmd.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* target.c */
extern int target_response_timeout;
int target_l2(L2CMD *c, char **results, int ip, char *cptr, int response, int delay, int final);
int target_l1(L2CMD *c, int ip, int port, int l1, char *cptr, int response, int delay, int final);
int target_pkt(L2CMD *c, IRAddress addr, int opcode, int argc, IRArgument *argv, int response, int delay, int final);

#endif /* SYS_CTRL_L3_L2_TARGET_H */
