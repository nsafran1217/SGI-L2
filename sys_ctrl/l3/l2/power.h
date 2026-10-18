/*
 * sys_ctrl/l3/l2/power.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/power.h
 */

#ifndef SYS_CTRL_L3_L2_POWER_H
#define SYS_CTRL_L3_L2_POWER_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "../../common/IRouter/IRouter.h"   /* for the prototypes */
/* power.c */
extern int power_check;
extern int power_abort;
void power_init(void);
void power_timer(void);
int power_query(void);
void power_process_request(void);
void power_process_response(IRPacket *p);
int power_status(int rack, int slot);

#endif /* SYS_CTRL_L3_L2_POWER_H */
