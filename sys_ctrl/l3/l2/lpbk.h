/*
 * sys_ctrl/l3/l2/lpbk.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/lpbk.h
 */

#ifndef SYS_CTRL_L3_L2_LPBK_H
#define SYS_CTRL_L3_L2_LPBK_H

#include "smp.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* lpbk.c */
void lpbk(int session, IRAddress addr, int length, int count, SMP *smp);
void lpbk_process_response(IRPacket *p);

#endif /* SYS_CTRL_L3_L2_LPBK_H */
