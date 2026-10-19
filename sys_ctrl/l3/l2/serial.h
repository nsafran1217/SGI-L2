/*
 * sys_ctrl/l3/l2/serial.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/serial.h
 */

#ifndef SYS_CTRL_L3_L2_SERIAL_H
#define SYS_CTRL_L3_L2_SERIAL_H

#include "smp.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* serial.c */
extern SMP *serial_console;
void serial_init(void);
void serial_reset(int sd);

#endif /* SYS_CTRL_L3_L2_SERIAL_H */
