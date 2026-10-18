/*
 * sys_ctrl/l3/gui/mainwin.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/mainwin.h
 */

#ifndef SYS_CTRL_L3_GUI_MAINWIN_H
#define SYS_CTRL_L3_GUI_MAINWIN_H

#include <stdint.h>
#include "fl.h"

extern char current_dest_label[100];
extern char status_buf[200];
extern uint32_t my_ip;                  /* STABS: long unsigned int (32 bits) */
extern char firmware_version[30];

int mainwin_init(void);
int mainwin_update_dest(char *dest);
int mainwin_update_status(char *statmsg);
int mainwin_update_config(void);
int mainwin_actions(int enable);

#endif /* SYS_CTRL_L3_GUI_MAINWIN_H */
