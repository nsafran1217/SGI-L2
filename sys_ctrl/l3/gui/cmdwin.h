/*
 * sys_ctrl/l3/gui/cmdwin.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/cmdwin.h
 */

#ifndef SYS_CTRL_L3_GUI_CMDWIN_H
#define SYS_CTRL_L3_GUI_CMDWIN_H

extern char cmdwin_buf[300];

int cmdwin_init(void);
int cmdwin_do_command(char *command, char *dest);

#endif /* SYS_CTRL_L3_GUI_CMDWIN_H */
