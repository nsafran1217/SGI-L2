/*
 * sys_ctrl/l3/gui/l2gui.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/l2gui.h
 */

#ifndef SYS_CTRL_L3_GUI_L2GUI_H
#define SYS_CTRL_L3_GUI_L2GUI_H

#include "mainwin.h"
#include "logowin.h"
#include "destwin.h"
#include "graphwin.h"
#include "cmdwin.h"

/* l2gui.cc */
extern Fl_Window *mainwin;
extern Fl_Window *logowin;
extern Fl_Window *destwin;
extern Fl_Window *graphwin;
extern Fl_Window *cmdwin;
extern char *myname;
void l2gui_show(Fl_Window *w, int x, int y);

#endif /* SYS_CTRL_L3_GUI_L2GUI_H */
