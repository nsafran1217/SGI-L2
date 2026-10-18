/*
 * sys_ctrl/l3/gui/graphwin.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/graphwin.h
 */

#ifndef SYS_CTRL_L3_GUI_GRAPHWIN_H
#define SYS_CTRL_L3_GUI_GRAPHWIN_H

typedef struct _graph_def {
  const char *name;
  double value;
  unsigned char color;
} graph_def;

int graphwin_init(void);
void graphwin_update_data(void *data);
void graphwin_show(void);
void graphwin_hide(void);

#endif /* SYS_CTRL_L3_GUI_GRAPHWIN_H */
