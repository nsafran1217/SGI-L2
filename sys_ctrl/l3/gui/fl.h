/*
 * sys_ctrl/l3/gui/fl.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/fl.h
 */

#ifndef SYS_CTRL_L3_GUI_FL_H
#define SYS_CTRL_L3_GUI_FL_H

#include <FL/Fl.H>
#include <FL/Fl_Double_Window.H>
#include <FL/Fl_Window.H>
#include <FL/Fl_Group.H>
#include <FL/Fl_Widget.H>
#include <FL/Fl_Button.H>
#include <FL/Fl_Box.H>
#include <FL/Fl_Output.H>

/* Run the event loop for wtime seconds. The original looped on FLTK 1.0's
 * Fl::wait(double), which returned the time left; later FLTK versions do not,
 * so wait for a timeout instead. */
static void fl_sleep_done(void *done) { *(int *)done = 1; }
inline void fl_sleep(double wtime)
{
  int done = 0;

  Fl::add_timeout(wtime, fl_sleep_done, &done);
  while (!done)
    Fl::wait();
}

/* flboxtype.cc (added by the reconstruction): FLTK 1.0's inactive boxes */
void fl10_boxtypes(void);

#endif /* SYS_CTRL_L3_GUI_FL_H */
