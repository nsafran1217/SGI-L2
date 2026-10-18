/*
 * sys_ctrl/l3/gui/logowin.cc
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/logowin.cc
 *
 * The "screen saver": a full-screen SGI logo, dismissed by a touch.
 */

#include "l2gui.h"
#include "ui/logowin.cxx"

int logowin_init(void)
{
  logowin = make_logowin();
  logowin->hide();
  return 0;
}
