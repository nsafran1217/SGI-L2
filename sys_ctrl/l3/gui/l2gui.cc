/*
 * sys_ctrl/l3/gui/l2gui.cc
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/l2gui.cc
 *
 * l2gui: the L2 controller's touch-screen GUI (320x240), run as an X11 client.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
extern "C" {
#include "../api/SCapi.h"
#include "../IRouter/IRouterOS.h"
#include "../main/SysCfg.h"
}
#include "l2gui.h"
#include "config.h"
#include "l2comm.h"

Fl_Window *mainwin;
Fl_Window *logowin;
Fl_Window *destwin;
Fl_Window *graphwin;
Fl_Window *cmdwin;
char *myname;

static int gui_init(void);

void oops_handler(int sig)
{
  printf("oops! received signal %d\n", sig);
  exit(2);
}

int main(int argc, char **argv)
{
  struct sigaction sa;
  int serial;

  myname = argv[0];
  sigaction(SIGSEGV, NULL, &sa);
  sa.sa_handler = oops_handler;
  sigaction(SIGSEGV, &sa, NULL);
  if (sn1SCParseCmdline(&argc, argv, &serial) < 0) {
    fprintf(stderr, "%s: error while parsing library command arguments\n", myname);
    exit(-1);
  }
  /* The original's FLTK (FLNX, on Nano-X) asked for Arial TrueType fonts the
   * L2 never had, so it drew everything in Nano-X's 13-pixel System font.
   * FLTK's size 12 is the nearest match (the layouts assume it). */
  FL_NORMAL_SIZE = 12;
  gui_init();
  config_init("r * s *");
  l2comm_init();
  return Fl::run();
}

/* Show a window at (x, y) in the main window. The original placed windows on
 * the screen, which on the L2's 320x240 panel was the main window. */
void l2gui_show(Fl_Window *w, int x, int y)
{
  w->position(mainwin->x() + x, mainwin->y() + y);
  w->show();
}

static int gui_init(void)
{
  destwin_init();
  logowin_init();
  graphwin_init();
  cmdwin_init();
  mainwin_init();
  return 0;
}
