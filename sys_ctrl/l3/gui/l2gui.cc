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
#include "../main/SysCfg.h"
}
#include "l2gui.h"
#include "config.h"
#include "l2comm.h"
#include "stdbuf.h"   /* (new) */

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

  stdout_buffered();
  myname = argv[0];
  sigaction(SIGSEGV, NULL, &sa);
  sa.sa_handler = oops_handler;
  sigaction(SIGSEGV, &sa, NULL);
  if (sn1SCParseCmdline(&argc, argv) < 0) {
    fprintf(stderr, "%s: error while parsing library command arguments\n", myname);
    exit(-1);
  }
  /* The original's FLTK (FLNX, on Nano-X) asked for Arial TrueType fonts the
   * L2 never had, so it drew everything in Nano-X's 13-pixel System font.
   * FLTK's size 12 is the nearest match (the layouts assume it). */
  FL_NORMAL_SIZE = 12;
  fl10_boxtypes();
  gui_init();
  config_init("r * s *");
  l2comm_init();
  return Fl::run();
}

/* The original's windows were Nano-X windows on a 320x240 screen (the L2's
 * panel, or one X window on a workstation). Here that screen is a top-level
 * window and each l2gui window is a subwindow of it, at the same coordinates. */
static Fl_Window *screen;

static void screen_cb(Fl_Widget *w, void *data)
{
  if (Fl::event() == FL_SHORTCUT && Fl::event_key() == FL_Escape)
    mainwin->do_callback();     /* as when the main window was a top-level window */
  else
    exit(0);                    /* closed: the original lost its X connection */
}

void l2gui_add(Fl_Window *w)
{
  if (screen == NULL) {
    screen = new Fl_Window(320, 240, "L2 Controller GUI");
    screen->end();
    screen->callback(screen_cb);
  }
  screen->add(w);
}

/* Show a window on top of the others. FLTK offers a click to the screen's
 * subwindows from the last child back, so the window shown last must be the
 * last child, as it is the topmost window drawn. */
void l2gui_show(Fl_Window *w)
{
  screen->add(w);
  w->show();
}

static int gui_init(void)
{
  destwin_init();
  logowin_init();
  graphwin_init();
  cmdwin_init();
  mainwin_init();
  screen->show();
  return 0;
}
