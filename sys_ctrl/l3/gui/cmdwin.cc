/*
 * sys_ctrl/l3/gui/cmdwin.cc
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/cmdwin.cc
 *
 * The command window: asks for confirmation, sends the command to the L2 and
 * reports an error, if any.
 */

#include <stdio.h>
#include <string.h>
extern "C" {
#include "../main/SysCfg.h"
#include "../../common/sys/Logger.h"
}
#include "l2gui.h"
#include "l2comm.h"

static void cancel_button_cb(Fl_Button *btn, void *data);
#include "ui/cmdwin.cxx"

static char current_command[200];
char cmdwin_buf[300];

static void cmdwin_show(void);
static void cmdwin_hide(void);
static int start_command(void);
static int do_command(void);
static int command_done(IRPacket *pkt, void *data);
static int command_error(int err);
static void ok_button_continue_cb(Fl_Button *btn, void *data);
static void ok_button_done_cb(Fl_Button *btn, void *data);

int cmdwin_init(void)
{
  cmdwin = make_cmdwin();
  l2gui_add(cmdwin);
  /* FLTK only honours modal top-level windows; the main window is
   * deactivated while this one is up, which has the same effect */
  cmdwin->clear_modal_states();
  return 0;
}

int cmdwin_do_command(char *command, char *dest)
{
  if (cmdwin == NULL) {
    cmdwin = make_cmdwin();
    l2gui_add(cmdwin);
    cmdwin->clear_modal_states();
  }
  strcpy(current_command, dest);
  strcat(current_command, " ");
  strcat(current_command, command);
  return start_command();
}

static void cmdwin_show(void)
{
  ok_button->activate();
  cancel_button->activate();
  mainwin->deactivate();
  mainwin->redraw();
  l2gui_show(cmdwin);
}

static void cmdwin_hide(void)
{
  cmdwin->hide();
  mainwin->activate();
  mainwin->redraw();
}

static int start_command(void)
{
  sprintf(cmdwin_buf, "Press the \"OK\" button to issue the\n\"%s\" command.\n", current_command);
  cmdtxt->value(cmdwin_buf);
  ok_button->callback((Fl_Callback *)ok_button_continue_cb);
  cmdwin_show();
  return 0;
}

static int do_command(void)
{
  int rval;

  ok_button->deactivate();
  ok_button->redraw();
  rval = l2comm_send_text_command(current_command, command_done, NULL);
  if (rval < 0)
    command_error(rval);
  return 0;
}

static int command_done(IRPacket *pkt, void *data)
{
  int rval;

  rval = pkt->_err;
  if (rval == 0)
    rval = (pkt->_argv[0]._clas & 7) == 0 ? (int)pkt->_argv[0]._val : (int)IRArg(pkt, 0);
  if (rval != 0)
    command_error(rval);
  SysCfgConnRequest(NULL, myname);
  cmdwin_hide();
  return 0;
}

static int command_error(int err)
{
  sprintf(cmdwin_buf, "ERROR sending \"%s\" command:\n\n%s\n", current_command,
          LoggerDefaultMessage(err));
  cmdtxt->value(cmdwin_buf);
  cmdtxt->redraw();
  ok_button->activate();
  ok_button->redraw();
  ok_button->callback((Fl_Callback *)ok_button_done_cb);
  cancel_button->deactivate();
  cancel_button->redraw();
  SysCfgConnRequest(NULL, myname);
  return 0;
}

static void ok_button_continue_cb(Fl_Button *btn, void *data)
{
  do_command();
}

static void ok_button_done_cb(Fl_Button *btn, void *data)
{
  cmdwin_hide();
}

static void cancel_button_cb(Fl_Button *btn, void *data)
{
  cmdwin_hide();
}
