/*
 * sys_ctrl/l3/gui/mainwin.cc
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/mainwin.cc
 *
 * The main window: L2 status and power summary for the current destination,
 * and the power/reset/NMI buttons.
 */

#include <stdio.h>
#include <string.h>
extern "C" {
#include "../main/SysCfg.h"
#include "../../common/Router/Socket.h"
}
#include "l2gui.h"
#include "config.h"
#include <FL/fl_message.H>

char current_dest_label[100];

static void power_up_cb(Fl_Button *btn, void *data);
static void power_down_cb(Fl_Button *btn, void *data);
static void reset_cb(Fl_Button *btn, void *data);
static void nmi_cb(Fl_Button *btn, void *data);
#include "ui/mainwin.cxx"

char status_buf[200];
uint32_t my_ip;
char firmware_version[30];

int mainwin_init(void)
{
  char *myhost;

  if (SocketGetHostName(&myhost) == -1)
    myhost = "localhost";
  SocketGetAddr(myhost, &my_ip);
  firmware_version[0] = '\0';
  mainwin = make_mainwin();
  current_dest->label(current_dest_label);
  mainwin_update_config();
  mainwin->show();
  mainwin_actions(0);
  return 0;
}

int mainwin_update_dest(char *dest)
{
  mainwin_update_config();
  return 0;
}

int mainwin_update_status(char *statmsg)
{
  strcpy(status_buf, statmsg);
  status->value(status_buf);
  status->redraw();
  return 0;
}

int mainwin_update_config(void)
{
  char buf[200];
  char tstr[50] = "";
  char nstr[50] = "";
  char rstr[50] = "";
  char pwrstr[50] = "";
  L2Cfg *myl2;
  int power_on, power_off, power_other;
  int i, bcnt;
  char *rptr;

  myl2 = SysCfgL2List[0];
  power_on = 0;
  power_off = 0;
  power_other = 0;
  if (myl2 == NULL)
    mainwin_actions(0);
  else
    mainwin_actions(!myl2->l2dsp_disabled);

  if (firmware_version[0] == '\0')
    sprintf(tstr, "SGI L2 Controller\n");
  else
    /* never: nothing sets firmware_version. %.19s keeps tstr[50] from overflowing */
    sprintf(tstr, "SGI L2 Controller, Firmware v%.19s\n", firmware_version);
  if (SysCfgL2Count > 0) {
    if (myl2->sysname[0] != '\0')
      sprintf(nstr, " [%s]", myl2->sysname);
    if (myl2->rack == 0)
      sprintf(rstr, "%s", SocketAddrStr(myl2->net.ip_addr == 0x7f000001 ? my_ip : myl2->net.ip_addr));
    else
      sprintf(rstr, "%03d", myl2->rack);
    sprintf(buf, "%sL2-%s  S/N %s%s", tstr, rstr, myl2->ssn[0] ? myl2->ssn : "<not set>", nstr);
  }
  else {
    sprintf(buf, "%sConnecting to the L2 Controller...", tstr);
  }

  for (i = 0; i < SysCfgL1Count; i++) {
    L2CfgL1 *l1 = SysCfgL1List[i];
    int state = l1->power_state;

    if (config_dest_includes_l1(l1)) {
      switch (state) {
      case 0:
        power_off++;
        break;
      case 1:
        power_on++;
        break;
      case -1:          /* never matches: power_state is unsigned */
        power_other++;
        break;
      }
    }
  }
  if (power_off + power_on + power_other == 0)
    sprintf(pwrstr, "Power: <no Bricks>");
  else if (power_off + power_other == 0)
    sprintf(pwrstr, "Power: ON");
  else if (power_on + power_other == 0)
    sprintf(pwrstr, "Power: OFF");
  else if (power_on + power_off == 0)
    sprintf(pwrstr, "Power: UNKNOWN (for all %d Bricks)", power_other);
  else {
    rptr = pwrstr;
    strcpy(rptr, "Power: ");
    rptr += strlen(rptr);
    if (power_on || power_off) {
      sprintf(rptr, "%d bricks ON, %d OFF", power_on, power_off);
      rptr += strlen(rptr);
    }
    if (power_other)
      sprintf(rptr, ",%d UNKNOWN", power_other);
  }
  strcat(buf, "\n\n");
  strcat(buf, pwrstr);
  mainwin_update_status(buf);

  bcnt = 0;
  for (i = 0; i < SysCfgL1Count; i++)
    if (config_dest_includes_l1(SysCfgL1List[i]))
      bcnt++;
  sprintf(current_dest_label, "%s   [%d Bricks]", config_command_dest(), bcnt);
  mainwin->redraw();
  return 0;
}

/* enable or disable the controls (disabled while not connected, or when the
 * L2 display is locked); returns 1 if that changed anything */
int mainwin_actions(int enable)
{
  static int cur_enable = 1;

  if (cur_enable == enable)
    return 0;
  if (enable) {
    control_area->activate();
  }
  else {
    destwin->hide();
    graphwin->hide();
    cmdwin->hide();
    mainwin->activate();
    control_area->deactivate();
  }
  cur_enable = enable;
  return 1;
}

static void power_up_cb(Fl_Button *btn, void *data)
{
  cmdwin_do_command("power up", config_command_dest());
}

static void power_down_cb(Fl_Button *btn, void *data)
{
  cmdwin_do_command("power down", config_command_dest());
}

static void reset_cb(Fl_Button *btn, void *data)
{
  cmdwin_do_command("reset", config_command_dest());
}

static void nmi_cb(Fl_Button *btn, void *data)
{
  cmdwin_do_command("nmi", config_command_dest());
}
