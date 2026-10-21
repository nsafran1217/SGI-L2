/*
 * sys_ctrl/l3/webgui/mainwin.js
 *
 * New in the modern tree: gui/mainwin.cc and ui/mainwin.fl for the web
 * l2gui. The main window: L2 status and power summary for the current
 * destination, and the power/reset/NMI buttons.
 */

import {
  Box, Button, Group, Output, Window, FL_DOWN_BOX, FL_FLAT_BOX, FL_NO_BOX, FL_ROUND_DOWN_BOX,
  FL_ROUND_UP_BOX,
} from "./fl.js";
import { config_command_dest, config_dest_includes_l1 } from "./config.js";
import { cmdwin, cmdwin_do_command } from "./cmdwin.js";
import { destwin, destwin_show } from "./destwin.js";
import { logowin } from "./logowin.js";
import { syscfg } from "./l2comm.js";
import { images } from "./l2gui.js";

export let mainwin = null;
let control_area, status, current_dest;
let cur_enable = 1;

function make_mainwin() {
  const round = { box: FL_ROUND_UP_BOX, downBox: FL_ROUND_DOWN_BOX, selectionColor: 39 };
  const w = new Window(0, 0, 320, 240, "L2 Controller GUI").set({ box: FL_NO_BOX });

  control_area = new Group(-1, 64, 323, 176).set({ box: FL_FLAT_BOX, color: 45 });
  const hidden = (x, y, wd, label) => {
    const b = new Button(x, y, wd, 25, label).set(round);
    b.visible = b.active = false;
    return b;
  };
  current_dest = new Box(67, 214, 251, 21, "r * s *").set({ align: 20 });
  control_area.add(
    new Button(15, 74, 98, 25, "Power UP").set({ ...round, callback: power_up_cb }),
    new Button(15, 107, 98, 25, "Power DOWN").set({ ...round, callback: power_down_cb }),
    new Button(15, 140, 98, 25, "RESET").set({ ...round, callback: reset_cb }),
    new Button(15, 174, 98, 25, "NMI").set({ ...round, callback: nmi_cb }),
    /* (shown in no version: graphwin, a demo, is not part of this one) */
    hidden(142, 74, 159, "System Info..."),
    hidden(142, 107, 159, "Warnings/Faults..."),
    hidden(142, 140, 157, "L1/L2 Logs..."),
    hidden(142, 174, 157, "Performance Graphs..."),
    current_dest,
    new Button(2, 213, 62, 25, "DEST:").set({
      downBox: FL_DOWN_BOX, selectionColor: 39, callback: () => destwin_show(1),
    }));
  status = new Output(0, 0, 242, 64).set({ box: FL_FLAT_BOX, selectionColor: 7 });
  w.add(control_area, status,
    new Button(242, 0, 80, 64).set({
      box: FL_FLAT_BOX, downBox: FL_FLAT_BOX, color: 7, selectionColor: 7, labelcolor: 7,
      image: images.sgilogo_tiny, callback: () => logowin.show(),
    }));
  return w;
}

export function mainwin_init() {
  mainwin = make_mainwin();
  mainwin_update_config();
  mainwin.show();
  mainwin_actions(0);
}

export function mainwin_update_dest(dest) {
  mainwin_update_config();
}

export function mainwin_update_status(statmsg) {
  status.value(statmsg);
}

export function mainwin_update_config() {
  const myl2 = syscfg.l2s.length > 0 ? syscfg.l2s[0] : null;
  let buf, nstr = "", rstr, pwrstr;
  let power_on = 0, power_off = 0;

  /* (with no connection, the controls stay off: the original's list was
   * empty then) */
  mainwin_actions(myl2 === null || !syscfg.connected ? 0 : !myl2.display_disabled);
  const tstr = "SGI L2 Controller\n";
  if (myl2 !== null) {
    if (myl2.sysname !== "")
      nstr = ` [${myl2.sysname}]`;
    rstr = myl2.rack === 0 ? myl2.ip : String(myl2.rack).padStart(3, "0");
    buf = `${tstr}L2-${rstr}  S/N ${myl2.serial !== "" ? myl2.serial : "<not set>"}${nstr}`;
  }
  else
    buf = `${tstr}Connecting to the L2 Controller...`;

  for (const l1 of syscfg.bricks)
    if (config_dest_includes_l1(l1)) {
      if (l1.power)
        power_on++;
      else
        power_off++;
    }
  if (power_off + power_on === 0)
    pwrstr = "Power: <no Bricks>";
  else if (power_off === 0)
    pwrstr = "Power: ON";
  else if (power_on === 0)
    pwrstr = "Power: OFF";
  else
    pwrstr = `Power: ${power_on} bricks ON, ${power_off} OFF`;
  if (syscfg.connected)
    mainwin_update_status(`${buf}\n\n${pwrstr}`);

  const bcnt = syscfg.bricks.filter(config_dest_includes_l1).length;
  current_dest.setLabel(`${config_command_dest()}   [${bcnt} Bricks]`);
}

/* enable or disable the controls (disabled while not connected, or when the
 * L2 display is locked); returns 1 if that changed anything */
export function mainwin_actions(enable) {
  enable = enable ? 1 : 0;
  if (cur_enable === enable)
    return 0;
  if (enable)
    control_area.activate();
  else {
    destwin.hide();
    cmdwin.hide();
    mainwin.activate();
    control_area.deactivate();
  }
  cur_enable = enable;
  return 1;
}

function power_up_cb() {
  cmdwin_do_command("power up", config_command_dest());
}

function power_down_cb() {
  cmdwin_do_command("power down", config_command_dest());
}

function reset_cb() {
  cmdwin_do_command("reset", config_command_dest());
}

function nmi_cb() {
  cmdwin_do_command("nmi", config_command_dest());
}
