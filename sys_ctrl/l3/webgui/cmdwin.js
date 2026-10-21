/*
 * sys_ctrl/l3/webgui/cmdwin.js
 *
 * New in the modern tree: gui/cmdwin.cc and ui/cmdwin.fl for the web
 * l2gui. The command window: asks for confirmation, sends the command to
 * the L2 and reports an error, if any.
 */

import { Button, Output, Window, FL_FLAT_BOX, FL_ROUND_DOWN_BOX, FL_ROUND_UP_BOX } from "./fl.js";
import { mainwin } from "./mainwin.js";
import { l2comm_send_text_command } from "./l2comm.js";

export let cmdwin = null;
let cmdtxt, ok_button, cancel_button;
let current_command = "";

function make_cmdwin() {
  const round = { box: FL_ROUND_UP_BOX, downBox: FL_ROUND_DOWN_BOX };
  const w = new Window(0, 64, 320, 176, "Command Window");

  w.modal = true;
  cmdtxt = new Output(14, 10, 291, 125).set({ box: FL_FLAT_BOX, color: 49 });
  ok_button = new Button(48, 145, 110, 25, "OK").set(round);
  cancel_button = new Button(178, 145, 110, 25, "Cancel").set({ ...round, callback: cmdwin_hide });
  w.add(cmdtxt, ok_button, cancel_button);
  return w;
}

export function cmdwin_init() {
  cmdwin = make_cmdwin();
}

export function cmdwin_do_command(command, dest) {
  current_command = `${dest} ${command}`;
  start_command();
}

function cmdwin_show() {
  ok_button.activate();
  cancel_button.activate();
  mainwin.deactivate();
  cmdwin.show();
}

function cmdwin_hide() {
  cmdwin.hide();
  mainwin.activate();
}

function start_command() {
  cmdtxt.value(`Press the "OK" button to issue the\n"${current_command}" command.\n`);
  ok_button.callback = do_command;
  cmdwin_show();
}

async function do_command() {
  let reply;

  ok_button.deactivate();
  try {
    reply = await l2comm_send_text_command(current_command);
  }
  catch (e) {
    command_error(e.message);
    return;
  }
  command_done(reply);
}

/* (as in the original, an error the L2 answers with is shown and at once
 * hidden with the window) */
function command_done(reply) {
  if (reply.status !== 0)
    command_error(reply.message);
  cmdwin_hide();
}

function command_error(message) {
  cmdtxt.value(`ERROR sending "${current_command}" command:\n\n${message}\n`);
  ok_button.activate();
  ok_button.callback = cmdwin_hide;
  cancel_button.deactivate();
}
