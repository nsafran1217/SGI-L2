/*
 * sys_ctrl/l3/webgui/l2comm.js
 *
 * New in the modern tree: gui/l2comm.cc for the web l2gui. The L2 comes
 * through l2api: its server-sent events give the configuration (SysCfg's
 * L2 and L1 lists, as "l2" and "config"), and a command goes to the L2's
 * command task as POST /api/v1/command. Paths are relative, so the page
 * also works under a reverse proxy's subdirectory.
 */

import { mainwin_actions, mainwin_update_config, mainwin_update_status } from "./mainwin.js";
import { destwin_update_config } from "./destwin.js";

/* SysCfgL2List (GET /api/v1/l2's "l2s") and SysCfgL1List ("bricks") */
export const syscfg = { l2s: [], bricks: [], connected: false };

let first = true;

/* waiting for the L2, as when (re)connecting */
function connecting() {
  syscfg.connected = false;
  mainwin_actions(0);
  mainwin_update_status(first ? "Connecting to L2 Controller..." : "Reconnecting to L2 Controller...");
}

function config_changed() {
  mainwin_update_config();
  destwin_update_config();
}

export function l2comm_init() {
  const events = new EventSource("api/v1/events");

  connecting();
  events.addEventListener("config", e => {
    syscfg.bricks = JSON.parse(e.data).bricks;
    if (syscfg.connected)
      config_changed();
  });
  events.addEventListener("l2", e => {
    const l2 = JSON.parse(e.data);

    syscfg.l2s = l2.l2s;
    if (!l2.connected) {
      connecting();
      return;
    }
    syscfg.connected = true;
    first = false;
    config_changed();
  });
  /* (the browser reconnects by itself) */
  events.onerror = () => connecting();
}

/* a text command to the L2's command task: resolves to its status, or
 * rejects with the reason it could not be sent */
export async function l2comm_send_text_command(cmd) {
  let r, reply;

  try {
    r = await fetch("api/v1/command", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ command: cmd }),
    });
    reply = await r.json();
  }
  catch (e) {
    throw new Error("can't reach l2api");
  }
  if (typeof reply.status !== "number")
    throw new Error(reply.error || `HTTP ${r.status}`);
  return reply;
}
