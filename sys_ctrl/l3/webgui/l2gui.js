/*
 * sys_ctrl/l3/webgui/l2gui.js
 *
 * New in the modern tree: gui/l2gui.cc for the web. l2gui, the L2
 * controller's touch-screen GUI (320x240), in a browser page served by
 * l2api --www: the same windows, drawn as SGI's drew them.
 */

import { attach, parseXpm } from "./fl.js";
import { config_init } from "./config.js";
import { cmdwin_init } from "./cmdwin.js";
import { destwin_init } from "./destwin.js";
import { l2comm_init } from "./l2comm.js";
import { logowin_init } from "./logowin.js";
import { mainwin_init } from "./mainwin.js";

/* the logos, from gui/ui/images */
export const images = {};

function gui_init() {
  destwin_init();
  logowin_init();
  cmdwin_init();
  mainwin_init();
}

async function main() {
  for (const name of ["sgilogo", "sgilogo_tiny"])
    images[name] = parseXpm(await (await fetch(`images/${name}.xpm`)).text());
  attach(document.getElementById("screen"));
  gui_init();
  config_init("r * s *");
  l2comm_init();
}

main();
