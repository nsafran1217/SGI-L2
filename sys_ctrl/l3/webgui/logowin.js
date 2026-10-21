/*
 * sys_ctrl/l3/webgui/logowin.js
 *
 * New in the modern tree: gui/logowin.cc and ui/logowin.fl for the web
 * l2gui. The "screen saver": a full-screen SGI logo, dismissed by a touch.
 */

import { Box, Button, Window, FL_NO_BOX } from "./fl.js";
import { images } from "./l2gui.js";

export let logowin = null;

function make_logowin() {
  const w = new Window(0, 0, 320, 240, "Screen Saver (SGI Logo...)").set({ color: 7, selectionColor: 7 });

  w.add(new Box(0, 0, 320, 240).set({ image: images.sgilogo }),
    new Button(0, 0, 320, 265).set({ box: FL_NO_BOX, callback: () => logowin.hide() }));
  return w;
}

export function logowin_init() {
  logowin = make_logowin();
}
