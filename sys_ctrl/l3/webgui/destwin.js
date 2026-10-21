/*
 * sys_ctrl/l3/webgui/destwin.js
 *
 * New in the modern tree: gui/destwin.cc and ui/destwin.fl for the web
 * l2gui. The destination window: pick racks and slots, or partitions,
 * from the current configuration and build a destination string
 * ("r 1,3-5 s *").
 *
 * A selection list (CmdData rlist/slist/plist) has one entry per rack,
 * slot or partition: 0 not selected, 1 selected alone, 2 first of a range,
 * 3 inside a range, 4 last of a range; 5 in the first entry means all.
 */

import {
  Box, Button, Group, Window, FL_DOWN_BOX, FL_EMBOSSED_FRAME, FL_FLAT_BOX, FL_NO_BOX,
  FL_RADIO_BUTTON, FL_ROUND_DOWN_BOX, FL_ROUND_UP_BOX, FL_TOGGLE_BUTTON,
} from "./fl.js";
import {
  config_command_dest, config_parse_dest, config_popcnt, config_set_command_dest, newCmdData,
} from "./config.js";
import { syscfg } from "./l2comm.js";

const NRACKBTN = 12, NSLOTBTN = 20;

export let destwin = null;
let rackpart_rack, rackpart_part, rackpart_all, rackpart_prev, rackpart_next;
let slot_area, slot_all, reset_btn, dest_result;
const rack_buttons = [], slot_buttons = [];

let first_rack = 0;             /* first rack (partition) shown on the buttons */
let first_part = 0;
let dest_mode_rack = 1;         /* 1: racks and slots, 0: partitions */
let config_changed = 0;
const dest_data = newCmdData();
/* the configuration's racks (sorted), each rack's slots, and the partitions */
let racklist = [], rackidx = new Map(), slotlist = [], partlist = [];

function make_destwin() {
  const toggle = { type: FL_TOGGLE_BUTTON, downBox: FL_DOWN_BOX, selectionColor: 7 };
  const plain = { downBox: FL_DOWN_BOX, selectionColor: 39 };
  const round = { box: FL_ROUND_UP_BOX, downBox: FL_ROUND_DOWN_BOX, selectionColor: 39 };
  const w = new Window(0, 0, 320, 240, "Destination window").set({ box: FL_NO_BOX });
  const rackpart = new Group(-1, 0, 323, 241).set({ box: FL_FLAT_BOX, color: 45 });
  const choice = new Group(1, 0, 130, 36);
  const slot_buttons_group = new Group(157, 33, 161, 135);
  const rack_buttons_group = new Group(1, 69, 130, 101);

  rackpart_rack = new Button(2, 2, 62, 32, "Rack/Slot").set({
    type: FL_RADIO_BUTTON, downBox: FL_DOWN_BOX, selectionColor: 7, callback: rackpart_rack_cb,
  });
  rackpart_rack.value(1);
  rackpart_part = new Button(65, 2, 63, 32, "Partition").set({
    type: FL_RADIO_BUTTON, downBox: FL_DOWN_BOX, selectionColor: 7, callback: rackpart_part_cb,
  });
  choice.add(rackpart_rack, rackpart_part);
  rackpart_all = new Button(2, 38, 30, 28, "ALL").set({ ...toggle, callback: rackpart_all_cb });
  rackpart_prev = new Button(66, 38, 30, 28, "<<").set({ ...plain, callback: rackpart_prev_cb });
  rackpart_next = new Button(98, 38, 30, 28, ">>").set({ ...plain, callback: rackpart_next_cb });
  slot_area = new Group(157, 1, 163, 172).set({ box: FL_EMBOSSED_FRAME });
  slot_all = new Button(224, 5, 30, 28, "ALL").set({ ...toggle, callback: slot_all_cb });
  for (let i = 0; i < NSLOTBTN; i++) {
    const b = new Button(160 + i % 5 * 32, 38 + Math.trunc(i / 5) * 34, 30, 28, String(i));
    slot_buttons.push(b.set({ ...toggle, userData: i, callback: slot_button_cb }));
  }
  slot_buttons_group.add(...slot_buttons);
  slot_area.add(new Box(160, 8, 53, 21, "Slots:").set({ align: 20 }), slot_all,
    new Button(256, 5, 30, 28, "CLR").set({ ...plain, callback: slot_clr_cb }), slot_buttons_group);
  for (let i = 0; i < NRACKBTN; i++) {
    const row = Math.trunc(i / 4);
    const b = new Button(2 + i % 4 * 32, [72, 106, 140][row], 30, row ? 29 : 28, String(i));
    rack_buttons.push(b.set({ ...toggle, userData: i, callback: rackpart_button_cb }));
  }
  rack_buttons_group.add(...rack_buttons);
  rackpart.add(new Box(1, 176, 81, 23, "New DEST:").set({ align: 20 }), choice, rackpart_all,
    new Button(34, 38, 30, 28, "CLR").set({ ...plain, callback: rackpart_clr_cb }),
    rackpart_prev, rackpart_next,
    new Button(32, 205, 64, 31, "Apply").set({ ...round, callback: apply_button_cb }),
    new Button(224, 205, 63, 31, "Cancel").set({ ...round, callback: () => destwin.hide() }),
    slot_area, rack_buttons_group);
  reset_btn = new Button(108, 205, 103, 31, "Reset DEST").set({ ...round, callback: reset_button_cb });
  dest_result = new Box(71, 176, 232, 23, "r * s *").set({ align: 20 });
  w.add(rackpart, reset_btn, dest_result);
  return w;
}

export function destwin_init() {
  destwin = make_destwin();
  rack_buttons.forEach((b, i) => b.setLabel(i < 8 ? String(i).padStart(3, "0") : ""));
  slot_buttons.forEach((b, i) => b.setLabel(String(i).padStart(2, "0")));
  set_dest("r * s *");
  destwin_update_config();
}

export function destwin_show(cmd) {
  set_dest(config_command_dest());
  if (config_changed)
    update_dest();
  destwin.show();
  reset_btn.deactivate();
}

/* index of the first selected entry, or -1 */
function popfirst(s) {
  return s.findIndex(v => v !== 0);
}

/* a selection list as text: "*", "<none>" or "1,3-5,7" */
function dest_text(list) {
  let dest = "";

  if (list[0] === 5)
    return "*";
  if (config_popcnt(list) === 0)
    return "<none>";
  for (let i = 0; i < list.length; i++)
    switch (list[i]) {
    case 1:
    case 2:
      if (dest !== "")
        dest += ",";
      dest += i;
      break;
    case 4:
      dest += `-${i}`;
      break;
    }
  return dest;
}

function remove_dest(list, idx) {
  if (list[idx] === 2 || list[idx] === 3) {
    /* the entry after it starts the rest of the range */
    if (list[idx + 1] === 3)
      list[idx + 1] = 2;
    else if (list[idx + 1] === 4)
      list[idx + 1] = 1;
    list[idx] = 0;
  }
  /* (SGI's bug, kept: meant to end the range at the entry before it, but
   * tests 2 or 3 again, which the block above has just cleared) */
  if (list[idx] === 2 || list[idx] === 3) {
    if (list[idx - 1] === 3)
      list[idx - 1] = 4;
    else if (list[idx - 1] === 2)
      list[idx - 1] = 1;
  }
  list[idx] = 0;
}

function set_dest(dest) {
  config_parse_dest(dest, dest_data);
  update_dest();
}

/* item into the sorted list (0 is never added, as numbers start at 1):
 * its index */
function list_insert(item, list) {
  let i = 0;

  while (i < list.length && list[i] < item)
    i++;
  if (item !== 0 && list[i] !== item)
    list.splice(i, 0, item);
  return i;
}

export function destwin_update_config() {
  let idx = 0;

  racklist = [];
  slotlist = [];
  partlist = [];
  for (const l1 of syscfg.bricks) {
    /* (rack 0 is not added: its slots go to the rack before it) */
    if (l1.rack !== 0) {
      const n = racklist.length;
      idx = list_insert(l1.rack, racklist);
      if (racklist.length > n)
        slotlist.splice(idx, 0, []);
    }
    if (slotlist[idx] === undefined)
      slotlist[idx] = [];
    list_insert(l1.slot, slotlist[idx]);
    list_insert(l1.partition, partlist);
  }
  rackidx = new Map(racklist.map((r, i) => [r, i]));
  first_rack = 0;
  first_part = 0;
  if (destwin && destwin.visibleR()) {
    update_dest();
    return;
  }
  config_changed = 1;
}

/* show the buttons for list[first..], labelled and set from the selection list */
function update_buttonlist(buttons, first, list, sellist, allbtn, revbtn, fwdbtn) {
  buttons.forEach((b, i) => {
    if (i + first < list.length) {
      const n = list[i + first];
      b.show();
      b.setLabel(String(n).padStart(3, "0"));
      b.value(sellist[0] === 5 || sellist[n] === 0 ? 0 : 1);
      b.userData = n;
    }
    else
      b.hide();
  });
  if (revbtn) {
    if (first > 0)
      revbtn.activate();
    else
      revbtn.deactivate();
  }
  if (fwdbtn) {
    if (first + buttons.length < list.length)
      fwdbtn.activate();
    else
      fwdbtn.deactivate();
  }
  if (allbtn)
    allbtn.value(sellist[0] === 5);
}

function update_dest() {
  let label;

  if (dest_mode_rack) {
    rackpart_rack.value(1);
    rackpart_part.value(0);
    slot_area.show();
    if (config_popcnt(dest_data.rlist) === 1) {
      /* one rack: offer its slots */
      const rack = popfirst(dest_data.rlist);
      let selidx = rackidx.get(rack);
      if (selidx === undefined) {
        console.error(`ERROR!! selected rack (${rack}) is not part of current config!`);
        selidx = 0;
      }
      update_buttonlist(slot_buttons, 0, slotlist[selidx] || [], dest_data.slist, slot_all, null, null);
      slot_area.activate();
    }
    else {
      slot_all.value(1);
      for (const b of slot_buttons) {
        b.setLabel("");
        b.value(0);
        b.show();
      }
      slot_area.deactivate();
    }
    update_buttonlist(rack_buttons, first_rack, racklist, dest_data.rlist, rackpart_all,
                      rackpart_prev, rackpart_next);
    label = `r ${dest_text(dest_data.rlist)} s ${dest_text(dest_data.slist)}`;
  }
  else {
    rackpart_part.value(1);
    rackpart_rack.value(0);
    slot_area.hide();
    update_buttonlist(rack_buttons, first_part, partlist, dest_data.plist, rackpart_all,
                      rackpart_prev, rackpart_next);
    label = `p ${dest_text(dest_data.plist)}`;
  }
  dest_result.setLabel(label);
  if (label === config_command_dest())
    reset_btn.deactivate();
  else
    reset_btn.activate();
}

function rackpart_rack_cb() {
  dest_mode_rack = 1;
  update_dest();
}

function rackpart_part_cb() {
  dest_mode_rack = 0;
  update_dest();
}

function rackpart_all_cb(btn) {
  const fillval = btn.value() === 1 ? 5 : 0;

  if (dest_mode_rack) {
    dest_data.rlist.fill(fillval);
    if (fillval)
      dest_data.slist.fill(fillval);
  }
  else
    dest_data.plist.fill(fillval);
  update_dest();
}

function rackpart_clr_cb() {
  rackpart_all.value(0);
  (dest_mode_rack ? dest_data.rlist : dest_data.plist).fill(0);
  update_dest();
}

function rackpart_prev_cb() {
  if (dest_mode_rack)
    first_rack = Math.max(first_rack - NRACKBTN, 0);
  else
    first_part = Math.max(first_part - NRACKBTN, 0);
  update_dest();
}

function rackpart_next_cb() {
  const count = dest_mode_rack ? racklist.length : partlist.length;
  const last = Math.trunc(count / NRACKBTN) * NRACKBTN;

  if (dest_mode_rack)
    first_rack = Math.min(first_rack + NRACKBTN, last);
  else
    first_part = Math.min(first_part + NRACKBTN, last);
  update_dest();
}

function rackpart_button_cb(btn, n) {
  const list = dest_mode_rack ? dest_data.rlist : dest_data.plist;

  if (btn.value()) {
    if (list[0] === 5)
      list.fill(0);
    list[n] = 1;
  }
  else
    remove_dest(list, n);
  if (config_popcnt(dest_data.rlist) !== 1)
    dest_data.slist.fill(5);
  update_dest();
}

function slot_all_cb(btn) {
  dest_data.slist.fill(btn.value() === 1 ? 5 : 0);
  update_dest();
}

function slot_clr_cb() {
  slot_all.value(0);
  dest_data.slist.fill(0);
  update_dest();
}

function slot_button_cb(btn, slot) {
  if (btn.value()) {
    if (dest_data.slist[0] === 5)
      dest_data.slist.fill(0);
    dest_data.slist[slot] = 1;
  }
  else
    remove_dest(dest_data.slist, slot);
  update_dest();
}

function apply_button_cb() {
  config_set_command_dest(dest_result.label);
  destwin.hide();
}

function reset_button_cb() {
  set_dest(config_command_dest());
}
