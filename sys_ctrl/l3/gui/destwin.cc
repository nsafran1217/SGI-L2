/*
 * sys_ctrl/l3/gui/destwin.cc
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/destwin.cc
 *
 * The destination window: pick racks and slots, or partitions, from the
 * current configuration and build a destination string ("r 1,3-5 s *").
 *
 * A selection list (CmdData rlist/slist/plist, filled by the L2's command
 * parser) has one byte per rack, slot or partition: 0 not selected,
 * 1 selected alone, 2 first of a range, 3 inside a range, 4 last of a range;
 * 5 in the first byte means all.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
extern "C" {
#include "../../common/sys/Cmd.h"
#include "../../common/sys/Logger.h"
#include "../main/SysCfg.h"
}
#include "l2gui.h"
#include "config.h"

typedef char labelstr[4];

static void rackpart_rack_cb(Fl_Button *btn, void *user_data);
static void rackpart_part_cb(Fl_Button *btn, void *user_data);
static void rackpart_all_cb(Fl_Button *btn, void *user_data);
static void rackpart_clr_cb(Fl_Button *btn, void *user_data);
static void rackpart_prev_cb(Fl_Button *btn, void *user_data);
static void rackpart_next_cb(Fl_Button *btn, void *user_data);
static void rackpart_button_cb(Fl_Button *btn, void *data);
static void slot_all_cb(Fl_Button *btn, void *user_data);
static void slot_clr_cb(Fl_Button *btn, void *user_data);
static void slot_button_cb(Fl_Button *btn, void *data);
static void apply_button_cb(Fl_Button *btn, void *data);
static void cancel_button_cb(Fl_Button *btn, void *data);
static void reset_button_cb(Fl_Button *btn, void *data);
#include "ui/destwin.cxx"

#define NRACKBTN 12
#define NSLOTBTN 20

static Fl_Button **rack_buttons[NRACKBTN] = {
  &rack0, &rack1, &rack2, &rack3, &rack4, &rack5,
  &rack6, &rack7, &rack8, &rack9, &rack10, &rack11,
};
static labelstr rack_labels[NRACKBTN] = {
  "000", "001", "002", "003", "004", "005", "006", "007",
};
static Fl_Button **slot_buttons[NSLOTBTN] = {
  &slot0, &slot1, &slot2, &slot3, &slot4, &slot5, &slot6, &slot7, &slot8, &slot9,
  &slot10, &slot11, &slot12, &slot13, &slot14, &slot15, &slot16, &slot17, &slot18, &slot19,
};
static labelstr slot_labels[NSLOTBTN] = {
  "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
  "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
};
static int first_rack;                  /* first rack (partition) shown on the buttons */
static int first_part;
static int dest_mode_rack = 1;          /* 1: racks and slots, 0: partitions */

static char dest_result_label[100];
static int config_changed;
static CmdData dest_data;
/* the configuration's racks (sorted), each rack's slots, and the partitions */
static int racklist[128];
static int numracks;
static int rackidx[256];                /* rack number -> racklist index */
static int slotlist[128][40];
static int numslots[128];
static int partlist[256];
static int numparts;

static int set_dest(char *dest);
static int update_dest(void);

int destwin_init(void)
{
  int i;

  destwin = make_destwin();
  for (i = 0; i < NRACKBTN; i++)
    (*rack_buttons[i])->label(rack_labels[i]);
  for (i = 0; i < NSLOTBTN; i++)
    (*slot_buttons[i])->label(slot_labels[i]);
  dest_result->label(dest_result_label);
  destwin->hide();
  set_dest("r * s *");
  destwin_update_config();
  return 0;
}

int destwin_show(int cmd)
{
  set_dest(config_command_dest());
  if (config_changed)
    update_dest();
  l2gui_show(destwin, 0, 0);
  reset_btn->deactivate();
  return 0;
}

/* index of the first selected entry, or -1 */
static int popfirst(char *s, int slen)
{
  int i = 0;

  while (slen--) {
    if (*s)
      return i;
    i++;
    s++;
  }
  return -1;
}

/* unused. ORIGINAL BUG: plist has 64 entries, not 256 */
static int dest_is_rack(void)
{
  return config_popcnt(dest_data.plist, 256) != 0;
}

/* a selection list as text: "*", "<none>" or "1,3-5,7" */
static char *dest_text(char *list, int len)
{
  static char dest[200];
  char *dptr = dest;
  int i;

  if (list[0] == 5) {
    strcpy(dest, "*");
  }
  else if (config_popcnt(list, len) == 0) {
    strcpy(dest, "<none>");
  }
  else {
    for (i = 0; i < len; i++) {
      switch (list[i]) {
      case 1:
      case 2:
        if (dptr != dest)
          *dptr++ = ',';
        sprintf(dptr, "%d", i);
        dptr += strlen(dptr);
        break;
      case 4:
        sprintf(dptr, "-%d", i);
        dptr += strlen(dptr);
        break;
      }
    }
  }
  return dest;
}

static int remove_dest(char *list, int len, int idx)
{
  if (list[idx] == 2 || list[idx] == 3) {
    /* the entry after it starts the rest of the range */
    if (list[idx + 1] == 3)
      list[idx + 1] = 2;
    else if (list[idx + 1] == 4)
      list[idx + 1] = 1;
    list[idx] = 0;
  }
  /* ORIGINAL BUG: meant to end the range at the entry before it (3 or 4),
   * but tests 2 or 3 again, which the block above has just cleared */
  if (list[idx] == 2 || list[idx] == 3) {
    if (list[idx - 1] == 3)
      list[idx - 1] = 4;
    else if (list[idx - 1] == 2)
      list[idx - 1] = 1;
  }
  list[idx] = 0;
  return 0;
}

static int set_dest(char *dest)
{
  config_parse_dest(dest, &dest_data);
  return update_dest();
}

/* insert item into the sorted list; returns 0 if it was there already (or
 * is 0), 1 if appended, 2 if inserted before existing entries */
static int list_insert(int item, int *list, int *lcnt, int *item_idx)
{
  int rval = 1;
  int i;

  if (item == 0)
    return 0;
  for (i = 0; i < *lcnt && list[i] < item; i++)
    ;
  if (i < *lcnt && item < list[i]) {
    memmove(&list[i + 1], &list[i], (*lcnt - i) * sizeof(*list));
    rval = 2;
  }
  if (item == list[i]) {
    *item_idx = i;
    rval = 0;
  }
  else {
    list[i] = item;
    *item_idx = i;
    (*lcnt)++;
  }
  return rval;
}

int destwin_update_config(void)
{
  int i, lsize, junk_idx;
  int idx = 0;  /* ORIGINAL BUG: uninitialized, and list_insert leaves it unset for rack 0 */
  int rack, slot, part;

  numracks = 0;
  memset(numslots, 0, sizeof(numslots));
  numparts = 0;
  memset(racklist, -1, sizeof(racklist));
  memset(rackidx, -1, sizeof(rackidx));
  memset(slotlist, -1, sizeof(slotlist));
  memset(partlist, -1, sizeof(partlist));
  lsize = SysCfgL1Count;
  for (i = 0; i < lsize; i++) {
    rack = SysCfgL1List[i]->rack;
    slot = SysCfgL1List[i]->slot;
    part = SysCfgL1List[i]->partition;
    if (list_insert(rack, racklist, &numracks, &idx) == 2) {
      /* a new rack before others: shift their slot lists too */
      memmove(slotlist[idx + 1], slotlist[idx], (127 - idx) * sizeof(slotlist[0]));
      memset(slotlist[idx], -1, sizeof(slotlist[0]));
      memmove(&numslots[idx + 1], &numslots[idx], (127 - idx) * sizeof(numslots[0]));
      numslots[idx] = 0;
    }
    list_insert(slot, slotlist[idx], &numslots[idx], &junk_idx);
    list_insert(part, partlist, &numparts, &junk_idx);
  }
  for (i = 0; i < numracks; i++)
    rackidx[racklist[i]] = i;
  first_rack = 0;
  first_part = 0;
  if (destwin && destwin->visible_r())
    return update_dest();
  config_changed = 1;
  return 0;
}

/* show the buttons for list[first..], labelled and set from the selection list */
static int update_buttonlist(Fl_Button ***buttons, labelstr *labels, int bcnt, int first,
                             int *list, int lcnt, char *sellist, Fl_Button *allbtn,
                             Fl_Button *revbtn, Fl_Button *fwdbtn)
{
  int i;

  for (i = 0; i < bcnt; i++) {
    if (i + first < lcnt) {
      (*buttons[i])->show();
      sprintf(labels[i], "%03d", list[i + first]);
      if (sellist[0] == 5 || sellist[list[first + i]] == 0)
        (*buttons[i])->value(0);
      else
        (*buttons[i])->value(1);
      (*buttons[i])->user_data((void *)(intptr_t)list[i + first]);
    }
    else {
      (*buttons[i])->hide();
    }
  }
  if (revbtn) {
    if (first > 0)
      revbtn->activate();
    else
      revbtn->deactivate();
  }
  if (fwdbtn) {
    if (first + bcnt < lcnt)
      fwdbtn->activate();
    else
      fwdbtn->deactivate();
  }
  if (allbtn)
    allbtn->value(sellist[0] == 5);
  return 0;
}

static int update_dest(void)
{
  char *rptr;
  int selidx;
  int i;

  if (dest_mode_rack) {
    rackpart_rack->value(1);
    rackpart_part->value(0);
    slot_area->show();
    if (config_popcnt(dest_data.rlist, 256) == 1) {
      /* one rack: offer its slots */
      selidx = rackidx[popfirst(dest_data.rlist, 256)];
      if (selidx == -1) {
        /* ORIGINAL BUG: the rack number argument is missing */
        fprintf(stderr, "ERROR!! selected rack (%d) is not part of current config!\n",
                popfirst(dest_data.rlist, 256));
        selidx = 0;
      }
      update_buttonlist(slot_buttons, slot_labels, NSLOTBTN, 0, slotlist[selidx],
                        numslots[selidx], dest_data.slist, slot_all, NULL, NULL);
      slot_area->activate();
    }
    else {
      slot_all->value(1);
      for (i = 0; i < NSLOTBTN; i++) {
        slot_labels[i][0] = '\0';
        (*slot_buttons[i])->value(0);
        (*slot_buttons[i])->show();
      }
      slot_area->deactivate();
    }
    update_buttonlist(rack_buttons, rack_labels, NRACKBTN, first_rack, racklist, numracks,
                      dest_data.rlist, rackpart_all, rackpart_prev, rackpart_next);
    strcpy(dest_result_label, "r ");
    rptr = dest_result_label + strlen(dest_result_label);
    strcpy(rptr, dest_text(dest_data.rlist, 256));
    rptr += strlen(rptr);
    strcpy(rptr, " s ");
    rptr += strlen(rptr);
    strcpy(rptr, dest_text(dest_data.slist, 64));
  }
  else {
    rackpart_part->value(1);
    rackpart_rack->value(0);
    slot_area->hide();
    update_buttonlist(rack_buttons, rack_labels, NRACKBTN, first_part, partlist, numparts,
                      dest_data.plist, rackpart_all, rackpart_prev, rackpart_next);
    strcpy(dest_result_label, "p ");
    rptr = dest_result_label + strlen(dest_result_label);
    strcpy(rptr, dest_text(dest_data.plist, 64));
  }
  if (strcmp(dest_result_label, config_command_dest()) == 0)
    reset_btn->deactivate();
  else
    reset_btn->activate();
  destwin->redraw();
  return 0;
}

static void rackpart_rack_cb(Fl_Button *btn, void *user_data)
{
  dest_mode_rack = 1;
  update_dest();
}

static void rackpart_part_cb(Fl_Button *btn, void *user_data)
{
  dest_mode_rack = 0;
  update_dest();
}

static void rackpart_all_cb(Fl_Button *btn, void *user_data)
{
  int fillval = btn->value() == 1 ? 5 : 0;

  if (dest_mode_rack) {
    memset(dest_data.rlist, fillval, sizeof(dest_data.rlist));
    if (fillval)
      memset(dest_data.slist, fillval, sizeof(dest_data.slist));
  }
  else {
    memset(dest_data.plist, fillval, sizeof(dest_data.plist));
  }
  update_dest();
}

static void rackpart_clr_cb(Fl_Button *btn, void *user_data)
{
  rackpart_all->value(0);
  if (dest_mode_rack)
    memset(dest_data.rlist, 0, sizeof(dest_data.rlist));
  else
    memset(dest_data.plist, 0, sizeof(dest_data.plist));
  update_dest();
}

static void rackpart_prev_cb(Fl_Button *btn, void *user_data)
{
  int *first_p = dest_mode_rack ? &first_rack : &first_part;

  *first_p -= NRACKBTN;
  if (*first_p < 0)
    *first_p = 0;
  update_dest();
}

static void rackpart_next_cb(Fl_Button *btn, void *user_data)
{
  int *first_p = dest_mode_rack ? &first_rack : &first_part;
  int count = dest_mode_rack ? numracks : numparts;
  int last = count / NRACKBTN * NRACKBTN;

  *first_p = *first_p + NRACKBTN < last ? *first_p + NRACKBTN : last;
  update_dest();
}

static void rackpart_button_cb(Fl_Button *btn, void *data)
{
  int selecting = btn->value();
  int n = (int)(intptr_t)data;          /* the rack (partition) number */

  if (dest_mode_rack) {
    if (selecting) {
      if (dest_data.rlist[0] == 5)
        memset(dest_data.rlist, 0, sizeof(dest_data.rlist));
      dest_data.rlist[n] = 1;
    }
    else {
      remove_dest(dest_data.rlist, 256, n);
    }
  }
  else {
    if (selecting) {
      if (dest_data.plist[0] == 5)
        memset(dest_data.plist, 0, sizeof(dest_data.plist));
      dest_data.plist[n] = 1;
    }
    else {
      remove_dest(dest_data.plist, 64, n);
    }
  }
  if (config_popcnt(dest_data.rlist, 256) != 1)
    memset(dest_data.slist, 5, sizeof(dest_data.slist));
  update_dest();
}

static void slot_all_cb(Fl_Button *btn, void *user_data)
{
  int fillval = btn->value() == 1 ? 5 : 0;

  memset(dest_data.slist, fillval, sizeof(dest_data.slist));
  update_dest();
}

static void slot_clr_cb(Fl_Button *btn, void *user_data)
{
  slot_all->value(0);
  memset(dest_data.slist, 0, sizeof(dest_data.slist));
  update_dest();
}

static void slot_button_cb(Fl_Button *btn, void *data)
{
  int slot = (int)(intptr_t)data;

  if (btn->value()) {
    if (dest_data.slist[0] == 5)
      memset(dest_data.slist, 0, sizeof(dest_data.slist));
    dest_data.slist[slot] = 1;
  }
  else {
    remove_dest(dest_data.slist, 64, slot);
  }
  update_dest();
}

static void apply_button_cb(Fl_Button *btn, void *data)
{
  config_set_command_dest(dest_result_label);
  destwin->hide();
}

static void cancel_button_cb(Fl_Button *btn, void *data)
{
  destwin->hide();
}

static void reset_button_cb(Fl_Button *btn, void *data)
{
  set_dest(config_command_dest());
}
