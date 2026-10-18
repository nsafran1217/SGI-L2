/*
 * sys_ctrl/l3/gui/flboxtype.cc
 *
 * Added by the reconstruction (not an original SGI file).
 *
 * FLTK 1.0 box drawing for the box types l2gui uses. The original's FLTK
 * (FLNX, a 1.0 port) drew an inactive widget's bevels from the inactive gray
 * ramp but filled it with its own color, so the white status area stays white
 * while the command window is up. FLTK 1.1 and later fade the fill as well.
 * The round boxes follow FLTK 1.3's fl_round_box.cxx (LGPL).
 */

#include <FL/Fl.H>
#include <FL/fl_draw.H>
#include "fl.h"

extern const uchar *fl_gray_ramp();     /* in libfltk, not in its headers */

static Fl_Box_Draw_F *up_frame, *down_frame;

static void flat_box(int x, int y, int w, int h, Fl_Color c)
{
  fl_rectf(x, y, w, h, c);
}

static void up_box(int x, int y, int w, int h, Fl_Color c)
{
  int d = Fl::box_dx(FL_UP_FRAME);

  up_frame(x, y, w, h, c);
  fl_rectf(x + d, y + d, w - 2 * d, h - 2 * d, c);
}

static void down_box(int x, int y, int w, int h, Fl_Color c)
{
  int d = Fl::box_dx(FL_DOWN_FRAME);

  down_frame(x, y, w, h, c);
  fl_rectf(x + d, y + d, w - 2 * d, h - 2 * d, c);
}

enum { UPPER_LEFT, LOWER_RIGHT, CLOSED, FILL };

static void arc(int x, int y, int w, int h, double a1, double a2)
{
  fl_arc(x, y, w, h, a1, a2);
}

static void round_part(int which, int x, int y, int w, int h, int inset, Fl_Color color)
{
  void (*f)(int, int, int, int, double, double);
  int d;

  if (inset * 2 >= w) inset = (w - 1) / 2;
  if (inset * 2 >= h) inset = (h - 1) / 2;
  x += inset;
  y += inset;
  w -= 2 * inset;
  h -= 2 * inset;
  d = w <= h ? w : h;
  if (d <= 1)
    return;
  fl_color(color);
  f = which == FILL ? fl_pie : arc;
  if (which >= CLOSED) {
    f(x + w - d, y, d, d, w <= h ? 0 : -90, w <= h ? 180 : 90);
    f(x, y + h - d, d, d, w <= h ? 180 : 90, w <= h ? 360 : 270);
  }
  else if (which == UPPER_LEFT) {
    f(x + w - d, y, d, d, 45, w <= h ? 180 : 90);
    f(x, y + h - d, d, d, w <= h ? 180 : 90, 225);
  }
  else {
    f(x, y + h - d, d, d, 225, w <= h ? 360 : 270);
    f(x + w - d, y, d, d, w <= h ? 360 : 270, 360 + 45);
  }
  if (which == FILL) {
    if (w < h)
      fl_rectf(x, y + d / 2, w, h - (d & -2));
    else if (w > h)
      fl_rectf(x + d / 2, y, w - (d & -2), h);
  }
  else if (w < h) {
    if (which != UPPER_LEFT) fl_yxline(x + w - 1, y + d / 2 - 1, y + h - d / 2 + 1);
    if (which != LOWER_RIGHT) fl_yxline(x, y + d / 2 - 1, y + h - d / 2 + 1);
  }
  else if (w > h) {
    if (which != UPPER_LEFT) fl_xyline(x + d / 2 - 1, y + h - 1, x + w - d / 2 + 1);
    if (which != LOWER_RIGHT) fl_xyline(x + d / 2 - 1, y, x + w - d / 2 + 1);
  }
}

static void round_up_box(int x, int y, int w, int h, Fl_Color c)
{
  const uchar *g = fl_gray_ramp();

  round_part(FILL, x, y, w, h, 2, c);
  round_part(LOWER_RIGHT, x + 1, y, w - 2, h, 0, (Fl_Color)g['H']);
  round_part(LOWER_RIGHT, x + 1, y, w - 2, h, 1, (Fl_Color)g['N']);
  round_part(LOWER_RIGHT, x, y, w, h, 1, (Fl_Color)g['H']);
  round_part(LOWER_RIGHT, x, y, w, h, 2, (Fl_Color)g['N']);
  round_part(UPPER_LEFT, x, y, w, h, 2, (Fl_Color)g['U']);
  round_part(UPPER_LEFT, x + 1, y, w - 2, h, 1, (Fl_Color)g['S']);
  round_part(UPPER_LEFT, x, y, w, h, 1, (Fl_Color)g['W']);
  round_part(UPPER_LEFT, x + 1, y, w - 2, h, 0, (Fl_Color)g['U']);
  round_part(CLOSED, x, y, w, h, 0, (Fl_Color)g['A']);
}

static void round_down_box(int x, int y, int w, int h, Fl_Color c)
{
  const uchar *g = fl_gray_ramp();

  round_part(FILL, x, y, w, h, 2, c);
  round_part(UPPER_LEFT, x + 1, y, w - 2, h, 0, (Fl_Color)g['N']);
  round_part(UPPER_LEFT, x + 1, y, w - 2, h, 1, (Fl_Color)g['H']);
  round_part(UPPER_LEFT, x, y, w, h, 0, (Fl_Color)g['N']);
  round_part(UPPER_LEFT, x, y, w, h, 1, (Fl_Color)g['H']);
  round_part(LOWER_RIGHT, x, y, w, h, 0, (Fl_Color)g['S']);
  round_part(LOWER_RIGHT, x + 1, y, w - 2, h, 0, (Fl_Color)g['U']);
  round_part(LOWER_RIGHT, x, y, w, h, 1, (Fl_Color)g['U']);
  round_part(LOWER_RIGHT, x + 1, y, w - 2, h, 1, (Fl_Color)g['W']);
  round_part(CLOSED, x, y, w, h, 2, (Fl_Color)g['A']);
}

static void set(Fl_Boxtype t, Fl_Box_Draw_F *f)
{
  Fl::set_boxtype(t, f, Fl::box_dx(t), Fl::box_dy(t), Fl::box_dw(t), Fl::box_dh(t));
}

void fl10_boxtypes(void)
{
  up_frame = Fl::get_boxtype(FL_UP_FRAME);
  down_frame = Fl::get_boxtype(FL_DOWN_FRAME);
  set(FL_FLAT_BOX, flat_box);
  set(FL_UP_BOX, up_box);
  set(FL_DOWN_BOX, down_box);
  set(FL_ROUND_UP_BOX, round_up_box);   /* (the macros define the round boxes first) */
  set(FL_ROUND_DOWN_BOX, round_down_box);
}
