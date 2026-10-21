/*
 * sys_ctrl/l3/webgui/fl.js
 *
 * New in the modern tree. What the web l2gui needs of the original's
 * graphics stack, drawing the same pixels: FLTK 1.0 (FLNX, SGI's Nano-X
 * port) widgets, box types and text layout, over Nano-X's drawing
 * primitives (its arcs, bitmap font and 8-bit palette) on a 320x240 screen.
 * Ported from FLTK 1.0 (LGPL; FLNX's frames are those of 1.0.10 and later)
 * and Microwindows 0.89 (MPL), checked against screenshots of SGI's l2gui;
 * the data tables (fldata.js) come from the l2gui binary itself.
 *
 * As in the original, every l2gui window is a top-level window on the
 * screen, and a widget's coordinates are relative to its window.
 */

import { cmap, palette, activeRamp, inactiveRamp, cosine, font } from "./fldata.js";

export const SCREEN_W = 320, SCREEN_H = 240;

/* Fl_Color */
export const FL_BLACK = 0, FL_WHITE = 7, FL_GRAY = 49;

/* Fl_Boxtype */
export const FL_NO_BOX = 0, FL_FLAT_BOX = 1, FL_UP_BOX = 2, FL_DOWN_BOX = 3,
  FL_EMBOSSED_FRAME = 13, FL_ROUND_UP_BOX = 22, FL_ROUND_DOWN_BOX = 23;

/* Fl_Align */
export const FL_ALIGN_CENTER = 0, FL_ALIGN_TOP = 1, FL_ALIGN_BOTTOM = 2,
  FL_ALIGN_LEFT = 4, FL_ALIGN_RIGHT = 8, FL_ALIGN_INSIDE = 16;

/* Fl_Button types */
export const FL_NORMAL_BUTTON = 0, FL_TOGGLE_BUTTON = 1, FL_RADIO_BUTTON = 102;

/* events */
const FL_PUSH = 1, FL_RELEASE = 2, FL_DRAG = 5;

/* --- Nano-X: the screen --- */

const pixels = new Uint32Array(SCREEN_W * SCREEN_H);
let ctx, image;
let fg = 0;                     /* the foreground, as an RGBA pixel */
let ox = 0, oy = 0;             /* the window being drawn: its screen position */
let clip = { x0: 0, y0: 0, x1: SCREEN_W - 1, y1: SCREEN_H - 1 };
const clips = [];

/* GdFindNearestColor(): the palette entry nearest an RGB colour */
const nearest = new Map();
function hwcolor(rgb) {
  let px = nearest.get(rgb);

  if (px === undefined) {
    const r = rgb >> 16 & 255, g = rgb >> 8 & 255, b = rgb & 255;
    let diff = 0x7fffffff, best = 0;
    for (const p of palette) {
      const sq = Math.abs((p >> 16 & 255) - r) + Math.abs((p >> 8 & 255) - g) + Math.abs((p & 255) - b);
      if (sq < diff) {
        best = p;
        if ((diff = sq) === 0)
          break;
      }
    }
    px = (0xff000000 | (best & 255) << 16 | (best & 0xff00) | best >> 16 & 255) >>> 0;
    nearest.set(rgb, px);
  }
  return px;
}

function drawpoint(x, y) {
  if (x >= clip.x0 && x <= clip.x1 && y >= clip.y0 && y <= clip.y1)
    pixels[y * SCREEN_W + x] = fg;
}

/* x1 to x2 (either order), inclusive, in screen coordinates */
function drawrow(x1, x2, y) {
  if (x1 > x2)
    [x1, x2] = [x2, x1];
  if (y < clip.y0 || y > clip.y1)
    return;
  x1 = Math.max(x1, clip.x0);
  x2 = Math.min(x2, clip.x1);
  for (let x = x1; x <= x2; x++)
    pixels[y * SCREEN_W + x] = fg;
}

function drawcol(x, y1, y2) {
  if (y1 > y2)
    [y1, y2] = [y2, y1];
  for (let y = y1; y <= y2; y++)
    drawpoint(x, y);
}

/* --- Nano-X arcs (devarc.c, GdArcAngle with its float qcos/qsin) --- */

const f32 = Math.fround;
const MWARC = 1, MWPIE = 4;

function qcos(angle) {
  angle = f32(angle);
  let a = Math.trunc(angle), b, c;

  if (a < 0) {
    angle = f32(a - angle);
    a = -a;
  }
  else
    angle = f32(angle - a);
  b = Math.trunc(a / 90);
  c = a - b * 90;
  return quadrant(b, c, angle);
}

function qsin(angle) {
  angle = f32(angle);
  let a = Math.trunc(angle) - 90, b, c;

  if (a < 0) {
    angle = f32(a + 90 - angle);
    a = -a;
  }
  else
    angle = f32(angle - (a + 90));
  b = Math.trunc(a / 90);
  c = a - b * 90;
  return quadrant(b, c, angle);
}

function quadrant(b, c, angle) {
  const cos = n => cosine[2 * n], step = n => cosine[2 * n + 1];

  switch (b & 3) {
  case 3:
    c = 90 - c;
    return f32(cos(c) - f32(step(c - 1) * angle));
  case 2:
    return f32(-f32(cos(c) + f32(step(c) * angle)));
  case 1:
    c = 90 - c;
    return f32(f32(step(c - 1) * angle) - cos(c));
  default:
    return f32(cos(c) + f32(step(c) * angle));
  }
}

/* angles in 64ths of a degree */
function arcangle(x0, y0, rx, ry, angle1, angle2, type) {
  const ax = Math.trunc(f32(qcos(angle1 / 64) * rx));
  const bx = Math.trunc(f32(qcos(angle2 / 64) * rx));
  const ay = Math.trunc(f32(-qsin(angle1 / 64) * ry));
  const by = Math.trunc(f32(-qsin(angle2 / 64) * ry));

  arc(x0, y0, rx, ry, ax, ay, bx, by, type);
}

function arc(x0, y0, rx, ry, ax, ay, bx, by, type) {
  let adir, bdir;

  if (rx <= 0 || ry <= 0)
    return;
  adir = ay >= 0 ? 1 : -1;
  bdir = by >= 0 ? -1 : 1;
  if (ay === 0)
    ++ay;
  if (by === 0)
    ++by;
  if (bx > ax) {
    [ax, bx] = [bx, ax];
    [ay, by] = [by, ay];
    [adir, bdir] = [bdir, adir];
  }
  drawarc({ x0, y0, rx, ry, ax, ay, bx, by, adir, bdir, type });
}

function clipline(s, xe, ye, dir, y, r) {
  if ((y >= 0 && ye >= 0) || (y < 0 && ye < 0)) {
    const x = ye === 0 ? xe : Math.trunc(xe * y / ye);

    if (x >= r.x0 && x <= r.x1) {
      if (dir > 0)
        r.x0 = x;
      else
        r.x1 = x;
      return 0;
    }
    if (dir > 0) {
      if (x <= r.x0)
        return 0;
    }
    else if (x >= r.x1)
      return 0;
    return 3;
  }
  return 1;
}

/* relative offsets, left to right */
function drawline(s, x0, y, x1) {
  const dbl = s.adir > 0 && s.bdir < 0;
  const r = { x0, x1 };
  let discard, ret;

  if (y === 0) {
    if (s.type !== MWPIE)
      return;
    if ((s.ay <= 0 && s.by >= 0) || (s.ay >= 0 && s.by <= 0)) {
      if (s.adir < 0 && x1 > 0)
        x1 = 0;
      if (s.bdir > 0 && x0 < 0)
        x0 = 0;
    }
    else if (!dbl) {
      drawpoint(s.x0, s.y0);
      return;
    }
    drawrow(s.x0 + x0, s.x0 + x1, s.y0);
    return;
  }
  ret = clipline(s, s.ax, s.ay, s.adir, y, r);
  if (dbl) {
    if (!ret) {
      drawrow(s.x0 + r.x0, s.x0 + r.x1, s.y0 + y);
      r.x0 = x0;
      r.x1 = x1;
    }
  }
  else if (ret > 1)
    return;
  discard = ret;
  ret = clipline(s, s.bx, s.by, s.bdir, y, r);
  discard += ret;
  if (discard > 2 && !(dbl && ret === 0 && discard === 3))
    return;
  if (discard === 2 && (s.adir < 0 || s.bdir > 0))
    return;
  drawrow(s.x0 + r.x0, s.x0 + r.x1, s.y0 + y);
}

function drawarcsegment(s, xp, yp) {
  if (s.type === MWPIE) {
    drawline(s, -xp, -yp, +xp);
    drawline(s, -xp, +yp, +xp);
  }
  else {
    drawline(s, +xp, +yp, +xp);
    drawline(s, -xp, +yp, -xp);
    drawline(s, +xp, -yp, +xp);
    drawline(s, -xp, -yp, -xp);
  }
}

function drawarc(s) {
  const Asquared = s.rx * s.rx, TwoAsquared = 2 * Asquared;
  const Bsquared = s.ry * s.ry, TwoBsquared = 2 * Bsquared;
  let xp = 0, yp = s.ry;
  let d = Bsquared - Asquared * s.ry + (Asquared >> 2);
  let dx = 0, dy = TwoAsquared * s.ry;

  while (dx < dy) {
    drawarcsegment(s, xp, yp);
    if (d > 0) {
      yp--;
      dy -= TwoAsquared;
      d -= dy;
    }
    xp++;
    dx += TwoBsquared;
    d += Bsquared + dx;
  }
  d += (Math.trunc(3 * (Asquared - Bsquared) / 2) - (dx + dy)) >> 1;
  while (yp >= 0) {
    drawarcsegment(s, xp, yp);
    if (d < 0) {
      xp++;
      dx += TwoBsquared;
      d += dx;
    }
    yp--;
    dy -= TwoAsquared;
    d += Asquared - dy;
  }
}

/* --- fl_draw: FLNX's drawing calls, in window coordinates --- */

export function fl_color(c) {
  fg = hwcolor(cmap[c]);
}

export function fl_rectf(x, y, w, h) {
  if (w <= 0 || h <= 0)
    return;
  for (let j = 0; j < h; j++)
    drawrow(ox + x, ox + x + w - 1, oy + y + j);
}

export function fl_xyline(x, y, x1) {
  drawrow(ox + x, ox + x1, oy + y);
}

export function fl_yxline(x, y, y1) {
  drawcol(ox + x, oy + y, oy + y1);
}

function fl_arc(x, y, w, h, a1, a2) {
  if (w > 0 && h > 0)
    arcangle(ox + Math.trunc((w - 1) / 2) + x, oy + Math.trunc((h - 1) / 2) + y, Math.trunc((w - 1) / 2),
             Math.trunc((h - 1) / 2), Math.round(a1 * 64), Math.round(a2 * 64), MWARC);
}

function fl_pie(x, y, w, h, a1, a2) {
  if (w > 0 && h > 0 && a1 !== a2)
    arcangle(ox + Math.trunc((w - 1) / 2) + x, oy + Math.trunc((h - 1) / 2) + y, Math.trunc((w - 1) / 2),
             Math.trunc((h - 1) / 2), Math.round(a1 * 64), Math.round(a2 * 64), MWPIE);
}

export function fl_push_clip(x, y, w, h) {
  clips.push(clip);
  clip = {
    x0: Math.max(clip.x0, ox + x), y0: Math.max(clip.y0, oy + y),
    x1: Math.min(clip.x1, ox + x + w - 1), y1: Math.min(clip.y1, oy + y + h - 1),
  };
}

export function fl_pop_clip() {
  clip = clips.pop();
}

export function fl_height() {
  return font.height;
}

export function fl_descent() {
  return font.height - font.ascent;
}

function glyph(c) {
  return c < font.first || c >= font.first + font.widths.length ? 0 : c - font.first;
}

export function fl_width(s) {
  let w = 0;

  for (const ch of s)
    w += font.widths[glyph(ch.charCodeAt(0))];
  return w;
}

/* GrText() at the baseline y */
export function fl_draw_text(s, x, y) {
  x += ox;
  y += oy - font.ascent;
  for (const ch of s) {
    const g = glyph(ch.charCodeAt(0)), w = font.widths[g];

    for (let row = 0; row < font.height; row++) {
      const bits = font.bits[g * font.stride + row];
      for (let col = 0; col < w; col++)
        if (bits & 0x8000 >> col)
          drawpoint(x + col, y + row);
    }
    x += w;
  }
}

/* fl_draw(str, x, y, w, h, align): a label's lines, aligned in a box
 * (no word wrap, no '&' shortcuts: l2gui uses neither) */
export function fl_draw(str, x, y, w, h, align) {
  if (!str)
    return;
  const lines = str.split("\n").map(s => s.replace(/[\x00-\x1f\x7f]/g, c => "^" +
    String.fromCharCode(c.charCodeAt(0) ^ 0x40)));
  const height = fl_height();
  let ypos;

  if (align & FL_ALIGN_BOTTOM)
    ypos = y + h - (lines.length - 1) * height;
  else if (align & FL_ALIGN_TOP)
    ypos = y + height;
  else
    ypos = y + Math.trunc((h - lines.length * height) / 2) + height;
  for (const line of lines) {
    const width = fl_width(line);
    let xpos;

    if (align & FL_ALIGN_LEFT)
      xpos = x;
    else if (align & FL_ALIGN_RIGHT)
      xpos = x + w - width;
    else
      xpos = x + Math.trunc((w - width) / 2);
    fl_draw_text(line, xpos, ypos - fl_descent());
    ypos += height;
  }
}

/* --- FLTK 1.0 box types (fl_boxtype.cxx, fl_round_box.cxx) --- */

let drawActive = true;

function ramp(letter) {
  return (drawActive ? activeRamp : inactiveRamp)[letter.charCodeAt(0) - 65];
}

function frame2(s, x, y, w, h) {
  if (h <= 0 || w <= 0)
    return;
  for (let i = 0; i < s.length;) {
    fl_color(ramp(s[i++]));
    fl_xyline(x, y + h - 1, x + w - 1);
    if (--h <= 0)
      break;
    fl_color(ramp(s[i++]));
    fl_yxline(x + w - 1, y + h - 1, y);
    if (--w <= 0)
      break;
    fl_color(ramp(s[i++]));
    fl_xyline(x, y, x + w - 1);
    y++;
    if (--h <= 0)
      break;
    fl_color(ramp(s[i++]));
    fl_yxline(x, y + h - 1, y);
    x++;
    if (--w <= 0)
      break;
  }
}

function frame(s, x, y, w, h) {
  if (h <= 0 || w <= 0)
    return;
  for (let i = 0; i < s.length;) {
    fl_color(ramp(s[i++]));
    fl_xyline(x, y, x + w - 1);
    y++;
    if (--h <= 0)
      break;
    fl_color(ramp(s[i++]));
    fl_yxline(x, y + h - 1, y);
    x++;
    if (--w <= 0)
      break;
    fl_color(ramp(s[i++]));
    fl_xyline(x, y + h - 1, x + w - 1);
    if (--h <= 0)
      break;
    fl_color(ramp(s[i++]));
    fl_yxline(x + w - 1, y + h - 1, y);
    if (--w <= 0)
      break;
  }
}

const UPPER_LEFT = 0, LOWER_RIGHT = 1, CLOSED = 2, FILL = 3;

function roundPart(which, x, y, w, h, inset, color) {
  if (inset * 2 >= w)
    inset = Math.trunc((w - 1) / 2);
  if (inset * 2 >= h)
    inset = Math.trunc((h - 1) / 2);
  x += inset;
  y += inset;
  w -= 2 * inset;
  h -= 2 * inset;
  const d = w <= h ? w : h;
  if (d <= 1)
    return;
  fl_color(color);
  const f = which === FILL ? fl_pie : fl_arc;
  if (which >= CLOSED) {
    f(x + w - d, y, d, d, w <= h ? 0 : -90, w <= h ? 180 : 90);
    f(x, y + h - d, d, d, w <= h ? 180 : 90, w <= h ? 360 : 270);
  }
  else if (which === UPPER_LEFT) {
    f(x + w - d, y, d, d, 45, w <= h ? 180 : 90);
    f(x, y + h - d, d, d, w <= h ? 180 : 90, 225);
  }
  else {
    f(x, y + h - d, d, d, 225, w <= h ? 360 : 270);
    f(x + w - d, y, d, d, w <= h ? 360 : 270, 360 + 45);
  }
  const half = Math.trunc(d / 2);
  if (which === FILL) {
    if (w < h)
      fl_rectf(x, y + half, w, h - (d & -2));
    else if (w > h)
      fl_rectf(x + half, y, w - (d & -2), h);
  }
  else if (w < h) {
    if (which !== UPPER_LEFT)
      fl_yxline(x + w - 1, y + half, y + h - half);
    if (which !== LOWER_RIGHT)
      fl_yxline(x, y + half, y + h - half);
  }
  else if (w > h) {
    if (which !== UPPER_LEFT)
      fl_xyline(x + half, y + h - 1, x + w - half);
    if (which !== LOWER_RIGHT)
      fl_xyline(x + half, y, x + w - half);
  }
}

const boxes = {
  [FL_NO_BOX]: { d: 0, draw() {} },
  [FL_FLAT_BOX]: { d: 0, draw(x, y, w, h, c) { fl_color(c); fl_rectf(x, y, w, h); } },
  [FL_UP_BOX]: {
    d: 2,
    draw(x, y, w, h, c) {
      frame2("AAUWMMTT", x, y, w, h);
      fl_color(c);
      fl_rectf(x + 2, y + 2, w - 4, h - 4);
    },
  },
  [FL_DOWN_BOX]: {
    d: 2,
    draw(x, y, w, h, c) {
      frame2("UWMMPPAA", x, y, w, h);
      fl_color(c);
      fl_rectf(x + 2, y + 2, w - 4, h - 4);
    },
  },
  [FL_EMBOSSED_FRAME]: { d: 2, draw(x, y, w, h) { frame("WWHHHHWW", x, y, w, h); } },
  [FL_ROUND_UP_BOX]: {
    d: 3,
    draw(x, y, w, h, c) {
      roundPart(FILL, x, y, w, h, 2, c);
      roundPart(LOWER_RIGHT, x + 1, y, w - 2, h, 0, ramp("H"));
      roundPart(LOWER_RIGHT, x + 1, y, w - 2, h, 1, ramp("N"));
      roundPart(LOWER_RIGHT, x, y, w, h, 1, ramp("H"));
      roundPart(LOWER_RIGHT, x, y, w, h, 2, ramp("N"));
      roundPart(UPPER_LEFT, x, y, w, h, 2, ramp("U"));
      roundPart(UPPER_LEFT, x + 1, y, w - 2, h, 1, ramp("S"));
      roundPart(UPPER_LEFT, x, y, w, h, 1, ramp("W"));
      roundPart(UPPER_LEFT, x + 1, y, w - 2, h, 0, ramp("U"));
      roundPart(CLOSED, x, y, w, h, 0, ramp("A"));
    },
  },
  [FL_ROUND_DOWN_BOX]: {
    d: 3,
    draw(x, y, w, h, c) {
      roundPart(FILL, x, y, w, h, 2, c);
      roundPart(UPPER_LEFT, x + 1, y, w - 2, h, 0, ramp("N"));
      roundPart(UPPER_LEFT, x + 1, y, w - 2, h, 1, ramp("H"));
      roundPart(UPPER_LEFT, x, y, w, h, 0, ramp("N"));
      roundPart(UPPER_LEFT, x, y, w, h, 1, ramp("H"));
      roundPart(LOWER_RIGHT, x, y, w, h, 0, ramp("S"));
      roundPart(LOWER_RIGHT, x + 1, y, w - 2, h, 0, ramp("U"));
      roundPart(LOWER_RIGHT, x, y, w, h, 1, ramp("U"));
      roundPart(LOWER_RIGHT, x + 1, y, w - 2, h, 1, ramp("W"));
      roundPart(CLOSED, x, y, w, h, 2, ramp("A"));
    },
  },
};

/* fl_down(): the pressed form of a box type */
function down(b) {
  return b === FL_UP_BOX ? FL_DOWN_BOX : b === FL_ROUND_UP_BOX ? FL_ROUND_DOWN_BOX : b;
}

/* fl_color_average(c, FL_GRAY, .33): an inactive widget's label colour */
function inactive(c) {
  const weight = f32(0.33), rest = f32(1 - weight);
  const rgb1 = cmap[c], rgb2 = cmap[FL_GRAY];
  const mix = sh => Math.trunc(f32((rgb1 >> sh & 255) * weight) + f32((rgb2 >> sh & 255) * rest)) & 255;
  const r = mix(16), g = mix(8), b = mix(0);

  if (r === g && r === b)
    return 32 + Math.trunc(r * 24 / 256);
  return 56 + (Math.trunc(b * 5 / 256) * 5 + Math.trunc(r * 5 / 256)) * 8 + Math.trunc(g * 8 / 256);
}

/* --- widgets --- */

let pushed = null;              /* Fl::pushed() */
let redrawPending = false;
let screenWindows = [];         /* the windows shown, bottom to top */

export class Widget {
  constructor(x, y, w, h, label = null) {
    Object.assign(this, {
      x, y, w, h, label, box: FL_NO_BOX, color: FL_GRAY, selectionColor: FL_GRAY,
      labelcolor: FL_BLACK, align: FL_ALIGN_CENTER, image: null, type: 0,
      visible: true, active: true, parent: null, callback: null, userData: null,
    });
  }

  set(props) {
    Object.assign(this, props);
    return this;
  }

  activeR() {
    for (let w = this; w; w = w.parent)
      if (!w.active)
        return false;
    return true;
  }

  visibleR() {
    for (let w = this; w; w = w.parent)
      if (!w.visible)
        return false;
    return true;
  }

  show() { this.visible = true; redraw(); }
  hide() { this.visible = false; redraw(); }
  activate() { this.active = true; redraw(); }
  deactivate() { this.active = false; redraw(); }
  setLabel(l) { this.label = l; redraw(); }

  takesEvents() {
    return this.visible && this.active;
  }

  inside(ex, ey) {
    return ex >= this.x && ex < this.x + this.w && ey >= this.y && ey < this.y + this.h;
  }

  doCallback() {
    if (this.callback)
      this.callback(this, this.userData);
  }

  drawBox(b = this.box, c = this.color) {
    drawActive = this.activeR();
    boxes[b].draw(this.x, this.y, this.w, this.h, c);
    drawActive = true;
  }

  drawLabel() {
    const d = boxes[this.box].d;
    let X = this.x + d, W = this.w - 2 * d;

    if (W > 11 && this.align & (FL_ALIGN_LEFT | FL_ALIGN_RIGHT)) {
      X += 3;
      W -= 6;
    }
    this.drawLabelIn(X, this.y + d, W, this.h - 2 * d);
  }

  drawLabelIn(X, Y, W, H) {
    if ((this.align & 15) && !(this.align & FL_ALIGN_INSIDE))
      return;
    if (this.image) {
      drawImage(this.image, X, Y, W, H, this.align);
      return;
    }
    fl_color(this.activeR() ? this.labelcolor : inactive(this.labelcolor));
    fl_draw(this.label, X, Y, W, H, this.align);
  }

  draw() {
    this.drawBox();
    this.drawLabel();
  }

  handle(ev, ex, ey) {
    return 0;
  }
}

export class Box extends Widget {}

export class Button extends Widget {
  constructor(x, y, w, h, label) {
    super(x, y, w, h, label);
    this.box = FL_UP_BOX;
    this.downBox = FL_NO_BOX;
    this.value_ = this.oldval = 0;
  }

  value(v) {
    if (v === undefined)
      return this.value_;
    v = v ? 1 : 0;
    this.oldval = v;
    if (this.value_ !== v) {
      this.value_ = v;
      redraw();
      return 1;
    }
    return 0;
  }

  setonly() {
    this.value(1);
    for (const o of this.parent.children)
      if (o !== this && o.type === FL_RADIO_BUTTON)
        o.value(0);
  }

  draw() {
    if (this.box === FL_NO_BOX)
      return;
    const col = this.value_ ? this.selectionColor : this.color;
    this.drawBox(this.value_ ? (this.downBox || down(this.box)) : this.box, col);
    this.drawLabel();
  }

  /* (when() is FL_WHEN_RELEASE: the callback runs on the release) */
  handle(ev, ex, ey) {
    let newval;

    switch (ev) {
    case FL_PUSH:
    case FL_DRAG:
      if (this.inside(ex, ey))
        newval = this.type === FL_RADIO_BUTTON ? 1 : this.oldval ? 0 : 1;
      else
        newval = this.oldval;
      if (newval !== this.value_) {
        this.value_ = newval;
        redraw();
      }
      return 1;
    case FL_RELEASE:
      if (this.value_ === this.oldval)
        return 1;
      if (this.type === FL_RADIO_BUTTON)
        this.setonly();
      else if (this.type === FL_TOGGLE_BUTTON)
        this.oldval = this.value_;
      else
        this.value(this.oldval);
      this.doCallback();
      return 1;
    }
    return 0;
  }
}

/* Fl_Output (multiline): text in its own colour, no cursor or selection */
export class Output extends Widget {
  constructor(x, y, w, h, label) {
    super(x, y, w, h, label);
    this.box = FL_DOWN_BOX;
    this.color = FL_WHITE;
    this.textcolor = FL_BLACK;
    this.text = "";
  }

  value(v) {
    if (v === undefined)
      return this.text;
    this.text = v;
    redraw();
  }

  draw() {
    const b = this.box || FL_DOWN_BOX, d = boxes[b].d;
    const X = this.x + d + 3, Y = this.y + d, W = this.w - 2 * d - 6, H = this.h - 2 * d;
    const height = fl_height();

    this.drawBox(b, this.color);
    if (this.text === "")
      return;
    fl_push_clip(X, Y, W, H);
    fl_color(this.activeR() ? this.textcolor : inactive(this.textcolor));
    let ypos = 0;
    for (const line of this.text.split("\n")) {
      if (ypos >= H)
        break;
      fl_draw_text(line.replace(/\t/g, "        "), X, Y + ypos + height - fl_descent());
      ypos += height;
    }
    fl_pop_clip();
  }

  handle(ev) {
    return ev === FL_PUSH || ev === FL_DRAG || ev === FL_RELEASE ? 1 : 0;
  }
}

export class Group extends Widget {
  constructor(x, y, w, h, label) {
    super(x, y, w, h, label);
    this.children = [];
  }

  add(...ws) {
    for (const w of ws) {
      if (w.parent)
        w.parent.children.splice(w.parent.children.indexOf(w), 1);
      w.parent = this;
      this.children.push(w);
    }
    return this;
  }

  contains(o) {
    for (; o; o = o.parent)
      if (o === this)
        return true;
    return false;
  }

  draw() {
    this.drawBox();
    this.drawLabel();
    for (const o of this.children)
      if (o.visible)
        o.draw();
  }

  handle(ev, ex, ey) {
    if (ev !== FL_PUSH)
      return 0;
    for (let i = this.children.length; i--;) {
      const o = this.children[i];
      if (o.takesEvents() && o.inside(ex, ey) && o.handle(FL_PUSH, ex, ey)) {
        if (pushed && !(o instanceof Group ? o.contains(pushed) : o === pushed))
          pushed = o;
        return 1;
      }
    }
    return 0;
  }
}

/* a top-level window on the screen, at (x, y) */
export class Window extends Group {
  constructor(x, y, w, h, label) {
    super(x, y, w, h, label);
    this.box = FL_FLAT_BOX;
    this.visible = false;       /* until shown */
    this.modal = false;
  }

  /* shows it on top of the others */
  show() {
    screenWindows = screenWindows.filter(w => w !== this);
    screenWindows.push(this);
    super.show();
  }

  hide() {
    screenWindows = screenWindows.filter(w => w !== this);
    if (pushed && this.contains(pushed))
      pushed = null;
    super.hide();
  }

  /* children are relative to the window */
  draw() {
    const { x, y } = this;

    ox = x;
    oy = y;
    fl_push_clip(0, 0, this.w, this.h);
    this.x = this.y = 0;
    super.draw();
    this.x = x;
    this.y = y;
    fl_pop_clip();
    ox = oy = 0;
  }
}

/* --- images (Fl_Pixmap as a label) --- */

/* an XPM file's text: { w, h, pixels (0xRRGGBB, or -1 for None) } */
export function parseXpm(text) {
  const strs = [...text.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map(m => m[1]);
  const [w, h, ncolors, cpp] = strs[0].trim().split(/\s+/).map(Number);
  const colors = new Map();

  for (let i = 1; i <= ncolors; i++) {
    const s = strs[i], m = / c\s+(\S+)/.exec(s.slice(cpp));
    const v = m && m[1].startsWith("#") ? parseInt(m[1].slice(1), 16) : -1;
    colors.set(s.slice(0, cpp), v);
  }
  const pixels = new Int32Array(w * h);
  for (let y = 0; y < h; y++) {
    const row = strs[1 + ncolors + y];
    for (let x = 0; x < w; x++)
      pixels[y * w + x] = colors.get(row.substr(x * cpp, cpp));
  }
  return { w, h, pixels };
}

/* pixmap_labeltype(): the image in the box, aligned, clipped to it */
function drawImage(img, X, Y, W, H, align) {
  let cx = align & FL_ALIGN_LEFT ? 0 : align & FL_ALIGN_RIGHT ? img.w - W : Math.trunc((img.w - W) / 2);
  let cy = align & FL_ALIGN_TOP ? 0 : align & FL_ALIGN_BOTTOM ? img.h - H : Math.trunc((img.h - H) / 2);

  if (cx < 0) {
    W += cx;
    X -= cx;
    cx = 0;
  }
  if (cx + W > img.w)
    W = img.w - cx;
  if (cy < 0) {
    H += cy;
    Y -= cy;
    cy = 0;
  }
  if (cy + H > img.h)
    H = img.h - cy;
  for (let j = 0; j < H; j++)
    for (let i = 0; i < W; i++) {
      const p = img.pixels[(cy + j) * img.w + cx + i];
      if (p >= 0) {
        fg = hwcolor(p);
        drawpoint(ox + X + i, oy + Y + j);
      }
    }
}

/* --- the screen: drawing and pointer events --- */

export function redraw() {
  if (!redrawPending && ctx) {
    redrawPending = true;
    requestAnimationFrame(flush);
  }
}

/* draws the screen: black, then the windows shown, bottom to top */
export function flush() {
  redrawPending = false;
  pixels.fill(0xff000000);
  for (const w of screenWindows)
    w.draw();
  image.data.set(new Uint8ClampedArray(pixels.buffer));
  ctx.putImageData(image, 0, 0);
}

/* Fl::modal(): the topmost modal window shown */
function modal() {
  for (let i = screenWindows.length; i--;)
    if (screenWindows[i].modal)
      return screenWindows[i];
  return null;
}

function windowAt(sx, sy) {
  for (let i = screenWindows.length; i--;)
    if (screenWindows[i].inside(sx, sy))
      return screenWindows[i];
  return null;
}

function windowOf(w) {
  while (w.parent)
    w = w.parent;
  return w;
}

/* Fl::handle(): a press at screen (sx, sy), then drags and the release go
 * to the widget that took the press */
function press(sx, sy) {
  const win = windowAt(sx, sy);

  if (win === null || (modal() && win !== modal()))
    return;
  pushed = win;
  if (!win.handle(FL_PUSH, sx - win.x, sy - win.y))
    win.show();                 /* raise windows that are clicked on */
}

function drag(sx, sy) {
  if (pushed) {
    const win = windowOf(pushed);
    pushed.handle(FL_DRAG, sx - win.x, sy - win.y);
  }
}

function release(sx, sy) {
  const w = pushed;

  if (w) {
    const win = windowOf(w);
    pushed = null;
    w.handle(FL_RELEASE, sx - win.x, sy - win.y);
  }
}

/* the screen is canvas, scaled by CSS: pointer events in screen pixels */
export function attach(canvas) {
  const at = e => {
    const r = canvas.getBoundingClientRect();
    return [Math.floor((e.clientX - r.left) * SCREEN_W / r.width),
            Math.floor((e.clientY - r.top) * SCREEN_H / r.height)];
  };

  canvas.width = SCREEN_W;
  canvas.height = SCREEN_H;
  ctx = canvas.getContext("2d");
  image = ctx.createImageData(SCREEN_W, SCREEN_H);
  canvas.addEventListener("pointerdown", e => {
    if (e.button !== 0)
      return;
    canvas.setPointerCapture(e.pointerId);
    press(...at(e));
    e.preventDefault();
  });
  canvas.addEventListener("pointermove", e => {
    if (e.buttons & 1)
      drag(...at(e));
  });
  canvas.addEventListener("pointerup", e => {
    if (e.button === 0)
      release(...at(e));
  });
  canvas.addEventListener("pointercancel", e => release(...at(e)));
  redraw();
}
