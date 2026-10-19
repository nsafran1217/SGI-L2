/*
 * Equivalence test for the PPP framing (common/sys/PPP.c): the rewritten
 * PPPWrite(), PPPRead() and PPPDecode() against the original
 * reconstruction (decomp branch, compiled in as OrigPPP*), on random frames
 * and on noisy streams read in random pieces. Every return value, frame
 * and error callback must agree. Built and run by tests/unit/ppp_test.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../sys_ctrl/common/sys/PPP.h"
#include "orig_ppp.h"

/* a transcript of what an implementation did */
static char log_new[1 << 20], log_orig[1 << 20];
static char *logp;

static void logf_(const char *fmt, long a, long b)
{
  logp += sprintf(logp, fmt, a, b);
}

static void log_bytes(const unsigned char *p, unsigned int n)
{
  unsigned int i;

  for (i = 0; i < n; i++)
    logp += sprintf(logp, "%02x", p[i]);
  *logp++ = '\n';
  *logp = '\0';
}

static void efcn(void *arg, PPPError *e)
{
  logf_("efcn %ld len %ld: ", e->status, e->blen);
  if (e->bptr != NULL && e->blen < 5000)
    log_bytes(e->bptr, e->blen);
  else
    log_bytes(NULL, 0);
}

static void orig_efcn(void *arg, OrigPPPError *e)
{
  efcn(arg, (PPPError *)e);
}

/* ---- writing ---- */

static unsigned char wout[100000];
static int wlen, wcalls, wfail_at;

static int wfcn(void *fd, unsigned char *buf, int len)
{
  wcalls++;
  if (wcalls == wfail_at)
    len /= 2;
  memcpy(wout + wlen, buf, len);
  wlen += len;
  logf_("write %ld (%ld)\n", len, wcalls);
  return len;
}

static int failures, compared;

static void compare(const char *what, int n)
{
  if (strcmp(log_new, log_orig) != 0) {
    printf("FAIL  %s %d\n", what, n);
    if (failures < 3) {
      char *a = log_new, *b = log_orig;
      while (*a && *a == *b) { a++; b++; }
      while (a > log_new && a[-1] != '\n') { a--; b--; }
      printf("  new:  %.200s\n  orig: %.200s\n", a, b);
    }
    failures++;
  }
  compared++;
}

/* PPPWrite with both; leaves the new one's output in wout */
static void check_write(unsigned char *data, int len, int xonxoff, int control, int osize, int fail_at, int n)
{
  unsigned char obuf[2][1000];
  PPPInstance p;
  OrigPPPInstance op;
  int r;

  logp = log_orig;
  wlen = wcalls = 0;
  wfail_at = fail_at;
  OrigPPPInit(&op, NULL, 0, obuf[0], osize, xonxoff, control, 0, 0, orig_efcn, NULL);
  r = OrigPPPWrite(&op, wfcn, NULL, data, len);
  logf_("= %ld olen %ld\n", r, op.olen);
  log_bytes(wout, wlen);

  logp = log_new;
  wlen = wcalls = 0;
  PPPInit(&p, NULL, 0, obuf[1], osize, xonxoff, control, 0, 0, efcn, NULL);
  r = PPPWrite(&p, wfcn, NULL, data, len);
  logf_("= %ld olen %ld\n", r, p.olen);
  log_bytes(wout, wlen);
  compare("write", n);
}

/* ---- reading ---- */

struct stream {
  unsigned char *data;
  int len, pos;
  unsigned int seed;
  int reset_every;              /* PPPReset() the input every n reads */
  void *ppp;
  int orig;
  int reads;
};

static int rfcn(struct stream *s, unsigned char *buf, int size)
{
  int n;

  s->reads++;
  if (s->pos >= s->len)
    return -1;
  if (s->reset_every && s->reads % s->reset_every == 0) {
    if (s->orig)
      OrigPPPReset(s->ppp, 1);
    else
      PPPReset(s->ppp, PPP_RESET_INPUT);
  }
  n = rand_r(&s->seed) % (size + 1);   /* (0 now and then) */
  if (n > s->len - s->pos)
    n = s->len - s->pos;
  memcpy(buf, s->data + s->pos, n);
  s->pos += n;
  return n;
}

static void read_all(int orig, unsigned char *data, int len, unsigned int seed, int isize,
                     int control, int rmax, int offset, int resize, int reset_every)
{
  unsigned char ibuf[64];
  unsigned char *rbuf = malloc(offset + rmax);
  struct stream s = { data, len, 0, seed, reset_every, NULL, orig, 0 };
  PPPInstance p;
  OrigPPPInstance op;
  int r, guard = 0;

  if (orig) {
    s.ppp = &op;
    OrigPPPInit(&op, ibuf, isize, NULL, 0, 0, control, offset, resize, orig_efcn, NULL);
  }
  else {
    s.ppp = &p;
    PPPInit(&p, ibuf, isize, NULL, 0, 0, control, offset, resize, efcn, NULL);
  }
  do {
    r = orig ? OrigPPPRead(&op, (int (*)())rfcn, &s, &rbuf, rmax)
             : PPPRead(&p, (int (*)())rfcn, &s, &rbuf, rmax);
    logf_("read = %ld at %ld: ", r, s.pos);
    log_bytes(r > 0 ? rbuf + offset : NULL, r > 0 ? r : 0);
  } while (r != -1 && ++guard < 10000);
  free(rbuf);
}

static void check_read(unsigned char *data, int len, unsigned int seed, int n)
{
  static const struct { int isize, control, rmax, offset, resize, reset; } cfg[] = {
    { 8, 1, 300, 20, 0, 0 }, { 64, 0, 300, 0, 0, 0 }, { 1, 1, 40, 4, 0, 0 },
    { 13, 1, 40, 4, 600, 0 }, { 8, 1, 300, 20, 0, 7 }, { 5, 0, 2, 0, 0, 0 }, { 13, 1, 40, 4, 100, 0 },
  };
  unsigned int c;

  for (c = 0; c < sizeof(cfg) / sizeof(cfg[0]); c++) {
    logp = log_orig;
    read_all(1, data, len, seed, cfg[c].isize, cfg[c].control, cfg[c].rmax, cfg[c].offset,
             cfg[c].resize, cfg[c].reset);
    logp = log_new;
    read_all(0, data, len, seed, cfg[c].isize, cfg[c].control, cfg[c].rmax, cfg[c].offset,
             cfg[c].resize, cfg[c].reset);
    compare("read", n * 10 + c);
  }
}

static void check_decode(unsigned char *data, int len, int osize, int n)
{
  unsigned char obuf[2][400];
  PPPDecodeState ds;
  OrigPPPDecodeState ods;
  int i, r;

  logp = log_orig;
  OrigPPPDecodeInit(&ods, obuf[0], osize, orig_efcn, NULL);
  for (i = 0; i < len; i++) {
    if (i == len / 2)
      OrigPPPDecodeReset(&ods);
    r = OrigPPPDecode(&ods, data[i]);
    if (r != 0) {
      logf_("decode %ld at %ld: ", r, i);
      log_bytes(r > 0 ? obuf[0] : NULL, r > 0 ? r : 0);
    }
  }
  logp = log_new;
  PPPDecodeInit(&ds, obuf[1], osize, efcn, NULL);
  for (i = 0; i < len; i++) {
    if (i == len / 2)
      PPPDecodeReset(&ds);
    r = PPPDecode(&ds, data[i]);
    if (r != 0) {
      logf_("decode %ld at %ld: ", r, i);
      log_bytes(r > 0 ? obuf[1] : NULL, r > 0 ? r : 0);
    }
  }
  compare("decode", n);
}

int main(void)
{
  static unsigned char data[2000], stream[60000];
  static const unsigned char special[] = { 0x7e, 0x7d, 0x11, 0x13, 0x0d, 0x20, 0x5e, 0x5d };
  unsigned int seed = 1;
  int run, i, len, slen, frames, f, osize;

  /* frames */
  for (run = 0; run < 3000; run++) {
    len = rand_r(&seed) % (run < 100 ? 8 : 600);
    for (i = 0; i < len; i++)
      data[i] = rand_r(&seed) % 3 ? special[rand_r(&seed) % 8] : rand_r(&seed);
    osize = (int[]){ 16, 64, 256, 1000 }[run % 4];
    check_write(data, len, run & 1, (run >> 1) & 1, osize, run % 7 == 0 ? 1 + run % 3 : 0, run);
  }

  /* streams: frames from PPPWrite with noise between and inside them */
  for (run = 0; run < 400; run++) {
    slen = 0;
    frames = 1 + rand_r(&seed) % 12;
    for (f = 0; f < frames; f++) {
      len = rand_r(&seed) % (rand_r(&seed) % 4 ? 60 : 400);
      for (i = 0; i < len; i++)
        data[i] = rand_r(&seed) % 4 ? special[rand_r(&seed) % 8] : rand_r(&seed);
      check_write(data, len, 0, 1, 1000, 0, -1);    /* (output in wout) */
      switch (rand_r(&seed) % 10) {
      case 0: wout[rand_r(&seed) % wlen] ^= 1 << (rand_r(&seed) % 8); break;     /* corrupt */
      case 1: wlen--; break;                                                  /* no end flag */
      case 2: if (wlen > 3) { wout[wlen - 2] = 0x7d; } break;                 /* escaped flag */
      case 3: memcpy(stream + slen, "junk\r", 5); slen += 5; break;           /* text, CR */
      case 4: memcpy(stream + slen, "xyz", 3); slen += 3; break;
      case 5: memcpy(stream + slen, "\x7e\x7e\x01\x02\x7e", 5); slen += 5; break;
      case 6: memcpy(stream + slen, "\r\rab", 4); slen += 4; break;          /* CR twice */
      }
      memcpy(stream + slen, wout, wlen);
      slen += wlen;
    }
    check_read(stream, slen, run, run);
    check_decode(stream, slen, (int[]){ 300, 40, 2 }[run % 3], run);
  }

  if (failures == 0)
    printf("PASS  ppp: %d writes, reads and decodes compared with the original\n", compared);
  return failures != 0;
}
