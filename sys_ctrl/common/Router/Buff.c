/*
 * sys_ctrl/common/Router/Buff.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Buff.c
 *
 * Router packet compression, a run-length code. Compressed data is the
 * uncompressed length (4 bytes, big-endian) followed by:
 *
 *   0xfe n c        a run of n (1..255) bytes c
 *   0xfd n1 n0 c    a run of n (256..65535, big-endian) bytes c
 *   c               any other byte stands for itself
 *
 * Runs of 2 to 4 ordinary bytes are written out; the escape bytes 0xfe and
 * 0xfd always go as runs, even alone.
 */

#include <stdint.h>
#include <stdlib.h>
#include "Buff.h"

#define RUN8    0xfe
#define RUN16   0xfd
#define MAXRUN  0xffff

static int is_escape(unsigned char c)
{
  return c == RUN8 || c == RUN16;
}

static unsigned char *put_run(unsigned char *out, unsigned char c, int count)
{
  if (count <= 4 && !is_escape(c)) {
    while (count--)
      *out++ = c;
  }
  else if (count < 0x100) {
    *out++ = RUN8;
    *out++ = count;
    *out++ = c;
  }
  else {
    *out++ = RUN16;
    *out++ = count >> 8;
    *out++ = count;
    *out++ = c;
  }
  return out;
}

int BuffCompress(unsigned char *ibuf, unsigned int ilen, unsigned char **obuf, unsigned int *olen)
{
  unsigned char *buff, *out;
  unsigned char c;
  unsigned int i;
  int count;

  /* worst case: every byte an escape byte, 3 bytes each (the original
   * allocated 2.5 bytes per input byte: ORIGINAL_BUGS.md) */
  buff = malloc(4 + 3 * (size_t)ilen);
  if (buff == NULL)
    return -1;
  out = buff + 4;
  if (ilen > 0) {
    c = ibuf[0];
    count = 1;
    for (i = 1; i < ilen; i++) {
      if (ibuf[i] == c && count < MAXRUN) {
        count++;
      }
      else {
        out = put_run(out, c, count);
        c = ibuf[i];
        count = 1;
      }
    }
    out = put_run(out, c, count);
  }
  if (obuf != NULL && olen != NULL) {
    buff[0] = ilen >> 24;
    buff[1] = ilen >> 16;
    buff[2] = ilen >> 8;
    buff[3] = ilen;
    *obuf = buff;
    *olen = out - buff;
  }
  return 0;
}

int BuffUncompress(unsigned char *ibuf, unsigned int ilen, unsigned char **obuf, unsigned int *olen)
{
  unsigned char *buff, *out, *in, *end;
  unsigned int size, n;
  unsigned char c;

  if (ilen < 4)
    return -1;
  size = (unsigned int)ibuf[0] << 24 | ibuf[1] << 16 | ibuf[2] << 8 | ibuf[3];
  buff = malloc(size);
  if (buff == NULL)
    return -1;
  out = buff;
  in = ibuf + 4;
  end = ibuf + ilen;
  /* (the original trusted the data; a malformed packet ran past either buffer) */
  while (in < end) {
    c = *in++;
    if (c == RUN8 || c == RUN16) {
      if (end - in < (c == RUN8 ? 2 : 3))
        goto bad;
      n = c == RUN8 ? in[0] : (unsigned int)(in[0] << 8 | in[1]);
      in += c == RUN8 ? 1 : 2;
      c = *in++;
    }
    else {
      n = 1;
    }
    if (n > size - (unsigned int)(out - buff))
      goto bad;
    while (n--)
      *out++ = c;
  }
  if (obuf != NULL && olen != NULL) {
    *obuf = buff;
    *olen = out - buff;
  }
  return 0;

bad:
  free(buff);
  return -1;
}

int BuffFree(unsigned char *buff)
{
  free(buff);
  return 0;
}
