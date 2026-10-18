/*
 * sys_ctrl/common/sys/BuffWrite.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/BuffWrite.c
 */

#include "PPP.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include "BuffWrite.h"
#include "sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include "brick_types.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

BuffWrite_t *BuffWriteInit(void)
{
  BuffWrite_t *o;
  
  o = malloc(sizeof(BuffWrite_t));
  o->buff = NULL;
  o->blen = 0;
  o->ulen = 0;
  return o;
}

char *BuffWriteDone(BuffWrite_t *o, int free_buff)
{
  char *buffout;
  
  buffout = NULL;
  if ((free_buff == 0) || (o->buff == NULL)) {
    buffout = o->buff;
  }
  else {
    free(o->buff);
  }
  free(o);
  return buffout;
}

/* Append str (len bytes, or all of it if len is -1) to the buffer; data is a
 * BuffWrite_t. Grows in 1 KB steps, or len + 200 for long strings. */
int BuffWrite(void *data, char *str, int len)
{
  BuffWrite_t *o = data;
  int addlen;

  if (len == -1) {
    len = strlen(str);
  }
  addlen = (len < 0x400) ? 0x400 : len + 200;
  if (o->buff == NULL) {
    o->blen = addlen;
    o->buff = malloc(addlen);
    o->ulen = 0;
  }
  else if (o->blen < len + o->ulen) {
    o->blen = addlen + o->blen;
    o->buff = realloc(o->buff, o->blen);
  }
  strcpy(o->buff + o->ulen, str);
  o->ulen = len + o->ulen;
  return len;
}
