/*
 * sys_ctrl/common/sys/BuffWrite.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/BuffWrite.c
 *
 * A growing string buffer: BuffWriteInit(), BuffWrite() to append, then
 * BuffWriteDone() for the string.
 */

#include <stdlib.h>
#include <string.h>
#include "BuffWrite.h"

#define BUFF_STEP   0x400       /* grow by at least this much */
#define BUFF_EXTRA  200         /* ... and by this beyond a longer string */

BuffWrite_t *BuffWriteInit(void)
{
  BuffWrite_t *o;

  o = malloc(sizeof(BuffWrite_t));
  o->buff = NULL;
  o->blen = 0;
  o->ulen = 0;
  return o;
}

/* free the writer; returns the string, or frees it too if free_buff is set */
char *BuffWriteDone(BuffWrite_t *o, int free_buff)
{
  char *buffout = NULL;

  if (free_buff && o->buff != NULL)
    free(o->buff);
  else
    buffout = o->buff;
  free(o);
  return buffout;
}

/*
 * Append the first len bytes of str (all of it if len is -1); data is a
 * BuffWrite_t. Returns len. (The original copied all of str whatever len
 * said, and grew only when the text without its terminator did not fit.)
 */
int BuffWrite(void *data, char *str, int len)
{
  BuffWrite_t *o = data;
  int addlen;

  if (len == -1)
    len = strlen(str);
  addlen = len < BUFF_STEP ? BUFF_STEP : len + BUFF_EXTRA;
  if (o->buff == NULL) {
    o->blen = addlen;
    o->buff = malloc(o->blen);
    o->ulen = 0;
  }
  else if (o->ulen + len >= o->blen) {
    o->blen += addlen;
    o->buff = realloc(o->buff,o->blen);
  }
  memcpy(o->buff + o->ulen,str,len);
  o->ulen += len;
  o->buff[o->ulen] = '\0';
  return len;
}
