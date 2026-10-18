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

int BuffWrite(void *data, char *str, int len)
{
  size_t __size;
  int addlen;
  void *pvVar1;
  BuffWrite_t *o;
  
  if (len == -1) {
    len = strlen(str);
  }
  if (len < 0x400) {
    addlen = 0x400;
  }
  else {
    addlen = len + 200;
  }
  if (*(int *)data == 0) {
    *(int *)((int)data + 4) = addlen;
    pvVar1 = malloc(addlen);
    *(void **)data = pvVar1;
    *(undefined4 *)((int)data + 8) = 0;
  }
  else if (*(int *)((int)data + 4) < len + *(int *)((int)data + 8)) {
    __size = addlen + *(int *)((int)data + 4);
    *(size_t *)((int)data + 4) = __size;
    pvVar1 = realloc(*(void **)data,__size);
    *(void **)data = pvVar1;
  }
  strcpy((char *)(*(int *)data + *(int *)((int)data + 8)),str);
  *(int *)((int)data + 8) = len + *(int *)((int)data + 8);
  return len;
}
