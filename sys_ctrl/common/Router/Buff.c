/*
 * sys_ctrl/common/Router/Buff.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Buff.c
 */

#include <stdlib.h>
#include "../sys/PPP.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include "Buff.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int BuffCompress(unsigned char *ibuf, unsigned int ilen, unsigned char **obuf, unsigned int *olen)
{
  uchar *puVar1;
  uchar *puVar2;
  uchar uVar3;
  uchar *puVar4;
  int iVar5;
  uchar c;
  int count;
  int out_count;
  uint len;
  uchar *buff;
  int iVar6;
  
  out_count = 0;
  count = 1;
  puVar2 = malloc((ilen >> 1) * 4 + (ilen >> 1) + 8);
  if (puVar2 == NULL) {
    return -1;
  }
  puVar4 = puVar2 + 4;
  if (ilen == 0) {
    *puVar2 = '\0';
    puVar2[1] = '\0';
    puVar2[2] = '\0';
    puVar2[3] = '\0';
    *obuf = puVar2;
    *olen = 4;
    return 0;
  }
  c = *ibuf;
  iVar5 = ilen - 1;
  while( true ) {
    puVar1 = ibuf;
    iVar6 = iVar5;
    ibuf = puVar1 + 1;
    iVar5 = iVar6 + -1;
    uVar3 = (uchar)((uint)count >> 8);
    if (iVar5 == -1) break;
    if (*ibuf == c) {
      count = count + 1;
      if (count == 0xffff) {
        *puVar4 = 0xfd;
        puVar4[1] = 0xff;
        puVar4[2] = 0xff;
        puVar4[3] = c;
        puVar4 = puVar4 + 4;
        out_count = out_count + 4;
        count = 0;
        if (iVar5 != 0) {
          ibuf = puVar1 + 2;
          c = *ibuf;
          count = 1;
          iVar5 = iVar6 + -2;
        }
      }
    }
    else {
      if ((((count < 2) || (4 < count)) || (c == 0xfe)) || (c == 0xfd)) {
        if ((count < 2) && ((count < 1 || ((c != 0xfe && (c != 0xfd)))))) {
          *puVar4 = c;
          puVar4 = puVar4 + 1;
          out_count = out_count + 1;
        }
        else {
          if (count < 0x100) {
            *puVar4 = 0xfe;
            puVar4 = puVar4 + 1;
            out_count = out_count + 3;
          }
          else {
            *puVar4 = 0xfd;
            puVar4[1] = uVar3;
            puVar4 = puVar4 + 2;
            out_count = out_count + 4;
          }
          *puVar4 = (uchar)count;
          puVar4[1] = c;
          puVar4 = puVar4 + 2;
        }
      }
      else {
        if (count == 2) {
LAB_0807b1c2:
          *puVar4 = c;
          puVar4 = puVar4 + 1;
          out_count = out_count + 1;
        }
        else {
          if (2 < count) {
            if (count != 3) {
              if (count != 4) goto LAB_0807b231;
              *puVar4 = c;
              puVar4 = puVar4 + 1;
              out_count = out_count + 1;
            }
            *puVar4 = c;
            puVar4 = puVar4 + 1;
            out_count = out_count + 1;
            goto LAB_0807b1c2;
          }
          if (count != 1) goto LAB_0807b231;
        }
        *puVar4 = c;
        puVar4 = puVar4 + 1;
        out_count = out_count + 1;
      }
LAB_0807b231:
      c = *ibuf;
      count = 1;
    }
  }
  if (count == 0) goto LAB_0807b311;
  if ((((count < 2) || (4 < count)) || (c == 0xfe)) || (c == 0xfd)) {
    if ((count < 2) && ((count < 1 || ((c != 0xfe && (c != 0xfd)))))) {
      *puVar4 = c;
      out_count = out_count + 1;
    }
    else {
      if (count < 0x100) {
        *puVar4 = 0xfe;
        puVar4 = puVar4 + 1;
        out_count = out_count + 3;
      }
      else {
        *puVar4 = 0xfd;
        puVar4[1] = uVar3;
        puVar4 = puVar4 + 2;
        out_count = out_count + 4;
      }
      *puVar4 = (uchar)count;
      puVar4[1] = c;
    }
    goto LAB_0807b311;
  }
  if (count == 2) {
LAB_0807b2a2:
    *puVar4 = c;
    puVar4 = puVar4 + 1;
    out_count = out_count + 1;
  }
  else {
    if (2 < count) {
      if (count != 3) {
        if (count != 4) goto LAB_0807b311;
        *puVar4 = c;
        puVar4 = puVar4 + 1;
        out_count = out_count + 1;
      }
      *puVar4 = c;
      puVar4 = puVar4 + 1;
      out_count = out_count + 1;
      goto LAB_0807b2a2;
    }
    if (count != 1) goto LAB_0807b311;
  }
  *puVar4 = c;
  out_count = out_count + 1;
LAB_0807b311:
  if ((obuf != NULL) && (olen != NULL)) {
    *puVar2 = (uchar)(ilen >> 0x18);
    puVar2[1] = (uchar)(ilen >> 0x10);
    puVar2[2] = (uchar)(ilen >> 8);
    puVar2[3] = (uchar)ilen;
    *obuf = puVar2;
    *olen = out_count + 4;
  }
  return 0;
}

int BuffUncompress(unsigned char *ibuf, unsigned int ilen, unsigned char **obuf, unsigned int *olen)
{
  byte bVar1;
  byte *pbVar2;
  uint uVar3;
  byte *pbVar4;
  byte *pbVar5;
  byte *pbVar6;
  int iVar7;
  int out_count;
  uint len;
  uchar *buff;
  uchar c;
  
  out_count = 0;
  iVar7 = ilen - 4;
  pbVar2 = malloc((uint)*ibuf << 0x18 | (uint)ibuf[1] << 0x10 | (uint)ibuf[2] << 8 | (uint)ibuf[3]);
  pbVar4 = pbVar2;
  pbVar6 = ibuf + 4;
  if (pbVar2 == NULL) {
    iVar7 = -1;
  }
  else {
    while (iVar7 != 0) {
      c = *pbVar6;
      pbVar5 = pbVar6 + 1;
      if (c == 0xfe) {
        uVar3 = (uint)*pbVar5;
        bVar1 = pbVar6[2];
        pbVar6 = pbVar6 + 3;
        out_count = out_count + uVar3;
        iVar7 = iVar7 + -3;
        while (uVar3 = uVar3 - 1, uVar3 != 0xffffffff) {
          *pbVar4 = bVar1;
          pbVar4 = pbVar4 + 1;
        }
      }
      else if (c == 0xfd) {
        uVar3 = (uint)CONCAT11(*pbVar5,pbVar6[2]);
        bVar1 = pbVar6[3];
        pbVar6 = pbVar6 + 4;
        out_count = out_count + uVar3;
        iVar7 = iVar7 + -4;
        while (uVar3 = uVar3 - 1, uVar3 != 0xffffffff) {
          *pbVar4 = bVar1;
          pbVar4 = pbVar4 + 1;
        }
      }
      else {
        *pbVar4 = c;
        pbVar4 = pbVar4 + 1;
        out_count = out_count + 1;
        iVar7 = iVar7 + -1;
        pbVar6 = pbVar5;
      }
    }
    if ((obuf != NULL) && (olen != NULL)) {
      *obuf = pbVar2;
      *olen = out_count;
    }
    iVar7 = 0;
  }
  return iVar7;
}

int BuffFree(unsigned char *buff)
{
  /* the original returned -1 if free() left a nonzero EAX (no caller checks) */
  free(buff);
  return 0;
}
