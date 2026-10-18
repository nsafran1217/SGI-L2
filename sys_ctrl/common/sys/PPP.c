/*
 * sys_ctrl/common/sys/PPP.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/PPP.c
 */

#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include "sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include "pmalloc.h"
#include <stdlib.h>
#include "PPP.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static U16 pppfcs(int fcs, unsigned char *bptr, unsigned int blen, unsigned char *fptr);
static U16 pppnext(int cptr, int fcs);
static void call_efcn(PPPInstance *pptr, unsigned int status, unsigned char *bptr, unsigned int blen, unsigned char *csbuf, unsigned char *rawbuf, unsigned int rawlen);

static U16 fcstab[256] = { 0, 4489, 8978, 12955, 17956, 22445, 25910, 29887, 35912, 40385, 44890, 48851, 51820, 56293, 59774, 63735, 4225, 264, 13203, 8730, 22181, 18220, 30135, 25662, 40137, 36160, 49115, 44626, 56045, 52068, 63999, 59510, 8450, 12427, 528, 5017, 26406, 30383, 17460, 21949, 44362, 48323, 36440, 40913, 60270, 64231, 51324, 55797, 12675, 8202, 4753, 792, 30631, 26158, 21685, 17724, 48587, 44098, 40665, 36688, 64495, 60006, 55549, 51572, 16900, 21389, 24854, 28831, 1056, 5545, 10034, 14011, 52812, 57285, 60766, 64727, 34920, 39393, 43898, 47859, 21125, 17164, 29079, 24606, 5281, 1320, 14259, 9786, 57037, 53060, 64991, 60502, 39145, 35168, 48123, 43634, 25350, 29327, 16404, 20893, 9506, 13483, 1584, 6073, 61262, 65223, 52316, 56789, 43370, 47331, 35448, 39921, 29575, 25102, 20629, 16668, 13731, 9258, 5809, 1848, 65487, 60998, 56541, 52564, 47595, 43106, 39673, 35696, 33800, 38273, 42778, 46739, 49708, 54181, 57662, 61623, 2112, 6601, 11090, 15067, 20068, 24557, 28022, 31999, 38025, 34048, 47003, 42514, 53933, 49956, 61887, 57398, 6337, 2376, 15315, 10842, 24293, 20332, 32247, 27774, 42250, 46211, 34328, 38801, 58158, 62119, 49212, 53685, 10562, 14539, 2640, 7129, 28518, 32495, 19572, 24061, 46475, 41986, 38553, 34576, 62383, 57894, 53437, 49460, 14787, 10314, 6865, 2904, 32743, 28270, 23797, 19836, 50700, 55173, 58654, 62615, 32808, 37281, 41786, 45747, 19012, 23501, 26966, 30943, 3168, 7657, 12146, 16123, 54925, 50948, 62879, 58390, 37033, 33056, 46011, 41522, 23237, 19276, 31191, 26718, 7393, 3432, 16371, 11898, 59150, 63111, 50204, 54677, 41258, 45219, 33336, 37809, 27462, 31439, 18516, 23005, 11618, 15595, 3696, 8185, 63375, 58886, 54429, 50452, 45483, 40994, 37561, 33584, 31687, 27214, 22741, 18780, 15843, 11370, 7921, 3960 };
char buff[128];

static U16 pppfcs(int fcs, unsigned char *bptr, unsigned int blen, unsigned char *fptr)
{
  ushort uVar1;
  
  while (blen = blen - 1, uVar1 = (ushort)((uint)fcs >> 8), blen != 0xffffffff) {
    fcs = (int)(uVar1 & 0xff ^ fcstab[(fcs & 0xffffU ^ (uint)*bptr) & 0xff]);
    bptr = bptr + 1;
  }
  return fcstab[(fcs & 0xffffU ^ (uint)*fptr) & 0xff] >> 8 ^
         fcstab[((uint)(uVar1 & 0xff ^ fcstab[(fcs & 0xffffU ^ (uint)*fptr) & 0xff]) ^ (uint)fptr[1]
                ) & 0xff];
}

static U16 pppnext(int cptr, int fcs)
{
  return (ushort)((uint)fcs >> 8) & 0xff ^ fcstab[(fcs & 0xffffU ^ cptr & 0xffU) & 0xff];
}

static void call_efcn(PPPInstance *pptr, unsigned int status, unsigned char *bptr, unsigned int blen, unsigned char *csbuf, unsigned char *rawbuf, unsigned int rawlen)
{
  PPPError ppperr;
  
  if (pptr->efcn != NULL) {
    ppperr.status = status;
    ppperr.bptr = bptr;
    ppperr.blen = blen;
    (*pptr->efcn)(pptr->efcn_arg,&ppperr);
  }
  return;
}

void PPPInit(PPPInstance *pptr, unsigned char *iptr, unsigned int isize, unsigned char *optr, unsigned int osize, unsigned int xonxoff, unsigned int control, unsigned int offset, unsigned int resize, void (*efcn)(), void *efcn_arg)
{
  memset(pptr,0,0x3c);
  pptr->ibuf = iptr;
  pptr->isize = isize;
  pptr->obuf = optr;
  pptr->osize = osize;
  pptr->xonxoff = (uint)(xonxoff != 0);
  pptr->control = (uint)(control != 0);
  pptr->offset = offset;
  pptr->resize = resize;
  pptr->efcn = efcn;
  pptr->efcn_arg = efcn_arg;
  PPPReset(pptr,3);
  return;
}

void PPPReset(PPPInstance *pptr, int which)
{
  if ((which & 1U) != 0) {
    pptr->ilen = 0;
    pptr->inframe = 0;
  }
  if ((which & 2U) != 0) {
    pptr->olen = 0;
  }
  return;
}

int PPPWrite(PPPInstance *pptr, int (*wfcn)(), void *fd, unsigned char *bptr, int blen)
{
  ushort uVar1;
  byte bVar2;
  uint blen_00;
  uint status_00;
  int status;
  int iVar3;
  bool escaped;
  int bytes;
  uchar fbuf [2];
  U16 fcs;
  int wlen;
  
  iVar3 = blen;
  pptr->optr = pptr->obuf;
  *pptr->optr = '~';
  pptr->optr = pptr->optr + 1;
  pptr->olen = 1;
  fcs = 0xffff;
  while (blen != 0) {
    escaped = false;
    bVar2 = *bptr;
    if (bVar2 == 0x13) {
LAB_0807f7a2:
      escaped = pptr->xonxoff != 0;
    }
    else if (bVar2 < 0x14) {
      if (bVar2 == 0xd) {
        escaped = pptr->control != 0;
      }
      else if (bVar2 == 0x11) goto LAB_0807f7a2;
    }
    else if ((bVar2 < 0x7f) && (0x7c < bVar2)) {
      escaped = true;
    }
    if (escaped) {
      *pptr->optr = '}';
      pptr->optr = pptr->optr + 1;
      *pptr->optr = *bptr ^ 0x20;
      pptr->optr = pptr->optr + 1;
      pptr->olen = pptr->olen + 2;
    }
    else {
      *pptr->optr = *bptr;
      pptr->optr = pptr->optr + 1;
      pptr->olen = pptr->olen + 1;
    }
    fcs = pppnext((uint)*bptr,(uint)fcs);
    bptr = bptr + 1;
    blen = blen + -1;
    if (pptr->osize <= pptr->olen + 5U) {
      blen_00 = pptr->olen;
      status_00 = (*wfcn)(fd,pptr->obuf,blen_00);
      if (status_00 != blen_00) {
        call_efcn(pptr,status_00,pptr->obuf,blen_00,NULL,NULL,0);
        return status_00;
      }
      pptr->optr = pptr->obuf;
      pptr->olen = 0;
    }
  }
  fcs = ~fcs;
  fbuf[0] = (uchar)fcs;
  fbuf[1] = (uchar)(fcs >> 8);
  fcs = 0;
  do {
    if (1 < fcs) {
      *pptr->optr = '~';
      pptr->olen = pptr->olen + 1;
      wlen = pptr->olen;
      status = (*wfcn)(fd,pptr->obuf,wlen);
      if (status != wlen) {
        call_efcn(pptr,status,pptr->obuf,wlen,NULL,NULL,0);
        iVar3 = status;
      }
      return iVar3;
    }
    escaped = false;
    bVar2 = fbuf[fcs];
    if (bVar2 == 0x13) {
LAB_0807f936:
      escaped = pptr->xonxoff != 0;
    }
    else if (bVar2 < 0x14) {
      if (bVar2 == 0xd) {
        escaped = pptr->control != 0;
      }
      else if (bVar2 == 0x11) goto LAB_0807f936;
    }
    else if ((bVar2 < 0x7f) && (0x7c < bVar2)) {
      escaped = true;
    }
    if (escaped) {
      *pptr->optr = '}';
      pptr->optr = pptr->optr + 1;
      *pptr->optr = fbuf[fcs] ^ 0x20;
      pptr->optr = pptr->optr + 1;
      pptr->olen = pptr->olen + 2;
    }
    else {
      *pptr->optr = fbuf[fcs];
      pptr->optr = pptr->optr + 1;
      pptr->olen = pptr->olen + 1;
    }
    fcs = fcs + 1;
  } while( true );
}

int PPPRead(PPPInstance *pptr, int (*rfcn)(), void *fd, unsigned char **rbuf, int rmax)
{
  uint uVar1;
  U16 UVar2;
  uchar *puVar3;
  int iVar4;
  uint resize;
  uint offset;
  uint flen;
  uchar *fptr;
  uint rlen;
  uchar *rptr;
  uint rawlen_la;
  uint rawlen;
  uint rawsize;
  uchar *rawbuf;
  uchar fbuf [2];
  uchar c;
  int frame;
  int inframe;
  bool escaped;
  bool ignore_until_flag;
  
  frame = 0;
  rptr = NULL;
  rlen = 0;
  fptr = fbuf;
  flen = 0;
  escaped = false;
  ignore_until_flag = false;
  uVar1 = pptr->offset;
  resize = pptr->resize;
  if (pptr->inframe != 0) {
    rptr = *rbuf + uVar1;
    rlen = 0;
    fptr = fbuf;
    flen = 0;
  }
LAB_0807fad1:
  do {
    while( true ) {
      while( true ) {
        do {
          while ((frame != 0 || (pptr->ilen < 1))) {
            if (frame == 0) {
              inframe = pptr->inframe;
              pptr->iptr = pptr->ibuf;
              iVar4 = (*rfcn)(fd,pptr->ibuf,pptr->isize);
              pptr->ilen = iVar4;
              if (iVar4 < 0) {
                call_efcn(pptr,pptr->ilen,*rbuf + uVar1,rlen,NULL,NULL,0);
                pptr->inframe = 0;
                return pptr->ilen;
              }
              if ((inframe != 0) && (pptr->inframe == 0)) {
                rptr = NULL;
                fptr = fbuf;
                rlen = 0;
                escaped = false;
                ignore_until_flag = true;
              }
            }
            if (frame != 0) {
              return rlen;
            }
          }
          c = *pptr->iptr;
          pptr->iptr = pptr->iptr + 1;
          pptr->ilen = pptr->ilen + -1;
        } while ((ignore_until_flag) && (c != 0x7e));
        if (c != 0x7d) break;
        if (pptr->inframe != 0) {
          escaped = true;
        }
      }
      if (c < 0x7e) break;
      if (c != 0x7e) goto LAB_0807fd22;
      ignore_until_flag = false;
      if (pptr->inframe != 0) {
        if (escaped) {
          call_efcn(pptr,0xfffffd41,*rbuf + uVar1,rlen,NULL,NULL,0);
        }
        else if ((rlen == 0) || (2 < rlen)) {
          if (rlen != 0) {
            if (flen == 0) {
              fbuf[1] = rptr[-1];
              rptr = rptr + -2;
              fbuf[0] = *rptr;
              rlen = rlen - 2;
            }
            else if (flen == 1) {
              fbuf[1] = fbuf[0];
              rptr = rptr + -1;
              fbuf[0] = *rptr;
              rlen = rlen - 1;
            }
            UVar2 = pppfcs(0xffff,*rbuf + uVar1,rlen,fbuf);
            if (UVar2 == 0xf0b8) {
              frame = 1;
            }
            else {
              call_efcn(pptr,0xfffffd44,*rbuf + uVar1,rlen,fbuf,NULL,0);
            }
          }
        }
        else {
          call_efcn(pptr,0xfffffd42,*rbuf + uVar1,rlen,NULL,NULL,0);
        }
      }
      if (frame == 0) {
        pptr->inframe = 1;
        rptr = *rbuf + uVar1;
        rlen = 0;
        fptr = fbuf;
        flen = 0;
        escaped = false;
      }
    }
    if ((c == 0xd) && (pptr->control != 0)) {
      pptr->inframe = 0;
      call_efcn(pptr,0xfffffd40,*rbuf + uVar1,rlen,NULL,NULL,0);
      return -0x2c0;
    }
LAB_0807fd22:
    if (pptr->inframe != 0) {
      if (escaped) {
        c = c ^ 0x20;
        escaped = false;
      }
      if ((uint)rmax <= rlen) {
        if (resize == 0) {
          if (flen < 2) {
            *fptr = c;
            fptr = fptr + 1;
            flen = flen + 1;
          }
          else {
            call_efcn(pptr,0xfffffd43,*rbuf + uVar1,rlen,NULL,NULL,0);
            pptr->inframe = 0;
            rptr = NULL;
            rlen = 0;
            fptr = fbuf;
            flen = 0;
            escaped = false;
            ignore_until_flag = true;
          }
          goto LAB_0807fad1;
        }
        puVar3 = realloc(*rbuf,resize);
        *rbuf = puVar3;
        if (puVar3 == NULL) {
          pptr->inframe = 0;
          call_efcn(pptr,0xfffffd3e,NULL,0,NULL,NULL,0);
          return -0x2c2;
        }
        rptr = *rbuf + uVar1 + rmax;
        rmax = resize - uVar1;
        resize = 0;
      }
      *rptr = c;
      rptr = rptr + 1;
      rlen = rlen + 1;
      goto LAB_0807fad1;
    }
    if (!ignore_until_flag) {
      call_efcn(pptr,0xfffffd3f,&c,1,NULL,NULL,0);
      ignore_until_flag = true;
    }
  } while( true );
}

int PPPDecodeInit(PPPDecodeState *ds, unsigned char *obuf, int osize, void (*efcn)(), void *efcn_arg)
{
  memset(ds,0,0x34);
  ds->efcn = efcn;
  ds->efcn_arg = efcn_arg;
  ds->obuf = obuf;
  ds->osize = osize;
  PPPDecodeReset(ds);
  return 0;
}

int PPPDecodeReset(PPPDecodeState *ds)
{
  ds->async_reset = 1;
  return 0;
}

int PPPDecode(PPPDecodeState *ds, int c)
{
  U16 UVar1;
  uchar *csbuf;
  int cserr;
  int rval;
  uchar c_;
  
  c_ = (uchar)c;
  if (ds->async_reset != 0) {
    ds->resync = 1;
    ds->inframe = 0;
    ds->optr = NULL;
    ds->fptr = NULL;
    ds->async_reset = 0;
  }
  if ((ds->fptr == NULL) || (ds->optr == NULL)) {
    ds->olen = 0;
    ds->optr = ds->obuf;
    ds->flen = 0;
    ds->fptr = ds->fbuf;
    ds->escaped = 0;
  }
  if ((ds->resync != 0) && (c_ != 0x7e)) {
    return 0;
  }
  if ((c & 0xffU) == 0x7d) {
    if (ds->inframe != 0) {
      ds->escaped = 1;
    }
  }
  else if ((c & 0xffU) == 0x7e) {
    ds->resync = 0;
    if (ds->inframe != 0) {
      if (ds->olen == 0) {
        return 0;
      }
      if (ds->escaped == 0) {
        if ((ds->olen == 0) || (2 < ds->olen)) {
          if (ds->olen == 0) {
            return 0;
          }
          if (ds->flen == 0) {
            ds->optr = ds->optr + -1;
            ds->fbuf[1] = *ds->optr;
            ds->optr = ds->optr + -1;
            ds->fbuf[0] = *ds->optr;
            ds->olen = ds->olen + -2;
          }
          else if (ds->flen == 1) {
            ds->fbuf[1] = ds->fbuf[0];
            ds->optr = ds->optr + -1;
            ds->fbuf[0] = *ds->optr;
            ds->olen = ds->olen + -1;
          }
          UVar1 = pppfcs(0xffff,ds->obuf,ds->olen,ds->fbuf);
          if (UVar1 == 0xf0b8) {
            ds->optr = NULL;
            ds->fptr = NULL;
            return ds->olen;
          }
          rval = -700;
        }
        else {
          rval = -0x2be;
        }
      }
      else {
        rval = -0x2bf;
      }
      if (rval == -700) {
        csbuf = ds->fbuf;
      }
      else {
        csbuf = NULL;
      }
      call_efcn((PPPInstance *)ds,rval,ds->obuf,ds->olen,csbuf,NULL,0);
      ds->inframe = (uint)(c_ == 0x7e);
      ds->resync = (uint)(c_ != 0x7e);
      ds->optr = NULL;
      ds->fptr = NULL;
      return rval;
    }
    ds->inframe = 1;
    ds->olen = 0;
    ds->optr = ds->obuf;
    ds->flen = 0;
    ds->fptr = ds->fbuf;
  }
  else {
    if (ds->inframe == 0) {
      return -0x2c1;
    }
    if (ds->escaped != 0) {
      c_ = c_ ^ 0x20;
      ds->escaped = 0;
    }
    if (ds->olen < ds->osize) {
      *ds->optr = c_;
      ds->optr = ds->optr + 1;
      ds->olen = ds->olen + 1;
    }
    else {
      if (1 < ds->flen) {
        ds->inframe = 0;
        ds->optr = ds->obuf;
        ds->olen = 0;
        ds->fptr = ds->fbuf;
        ds->flen = 0;
        ds->escaped = 0;
        return -0x2bd;
      }
      *ds->fptr = c_;
      ds->fptr = ds->fptr + 1;
      ds->flen = ds->flen + 1;
    }
  }
  return 0;
}
