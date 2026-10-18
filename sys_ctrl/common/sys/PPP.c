/*
 * sys_ctrl/common/sys/PPP.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/PPP.c
 *
 * PPP-style (RFC 1662 HDLC-like) framing for the serial link to an L1:
 * a frame is flag (0x7e), data, 16-bit FCS (low byte first), flag. Inside
 * it, 0x7d escapes the next byte (xor 0x20); escaped are the flag and the
 * escape themselves, XON/XOFF if xonxoff is set and CR if control is set
 * (a raw CR then means the L1 dropped out of PPP, see PPPRead()). One flag
 * may both end a frame and start the next.
 *
 * Errors go to the instance's efcn(efcn_arg, PPPError *) and are returned
 * as PPP_ERR_* (-7xx).
 */

#include <stdlib.h>
#include <string.h>
#include "PPP.h"

#define PPP_FLAG      0x7e
#define PPP_ESCAPE    0x7d
#define PPP_TRANS     0x20      /* an escaped byte is xored with this */
#define PPP_INIT_FCS  0xffff
#define PPP_GOOD_FCS  0xf0b8    /* the FCS over data and FCS of a good frame */
#define XON           0x11
#define XOFF          0x13

/* the FCS-16 table, RFC 1662 */
static U16 fcstab[256] = {
  0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
  0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
  0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
  0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
  0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
  0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
  0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
  0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
  0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
  0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
  0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
  0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
  0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
  0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
  0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
  0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
  0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
  0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
  0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
  0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
  0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
  0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
  0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
  0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
  0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
  0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78,
};

char buff[128];                 /* (unused; in the original's symbols) */

static U16 pppnext(unsigned char c, U16 fcs)
{
  return (fcs >> 8) ^ fcstab[(fcs ^ c) & 0xff];
}

/* the FCS over blen bytes and then the frame's two FCS bytes */
static U16 pppfcs(U16 fcs, unsigned char *bptr, unsigned int blen, unsigned char *fptr)
{
  while (blen-- != 0)
    fcs = pppnext(*bptr++,fcs);
  fcs = pppnext(fptr[0],fcs);
  return pppnext(fptr[1],fcs);
}

static void call_efcn(void (*efcn)(), void *efcn_arg, int status, unsigned char *bptr, unsigned int blen)
{
  PPPError ppperr;

  if (efcn != NULL) {
    ppperr.status = status;
    ppperr.bptr = bptr;
    ppperr.blen = blen;
    efcn(efcn_arg,&ppperr);
  }
}

/*
 * At a frame's end: move its FCS, the last two bytes, to fbuf, where the
 * flen bytes that did not fit in the buffer already are. end is past the
 * data; returns how many bytes came off it.
 */
static unsigned int split_fcs(unsigned char *fbuf, unsigned int flen, unsigned char *end)
{
  if (flen == 0) {
    fbuf[1] = end[-1];
    fbuf[0] = end[-2];
    return 2;
  }
  if (flen == 1) {
    fbuf[1] = fbuf[0];
    fbuf[0] = end[-1];
    return 1;
  }
  return 0;
}

/*
 * iptr/isize: the read buffer; optr/osize: the write buffer. offset: where
 * PPPRead() puts a frame in its buffer; resize: what that buffer may grow
 * to once (0: it may not).
 */
void PPPInit(PPPInstance *pptr, unsigned char *iptr, unsigned int isize, unsigned char *optr, unsigned int osize, unsigned int xonxoff, unsigned int control, unsigned int offset, unsigned int resize, void (*efcn)(), void *efcn_arg)
{
  memset(pptr,0,sizeof(*pptr));
  pptr->ibuf = iptr;
  pptr->isize = isize;
  pptr->obuf = optr;
  pptr->osize = osize;
  pptr->xonxoff = xonxoff != 0;
  pptr->control = control != 0;
  pptr->offset = offset;
  pptr->resize = resize;
  pptr->efcn = efcn;
  pptr->efcn_arg = efcn_arg;
  PPPReset(pptr,PPP_RESET_INPUT | PPP_RESET_OUTPUT);
}

/* drop buffered input (and any frame in progress) and/or output */
void PPPReset(PPPInstance *pptr, int which)
{
  if (which & PPP_RESET_INPUT) {
    pptr->ilen = 0;
    pptr->inframe = 0;
  }
  if (which & PPP_RESET_OUTPUT)
    pptr->olen = 0;
}

static int must_escape(PPPInstance *pptr, unsigned char c)
{
  switch (c) {
  case XON:
  case XOFF:
    return pptr->xonxoff != 0;
  case '\r':
    return pptr->control != 0;
  case PPP_ESCAPE:
  case PPP_FLAG:
    return 1;
  default:
    return 0;
  }
}

static void put_byte(PPPInstance *pptr, unsigned char c)
{
  if (must_escape(pptr,c)) {
    *pptr->optr++ = PPP_ESCAPE;
    *pptr->optr++ = c ^ PPP_TRANS;
    pptr->olen += 2;
  }
  else {
    *pptr->optr++ = c;
    pptr->olen++;
  }
}

/* write one frame of blen bytes with wfcn(fd, buf, len); returns blen, or
 * wfcn's result when it writes short */
int PPPWrite(PPPInstance *pptr, int (*wfcn)(), void *fd, unsigned char *bptr, int blen)
{
  int rval = blen;
  U16 fcs = PPP_INIT_FCS;
  int status, wlen;

  pptr->optr = pptr->obuf;
  pptr->olen = 0;
  *pptr->optr++ = PPP_FLAG;
  pptr->olen++;
  for (; blen > 0; blen--, bptr++) {
    put_byte(pptr,*bptr);
    fcs = pppnext(*bptr,fcs);
    /* flush, keeping room for the escaped FCS and the flag */
    if (pptr->olen + 5U >= pptr->osize) {
      wlen = pptr->olen;
      status = wfcn(fd,pptr->obuf,wlen);
      if (status != wlen) {
        call_efcn(pptr->efcn,pptr->efcn_arg,status,pptr->obuf,wlen);
        return status;
      }
      pptr->optr = pptr->obuf;
      pptr->olen = 0;
    }
  }
  fcs = ~fcs;
  put_byte(pptr,fcs & 0xff);
  put_byte(pptr,fcs >> 8);
  *pptr->optr++ = PPP_FLAG;
  pptr->olen++;
  wlen = pptr->olen;
  status = wfcn(fd,pptr->obuf,wlen);
  if (status != wlen) {
    call_efcn(pptr->efcn,pptr->efcn_arg,status,pptr->obuf,wlen);
    return status;
  }
  return rval;
}

/*
 * Read one frame into *rbuf + offset (rmax bytes there) with
 * rfcn(fd, buf, size), which returns what it read, 0 to be called again,
 * or an error. Returns the frame's length, or rfcn's error, PPP_ERR_CONTROL
 * (a raw CR: the L1 is talking plain text) or PPP_ERR_REALLOC. Bad frames
 * go to efcn and are skipped; bytes outside a frame are skipped up to the
 * next flag. Bytes read past the frame wait in the read buffer for the
 * next call. rfcn may PPPReset() the input, abandoning the frame.
 */
int PPPRead(PPPInstance *pptr, int (*rfcn)(), void *fd, unsigned char **rbuf, int rmax)
{
  unsigned int offset = pptr->offset;
  unsigned int resize = pptr->resize;
  unsigned char *rptr = NULL;
  unsigned int rlen = 0;
  unsigned char fbuf[2];        /* bytes past rmax: the FCS, if the frame ends */
  unsigned int flen = 0;
  int escaped = 0;
  int ignore_until_flag = 0;
  int was_inframe;
  unsigned char c;

  if (pptr->inframe)            /* the last call's closing flag opened this frame */
    rptr = *rbuf + offset;

  for (;;) {
    while (pptr->ilen < 1) {
      was_inframe = pptr->inframe;
      pptr->iptr = pptr->ibuf;
      pptr->ilen = rfcn(fd,pptr->ibuf,pptr->isize);
      if (pptr->ilen < 0) {
        call_efcn(pptr->efcn,pptr->efcn_arg,pptr->ilen,*rbuf + offset,rlen);
        pptr->inframe = 0;
        return pptr->ilen;
      }
      if (was_inframe && !pptr->inframe) {      /* reset by rfcn */
        rptr = NULL;
        rlen = 0;
        escaped = 0;
        ignore_until_flag = 1;
      }
    }
    c = *pptr->iptr++;
    pptr->ilen--;

    if (ignore_until_flag && c != PPP_FLAG)
      continue;
    if (c == PPP_ESCAPE) {
      if (pptr->inframe)
        escaped = 1;
      continue;
    }
    if (c == PPP_FLAG) {
      ignore_until_flag = 0;
      if (pptr->inframe) {
        if (escaped) {
          call_efcn(pptr->efcn,pptr->efcn_arg,PPP_ERR_ESCAPE,*rbuf + offset,rlen);
        }
        else if (rlen > 0 && rlen <= 2) {
          call_efcn(pptr->efcn,pptr->efcn_arg,PPP_ERR_SHORT,*rbuf + offset,rlen);
        }
        else if (rlen > 0) {
          unsigned int n = split_fcs(fbuf,flen,rptr);

          rptr -= n;
          rlen -= n;
          if (pppfcs(PPP_INIT_FCS,*rbuf + offset,rlen,fbuf) == PPP_GOOD_FCS)
            return rlen;
          call_efcn(pptr->efcn,pptr->efcn_arg,PPP_ERR_FCS,*rbuf + offset,rlen);
        }
        /* (an empty frame: two flags in a row) */
      }
      pptr->inframe = 1;
      rptr = *rbuf + offset;
      rlen = 0;
      flen = 0;
      escaped = 0;
      continue;
    }
    if (c == '\r' && pptr->control) {
      pptr->inframe = 0;
      call_efcn(pptr->efcn,pptr->efcn_arg,PPP_ERR_CONTROL,*rbuf + offset,rlen);
      return PPP_ERR_CONTROL;
    }
    if (!pptr->inframe) {
      if (!ignore_until_flag) {
        call_efcn(pptr->efcn,pptr->efcn_arg,PPP_ERR_NOT_IN_FRAME,&c,1);
        ignore_until_flag = 1;
      }
      continue;
    }

    if (escaped) {
      c ^= PPP_TRANS;
      escaped = 0;
    }
    if (rlen >= (unsigned int)rmax) {
      if (resize == 0) {
        if (flen < 2) {         /* perhaps the FCS */
          fbuf[flen++] = c;
          continue;
        }
        call_efcn(pptr->efcn,pptr->efcn_arg,PPP_ERR_OVERFLOW,*rbuf + offset,rlen);
        pptr->inframe = 0;
        rptr = NULL;
        rlen = 0;
        flen = 0;
        escaped = 0;
        ignore_until_flag = 1;
        continue;
      }
      *rbuf = realloc(*rbuf,resize);
      if (*rbuf == NULL) {
        pptr->inframe = 0;
        call_efcn(pptr->efcn,pptr->efcn_arg,PPP_ERR_REALLOC,NULL,0);
        return PPP_ERR_REALLOC;
      }
      rptr = *rbuf + offset + rmax;
      rmax = resize - offset;
      resize = 0;               /* (once per call) */
    }
    *rptr++ = c;
    rlen++;
  }
}

/* the same framing one byte at a time (PPPDecode()), into obuf */
int PPPDecodeInit(PPPDecodeState *ds, unsigned char *obuf, int osize, void (*efcn)(), void *efcn_arg)
{
  memset(ds,0,sizeof(*ds));
  ds->efcn = efcn;
  ds->efcn_arg = efcn_arg;
  ds->obuf = obuf;
  ds->osize = osize;
  PPPDecodeReset(ds);
  return 0;
}

/* (takes effect with the next byte) */
int PPPDecodeReset(PPPDecodeState *ds)
{
  ds->async_reset = 1;
  return 0;
}

/*
 * Take one byte. Returns a frame's length when c completes one (in obuf),
 * a PPP_ERR_* for a bad frame (bad FCS, short or escaped flag: also to
 * efcn; overflow or a byte outside a frame: not), else 0.
 */
int PPPDecode(PPPDecodeState *ds, int c)
{
  unsigned char ch = c;
  int rval;

  if (ds->async_reset) {
    ds->resync = 1;
    ds->inframe = 0;
    ds->optr = NULL;
    ds->fptr = NULL;
    ds->async_reset = 0;
  }
  if (ds->fptr == NULL || ds->optr == NULL) {   /* start over */
    ds->olen = 0;
    ds->optr = ds->obuf;
    ds->flen = 0;
    ds->fptr = ds->fbuf;
    ds->escaped = 0;
  }
  if (ds->resync && ch != PPP_FLAG)
    return 0;

  if (ch == PPP_ESCAPE) {
    if (ds->inframe)
      ds->escaped = 1;
    return 0;
  }
  if (ch == PPP_FLAG) {
    ds->resync = 0;
    if (!ds->inframe) {
      ds->inframe = 1;
      ds->olen = 0;
      ds->optr = ds->obuf;
      ds->flen = 0;
      ds->fptr = ds->fbuf;
      return 0;
    }
    if (ds->olen == 0)          /* two flags in a row */
      return 0;
    if (ds->escaped) {
      rval = PPP_ERR_ESCAPE;
    }
    else if (ds->olen <= 2) {
      rval = PPP_ERR_SHORT;
    }
    else {
      int n = split_fcs(ds->fbuf,ds->flen,ds->optr);

      ds->optr -= n;
      ds->olen -= n;
      if (pppfcs(PPP_INIT_FCS,ds->obuf,ds->olen,ds->fbuf) == PPP_GOOD_FCS) {
        ds->optr = NULL;        /* the next byte starts over */
        ds->fptr = NULL;
        return ds->olen;
      }
      rval = PPP_ERR_FCS;
    }
    call_efcn(ds->efcn,ds->efcn_arg,rval,ds->obuf,ds->olen);
    /* the flag opens the next frame */
    ds->inframe = 1;
    ds->resync = 0;
    ds->optr = NULL;
    ds->fptr = NULL;
    return rval;
  }

  if (!ds->inframe)
    return PPP_ERR_NOT_IN_FRAME;
  if (ds->escaped) {
    ch ^= PPP_TRANS;
    ds->escaped = 0;
  }
  if (ds->olen < ds->osize) {
    *ds->optr++ = ch;
    ds->olen++;
  }
  else if (ds->flen < 2) {      /* perhaps the FCS */
    *ds->fptr++ = ch;
    ds->flen++;
  }
  else {
    ds->inframe = 0;
    ds->optr = ds->obuf;
    ds->olen = 0;
    ds->fptr = ds->fbuf;
    ds->flen = 0;
    ds->escaped = 0;
    return PPP_ERR_OVERFLOW;
  }
  return 0;
}
