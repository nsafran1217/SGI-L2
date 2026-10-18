/*
 * sys_ctrl/common/sys/PPP.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/PPP.h
 */

#ifndef SYS_CTRL_COMMON_SYS_PPP_H
#define SYS_CTRL_COMMON_SYS_PPP_H

typedef short unsigned int U16;
struct _PPPError {
    int status;
    unsigned char *bptr;
    unsigned int blen;
};
typedef struct _PPPError PPPError;
struct _PPPInstance {
    void (*efcn)();
    void *efcn_arg;
    unsigned char *ibuf;
    unsigned int isize;
    unsigned char *iptr;
    int ilen;
    unsigned char *obuf;
    unsigned int osize;
    unsigned char *optr;
    int olen;
    unsigned int xonxoff;
    unsigned int control;
    unsigned int offset;
    unsigned int resize;
    unsigned int inframe;
};
typedef struct _PPPInstance PPPInstance;
struct _PPPDecodeState {
    void (*efcn)();
    void *efcn_arg;
    unsigned char *obuf;
    unsigned char *optr;
    int olen;
    int osize;
    unsigned char fbuf[2];
    unsigned char __stabs_pad1[2];
    unsigned char *fptr;
    unsigned int flen;
    int escaped;
    int resync;
    int inframe;
    int async_reset;
};
typedef struct _PPPDecodeState PPPDecodeState;

/* PPP error numbers, -700 + the index in Logger's PPPErrorList.
 * (The numbers are SGI's; the names were added by the reconstruction.) */
enum {
    PPP_ERR_FCS = -700,                 /* bad FCS (checksum) */
    PPP_ERR_OVERFLOW = -701,            /* read buffer overflow */
    PPP_ERR_SHORT = -702,               /* short read/frame */
    PPP_ERR_ESCAPE = -703,              /* escape sequence in read stream */
    PPP_ERR_CONTROL = -704,             /* control sequence in read stream */
    PPP_ERR_NOT_IN_FRAME = -705,        /* read stream not in frame */
    PPP_ERR_REALLOC = -706,             /* read buffer reallocation failed */
};

/* PPPReset() which */
#define PPP_RESET_INPUT   1
#define PPP_RESET_OUTPUT  2

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* PPP.c */

void PPPInit(PPPInstance *pptr, unsigned char *iptr, unsigned int isize, unsigned char *optr, unsigned int osize, unsigned int xonxoff, unsigned int control, unsigned int offset, unsigned int resize, void (*efcn)(), void *efcn_arg);
void PPPReset(PPPInstance *pptr, int which);
int PPPWrite(PPPInstance *pptr, int (*wfcn)(), void *fd, unsigned char *bptr, int blen);
int PPPRead(PPPInstance *pptr, int (*rfcn)(), void *fd, unsigned char **rbuf, int rmax);
int PPPDecodeInit(PPPDecodeState *ds, unsigned char *obuf, int osize, void (*efcn)(), void *efcn_arg);
int PPPDecodeReset(PPPDecodeState *ds);
int PPPDecode(PPPDecodeState *ds, int c);

#endif /* SYS_CTRL_COMMON_SYS_PPP_H */
