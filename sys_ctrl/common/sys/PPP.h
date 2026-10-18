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

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* PPP.c */
extern char buff[128];
void PPPInit(PPPInstance *pptr, unsigned char *iptr, unsigned int isize, unsigned char *optr, unsigned int osize, unsigned int xonxoff, unsigned int control, unsigned int offset, unsigned int resize, void (*efcn)(), void *efcn_arg);
void PPPReset(PPPInstance *pptr, int which);
int PPPWrite(PPPInstance *pptr, int (*wfcn)(), void *fd, unsigned char *bptr, int blen);
int PPPRead(PPPInstance *pptr, int (*rfcn)(), void *fd, unsigned char **rbuf, int rmax);
int PPPDecodeInit(PPPDecodeState *ds, unsigned char *obuf, int osize, void (*efcn)(), void *efcn_arg);
int PPPDecodeReset(PPPDecodeState *ds);
int PPPDecode(PPPDecodeState *ds, int c);

#endif /* SYS_CTRL_COMMON_SYS_PPP_H */
