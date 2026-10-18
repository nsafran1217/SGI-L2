/*
 * sys_ctrl/l3/l2/dest.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/dest.h
 */

#ifndef SYS_CTRL_L3_L2_DEST_H
#define SYS_CTRL_L3_L2_DEST_H

#include "../../common/sys/Cmd.h"
struct DEST_s {
    char plist[64];
    char rlist[256];
    char slist[64];
    int type;
    IRAddress list[1024];
    int count;
};
typedef struct DEST_s DEST;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* dest.c */
DEST *dest_init(void);
void dest_free(DEST *d);
void dest_reset(DEST *d);
void dest_default(DEST *d, CmdData *cptr);
int dest_l1(DEST *d, CmdData *cptr);
int dest_l2(DEST *d, CmdData *cptr);
int dest_pcheck(DEST *d, CmdData *cptr, char *rptr);
void dest_print(DEST *d, char *sptr);

#endif /* SYS_CTRL_L3_L2_DEST_H */
