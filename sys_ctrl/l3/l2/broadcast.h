/*
 * sys_ctrl/l3/l2/broadcast.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/broadcast.h
 */

#ifndef SYS_CTRL_L3_L2_BROADCAST_H
#define SYS_CTRL_L3_L2_BROADCAST_H

#include "../../common/IRouter/IRouter.h"
#include "reqrspq.h"
#include "l2cmd.h"

/* (added by the reconstruction) broadcast_l1()'s method ... */
enum { BCAST_PARALLEL = 1, BCAST_SERIAL = 2 };
/* ... and type: the classes of brick (one bit each, sent class by class in
 * this order), and which power states */
#define BCAST_ROUTER    0x01
#define BCAST_IO        0x02
#define BCAST_COMPUTE   0x04
#define BCAST_OTHER     0x80
#define BCAST_ALL       0xff
#define BCAST_POWER_OFF 0x10000     /* only bricks that are off */
#define BCAST_POWER_ON  0x20000     /* only bricks that are on */

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* broadcast.c */
extern int broadcast_debug;
extern int broadcast_response_timeout;
int broadcast(REQRSPQ *q, IRIdent *id);
int broadcast_l2(L2CMD *c, char **results, char *cmd, int response, int delay, int final);
int broadcast_l1(L2CMD *c, int method, char *cmd, int response, int delay, int type, int *slots, int final);

#endif /* SYS_CTRL_L3_L2_BROADCAST_H */
