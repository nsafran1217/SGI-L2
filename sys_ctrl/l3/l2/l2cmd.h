/*
 * sys_ctrl/l3/l2/l2cmd.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l2cmd.h
 */

#ifndef SYS_CTRL_L3_L2_L2CMD_H
#define SYS_CTRL_L3_L2_L2CMD_H

#include "reqrspq.h"
#include "dest.h"
typedef struct L2CMD_s L2CMD;
typedef void l2cmd_timeout_cb();
typedef void l2cmd_response_cb();
typedef void l2cmd_etimeout_cb();
struct L2CMD_s {
    IRIdent *id;
    REQRSPQ *q;
    DEST *dest;
    l2cmd_timeout_cb *tofunc;
    l2cmd_etimeout_cb *etofunc;
    l2cmd_response_cb *rspfunc;
    void *data;
    int busy;
};

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "cmd.h"   /* for the prototypes */
/* l2cmd.c */
extern Cmd l2cmd_cmds[0];
L2CMD *l2cmd_init(IRIdent *id, l2cmd_timeout_cb *tofunc, l2cmd_etimeout_cb *etofunc, l2cmd_response_cb *rspfunc, void *data);
void l2cmd_free(L2CMD *c);
int l2cmd_process(L2CMD *c, char *command, char **rptr, void *data);
int l2cmd_process_response(L2CMD *c, char *rsp, int rval);
int l2cmd_queue_response(L2CMD *c, unsigned int seqn, IRAddress dest, int timeout);
int l2cmd_power(CmdData *cptr, char **results, L2CMD *c);
int pbay_rsp(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data);
void quit(void);
/* l2cmd.c */
extern char *myname;
void usage(void);

#endif /* SYS_CTRL_L3_L2_L2CMD_H */
