/*
 * sys_ctrl/l3/l2/cmd.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/cmd.h
 */

#ifndef SYS_CTRL_L3_L2_CMD_H
#define SYS_CTRL_L3_L2_CMD_H

#include "l2cmd.h"
struct _cmd_response {
    char *sptr;
    char *eptr;
    int size;
    int slen;
    int status;
};
typedef struct _cmd_response cmd_response;
typedef int cmd_packet_cb();
typedef int cmd_response_cb();

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* cmd.c */
void cmd_init(void);
L2CMD *cmd_setup_usr_response(cmd_packet_cb *rsp_cb, void *data);
void cmd_process_request(IRPacket *req);
void cmd_process_response(IRPacket *rsp);
void cmd_process_response_usr(IRPacket *rsp);
int cmd_process_packet_default(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data);
int cmd_process_packet_args(IRPacket *rsp, L2CMD *c, IRAddress *dest, cmd_response *cmd_rsp, int print_source);
int cmd_estimate_packet_rsplen(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data);

#endif /* SYS_CTRL_L3_L2_CMD_H */
