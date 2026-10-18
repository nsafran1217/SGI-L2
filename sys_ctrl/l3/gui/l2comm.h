/*
 * sys_ctrl/l3/gui/l2comm.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/l2comm.h
 */

#ifndef SYS_CTRL_L3_GUI_L2COMM_H
#define SYS_CTRL_L3_GUI_L2COMM_H

extern "C" {
#include "../../common/IRouter/IRouter.h"
}

typedef int l2comm_packet_cb(IRPacket *pkt, void *data);

int l2comm_init(void);
void *l2comm_add_packet_handler(int pkt_types, l2comm_packet_cb *handler_cb, void *data);
void l2comm_remove_packet_handler(void *handle);
int l2comm_send_text_command(char *cmd, l2comm_packet_cb *handler, void *data);

#endif /* SYS_CTRL_L3_GUI_L2COMM_H */
