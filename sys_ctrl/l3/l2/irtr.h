/*
 * sys_ctrl/l3/l2/irtr.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/irtr.h
 */

#ifndef SYS_CTRL_L3_L2_IRTR_H
#define SYS_CTRL_L3_L2_IRTR_H

#include "../../common/IRouter/IRouter.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* irtr.c */
extern int irtr_debug;
int IRouterSendTargetedPacket(IRIdent *id, IRPacket *pkt);
int IRouterSendBroadcastPacket(IRIdent *id, IRPacket *pkt);
int IRouterSendBroadcastPacketToClients(IRIdent *id, IRPacket *pkt);
int IRouterSendPacket(IRIdent *id, IRPacket *pkt);

#endif /* SYS_CTRL_L3_L2_IRTR_H */
