/*
 * sys_ctrl/common/IRouter/IRouter2Router.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/IRouter/IRouter2Router.h
 */

#ifndef SYS_CTRL_COMMON_IROUTER_IROUTER2ROUTER_H
#define SYS_CTRL_COMMON_IROUTER_IROUTER2ROUTER_H

#include "../Router/Router.h"
#include "IRouter.h"
typedef RouterClient IRClient;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* IRouter2Router.c */
int IRouterForwardPacket(IRClient *client, IRIdent *id, IRPacket *pkt);
int IRouterPacketToRouter(RouterClient *client, IRIdent *id, IRPacket *pkt);
IRPacket *IRouterPacketFromRouter(int argcount, RouterArgument *arglistin);

#endif /* SYS_CTRL_COMMON_IROUTER_IROUTER2ROUTER_H */
