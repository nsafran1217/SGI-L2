/*
 * sys_ctrl/l3/IRouter/IRouterOS.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/IRouter/IRouterOS.h
 */

#ifndef SYS_CTRL_L3_IROUTER_IROUTEROS_H
#define SYS_CTRL_L3_IROUTER_IROUTEROS_H

#include "../../common/Router/Router.h"
#include "../../common/IRouter/IRouter.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "../../common/IRouter/IRouter2Router.h"   /* for the prototypes */
/* IRouterOS.c */
int IRouterConnectOS(char *cname, char *device, int port, IRClient **client, int events, char *(*pw_cb)());
void IRouterDisconnectOS(IRClient *client);
int IRouterRequestOS(IRClient *client, IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum);
int IRouterResponseOS(IRClient *client, IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist);
int IRouterEventOS(IRClient *client, IRIdent *id, int opcode, int argcount, IRArgument *arglist);
int IRouterGetPacketOS(IRIdent *id, IRPacket **pkt, IRClient **client, int wait, int response);

#endif /* SYS_CTRL_L3_IROUTER_IROUTEROS_H */
