/*
 * sys_ctrl/l3/IRouter/IRouterL3.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/IRouter/IRouterL3.h
 */

#ifndef SYS_CTRL_L3_IROUTER_IROUTERL3_H
#define SYS_CTRL_L3_IROUTER_IROUTERL3_H

#include "../../common/Router/Router.h"
#include "../../common/IRouter/IRouter.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "../../common/IRouter/IRouter2Router.h"   /* for the prototypes */
#include "../../common/Router/Event.h"   /* for the prototypes */
/* IRouterL3.c */
extern int rtr_error;
extern int rtr_waiting_for;
extern int rtr_rsp_queue_rd;
extern int rtr_rsp_queue_wr;
extern int IRouterEventLoop;

extern RouterClient *rtr_server;
extern IRPacket *rtr_pkt;
extern IRPacket *rtr_rsp_queue[100];
int IRouterConnectL3(char *cname, char *host, int port, IRClient **client, int events, char *(*pw_cb)());
void IRouterDisconnectL3(IRClient *client);
int IRouterRequestL3(IRClient *client, IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum);
int IRouterResponseL3(IRClient *client, IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist);
int IRouterEventL3(IRClient *client, IRIdent *id, int opcode, int argcount, IRArgument *arglist);
int IRouterGetPacketL3(IRIdent *id, IRPacket **pkt, IRClient **client, int wait, int response);
int rtr_connected(RouterClient *client, int opcode, RouterArgument **arglistout);
void rtr_connect_failure(RouterClient *client, int msgnbr, char *host, int port, int retrys);
void rtr_event(RouterClient *client, int opcode, int argcount, RouterArgument *arglistin);

#endif /* SYS_CTRL_L3_IROUTER_IROUTERL3_H */
