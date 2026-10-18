/*
 * sys_ctrl/common/main/EnetServer.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/main/EnetServer.h
 */

#ifndef SYS_CTRL_COMMON_MAIN_ENETSERVER_H
#define SYS_CTRL_COMMON_MAIN_ENETSERVER_H

#include "../IRouter/IRouter.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "../Router/Router.h"   /* for the prototypes */
/* EnetServer.c */
extern RouterServer *enet_server;
extern long unsigned int enet_ip;
extern IRIdent *enet_id;
void EnetServerInit(IRIdent *id, int (*password_cb)(), void (*connect_cb)(), void (*disconnect_cb)(), void (*establish_cb)(), int (*packet_cb)());
void EnetServerStart(int port, int my_process_id, char *appname);
int EnetServerCheck(int port);
int enet_client_add(unsigned int ip, unsigned int port, RouterClient *client);
int enet_validate(RouterClient *client, long unsigned int addr, char *host);
int enet_client_connected(RouterClient *client, int opcode, int id, int retrys, int argcountin, RouterArgument *arglistin);
void enet_client_disconnected(RouterClient *client, int msgnbr, char *host, int port, int retrys);
int EnetServerConnect(char *host, int port);
int enet_established(RouterClient *client, int opcode, RouterArgument **arglistout);
void enet_failure(RouterClient *client, int msgnbr, char *host, int port, int retrys);
void enet_client_free(RouterClient *client);
int enet_request(RouterClient *client, int request, int argcountin, RouterArgument *arglistin, RouterArgument **arglistout);
void enet_event(RouterClient *client, int event, int argcountin, RouterArgument *arglistin);

#endif /* SYS_CTRL_COMMON_MAIN_ENETSERVER_H */
