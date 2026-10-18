/*
 * sys_ctrl/common/Router/RouterSv.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * (No such header existed; this holds the module's prototypes.)
 * Module: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterSv.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_ROUTERSV_H
#define SYS_CTRL_COMMON_ROUTER_ROUTERSV_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "Router.h"   /* for the prototypes */
/* RouterSv.c */
RouterServer *RouterStartServer(int port, int (*validate_cb)(), void (*error_cb)());
int RouterCheckServer(int port);
void RouterStopServer(RouterServer *server);
int RouterGetClients(RouterID **buf);
int RouterGetIDClients(int process_id, RouterID **buf);
void RouterShutDownServers(void);
void RouterCloseOnlyServers(void);
void RouterCloseOnlyServer(RouterServer *server);
RouterServer *RouterFindServer(RouterServer *server);
void RouterConfigure(RouterClient *client);

#endif /* SYS_CTRL_COMMON_ROUTER_ROUTERSV_H */
