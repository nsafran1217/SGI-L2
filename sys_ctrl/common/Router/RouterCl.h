/*
 * sys_ctrl/common/Router/RouterCl.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * (No such header existed; this holds the module's prototypes.)
 * Module: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterCl.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_ROUTERCL_H
#define SYS_CTRL_COMMON_ROUTER_ROUTERCL_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "Router.h"   /* for the prototypes */
/* RouterCl.c */
RouterClient *RouterMakeConnection(char *host, int port, int process_id, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)());
RouterClient *RouterMakeGroupConnection(char *host, int port, int process_id, RouterGroupSet *groups, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)());
RouterClient *RouterMakeTransConnection(char *host, int port, int process_id, int timeout, int limit, int (*connect_cb)(), void (*error_cb)());
void RouterRetryConnection(RouterClient *client);
void RouterSetGroups(RouterClient *client, RouterGroupSet *groups);

#endif /* SYS_CTRL_COMMON_ROUTER_ROUTERCL_H */
