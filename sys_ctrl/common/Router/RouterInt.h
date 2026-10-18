/*
 * sys_ctrl/common/Router/RouterInt.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterInt.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_ROUTERINT_H
#define SYS_CTRL_COMMON_ROUTER_ROUTERINT_H

#include "Router.h"   /* needed by the reconstruction */
#include "Event.h"
#include <time.h>
#include <sys/time.h>
#include <stddef.h>
typedef void RouterFunc;
typedef struct {
    RouterClient *head;
    RouterClient *tail;
    int total;
} RouterClientList;
typedef struct {
    RouterServer *head;
    RouterServer *tail;
    int total;
} RouterServerList;
typedef struct {
    unsigned int use;
    unsigned int group_count;
} RouterClientType;

#endif /* SYS_CTRL_COMMON_ROUTER_ROUTERINT_H */
