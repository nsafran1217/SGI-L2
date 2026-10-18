/*
 * sys_ctrl/common/IRouter/IRouterInt.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/IRouter/IRouterInt.h
 */

#ifndef SYS_CTRL_COMMON_IROUTER_IROUTERINT_H
#define SYS_CTRL_COMMON_IROUTER_IROUTERINT_H

#include "IRouter.h"   /* needed by the reconstruction */
#include "../sys/sysctl_types.h"   /* needed by the reconstruction */
typedef struct {
    uint32 data;
    uint16 dtype;
    uint16 timeout;
    uint16 lost_req;
    uint16 lost_rsp;
    uint16 lost_evt;
    uint16 lost_evt_repl;
} IRAction;
typedef struct {
    IRAddress addr;
    IRAction action[2];
} IRLocalClient;
struct _IRRemoteClient {
    IRAddress addr;
    uint32 target;
    IRAction action[2];
    struct _IRRemoteClient *next;
};
typedef struct _IRRemoteClient IRRemoteClient;
struct _IREventClient {
    IRAddress addr;
    IRAction action;
    uint32 event_mask;
    struct _IREventClient *next;
};
typedef struct _IREventClient IREventClient;

#endif /* SYS_CTRL_COMMON_IROUTER_IROUTERINT_H */
