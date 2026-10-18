/*
 * sys_ctrl/common/Router/EventMsg.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/EventMsg.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_EVENTMSG_H
#define SYS_CTRL_COMMON_ROUTER_EVENTMSG_H

#include "../sys/Logger.h"

/* Event error numbers, -500 + the index in Logger's EventErrorList.
 * (The numbers are SGI's; the names were added by the reconstruction.) */
enum {
    EVENT_ERR_FD_RANGE = -500,          /* File descriptor is out of range */
    EVENT_ERR_INPUT_OVERLAY = -501,     /* Input event processing is being overlayed */
    EVENT_ERR_OUTPUT_OVERLAY = -502,    /* Output event processing is being overlayed */
    EVENT_ERR_MALLOC = -503,            /* Memory allocation failed */
    EVENT_ERR_SELECT = -504,            /* Event processing error */
    EVENT_ERR_NO_INPUT_FUNC = -505,     /* Missing input event processing function */
    EVENT_ERR_NO_OUTPUT_FUNC = -506,    /* Missing output event processing function */
};

#endif /* SYS_CTRL_COMMON_ROUTER_EVENTMSG_H */
