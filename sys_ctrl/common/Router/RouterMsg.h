/*
 * sys_ctrl/common/Router/RouterMsg.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterMsg.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_ROUTERMSG_H
#define SYS_CTRL_COMMON_ROUTER_ROUTERMSG_H

#include "../sys/Logger.h"

/* Router error numbers, -300 + the index in Logger's RouterErrorList.
 * (The numbers are SGI's; the names were added by the reconstruction.) */
enum {
    ROUTER_ERR_CONNECT_FAILED = -300,   /* Connection attempt failed */
    ROUTER_ERR_CONNECT_TIMEOUT = -301,  /* Connection attempt timed out */
    ROUTER_ERR_CONNECT_ERROR = -302,    /* Connection attempt error */
    ROUTER_ERR_LOST = -303,             /* Connection lost */
    ROUTER_ERR_TIMEOUT = -304,          /* Connection timed out */
    ROUTER_ERR_ERROR = -305,            /* Connection error */
    ROUTER_ERR_CLOSED_LOCAL = -306,     /* Connection was disconnected by the local side */
    ROUTER_ERR_CLOSED_REMOTE = -307,    /* Connection was disconnected by the remote side */
    ROUTER_ERR_CLOSE_ERROR = -308,      /* Connection disconnect error */
    ROUTER_ERR_SERVER_RUNNING = -309,   /* Server process is already running */
    ROUTER_ERR_NO_OUTPUT = -310,        /* Can not do output on this connection */
    ROUTER_ERR_MALLOC = -311,           /* Memory allocation failed */
    ROUTER_ERR_UNEXPECTED_CLASS = -312, /* Unexpected packet class received */
    ROUTER_ERR_BAD_CLASS = -313,        /* Invalid packet class received */
    ROUTER_ERR_SEQUENCE = -314,         /* Packet sequence error */
    ROUTER_ERR_HOST_ADDR = -315,        /* Cannot determine the Internet address of a host name */
    ROUTER_ERR_HOST_NAME = -316,        /* Cannot determine the host name of a connected host */
    ROUTER_ERR_PROTOCOL = -317,         /* Protocol error */
    ROUTER_ERR_ARG_COUNT = -318,        /* Incorrect number of arguments received */
    ROUTER_ERR_ARG_CLASS = -319,        /* Received arguments are of the wrong class */
    ROUTER_ERR_ARG_SIZE = -320,         /* Received arguments are of the wrong size */
    ROUTER_ERR_NO_PASSWD = -321,        /* Cannot get password file entry of this process */
    ROUTER_ERR_PROCESS_ID = -322,       /* Received an incorrect process ID from the server */
    ROUTER_ERR_DENIED = -323,           /* Connection was denied by the server */
};

#endif /* SYS_CTRL_COMMON_ROUTER_ROUTERMSG_H */
