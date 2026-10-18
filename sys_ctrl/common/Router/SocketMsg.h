/*
 * sys_ctrl/common/Router/SocketMsg.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/SocketMsg.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_SOCKETMSG_H
#define SYS_CTRL_COMMON_ROUTER_SOCKETMSG_H

#include "../sys/Logger.h"

/* Socket error numbers, -400 + the index in Logger's SocketErrorList.
 * (The numbers are SGI's; the names were added by the reconstruction.) */
enum {
    SOCKET_ERR_EXPORT_INET = -400,      /* Cannot export Internet domain service */
    SOCKET_ERR_EXPORT_UNIX = -401,      /* Cannot export Unix domain service */
    SOCKET_ERR_ACCEPT_INET = -402,      /* Cannot accept Internet domain connection request */
    SOCKET_ERR_ACCEPT_UNIX = -403,      /* Cannot accept Unix domain connection request */
    SOCKET_ERR_CONNECT_INET = -404,     /* Cannot make Internet domain connection */
    SOCKET_ERR_CONNECT_UNIX = -405,     /* Cannot make Unix domain connection */
    SOCKET_ERR_HOST_ADDR = -406,        /* Cannot determine the Internet address of a host name */
    SOCKET_ERR_PEER_HOST = -407,        /* Cannot determine host of connected process */
    SOCKET_ERR_LOCAL_HOST = -408,       /* Cannot get the local host name */
    SOCKET_ERR_BUFFER_SIZE = -409,      /* Cannot set the send/receive buffer size */
};

#endif /* SYS_CTRL_COMMON_ROUTER_SOCKETMSG_H */
