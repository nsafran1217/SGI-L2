/*
 * sys_ctrl/common/Router/Socket.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Socket.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_SOCKET_H
#define SYS_CTRL_COMMON_ROUTER_SOCKET_H

#include <stdint.h>

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* Socket.c */
int SocketExportInetConnection(int port);
int SocketExportUnixConnection(int port);
int SocketAcceptInetConnection(int sock, int no_delay);
int SocketAcceptUnixConnection(int sock, int no_delay);
int SocketNodelayMode(int sock, int no_delay);
int SocketMakeInetConnection(char *host, int port, int no_delay);
int SocketMakeUnixConnection(int port, int no_delay);
int SocketSetBufferSize(int sock, int sendbuf, int recvbuf);
int SocketClose(int sock);
int SocketCloseOnly(int sock);
int SocketCloseUnixServer(int sock, int port);
int SocketGetAddr(char *host, uint32_t *addr);
int SocketGetPeerAddr(int sock, uint32_t *addr);
int SocketGetSockAddr(int sock, uint32_t *addr);
int SocketGetName(uint32_t addr, char *name, int name_length);
int SocketIsLocalHost(char *host);
int SocketGetHostName(char **host_name);
int SocketGetHostAddr(uint32_t *addr);
char *SocketAddrStr(uint32_t addr);

#endif /* SYS_CTRL_COMMON_ROUTER_SOCKET_H */
