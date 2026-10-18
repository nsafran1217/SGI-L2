/*
 * sys_ctrl/common/Router/SocketIO.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * (No such header existed; this holds the module's prototypes.)
 * Module: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/SocketIO.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_SOCKETIO_H
#define SYS_CTRL_COMMON_ROUTER_SOCKETIO_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* SocketIO.c */
int SocketRead(int fd, unsigned char *buffer, int len);
int SocketWrite(int fd, unsigned char *buffer, int len);

#endif /* SYS_CTRL_COMMON_ROUTER_SOCKETIO_H */
