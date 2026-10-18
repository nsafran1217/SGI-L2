/*
 * sys_ctrl/l3/api/L1Direct.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/L1Direct.h
 */

#ifndef SYS_CTRL_L3_API_L1DIRECT_H
#define SYS_CTRL_L3_API_L1DIRECT_H

#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <stddef.h>
#include <getopt.h>
#include "../../common/Router/Socket.h"
#include "../../common/Router/Event.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/PPP.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* L1Direct.c */
extern unsigned char l1d_pkt_in[1];
extern unsigned char l1d_pkt_out[1];
extern PPPInstance ppp;
extern unsigned char ppp_ibuf[8];
extern unsigned char ppp_obuf[256];
char *L1DirectUsage(void);
int L1DirectParseCmdline(int *argc, char **argv, int *use_direct);
int L1DirectConnect(void);
int L1DirectOpen(void);
int L1DirectClose(void);
int L1DirectRequest(IRIdent *id, IRAddress *toaddr, int opcode, int argcount, IRArgument *arglist, int *seqnum);
int L1DirectResponse(IRIdent *id, int errcode, IRPacket *reqpkt, int argcount, IRArgument *arglist);
int L1DirectEvent(IRIdent *id, int opcode, int argcount, IRArgument *arglist);
int L1DirectSendPacket(IRPacket *pkt, int fd);
int L1DirectGetPacket(IRPacket **pkt, int wait, int response);
int l1d_open_serial_direct(void);
int l1d_close_serial_direct(void);
int l1d_open_serial_enet(void);
int l1d_close_serial_enet(void);
int l1d_open(int connect);
int l1d_close(void);
void l1d_tty_debug(int td);
int l1d_tty_open(char *device);
int l1d_tty_close(int td);
int l1d_read_data(int fd, unsigned char *bptr, int blen);
int l1d_read_ppp(int fd, uint8 **bptr, int32 blen);
void l1d_read_packet(int port, int fd);
int l1d_write_data(int fd, unsigned char *bptr, int blen);
int l1d_write_ppp(int fd, uint8 *bptr, int blen);
void l1d_write_packet(int fd, IRPacket *p);
void l1d_ppperr(void *arg, PPPError *err);   /* original: (void *, int err, char *, int) */

#endif /* SYS_CTRL_L3_API_L1DIRECT_H */
