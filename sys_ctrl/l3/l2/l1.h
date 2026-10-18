/*
 * sys_ctrl/l3/l2/l1.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l1.h
 */

#ifndef SYS_CTRL_L3_L2_L1_H
#define SYS_CTRL_L3_L2_L1_H

#include "../../common/Router/Event.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "../../common/IRouter/IRouter.h"   /* for the prototypes */
#include "../../common/sys/PPP.h"   /* for the prototypes */
#include "../../common/sys/sysctl_types.h"   /* for the prototypes */
/* l1.c */
extern int l1_throttle_freq;
extern unsigned char l1_pkt_in[1];
extern unsigned char l1_pkt_out[1];
extern int l1usb_debug;
extern EventID l1_throttle_timerid;
extern PPPInstance ppp;
extern unsigned char ppp_ibuf[8];
extern unsigned char ppp_obuf[256];
int l1_fd_device(int fd);
int l1_open_usb(void);
int l1_usb_ioctl(int fd, int request);
int l1_flush_usb_device(int fd, int reset);
int l1_open_usb_device(int device);
int l1_close_usb_device(int device, int reopen, char *who);
void l1_service_usb(int data, int fd);
int l1_close_usb(void);
int l1_open_serial_direct(void);
int l1_close_serial_direct(void);
int l1_open_serial_enet(void);
int l1_close_serial_enet(void);
void l1_open(void);
void l1_close(int fd);
void l1_tty_debug(int td);
int l1_tty_open(char *device);
int l1_tty_close(int td);
int l1_usb_recover(int fd, int error);
int l1_read_usb(int fd, unsigned char **bptr, int blen);
int l1_read_raw(int fd, unsigned char *bptr, int blen);
int l1_read_socket(int fd, unsigned char *bptr, int blen);
int l1_read_ppp(int fd, unsigned char **bptr, int32 blen);
int l1_read_l1net(int fd, unsigned char **pbptr, int blen);
void l1_throttle_input(int throttle);
void l1_read_packet(int port, int fd);
int l1_write_usb(int fd, unsigned char *bptr, int blen);
int l1_write_raw(int fd, unsigned char *bptr, int blen);
int l1_write_socket(int fd, unsigned char *bptr, int blen);
int l1_write_ppp(int fd, unsigned char *bptr, int blen);
int l1_write_l1net(int fd, unsigned char *bptr, int blen);
void l1_write_packet(int fd, IRPacket *p);
void l1_ppperr(void *arg, PPPError *err);   /* original: (void *, int err, char *, int) */
int l1_parse_usbpath(char *usbpath);

#endif /* SYS_CTRL_L3_L2_L1_H */
