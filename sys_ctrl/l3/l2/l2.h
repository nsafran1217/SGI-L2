/*
 * sys_ctrl/l3/l2/l2.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l2.h
 */

#ifndef SYS_CTRL_L3_L2_L2_H
#define SYS_CTRL_L3_L2_L2_H

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include "../../common/Router/Socket.h"
#include "../../common/Router/Event.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../../common/sys/PPP.h"
#include "../../common/sys/brick_types.h"
#include "../../common/main/EnetServer.h"
#include "../../common/main/L2Cfg.h"
#include "l2_rev.h"
typedef struct {
    int status;
    char device[20];
    char usbpath[30];
    unsigned char __stabs_pad1[2];
    int fd;
    EventID timer;
    int rd_errcnt;
    int wr_errcnt;
} L2L1Port;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include <signal.h>   /* for the prototypes */
/* l2.c */
extern char *l2_myname;
extern int l2_debug;
extern int l2_discover;
extern int l2_l1_conn_mode;
extern int l2_l1_local_port;
extern int l2_l1_serial_hostport;
extern int l2_pc;
extern int l2_hardware;
extern int l2_flow_hwater;
extern int l2_flow_lwater;
extern int l2_copynum;
extern char l2_l1_serial_device[512];
extern char l2_l1_serial_hostname[32];
extern L2L1Port l2_l1_ports[40];
extern int l2_l1_control;
extern char *l2_l1_device;
extern IRIdent l2_id;
extern IRIdent l2_console_id;
extern IRIdent l2_modem_id;
extern IRIdent l2_cfg_id;
extern IRIdent l2_lpbk_id;
extern IRIdent l2_route_id;
extern IRIdent l2_cmd_id;
extern IRIdent l2_cmdusr_id;
extern IRIdent l2_apwr_id;
extern char l2_current_version[32];
extern char l2_flash_version[32];
extern char l2_display_version[32];
extern uint32 l2_ip;
void oops_handler(int sig, siginfo_t *info, void *raw_uc);
char *l2_firmware_version(void);
void l2_flow_setup(int hwater, int lwater);

#endif /* SYS_CTRL_L3_L2_L2_H */
