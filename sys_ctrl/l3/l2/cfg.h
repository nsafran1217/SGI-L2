/*
 * sys_ctrl/l3/l2/cfg.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/cfg.h
 */

#ifndef SYS_CTRL_L3_L2_CFG_H
#define SYS_CTRL_L3_L2_CFG_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "../../common/IRouter/IRouter.h"   /* for the prototypes */
#include "../../common/Router/Router.h"   /* for the prototypes */
#include "../../common/sys/sysctl_types.h"   /* for the prototypes */
/* cfg.c */
extern int cfg_start_time;
extern int cfg_auto_rescan;
extern int cfg_l2ping_sd;
extern int cfg_ping_response_minimum;
extern int cfg_ping_response_maximum;
extern int cfg_ping_l2_frequency;
extern int cfg_ping_l1_frequency;
extern int cfg_throttle_frequency;
extern int cfg_ping_sender_valid;
extern char cfg_client_id[30];
extern RouterClient *del_client;
extern uint32 del_addr;
void cfg_ping_reset(void);
void cfg_ping_init(void);
void cfg_init(void);
void cfg_ping_l1(int device);
void cfg_ping_l2(RouterClient *client);
void cfg_process_request(IRPacket *req_p);
void cfg_process_response(IRPacket *p);
void pp(IRPacket *p);
void cfg_process_event(IRPacket *p);
void cfg_console_subchannel(IRPacket *p);
void cfg_console_enable(IRPacket *p);
void cfg_power_state(IRPacket *p);
void cfg_margin_state(IRPacket *p);
void cfg_partition(IRPacket *p);
void cfg_system_sn(IRPacket *p);
void cfg_environmental(IRPacket *p);
int strdiff(char *s1, char *s2);
void cfg_setup_configcheck(int delay);
void cfg_setup_l2ping(int delay);
void cfg_configcheck(int start_timer);
void cfg_check_console_events(void);
void cfg_check_smp_events(void);
int cfg_password(RouterClient *client, char *pwguess);
void cfg_connect(RouterClient *client);
void cfg_disconnect(RouterClient *client);
void cfg_establish(RouterClient *client);
void cfg_recv_l2ping(void *cd, int sd);
void cfg_l2ping(int start_timer);

#endif /* SYS_CTRL_L3_L2_CFG_H */
