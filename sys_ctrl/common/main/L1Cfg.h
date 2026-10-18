/*
 * sys_ctrl/common/main/L1Cfg.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/main/L1Cfg.h
 */

#ifndef SYS_CTRL_COMMON_MAIN_L1CFG_H
#define SYS_CTRL_COMMON_MAIN_L1CFG_H

#include "../IRouter/IRouter.h"
typedef struct {
    int configured;
    int revision;
    int rack;
    int slot;
    int type;
    int console_subchannel;
    int console_enabled;
    unsigned char shub_addrmode;
    unsigned char shub_shrmode;
    short unsigned int unused1;
    int unused2;
    unsigned int cfgbits;
    int scramble_mode;
    int router_type;
    int xtalk_speed;
    int power_state;
    int margin_state;
    int partition;
    char brick_sn[12];
    char system_sn[12];
    int l2_detect;
    unsigned int env_state;
    int conn_state;
    char l2_system_sn[12];
} L1CfgL1;

#endif /* SYS_CTRL_COMMON_MAIN_L1CFG_H */
