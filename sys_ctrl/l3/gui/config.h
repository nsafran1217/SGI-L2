/*
 * sys_ctrl/l3/gui/config.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/config.h
 */

#ifndef SYS_CTRL_L3_GUI_CONFIG_H
#define SYS_CTRL_L3_GUI_CONFIG_H

extern "C" {
#include "../../common/sys/Cmd.h"
#include "../../common/main/L2Cfg.h"
}

extern CmdData *parse_data_ptr;

int config_init(char *dest);
int config_set_command_dest(char *str);
char *config_command_dest(void);
int config_dest_includes_l1(L2CfgL1 *l1);
int config_parse_dest(char *str, CmdData *data);
int config_popcnt(char *s, int slen);

#endif /* SYS_CTRL_L3_GUI_CONFIG_H */
