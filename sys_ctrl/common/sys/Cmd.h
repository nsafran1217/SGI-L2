/*
 * sys_ctrl/common/sys/Cmd.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/Cmd.h
 */

#ifndef SYS_CTRL_COMMON_SYS_CMD_H
#define SYS_CTRL_COMMON_SYS_CMD_H

typedef int CmdCallback();
struct _Cmd {
    char *toks[10];
    CmdCallback *func;
    unsigned int params[4];
    char *desc;
    int visibility;
};
typedef struct _Cmd Cmd;
struct _CmdInstance {
    char *toks[10];
    unsigned int exp_stack[8];
    unsigned int exp_max;
    char *str_stack[8];
    unsigned int str_max;
    unsigned int *params;
    char rlist[256];
    char slist[64];
    char plist[64];
};
typedef struct _CmdInstance CmdData;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* Cmd.c */
extern int cmdlistcnt;
extern Cmd *cmdlist[10];
extern int cmdlistnum[10];
int CmdAddCmds(Cmd *cmds, int num_cmds);
int CmdProcess(int mode, char *cmd, char **results, Cmd *cmds_in, int num_cmds_in, void *data);
void CmdHelpAll(Cmd *cmds_in, int num_cmds_in, int showall, char *rptr);
char *CmdFormat(Cmd *cmds, int cmd);
void CmdHelpCmd(Cmd *cmds_in, int num_cmds_in, char *which, int showall, char **rrptr);
int CmdMatchRange(char *X, int xmax, char *s);

#endif /* SYS_CTRL_COMMON_SYS_CMD_H */
