/*
 * sys_ctrl/common/sys/Cmd.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/Cmd.h
 */

#ifndef SYS_CTRL_COMMON_SYS_CMD_H
#define SYS_CTRL_COMMON_SYS_CMD_H

#include <stdint.h>

/*
 * A command form's tokens (Cmd.toks, up to CMD_TOKS, ended by CMD_END) are
 * words, "a|b" for alternatives, or token types: "pointers" below
 * CMD_WORD_MIN. (The numbers are SGI's; the names were added by the
 * reconstruction.)
 */
enum {
    CMD_END = 0,                /* end of the form: nothing may follow */
    CMD_EXP = 1,                /* a number, C notation (strtoul base 0) */
    CMD_DEC = 2,                /* a decimal number */
    CMD_HEX = 3,                /* a hexadecimal number */
    CMD_OCT = 4,                /* an octal number */
    CMD_STR = 5,                /* any word */
    CMD_REST = 6,               /* the rest of the line ("<command>") */
    CMD_IP = 7,                 /* a.b.c.d */
    CMD_PORT_L1 = 8,            /* :port:l1 */
    CMD_IP_PORT_L1 = 9,         /* a.b.c.d:port:l1 */
    CMD_RANGE = 10,             /* "rack|r <rng> [slot|s <rng>]", "partition|p <rng>", "*" */
    CMD_RACKSLOT = 11,          /* <rack><type><slot>, as 001c05 */
    CMD_BAY = 12,               /* "s|b<rng>": only in usage text, matches nothing */
    CMD_WORD = 13,              /* (what token_type() says for a word) */
};
#define CMD_WORD_MIN  1000
#define CMD_TOK(type) ((char *)(uintptr_t)(type))
#define CMD_TOKS      10

/* what a range list (CmdData rlist/slist/plist, CmdMatchRange()) holds */
enum {
    CMD_RANGE_NONE = 0,         /* not selected */
    CMD_RANGE_ONE = 1,          /* a single number */
    CMD_RANGE_FIRST = 2,        /* n-m: n */
    CMD_RANGE_MID = 3,          /* n-m: between */
    CMD_RANGE_LAST = 4,         /* n-m: m */
    CMD_RANGE_ALL = 5,          /* "*" or "all" */
    CMD_RANGE_ANY = 6,          /* none given: all by default ("**") */
};

/* CmdProcess() modes and errors (Logger's Cmd module, -8xx) */
#define CMD_EXECUTE     1       /* run the command; otherwise just match it */
enum {
    CMD_ERR_ERROR = -800,       /* CMD_ERROR: no form matches */
    CMD_ERR_EMPTY = -801,       /* CMD_EMPTY: a blank line */
};

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
