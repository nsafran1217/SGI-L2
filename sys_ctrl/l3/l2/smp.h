/*
 * sys_ctrl/l3/l2/smp.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/smp.h
 */

#ifndef SYS_CTRL_L3_L2_SMP_H
#define SYS_CTRL_L3_L2_SMP_H

struct L2CMD_s;

#include "l2cmd.h"
#include "dest.h"
struct SMPGroup_s {
    int id;
    int count;
    int mode;
    int partition;
    int confilter;
    IRAddress l1addr;
    IRAddress conaddr;
    struct L2CMD_s *l2cmd;
    char ibuf[1];
    unsigned char __stabs_pad1[3];
    int ilen;
    char cbuf[128];
    int clen;
    char *cptr;
    int shell;
    int lpbk_pending;
};
typedef struct SMPGroup_s SMPGroup;
struct SMP_s {
    IRIdent *id;
    int rfd;
    int wfd;
    uint32 host;
    int hung;
    void (*rfcn)();
    int grpid;
    SMPGroup *grp;
    struct SMP_s *next;
};
typedef struct SMP_s SMP;

/* (added by the reconstruction) SMPGroup.mode */
enum {
    SMP_MODE_L2 = 0,            /* the L2's command line */
    SMP_MODE_CONSOLE = 1,       /* keys to the system console */
    SMP_MODE_CONSOLE_ESC = 2,   /* ... escaped to the L2 for one command (CTRL-T) */
    SMP_MODE_L1 = 3,            /* keys to an L1's command processor */
    SMP_MODE_L1_ESC = 4,        /* ... escaped */
    SMP_MODE_SHELL = 5,         /* "shell" */
};

/* the SMP (console) network ports, plus IR_PORT_BIAS (enet.c); the serial
 * consoles also give smp_init() SMP_PORT */
#define SMP_PORT        8001
#define SMP_QUIET_PORT  8003    /* connections not logged */

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* smp.c */
extern SMP *smp_list;
extern int smp_count;
extern int smp_debug;
extern int smp_input_debug;
extern int smp_console_debug;
SMP *smp_init(IRIdent *id, int rfd, int wfd, void (*rfcn)(), uint32 host, int port);
void smp_free(SMP *smp);
void smp_cleanup(void);
void smp_reset(void);
int smp_is_valid(SMP *smp);
void smp_baud(int baud);
int smp_console_count(unsigned char *pselect);
int smp_get_mode(SMP *smp);
int smp_set_mode(SMP *smp, int mode);
IRAddress smp_get_l1addr(SMP *smp);
IRAddress smp_set_l1addr(SMP *smp, IRAddress l1addr);
IRAddress smp_get_conaddr(SMP *smp, IRAddress *raddr, int *override);
IRAddress smp_set_conaddr(SMP *smp, IRAddress new_conaddr);
int smp_get_partition(SMP *smp);
int smp_set_partition(SMP *smp, int partition);
IRAddress smp_get_confilter(SMP *smp);
IRAddress smp_set_confilter(SMP *smp, IRAddress confilter);
void smp_query(SMP *smp, int verbose, char **results);
int smp_join(SMP *smp, int group);
int smp_leave(SMP *smp);
void smp_input_l1sysco(SMP *smp, int c);
void smp_input_console(SMP *smp, int c);
void smp_input(SMP *smp, char *rbuf, int rlen);
void smp_output(SMP *smp, char *bptr, int blen);
void smp_prompt(SMP *smp);
IRAddress smp_chkcon_present(SMP *smp);
void smp_chkcon_changes(int get_check);
int smp_shell(SMP *smp, char *cmd);
void smp_process_packet(SMP *smp, IRPacket *p, int source, void (*w)());
void smp_process_event(IRPacket *p);
void q(SMP *smp);
void smp_process_response(IRPacket *p);
void smp_read(SMP *smp);
void smp_write(SMP *smp, char *ibptr, int iblen);
int l2_console_printf(const char *format, ...) __attribute__((format(printf, 1, 2)));   /* SGI code writes fprintf(NULL, ...) */
void smp_echo(SMP *smp);
void smp_console(SMP *smp, IRAddress conaddr, int reenter);
void smp_tty_config(int fd, int baud);
void smp_tty_reconfig(int fd);
void smp_tty_debug(int fd);

#endif /* SYS_CTRL_L3_L2_SMP_H */
