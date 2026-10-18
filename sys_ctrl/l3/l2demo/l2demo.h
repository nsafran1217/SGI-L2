/*
 * sys_ctrl/l3/l2demo/l2demo.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2demo/l2demo.h
 */

#ifndef SYS_CTRL_L3_L2DEMO_L2DEMO_H
#define SYS_CTRL_L3_L2DEMO_L2DEMO_H

struct _demo_msg_t {
    int msgno;
    char msgtxt[81];
};
typedef struct _demo_msg_t demo_msg_t;
struct _demo_db_t {
    int current_msgno;
    int current_msgidx;
    int nmsgs;
    demo_msg_t msg[20];
};
typedef struct _demo_db_t demo_db_t;

#endif /* SYS_CTRL_L3_L2DEMO_L2DEMO_H */
