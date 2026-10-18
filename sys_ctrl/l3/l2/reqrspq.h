/*
 * sys_ctrl/l3/l2/reqrspq.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/reqrspq.h
 */

#ifndef SYS_CTRL_L3_L2_REQRSPQ_H
#define SYS_CTRL_L3_L2_REQRSPQ_H

#include "../../common/IRouter/IRouter.h"   /* needed by the reconstruction */
#include "../../common/Router/Event.h"   /* needed by the reconstruction */
#include "../../common/sys/sysctl_types.h"   /* needed by the reconstruction */
struct RSPQ_s {
    unsigned int seqn;
    IRAddress dest;
    IRPacket *pkt;
    unsigned int sort;
    struct RSPQ_s *prev;
    struct RSPQ_s *next;
};
typedef struct RSPQ_s RSPQ;
struct REQQ_s {
    IRPacket *pkt;
    int response;
    int delay;
    struct REQQ_s *prev;
    struct REQQ_s *next;
};
typedef struct REQQ_s REQQ;
struct REQRSPQ_s {
    REQQ *reqq_head;
    REQQ *reqq_tail;
    int reqq_length;
    RSPQ *rspq_head;
    RSPQ *rspq_tail;
    int rspq_length;
    int rspq_max_length;
    int rspq_pending;
    int rspq_timeout;
    int rspq_etimeout;
    EventID rspq_timer;
    void (*rspq_tofunc)();
    void (*rspq_etofunc)();
    void *rspq_todata;
};
typedef struct REQRSPQ_s REQRSPQ;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* reqrspq.c */
REQRSPQ *reqrspq_init(void (*tofunc)(), void (*etofunc)(), void *todata);
void reqrspq_reset(REQRSPQ *q);
void reqrspq_free(REQRSPQ *q);
void reqq_put(REQRSPQ *q, IRPacket *pkt, int response, int delay);
int reqq_get(REQRSPQ *q, IRPacket **pkt, int *response, int *delay);
int reqq_empty(REQRSPQ *q);
void reqq_reset(REQRSPQ *q);
void rspq_put(REQRSPQ *q, unsigned int seqn, IRAddress dest);
int rspq_update(REQRSPQ *q, IRPacket *pkt);
void rspq_reset(REQRSPQ *q);
int rspq_get(REQRSPQ *q, unsigned int *seqn, IRAddress *dest, IRPacket **pkt);
RSPQ *rspq_peek(REQRSPQ *q, RSPQ *qe, unsigned int *seqn, IRAddress *dest, IRPacket **pkt);
int rspq_empty(REQRSPQ *q);
void rspq_timeout_set(REQRSPQ *q, int to);
void rspq_timeout_clr(REQRSPQ *q);

#endif /* SYS_CTRL_L3_L2_REQRSPQ_H */
