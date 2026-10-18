/*
 * sys_ctrl/common/sys/sysutils.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/sysutils.h
 */

#ifndef SYS_CTRL_COMMON_SYS_SYSUTILS_H
#define SYS_CTRL_COMMON_SYS_SYSUTILS_H

#include "sysctl_types.h"   /* needed by the reconstruction */
#include <pthread.h>
#include <errno.h>
typedef pthread_t task_t;
struct _sem_t {
    char name[8];
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    uint8 count;
    uint8 reset;
};
typedef struct _sem_t sem_t;
struct _queue_t {
    pthread_mutex_t mutex;
    pthread_cond_t rcond;
    pthread_cond_t wcond;
    char qu_name[8];
    uint16 qu_size;
    uint16 qu_highwater;
    uint16 qu_available;
    uint16 qu_messages;
    uint8 qu_message_size;
    unsigned char __stabs_pad1[3];
    uint32 *qu_start;
    uint32 *qu_end;
    uint32 *qu_write;
    uint32 *qu_read;
    uint32 qu_total;
    uint32 qu_wait;
};
typedef struct _queue_t queue_t;

#endif /* SYS_CTRL_COMMON_SYS_SYSUTILS_H */
