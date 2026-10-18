/*
 * sys_ctrl/common/sys/BuffWrite.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/BuffWrite.h
 */

#ifndef SYS_CTRL_COMMON_SYS_BUFFWRITE_H
#define SYS_CTRL_COMMON_SYS_BUFFWRITE_H

struct _BuffWrite_t {
    char *buff;
    int blen;
    int ulen;
};
typedef struct _BuffWrite_t BuffWrite_t;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* BuffWrite.c */
BuffWrite_t *BuffWriteInit(void);
char *BuffWriteDone(BuffWrite_t *o, int free_buff);
int BuffWrite(void *data, char *str, int len);

#endif /* SYS_CTRL_COMMON_SYS_BUFFWRITE_H */
