/*
 * sys_ctrl/common/sys/minfo.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * (No such header existed; this holds the module's prototypes.)
 * Module: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/minfo.h
 */

#ifndef SYS_CTRL_COMMON_SYS_MINFO_H
#define SYS_CTRL_COMMON_SYS_MINFO_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* minfo.c */
int list_delete(char *addr, char *who);
void MInfoReset(void);
void MInfoEnable(char **rptr);
void MInfoDisable(void);
void MInfoStatPrint(char **rptr);
void MInfoMapPrint(char **rptr);

#endif /* SYS_CTRL_COMMON_SYS_MINFO_H */
