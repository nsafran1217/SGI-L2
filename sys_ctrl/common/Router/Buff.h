/*
 * sys_ctrl/common/Router/Buff.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Buff.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_BUFF_H
#define SYS_CTRL_COMMON_ROUTER_BUFF_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* Buff.c */
int BuffCompress(unsigned char *ibuf, unsigned int ilen, unsigned char **obuf, unsigned int *olen);
int BuffUncompress(unsigned char *ibuf, unsigned int ilen, unsigned char **obuf, unsigned int *olen);
int BuffFree(unsigned char *buff);

#endif /* SYS_CTRL_COMMON_ROUTER_BUFF_H */
