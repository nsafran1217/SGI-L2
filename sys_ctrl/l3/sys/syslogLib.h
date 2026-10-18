/*
 * sys_ctrl/l3/sys/syslogLib.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * (No such header existed; this holds the module's prototypes.)
 * Module: /data/cf/sysco/scs123.patch/sys_ctrl/l3/sys/syslogLib.h
 */

#ifndef SYS_CTRL_L3_SYS_SYSLOGLIB_H
#define SYS_CTRL_L3_SYS_SYSLOGLIB_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* syslogLib.c */
/* SGI's own syslog (not <syslog.h>'s): level, source file, line, message number, format */
void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...) __attribute__((format(printf, 5, 6)));
void syslogLibInit(void (*msgcb)());

#endif /* SYS_CTRL_L3_SYS_SYSLOGLIB_H */
