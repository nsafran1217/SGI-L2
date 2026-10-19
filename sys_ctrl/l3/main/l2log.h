/*
 * sys_ctrl/l3/main/l2log.h
 *
 * New in the modern tree: l2's log ("log" command) in a text file,
 * replacing the NVRAM image's log ring. See l2log.c.
 */

#ifndef SYS_CTRL_L3_MAIN_L2LOG_H
#define SYS_CTRL_L3_MAIN_L2LOG_H

void l2logInit(void);
const char *l2logPath(void);
void l2logReset(void);
void l2logInsert(char *message);
void l2logFinsert(char *fmt, ...) __attribute__((format(printf, 1, 2)));
char *l2logFetch(void);

#endif /* SYS_CTRL_L3_MAIN_L2LOG_H */
