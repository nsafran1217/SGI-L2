/*
 * sys_ctrl/common/sys/Logger.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/Logger.h
 */

#ifndef SYS_CTRL_COMMON_SYS_LOGGER_H
#define SYS_CTRL_COMMON_SYS_LOGGER_H

typedef struct {
    char *proc_name;
    long int time;
    int msgnbr;
    char *func_name;
    int errnbr;
    char *host;
    int port;
    char *process;
    char *opt_text;
} LoggerEntry;
typedef struct {
    char *name;
    int count;
    char **message;
} LoggerMessageRange;
#include "../../l3/sys/LoggerMsg.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* Logger.c */
extern char *RouterErrorList[0];
extern char *SocketErrorList[0];
extern char *EventErrorList[0];
extern char *IRouterErrorList[0];
extern char *PPPErrorList[0];
extern char *cmdErrorList[0];
extern char *flashdrvErrorList[0];
extern LoggerMessageRange LoggerErrorRange[0];
void LoggerInit(char *process_name);
void LoggerHandler(void (*logger_handler)());
int LoggerEnable(void);
int LoggerDisable(void);
void LoggerRestore(int value);
void LogError(int msgnbr, char *func_name, int errnbr, char *format);
void LogErrorHost(int msgnbr, char *func_name, int errnbr, char *host, int port, char *format);
char *LoggerTime(LoggerEntry *entry);
char *LoggerFormat(LoggerEntry *entry);
void LoggerStrFormat(LoggerEntry *entry, char *str);
char *LoggerDefaultMessage(int msgnbr);
char *LoggerModuleMessage(int msgnbr);
char *LoggerErrorMessage(int msgnbr);
void LoggerLogMessage(int msgnbr, char *func_name, int errnbr, char *host, int port, char *process, char *format, ...);

#endif /* SYS_CTRL_COMMON_SYS_LOGGER_H */
