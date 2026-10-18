/*
 * sys_ctrl/common/sys/Logger.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/Logger.c
 *
 * Error logging and error numbers. An error number (msgnbr) is either an
 * errno value, 1..299 of either sign, or a module message, -(300 + 100 *
 * module + index): the modules and their messages are LoggerErrorRange
 * below (Router -3xx, Socket -4xx, Event -5xx, IRouter -6xx, PPP -7xx,
 * Cmd -8xx, FlashDrv -9xx). Each message list ends in NULL; a module's
 * count includes it.
 *
 * LogError() and friends fill in a LoggerEntry and hand it to the handler
 * (LoggerHandler()), by default one that prints to stderr.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "Logger.h"

char *RouterErrorList[25] = {
  "Connection attempt failed",
  "Connection attempt timed out",
  "Connection attempt error",
  "Connection lost",
  "Connection timed out",
  "Connection error",
  "Connection was disconnected by the local side",
  "Connection was disconnected by the remote side",
  "Connection disconnect error",
  "Server process is already running",
  "Can not do output on this connection",
  "Memory allocation failed",
  "Unexpected packet class received",
  "Invalid packet class received",
  "Packet sequence error",
  "Cannot determine the Internet address of a host name",
  "Cannot determine the host name of a connected host",
  "Protocol error",
  "Incorrect number of arguments received",
  "Received arguments are of the wrong class",
  "Received arguments are of the wrong size",
  "Cannot get password file entry of this process",
  "Received an incorrect process ID from the server",
  "Connection was denied by the server",
  NULL
};
char *SocketErrorList[11] = {
  "Cannot export Internet domain service",
  "Cannot export Unix domain service",
  "Cannot accept Internet domain connection request",
  "Cannot accept Unix domain connection request",
  "Cannot make Internet domain connection",
  "Cannot make Unix domain connection",
  "Cannot determine the Internet address of a host name",
  "Cannot determine host of connected process",
  "Cannot get the local host name",
  "Cannot set the send/receive buffer size",
  NULL
};
char *EventErrorList[8] = {
  "File descriptor is out of range",
  "Input event processing is being overlayed",
  "Output event processing is being overlayed",
  "Memory allocation failed",
  "Event processing error",
  "Missing input event processing function",
  "Missing output event processing function",
  NULL
};
char *IRouterErrorList[29] = {
  "NO_ROUTER_ERROR",
  "bad packet type",
  "bad task ID",
  "duplicate target ID",
  "malloc failed",
  "duplicate task ID",
  "bad event entry",
  "bad argument list argument count",
  "no receiver for packet",
  "no device to read/write",
  "attempt to send to full queue",
  "queue is full",
  "read failed - read error",
  "read failed - not first frame",
  "read failed - unexpected frame",
  "read failed - select() error",
  "read timeout on multiframe packet",
  "write failed",
  "sequence ID mismatch",
  "wait further for response",
  "timeout waiting for packet",
  "read failed - end of file",
  "write failed - end of file (zero bytes written) ",
  "framing error, frame incomplete",
  "framing error, frame overflow",
  "framing error, frame underflow",
  "framing error, frame control",
  "response packet is too large",
  NULL
};
char *PPPErrorList[8] = {
  "bad FCS (checksum)",
  "read buffer overflow",
  "short read/frame",
  "escape sequence in read stream",
  "control sequence in read stream",
  "read stream not in frame",
  "read buffer reallocation failed",
  NULL
};
char *cmdErrorList[3] = {
  "CMD_ERROR",
  "CMD_EMPTY",
  NULL
};
char *flashdrvErrorList[10] = {
  "FLASHDRV_INVALID_ADDRESS",
  "FLASHDRV_PROGRAM_FAILED",
  "FLASHDRV_PROGRAM_MISCOMPARE",
  "FLASHDRV_ERASE_FAILED",
  "FLASHDRV_ERASE_MISCOMPARE",
  "FLASHDRV_ID_MISCOMPARE",
  "Error checking flash file status",
  "No flash space available to write this file",
  "Error writing to flash file",
  NULL
};
LoggerMessageRange LoggerErrorRange[8] = {
  { "Router", 25, RouterErrorList },
  { "Socket", 11, SocketErrorList },
  { "Event", 8, EventErrorList },
  { "IRouter", 29, IRouterErrorList },
  { "PPP", 8, PPPErrorList },
  { "Cmd", 3, cmdErrorList },
  { "FlashDrv", 10, flashdrvErrorList },
  { NULL, 0, NULL }
};

#define MODULE_FIRST  (-300)    /* the Router module's base */
#define MODULES       ((int)(sizeof(LoggerErrorRange) / sizeof(LoggerErrorRange[0])) - 1)
#define ERRNO_MAX     299       /* larger magnitudes are not errno values */

static void LoggerDefaultHandler(LoggerEntry *entry);

static char *ProcessName = "";
static char *Seperator = ", ";
static void (*LogHandler)() = LoggerDefaultHandler;
static int LogErrors = 1;
static char MsgBuf[1025];

/* name the log entries after the program (the last part of its path) */
void LoggerInit(char *process_name)
{
  char *slash;

  slash = strrchr(process_name,'/');
  ProcessName = slash != NULL ? slash + 1 : process_name;
}

void LoggerHandler(void (*logger_handler)())
{
  LogHandler = logger_handler;
}

/* LoggerEnable() and LoggerDisable() return the previous setting, for
 * LoggerRestore() */
int LoggerEnable(void)
{
  int previous = LogErrors;

  LogErrors = 1;
  return previous;
}

int LoggerDisable(void)
{
  int previous = LogErrors;

  LogErrors = 0;
  return previous;
}

void LoggerRestore(int value)
{
  LogErrors = value;
}

void LogError(int msgnbr, char *func_name, int errnbr, char *format, ...)
{
  va_list args;

  va_start(args,format);
  LoggerVLogMessage(msgnbr,func_name,errnbr,"",0,"",format,args);
  va_end(args);
}

void LogErrorHost(int msgnbr, char *func_name, int errnbr, char *host, int port, char *format, ...)
{
  va_list args;

  va_start(args,format);
  LoggerVLogMessage(msgnbr,func_name,errnbr,host,port,"",format,args);
  va_end(args);
}

/* the entry's time as ctime() prints it, without the newline */
char *LoggerTime(LoggerEntry *entry)
{
  time_t when = entry->time;
  char *time_str;

  time_str = ctime(&when);
  time_str[strlen(time_str) - 1] = '\0';
  return time_str;
}

/* append text to str (size bytes in all), truncating */
static void append(char *str, size_t size, char *text)
{
  size_t len = strlen(str);

  while (len + 1 < size && *text != '\0')
    str[len++] = *text++;
  str[len] = '\0';
}

/*
 * "proc, func(), errno text, text, host = h, port = p, process = q": the
 * parts that are set, separated by Seperator.
 */
static void format_entry(LoggerEntry *entry, char *str, size_t size)
{
  char number[40];
  char *syserr;

  str[0] = '\0';
  append(str,size,entry->proc_name);
  if (entry->func_name != NULL && *entry->func_name != '\0') {
    append(str,size,Seperator);
    append(str,size,entry->func_name);
    append(str,size,"()");
  }
  if (entry->errnbr != 0) {
    append(str,size,Seperator);
    syserr = strerror(entry->errnbr);
    if (syserr == NULL) {
      sprintf(number,"Unknown error number %d",entry->errnbr);
      syserr = number;
    }
    append(str,size,syserr);
  }
  if (entry->opt_text != NULL && *entry->opt_text != '\0') {
    append(str,size,Seperator);
    append(str,size,entry->opt_text);
  }
  if (entry->host != NULL && *entry->host != '\0') {
    append(str,size,Seperator);
    append(str,size,"host = ");
    append(str,size,entry->host);
  }
  if (entry->port > 0) {
    append(str,size,Seperator);
    sprintf(number,"port = %d",entry->port);
    append(str,size,number);
  }
  if (entry->process != NULL && *entry->process != '\0') {
    append(str,size,Seperator);
    append(str,size,"process = ");
    append(str,size,entry->process);
  }
}

/* the entry's text (a static buffer, truncated to fit) */
char *LoggerFormat(LoggerEntry *entry)
{
  format_entry(entry,MsgBuf,sizeof(MsgBuf));
  return MsgBuf;
}

/* the entry's text into str, which must be large enough */
void LoggerStrFormat(LoggerEntry *entry, char *str)
{
  format_entry(entry,str,SIZE_MAX);
}

/* msgnbr rounded toward zero to its module's base (-300, -400, ...) */
static int module_base(int msgnbr)
{
  return msgnbr / 100 * 100;
}

/*
 * The module msgnbr belongs to, or NULL. (The original also took -10xx,
 * the table's empty end entry: a "(null)" module, and -1000 crashed.)
 */
static LoggerMessageRange *module_of(int msgnbr)
{
  int base = module_base(msgnbr);
  int module;

  if (base > MODULE_FIRST)
    return NULL;
  module = (MODULE_FIRST - base) / 100;
  if (module >= MODULES)
    return NULL;
  return &LoggerErrorRange[module];
}

/* the module's text for msgnbr, or NULL if it has none (the original
 * printed a list's NULL end as "(null)" and read the slot past it) */
static char *message_of(LoggerMessageRange *module, int msgnbr)
{
  int index = -(msgnbr % 100);

  if (index >= module->count)
    return NULL;
  return module->message[index];
}

/* the text for any error number (a static buffer) */
char *LoggerDefaultMessage(int msgnbr)
{
  static char message[80];
  LoggerMessageRange *module;
  char *text;
  int errnum;

  if (msgnbr != 0 && msgnbr >= -ERRNO_MAX && msgnbr <= ERRNO_MAX) {
    errnum = abs(msgnbr);
    sprintf(message,"%s [errno %d]",strerror(errnum),errnum);
    return message;
  }
  module = module_of(msgnbr);
  if (module == NULL) {
    sprintf(message,"Unknown Module %d, message = %d",module_base(msgnbr),msgnbr % 100);
    return message;
  }
  text = message_of(module,msgnbr);
  if (text == NULL)
    sprintf(message,"Unknown %s message %d",module->name,msgnbr);
  else
    sprintf(message,"%s:%s",module->name,text);
  return message;
}

/* the name of msgnbr's module */
char *LoggerModuleMessage(int msgnbr)
{
  LoggerMessageRange *module = module_of(msgnbr);

  return module != NULL ? module->name : "Unknown";
}

/* the module's text for msgnbr alone */
char *LoggerErrorMessage(int msgnbr)
{
  LoggerMessageRange *module;
  char *text;

  module = module_of(msgnbr);
  if (module == NULL)
    return "Unknown Module";
  text = message_of(module,msgnbr);
  return text != NULL ? text : "Unknown Message";
}

void LoggerLogMessage(int msgnbr, char *func_name, int errnbr, char *host, int port, char *process, char *format, ...)
{
  va_list args;

  va_start(args,format);
  LoggerVLogMessage(msgnbr,func_name,errnbr,host,port,process,format,args);
  va_end(args);
}

/* log one error, if logging is on; format is printf's, "" for none */
void LoggerVLogMessage(int msgnbr, char *func_name, int errnbr, char *host, int port, char *process, char *format, va_list args)
{
  char buf[1025];
  LoggerEntry entry;

  if (!LogErrors)
    return;
  entry.proc_name = ProcessName;
  entry.time = time(NULL);
  entry.msgnbr = msgnbr;
  entry.func_name = func_name;
  entry.errnbr = errnbr;
  entry.host = host;
  entry.port = port;
  entry.process = process;
  if (*format == '\0') {
    entry.opt_text = "";
  }
  else {
    vsnprintf(buf,sizeof(buf),format,args);
    entry.opt_text = buf;
  }
  LogHandler(&entry);
}

/* "time: message text" (when there is a number), then the entry */
static void LoggerDefaultHandler(LoggerEntry *entry)
{
  fprintf(stderr,"%s: ",LoggerTime(entry));
  if (entry->msgnbr != 0)
    fprintf(stderr,"%s\n",LoggerDefaultMessage(entry->msgnbr));
  fprintf(stderr,"%s\n",LoggerFormat(entry));
  fflush(stderr);
}
