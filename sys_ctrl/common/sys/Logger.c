/*
 * sys_ctrl/common/sys/Logger.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/Logger.c
 */

#include "../Router/Router.h"   /* needed by the reconstruction */
#include "../../l3/l2/smp.h"   /* needed by the reconstruction */
#include "Logger.h"
#include "../../l3/sys/LoggerMsg.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void LoggerDefaultHandler(LoggerEntry *entry);

char *RouterErrorList[25] = { "Connection attempt failed", "Connection attempt timed out", "Connection attempt error", "Connection lost", "Connection timed out", "Connection error", "Connection was disconnected by the local side", "Connection was disconnected by the remote side", "Connection disconnect error", "Server process is already running", "Can not do output on this connection", "Memory allocation failed", "Unexpected packet class received", "Invalid packet class received", "Packet sequence error", "Cannot determine the Internet address of a host name", "Cannot determine the host name of a connected host", "Protocol error", "Incorrect number of arguments received", "Received arguments are of the wrong class", "Received arguments are of the wrong size", "Cannot get password file entry of this process", "Received an incorrect process ID from the server", "Connection was denied by the server" };
char *SocketErrorList[11] = { "Cannot export Internet domain service", "Cannot export Unix domain service", "Cannot accept Internet domain connection request", "Cannot accept Unix domain connection request", "Cannot make Internet domain connection", "Cannot make Unix domain connection", "Cannot determine the Internet address of a host name", "Cannot determine host of connected process", "Cannot get the local host name", "Cannot set the send/receive buffer size" };
char *EventErrorList[8] = { "File descriptor is out of range", "Input event processing is being overlayed", "Output event processing is being overlayed", "Memory allocation failed", "Event processing error", "Missing input event processing function", "Missing output event processing function" };
char *IRouterErrorList[29] = { "NO_ROUTER_ERROR", "bad packet type", "bad task ID", "duplicate target ID", "malloc failed", "duplicate task ID", "bad event entry", "bad argument list argument count", "no receiver for packet", "no device to read/write", "attempt to send to full queue", "queue is full", "read failed - read error", "read failed - not first frame", "read failed - unexpected frame", "read failed - select() error", "read timeout on multiframe packet", "write failed", "sequence ID mismatch", "wait further for response", "timeout waiting for packet", "read failed - end of file", "write failed - end of file (zero bytes written) ", "framing error, frame incomplete", "framing error, frame overflow", "framing error, frame underflow", "framing error, frame control", "response packet is too large" };
char *PPPErrorList[8] = { "bad FCS (checksum)", "read buffer overflow", "short read/frame", "escape sequence in read stream", "control sequence in read stream", "read stream not in frame", "read buffer reallocation failed" };
char *cmdErrorList[3] = { "CMD_ERROR", "CMD_EMPTY" };
char *flashdrvErrorList[10] = { "FLASHDRV_INVALID_ADDRESS", "FLASHDRV_PROGRAM_FAILED", "FLASHDRV_PROGRAM_MISCOMPARE", "FLASHDRV_ERASE_FAILED", "FLASHDRV_ERASE_MISCOMPARE", "FLASHDRV_ID_MISCOMPARE", "Error checking flash file status", "No flash space available to write this file", "Error writing to flash file" };
LoggerMessageRange LoggerErrorRange[8] = { { .name = "Router", .count = 25, .message = RouterErrorList }, { .name = "Socket", .count = 11, .message = SocketErrorList }, { .name = "Event", .count = 8, .message = EventErrorList }, { .name = "IRouter", .count = 29, .message = IRouterErrorList }, { .name = "PPP", .count = 8, .message = PPPErrorList }, { .name = "Cmd", .count = 3, .message = cmdErrorList }, { .name = "FlashDrv", .count = 10, .message = flashdrvErrorList } };
static char *ProcessName = "";
static char *Seperator = ", ";
static void (*LogHandler)() = LoggerDefaultHandler;
static int LogErrors = 1;
static char MsgBuf[1025];

void LoggerInit(char *process_name)
{
  char *pcVar1;
  
  pcVar1 = strrchr(process_name,0x2f);
  if (pcVar1 == NULL) {
    ProcessName = process_name;
  }
  else {
    ProcessName = pcVar1 + 1;
  }
  return;
}

void LoggerHandler(void (*logger_handler)())
{
  LogHandler = logger_handler;
  return;
}

int LoggerEnable(void)
{
  int iVar1;
  int rvalue;
  
  iVar1 = LogErrors;
  LogErrors = 1;
  return iVar1;
}

int LoggerDisable(void)
{
  int iVar1;
  int rvalue;
  
  iVar1 = LogErrors;
  LogErrors = 0;
  return iVar1;
}

void LoggerRestore(int value)
{
  LogErrors = value;
  return;
}

void LogError(int msgnbr, char *func_name, int errnbr, char *format)
{
  va_list args;
  
  LoggerLogMessage(msgnbr,func_name,errnbr,"",0,"",format);
  return;
}

void LogErrorHost(int msgnbr, char *func_name, int errnbr, char *host, int port, char *format)
{
  va_list args;
  
  LoggerLogMessage(msgnbr,func_name,errnbr,host,port,"",format);
  return;
}

char *LoggerTime(LoggerEntry *entry)
{
  char *time_str;
  size_t sVar1;
  
  time_str = ctime(&entry->time);
  sVar1 = strlen(time_str);
  time_str[sVar1 - 1] = '\0';
  return time_str;
}

char *LoggerFormat(LoggerEntry *entry)
{
  LoggerStrFormat(entry,MsgBuf);
  return MsgBuf;
}

void LoggerStrFormat(LoggerEntry *entry, char *str)
{
  char *syserr;
  size_t sVar1;
  char *pcVar2;
  int iVar3;
  
  strcpy(str,entry->proc_name);
  if ((entry->func_name != NULL) && (*entry->func_name != '\0')) {
    strcat(str,Seperator);
    strcat(str,entry->func_name);
    strcat(str,"()");
  }
  if (entry->errnbr != 0) {
    strcat(str,Seperator);
    syserr = strerror(entry->errnbr);
    if (syserr == NULL) {
      iVar3 = entry->errnbr;
      pcVar2 = "Unknown error number %d";
      sVar1 = strlen(str);
      sprintf(str + sVar1,pcVar2,iVar3);
    }
    else {
      strcat(str,syserr);
    }
  }
  if ((entry->opt_text != NULL) && (*entry->opt_text != '\0')) {
    strcat(str,Seperator);
    strcat(str,entry->opt_text);
  }
  if ((entry->host != NULL) && (*entry->host != '\0')) {
    strcat(str,Seperator);
    strcat(str,"host = ");
    strcat(str,entry->host);
  }
  if (0 < entry->port) {
    strcat(str,Seperator);
    iVar3 = entry->port;
    pcVar2 = "port = %d";
    sVar1 = strlen(str);
    sprintf(str + sVar1,pcVar2,iVar3);
  }
  if ((entry->process != NULL) && (*entry->process != '\0')) {
    strcat(str,Seperator);
    strcat(str,"process = ");
    strcat(str,entry->process);
  }
  return;
}

char *LoggerDefaultMessage(int msgnbr)
{
  int iVar1;
  int iVar2;
  static char message[80];
  char *pcVar3;
  undefined4 uVar4;
  int tmp;
  int msgidx;
  int modidx;
  int module;
  
  iVar2 = (msgnbr / 100) * 100;
  iVar1 = (iVar2 + 300) / 100;
  if (msgnbr < 0) {
    tmp = -msgnbr;
  }
  else {
    tmp = msgnbr;
  }
  if ((tmp < 1) || (299 < tmp)) {
    if ((iVar2 < -299) && (-0x3e9 < iVar2)) {
      if (*(int *)(&DAT_0808f95c + iVar1 * -0xc) < -(msgnbr % 100)) {
        pcVar3 = LoggerModuleMessage(msgnbr);
        sprintf((char *)&message,"Unknown %s message %d",pcVar3,msgnbr);
      }
      else {
        uVar4 = *(undefined4 *)(*(int *)(&DAT_0808f960 + iVar1 * -0xc) + (msgnbr % 100) * -4);
        pcVar3 = LoggerModuleMessage(msgnbr);
        sprintf((char *)&message,"%s:%s",pcVar3,uVar4);
      }
    }
    else {
      sprintf((char *)&message,"Unknown Module %d, message = %d",iVar2,msgnbr % 100);
    }
  }
  else {
    pcVar3 = strerror(tmp);
    sprintf((char *)&message,"%s [errno %d]",pcVar3,tmp);
  }
  return &message;
}

char *LoggerModuleMessage(int msgnbr)
{
  int iVar1;
  char *pcVar2;
  int modidx;
  int module;
  
  iVar1 = (msgnbr / 100) * 100;
  if ((iVar1 < -299) && (-0x3e9 < iVar1)) {
    pcVar2 = *(char **)(&LoggerErrorRange + ((iVar1 + 300) / 100) * -0xc);
  }
  else {
    pcVar2 = "Unknown";
  }
  return pcVar2;
}

char *LoggerErrorMessage(int msgnbr)
{
  int iVar1;
  int iVar2;
  char *pcVar3;
  int msgidx;
  int modidx;
  int module;
  
  iVar2 = (msgnbr / 100) * 100;
  iVar1 = (iVar2 + 300) / 100;
  if ((iVar2 < -299) && (-0x3e9 < iVar2)) {
    if (*(int *)(&DAT_0808f95c + iVar1 * -0xc) < -(msgnbr % 100)) {
      pcVar3 = "Unknown Message";
    }
    else {
      pcVar3 = *(char **)(*(int *)(&DAT_0808f960 + iVar1 * -0xc) + (msgnbr % 100) * -4);
    }
  }
  else {
    pcVar3 = "Unknown Module";
  }
  return pcVar3;
}

void LoggerLogMessage(int msgnbr, char *func_name, int errnbr, char *host, int port, char *process, char *format, ...)
{
  char buf [1025];
  LoggerEntry entry;
  va_list args;
  
  va_start(args,format);
  if (LogErrors != 0) {
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
      vsprintf(buf,format,args);
      entry.opt_text = buf;
    }
    (*LogHandler)(&entry);
  }
  va_end(args);
  return;
}

static void LoggerDefaultHandler(LoggerEntry *entry)
{
  char *pcVar1;
  
  pcVar1 = LoggerTime(entry);
  fprintf((FILE *)stderr,"%s: ",pcVar1);
  if (entry->msgnbr != 0) {
    pcVar1 = LoggerDefaultMessage(entry->msgnbr);
    fprintf((FILE *)stderr,"%s\n",pcVar1);
  }
  pcVar1 = LoggerFormat(entry);
  fprintf((FILE *)stderr,"%s\n",pcVar1);
  fflush(stderr);
  return;
}
