/*
 * sys_ctrl/l3/sys/syslogLib.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/sys/syslogLib.c
 *
 * SGI's syslog() (not the C library's): a message with a level, written to
 * stderr and handed to the callback syslogLibInit() set. Levels 0-2 get an
 * "L3: ... line ... ;" prefix, 3-7 their name, 8 none (and only the
 * callback and stderr see it), and 9 is a PANIC that exits.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "syslogLib.h"

#define LEVEL_PLAIN   8         /* the message alone */
#define LEVEL_PANIC   9         /* "PANIC: file line n ; message", then exit */
#define LEVEL_ALWAYS  0x100     /* to stderr even when log_console is off */

static int LogMask = 255;
static char *hwType = "L3";
static int log_console = 1;     /* (never turned off) */
static void (*syslog_cb)();
static char *syslog_txt[10] = { "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG" };
static char slog_usrmsg[256];
static char slog_fullmsg[256];

void syslogLibInit(void (*msgcb)())
{
  syslog_cb = msgcb;
}

/* the file name without its directories */
static char *basename(char *fl)
{
  char *slash = strrchr(fl,'/');

  return slash != NULL ? slash + 1 : fl;
}

/* add text after the prefix in slog_fullmsg (truncated: the original
 * overflowed the 256 bytes) */
static void append_message(int prefix_len, const char *text)
{
  if (prefix_len < 0 || prefix_len >= (int)sizeof(slog_fullmsg))
    return;
  strncpy(slog_fullmsg + prefix_len,text,sizeof(slog_fullmsg) - 1 - prefix_len);
}

void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...)
{
  int local_level;
  int len;
  va_list ap;

  va_start(ap,fmt);
  memset(slog_usrmsg,0,sizeof(slog_usrmsg));
  memset(slog_fullmsg,0,sizeof(slog_fullmsg));
  local_level = level & LogMask;
  switch (local_level) {
  case 0:
  case 1:
  case 2:
    vsnprintf(slog_usrmsg,sizeof(slog_usrmsg),fmt,ap);
    /* ORIGINAL BUG (kept, see ORIGINAL_BUGS.md): 5 arguments for 3 conversions; msgno lands
     * in the second %s and the level text's address in %d. Verified against the machine code.
     * Spelled out so it means the same on every ABI: msgno 0 is glibc's "(null)", and a
     * nonzero msgno (a wild pointer on i386) prints as its number. */
    if (msgno == 0)
      len = sprintf(slog_fullmsg,"%s: %s line %d ; ",hwType,"(null)",
                    (int)(uintptr_t)syslog_txt[local_level]);
    else
      len = sprintf(slog_fullmsg,"%s: %d line %d ; ",hwType,msgno,
                    (int)(uintptr_t)syslog_txt[local_level]);
    append_message(len,slog_usrmsg);
    if (syslog_cb != NULL)
      syslog_cb(local_level,slog_fullmsg);
    break;
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
    vsnprintf(slog_usrmsg,sizeof(slog_usrmsg),fmt,ap);
    len = sprintf(slog_fullmsg,"%s: ",syslog_txt[local_level]);
    append_message(len,slog_usrmsg);
    if (syslog_cb != NULL)
      syslog_cb(local_level,slog_fullmsg);
    break;
  case LEVEL_PLAIN:
    vsnprintf(slog_usrmsg,sizeof(slog_usrmsg),fmt,ap);
    fprintf(stderr,"%s\n",slog_usrmsg);
    if (syslog_cb != NULL)
      syslog_cb(local_level,slog_usrmsg);
    break;
  case LEVEL_PANIC:
    vsnprintf(slog_usrmsg,sizeof(slog_usrmsg),fmt,ap);
    len = snprintf(slog_fullmsg,sizeof(slog_fullmsg),"PANIC: %s line %d ; ",basename(fl),ln);
    append_message(len,slog_usrmsg);
    if (syslog_cb != NULL)
      syslog_cb(local_level,slog_fullmsg);
    fprintf(stderr,"%s\n",slog_fullmsg);
    va_end(ap);
    exit(-1);
  default:
    fprintf(stderr,"syslog: Invalid Message type\n");
  }
  if (log_console && slog_fullmsg[0] != '\0')
    fprintf(stderr,"%s\n",slog_fullmsg);
  if ((level & LEVEL_ALWAYS) && !log_console)
    fprintf(stderr,"%s\n",slog_fullmsg);
  va_end(ap);
}
