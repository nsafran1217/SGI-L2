/*
 * sys_ctrl/l3/sys/syslogLib.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/sys/syslogLib.c
 */

#include <stdlib.h>
#include "../l2/smp.h"   /* needed by the reconstruction */
#include "syslogLib.h"   /* needed by the reconstruction */
#include "../../common/sys/syslog.h"
#include "../../common/sys/sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static char *basename(char *fl);

static int LogMask = 255;
static char *hwType = "L3";
static int log_console = 1;
static void (*syslog_cb)();
static char *syslog_txt[10] = { "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFO", "DEBUG" };
static char slog_usrmsg[256];
static char slog_fullmsg[256];

void syslogLibInit(void (*msgcb)())
{
  syslog_cb = msgcb;
  return;
}

void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...)
{
  char *stripfl;
  int slen;
  int blen;
  size_t sVar1;
  int iVar2;
  int local_level;
  char *sys_buf;
  char *slog;
  char level_txt [25];
  char line [10];
  va_list ap;
  
  va_start(ap,fmt);
  stripfl = basename(fl);
  memset(slog_usrmsg,0,0x100);
  memset(slog_fullmsg,0,0x100);
  local_level = level & LogMask;
  switch(local_level) {
  case 0:
  case 1:
  case 2:
    sVar1 = vsprintf(slog_usrmsg,fmt,ap);
    /* ORIGINAL BUG (kept, see ORIGINAL_BUGS.md): 5 arguments for 3 conversions; msgno lands
     * in the second %s and the level text's address in %d. Verified against the machine code.
     * Spelled out so it means the same on every ABI: msgno 0 is glibc's "(null)", and a
     * nonzero msgno (a wild pointer on i386) prints as its number. */
    if (msgno == 0) {
      iVar2 = sprintf(slog_fullmsg,"%s: %s line %d ; ",hwType,"(null)",
                      (int)(uintptr_t)syslog_txt[local_level]);
    }
    else {
      iVar2 = sprintf(slog_fullmsg,"%s: %d line %d ; ",hwType,msgno,
                      (int)(uintptr_t)syslog_txt[local_level]);
    }
    strncpy(slog_fullmsg + iVar2,slog_usrmsg,sVar1);
    if (syslog_cb != NULL) {
      (*syslog_cb)(local_level,slog_fullmsg);
    }
    break;
  case 3:
  case 4:
  case 5:
  case 6:
  case 7:
    sVar1 = vsprintf(slog_usrmsg,fmt,ap);
    iVar2 = sprintf(slog_fullmsg,"%s: ",syslog_txt[local_level]);
    strncpy(slog_fullmsg + iVar2,slog_usrmsg,sVar1);
    if (syslog_cb != NULL) {
      (*syslog_cb)(local_level,slog_fullmsg);
    }
    break;
  case 8:
    vsprintf(slog_usrmsg,fmt,ap);
    fprintf(stderr,"%s\n",slog_usrmsg,0,0,0,0,0);
    if (syslog_cb != NULL) {
      (*syslog_cb)(local_level,slog_usrmsg);
    }
    break;
  case 9:
    slen = vsprintf(slog_usrmsg,fmt,ap);
    blen = sprintf(slog_fullmsg,"PANIC: %s line %d ; ",stripfl,ln);
    strncpy(slog_fullmsg + blen,slog_usrmsg,slen);
    if (syslog_cb != NULL) {
      (*syslog_cb)(local_level,slog_fullmsg);
    }
    fprintf(stderr,"%s\n",slog_fullmsg,0,0,0,0,0);
                    /* WARNING: Subroutine does not return */
    va_end(ap);
    exit(-1);
  default:
    fprintf(stderr,"syslog: Invalid Message type\n",0,0,0,0,0,0);
  }
  if ((log_console != 0) && (slog_fullmsg[0] != '\0')) {
    fprintf(stderr,"%s\n",slog_fullmsg,0,0,0,0,0);
  }
  if (((level & 0x100U) != 0) && (log_console == 0)) {
    fprintf(stderr,"%s\n",slog_fullmsg,0,0,0,0,0);
  }
  va_end(ap);
  return;
}

static char *basename(char *fl)
{
  size_t sVar1;
  int i;
  size_t ln;
  bool found;
  
  found = false;
  i = strlen(fl);
  do {
    sVar1 = i;
    i = sVar1 - 1;
    if (i < 0) goto LAB_0807e985;
  } while (fl[i] != '/');
  found = true;
LAB_0807e985:
  if (found) {
    fl = fl + sVar1;
  }
  return fl;
}
