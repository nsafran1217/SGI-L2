/*
 * sys_ctrl/l3/main/l2log.c
 *
 * New in the modern tree. l2's log, which SGI's tools kept as a ring in
 * the NVRAM image (nvram.c): a text file, l2.log next to the settings file
 * (l2.log.N for --copy N), one message a line, stamped "%m/%d/%y %X " as
 * the "log" command shows them. Past LOG_MAX bytes the older half is
 * dropped. Only l2 writes it (after l2logInit()); in other programs the
 * messages are dropped. (Written with fputs(): l2 replaces fprintf with its
 * console output, smp.c.)
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "l2log.h"
#include "settings.h"
#include "../../common/IRouter/IRouter.h"
#include "../sys/syslogLib.h"

#define LOG_MAX     (64 * 1024)

static char log_path[1100];
static int log_open;

void l2logInit(void)
{
  log_open = 1;
}

/* l2.log in the settings file's directory */
const char *l2logPath(void)
{
  const char *settings = settingsPath();
  const char *slash = strrchr(settings,'/');
  int dirlen = slash == NULL ? 0 : (int)(slash - settings + 1);

  if (IR_PORT_BIAS == 0)
    snprintf(log_path,sizeof(log_path),"%.*sl2.log",dirlen,settings);
  else
    snprintf(log_path,sizeof(log_path),"%.*sl2.log.%d",dirlen,settings,IR_PORT_BIAS / 10);
  return log_path;
}

/* the whole file, malloc()ed (at least 100 bytes, as the NVRAM log's
 * text was); NULL if out of memory */
static char *read_all(long *len)
{
  FILE *fp = fopen(l2logPath(),"r");
  long size = 0;
  char *buf;

  if (fp != NULL && fseek(fp,0,SEEK_END) == 0)
    size = ftell(fp);
  if (size < 0)
    size = 0;
  buf = malloc(size < 100 ? 100 : size + 1);
  if (buf == NULL) {
    if (fp != NULL)
      fclose(fp);
    return NULL;
  }
  if (fp != NULL) {
    rewind(fp);
    size = (long)fread(buf,1,size,fp);
    fclose(fp);
  }
  buf[size] = '\0';
  *len = size;
  return buf;
}

/* keep the newer half of a log that has grown past LOG_MAX */
static void trim(void)
{
  struct stat st;
  char *buf, *keep;
  long len;
  FILE *fp;

  if (stat(l2logPath(),&st) != 0 || st.st_size <= LOG_MAX)
    return;
  buf = read_all(&len);
  if (buf == NULL)
    return;
  keep = strchr(buf + len - LOG_MAX / 2,'\n');
  fp = fopen(l2logPath(),"w");
  if (fp != NULL) {
    if (keep != NULL)
      fputs(keep + 1,fp);
    fclose(fp);
  }
  free(buf);
}

void l2logReset(void)
{
  FILE *fp;

  if (!log_open)
    return;
  fp = fopen(l2logPath(),"w");
  if (fp != NULL)
    fclose(fp);
}

/* a message, with the time; a newline is added if it has none */
void l2logInsert(char *message)
{
  char stamp[32];
  char line[512];
  time_t now = time(NULL);
  size_t len = strlen(message);
  FILE *fp;

  if (!log_open)
    return;
  fp = fopen(l2logPath(),"a");
  if (fp == NULL) {
    log_open = 0;               /* (once, not for every message) */
    syslog(4,"l2log.c",__LINE__,0,"can\'t write the log \'%s\'",l2logPath());
    return;
  }
  strftime(stamp,sizeof(stamp),"%m/%d/%y %X ",localtime(&now));
  snprintf(line,sizeof(line),"%s%s%s",stamp,message,len == 0 || message[len - 1] != '\n' ? "\n" : "");
  fputs(line,fp);
  fclose(fp);
  trim();
}

void l2logFinsert(char *fmt, ...)
{
  char buff[160];
  va_list ap;

  va_start(ap,fmt);
  vsnprintf(buff,sizeof(buff),fmt,ap);
  va_end(ap);
  l2logInsert(buff);
}

/* the log as text (malloc()ed) */
char *l2logFetch(void)
{
  long len;

  return read_all(&len);
}
