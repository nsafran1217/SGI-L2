/*
 * sys_ctrl/l3/main/settings.c
 *
 * New in the modern tree. l2's settings, which SGI's tools kept in a
 * binary NVRAM image (nvram.c), in a text file of "key = value" lines:
 *
 *   # comments and blank lines are kept
 *   rack = 1
 *   sysname = onyx
 *
 * A setting changed by a console command rewrites its line (or appends
 * one), keeping everything else in the file; the file is replaced
 * atomically. Values keep the NVRAM fields' widths (rack and slot are 8
 * bits, the flags 1), so they truncate as before. Unknown keys are kept and
 * warned about. The file is settingsPath(): -c <file>, else
 * l3path_settings(). (Files are written with fputs(): l2 replaces fprintf
 * with its console output, smp.c.)
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include "settings.h"
#include "../../common/IRouter/IRouter.h"
#include "../sys/syslogLib.h"
#include "../../common/sys/l3paths.h"

#define LINE_MAX_LEN 512

struct setting {
  int id;
  const char *key;
  int bits;                     /* the value's width; 0 for a string */
  int size;                     /* a string's room, NUL included */
  uint32_t dflt;
  const char *help;             /* the comment above it in a new file */
};

static const struct setting settings[] = {
  { SET_RACK, "rack", 8, 0, 0, "this L2's rack number (rackid)" },
  { SET_SLOT, "slot", 8, 0, 0, NULL },
  { SET_SERIAL, "serial", 0, 16, 0, "the system serial number (serial set)" },
  { SET_SYSNAME, "sysname", 0, 32, 0, "the system name (sysname)" },
  { SET_MULTISYS, "multisys", 1, 0, 1, "1: L2s talk only to those with the same serial number (multisys)" },
  { SET_MASTER_SLAVE, "psmode", 3, 0, 0, "primary/secondary mode (psmode)" },
  { SET_AUTO_POWERUP, "autopower", 1, 0, 0, "1: power the system up when l2 starts (autopower)" },
  { SET_AUTOPOWER_DELAY, "autopower_delay", 32, 0, 0, NULL },
  { SET_SLOW_PWRUP, "slow_powerup", 1, 0, 0, NULL },
  { SET_L2DSP_DISABLED, "l2display_disabled", 1, 0, 0, NULL },
  { SET_PING_MIN, "ping_min", 32, 0, 0, "L2 and L1 pings (ping); 0 for the defaults" },
  { SET_PING_MAX, "ping_max", 32, 0, 0, NULL },
  { SET_PING_SENDER, "ping_sender", 32, 0, 0, NULL },
  { SET_PING_L2FREQ, "ping_l2", 32, 0, 0, NULL },
  { SET_PING_L1FREQ, "ping_l1", 32, 0, 0, NULL },
  { SET_BROADCAST_TIMEOUT, "broadcast_timeout", 8, 0, 0, "response timeouts in seconds (l2dbg brspto/trspto); 0 for the defaults" },
  { SET_TARGET_TIMEOUT, "target_timeout", 8, 0, 0, NULL },
};
#define NSETTINGS ((int)(sizeof(settings) / sizeof(settings[0])))

static uint32_t num_value[NSETTINGS];
static char str_value[NSETTINGS][32];
static char path_override[1024];
static int initialized;         /* the mode settingsInit() was given */
static int save_failing;        /* the last save failed (and said so) */
static int rw_count;            /* read-write initializations */

static int save(void);

/* a failed save, reported only if the last one worked */
static int save_failed(const char *what, const char *path)
{
  if (!save_failing)
    syslog(1,"settings.c",__LINE__,0,"can\'t %s the settings file \'%s\': %s",what,path,strerror(errno));
  save_failing = 1;
  return -1;
}

/* -c <file> (before settingsInit()) */
void settingsSetPath(const char *path)
{
  snprintf(path_override,sizeof(path_override),"%s",path);
}

const char *settingsPath(void)
{
  if (path_override[0] != '\0')
    return path_override;
  return l3path_settings(IR_PORT_BIAS);
}

static int find_id(int id)
{
  int i;

  for (i = 0; i < NSETTINGS; i++)
    if (settings[i].id == id)
      return i;
  return -1;
}

static int find_key(const char *key)
{
  int i;

  for (i = 0; i < NSETTINGS; i++)
    if (strcmp(settings[i].key,key) == 0)
      return i;
  return -1;
}

static uint32_t mask(int i, uint32_t v)
{
  return settings[i].bits >= 32 ? v : v & ((1u << settings[i].bits) - 1);
}

static void set_value(int i, uintptr_t value)
{
  if (settings[i].bits == 0)
    snprintf(str_value[i],settings[i].size,"%s",value != 0 ? (char *)value : "");
  else
    num_value[i] = mask(i,(uint32_t)value);
}

static void set_defaults(void)
{
  int i;

  for (i = 0; i < NSETTINGS; i++) {
    num_value[i] = settings[i].dflt;
    str_value[i][0] = '\0';
  }
}

/* trim white space in place */
static char *trim(char *s)
{
  char *e;

  while (isspace((unsigned char)*s))
    s++;
  e = s + strlen(s);
  while (e > s && isspace((unsigned char)e[-1]))
    *--e = '\0';
  return s;
}

/* a line "key = value": the key and value, trimmed; 0 if it is not one
 * (blank, a comment, no '=') */
static int split_line(char *line, char **key, char **value)
{
  char *eq;

  line = trim(line);
  if (*line == '\0' || *line == '#')
    return 0;
  eq = strchr(line,'=');
  if (eq == NULL)
    return 0;
  *eq = '\0';
  *key = trim(line);
  *value = trim(eq + 1);
  return 1;
}

/* a number, or for a flag on/off, yes/no, true/false; -1 if it is none */
static int parse_number(const char *s, uint32_t *v)
{
  char *end;
  unsigned long n;

  if (strcasecmp(s,"on") == 0 || strcasecmp(s,"yes") == 0 || strcasecmp(s,"true") == 0) {
    *v = 1;
    return 0;
  }
  if (strcasecmp(s,"off") == 0 || strcasecmp(s,"no") == 0 || strcasecmp(s,"false") == 0) {
    *v = 0;
    return 0;
  }
  errno = 0;
  n = strtoul(s,&end,0);
  if (*s == '\0' || *end != '\0' || errno != 0)
    return -1;
  *v = (uint32_t)n;
  return 0;
}

/* read the file into the settings; 1 if there is none, -1 if it can't be read */
static int load(void)
{
  const char *path = settingsPath();
  char line[LINE_MAX_LEN];
  char *key, *value;
  uint32_t v;
  int lineno = 0;
  int i;
  FILE *fp;

  fp = fopen(path,"r");
  if (fp == NULL) {
    if (errno == ENOENT)
      return 1;
    syslog(1,"settings.c",__LINE__,0,"can\'t read the settings file \'%s\': %s",path,strerror(errno));
    return -1;
  }
  while (fgets(line,sizeof(line),fp) != NULL) {
    lineno++;
    if (!split_line(line,&key,&value))
      continue;
    i = find_key(key);
    if (i < 0) {
      syslog(4,"settings.c",__LINE__,0,"%s:%d: unknown setting \'%s\'",path,lineno,key);
      continue;
    }
    if (settings[i].bits == 0) {
      set_value(i,(uintptr_t)value);
      continue;
    }
    if (parse_number(value,&v) != 0) {
      syslog(4,"settings.c",__LINE__,0,"%s:%d: \'%s\' is not a number for %s",path,lineno,value,key);
      continue;
    }
    set_value(i,v);
  }
  fclose(fp);
  return 0;
}

static void format_line(int i, char *buf, size_t size)
{
  if (settings[i].bits == 0)
    snprintf(buf,size,"%s = %s\n",settings[i].key,str_value[i]);
  else
    snprintf(buf,size,"%s = %u\n",settings[i].key,num_value[i]);
}

/* write the settings: the file's lines with each setting's value
 * replaced, then the settings it lacked; a new file gets a header and the
 * settings' help. Replaces the file atomically. */
static int save(void)
{
  const char *path = settingsPath();
  char tmp[1100];
  char line[LINE_MAX_LEN], copy[LINE_MAX_LEN];
  char *key, *value;
  int written[NSETTINGS];
  int is_new;
  int i;
  FILE *in, *out;

  snprintf(tmp,sizeof(tmp),"%s.tmp",path);
  out = fopen(tmp,"w");
  if (out == NULL)
    return save_failed("write",tmp);
  memset(written,0,sizeof(written));
  in = fopen(path,"r");
  is_new = in == NULL;
  if (is_new)
    fputs("# l2's settings: console commands change them, or edit this file while\n"
          "# l2 is stopped. A removed line is its default.\n",out);
  else {
    while (fgets(line,sizeof(line),in) != NULL) {
      snprintf(copy,sizeof(copy),"%s",line);
      if (split_line(copy,&key,&value) && (i = find_key(key)) >= 0 && !written[i]) {
        format_line(i,line,sizeof(line));
        written[i] = 1;
      }
      fputs(line,out);
    }
    fclose(in);
  }
  for (i = 0; i < NSETTINGS; i++) {
    if (written[i])
      continue;
    if (is_new && settings[i].help != NULL) {
      snprintf(line,sizeof(line),"\n# %s\n",settings[i].help);
      fputs(line,out);
    }
    format_line(i,line,sizeof(line));
    fputs(line,out);
  }
  if (fflush(out) != 0 || fsync(fileno(out)) != 0) {
    save_failed("write",tmp);
    fclose(out);
    unlink(tmp);
    return -1;
  }
  fclose(out);
  if (rename(tmp,path) != 0) {
    save_failed("replace",path);
    unlink(tmp);
    return -1;
  }
  save_failing = 0;
  return 0;
}

/*
 * Read the settings. SETTINGS_READONLY is quietly done once (settingsGet()
 * calls it); SETTINGS_READWRITE (l2) only by the first call, which also
 * creates a missing file. -1 if the file can't be read (the defaults
 * apply).
 */
int settingsInit(int mode)
{
  int rval;

  if (mode == SETTINGS_READONLY) {
    if (initialized)
      return 0;
  }
  else {
    if (rw_count != 0)
      return 0;
    rw_count = 1;
  }
  set_defaults();
  rval = load();
  if (rval == 1) {
    if (mode == SETTINGS_READWRITE) {
      syslog(6,"settings.c",__LINE__,0,"settings file \'%s\' doesn\'t exist.....initializing",
             settingsPath());
      save();
    }
    rval = 0;
  }
  initialized = mode;
  return rval;
}

/* back to the defaults ("nvram reset") */
int settingsReset(void)
{
  set_defaults();
  if (initialized == SETTINGS_READWRITE)
    save();
  return 0;
}

/* change a setting (unless settingsInit() has not run); saved in
 * SETTINGS_READWRITE mode */
void settingsSet(int id, uintptr_t value)
{
  int i = find_id(id);

  if (!initialized || i < 0)
    return;
  set_value(i,value);
  if (initialized == SETTINGS_READWRITE)
    save();
}

/* a setting: a number, or for the string settings a pointer to the
 * string; 0xffffffff for an unknown id */
uintptr_t settingsGet(int id)
{
  int i = find_id(id);

  if (!(initialized & SETTINGS_READONLY))
    settingsInit(SETTINGS_READONLY);
  if (i < 0)
    return 0xffffffff;
  if (settings[i].bits == 0)
    return (uintptr_t)str_value[i];
  return num_value[i];
}
