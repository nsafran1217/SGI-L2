/*
 * Unit test of l2's settings file (l3/main/settings.c, new in the modern
 * tree, so there is no original to compare with): defaults and a new
 * file, the NVRAM fields' widths, a hand-edited file (comments, unknown
 * keys, bad values and flags as on/off kept or reported), changes written
 * back in place, read-only mode and reset. Run by tests/unit/settings_test.sh
 * in a temp directory.
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "settings.h"

int IR_PORT_BIAS;
static char warnings[4096];
static int failures;

void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...)
{
  va_list ap;
  size_t len = strlen(warnings);

  va_start(ap, fmt);
  vsnprintf(warnings + len, sizeof(warnings) - len, fmt, ap);
  va_end(ap);
  strncat(warnings, "\n", sizeof(warnings) - strlen(warnings) - 1);
}

static char *slurp(const char *path)
{
  static char buf[8192];
  FILE *fp = fopen(path, "r");
  size_t n = 0;

  if (fp != NULL) {
    n = fread(buf, 1, sizeof(buf) - 1, fp);
    fclose(fp);
  }
  buf[n] = '\0';
  return buf;
}

static void check(int ok, const char *what)
{
  if (!ok) {
    printf("FAIL  settings: %s\n", what);
    failures++;
  }
}

#define NUM(id) ((unsigned long)settingsGet(id))
#define STR(id) ((const char *)settingsGet(id))

/* a missing file: the defaults, and a new file with every setting; then
 * changes */
static void test_new(void)
{
  char *text;

  settingsSetPath("new.conf");
  check(settingsInit(SETTINGS_READWRITE) == 0, "init without a file");
  check(NUM(SET_MULTISYS) == 1 && NUM(SET_RACK) == 0 && *STR(SET_SERIAL) == '\0', "defaults");
  text = slurp("new.conf");
  check(strstr(text, "# l2's settings") != NULL && strstr(text, "\nrack = 0\n") != NULL &&
        strstr(text, "\nmultisys = 1\n") != NULL && strstr(text, "\ntarget_timeout = 0\n") != NULL,
        "new file");
  check(strstr(warnings, "doesn't exist") != NULL, "new file reported");

  /* widths and truncation, as in the NVRAM image */
  settingsSet(SET_RACK, 300);
  settingsSet(SET_AUTO_POWERUP, 3);
  settingsSet(SET_MASTER_SLAVE, 9);
  settingsSet(SET_PING_L1FREQ, 70000);
  settingsSet(SET_SYSNAME, (uintptr_t)"a-system-name-longer-than-31-characters");
  settingsSet(SET_SERIAL, (uintptr_t)"L0123456789ABCDEF");
  check(NUM(SET_RACK) == 44 && NUM(SET_AUTO_POWERUP) == 1 && NUM(SET_MASTER_SLAVE) == 1 &&
        NUM(SET_PING_L1FREQ) == 70000, "widths");
  check(strcmp(STR(SET_SYSNAME), "a-system-name-longer-than-31-ch") == 0 &&
        strcmp(STR(SET_SERIAL), "L0123456789ABCD") == 0, "string lengths");
  text = slurp("new.conf");
  check(strstr(text, "\nrack = 44\n") != NULL &&
        strstr(text, "\nsysname = a-system-name-longer-than-31-ch\n") != NULL, "saved");
  check(settingsGet(99) == 0xffffffff, "unknown id");
  settingsReset();
  check(NUM(SET_RACK) == 0 && *STR(SET_SYSNAME) == '\0' && NUM(SET_MULTISYS) == 1, "reset");
  check(strstr(slurp("new.conf"), "\nrack = 0\n") != NULL, "reset saved");
}

/* a file edited by hand: read, and a change rewrites only its own line */
static void test_edited(void)
{
  static const char edited[] =
    "# my L2\n"
    "rack = 3   \n"
    "\n"
    "  sysname   =  my onyx  \n"
    "autopower = on\n"
    "colour = blue\n"
    "ping_min = lots\n"
    "multisys = off\n"
    "ping_l1 = 0x10\n";
  static const char rewritten[] =
    "# my L2\nrack = 4\n\nsysname = my onyx\nautopower = 1\ncolour = blue\n"
    "ping_min = 0\nmultisys = 0\nping_l1 = 16\nslot = 0\n";
  FILE *fp = fopen("edited.conf", "w");
  char *text;

  fputs(edited, fp);
  fclose(fp);
  settingsSetPath("edited.conf");
  check(settingsInit(SETTINGS_READWRITE) == 0, "init with a file");
  check(NUM(SET_RACK) == 3 && strcmp(STR(SET_SYSNAME), "my onyx") == 0 &&
        NUM(SET_AUTO_POWERUP) == 1 && NUM(SET_MULTISYS) == 0 && NUM(SET_PING_L1FREQ) == 16 &&
        NUM(SET_PING_MIN) == 0, "read");
  check(strstr(warnings, "edited.conf:6: unknown setting 'colour'") != NULL &&
        strstr(warnings, "edited.conf:7: 'lots' is not a number for ping_min") != NULL, "warnings");
  check(strcmp(slurp("edited.conf"), edited) == 0, "not rewritten by reading");
  settingsSet(SET_RACK, 4);
  text = slurp("edited.conf");
  check(strncmp(text, rewritten, strlen(rewritten)) == 0, "rewritten in place");
  check(strstr(text, "# this L2") == NULL && strstr(text, "\ntarget_timeout = 0\n") != NULL,
        "missing settings appended, without help");
}

/* read-only (the clients): changes are kept in memory, not saved */
static void test_readonly(void)
{
  FILE *fp = fopen("ro.conf", "w");

  fputs("rack = 9\n", fp);
  fclose(fp);
  settingsSetPath("ro.conf");
  check(NUM(SET_RACK) == 9, "read-only read");
  settingsSet(SET_RACK, 5);
  check(NUM(SET_RACK) == 5 && strcmp(slurp("ro.conf"), "rack = 9\n") == 0, "read-only set not saved");
}

int main(int argc, char **argv)
{
  if (argc > 1 && strcmp(argv[1], "new") == 0)
    test_new();
  else if (argc > 1 && strcmp(argv[1], "edited") == 0)
    test_edited();
  else if (argc > 1 && strcmp(argv[1], "readonly") == 0)
    test_readonly();
  else
    check(0, "usage: settings_test new|edited|readonly");
  return failures != 0;
}
