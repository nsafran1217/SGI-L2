/*
 * Equivalence test for SGI's syslog() (l3/sys/syslogLib.c): each level and
 * message through the rewritten and the original (decomp branch) version;
 * the stderr output and the callback's level and text must match. (Levels
 * 0-2's file and line are masked: the original printed an address.) Run by
 * tests/unit/syslog_test.sh.
 */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void new_syslog(int level, char *fl, int ln, int msgno, char *fmt, ...);
void orig_syslog(int level, char *fl, int ln, int msgno, char *fmt, ...);
void new_syslogLibInit(void (*msgcb)());
void orig_syslogLibInit(void (*msgcb)());

static char cb_text[600];

static void cb(int level, char *msg)
{
  snprintf(cb_text, sizeof(cb_text), "cb %d: %s", level, msg);
}

/* the stderr text of one call */
static void capture(int orig, int level, int msgno, const char *msg, char *out, size_t size)
{
  FILE *f = tmpfile();
  int saved = dup(2);
  size_t n;
  pid_t pid;
  char *p;

  fflush(stderr);
  dup2(fileno(f), 2);
  cb_text[0] = '\0';
  if ((level & 0xff) == 9) {    /* PANIC exits */
    pid = fork();
    if (pid == 0) {
      (orig ? orig_syslog : new_syslog)(level, "/some/dir/file.c", 123, msgno, "%s", msg);
      _exit(0);
    }
    waitpid(pid, NULL, 0);
  }
  else {
    (orig ? orig_syslog : new_syslog)(level, "/some/dir/file.c", 123, msgno, "%s", msg);
  }
  fflush(stderr);
  dup2(saved, 2);
  close(saved);
  rewind(f);
  n = fread(out, 1, size - 1, f);
  out[n] = '\0';
  fclose(f);
  strncat(out, cb_text, size - 1 - strlen(out));
  /* levels 0-2: "L3: <where> line <n> ; " (the original's printed "(null)"
   * and an address; the modern one the file and line) */
  if ((level & 0xff) <= 2)
    for (p = out; (p = strstr(p, "L3: ")) != NULL; p++) {
      char *end = strstr(p, " ; ");
      if (end != NULL)
        memmove(p + 4, end, strlen(end) + 1);
    }
}

int main(void)
{
  static const char *msgs[] = { "a message", "", "with %d percent", "line\nbreak",
    "a long message that goes on for a while, but not so long that it would overflow anything" };
  static const int levels[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 255, 0x103, 0x106, 0x108, -1 };
  char a[2000], b[2000];
  int failures = 0, compared = 0;
  unsigned int l, m, k;
  int msgno;

  new_syslogLibInit(cb);
  orig_syslogLibInit(cb);
  for (l = 0; l < sizeof(levels) / sizeof(levels[0]); l++)
    for (m = 0; m < sizeof(msgs) / sizeof(msgs[0]); m++)
      for (k = 0; k < 2; k++) {
        msgno = k ? 1234 : 0;
        if (k && (levels[l] & 0xff) <= 2)
          continue;             /* (the original printed msgno as a pointer: wild) */
        capture(0, levels[l], msgno, msgs[m], a, sizeof(a));
        capture(1, levels[l], msgno, msgs[m], b, sizeof(b));
        compared++;
        if (strcmp(a, b) != 0) {
          printf("FAIL  level %d msgno %d \"%s\":\n--- new\n%s\n--- orig\n%s\n", levels[l], msgno,
                 msgs[m], a, b);
          failures++;
        }
      }
  /* new only: a message longer than the buffers is cut, not overflowed */
  {
    static char big[1000];
    memset(big, 'x', sizeof(big) - 1);
    capture(0, 6, 0, big, a, sizeof(a));
    if (strncmp(a, "INFO: xxx", 9) != 0 || strlen(a) > 600) {
      printf("FAIL  long message: %zu bytes\n", strlen(a));
      failures++;
    }
  }
  if (failures == 0)
    printf("PASS  syslog: %d messages compared with the original\n", compared);
  return failures != 0;
}
