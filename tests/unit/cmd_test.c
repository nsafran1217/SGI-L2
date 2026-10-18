/*
 * Equivalence test for the command parser (common/sys/Cmd.c): every form
 * of l2's command table, filled in with good and bad values one token at
 * a time, shortened and lengthened, through the rewritten CmdProcess() and
 * the original reconstruction's (main branch, compiled in as Orig*); the
 * parsed CmdData, return values and messages must agree. Also the help
 * texts. Built and run by tests/unit/cmd_test.sh.
 */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../sys_ctrl/common/sys/Cmd.h"
#include "orig_cmd.h"

void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...)
{
}

static int record(CmdData *cd, char **results, void *data);
#include "table.h"
#define NCMDS ((int)(sizeof(test_cmds) / sizeof(test_cmds[0])))

/* the GUI's destination table (gui/config.cc) */
static Cmd dest_cmds[1] = { { { CMD_TOK(CMD_RANGE) }, record, { 0 }, "", 0 } };

static char seen[4096];
static int ret_value;

static void put(char **p, const char *fmt, const char *s, long n)
{
  *p += sprintf(*p, fmt, s, n);
}

/* everything the command gets, as text */
static int record(CmdData *cd, char **results, void *data)
{
  char *p = seen;
  unsigned i;

  for (i = 0; i < CMD_TOKS && cd->toks[i] != NULL; i++) {
    if ((uintptr_t)cd->toks[i] < CMD_WORD_MIN)
      put(&p, "%s<%ld>", "", (long)(uintptr_t)cd->toks[i]);
    else
      put(&p, "[%s]%ld", cd->toks[i], 0);
  }
  for (i = 0; i < cd->exp_max; i++)
    put(&p, "%se%ld", " ", (long)cd->exp_stack[i]);
  for (i = 0; i < cd->str_max; i++)
    put(&p, " s[%s]%ld", cd->str_stack[i], 0);
  put(&p, "%s form %ld", "", (long)(((Cmd *)((char *)cd->params - offsetof(Cmd, params))) - test_cmds));
  for (i = 0; i < 256; i++)
    p += sprintf(p, "%c", '0' + cd->rlist[i]);
  for (i = 0; i < 64; i++)
    p += sprintf(p, "%c", '0' + cd->slist[i]);
  for (i = 0; i < 64; i++)
    p += sprintf(p, "%c", '0' + cd->plist[i]);
  if (results != NULL && ret_value == 7) {
    *results = malloc(10);
    strcpy(*results, "out\n");
  }
  return ret_value;
}

static int failures, compared;

static void check_line(Cmd *cmds, int n, const char *line)
{
  char buf1[300], buf2[300], seen1[4096];
  char *r1, *r2;
  int v1, v2, mode;

  if (strlen(line) >= 256)
    return;
  for (mode = 0; mode <= 1; mode++) {
    strcpy(buf1, line);
    strcpy(buf2, line);
    seen[0] = '\0';
    v1 = CmdProcess(mode, buf1, &r1, cmds, n, NULL);
    strcpy(seen1, seen);
    seen[0] = '\0';
    v2 = OrigCmdProcess(mode, buf2, &r2, (OrigCmd *)cmds, n, NULL);
    if (v1 != v2 || strcmp(seen1, seen) != 0 ||
        (r1 == NULL) != (r2 == NULL) || (r1 != NULL && strcmp(r1, r2) != 0)) {
      printf("FAIL  mode %d \"%s\": %d vs %d\n  new  %s %s\n  orig %s %s\n", mode, line, v1, v2,
             r1 ? r1 : "-", seen1, r2 ? r2 : "-", seen);
      failures++;
    }
    free(r1);
    free(r2);
    compared++;
  }
}

static const char *samples(uintptr_t type, int i)
{
  static const char *exp[] = { "5", "0x10", "010", "abc", "-3", "12x", "4294967295", NULL };
  static const char *str[] = { "foo", "1", NULL };
  static const char *rest[] = { "a b c", "x", "pwr  up", NULL };
  static const char *ip[] = { "10.0.0.1", "1.2.3", "1.2.3.4x", NULL };
  static const char *portl1[] = { ":8000:1", ":1", "8000:1", NULL };
  static const char *ipportl1[] = { "1.2.3.4:5:6", "1.2.3.4", "1.2.3.4:5", NULL };
  static const char *range[] = { "*", "all", "r 1", "r 1-3 s 2,4", "rack 0,2-5,7 slot *",
    "r ** s 1", "p 1", "partition 2-3", "r 1 s", "r 300", "r 3-1", "r 1,", "r 1-", "r 1-2-3",
    "r 1,1-1,3", "r x", "s 1", "r 001 s 05", "p 64", "r 255 s 63", NULL };
  static const char *rackslot[] = { "001c05", "1.5", "3x60", "001c05x", "1c", "1.2.3.4", "7 9", NULL };
  const char **list;

  switch (type) {
  case CMD_EXP: case CMD_DEC: case CMD_HEX: case CMD_OCT: list = exp; break;
  case CMD_STR: list = str; break;
  case CMD_REST: list = rest; break;
  case CMD_IP: list = ip; break;
  case CMD_PORT_L1: list = portl1; break;
  case CMD_IP_PORT_L1: list = ipportl1; break;
  case CMD_RANGE: list = range; break;
  case CMD_RACKSLOT: list = rackslot; break;
  default: return NULL;
  }
  return list[i];
}

/* the i'th way to write a token: a sample value, or a word's alternative
 * (and a wrong word) */
static const char *variant(char *tok, int i, char *buf)
{
  const char *p, *bar;
  int k;

  if ((uintptr_t)tok < CMD_WORD_MIN)
    return samples((uintptr_t)tok, i);
  for (p = tok, k = 0; k < i; k++) {
    bar = strchr(p, '|');
    if (bar == NULL)
      return k == i - 1 ? "zzz" : NULL;
    p = bar + 1;
  }
  bar = strchr(p, '|');
  k = bar ? bar - p : (int)strlen(p);
  memcpy(buf, p, k);
  buf[k] = '\0';
  return buf;
}

static void check_form(Cmd *cmds, int n, Cmd *form)
{
  char line[600], buf[100], buf2[100];
  const char *v;
  int ntok, pos, i, t;

  for (ntok = 0; ntok < CMD_TOKS && form->toks[ntok] != NULL; ntok++)
    ;
  for (pos = 0; pos < ntok; pos++) {
    for (i = 0; (v = variant(form->toks[pos], i, buf)) != NULL; i++) {
      line[0] = '\0';
      for (t = 0; t < ntok; t++) {
        strcat(line, t == pos ? v : variant(form->toks[t], 0, buf2));
        strcat(line, " ");
      }
      check_line(cmds, n, line);
      strcat(line, "extra");
      check_line(cmds, n, line);
    }
  }
  /* shortened */
  line[0] = '\0';
  for (t = 0; t + 1 < ntok; t++) {
    strcat(line, variant(form->toks[t], 0, buf2));
    strcat(line, " ");
    check_line(cmds, n, line);
  }
}

int main(void)
{
  static const char *lines[] = { "", "   ", "\t", "  power up", "pwr\tu", "help", "nonsense",
    "r 1 s 2 power up", "* pwr d", "001c05 l1 ver", "1.2.3.4:5:6 hello", "10.1.1.1 cfg", NULL };
  char *h1, *h2;
  static char all1[20000], all2[20000];
  int i, showall;

  for (i = 0; lines[i] != NULL; i++)
    check_line(test_cmds, NCMDS, lines[i]);
  for (ret_value = 0; ret_value <= 7; ret_value += 7)
    for (i = 0; i < NCMDS; i++)
      check_form(test_cmds, NCMDS, &test_cmds[i]);
  ret_value = 0;
  for (i = 0; samples(CMD_RANGE, i) != NULL; i++)
    check_line(dest_cmds, 1, samples(CMD_RANGE, i));

  /* the registered tables */
  CmdAddCmds(test_cmds, NCMDS);
  OrigCmdAddCmds((OrigCmd *)test_cmds, NCMDS);
  check_line(NULL, 0, "r 1 s 2 power up");
  check_line(NULL, 0, "pwr");

  /* help */
  for (showall = 0; showall <= 1; showall++) {
    CmdHelpAll(test_cmds, NCMDS, showall, all1);
    OrigCmdHelpAll((OrigCmd *)test_cmds, NCMDS, showall, all2);
    if (strcmp(all1, all2) != 0) {
      printf("FAIL  CmdHelpAll(showall %d)\n", showall);
      failures++;
    }
    for (i = 0; i <= NCMDS; i++) {
      char *which = i == NCMDS ? NULL : (char *)variant(test_cmds[i].toks[0], 0, all1);
      if (which == NULL || (uintptr_t)test_cmds[i].toks[0] < CMD_WORD_MIN)
        which = i == NCMDS ? NULL : "<command>";
      CmdHelpCmd(test_cmds, NCMDS, which, showall, &h1);
      OrigCmdHelpCmd((OrigCmd *)test_cmds, NCMDS, which, showall, &h2);
      if (strcmp(h1, h2) != 0) {
        printf("FAIL  CmdHelpCmd(%s, showall %d)\n", which ? which : "NULL", showall);
        failures++;
      }
      free(h1);
      free(h2);
      compared++;
    }
    CmdHelpCmd(test_cmds, NCMDS, "nosuch", showall, &h1);
    OrigCmdHelpCmd((OrigCmd *)test_cmds, NCMDS, "nosuch", showall, &h2);
    if (strcmp(h1, h2) != 0) {
      printf("FAIL  CmdHelpCmd(nosuch)\n");
      failures++;
    }
    free(h1);
    free(h2);
  }

  /* fixed: these overflowed in the original */
  {
    char big[400], *r;
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    if (CmdProcess(1, big, &r, test_cmds, NCMDS, NULL) != CMD_ERR_ERROR) {
      printf("FAIL  long line\n");
      failures++;
    }
    free(r);
    strcpy(big, "1c200 l1 ver");      /* slot 200: past CmdData */
    CmdProcess(1, big, &r, test_cmds, NCMDS, NULL);
    free(r);
    strcpy(big, "-5c3 l1 ver");       /* rack -5: before rlist */
    CmdProcess(1, big, &r, test_cmds, NCMDS, NULL);
    free(r);
    ret_value = -2;                   /* a form starting with a range */
    strcpy(big, "r 1 power up");
    CmdProcess(1, big, &r, test_cmds, NCMDS, NULL);
    if (r == NULL || strcmp(r, "ERROR: invalid arguments for 'power' command\n") != 0) {
      printf("FAIL  -2 message: %s\n", r ? r : "NULL");
      failures++;
    }
    free(r);
  }

  if (failures == 0)
    printf("PASS  cmd: %d parses and help texts compared with the original\n", compared);
  return failures != 0;
}
