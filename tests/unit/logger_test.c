/*
 * Equivalence test for the error messages and log formatting
 * (common/sys/Logger.c): the rewritten functions against the original
 * reconstruction (main branch), compiled in as Orig*. Built and run by
 * tests/unit/logger_test.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../sys_ctrl/common/sys/Logger.h"
#include "orig_logger.h"

static int failures, compared, new_only;

static void expect(const char *what, int msgnbr, const char *got, const char *want)
{
  if (got == NULL || want == NULL) {
    printf("FAIL  %s(%d): %s returned NULL\n", what, msgnbr, got == NULL ? "new" : "original");
    failures++;
    return;
  }
  if (strcmp(got, want) != 0) {
    printf("FAIL  %s(%d): \"%s\", expected \"%s\"\n", what, msgnbr, got, want);
    failures++;
  }
}

/* the number names a message list's NULL end or the slot past it, which
 * the original printed as "(null)" or read out of bounds */
static int past_list(int msgnbr)
{
  int base = msgnbr / 100 * 100;
  int index = -(msgnbr % 100);

  if (base > -300 || base < -900)
    return 0;
  return index >= LoggerErrorRange[(-300 - base) / 100].count - 1;
}

/* -10xx: the original took these for an eighth module, the table's empty
 * end entry (a "(null)" name; -1000 dereferenced its NULL list) */
static int past_table(int msgnbr)
{
  return msgnbr / 100 * 100 == -1000;
}

static void check_number(int msgnbr)
{
  char want[80];

  if (past_table(msgnbr)) {
    snprintf(want, sizeof(want), "Unknown Module -1000, message = %d", msgnbr % 100);
    expect("LoggerDefaultMessage", msgnbr, LoggerDefaultMessage(msgnbr), want);
    expect("LoggerErrorMessage", msgnbr, LoggerErrorMessage(msgnbr), "Unknown Module");
    expect("LoggerModuleMessage", msgnbr, LoggerModuleMessage(msgnbr), "Unknown");
    new_only++;
    return;
  }

  if (past_list(msgnbr)) {
    snprintf(want, sizeof(want), "Unknown %s message %d", LoggerModuleMessage(msgnbr), msgnbr);
    expect("LoggerDefaultMessage", msgnbr, LoggerDefaultMessage(msgnbr), want);
    expect("LoggerErrorMessage", msgnbr, LoggerErrorMessage(msgnbr), "Unknown Message");
    expect("LoggerModuleMessage", msgnbr, LoggerModuleMessage(msgnbr), OrigLoggerModuleMessage(msgnbr));
    new_only++;
    return;
  }
  expect("LoggerDefaultMessage", msgnbr, LoggerDefaultMessage(msgnbr), OrigLoggerDefaultMessage(msgnbr));
  expect("LoggerErrorMessage", msgnbr, LoggerErrorMessage(msgnbr), OrigLoggerErrorMessage(msgnbr));
  expect("LoggerModuleMessage", msgnbr, LoggerModuleMessage(msgnbr), OrigLoggerModuleMessage(msgnbr));
  compared++;
}

static char new_text[2048], orig_text[2048];

static void new_handler(LoggerEntry *entry)
{
  snprintf(new_text, sizeof(new_text), "%d|%s", entry->msgnbr, LoggerFormat(entry));
}

static void orig_handler(OrigLoggerEntry *entry)
{
  snprintf(orig_text, sizeof(orig_text), "%d|%s", entry->msgnbr, OrigLoggerFormat(entry));
}

int main(void)
{
  char longtext[1100];
  int msgnbr;

  for (msgnbr = -1200; msgnbr <= 1200; msgnbr++)
    check_number(msgnbr);
  check_number(-2147483647 - 1);
  check_number(2147483647);

  /* entries without format conversions (the original dropped their arguments) */
  LoggerHandler(new_handler);
  OrigLoggerHandler(orig_handler);
  LogError(-301, "f", 0, "");
  OrigLogError(-301, "f", 0, "");
  expect("LogError", -301, new_text, orig_text);
  LogError(-405, "connect", 2, "text");
  OrigLogError(-405, "connect", 2, "text");
  expect("LogError", -405, new_text, orig_text);
  LogErrorHost(-315, "", 0, "somehost", 8000, "");
  OrigLogErrorHost(-315, "", 0, "somehost", 8000, "");
  expect("LogErrorHost", -315, new_text, orig_text);
  LoggerLogMessage(-322, "RouterGetConRequest", 111, "h", 0, "proc", "");
  OrigLoggerLogMessage(-322, "RouterGetConRequest", 111, "h", 0, "proc", "");
  expect("LoggerLogMessage", -322, new_text, orig_text);
  compared += 4;

  /* the arguments now reach the text */
  LogError(-405, "connect", 0, "%s", "/usr/tmp/UNIX_1f43");
  expect("LogError", -405, new_text, "-405|, connect(), /usr/tmp/UNIX_1f43");
  LoggerLogMessage(-322, "", 0, "h", 0, "", "ID = %d", 42);
  expect("LoggerLogMessage", -322, new_text, "-322|, ID = 42, host = h");
  /* and an over-long text is truncated, not overflowed */
  memset(longtext, 'x', sizeof(longtext) - 1);
  longtext[sizeof(longtext) - 1] = '\0';
  LogErrorHost(-301, "f", 0, "host", 1, "%s", longtext);
  if (strlen(new_text) != strlen("-301|") + 1024) {
    printf("FAIL  long text: %zu bytes\n", strlen(new_text));
    failures++;
  }
  /* disabled */
  LoggerDisable();
  new_text[0] = '\0';
  LogError(-301, "f", 0, "");
  expect("LoggerDisable", -301, new_text, "");
  new_only += 4;

  if (failures == 0)
    printf("PASS  logger: %d cases compared with the original, %d checked against the new code only\n",
           compared, new_only);
  return failures != 0;
}
