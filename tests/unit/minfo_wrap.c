/*
 * One implementation of common/sys/minfo.c (IMPL) with its statics reached
 * through PREFIX_* functions, for tests/unit/minfo_test.c.
 */
#define MInfoReset      CAT(PREFIX, _MInfoReset)
#define MInfoEnable     CAT(PREFIX, _MInfoEnable)
#define MInfoDisable    CAT(PREFIX, _MInfoDisable)
#define MInfoStatPrint  CAT(PREFIX, _MInfoStatPrint)
#define MInfoMapPrint   CAT(PREFIX, _MInfoMapPrint)
#define list_delete     CAT(PREFIX, _list_delete)
#define CAT(a, b) CAT2(a, b)
#define CAT2(a, b) a##b
#include IMPL

void nvramLogFinsert(char *fmt, ...) __attribute__((weak));
void nvramLogFinsert(char *fmt, ...) {}

/* what mmalloc() does, for a block at addr */
void CAT(PREFIX, _add)(char *addr, size_t usize, size_t size)
{
  list_insert(addr, usize, size, (void *)0x1234, "malloc");
  if (size < 0x100000) {
    mhist[size >> 10]++;
    mcurr[size >> 10]++;
  }
}

/* what mfree() does */
void CAT(PREFIX, _del)(char *addr, size_t size)
{
  if (list_delete(addr, "free") && size < 0x100000)
    mcurr[size >> 10]--;
}

void CAT(PREFIX, _stat)(char **r) { MInfoStatPrint(r); }
void CAT(PREFIX, _map)(char **r) { MInfoMapPrint(r); }
void CAT(PREFIX, _enable)(void) { MInfoEnable(NULL); }
void CAT(PREFIX, _disable)(void) { MInfoDisable(); }
void CAT(PREFIX, _reset)(void) { MInfoReset(); }
