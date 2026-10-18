/* One implementation of l3/sys/syslogLib.c (IMPL), its functions renamed
 * PREFIX_*, for tests/unit/syslog_test.c. */
#define CAT(a, b) CAT2(a, b)
#define CAT2(a, b) a##b
#define syslog          CAT(PREFIX, _syslog)
#define syslogLibInit   CAT(PREFIX, _syslogLibInit)
#include IMPL
