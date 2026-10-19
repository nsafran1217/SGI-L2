/*
 * sys_ctrl/common/sys/l3paths.c
 *
 * New in the reconstruction: configurable versions of the paths the original
 * tools hardcoded. See l3paths.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "l3paths.h"

static const char *env_or(const char *var, const char *dflt)
{
  const char *v = getenv(var);
  return (v != NULL && *v != '\0') ? v : dflt;
}

const char *l3path_nvram(int port_bias)
{
  static char path[1024];
  const char *base = env_or("SGI_L2_NVRAM", "./.l2_NVRAM");

  /* the original: "%sl2_NVRAM" / "%sl2_NVRAM.%d" with prefix "./." and bias / 10 */
  if (port_bias == 0)
    snprintf(path, sizeof(path), "%s", base);
  else
    snprintf(path, sizeof(path), "%s.%d", base, port_bias / 10);
  return path;
}

const char *l3path_socket_dir(void)
{
  struct stat st;
  const char *v = getenv("SGI_L3_SOCKET_DIR");

  if (v != NULL && *v != '\0')
    return v;
  /* the original always used /usr/tmp, which modern systems usually lack */
  if (stat("/usr/tmp", &st) == 0 && S_ISDIR(st.st_mode))
    return "/usr/tmp";
  return "/tmp";
}

const char *l3path_dev_dir(void)
{
  return env_or("SGI_L3_DEV_DIR", "/dev");
}

const char *l3path_dev(const char *name)
{
  /* a few distinct names are in use at once (sgil1_cs plus the serial ports) */
  static char bufs[4][512];
  static int next;
  char *b = bufs[next++ & 3];

  snprintf(b, sizeof(bufs[0]), "%s/%s", l3path_dev_dir(), name);
  return b;
}
