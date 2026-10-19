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

const char *l3path_settings(int port_bias)
{
  static char path[1024];
  char base[1000];
  const char *config = env_or("SGI_L2_CONFIG", NULL);
  const char *state = env_or("STATE_DIRECTORY", NULL);   /* systemd's StateDirectory= */
  size_t len;

  if (config != NULL)
    snprintf(base, sizeof(base), "%s", config);
  else if (state != NULL) {
    len = strcspn(state, ":");                     /* (the first of several) */
    snprintf(base, sizeof(base), "%.*s/l2.conf", (int)len, state);
  }
  else
    snprintf(base, sizeof(base), "./l2.conf");
  /* (the original's NVRAM file had .<bias / 10> appended the same way) */
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

