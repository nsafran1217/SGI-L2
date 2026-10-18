/*
 * LD_PRELOAD shim for running SGI's original l2 in tests: it hardcodes
 * /usr/tmp for its local (AF_UNIX) sockets, which modern hosts lack. Socket
 * paths under /usr/tmp go to $USRTMP_SHIM_DIR (default /tmp) instead.
 * Built 32-bit by tests/l1_test.py: gcc -m32 -shared -fPIC -o x.so usrtmp_shim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

static const char *redirect(const char *path, char *buf, size_t len)
{
  const char *dir = getenv("USRTMP_SHIM_DIR");

  if (strncmp(path, "/usr/tmp/", 9) != 0)
    return path;
  snprintf(buf, len, "%s/%s", dir ? dir : "/tmp", path + 9);
  return buf;
}

static const struct sockaddr *fix(const struct sockaddr *a, socklen_t *len, struct sockaddr_un *u)
{
  char buf[sizeof(u->sun_path)];
  const char *p;

  if (a == NULL || a->sa_family != AF_UNIX)
    return a;
  p = redirect(((const struct sockaddr_un *)a)->sun_path, buf, sizeof(buf));
  if (p == ((const struct sockaddr_un *)a)->sun_path)
    return a;
  memset(u, 0, sizeof(*u));
  u->sun_family = AF_UNIX;
  strncpy(u->sun_path, p, sizeof(u->sun_path) - 1);
  *len = sizeof(*u);
  return (const struct sockaddr *)u;
}

int bind(int fd, const struct sockaddr *a, socklen_t len)
{
  static int (*real)(int, const struct sockaddr *, socklen_t);
  struct sockaddr_un u;

  if (!real)
    real = dlsym(RTLD_NEXT, "bind");
  a = fix(a, &len, &u);
  return real(fd, a, len);
}

int connect(int fd, const struct sockaddr *a, socklen_t len)
{
  static int (*real)(int, const struct sockaddr *, socklen_t);
  struct sockaddr_un u;

  if (!real)
    real = dlsym(RTLD_NEXT, "connect");
  a = fix(a, &len, &u);
  return real(fd, a, len);
}

int unlink(const char *path)
{
  static int (*real)(const char *);
  char buf[108];

  if (!real)
    real = dlsym(RTLD_NEXT, "unlink");
  return real(redirect(path, buf, sizeof(buf)));
}
