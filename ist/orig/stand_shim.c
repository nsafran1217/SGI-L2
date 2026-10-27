/*
 * LD_PRELOAD shim for running SGI's original IST tools (perl 5.6.1, its XS
 * modules, the scan binaries) from an unpacked tree. They hardcode /stand
 * for themselves and /usr/people/sgidiag for their logs; this rewrites path
 * prefixes for the libc calls they make.
 *
 * IST_PATH_MAP is a ':'-separated list of FROM=TO prefixes, the first match
 * wins; FROM matches whole path components. Scripts run through exec*()
 * get their "#!" interpreter mapped too, as the kernel would not.
 *
 * Built twice by ist/orig/Makefile (-m32 for the tools, native for the
 * /bin/sh that system() and popen() run), and preloaded as .../$LIB/...
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#define MAXARGS 1024

static const char *map(const char *path, char *buf)
{
  const char *m = getenv("IST_PATH_MAP");

  if (path == NULL || m == NULL || path[0] != '/')
    return path;
  while (*m) {
    const char *eq = strchr(m, '='), *end = strchr(m, ':');
    size_t flen, tlen;

    if (end == NULL)
      end = m + strlen(m);
    if (eq != NULL && eq < end) {
      flen = eq - m;
      tlen = end - eq - 1;
      if (flen > 0 && strncmp(path, m, flen) == 0
          && (path[flen] == '/' || path[flen] == '\0')
          && tlen + strlen(path + flen) < PATH_MAX) {
        memcpy(buf, eq + 1, tlen);
        strcpy(buf + tlen, path + flen);
        return buf;
      }
    }
    m = *end ? end + 1 : end;
  }
  return path;
}

#define REAL(name) \
  static __typeof__(name) *real; \
  if (!real) \
    real = (__typeof__(name) *)dlsym(RTLD_NEXT, #name)

#define WRAP1(ret, name, T1)                    \
  ret name(const char *p, T1 a)                 \
  {                                             \
    char b[PATH_MAX];                           \
    REAL(name);                                 \
    return real(map(p, b), a);                  \
  }

int open(const char *p, int flags, ...)
{
  char b[PATH_MAX];
  mode_t mode = 0;
  va_list ap;
  REAL(open);

  va_start(ap, flags);
  if (flags & (O_CREAT | O_TMPFILE))
    mode = va_arg(ap, int);
  va_end(ap);
  return real(map(p, b), flags, mode);
}

int open64(const char *p, int flags, ...)
{
  char b[PATH_MAX];
  mode_t mode = 0;
  va_list ap;
  REAL(open64);

  va_start(ap, flags);
  if (flags & (O_CREAT | O_TMPFILE))
    mode = va_arg(ap, int);
  va_end(ap);
  return real(map(p, b), flags, mode);
}

WRAP1(FILE *, fopen, const char *)
WRAP1(FILE *, fopen64, const char *)
WRAP1(int, access, int)
WRAP1(int, mkdir, mode_t)
WRAP1(int, chmod, mode_t)
WRAP1(int, truncate, off_t)
WRAP1(int, truncate64, off64_t)
WRAP1(int, utime, const struct utimbuf *)
WRAP1(int, stat, struct stat *)
WRAP1(int, lstat, struct stat *)
WRAP1(int, stat64, struct stat64 *)
WRAP1(int, lstat64, struct stat64 *)

FILE *freopen(const char *p, const char *mode, FILE *f)
{
  char b[PATH_MAX];
  REAL(freopen);
  return real(map(p, b), mode, f);
}

int chdir(const char *p)
{
  char b[PATH_MAX];
  REAL(chdir);
  return real(map(p, b));
}

int rmdir(const char *p)
{
  char b[PATH_MAX];
  REAL(rmdir);
  return real(map(p, b));
}

int unlink(const char *p)
{
  char b[PATH_MAX];
  REAL(unlink);
  return real(map(p, b));
}

DIR *opendir(const char *p)
{
  char b[PATH_MAX];
  REAL(opendir);
  return real(map(p, b));
}

int chown(const char *p, uid_t u, gid_t g)
{
  char b[PATH_MAX];
  REAL(chown);
  return real(map(p, b), u, g);
}

ssize_t readlink(const char *p, char *buf, size_t len)
{
  char b[PATH_MAX];
  REAL(readlink);
  return real(map(p, b), buf, len);
}

int rename(const char *from, const char *to)
{
  char b1[PATH_MAX], b2[PATH_MAX];
  REAL(rename);
  return real(map(from, b1), map(to, b2));
}

int link(const char *from, const char *to)
{
  char b1[PATH_MAX], b2[PATH_MAX];
  REAL(link);
  return real(map(from, b1), map(to, b2));
}

int symlink(const char *target, const char *to)
{
  char b[PATH_MAX];
  REAL(symlink);
  return real(target, map(to, b));
}

/* perl's DynaLoader loads XS modules from @INC */
void *dlopen(const char *p, int flags)
{
  char b[PATH_MAX];
  REAL(dlopen);
  return real(map(p, b), flags);
}

#ifdef __i386__
/* glibc 2.1's stat entry points, which the 2000-era binaries import;
 * modern glibc keeps them only as compat symbols. */
#define XSTAT(name)                                                     \
  int name(int ver, const char *p, void *st)                            \
  {                                                                     \
    static int (*real)(int, const char *, void *);                      \
    char b[PATH_MAX];                                                   \
    if (!real)                                                          \
      real = (int (*)(int, const char *, void *))                       \
        dlvsym(RTLD_NEXT, #name, "GLIBC_2.1");                          \
    if (!real)                                                          \
      real = (int (*)(int, const char *, void *))                       \
        dlvsym(RTLD_NEXT, #name, "GLIBC_2.0");                          \
    return real(ver, map(p, b), st);                                    \
  }
XSTAT(__xstat)
XSTAT(__lxstat)
XSTAT(__xstat64)
XSTAT(__lxstat64)
#endif

/* exec: map the program, and a "#!" interpreter the kernel would look up
 * unmapped. */
int execve(const char *p, char *const argv[], char *const envp[])
{
  char b[PATH_MAX], ib[PATH_MAX], line[PATH_MAX];
  const char *path = map(p, b);
  char *interp, *arg, *nargv[MAXARGS + 3];
  int fd, n, i, k = 0;
  ssize_t got;
  REAL(execve);

  fd = (open)(path, O_RDONLY);
  if (fd < 0)
    return real(path, argv, envp);
  got = read(fd, line, sizeof(line) - 1);
  close(fd);
  if (got < 4 || line[0] != '#' || line[1] != '!')
    return real(path, argv, envp);
  line[got] = '\0';
  line[strcspn(line, "\n")] = '\0';
  interp = line + 2 + strspn(line + 2, " \t");
  n = strcspn(interp, " \t");
  arg = interp[n] ? interp + n + 1 + strspn(interp + n + 1, " \t") : NULL;
  interp[n] = '\0';
  if (map(interp, ib) == interp)
    return real(path, argv, envp);
  nargv[k++] = ib;
  if (arg && *arg)
    nargv[k++] = arg;
  nargv[k++] = (char *)path;
  for (i = 1; argv[0] && argv[i] && k < MAXARGS + 2; i++)
    nargv[k++] = argv[i];
  nargv[k] = NULL;
  return real(ib, nargv, envp);
}

int execv(const char *p, char *const argv[])
{
  return execve(p, argv, environ);
}

int execvp(const char *file, char *const argv[])
{
  char buf[PATH_MAX], b[PATH_MAX];
  const char *path, *dir, *end;

  if (strchr(file, '/'))
    return execve(file, argv, environ);
  path = getenv("PATH");
  for (dir = path ? path : "/bin:/usr/bin"; *dir; dir = *end ? end + 1 : end) {
    end = strchr(dir, ':');
    if (end == NULL)
      end = dir + strlen(dir);
    snprintf(buf, sizeof(buf), "%.*s/%s", (int)(end - dir), dir, file);
    if ((access)(map(buf, b), X_OK) == 0) {
      execve(buf, argv, environ);
      return -1;
    }
  }
  errno = ENOENT;
  return -1;
}

int execl(const char *p, const char *arg, ...)
{
  char *argv[MAXARGS + 1];
  va_list ap;
  int i = 0;

  va_start(ap, arg);
  for (argv[i] = (char *)arg; argv[i] && i < MAXARGS; )
    argv[++i] = va_arg(ap, char *);
  va_end(ap);
  argv[i] = NULL;
  return execve(p, argv, environ);
}
