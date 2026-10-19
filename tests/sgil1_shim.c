/*
 * LD_PRELOAD shim: a fake sgil1 USB driver for tests (tests/l1usb_test.py).
 * Opening .../sgil1_cs or .../sgil1_<n> (any directory) connects instead to
 * the Unix SOCK_SEQPACKET socket $FAKE_SGIL1_DIR/sgil1_cs or .../sgil1_<n>,
 * where a fake L1 answers. As with the driver, each read or write of a
 * device is one frame, and a read of the control device returns one status
 * byte per device: the last status the fake sent (it sends one when the
 * status changes, which makes the device readable), at once. The ioctls
 * the driver offers are answered here: revision 2, and for device n the
 * USB path "bus 1, path n+1, dev n+2". A message "\xff\xfeERR<errno>" from
 * the fake makes that read of the device fail with that errno instead.
 * Built per architecture by the test: gcc [-m32] -shared -fPIC -o x.so sgil1_shim.c -ldl
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

/* the driver's ioctls (sgil1.h) */
#define SGIL1_RESET_READ        0x5301
#define SGIL1_RESET_WRITE       0x5302
#define SGIL1_RESET_DEVICE      0x5303
#define SGIL1_READ_CFG          0x80095304
#define SGIL1_RESET_PIPES       0x5305
#define SGIL1_ST_READ_REV       0x80045306
#define SGIL1_ST_READ_DEV_CFG   0xc0095307

typedef struct {
  unsigned char bus;
  unsigned char level;
  unsigned char dev;
  unsigned char path[6];
} sgil1_cfg_t;

#define MAXFD 1024
static int kind[MAXFD];         /* 0 not ours, 1 the control device, 2 + n device n */

static void fill_cfg(sgil1_cfg_t *cfg, int n)
{
  memset(cfg, 0, sizeof(*cfg));
  cfg->bus = 1;
  cfg->level = 1;
  cfg->path[0] = n + 1;
  cfg->dev = n + 2;
}

static int fake_open(const char *base)
{
  const char *dir = getenv("FAKE_SGIL1_DIR");
  struct sockaddr_un u;
  int fd;

  if (dir == NULL) {
    errno = ENODEV;
    return -1;
  }
  fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd < 0)
    return -1;
  memset(&u, 0, sizeof(u));
  u.sun_family = AF_UNIX;
  snprintf(u.sun_path, sizeof(u.sun_path), "%s/%s", dir, base);
  if (connect(fd, (struct sockaddr *)&u, sizeof(u)) < 0) {
    close(fd);
    errno = ENODEV;
    return -1;
  }
  return fd;
}

int open(const char *path, int flags, ...)
{
  static int (*real)(const char *, int, ...);
  const char *base = strrchr(path, '/');
  va_list ap;
  int mode = 0;
  int fd;

  base = base ? base + 1 : path;
  if (strncmp(base, "sgil1_", 6) == 0) {
    fd = fake_open(base);
    if (fd >= 0 && fd < MAXFD)
      kind[fd] = strcmp(base, "sgil1_cs") == 0 ? 1 : 2 + atoi(base + 6);
    return fd;
  }
  if (!real)
    real = dlsym(RTLD_NEXT, "open");
  va_start(ap, flags);
  if (flags & O_CREAT)
    mode = va_arg(ap, int);
  va_end(ap);
  return real(path, flags, mode);
}

int ioctl(int fd, unsigned long request, ...)
{
  static int (*real)(int, unsigned long, ...);
  va_list ap;
  void *arg;

  va_start(ap, request);
  arg = va_arg(ap, void *);
  va_end(ap);
  if (fd >= 0 && fd < MAXFD && kind[fd] != 0) {
    switch ((unsigned int)request) {
    case SGIL1_ST_READ_REV:
      *(int *)arg = 2;
      return 0;
    case SGIL1_ST_READ_DEV_CFG:
      fill_cfg(arg, ((sgil1_cfg_t *)arg)->dev);
      return 0;
    case SGIL1_READ_CFG:
      fill_cfg(arg, kind[fd] - 2);
      return 0;
    case SGIL1_RESET_READ:
    case SGIL1_RESET_WRITE:
    case SGIL1_RESET_DEVICE:
    case SGIL1_RESET_PIPES:
      return 0;
    }
    errno = EINVAL;
    return -1;
  }
  if (!real)
    real = dlsym(RTLD_NEXT, "ioctl");
  return real(fd, request, arg);
}

ssize_t read(int fd, void *buf, size_t count)
{
  static ssize_t (*real)(int, void *, size_t);
  ssize_t n;

  if (!real)
    real = dlsym(RTLD_NEXT, "read");
  if (fd >= 0 && fd < MAXFD && kind[fd] == 1) {
    /* the control device: take any new status, return the latest */
    static unsigned char status[256];
    static size_t slen;
    unsigned char msg[256];
    /* (the first status: wait for it, as the driver always has one) */
    while ((n = recv(fd, msg, sizeof(msg), slen == 0 ? 0 : MSG_DONTWAIT)) > 0) {
      memcpy(status, msg, n);
      slen = n;
    }
    n = slen < count ? slen : count;
    memcpy(buf, status, n);
    return n;
  }
  n = real(fd, buf, count);
  if (fd >= 0 && fd < MAXFD && kind[fd] >= 2 && n >= 5 && memcmp(buf, "\xff\xfe" "ERR", 5) == 0) {
    char num[16];
    size_t len = (size_t)n - 5 < sizeof(num) - 1 ? (size_t)n - 5 : sizeof(num) - 1;
    memcpy(num, (char *)buf + 5, len);
    num[len] = '\0';
    errno = atoi(num);
    return -1;
  }
  return n;
}

int close(int fd)
{
  static int (*real)(int);

  if (fd >= 0 && fd < MAXFD)
    kind[fd] = 0;
  if (!real)
    real = dlsym(RTLD_NEXT, "close");
  return real(fd);
}
