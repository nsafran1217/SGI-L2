/*
 * sys_ctrl/l3/l2/l1usb.c
 *
 * New in the modern tree. L1s on USB through libusb, in place of SGI's
 * sgil1 kernel driver, which l2 used as:
 *  - a control device, readable when an L1 comes or goes, giving one
 *    presence byte for each of 40 slots (l1usb_start(), l1usb_status());
 *  - a device per slot, where each read() is one frame from the L1's bulk
 *    IN endpoint and each write() one frame to its bulk OUT endpoint, the
 *    first two bytes replaced by the frame's length, big-endian
 *    (l1usb_open(), l1usb_read(), l1usb_write());
 *  - ioctls to clear a halted pipe or reset the device (l1usb_reset()) and
 *    to tell where it is on the bus (l1usb_cfg()).
 * A thread runs libusb's events, as the driver ran in the kernel: hotplug
 * (or, where libusb has none, a rescan every RESCAN_SECS) fills the slots,
 * first free first, and each open device keeps a read transfer submitted.
 * A frame read (or the error that ended the transfer) goes to l2 as one
 * packet on a SOCK_SEQPACKET socketpair, so to l2 an L1 is still one
 * descriptor in its event loop. Writes are synchronous, with the driver's
 * 3 second timeout.
 *
 * Built with L1USB_NONE (no libusb for the target), l1usb_start() fails:
 * l2 has only -net and -noconn.
 */

#include <errno.h>
#include <stdio.h>
#include "l1usb.h"

#ifdef L1USB_NONE

int l1usb_start(void)
{
  fprintf(stderr,"ERROR: this l2 was built without libusb: no USB L1s (-net or -noconn)\n");
  return -1;
}

void l1usb_stop(void) {}
void l1usb_drain(void) {}
int l1usb_status(unsigned char *status, int n) { return 0; }
int l1usb_cfg(int slot, l1usb_cfg_t *cfg) { errno = ENODEV; return -1; }
int l1usb_open(int slot) { errno = ENODEV; return -1; }
int l1usb_close(int slot) { errno = EBADF; return -1; }
int l1usb_read(int fd, unsigned char *buf, int len) { errno = EBADF; return -1; }
int l1usb_write(int slot, const unsigned char *buf, int len) { errno = ENODEV; return -1; }
int l1usb_reset(int slot, int what) { errno = ENODEV; return -1; }

#else

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <libusb.h>

#define RD_SIZE     4096        /* a read transfer: the driver's (a page) */
#define WR_TIMEOUT  3000        /* ms: the driver's */
#define RESCAN_SECS 2           /* without hotplug, look for devices this often */
#define HDR         4           /* a packet to l2: the status (int32), then the frame */
#define QUEUE       64          /* hotplug events waiting for the thread */

struct slot {
  int present;                  /* plugged in: the driver's status byte */
  libusb_device *dev;           /* (referenced while present or open) */
  libusb_device_handle *h;      /* open */
  int busy;                     /* l2 is opening or closing it */
  unsigned char ep_in, ep_out;
  int sv[2];                    /* socketpair: [0] l2's descriptor, [1] ours */
  struct libusb_transfer *rd;
  int rd_busy;                  /* rd is submitted */
  int pending;                  /* a packet waits for room in the socket */
  int rdlen;
  unsigned char rdbuf[HDR + RD_SIZE];
  l1usb_cfg_t cfg;
};

static struct slot slots[L1USB_SLOTS];
static libusb_context *ctx;
static libusb_hotplug_callback_handle hotplug;
static int have_hotplug;
static pthread_t thread;
static int thread_started;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static volatile int stopping;
static int ctl[2] = { -1, -1 };  /* [0] l2's: readable when a device came or went */
static struct {
  libusb_device *dev;
  int arrived;
} queue[QUEUE];
static int queued;

/* --- errors --- */

static int errno_of_error(int rc)
{
  switch (rc) {
  case LIBUSB_ERROR_INVALID_PARAM: return EINVAL;
  case LIBUSB_ERROR_ACCESS:        return EACCES;
  case LIBUSB_ERROR_NO_DEVICE:     return ENODEV;
  case LIBUSB_ERROR_NOT_FOUND:     return ENODEV;   /* (gone after a reset) */
  case LIBUSB_ERROR_BUSY:          return EBUSY;
  case LIBUSB_ERROR_TIMEOUT:       return ETIMEDOUT;
  case LIBUSB_ERROR_OVERFLOW:      return EOVERFLOW;
  case LIBUSB_ERROR_PIPE:          return EPIPE;
  case LIBUSB_ERROR_INTERRUPTED:   return EINTR;
  case LIBUSB_ERROR_NO_MEM:        return ENOMEM;
  case LIBUSB_ERROR_NOT_SUPPORTED: return ENOSYS;
  default:                         return EIO;
  }
}

static int errno_of_status(enum libusb_transfer_status status)
{
  switch (status) {
  case LIBUSB_TRANSFER_TIMED_OUT: return ETIMEDOUT;
  case LIBUSB_TRANSFER_STALL:     return EPIPE;
  case LIBUSB_TRANSFER_NO_DEVICE: return ENODEV;
  case LIBUSB_TRANSFER_OVERFLOW:  return EOVERFLOW;
  default:                        return EIO;
  }
}

/* --- the slots (with lock held) --- */

static void notify(void)
{
  char c = 0;

  if (write(ctl[1],&c,1) < 0 && errno != EAGAIN)
    fprintf(stderr,"WARNING: USB: can\'t signal a device change, %s\n",strerror(errno));
}

static void set_cfg(l1usb_cfg_t *cfg, libusb_device *dev)
{
  uint8_t ports[L1USB_MAX_LEVEL + 1];
  int n = libusb_get_port_numbers(dev,ports,sizeof(ports));
  int i;

  memset(cfg,0,sizeof(*cfg));
  cfg->bus = libusb_get_bus_number(dev);
  cfg->dev = libusb_get_device_address(dev);
  /* (the driver kept the last L1USB_MAX_LEVEL ports, nearest the device) */
  if (n > L1USB_MAX_LEVEL) {
    memmove(ports,ports + n - L1USB_MAX_LEVEL,L1USB_MAX_LEVEL);
    n = L1USB_MAX_LEVEL;
  }
  for (i = 0; i < n; i++)
    cfg->path[i] = ports[i];
  cfg->level = n < 0 ? 0 : n;
}

static void arrive(libusb_device *dev)
{
  int i;

  for (i = 0; i < L1USB_SLOTS; i++)
    if (slots[i].present && slots[i].dev == dev)
      return;
  for (i = 0; i < L1USB_SLOTS; i++)
    if (slots[i].dev == NULL)
      break;
  if (i == L1USB_SLOTS) {
    fprintf(stderr,"WARNING: USB: more than %d L1s, one ignored\n",L1USB_SLOTS);
    return;
  }
  slots[i].dev = libusb_ref_device(dev);
  slots[i].present = 1;
  set_cfg(&slots[i].cfg,dev);
  notify();
}

static void depart(libusb_device *dev)
{
  struct slot *s;
  int i;

  for (i = 0; i < L1USB_SLOTS; i++) {
    s = &slots[i];
    if (!s->present || s->dev != dev)
      continue;
    s->present = 0;
    if (s->h == NULL && !s->busy) {
      libusb_unref_device(s->dev);
      s->dev = NULL;
    }
    notify();
  }
}

static int is_l1(libusb_device *dev)
{
  struct libusb_device_descriptor d;

  return libusb_get_device_descriptor(dev,&d) == 0 && d.idVendor == L1USB_VENDOR &&
         d.idProduct == L1USB_PRODUCT;
}

/* without hotplug: the devices now against the slots */
static void rescan(void)
{
  libusb_device **list;
  ssize_t n, j;
  int i, found;

  n = libusb_get_device_list(ctx,&list);
  if (n < 0)
    return;
  for (i = 0; i < L1USB_SLOTS; i++) {
    if (!slots[i].present)
      continue;
    for (found = 0, j = 0; j < n && !found; j++)
      found = list[j] == slots[i].dev;
    if (!found)
      depart(slots[i].dev);
  }
  for (j = 0; j < n; j++)
    if (is_l1(list[j]))
      arrive(list[j]);
  libusb_free_device_list(list,1);
}

static void process_queue(void)
{
  int i;

  for (i = 0; i < queued; i++) {
    if (queue[i].arrived)
      arrive(queue[i].dev);
    else
      depart(queue[i].dev);
    libusb_unref_device(queue[i].dev);
  }
  queued = 0;
}

/* the pending packet to l2; 0 if the socket has no room yet */
static int send_pending(struct slot *s)
{
  if (!s->pending)
    return 1;
  if (send(s->sv[1],s->rdbuf,s->rdlen,MSG_DONTWAIT | MSG_NOSIGNAL) < 0 &&
      (errno == EAGAIN || errno == EWOULDBLOCK))
    return 0;
  s->pending = 0;               /* (sent, or l2 has closed its end) */
  return 1;
}

static void error_packet(struct slot *s, int err)
{
  int32_t status = -err;

  memcpy(s->rdbuf,&status,HDR);
  s->rdlen = HDR;
  s->pending = 1;
  send_pending(s);
}

static void LIBUSB_CALL read_done(struct libusb_transfer *t);

/* keep a read submitted on an open device */
static void submit_read(struct slot *s)
{
  int rc;

  if (s->h == NULL || s->rd_busy || s->pending || s->busy)
    return;
  libusb_fill_bulk_transfer(s->rd,s->h,s->ep_in,s->rdbuf + HDR,RD_SIZE,read_done,s,0);
  rc = libusb_submit_transfer(s->rd);
  if (rc == 0)
    s->rd_busy = 1;
  else
    error_packet(s,errno_of_error(rc));
}

/* a read ended (in the thread, from libusb's event handling) */
static void LIBUSB_CALL read_done(struct libusb_transfer *t)
{
  struct slot *s = t->user_data;
  int32_t status;

  pthread_mutex_lock(&lock);
  s->rd_busy = 0;
  pthread_cond_broadcast(&cond);
  if (s->busy)
    ;                           /* (l2 is closing or resetting it) */
  else if (t->status == LIBUSB_TRANSFER_COMPLETED) {
    /* (an empty read is no frame: the driver's read() returned 0) */
    if (t->actual_length > 0) {
      status = t->actual_length;
      memcpy(s->rdbuf,&status,HDR);
      s->rdlen = HDR + t->actual_length;
      s->pending = 1;
    }
    if (send_pending(s))
      submit_read(s);
  }
  else if (t->status != LIBUSB_TRANSFER_CANCELLED)
    error_packet(s,errno_of_status(t->status));   /* (resubmitted once l2 has seen it) */
  pthread_mutex_unlock(&lock);
}

/* take back the submitted read, if any (lock held, s->busy set) */
static void stop_read(struct slot *s)
{
  struct timespec until;

  if (!s->rd_busy)
    return;
  libusb_cancel_transfer(s->rd);
  clock_gettime(CLOCK_REALTIME,&until);
  until.tv_sec += 2;
  while (s->rd_busy && pthread_cond_timedwait(&cond,&lock,&until) == 0)
    ;
}

static int LIBUSB_CALL hotplug_cb(libusb_context *c, libusb_device *dev, libusb_hotplug_event event, void *data)
{
  pthread_mutex_lock(&lock);
  if (queued < QUEUE) {
    queue[queued].dev = libusb_ref_device(dev);
    queue[queued].arrived = event == LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED;
    queued++;
  }
  pthread_mutex_unlock(&lock);
  return 0;
}

static void *usb_thread(void *arg)
{
  time_t next_scan = 0;
  struct timeval tv;
  int i;

  while (!stopping) {
    tv.tv_sec = 0;
    tv.tv_usec = 100000;
    libusb_handle_events_timeout_completed(ctx,&tv,NULL);
    pthread_mutex_lock(&lock);
    process_queue();
    if (!have_hotplug && time(NULL) >= next_scan) {
      rescan();
      next_scan = time(NULL) + RESCAN_SECS;
    }
    for (i = 0; i < L1USB_SLOTS; i++)
      if (slots[i].pending && send_pending(&slots[i]) && slots[i].rdlen > HDR)
        submit_read(&slots[i]);
    pthread_mutex_unlock(&lock);
  }
  return NULL;
}

/* --- l2's side --- */

/* start: the control descriptor (readable when a device comes or goes,
 * then l1usb_drain() it), or -1 */
int l1usb_start(void)
{
  int rc;
  int i;

  for (i = 0; i < L1USB_SLOTS; i++)
    slots[i].sv[0] = slots[i].sv[1] = -1;
  rc = libusb_init(&ctx);
  if (rc != 0) {
    fprintf(stderr,"ERROR: can\'t start libusb: %s\n",libusb_strerror(rc));
    return -1;
  }
  if (socketpair(AF_UNIX,SOCK_STREAM,0,ctl) != 0) {
    fprintf(stderr,"ERROR: can\'t make the USB control socket: %s\n",strerror(errno));
    libusb_exit(ctx);
    return -1;
  }
  fcntl(ctl[0],F_SETFL,O_NONBLOCK);
  fcntl(ctl[1],F_SETFL,O_NONBLOCK);
  have_hotplug = libusb_has_capability(LIBUSB_CAP_HAS_HOTPLUG);
  if (have_hotplug) {
    rc = libusb_hotplug_register_callback(ctx,LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED | LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT,
                                          LIBUSB_HOTPLUG_ENUMERATE,L1USB_VENDOR,L1USB_PRODUCT,
                                          LIBUSB_HOTPLUG_MATCH_ANY,hotplug_cb,NULL,&hotplug);
    if (rc != 0) {
      fprintf(stderr,"WARNING: USB hotplug unavailable (%s): looking for L1s every %d seconds\n",
              libusb_strerror(rc),RESCAN_SECS);
      have_hotplug = 0;
    }
  }
  /* the L1s already there, before l2 first looks */
  pthread_mutex_lock(&lock);
  if (have_hotplug)
    process_queue();
  else
    rescan();
  pthread_mutex_unlock(&lock);
  rc = pthread_create(&thread,NULL,usb_thread,NULL);
  if (rc != 0) {
    fprintf(stderr,"ERROR: can\'t start the USB thread: %s\n",strerror(rc));
    return -1;
  }
  thread_started = 1;
  return ctl[0];
}

void l1usb_stop(void)
{
  int i;

  for (i = 0; i < L1USB_SLOTS; i++)
    if (slots[i].h != NULL)
      l1usb_close(i);
  stopping = 1;
  if (thread_started)
    pthread_join(thread,NULL);
  thread_started = 0;
  if (have_hotplug)
    libusb_hotplug_deregister_callback(ctx,hotplug);
  pthread_mutex_lock(&lock);
  process_queue();
  for (i = 0; i < L1USB_SLOTS; i++)
    if (slots[i].dev != NULL) {
      libusb_unref_device(slots[i].dev);
      slots[i].dev = NULL;
      slots[i].present = 0;
    }
  pthread_mutex_unlock(&lock);
  libusb_exit(ctx);
  close(ctl[0]);
  close(ctl[1]);
  ctl[0] = ctl[1] = -1;
}

/* empty the control descriptor */
void l1usb_drain(void)
{
  char buf[64];

  while (read(ctl[0],buf,sizeof(buf)) > 0)
    ;
}

/* the slots' presence (the driver's status bytes); how many */
int l1usb_status(unsigned char *status, int n)
{
  int i;

  if (n > L1USB_SLOTS)
    n = L1USB_SLOTS;
  pthread_mutex_lock(&lock);
  for (i = 0; i < n; i++)
    status[i] = slots[i].present;
  pthread_mutex_unlock(&lock);
  return n;
}

/* where slot's device is on the bus; -1 if there is none */
int l1usb_cfg(int slot, l1usb_cfg_t *cfg)
{
  int rval = -1;

  if (slot < 0 || slot >= L1USB_SLOTS) {
    errno = EINVAL;
    return -1;
  }
  pthread_mutex_lock(&lock);
  if (slots[slot].dev != NULL) {
    *cfg = slots[slot].cfg;
    rval = 0;
  }
  else
    errno = ENODEV;
  pthread_mutex_unlock(&lock);
  return rval;
}

/* the device's bulk endpoints (the driver took endpoint 0 out, 1 in) */
static int find_endpoints(struct slot *s)
{
  struct libusb_config_descriptor *c;
  const struct libusb_interface_descriptor *id;
  const struct libusb_endpoint_descriptor *ep;
  int i, rc;

  rc = libusb_get_active_config_descriptor(s->dev,&c);
  if (rc != 0)
    return rc;
  s->ep_in = s->ep_out = 0;
  if (c->bNumInterfaces > 0 && c->interface[0].num_altsetting > 0) {
    id = &c->interface[0].altsetting[0];
    for (i = 0; i < id->bNumEndpoints; i++) {
      ep = &id->endpoint[i];
      if ((ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != LIBUSB_TRANSFER_TYPE_BULK)
        continue;
      if ((ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN) {
        if (s->ep_in == 0)
          s->ep_in = ep->bEndpointAddress;
      }
      else if (s->ep_out == 0)
        s->ep_out = ep->bEndpointAddress;
    }
  }
  libusb_free_config_descriptor(c);
  return s->ep_in != 0 && s->ep_out != 0 ? 0 : LIBUSB_ERROR_NOT_FOUND;
}

/* open slot's device: the descriptor each frame comes on (l1usb_read()),
 * or -1 */
int l1usb_open(int slot)
{
  struct slot *s;
  int err = 0;
  int rc;

  if (slot < 0 || slot >= L1USB_SLOTS) {
    errno = EINVAL;
    return -1;
  }
  s = &slots[slot];
  pthread_mutex_lock(&lock);
  if (!s->present || s->h != NULL || s->busy)
    err = s->h != NULL ? EBUSY : ENODEV;
  else
    s->busy = 1;
  pthread_mutex_unlock(&lock);
  if (err != 0) {
    errno = err;
    return -1;
  }
  rc = libusb_open(s->dev,&s->h);
  if (rc == 0) {
    libusb_set_auto_detach_kernel_driver(s->h,1);   /* (sgil1, if it is loaded) */
    rc = libusb_claim_interface(s->h,0);
    if (rc == 0)
      rc = find_endpoints(s);
    if (rc == 0 && socketpair(AF_UNIX,SOCK_SEQPACKET,0,s->sv) != 0)
      rc = LIBUSB_ERROR_NO_MEM;
    if (rc == 0 && (s->rd = libusb_alloc_transfer(0)) == NULL) {
      close(s->sv[0]);
      close(s->sv[1]);
      rc = LIBUSB_ERROR_NO_MEM;
    }
    if (rc != 0) {
      libusb_close(s->h);
      s->h = NULL;
    }
  }
  pthread_mutex_lock(&lock);
  s->busy = 0;
  if (rc == 0) {
    s->rd_busy = s->pending = 0;
    submit_read(s);
  }
  else if (!s->present) {
    libusb_unref_device(s->dev);
    s->dev = NULL;
  }
  pthread_mutex_unlock(&lock);
  if (rc != 0) {
    errno = errno_of_error(rc);
    return -1;
  }
  return s->sv[0];
}

/* close slot's device, resetting it as the driver did; 0 or -1 */
int l1usb_close(int slot)
{
  struct slot *s;

  if (slot < 0 || slot >= L1USB_SLOTS || slots[slot].h == NULL) {
    errno = EBADF;
    return -1;
  }
  s = &slots[slot];
  pthread_mutex_lock(&lock);
  s->busy = 1;
  stop_read(s);
  pthread_mutex_unlock(&lock);
  libusb_release_interface(s->h,0);
  libusb_reset_device(s->h);
  libusb_close(s->h);
  if (!s->rd_busy)              /* (else libusb still has it: leaked) */
    libusb_free_transfer(s->rd);
  s->rd = NULL;
  close(s->sv[0]);
  close(s->sv[1]);
  pthread_mutex_lock(&lock);
  s->sv[0] = s->sv[1] = -1;
  s->h = NULL;
  s->busy = s->rd_busy = s->pending = 0;
  if (!s->present) {
    libusb_unref_device(s->dev);
    s->dev = NULL;
  }
  pthread_mutex_unlock(&lock);
  return 0;
}

static struct slot *slot_of_fd(int fd)
{
  int i;

  for (i = 0; i < L1USB_SLOTS; i++)
    if (slots[i].h != NULL && slots[i].sv[0] == fd)
      return &slots[i];
  return NULL;
}

/* a frame from fd into buf (len bytes): its length, 0 if there was none,
 * -1 with errno set if the read failed */
int l1usb_read(int fd, unsigned char *buf, int len)
{
  unsigned char pkt[HDR + RD_SIZE];
  struct slot *s = slot_of_fd(fd);
  int32_t status;
  ssize_t n;

  if (s == NULL) {
    errno = EBADF;
    return -1;
  }
  n = recv(fd,pkt,sizeof(pkt),MSG_DONTWAIT);
  if (n < HDR)
    return n < 0 && errno != EAGAIN ? -1 : 0;
  memcpy(&status,pkt,HDR);
  if (status < 0) {
    /* the read is resubmitted once l2 has the error (unless the device is gone) */
    pthread_mutex_lock(&lock);
    if (status != -ENODEV)
      submit_read(s);
    pthread_mutex_unlock(&lock);
    errno = -status;
    return -1;
  }
  if (n - HDR > len) {          /* (the driver: EINVAL for a buffer too small) */
    errno = EINVAL;
    return -1;
  }
  memcpy(buf,pkt + HDR,n - HDR);
  return n - HDR;
}

/* a frame to slot's device; its length, or -1 with errno set */
int l1usb_write(int slot, const unsigned char *buf, int len)
{
  unsigned char frame[RD_SIZE];
  libusb_device_handle *h;
  unsigned char ep;
  int actual = 0;
  int rc;

  if (slot < 0 || slot >= L1USB_SLOTS || len < 2 || len > (int)sizeof(frame)) {
    errno = EINVAL;
    return -1;
  }
  pthread_mutex_lock(&lock);
  h = slots[slot].busy ? NULL : slots[slot].h;
  ep = slots[slot].ep_out;
  pthread_mutex_unlock(&lock);
  if (h == NULL) {
    errno = ENODEV;
    return -1;
  }
  memcpy(frame,buf,len);
  frame[0] = (unsigned char)(len >> 8);     /* as the driver did */
  frame[1] = (unsigned char)len;
  rc = libusb_bulk_transfer(h,ep,frame,len,&actual,WR_TIMEOUT);
  if (rc == 0 && actual == len)
    return len;
  errno = rc != 0 ? errno_of_error(rc) : EIO;
  return -1;
}

/* the driver's resets: a pipe's halt cleared (L1USB_RESET_READ, _WRITE,
 * _PIPES), or the device reset; 0 or -1 with errno set */
int l1usb_reset(int slot, int what)
{
  libusb_device_handle *h;
  struct slot *s;
  int rc = 0;

  if (slot < 0 || slot >= L1USB_SLOTS) {
    errno = EINVAL;
    return -1;
  }
  s = &slots[slot];
  pthread_mutex_lock(&lock);
  h = s->busy ? NULL : s->h;
  if (h != NULL) {
    s->busy = 1;
    stop_read(s);
  }
  pthread_mutex_unlock(&lock);
  if (h == NULL) {
    errno = ENODEV;
    return -1;
  }
  if (what == L1USB_RESET_DEVICE)
    rc = libusb_reset_device(h);
  else {
    if (what & L1USB_RESET_WRITE)
      rc = libusb_clear_halt(h,s->ep_out);
    if (rc == 0 && (what & L1USB_RESET_READ))
      rc = libusb_clear_halt(h,s->ep_in);
  }
  pthread_mutex_lock(&lock);
  s->busy = 0;
  submit_read(s);
  pthread_mutex_unlock(&lock);
  if (rc != 0) {
    errno = errno_of_error(rc);
    return -1;
  }
  return 0;
}

#endif /* L1USB_NONE */
