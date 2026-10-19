/*
 * LD_PRELOAD shim: a fake libusb for tests (tests/l1usb_test.py), with the
 * calls l2's l1usb.c makes. Behind it are Unix SOCK_SEQPACKET sockets in
 * $FAKE_SGIL1_DIR, as for the fake sgil1 driver this replaced:
 *  - sgil1_cs sends the presence of each device (one byte each) whenever
 *    it changes: hotplug arrivals and departures here;
 *  - sgil1_<n> is device n's bulk pipes: each message from it completes a
 *    read transfer, and each bulk write is one message to it. A message
 *    "\xff\xfeERR<errno>" ends the read with an error instead (19 as
 *    LIBUSB_TRANSFER_NO_DEVICE, 32 as a stall, others LIBUSB_TRANSFER_ERROR).
 * Device n is on bus 1, port n+1, at address n+2 (the old shim's USB
 * path). Transfers complete, and hotplug callbacks run, in
 * libusb_handle_events_timeout_completed(), never in the caller's thread.
 * Built by the test: gcc -shared -fPIC $(pkg-config --cflags libusb-1.0)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <libusb.h>

#define DEVICES 40

struct libusb_device {
  int n;
  int refs;
};

struct libusb_device_handle {
  struct libusb_device *dev;
  int fd;
};

static struct libusb_device devs[DEVICES];
static struct libusb_device_handle *handles[DEVICES];
static struct libusb_transfer *reads[DEVICES];      /* submitted */
static struct libusb_transfer *cancelled[DEVICES];  /* to complete as cancelled */
static unsigned char status[DEVICES];
static int cs = -1;
static libusb_hotplug_callback_fn hotplug_cb;
static void *hotplug_data;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;

static int connect_to(const char *name)
{
  const char *dir = getenv("FAKE_SGIL1_DIR");
  struct sockaddr_un u;
  int fd;

  if (dir == NULL)
    return -1;
  fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (fd < 0)
    return -1;
  memset(&u, 0, sizeof(u));
  u.sun_family = AF_UNIX;
  snprintf(u.sun_path, sizeof(u.sun_path), "%s/%s", dir, name);
  if (connect(fd, (struct sockaddr *)&u, sizeof(u)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

int libusb_init(libusb_context **ctx)
{
  int i;

  for (i = 0; i < DEVICES; i++)
    devs[i].n = i;
  cs = connect_to("sgil1_cs");
  if (cs < 0)
    return LIBUSB_ERROR_OTHER;
  /* (the first status: wait for it, as the driver always had one) */
  if (recv(cs, status, sizeof(status), 0) < 0)
    return LIBUSB_ERROR_OTHER;
  if (ctx != NULL)
    *ctx = (libusb_context *)&cs;
  return 0;
}

void libusb_exit(libusb_context *ctx)
{
  close(cs);
  cs = -1;
}

const char *libusb_strerror(int code)
{
  return "fake libusb error";
}

int libusb_has_capability(uint32_t capability)
{
  return capability == LIBUSB_CAP_HAS_HOTPLUG;
}

int libusb_hotplug_register_callback(libusb_context *ctx, int events, int flags, int vendor_id,
                                     int product_id, int dev_class, libusb_hotplug_callback_fn cb_fn,
                                     void *user_data, libusb_hotplug_callback_handle *handle)
{
  int i;

  hotplug_cb = cb_fn;
  hotplug_data = user_data;
  if (handle != NULL)
    *handle = 1;
  if (flags & LIBUSB_HOTPLUG_ENUMERATE)
    for (i = 0; i < DEVICES; i++)
      if (status[i])
        cb_fn(ctx, &devs[i], LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED, user_data);
  return 0;
}

void libusb_hotplug_deregister_callback(libusb_context *ctx, libusb_hotplug_callback_handle handle)
{
  hotplug_cb = NULL;
}

static void complete(struct libusb_transfer *t, enum libusb_transfer_status st, int len)
{
  t->status = st;
  t->actual_length = len;
  t->callback(t);
}

int libusb_handle_events_timeout_completed(libusb_context *ctx, struct timeval *tv, int *completed)
{
  struct pollfd fds[DEVICES + 1];
  struct libusb_transfer *done[DEVICES];
  struct libusb_transfer *t;
  unsigned char msg[DEVICES];
  int which[DEVICES + 1];
  int nfds = 0, ndone = 0;
  int i, n;
  ssize_t len;

  pthread_mutex_lock(&mu);
  for (i = 0; i < DEVICES; i++)
    if (cancelled[i] != NULL) {
      done[ndone++] = cancelled[i];
      cancelled[i] = NULL;
    }
  pthread_mutex_unlock(&mu);
  for (i = 0; i < ndone; i++)
    complete(done[i], LIBUSB_TRANSFER_CANCELLED, 0);
  if (ndone > 0)
    return 0;

  pthread_mutex_lock(&mu);
  if (cs >= 0) {
    fds[nfds].fd = cs;
    fds[nfds].events = POLLIN;
    which[nfds++] = -1;
  }
  for (i = 0; i < DEVICES; i++)
    if (reads[i] != NULL && handles[i] != NULL) {
      fds[nfds].fd = handles[i]->fd;
      fds[nfds].events = POLLIN;
      which[nfds++] = i;
    }
  pthread_mutex_unlock(&mu);
  n = poll(fds, nfds, tv->tv_sec * 1000 + tv->tv_usec / 1000);
  if (n <= 0)
    return 0;
  for (i = 0; i < nfds; i++) {
    if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
      continue;
    if (which[i] < 0) {
      /* presence changed: arrivals and departures */
      len = recv(cs, msg, sizeof(msg), MSG_DONTWAIT);
      for (n = 0; n < len && n < DEVICES; n++) {
        if (msg[n] == status[n])
          continue;
        status[n] = msg[n];
        if (hotplug_cb != NULL)
          hotplug_cb(ctx, &devs[n], msg[n] ? LIBUSB_HOTPLUG_EVENT_DEVICE_ARRIVED
                                            : LIBUSB_HOTPLUG_EVENT_DEVICE_LEFT, hotplug_data);
      }
      continue;
    }
    pthread_mutex_lock(&mu);
    t = reads[which[i]];
    reads[which[i]] = NULL;
    pthread_mutex_unlock(&mu);
    if (t == NULL)
      continue;
    len = recv(fds[i].fd, t->buffer, t->length, MSG_DONTWAIT);
    if (len <= 0)
      complete(t, LIBUSB_TRANSFER_NO_DEVICE, 0);
    else if (len >= 5 && memcmp(t->buffer, "\xff\xfe" "ERR", 5) == 0) {
      char num[16];
      size_t l = (size_t)len - 5 < sizeof(num) - 1 ? (size_t)len - 5 : sizeof(num) - 1;
      memcpy(num, t->buffer + 5, l);
      num[l] = '\0';
      n = atoi(num);
      complete(t, n == ENODEV ? LIBUSB_TRANSFER_NO_DEVICE : n == EPIPE ? LIBUSB_TRANSFER_STALL
                                                                      : LIBUSB_TRANSFER_ERROR, 0);
    }
    else
      complete(t, LIBUSB_TRANSFER_COMPLETED, (int)len);
  }
  return 0;
}

ssize_t libusb_get_device_list(libusb_context *ctx, libusb_device ***list)
{
  int i, n = 0;

  *list = calloc(DEVICES + 1, sizeof(**list));
  for (i = 0; i < DEVICES; i++)
    if (status[i])
      (*list)[n++] = libusb_ref_device(&devs[i]);
  return n;
}

void libusb_free_device_list(libusb_device **list, int unref_devices)
{
  int i;

  if (unref_devices)
    for (i = 0; list[i] != NULL; i++)
      libusb_unref_device(list[i]);
  free(list);
}

int libusb_get_device_descriptor(libusb_device *dev, struct libusb_device_descriptor *desc)
{
  memset(desc, 0, sizeof(*desc));
  desc->idVendor = 0x065e;
  desc->idProduct = 0x1234;
  return 0;
}

libusb_device *libusb_ref_device(libusb_device *dev)
{
  __sync_fetch_and_add(&dev->refs, 1);
  return dev;
}

void libusb_unref_device(libusb_device *dev)
{
  __sync_fetch_and_sub(&dev->refs, 1);
}

int libusb_get_port_numbers(libusb_device *dev, uint8_t *port_numbers, int len)
{
  if (len < 1)
    return LIBUSB_ERROR_OVERFLOW;
  port_numbers[0] = dev->n + 1;
  return 1;
}

uint8_t libusb_get_bus_number(libusb_device *dev)
{
  return 1;
}

uint8_t libusb_get_device_address(libusb_device *dev)
{
  return dev->n + 2;
}

int libusb_open(libusb_device *dev, libusb_device_handle **dev_handle)
{
  char name[32];
  libusb_device_handle *h;

  snprintf(name, sizeof(name), "sgil1_%d", dev->n);
  h = calloc(1, sizeof(*h));
  h->dev = dev;
  h->fd = connect_to(name);
  if (h->fd < 0) {
    free(h);
    return LIBUSB_ERROR_NO_DEVICE;
  }
  pthread_mutex_lock(&mu);
  handles[dev->n] = h;
  pthread_mutex_unlock(&mu);
  *dev_handle = h;
  return 0;
}

void libusb_close(libusb_device_handle *h)
{
  pthread_mutex_lock(&mu);
  if (handles[h->dev->n] == h)
    handles[h->dev->n] = NULL;
  pthread_mutex_unlock(&mu);
  close(h->fd);
  free(h);
}

int libusb_set_auto_detach_kernel_driver(libusb_device_handle *h, int enable)
{
  return 0;
}

int libusb_claim_interface(libusb_device_handle *h, int interface_number)
{
  return 0;
}

int libusb_release_interface(libusb_device_handle *h, int interface_number)
{
  return 0;
}

static const struct libusb_endpoint_descriptor endpoints[2] = {
  { .bLength = 7, .bDescriptorType = LIBUSB_DT_ENDPOINT, .bEndpointAddress = 0x01,
    .bmAttributes = LIBUSB_TRANSFER_TYPE_BULK, .wMaxPacketSize = 64 },
  { .bLength = 7, .bDescriptorType = LIBUSB_DT_ENDPOINT, .bEndpointAddress = 0x81,
    .bmAttributes = LIBUSB_TRANSFER_TYPE_BULK, .wMaxPacketSize = 64 },
};
static const struct libusb_interface_descriptor altsetting = {
  .bLength = 9, .bDescriptorType = LIBUSB_DT_INTERFACE, .bNumEndpoints = 2, .endpoint = endpoints,
};
static const struct libusb_interface interface = { .altsetting = &altsetting, .num_altsetting = 1 };
static struct libusb_config_descriptor config = {
  .bLength = 9, .bDescriptorType = LIBUSB_DT_CONFIG, .bNumInterfaces = 1, .interface = &interface,
};

int libusb_get_active_config_descriptor(libusb_device *dev, struct libusb_config_descriptor **c)
{
  *c = &config;
  return 0;
}

void libusb_free_config_descriptor(struct libusb_config_descriptor *c)
{
}

struct libusb_transfer *libusb_alloc_transfer(int iso_packets)
{
  return calloc(1, sizeof(struct libusb_transfer) +
                   iso_packets * sizeof(struct libusb_iso_packet_descriptor));
}

void libusb_free_transfer(struct libusb_transfer *t)
{
  free(t);
}

int libusb_submit_transfer(struct libusb_transfer *t)
{
  int n = t->dev_handle->dev->n;
  int rc = 0;

  pthread_mutex_lock(&mu);
  if (handles[n] != t->dev_handle)
    rc = LIBUSB_ERROR_NO_DEVICE;
  else if (reads[n] != NULL)
    rc = LIBUSB_ERROR_BUSY;
  else
    reads[n] = t;
  pthread_mutex_unlock(&mu);
  return rc;
}

int libusb_cancel_transfer(struct libusb_transfer *t)
{
  int n = t->dev_handle->dev->n;
  int rc = LIBUSB_ERROR_NOT_FOUND;

  pthread_mutex_lock(&mu);
  if (reads[n] == t) {
    reads[n] = NULL;
    cancelled[n] = t;
    rc = 0;
  }
  pthread_mutex_unlock(&mu);
  return rc;
}

int libusb_bulk_transfer(libusb_device_handle *h, unsigned char endpoint, unsigned char *data,
                         int length, int *transferred, unsigned int timeout)
{
  if (send(h->fd, data, length, MSG_NOSIGNAL) < 0)
    return errno == EPIPE || errno == ECONNRESET ? LIBUSB_ERROR_NO_DEVICE : LIBUSB_ERROR_IO;
  *transferred = length;
  return 0;
}

int libusb_clear_halt(libusb_device_handle *h, unsigned char endpoint)
{
  return 0;
}

int libusb_reset_device(libusb_device_handle *h)
{
  return 0;
}
