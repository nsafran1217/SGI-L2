/*
 * sys_ctrl/l3/l2/l1.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l1.c
 *
 * The L2's links to its L1s, by l2_l1_conn_mode:
 *  - USB (the default): libusb (l1usb.c, which stands in for SGI's sgil1
 *    driver). It reports which devices are present; each present one is
 *    opened as an L1 port, and closed when it goes or after repeated
 *    errors;
 *  - sockets (-net): l1net.c accepts them.
 * Packets are read and written whole through IRouterReadPacket() and
 * IRouterWritePacket() with the link's read and write functions.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "l2.h"
#include "l1.h"
#include "cfg.h"
#include "dmp.h"
#include "irtr.h"
#include "l1net.h"
#include "l1usb.h"
#include "smp.h"
#include "../main/settings.h"
#include "../main/l2log.h"
#include "../../common/Router/SocketIO.h"
#include "../../common/sys/Logger.h"

#define MAX_FDS         64      /* lasterr[] and the like, by descriptor */
#define READ_ERRORS     3       /* a device is closed after this many in a row */
#define ACCESS_TRIES    20      /* a new device's open denied: tried again this often, */
#define ACCESS_USECS    250000  /* this far apart (udev may not have run its rule yet) */

static char *l1_usb_path_str(l1usb_cfg_t *cfg, int format);

int l1_throttle_freq = 50;      /* ms between reads while throttled */
static char **l1_usbpath_list;  /* -usbpath: only devices on these paths */
static int l1_usbpath_count;
static int l1_usbpath_size;
int l1usb_debug;                /* (USB messages as console events) */
EventID l1_throttle_timerid;
/* the last read error on each descriptor, and how often it repeated */
static int lasterr[MAX_FDS];
static int lastcnt[MAX_FDS];
static char lastdev[MAX_FDS][60];
static int access_tries[L2_L1_PORTS];

/* (the original indexed these by any descriptor) */
static int fd_ok(int fd)
{
  return fd >= 0 && fd < MAX_FDS;
}

/* src into a field of size bytes, cut to fit */
static void copy_field(char *dst, size_t size, const char *src)
{
  size_t n = strlen(src);

  if (n >= size)
    n = size - 1;
  memcpy(dst,src,n);
  dst[n] = '\0';
}

/* the port of an open descriptor, or -1 */
int l1_fd_device(int fd)
{
  int dev;

  for (dev = 0; dev < L2_L1_PORTS; dev++)
    if (l2_l1_ports[dev].fd == fd)
      return dev;
  return -1;
}

/* USB messages: console events when debugging USB, else to stderr */
#define USB_MSG(...) \
  do { if (l1usb_debug) l2_console_printf(__VA_ARGS__); else fprintf(stderr,__VA_ARGS__); } while (0)

/* --- USB --- */

int l1_open_usb(void)
{
  int i;

  if (l2_debug)
    fprintf(stderr,"l1_open_usb() in\n");
  l2_l1_control = l1usb_start();
  if (l2_l1_control < 0)
    return -1;
  fprintf(stderr,"INFO: watching for L1s on USB\n");
  if (l1_usbpath_count != 0) {
    fprintf(stderr,"INFO:  monitoring for L1 USB devices on the following USB paths:\n");
    for (i = 0; i < l1_usbpath_count; i++)
      fprintf(stderr,"       %s\n",l1_usbpath_list[i]);
  }
  l1_service_usb(0,0);
  EventAddInput(l2_l1_control,l1_service_usb,NULL,"l1_open_usb");
  if (l2_debug)
    fprintf(stderr,"l1_open_usb() out\n");
  return 0;
}

/* a reset of the device on descriptor fd (l1usb_reset()'s what) */
int l1_usb_reset(int fd, int what)
{
  return l1usb_reset(l1_fd_device(fd),what);
}

/* drop what the device has buffered (both ways); reset: and reset it */
int l1_flush_usb_device(int fd, int reset)
{
  if (l1_usb_reset(fd,L1USB_RESET_PIPES) != 0)
    return -1;
  if (reset && l1_usb_reset(fd,L1USB_RESET_DEVICE) != 0) {
    fprintf(stderr,"USB device reset error, %s\n",strerror(errno));
    return -1;
  }
  return 0;
}

/* a device's USB path: 0 "b<bus>;p<path>;d<dev>", 1 for people, 2 without
 * the device (as -usbpath gives it) */
static char *l1_usb_path_str(l1usb_cfg_t *cfg, int format)
{
  static char path[80];
  int i;

  if (format == 1)
    sprintf(path,"  bus: %u  path: ",cfg->bus);
  else
    sprintf(path,"b%u;p",cfg->bus);
  for (i = 0; i < cfg->level && i < (int)sizeof(cfg->path); i++)
    sprintf(path + strlen(path),i != 0 ? "/%d" : "%d",cfg->path[i]);
  if (format == 0)
    sprintf(path + strlen(path),";d%d",cfg->dev);
  else if (format == 1)
    sprintf(path + strlen(path),"  dev: %d",cfg->dev);
  return path;
}

/* whether device is on one of the -usbpath paths (all are, without
 * -usbpath); -1 if it is gone */
static int on_usbpath(int device)
{
  l1usb_cfg_t cfg;
  const char *path;
  int plen;
  int llen;
  int i;

  if (l1_usbpath_count == 0)
    return 1;
  if (l1usb_cfg(device,&cfg) != 0)
    return -1;
  path = l1_usb_path_str(&cfg,2);
  plen = strlen(path);
  for (i = 0; i < l1_usbpath_count; i++) {
    /* the device's path starts with the listed one, at a hub boundary */
    llen = strlen(l1_usbpath_list[i]);
    if (strncmp(path,l1_usbpath_list[i],llen) == 0 &&
        (llen < plen || l1_usbpath_list[i][plen] == '\0' || l1_usbpath_list[i][plen] == '/'))
      return 1;
  }
  return 0;
}

/* a device appeared: open it as L1 port device */
int l1_open_usb_device(int device)
{
  char dev_name[20];
  char usbpath[40] = "";
  l1usb_cfg_t cfg;
  int fd;

  if (l2_debug)
    fprintf(stderr,"l1_open_usb_device(%d) in\n",device);
  switch (on_usbpath(device)) {
  case -1:
    return -1;
  case 0:
    return 0;
  }
  /* (the original's /dev/sgil1_<n>) */
  snprintf(dev_name,sizeof(dev_name),"usb%d",device);
  if (l1usb_cfg(device,&cfg) == 0)
    snprintf(usbpath,sizeof(usbpath),"%s",l1_usb_path_str(&cfg,0));
  fd = l1usb_open(device);
  if (fd < 0 && errno == EACCES && access_tries[device]++ < ACCESS_TRIES) {
    /* (plugged in just now: libusb can tell of a device before udev has given
     * it to the rule's group; l1_service_usb() opens it again, as it is
     * present again) */
    l2_l1_ports[device].status = 0;
    EventAddTimeOut(0,ACCESS_USECS,l1_service_usb,NULL,"l1_open_usb_device");
    return 0;
  }
  access_tries[device] = 0;
  if (fd < 0) {
    fprintf(stderr,"ERROR: can\'t open USB device at %s, %s%s\n",usbpath,strerror(errno),
            errno == EACCES ? " (a udev rule for 065e:1234 lets l2 run as a user)" : "");
    return -1;
  }
  USB_MSG("INFO: opened USB device at %s (%s)\n",usbpath,dev_name);
  if (l2_l1_local_port == -1)
    l2_l1_local_port = device;
  /* (both fields are shorter than the strings can be: as the original) */
  copy_field(l2_l1_ports[device].device,sizeof(l2_l1_ports[device].device),dev_name);
  copy_field(l2_l1_ports[device].usbpath,sizeof(l2_l1_ports[device].usbpath),usbpath);
  l2_l1_ports[device].fd = fd;
  l1_flush_usb_device(fd,0);
  if (fd_ok(fd)) {
    lasterr[fd] = 0;
    lastcnt[fd] = 0;
  }
  if (L2CfgMAddPort(&L2CfgLocal,device,dev_name,usbpath,2,fd) == -1) {
    fprintf(stderr,"ERROR: device is already in use.\n");
    return -1;
  }
  l2_l1_ports[device].timer = EventAddTimeOut(0,750000,cfg_ping_l1,(EventData)(intptr_t)device,
                                              "l1_open_usb_device");
  EventAddInput(l2_l1_ports[device].fd,l1_read_packet,(EventData)(intptr_t)device,"l1_open_usb_device");
  if (l2_debug)
    fprintf(stderr,"l1_open_usb_device() out, fd: %d\n",fd);
  return 0;
}

/* close L1 port device (who: why, unused); reopen: look at the devices
 * again in 5 seconds */
int l1_close_usb_device(int device, int reopen, char *who)
{
  char *dname;
  int fd;

  if (device < 0)
    return 0;
  if (l2_debug)
    fprintf(stderr,"l1_close_usb_device(%d) in\n",device);
  fd = l2_l1_ports[device].fd;
  if (fd >= 0) {
    dname = L2CfgMDeviceName(&L2CfgLocal,fd);
    EventRemoveInput(fd);
    EventRemoveTimeOut(l2_l1_ports[device].timer);
    l2_l1_ports[device].fd = -1;
    l2_l1_ports[device].status = 0;
    l2_l1_ports[device].wr_errcnt = 0;
    l2_l1_ports[device].rd_errcnt = 0;
    l2_l1_ports[device].timer = 0;
    smp_chkcon_changes(0);
    L2CfgMCfgPort(&L2CfgLocal,device,NULL);
    smp_chkcon_changes(1);
    if (l1usb_close(device) != 0) {
      fprintf(stderr,"ERROR: can\'t close %s, %s - %s\n",dname,l2_l1_ports[device].device,strerror(errno));
      return -1;
    }
    USB_MSG("INFO: closed %s\n",dname);
    cfg_configcheck(1);
  }
  if (l2_debug)
    fprintf(stderr,"l1_close_usb_device() out\n");
  if (reopen)
    EventAddTimeOut(5,0,l1_service_usb,NULL,"l1_close_usb_device");
  return 0;
}

/* devices came or went (l1usb.c): close the ones that went, then open
 * the ones that came */
void l1_service_usb(int data, int fd)
{
  unsigned char status[L1USB_SLOTS];
  int devices;
  int device;

  if (l2_debug)
    fprintf(stderr,"l1_service_usb_device(%d) in\n",fd);
  l1usb_drain();
  devices = l1usb_status(status,sizeof(status));
  for (device = 0; device < devices; device++) {
    if (status[device] == 0)
      access_tries[device] = 0;
    if (status[device] != l2_l1_ports[device].status && status[device] == 0) {
      l2_l1_ports[device].status = status[device];
      l1_close_usb_device(device,0,"[driver]");
    }
  }
  for (device = 0; device < devices; device++) {
    if (status[device] != l2_l1_ports[device].status && status[device] != 0) {
      l2_l1_ports[device].status = status[device];
      l1_open_usb_device(device);
    }
  }
  if (l2_debug)
    fprintf(stderr,"l1_service_usb_device() out\n");
}

int l1_close_usb(void)
{
  int device;

  if (l2_debug)
    fprintf(stderr,"l1_close_usb() in\n");
  for (device = 0; device < L2_L1_PORTS; device++)
    if (l2_l1_ports[device].status != 0)
      l1_close_usb_device(device,0,"[app close]");
  EventRemoveInput(l2_l1_control);
  l1usb_stop();
  fprintf(stderr,"INFO: stopped watching USB\n");
  if (l2_debug)
    fprintf(stderr,"l1_close_usb() out\n");
  return 0;
}

/* open the L1 link(s); exits if it can't */
void l1_open(void)
{
  int status = 0;
  int device;

  memset(l2_l1_ports,0,sizeof(l2_l1_ports));
  for (device = 0; device < L2_L1_PORTS; device++)
    l2_l1_ports[device].fd = -1;
  if (l2_debug)
    fprintf(stderr,"l1_open() in\n");
  switch (l2_l1_conn_mode) {
  case L2_CONN_NET:
    status = l1net_export();
    break;
  case L2_CONN_USB:
    status = l1_open_usb();
    break;
  }
  if (status != 0) {
    fprintf(stderr,"FATAL: can\'t open connection to L1\n");
    exit(1);
  }
  if (l2_debug)
    fprintf(stderr,"l1_open() out\n");
}

/* an L1 link closed; exits if it can't be */
void l1_close(int fd)
{
  int status = 0;

  switch (l2_l1_conn_mode) {
  case L2_CONN_NET:
    l1net_close(fd);
    break;
  case L2_CONN_USB:
    status = l1_close_usb();
    break;
  }
  if (status != 0) {
    fprintf(stderr,"FATAL: can\'t close connection to L1\n");
    exit(1);
  }
}

/* after a failed read or write: a device that is gone is closed (0); 1 if
 * it is still there */
int l1_usb_recover(int fd, int error)
{
  if (error != ENODEV && error != EINVAL)
    return 1;
  l1_close_usb_device(l1_fd_device(fd),0,"[no device]");
  return 0;
}

/* after a failed read or write on a device that is still there: count
 * it, close the device after READ_ERRORS in a row, else reset that
 * direction (reset_dir), and the whole device if that fails. 0 if the
 * device is closed. */
static int usb_error(int fd, int dev, int *errcnt, const char *what, int reset_dir, const char *reset_name)
{
  if (++*errcnt >= READ_ERRORS) {
    l2_console_printf("WARNING: closing %s after multiple %s errors\n",L2CfgMDeviceName(&L2CfgLocal,fd),what);
    l1_flush_usb_device(fd,1);
    l1_close_usb_device(dev,1,*what == 'r' ? "[rd error]" : "[wr error]");
    return 0;
  }
  if (l1_usb_reset(fd,reset_dir) == 0)
    return 1;
  if (!l1_usb_recover(fd,errno))
    return 0;
  if (l2_debug)
    fprintf(stderr,"%s error, %s\n",reset_name,strerror(errno));
  if (l1_usb_reset(fd,L1USB_RESET_DEVICE) != 0) {
    if (!l1_usb_recover(fd,errno))
      return 0;
    fprintf(stderr,"USB device reset error, %s\n",strerror(errno));
  }
  return 1;
}

int l1_read_usb(int fd, unsigned char **bptr, int blen)
{
  int dev_still_open = 1;
  int dev = l1_fd_device(fd);
  int status;

  if (l2_debug)
    fprintf(stderr,"l1_read_usb(%d,%lx(%lx),%d) in\n",fd,(unsigned long)(uintptr_t)bptr,
            (unsigned long)(uintptr_t)*bptr,blen);
  errno = 0;
  status = l1usb_read(fd,*bptr + IR_FRAME_PREFIX,blen);
  if (status < 0) {
    dev_still_open = l1_usb_recover(fd,errno);
    if (dev_still_open)
      dev_still_open = usb_error(fd,dev,&l2_l1_ports[dev].rd_errcnt,"read",L1USB_RESET_READ,
                                 "USB read reset");
  }
  else
    l2_l1_ports[dev].rd_errcnt = 0;
  if (l2_debug)
    fprintf(stderr,"l1_read_usb() out, status %d, errno %d\n",status,errno);
  if (l2_debug > 1)
    dmp("READ",*bptr + IR_FRAME_PREFIX,status,1);
  return dev_still_open ? status : 0;
}

/* a frame from a socket: its 16-bit size (network order) first */
int l1_read_l1net(int fd, unsigned char **pbptr, int blen)
{
  unsigned char *bptr = *pbptr + IR_FRAME_PREFIX;
  int status;

  errno = 0;
  status = SocketRead(fd,bptr,2);
  if (status > 0) {
    status = SocketRead(fd,bptr + 2,(bptr[0] << 8 | bptr[1]) - 2);
    if (status > 0)
      status += 2;
  }
  return status;
}

/* network clients fall behind (throttle): read the L1s every
 * l1_throttle_freq ms only; 0: as fast as they come */
void l1_throttle_input(int throttle)
{
  int device;

  if (!throttle) {
    if (l1_throttle_timerid != 0) {
      EventRemoveTimeOut(l1_throttle_timerid);
      l1_throttle_timerid = 0;
    }
  }
  else
    l1_throttle_timerid = EventAddTimeOut(0,l1_throttle_freq * 1000,l1_throttle_input,(EventData)1,
                                          "L1 input throttle");
  for (device = 0; device < L2_L1_PORTS; device++)
    if (l2_l1_ports[device].fd >= 0)
      EventEnableInput(l2_l1_ports[device].fd,1);
}

/* the link's read and write functions */
static int (*read_fcn(void))()
{
  switch (l2_l1_conn_mode) {
  case L2_CONN_NET:
    return l1_read_l1net;
  case L2_CONN_USB:
    return l1_read_usb;
  }
  return NULL;
}

static int (*write_fcn(void))()
{
  switch (l2_l1_conn_mode) {
  case L2_CONN_NET:
    return l1_write_l1net;
  case L2_CONN_USB:
    return l1_write_usb;
  }
  return NULL;
}

/* read errors: console events on USB, else to stderr */
#define READ_MSG(...) \
  do { if (l2_l1_conn_mode == L2_CONN_USB) l2_console_printf(__VA_ARGS__); else fprintf(stderr,__VA_ARGS__); } while (0)

/* a packet from L1 port port (descriptor fd): route it. Read errors are
 * reported once, then counted until another (or a packet) comes. */
void l1_read_packet(int port, int fd)
{
  IRPacket *p;
  int status;

  if (l1_throttle_timerid != 0)
    EventEnableInput(fd,0);
  if (l2_debug)
    fprintf(stderr,"l1_read_packet(%x,%d) in\n",port,fd);
  status = IRouterReadPacket(&l2_id,read_fcn(),(void *)(intptr_t)fd,&p);
  if (status == 0) {
    if (fd_ok(fd)) {
      if (lastcnt[fd] > 1)
        READ_MSG("WARNING: last error on %s repeated %d times\n",lastdev[fd],lastcnt[fd]);
      lastcnt[fd] = 0;
      lasterr[fd] = 0;
    }
    p->_client_data = (uint8 *)(intptr_t)port;
    IRouterSendPacket(NULL,p);
  }
  else if (status == IR_ERRNO(IRERR_READ_FAILED_EOF)) {
    if (l2_l1_conn_mode == L2_CONN_NET)
      l1_close(fd);
  }
  else if (fd_ok(fd)) {
    if (status == lasterr[fd])
      lastcnt[fd]++;
    else {
      if (lastcnt[fd] > 1)
        READ_MSG("WARNING: last read error on %s repeated %d times\n",lastdev[fd],lastcnt[fd]);
      lasterr[fd] = status;
      lastcnt[fd] = 1;
      copy_field(lastdev[fd],sizeof(lastdev[fd]),L2CfgMDeviceName(&L2CfgLocal,fd));
      READ_MSG("WARNING: can\'t read packet from %s:   %s\n",lastdev[fd],LoggerDefaultMessage(status));
    }
  }
  if (l2_debug)
    fprintf(stderr,"l1_read_packet() out\n");
}

int l1_write_usb(int fd, unsigned char *bptr, int blen)
{
  int dev_still_open = 1;
  int dev = l1_fd_device(fd);
  int status;

  if (l2_debug)
    fprintf(stderr,"l1_write_usb(%d,%lx,%d) in\n",fd,(unsigned long)(uintptr_t)bptr,blen);
  status = l1usb_write(dev,bptr,blen);
  if (status < 0) {
    dev_still_open = l1_usb_recover(fd,errno);
    if (dev_still_open)
      dev_still_open = usb_error(fd,dev,&l2_l1_ports[dev].wr_errcnt,"write",L1USB_RESET_WRITE,
                                 "USB write reset");
  }
  else
    l2_l1_ports[dev].wr_errcnt = 0;
  if (l2_debug)
    fprintf(stderr,"l1_write_usb() out, status %d, errno %d\n",status,errno);
  if (l2_debug > 1)
    dmp("WRITE",bptr,blen,1);
  return dev_still_open ? status : 0;
}

int l1_write_l1net(int fd, unsigned char *bptr, int blen)
{
  return SocketWrite(fd,bptr,blen);
}

/* a packet to the L1 link at fd */
void l1_write_packet(int fd, IRPacket *p)
{
  IRAddress dest = p->_dest;
  int status;

  if (l2_debug)
    fprintf(stderr,"l1_write_packet(%d, %lx) in\n",fd,(unsigned long)(uintptr_t)p);
  status = IRouterWritePacket(&l2_id,write_fcn(),(void *)(intptr_t)fd,p);
  if (status != 0 && status != IR_ERRNO(IRERR_WRITE_FAILED_EOF))
    l2_console_printf("WARNING: can\'t write to %s [0x%08x]:   %s\n",L2CfgMDeviceName(&L2CfgLocal,fd),
                      dest,LoggerDefaultMessage(status));
  if (l2_debug)
    fprintf(stderr,"l1_write_packet() out\n");
}

/*
 * -usbpath <path>[,<path>...]: each "b<bus>;p<port>[/<port>...]" (the ';'
 * optional, either letter in either case), kept as "b<bus>;p<port>...".
 * -1 for an invalid one.
 */
int l1_parse_usbpath(char *usbpath)
{
  char path[100];
  char *list;
  char *next;
  char *cptr;
  char *path2;
  char *c1;
  char *c2;
  int pathno;
  int busno;
  int i;

  if (l1_usbpath_list != NULL) {
    for (i = 0; i < l1_usbpath_count; i++)
      free(l1_usbpath_list[i]);
    free(l1_usbpath_list);
  }
  l1_usbpath_list = malloc(10 * sizeof(char *));
  if (l1_usbpath_list == NULL) {
    fprintf(stderr,"ERROR: -usbpath: could not allocate memory to store USB path\n");
    return -1;
  }
  l1_usbpath_count = 0;
  l1_usbpath_size = 10;
  list = strdup(usbpath);
  /* (room for whatever %[ and %s match: the original scanned "%[Bb]" into
   * a char, and the rest into 100 bytes) */
  path2 = malloc(3 * strlen(usbpath) + 3);
  c1 = path2 + strlen(usbpath) + 1;
  c2 = c1 + strlen(usbpath) + 1;
  for (next = list; next != NULL && *next != '\0'; ) {
    cptr = next;
    next = strchr(cptr,',');
    if (next != NULL)
      *next++ = '\0';
    path2[0] = '\0';
    if (sscanf(cptr,"%[Bb]%d;%[Pp]%d%s",c1,&busno,c2,&pathno,path2) < 4 &&
        sscanf(cptr,"%[Bb]%d%[Pp]%d%s",c1,&busno,c2,&pathno,path2) < 4) {
      fprintf(stderr,"ERROR: -usbpath: invalid USB path:   \'%s\'\n",cptr);
      return -1;
    }
    if (path2[0] != '\0' && strspn(path2,"/0123456789") != strlen(path2)) {
      fprintf(stderr,"ERROR: -usbpath: invalid USB path:   \'%s\'\n",cptr);
      return -1;
    }
    /* (the original sprintf()ed past path's end for a long path) */
    if (snprintf(path,sizeof(path),"b%d;p%d%s",busno,pathno,path2) >= (int)sizeof(path)) {
      fprintf(stderr,"ERROR: -usbpath: invalid USB path:   \'%s\'\n",cptr);
      return -1;
    }
    if (l1_usbpath_count == l1_usbpath_size) {
      l1_usbpath_size += 10;
      l1_usbpath_list = realloc(l1_usbpath_list,l1_usbpath_size * sizeof(char *));
      if (l1_usbpath_list == NULL) {
        fprintf(stderr,"-usbpath: could not allocate memory to store USB path\n");
        return -1;
      }
    }
    l1_usbpath_list[l1_usbpath_count++] = strdup(path);
  }
  free(path2);
  free(list);
  return 0;
}
