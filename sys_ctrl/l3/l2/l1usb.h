/*
 * sys_ctrl/l3/l2/l1usb.h
 *
 * New in the modern tree: L1s on USB through libusb, in place of SGI's
 * sgil1 kernel driver. See l1usb.c.
 */

#ifndef SYS_CTRL_L3_L2_L1USB_H
#define SYS_CTRL_L3_L2_L1USB_H

#define L1USB_VENDOR    0x065e  /* SGI */
#define L1USB_PRODUCT   0x1234  /* an L1 */
#define L1USB_SLOTS     40      /* devices at once (the driver's) */
#define L1USB_MAX_LEVEL 6       /* hubs on a device's path */

/* where a device is, as the driver's sgil1_cfg_t had it */
typedef struct {
    unsigned char bus;
    unsigned char level;        /* ports on the way: path[0..level-1] */
    unsigned char dev;          /* the device address */
    unsigned char path[L1USB_MAX_LEVEL];
} l1usb_cfg_t;

/* l1usb_reset() */
enum {
    L1USB_RESET_READ = 1,
    L1USB_RESET_WRITE = 2,
    L1USB_RESET_PIPES = 3,      /* both */
    L1USB_RESET_DEVICE = 4,
};

int l1usb_start(void);
void l1usb_stop(void);
void l1usb_drain(void);
int l1usb_status(unsigned char *status, int n);
int l1usb_cfg(int slot, l1usb_cfg_t *cfg);
int l1usb_open(int slot);
int l1usb_close(int slot);
int l1usb_read(int fd, unsigned char *buf, int len);
int l1usb_write(int slot, const unsigned char *buf, int len);
int l1usb_reset(int slot, int what);

#endif /* SYS_CTRL_L3_L2_L1USB_H */
