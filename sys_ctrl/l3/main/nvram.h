/*
 * sys_ctrl/l3/main/nvram.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/main/nvram.h
 */

#ifndef SYS_CTRL_L3_MAIN_NVRAM_H
#define SYS_CTRL_L3_MAIN_NVRAM_H

#include <stdint.h>

#include "../../common/sys/sysctl_types.h"   /* needed by the reconstruction */
#include "../../common/sys/ipmi.h"
typedef char nvramLog;
/* A little-endian 32-bit field of the NVRAM image (the file is the i386 layout);
 * read and written with nv32()/nv32set() in nvram.c. */
typedef struct {
    uint8 b[4];
} nvle32;
/* Sub-byte bitfields are declared in reverse on big-endian hosts so they land on
 * the same bits as on i386 (gcc allocates them from the other end of the byte). */
typedef struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned int version : 4;
    unsigned int __anon0 : 4;
#else
    unsigned int __anon0 : 4;
    unsigned int version : 4;
#endif
    uint8 unused1[2];
    uint8 slot;
    uint8 rack;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned int master_slave : 3;
    unsigned int slow_pwrup : 1;
    unsigned int dhcps_disabled : 1;
    unsigned int l2dsp_disabled : 1;
    unsigned int multisys : 1;
    unsigned int auto_powerup : 1;
#else
    unsigned int auto_powerup : 1;
    unsigned int multisys : 1;
    unsigned int l2dsp_disabled : 1;
    unsigned int dhcps_disabled : 1;
    unsigned int slow_pwrup : 1;
    unsigned int master_slave : 3;
#endif
    uint8 unused2[2];
    char system_serial_number[16];
    char system_name[32];
    nvle32 ip_addr;
    nvle32 ip_netmask;
    nvle32 ip_broadcast;
    nvle32 l1usb_debug;
    nvle32 ping_min;
    nvle32 ping_max;
    nvle32 ping_sender;
    nvle32 ping_l2freq;
    nvle32 ping_l1freq;
    char timezone[80];
    uint8 modem_baud;
    uint8 unused3[3];
    char password[16];
    nvle32 autopower_delay;
    uint8 broadcast_timeout;
    uint8 target_timeout;
    uint8 open1;
    uint8 open2;
    nvle32 ip_gateway;
    nvle32 extra[467];
    /* Original: nvramLog * (absolute 32-bit pointers in memory, rebased to
     * offsets on disk). Now always offsets into the NVRAM image, their disk
     * form, so the layout is the same on every architecture. */
    nvle32 log_start;
    nvle32 log_end;
    nvle32 log_head;
    nvle32 log_tail;
    uint8 pad[3];
    uint8 checksum;
} nvramInternalUseArea;
typedef struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned int version : 4;
    unsigned int __anon0 : 4;
#else
    unsigned int __anon0 : 4;
    unsigned int version : 4;
#endif
} nvramProductInfoArea;
struct _nvramInstance {
    int unused;
};
typedef struct _nvramInstance nvramInstance;

/* The NVRAM image (the file): an IPMI common header, the internal use area
 * at internal_use_area * 8, and after it the log ring up to NVRAM_LOG_END. */
#define NVRAM_SIZE      0x4000
#define NVRAM_LOG_END   (NVRAM_SIZE - 8)

/* nvramInit() modes: read-only keeps changes in memory; read-write saves
 * every change to the file */
#define NVRAM_READONLY  1
#define NVRAM_READWRITE 3

/* nvramGet()/nvramSet() fields. (The numbers are SGI's; the names were
 * added by the reconstruction.) The string fields pass a char *. */
enum {
    NVRAM_RACK = 1,
    NVRAM_AUTO_POWERUP = 2,
    NVRAM_SERIAL = 3,               /* string: the system serial number */
    NVRAM_SYSNAME = 4,              /* string */
    NVRAM_MULTISYS = 5,
    NVRAM_IP_ADDR = 6,
    NVRAM_IP_NETMASK = 7,
    NVRAM_IP_BROADCAST = 8,
    NVRAM_L2DSP_DISABLED = 9,
    NVRAM_L1USB_DEBUG = 10,
    NVRAM_PING_MIN = 11,
    NVRAM_PING_MAX = 12,
    NVRAM_PING_SENDER = 13,
    NVRAM_PING_L2FREQ = 14,
    NVRAM_PING_L1FREQ = 15,
    NVRAM_DHCPS_DISABLED = 16,
    NVRAM_TIMEZONE = 17,            /* string */
    NVRAM_MODEM_BAUD = 18,
    NVRAM_PASSWORD = 19,            /* string */
    NVRAM_AUTOPOWER_DELAY = 20,
    NVRAM_SLOW_PWRUP = 21,
    NVRAM_SLOT = 22,
    NVRAM_BROADCAST_TIMEOUT = 23,
    NVRAM_TARGET_TIMEOUT = 24,
    NVRAM_IP_GATEWAY = 25,
    NVRAM_MASTER_SLAVE = 26,
};

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* nvram.c */
extern ipmiCommonHeader *nvramCH;
extern nvramProductInfoArea *nvramPIA;
extern nvramInternalUseArea *nvramIUA;
extern nvramLog *nvramLogStart;
extern nvramLog *nvramLogEnd;
extern int32 nvramCount;
extern int32 nvramSim;
extern nvramInstance nvram;
int nvramInit(int mode);
int nvramReset(void);
void nvramSet(int32 location, uintptr_t value);   /* original: uint32 value */
uintptr_t nvramGet(int32 location);   /* original: uint32 */
void nvramLogReset(void);
void nvramLogInsert(char *message);
void nvramLogFinsert(char *fmt, ...) __attribute__((format(printf, 1, 2)));
char *nvramLogFetch(void);

#endif /* SYS_CTRL_L3_MAIN_NVRAM_H */
