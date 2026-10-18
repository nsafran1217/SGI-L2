/*
 * sys_ctrl/l3/main/nvram.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/main/nvram.h
 */

#ifndef SYS_CTRL_L3_MAIN_NVRAM_H
#define SYS_CTRL_L3_MAIN_NVRAM_H

#include "../../common/sys/sysctl_types.h"   /* needed by the reconstruction */
#include "../../common/sys/ipmi.h"
typedef char nvramLog;
typedef struct {
    unsigned int __anon0 : 4;
    unsigned int version : 4;
    uint8 unused1[2];
    uint8 slot;
    uint8 rack;
    unsigned int auto_powerup : 1;
    unsigned int multisys : 1;
    unsigned int l2dsp_disabled : 1;
    unsigned int dhcps_disabled : 1;
    unsigned int slow_pwrup : 1;
    unsigned int master_slave : 3;
    uint8 unused2[2];
    char system_serial_number[16];
    char system_name[32];
    uint32 ip_addr;
    uint32 ip_netmask;
    uint32 ip_broadcast;
    uint32 l1usb_debug;
    uint32 ping_min;
    uint32 ping_max;
    uint32 ping_sender;
    uint32 ping_l2freq;
    uint32 ping_l1freq;
    char timezone[80];
    uint8 modem_baud;
    uint8 unused3[3];
    char password[16];
    uint32 autopower_delay;
    uint8 broadcast_timeout;
    uint8 target_timeout;
    uint8 open1;
    uint8 open2;
    uint32 ip_gateway;
    uint32 extra[467];
    nvramLog *log_start;
    nvramLog *log_end;
    nvramLog *log_head;
    nvramLog *log_tail;
    uint8 pad[3];
    uint8 checksum;
} nvramInternalUseArea;
typedef struct {
    unsigned int __anon0 : 4;
    unsigned int version : 4;
} nvramProductInfoArea;
struct _nvramInstance {
    int unused;
};
typedef struct _nvramInstance nvramInstance;

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
void nvramSet(int32 location, uint32 value);
uint32 nvramGet(int32 location);
void nvramLogReset(void);
void nvramLogInsert(char *message);
void nvramLogFinsert(char *fmt, ...);
char *nvramLogFetch(void);

#endif /* SYS_CTRL_L3_MAIN_NVRAM_H */
