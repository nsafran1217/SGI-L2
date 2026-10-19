/*
 * sys_ctrl/l3/main/settings.h
 *
 * New in the modern tree: l2's settings in a text file, replacing the
 * NVRAM image (nvram.c) of SGI's tools. See settings.c.
 */

#ifndef SYS_CTRL_L3_MAIN_SETTINGS_H
#define SYS_CTRL_L3_MAIN_SETTINGS_H

#include <stdint.h>

/* settingsInit() modes: read-only keeps changes in memory; read-write
 * saves every change to the file */
#define SETTINGS_READONLY   1
#define SETTINGS_READWRITE  3

/* settingsGet()/settingsSet() ids: SGI's NVRAM field numbers, for those
 * that are left. The string settings pass a char *. */
enum {
    SET_RACK = 1,
    SET_AUTO_POWERUP = 2,
    SET_SERIAL = 3,                 /* string: the system serial number */
    SET_SYSNAME = 4,                /* string */
    SET_MULTISYS = 5,
    SET_L2DSP_DISABLED = 9,
    SET_PING_MIN = 11,
    SET_PING_MAX = 12,
    SET_PING_SENDER = 13,
    SET_PING_L2FREQ = 14,
    SET_PING_L1FREQ = 15,
    SET_AUTOPOWER_DELAY = 20,
    SET_SLOW_PWRUP = 21,
    SET_SLOT = 22,
    SET_BROADCAST_TIMEOUT = 23,
    SET_TARGET_TIMEOUT = 24,
    SET_MASTER_SLAVE = 26,
};

void settingsSetPath(const char *path);
const char *settingsPath(void);
int settingsInit(int mode);
int settingsReset(void);
void settingsSet(int id, uintptr_t value);
uintptr_t settingsGet(int id);

#endif /* SYS_CTRL_L3_MAIN_SETTINGS_H */
