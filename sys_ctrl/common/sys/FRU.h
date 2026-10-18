/*
 * sys_ctrl/common/sys/FRU.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/FRU.h
 */

#ifndef SYS_CTRL_COMMON_SYS_FRU_H
#define SYS_CTRL_COMMON_SYS_FRU_H

#include "../IRouter/IRouter.h"
struct FRU_MMR_ADDR_S {
    unsigned int addr;
    unsigned int type;
    char *name;
};
typedef struct FRU_MMR_ADDR_S FRU_MMR_ADDR;
struct FRU_MMR_DATA_S {
    unsigned char data[8];
};
typedef struct FRU_MMR_DATA_S FRU_MMR_DATA;
struct FRU_EXT_DATA_S {
    int count;
    FRU_MMR_DATA *data;
};
typedef struct FRU_EXT_DATA_S FRU_EXT_DATA;
struct FRU_ASIC_S {
    char desc[80];
    int status;
    int type;
    int index;
    int mmr_count;
    unsigned int *mmr_addr;
    FRU_MMR_DATA *mmr_data;
    int ext_count;
    FRU_EXT_DATA *ext_data;
};
typedef struct FRU_ASIC_S FRU_ASIC;
struct FRU_SLOT_S {
    char id[16];
    int nasics;
    FRU_ASIC *asics;
};
typedef struct FRU_SLOT_S FRU_SLOT;
struct FRU_DATA_S {
    int revision;
    int tstamp;
    int source;
    int rack;
    int slot;
    int type;
    int status;
    int nslots;
    FRU_SLOT *slots;
    char *cstatus;
    char *kstatus;
    char *estatus;
    char *mstatus;
    char *sstatus;
    char *lstatus;
};
typedef struct FRU_DATA_S FRU_DATA;

#endif /* SYS_CTRL_COMMON_SYS_FRU_H */
