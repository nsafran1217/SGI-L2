/*
 * sys_ctrl/common/sys/ipmi.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/ipmi.h
 */

#ifndef SYS_CTRL_COMMON_SYS_IPMI_H
#define SYS_CTRL_COMMON_SYS_IPMI_H

#include "sysctl_types.h"   /* needed by the reconstruction */
/* reserved/version share a byte: reversed on big-endian hosts (see nvram.h) */
typedef struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint32 version : 4;
    uint32 reserved : 4;
#else
    uint32 reserved : 4;
    uint32 version : 4;
#endif
    uint32 internal_use_area : 8;
    uint32 chassis_info_area : 8;
    uint32 board_info_area : 8;
    uint32 poduct_info_area : 8;
    uint32 multi_record_area : 8;
    uint32 pad : 8;
    uint32 checksum : 8;
} ipmiCommonHeader;
typedef uint8 *ipmiInternalUseArea;
typedef uint8 *ipmiChassisInfoArea;
typedef uint8 *ipmiBoardInfoArea;
typedef uint8 *ipmiProductInfoArea;
typedef uint8 *ipmiMultiRecordArea;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* ipmi.c */
void ipmiInit(void);
uint8 ipmiCheckCSum(uint8 *cptr, uint32 bytes);
uint8 ipmiCalcCSum(uint8 *cptr, uint32 bytes);

#endif /* SYS_CTRL_COMMON_SYS_IPMI_H */
