/*
 * sys_ctrl/l3/api/SCapiL2.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * (No such header existed; this holds the module's prototypes.)
 * Module: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapiL2.h
 */

#ifndef SYS_CTRL_L3_API_SCAPIL2_H
#define SYS_CTRL_L3_API_SCAPIL2_H

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "SCapi.h"   /* for the prototypes */
/* SCapiL2.c */
int sn1SCDiscoverL2(char *dev, char *client_info, sn1SC_L2 **l2_return_list, int *l2_cnt, int wait);
int sn1SCDiscoverL2Start(int sd, char *dev, char *client_info);
int sn1SCDiscoverL2Response(int sd, sn1SC_L2 *l2, int wait);
int sn1SCDiscoverL2Done(int sd);
int find_l2_slot(sn1SC_L2 *l2ent, sn1SC_L2 *l2_list, int beg, int end);

#endif /* SYS_CTRL_L3_API_SCAPIL2_H */
