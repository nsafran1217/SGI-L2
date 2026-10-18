/*
 * sys_ctrl/l3/main/SysCfg.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/main/SysCfg.h
 */

#ifndef SYS_CTRL_L3_MAIN_SYSCFG_H
#define SYS_CTRL_L3_MAIN_SYSCFG_H

#include "../api/SCapiConn.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/main/L1Cfg.h"
#include "../../common/main/L2Cfg.h"
typedef L2CfgL1 SysCfgL1;
typedef L2Cfg SysCfgL2;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* SysCfg.c */
extern SysCfgL2 *SysCfgFull;
extern int SysCfgL1Count;
extern int SysCfgL2Count;
extern SysCfgL1 *SysCfgL1List[1024];
extern SysCfgL2 *SysCfgL2List[128];
void SysCfgConnInit(sn1SCConn *conn, char *user);
void SysCfgConnRequest(sn1SCConn *conn, char *user);
int SysCfgConnProcessEvent(sn1SCConn *conn, char *user, IRPacket *pkt);
void SysCfgConnPrintL1(sn1SCConn *conn, int fd);
void SysCfgConnPrintL2(sn1SCConn *conn, int fd);
char *SysCfgConnAddrStr(sn1SCConn *conn, IRAddress addr, int verbose);
IRAddress SysCfgConsole(sn1SCConn *conn, int partition);

#endif /* SYS_CTRL_L3_MAIN_SYSCFG_H */
