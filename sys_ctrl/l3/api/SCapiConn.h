/*
 * sys_ctrl/l3/api/SCapiConn.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapiConn.h
 */

#ifndef SYS_CTRL_L3_API_SCAPICONN_H
#define SYS_CTRL_L3_API_SCAPICONN_H

#include "../../common/IRouter/IRouter2Router.h"   /* needed by the reconstruction */
#include "../../common/main/L1Cfg.h"
#include "../../common/main/L2Cfg.h"
struct _sn1SCConn {
    char host[64];
    char passwd[64];
    unsigned char passwd_retrys;
    unsigned char passwd_prompt;
    unsigned char __stabs_pad1[2];
    IRClient *client;
    IRIdent ir_id;
    int task_id;
    L2Cfg SysCfgFull;
    int SysCfgL1Count;
    L2CfgL1 *SysCfgL1List[1024];
    int SysCfgL2Count;
    L2Cfg *SysCfgL2List[128];
    char *SysCfgQuery;
};
typedef struct _sn1SCConn sn1SCConn;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* SCapiConn.c */
extern sn1SCConn *conn_in_progress;
int sn1SCConnInit(char *cname);
int sn1SCConnInitConn(sn1SCConn *conn, int id, char *host, char *iface, char *sysname, char *ssn, char *passwd);
int sn1SCConnReconnect(sn1SCConn *conn);
int sn1SCConnFindL2(char *host, char *iface, char *sysname, char *ssn);
void sn1SCConnDisconnect(sn1SCConn *conn);
int sn1SCConnSocket(sn1SCConn *conn);
char *sn1SCConnHost(sn1SCConn *conn);
IRClient *sn1SCConnClient(sn1SCConn *conn);
int sn1SCConnReq(sn1SCConn *conn, IRAddress *toaddr, int opcode, int argc, IRArgument *argv, uint32 *id);
int sn1SCConnRsp(sn1SCConn *conn, IRPacket **pkt, uint32 *id, int wait);
int sn1SCConnPkt(sn1SCConn *conn, IRPacket **pkt, sn1SCConn **pktconn, int wait);
int sn1SCConnSendRsp(sn1SCConn *conn, int errcode, IRPacket *reqpkt, int argc, IRArgument *argv);
int sn1SCConnCmd(sn1SCConn *conn, IRAddress *toaddr, int opcode, int argc, IRArgument *argv, IRPacket **rpkt, int wait);
int sn1SCConnCmdParallel(sn1SCConn *conn, IRAddress *toaddr, int ntargets, int opcode, int argc, IRArgument *argv, int share_args, IRPacket **rpkt, int *errlist, int *nerrs, int wait);

#endif /* SYS_CTRL_L3_API_SCAPICONN_H */
