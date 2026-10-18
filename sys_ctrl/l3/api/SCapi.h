/*
 * sys_ctrl/l3/api/SCapi.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapi.h
 */

#ifndef SYS_CTRL_L3_API_SCAPI_H
#define SYS_CTRL_L3_API_SCAPI_H

#include "../IRouter/IRouterL3.h"
#include "../IRouter/IRouterOS.h"
struct _sn1SC_L2 {
    char raw[200];
    uint32 ip_addr;
    int discover_rev;
    char ssn[20];
    char sysname[32];
    int rack;
    char version[20];
    int ms;
    int group;
};
typedef struct _sn1SC_L2 sn1SC_L2;

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* SCapi.c */
extern int ir_show;
extern int (*IRouterConnect)();
extern void (*IRouterDisconnect)();
extern int (*IRouterRequest)();
extern int (*IRouterResponse)();
extern int (*IRouterEvent)();
extern int (*IRouterGetPacket)();
char *sn1SCUsage(void);
char *SCFmtPkt(int seqnum, int clas, int argc, int err, IRAddress *to, IRAddress *from, char *bptr);
int sn1SCParseCmdline(int *argc, char **argv, int *serial);
void sn1SCSetL2Host(char *host);
char *sn1SCGetL2Host(void);
void sn1SCSetSysName(char *sysname);
char *sn1SCGetSysName(void);
void sn1SCSetSSN(char *ssn);
char *sn1SCGetSSN(void);
void sn1SCUseSCDevice(char *dev);
int sn1SCInitPortAddr(char *cname, char *host, int task, int port, IRAddress addr);
int sn1SCInit(char *cname, char *host, int task);
int sn1SCInitL2App(char *cname, char *host, int task);
int sn1SCReconnect(void);
void sn1SCDisconnect(void);
int sn1SCFindL2(char *host);
int sn1SCSocket(void);
char *sn1SCHost(void);
IRClient *sn1SCClient(void);
int sn1SCCopy(void);
int sn1SCIsQuiet(void);
void sn1SCUseQuiet(void);
int sn1SCReq(IRAddress *toaddr, int opcode, int argc, IRArgument *argv, uint32 *id);
int sn1SCRsp(IRPacket **pkt, uint32 *id, int wait);
int sn1SCEvent(int opcode, int argc, IRArgument *argv);
int sn1SCPkt(IRPacket **pkt, int wait);
int sn1SCSendRsp(int errcode, IRPacket *reqpkt, int argc, IRArgument *argv);
int sn1SCCmd(IRAddress *toaddr, int opcode, int argc, IRArgument *argv, IRPacket **rpkt, int wait);
int sn1SCCmdParallel(IRAddress *toaddr, int ntargets, int opcode, int argc, IRArgument *argv, int share_args, IRPacket **rpkt, int *errlist, int *nerrs, int wait);
int sn1SCTextCmd(IRAddress *toaddr, char *cmd, char **rsp);
char *sn1SCGetPassword(IRClient *client);
int sn1SCSetResponseTimeout(int new_to);

#endif /* SYS_CTRL_L3_API_SCAPI_H */
