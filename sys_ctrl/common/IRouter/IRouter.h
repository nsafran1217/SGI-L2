/*
 * sys_ctrl/common/IRouter/IRouter.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/IRouter/IRouter.h
 */

#ifndef SYS_CTRL_COMMON_IROUTER_IROUTER_H
#define SYS_CTRL_COMMON_IROUTER_IROUTER_H

#include "../sys/sysctl_types.h"
#include "../sys/sysutils.h"
typedef uint32 IRAddress;
typedef enum {
    IR_L1_INVALID = 0,
    IR_L1_TASK_FIRST = 1,
    IR_L1_IROUTER = 1,
    IR_IROUTER = 1,
    IR_L1_SMP = 2,
    IR_L1_CMD = 3,
    IR_L1_ENV = 4,
    IR_L1_BDR = 5,
    IR_L1_REQ = 6,
    IR_L1_B2B = 10,
    IR_L1_B2B_NI = 11,
    IR_L1_B2B_II = 12,
    IR_L1_CFG = 14,
    IR_L1_SCAN = 15,
    IR_L1_FLASH = 16,
    IR_L1_USB = 17,
    IR_L1_LPBK = 18,
    IR_L1_PBAY_FLASH = 19,
    IR_L1_APWR = 20,
    IR_L1_PIPE = 21,
    IR_L1_FRU = 22,
    IR_L1_ROUTE = 23,
    IR_L1_BKDR = 24,
    IR_L1_TASK_LAST = 25,
} IRL1TaskType;
typedef enum {
    IR_L2_INVALID = 0,
    IR_L2_TASK_FIRST = 1,
    IR_L2_IROUTER = 1,
    IR_L2_CONSOLE = 2,
    IR_L2_CMD = 3,
    IR_L2_CFG = 4,
    IR_L2_LPBK = 5,
    IR_L2_DSP = 6,
    IR_L2_MODEM = 7,
    IR_L2_FLASH = 8,
    IR_L2_APWR = 9,
    IR_L2_PART = 10,
    IR_L2_DEMO = 11,
    IR_L2_CMDUSR = 12,
    IR_L2_ROUTE = 13,
    IR_L2_WEBS = 14,
    IR_L2_TASK_LAST = 15,
} IRL2TaskType;
typedef enum {
    IR_OS_INVALID = 0,
    IR_OS_TASK_FIRST = 1,
    IR_OS_IROUTER = 1,
    IR_OS_ACTIVITY = 2,
    IR_OS_ERROR = 3,
    IR_OS_TASK_LAST = 4,
} IROSTaskType;
typedef struct {
    uint8 _clas;
    uint8 _frame;
    uint16 _size;
    uint32 _val;
} IRArgument;
struct _IRFrame {
    struct _IRFrame *_next_frame;
    uint16 _external : 1;
    uint16 _use_count : 15;
    uint16 _byte_order : 2;
    uint16 _qsuspend : 14;
    uint8 **_arg_data;
    uint8 *_client_data;
    uint16 _size;
    uint8 _rev;
    uint8 _err;
    uint8 _seqnum0;
    uint8 _fnum;
    uint8 _clas;
    uint8 _pdata_auth;
    IRAddress _dest;
    IRAddress _src;
    uint8 _argc;
    uint8 _seqnum1;
    uint16 _opcode;
    IRArgument _argv[1];
};
typedef struct _IRFrame IRFrame;
typedef IRFrame IRPacket;
typedef void IRPacketProcessFunction();
typedef struct {
    IRAddress addr;
    uint8 authority;
    unsigned char __stabs_pad1[1];
    uint16 seqnum;
} IRIdent;
typedef enum {
    IRERR_NONE = 0,
    IRERR_BAD_PKT_TYPE = 1,
    IRERR_BAD_TASK_ID = 2,
    IRERR_DUPLICATE_TARGET_ID = 3,
    IRERR_MALLOC_FAILED = 4,
    IRERR_TASK_ID_ALLOCATED = 5,
    IRERR_BAD_EVENT_ENTRY = 6,
    IRERR_BAD_ARGLIST_ARGCOUNT = 7,
    IRERR_NO_RECEIVER = 8,
    IRERR_NO_DEVICE = 9,
    IRERR_SEND_TO_QUEUE_ERROR = 10,
    IRERR_QUEUE_FULL = 11,
    IRERR_READ_FAILED_RDERR = 12,
    IRERR_READ_FAILED_NOTFF = 13,
    IRERR_READ_FAILED_UNEXF = 14,
    IRERR_READ_FAILED_SELFAIL = 15,
    IRERR_READ_FAILED_TIMEOUT = 16,
    IRERR_WRITE_FAILED = 17,
    IRERR_SEQ_ID_MISMATCH = 18,
    IRERR_RESPONSE_WAIT = 19,
    IRERR_TIMEOUT = 20,
    IRERR_READ_FAILED_EOF = 21,
    IRERR_WRITE_FAILED_EOF = 22,
    IRERR_FRAME_INCOMPLETE = 23,
    IRERR_FRAME_OVERFLOW = 24,
    IRERR_FRAME_UNDERFLOW = 25,
    IRERR_FRAME_CONTROL = 26,
    IRERR_PKT_TOO_LARGE = 27,
} IRErrorCodes;
#include "../sys/Logger.h"

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include "IRouterInt.h"   /* for the prototypes */
/* IRouter.c */
extern int IR_PORT_BIAS;
extern int IRByteOrder;
extern int IRouterDebugMallocFree;
extern int IRouterDebugFrameErrors;
extern int IRouterPackets;
extern int IRouterTotalPackets;
extern int IRouterOutstandingPackets;
extern int IRouterMaxPackets;
extern IRPacket *IRouterTracePacket;
extern IRLocalClient IRouterLocalRequest[15];
extern IRRemoteClient *IRouterRequestList;
extern IRLocalClient IRouterRequestDefault;
extern IREventClient *IRouterEventList;
extern IRAddress IRouterLocalAddress;
extern IRIdent IRouterInternalID;
int IRouterInit(uint32 ip);
int IRouterInitID(IRIdent *id, uint32 task, int authority);
int IRouterSetAuthority(IRIdent *id, int authority);
int IRouterFreePacket(IRPacket *pkt);
void IRouterSetQueueSuspendTime(int req_rsp_time, int evt_time);
void IRouterGetQueueSuspendTime(int *req_rsp_time, int *evt_time);
IRPacket *IRouterMakePacket(IRIdent *id, IRAddress *toaddr, int pdata, int opcode, int clas, int prev, int argcount, IRArgument *arglist);
int IRouterReadPacket(IRIdent *id, int (*rfcn)(), void *fd, IRPacket **pkt);
int IRouterWritePacket(IRIdent *id, int (*wfcn)(), void *fd, IRPacket *pkt);
int IRouterWritePacketReliable(IRIdent *id, int (*wfcn)(), void *fd, IRPacket *pkt, int foe);
void IRouterSetFrameByteOrder(IRFrame *frame, int byteorder);
unsigned int IRArg(IRPacket *pkt, int arg);
char *IRFmtClas(int clas);
char *IRFmtAddr(IRAddress addr, char *bptr);
char *IRFmtPkt(char *who, IRPacket *p, char *bptr);
void IRPrintFrame(char *who, IRFrame *f);
char *IRFmtError(int errcode);

#endif /* SYS_CTRL_COMMON_IROUTER_IROUTER_H */
