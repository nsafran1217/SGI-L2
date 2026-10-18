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

/* (Added by the reconstruction.) IRouter functions return 0 or -600 - an
 * IRErrorCodes value (Logger's IRouterErrorList). */
#define IR_ERRNO(e)  (-600 - (e))

/* IRFrame._clas */
enum { IR_REQ = 0, IR_RSP = 1, IR_EVT = 2 };

/*
 * (Added by the reconstruction.) An IRAddress, as IRFmtAddr reads it. With
 * the top bit clear: type (4 bits; IR_ADDR_L1 ...), rack (10), slot (6),
 * number (7) and task (5). With it set: an IP-routed address, type 0xe when
 * the next bit is clear (else 0xf), task in bits 24-29 and the low 24 bits
 * of the IP address.
 */
enum {
    IR_ADDR_L1 = 0, IR_ADDR_L2 = 1, IR_ADDR_L3 = 2, IR_ADDR_C = 3, IR_ADDR_I = 4,
    IR_ADDR_CI = 5, IR_ADDR_CC = 6, IR_ADDR_IP = 0xe, IR_ADDR_IP_OTHER = 0xf,
};
#define IR_ADDR_IS_IP(a)   (((a) & 0x80000000) != 0)
#define IR_ADDR_TYPE(a)    (!IR_ADDR_IS_IP(a) ? (int)((a) >> 28) : ((a) >> 30) == 2 ? IR_ADDR_IP : IR_ADDR_IP_OTHER)
#define IR_ADDR_TASK(a)    (!IR_ADDR_IS_IP(a) ? (int)((a) & 0x1f) : (int)(((a) >> 24) & 0x3f))
#define IR_ADDR_NUM(a)     (!IR_ADDR_IS_IP(a) ? (int)(((a) >> 5) & 0x7f) : -1)
#define IR_ADDR_RACK(a)    ((int)(((a) >> 18) & 0x3ff))
#define IR_ADDR_SLOT(a)    ((int)(((a) >> 12) & 0x3f))

/* IRFrame._fnum: the first frame has the top bit set; the frames are
 * numbered down to 1. A frame is at most 1024 bytes (extended frames, for
 * big responses between L2s/L3s, up to 0x3400), the header 20. */
#define IR_FNUM_FIRST      0x80
#define IR_FRAME_HDR       20
#define IR_FRAME_MAX       0x400
#include "../sys/Logger.h"

/* (added by the reconstruction) a frame's 16-bit sequence number */
#define IR_SEQNUM(f)  ((uint16)((f)->_seqnum1 << 8 | (f)->_seqnum0))

/* --- added by the reconstruction: architecture-independent frame access --- */
#include <stddef.h>
#include <stdint.h>

/* A frame in memory is a few host-only fields followed by the wire frame,
 * which starts at _size: a 20-byte header, 8-byte arguments, then data. */
#define IR_FRAME_PREFIX   offsetof(IRFrame, _size)      /* 16 on i386 */
#define IR_FRAME_WIRE(f)  ((uint8 *)&(f)->_size)

/* A data argument's _val is its frame offset as the original i386 code laid
 * frames out in memory: wire offset + 16. Keep that wire convention. */
#define IR_DATA_OFFSET(f, p) ((uint32)((uint8 *)(p) - IR_FRAME_WIRE(f)) + 0x10)
#define IR_DATA_PTR(f, v)    (IR_FRAME_WIRE(f) + ((v) - 0x10))

/* Pointers stored in an IRArgument's 32-bit _val: the source of a data
 * argument until IRouterMakePacket copies it into the frame (never on the
 * wire). On 32-bit hosts the pointer itself, as in the original; on 64-bit
 * hosts a handle into a ring of recently stored pointers (IRouter.c). */
#if UINTPTR_MAX == 0xffffffffu
#define IR_PTR_VAL(p)  ((uint32)(uintptr_t)(p))
#define IR_VAL_PTR(v)  ((void *)(uintptr_t)(v))
#else
uint32 IRPtrToVal(const void *p);
void *IRValToPtr(uint32 v);
#define IR_PTR_VAL(p)  IRPtrToVal(p)
#define IR_VAL_PTR(v)  IRValToPtr(v)
#endif

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
uintptr_t IRArg(IRPacket *pkt, int arg);   /* original: unsigned int; returns data pointers */
char *IRFmtClas(int clas);
char *IRFmtAddr(IRAddress addr, char *bptr);
char *IRFmtPkt(char *who, IRPacket *p, char *bptr);
void IRPrintFrame(char *who, IRFrame *f);
char *IRFmtError(int errcode);

#endif /* SYS_CTRL_COMMON_IROUTER_IROUTER_H */
