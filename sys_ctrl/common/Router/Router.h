/*
 * sys_ctrl/common/Router/Router.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Router.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_ROUTER_H
#define SYS_CTRL_COMMON_ROUTER_ROUTER_H

#include <stdint.h>

typedef char Hostname[65];
typedef char Procname[17];
typedef char Username[9];
typedef char Fullname[33];
typedef struct {
    Hostname hostname;
    Procname procname;
    Username username;
    Fullname fullname;
    uint32_t ipaddr;
} RouterID;
typedef struct {
    unsigned int count;
    char *bits;
} RouterGroupSet;
typedef struct {
    unsigned int opcode : 16;
    unsigned int clas : 8;
    unsigned int id : 8;
    unsigned int config : 8;
    unsigned int length : 24;
} RouterHeader;
struct _RouterConfig {
    unsigned int rev;
    unsigned int flags;
    unsigned int unused[16];
};
typedef struct _RouterConfig RouterConfig;
struct _RouterCompressStats {
    unsigned int notry_count;
    unsigned int toosmall_count;
    unsigned int nocompress_count;
    unsigned int compress_count;
    unsigned int notry_bytes;
    unsigned int toosmall_bytes;
    unsigned int nocompress_bytes;
    unsigned int nocompress_compressed_bytes;
    unsigned int compress_bytes;
    unsigned int uncompressed_bytes;
};
typedef struct _RouterCompressStats RouterCompressStats;
struct _RouterQEntry {
    void (*response_cb)();
    unsigned char *response_data;
    void (*error_cb)();
    unsigned char *error_data;
    unsigned char priority;
    unsigned char __stabs_pad1[3];
    void *purge_data;
    RouterHeader header;
    RouterHeader *packet;
    struct _RouterQEntry *next;
};
typedef struct _RouterQEntry RouterQEntry;
typedef struct {
    RouterQEntry *head;
    RouterQEntry *tail;
    int total;
    int bytes;
    int total_max;
    int bytes_max;
} RouterQ;
typedef struct {
    unsigned int fre : 1;
    unsigned int clas : 7;
    int size : 24;
    long unsigned int val;
} RouterArgument;
struct _RouterServer {
    int inet_socket;
    int unix_socket;
    long unsigned int inet_id;
    long unsigned int unix_id;
    int port;
    int (*validate_cb)();
    void (*error_cb)();
    char *cpp_hook;
    struct _RouterServer *next;
};
typedef struct _RouterServer RouterServer;
struct _RouterClient {
    int socket;
    uint32_t addr;
    int port;
    int process_id;
    RouterGroupSet groups;
    int use;
    RouterServer *server;
    int timeout;
    int retrys;
    int accepted;
    RouterID id;
    char *cpp_hook;
    int (*connect_cb)();
    int (*request_cb)();
    void (*event_cb)();
    void (*error_cb)();
    long unsigned int input_id;
    long unsigned int output_id;
    long unsigned int timer_id;
    RouterQ in_queue;
    RouterHeader *in_buf;
    char *in_bufptr;
    int in_bytesneeded;
    int in_bufsize;
    short int in_sequence;
    short int in_hostbyteorder;
    int (*in_handler)();
    RouterConfig *in_cfg;
    RouterCompressStats in_stats;
    int in_pkts;
    RouterQ out_queue;
    RouterQEntry *out_buf;
    char *out_bufptr;
    int out_bytesleft;
    int out_sequence;
    char out_stopped;
    char out_highwater;
    short int out_limit;
    RouterConfig *out_cfg;
    RouterCompressStats out_stats;
    int out_pkts;
    int InArgListSize;
    RouterArgument *InArgList;
    int ResponseSent;
    struct _RouterClient *next;
};
typedef struct _RouterClient RouterClient;
typedef void Router_InitFailCB();
typedef void Router_ClientFreeCB();
typedef int Router_ValidateCB();
typedef int Router_SvConnectCB();
typedef int Router_ClConnectCB();
typedef void Router_ErrorCB();
typedef int Router_RequestCB();
typedef void Router_ResponseCB();
typedef void Router_EventCB();

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include <stdio.h>   /* for the prototypes */
#include "RouterInt.h"   /* for the prototypes */
/* Router.c */
extern RouterClientList ClientList;
extern RouterServerList ServerList;
extern int MaxInArgs;
extern int UseUnix;

extern int ProcessID;
extern void (*FatalCB)();
extern void (*ClientFreeCB)();
extern uint32_t IPAddress;
extern RouterConfig RouterLocalConfig;
extern int SocketSendBufsize;
extern int SocketReceiveBufsize;
extern int MonitorHighWaterEntries;
extern int MonitorHighWaterBytes;
extern int MonitorLowWaterEntries;
extern int MonitorLowWaterBytes;
extern int debug;
extern Username UserName;
extern Fullname FullName;
extern RouterCompressStats InputStats;
extern RouterCompressStats OutputStats;
extern void (*MonitorCB)();
extern void *MonitorCBData;
int RouterInit(int max_in_args, int use_unix, char *process_name, int process_id, void (*fatal_cb)());
int RouterSetFreeCB(void (*free_cb)());
int RouterClientsConnected(void);
int RouterConnectionCount(void);
int RouterHostConnected(char *host, int port, int process_id, RouterClient **client);
int RouterAddrConnected(uint32_t addr, int port, int process_id, RouterClient **client);
void RouterInitClient(RouterClient *client, int timeout, int limit, int (*connect_cb)(), int (*request_cb)(), void (*event_cb)(), void (*error_cb)());
int RouterRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, int limit);
int RouterPriRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, int limit, int priority, void *purge_data);
int RouterRelRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, void (*error_cb)(), void *error_data, int limit);
int RouterPriRelRequestOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, void (*response_cb)(), void *response_data, void (*error_cb)(), void *error_data, int limit, int priority, void *purge_data);
void RouterResponseOut(RouterClient *client, int argcount, RouterArgument *arglist);
void RouterPriResponseOut(RouterClient *client, int argcount, RouterArgument *arglist, int priority, void *purge_data);
int RouterEventOut(int opcode, int argcount, RouterArgument *arglist);
int RouterPriEventOut(int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data);
int RouterIDEventOut(int process_id, int opcode, int argcount, RouterArgument *arglist);
int RouterPriIDEventOut(int process_id, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data);
int RouterGroupEventOut(int process_id, int group, int opcode, int argcount, RouterArgument *arglist);
int RouterPriGroupEventOut(int process_id, int group, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data);
void RouterClientEventOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist);
void RouterPriClientEventOut(RouterClient *client, int opcode, int argcount, RouterArgument *arglist, int priority, void *purge_data);
void RouterFlushOutputs(int timeout);
void RouterFlushOutput(RouterClient *client, int timeout);
int RouterDisconnectClients(int timeout);
void RouterDisconnect(RouterClient *client, int timeout);
void RouterShutDownClients(void);
void RouterCloseOnlyClients(void);
void RouterCloseOnlyClient(RouterClient *client);
void RouterPing(RouterClient *client);
int RouterSetBufferSize(int sendbuf, int recvbuf);
int RouterClientSetBufferSize(RouterClient *client, int sendbuf, int recvbuf);
RouterClient *RouterMakeClient(int socket, uint32_t addr, int port, int process_id, int use, RouterServer *server, char *host, int (*in_handler)());
void RouterSetClientID(RouterID *client_id);
void RouterAddClient(RouterClient *client);
void RouterRemoveClient(RouterClient *client, int return_rel_request);
RouterClient *RouterFindClient(RouterClient *client);
void RouterListClients(void (*cb_func)());
void RouterStartInput(RouterClient *client);
RouterFunc RouterInput(RouterClient *client);
int RouterProcessPacket(RouterClient *client);
void RouterDoOutput(RouterClient *client, int opcode, int clas, int argcount, RouterArgument *arglist, void (*response_cb)(), unsigned char *response_data, void (*error_cb)(), unsigned char *error_data, int priority, void *purge_data);
void RouterPurge(RouterClient *client, int (*purge_cb)(), void *purge_data);
int RouterSetOutputMonitor(void (*output_monitor_cb)(), void *cb_data, int high_water_entries, int high_water_bytes, int low_water_entries, int low_water_bytes);
void RouterPack(RouterClient *client, int opcode, int clas, int argcount, RouterArgument *arglist, void (*response_cb)(), unsigned char *response_data, void (*error_cb)(), unsigned char *error_data, int priority, void *purge_data, RouterQEntry **entry);
int RouterUnpack(RouterClient *client, RouterHeader *packet);
char *RouterDumpQStats(char *buf, RouterClient *client);
void RouterResetQStats(RouterClient *client);
void RouterDebugStats(int reset);
void RouterPrintProcessStats(FILE *fd, int reset);
void RouterPrintAllStats(FILE *fd, int reset);
void RouterPrintClientStats(RouterClient *client, FILE *fd, int reset);
void RouterFreeArguments(int argcount, RouterArgument *arglist);
void RouterFreeClient(RouterClient *client, int return_rel_request);
void RouterFreeGroups(RouterClient *client);
void RouterAddTimer(RouterClient *client, RouterFunc (*timer_func)(), int timeout);
void RouterRemoveTimer(RouterClient *client);
void RouterLogError(int msgnbr, char *func_name, int errnbr, RouterClient *client, char *format);
int RouterCheckOutput(RouterClient *client, char *func_name);
void RouterConnectionLost(RouterClient *client);
void RouterConnectionTimeout(RouterClient *client);
void RouterConnectionError(RouterClient *client);
void RouterClientError(RouterClient *client, int msgnbr);
void RouterBadClass(RouterClient *client, char *func_name);
void RouterMemError(void);
int RouterClose(RouterClient *client);
int RouterDoClose(RouterClient *client, int return_rel_request);

#endif /* SYS_CTRL_COMMON_ROUTER_ROUTER_H */
