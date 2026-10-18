/*
 * sys_ctrl/common/main/L2Cfg.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/main/L2Cfg.h
 */

#ifndef SYS_CTRL_COMMON_MAIN_L2CFG_H
#define SYS_CTRL_COMMON_MAIN_L2CFG_H

#include "../IRouter/IRouter.h"
#include "../Router/Router.h"
#include "L1Cfg.h"
struct _L2CfgL1 {
    uint8 index;
    uint8 configured;
    uint8 revision;
    uint8 rack;
    uint8 slot;
    uint8 type;
    uint8 partition;
    unsigned char __stabs_pad1[1];
    uint32 console_subchannel;
    uint8 console_enabled;
    uint8 shub_addrmode;
    uint8 shub_shrmode;
    uint8 router_type;
    uint8 power_state;
    uint8 margin_state;
    uint8 conn_state;
    unsigned char __stabs_pad2[1];
    uint32 env_state;
    char brick_sn[12];
    char system_sn[12];
};
typedef struct _L2CfgL1 L2CfgL1;
struct _L2CfgPort {
    int state;
    int type;
    int fd;
    char *device;
    char *usbpath;
    int l1count;
    L2CfgL1 *l1cfg;
};
typedef struct _L2CfgPort L2CfgPort;
typedef struct {
    IRAddress detected;
} L2CfgSysCon;
typedef unsigned char L2CfgPSelect[256];
struct _L2CfgNode {
    uint32 ip_addr;
    IRAddress ir_addr;
    RouterClient *client;
    unsigned int events;
    unsigned int msmode;
    unsigned int msip;
    struct _L2CfgNode *msnode;
    L2CfgPSelect pselect;
    unsigned int os;
    unsigned int heartbeat;
    struct _L2CfgNode *next;
};
typedef struct _L2CfgNode L2CfgNode;
typedef L2CfgNode L2CfgL3Client;
typedef L2CfgNode L2CfgL2Client;
typedef L2CfgNode L2CfgL2Peer;
struct _L2Cfg {
    L2CfgNode net;
    int rack;
    char ssn[20];
    char sysname[20];
    unsigned int l2dsp_disabled : 1;
    unsigned int unused1 : 31;
    int port_count;
    L2CfgPort port_list[40];
    L2CfgL3Client *l3_clients;
    L2CfgL2Client *l2_clients;
    L2CfgSysCon *syscon;
};
typedef struct _L2Cfg L2Cfg;
/* (added by the reconstruction) lists of L2Cfg are walked through their first
 * member, net (an L2CfgNode); the decompiler showed the L2Cfg fields beyond it
 * as node[1].<field> at i386 offsets */
#define L2CFG_OF(node) ((L2Cfg *)(node))

/* prototypes (not recorded in STABS; reconstructed from definitions) */
/* L2Cfg.c */
extern int L2CfgDebug;
extern int L2CfgDebugX;
extern int L2CfgMode;
extern L2Cfg L2CfgLocal;
int L2CfgInitLocal(uint32 ip_addr, RouterClient *client);
int L2CfgMInitL3(L2Cfg *head, RouterClient *client);
int L2CfgMAddL2(L2Cfg *head, uint32 ip_addr, uint32 port, RouterClient *client, L2CfgNode **node);
int L2CfgMAddL3(L2Cfg *head, uint32 ip_addr, RouterClient *client);
int L2CfgMDeleteNode(L2Cfg *head, RouterClient *client);
L2CfgNode *L2CfgInitNode(L2CfgNode *node, int l2, uint32 ip_addr, IRAddress ir_addr, RouterClient *client);
L2CfgNode *L2CfgMFindL2Node(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client);
L2CfgNode *L2CfgMFindL3Node(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client);
L2CfgNode *L2CfgMFindNodeLocal(L2Cfg *head, uint32 ip_addr);
L2CfgNode *L2CfgMFindNode(L2Cfg *head, uint32 ip_addr, IRAddress ir_addr, RouterClient *client);
char *L2CfgMFindDevice(L2Cfg *head, int fd);
L2CfgPort *L2CfgMFindPort(L2Cfg *head, int fd);
L2CfgPort *L2CfgMGetPort(L2Cfg *head, int port);
char *L2CfgMDeviceName(L2Cfg *head, int fd);
int L2CfgMDeleteL2Peer(L2Cfg *head, L2CfgNode *peer);
int L2CfgDeleteL2Client(L2CfgNode **list, L2CfgNode *client);
void L2CfgMEventRack(L2Cfg *head);
void L2CfgMEventSystemSN(L2Cfg *head);
void L2CfgMEventSystemName(L2Cfg *head);
void L2CfgMEventDisplayDisable(L2Cfg *head);
void FmtBrick(char *bptr, int rack, int type, int slot);
void L2CfgMPrint(L2Cfg *head, char **rrptr, int mode, int show_l1);
void L2CfgMPrintX(L2Cfg *head, char **rrptr);
void L2CfgMPrintY(L2Cfg *head, char **rrptr);
int L2CfgMAddPort(L2Cfg *head, int port, char *device, char *usbpath, int conn_type, int conn_fd);
int L2CfgMDeletePort(L2Cfg *head, int conn_fd);
void L2CfgMCfgL2_rev1(L2Cfg *head, IRPacket *pkt);
void L2CfgMCfgL2(L2Cfg *head, IRPacket *p);
int L2CfgMCfgPort(L2Cfg *head, int port, IRPacket *p);
int L2CfgMFindBrickRS(L2Cfg *head, int ip, int port, int index, int *rack, int *slot);
int L2CfgMFindBrickIP(L2Cfg *head, int rack, int slot, int *ip, int *p, int *l);
L2CfgNode *L2CfgMFindBrickL2(L2Cfg *head, int rack, int slot);
L2CfgL1 *L2CfgMFindBrickCfg(L2Cfg *head, int rack, int slot, int local);
int L2CfgMFindBrickType(L2Cfg *head, int rack, int slot);
char *L2CfgMQuery(L2Cfg *head, int mode, int format);
char *L2CfgMAddrStr(L2Cfg *head, IRAddress addr, int verbose);
IRAddress L2CfgMGetConsole(L2Cfg *head, int partition);
int L2CfgMCount(L2Cfg *head);
int L2CfgMAdviseConsole(L2Cfg *head, char *rptr, int partition, IRAddress addr);

#endif /* SYS_CTRL_COMMON_MAIN_L2CFG_H */
