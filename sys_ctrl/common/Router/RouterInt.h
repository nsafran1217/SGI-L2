/*
 * sys_ctrl/common/Router/RouterInt.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/RouterInt.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_ROUTERINT_H
#define SYS_CTRL_COMMON_ROUTER_ROUTERINT_H

#include "Router.h"   /* needed by the reconstruction */
#include "Event.h"
#include <time.h>
#include <sys/time.h>
#include <stddef.h>
typedef void RouterFunc;
typedef struct {
    RouterClient *head;
    RouterClient *tail;
    int total;
} RouterClientList;
typedef struct {
    RouterServer *head;
    RouterServer *tail;
    int total;
} RouterServerList;
typedef struct {
    unsigned int use;
    unsigned int group_count;
} RouterClientType;

/*
 * (Added by the reconstruction: the values are SGI's, the names ours.)
 *
 * RouterClient.use describes a connection: its state in the low six bits,
 * which side opened it, what kind it is, and its transport.
 */
#define RU_CONNECTING     0x00001   /* handshake in progress */
#define RU_ACCEPTED       0x00002   /* (server side) handshake done */
#define RU_CONNECTED      0x00004   /* requests and events may be sent */
#define RU_DISCONNECTING  0x00008   /* we asked the other side to disconnect */
#define RU_DISCONNECTED   0x00010   /* the other side asked us to disconnect */
#define RU_STATE          0x0003f
#define RU_CLIENT         0x00040   /* we connected to a server */
#define RU_SERVER         0x00080   /* a client connected to our server */
#define RU_SIDE           0x000c0
#define RU_PERSISTENT     0x00200   /* stays up (RouterMakeConnection) */
#define RU_TRANSACTION    0x00400   /* disconnects once its output is sent */
#define RU_KIND           0x00600
#define RU_INET           0x01000
#define RU_UNIX           0x02000
#define RU_CONFIGURE      0x04000   /* exchanges a RouterConfig after connecting */
#define RU_INORDER        0x08000   /* responses come back in request order */
#define RU_ORDER          0x18000   /* (0x10000 is never set) */

/* RouterHeader.clas: what a packet is */
#define RC_PASSWORD_REQ   0x01      /* server: send a password */
#define RC_PASSWORD       0x02      /* client: the password */
#define RC_ACCEPT         0x04      /* server: accepted, with its RouterID */
#define RC_CLIENT_ID      0x08      /* client: its type, RouterID and groups */
#define RC_REQUEST        0x10
#define RC_DISCONNECT_REQ 0x11
#define RC_DISCONNECT_RSP 0x12
#define RC_CONFIG_INIT    0x14      /* a RouterConfig, answered by RC_CONFIG_REQ */
#define RC_CONFIG_REQ     0x18      /* ... answered by RC_CONFIG_RSP */
#define RC_REL_REQUEST    0x20      /* request whose error callback gets it back if undelivered */
#define RC_CONFIG_RSP     0x21
#define RC_DENIED         0x22      /* server: connection refused */
#define RC_PING           0x24
#define RC_RESPONSE       0x40
#define RC_EVENT          0x80

/* RouterHeader.config */
#define RH_COMPRESSED     0x80      /* the arguments are BuffCompress()ed */

/* RouterConfig.flags */
#define RCF_COMPRESS      0x80000000

/* the input queue's flow control: output stops while this many requests
 * await responses, and resumes below RQ_RESUME */
#define RQ_STOP           250
#define RQ_RESUME         231

/* Router.c: a RouterID on the wire is procname, username and fullname as
 * NUL-terminated strings, then the IP address (4 bytes, network order) */
int RouterPackID(RouterID *id, unsigned char *buf);
void RouterUnpackID(RouterID *id, char *buf, int size);

#endif /* SYS_CTRL_COMMON_ROUTER_ROUTERINT_H */
