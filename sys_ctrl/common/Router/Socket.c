/*
 * sys_ctrl/common/Router/Socket.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Socket.c
 *
 * TCP and local (AF_UNIX) stream sockets for the Router, and host name and
 * address helpers. Local sockets are named after a port number:
 * <SGI_L3_SOCKET_DIR>/UNIX_<port in hex>. Errors are logged through Logger
 * (SocketMsg.h numbers) and returned as -1.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "Socket.h"
#include "SocketMsg.h"
#include "../sys/l3paths.h"

static int SocketUnixLoad(struct sockaddr_un *addr_unix, int port);

/* listen on TCP port; returns the listening socket */
int SocketExportInetConnection(int port)
{
  struct sockaddr_in addr_inet;
  int opt = 1;
  int sock;

  sock = socket(AF_INET,SOCK_STREAM,0);
  if (sock < 0) {
    LogError(SOCKET_ERR_EXPORT_INET,"socket",errno,"");
    return -1;
  }
  if (setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt)) < 0) {
    LogError(SOCKET_ERR_EXPORT_INET,"setsockopt",errno,"SO_REUSEADDR");
    close(sock);
    return -1;
  }
  memset(&addr_inet,0,sizeof(addr_inet));
  addr_inet.sin_family = AF_INET;
  addr_inet.sin_port = htons(port);
  addr_inet.sin_addr.s_addr = INADDR_ANY;
  if (bind(sock,(struct sockaddr *)&addr_inet,sizeof(addr_inet)) < 0) {
    LogErrorHost(SOCKET_ERR_EXPORT_INET,"bind",errno,"",port,"");
    close(sock);
    return -1;
  }
  if (listen(sock,5) < 0) {
    LogError(SOCKET_ERR_EXPORT_INET,"listen",errno,"");
    close(sock);
    return -1;
  }
  return sock;
}

/* listen on the local socket for port (replacing a stale one) */
int SocketExportUnixConnection(int port)
{
  struct sockaddr_un addr_unix;
  int length;
  int sock;

  sock = socket(AF_UNIX,SOCK_STREAM,0);
  if (sock < 0) {
    LogError(SOCKET_ERR_EXPORT_UNIX,"socket",errno,"");
    return -1;
  }
  length = SocketUnixLoad(&addr_unix,port);
  unlink(addr_unix.sun_path);
  if (bind(sock,(struct sockaddr *)&addr_unix,length) < 0) {
    LogError(SOCKET_ERR_EXPORT_UNIX,"bind",errno,"%s",addr_unix.sun_path);
    close(sock);
    return -1;
  }
  if (listen(sock,5) < 0) {
    LogError(SOCKET_ERR_EXPORT_UNIX,"listen",errno,"");
    close(sock);
    return -1;
  }
  return sock;
}

/* accept a connection, non-blocking with no_delay */
static int accept_connection(int sock, int no_delay, int err, struct sockaddr *addr, socklen_t addr_len)
{
  int conn_sock;

  conn_sock = accept(sock,addr,&addr_len);
  if (conn_sock < 0) {
    LogError(err,"accept",errno,"");
    return -1;
  }
  if (no_delay && fcntl(conn_sock,F_SETFL,O_NDELAY) != 0) {
    LogError(err,"fcntl",errno,"O_NDELAY");
    close(conn_sock);
    return -1;
  }
  return conn_sock;
}

int SocketAcceptInetConnection(int sock, int no_delay)
{
  struct sockaddr_in addr_inet;

  return accept_connection(sock,no_delay,SOCKET_ERR_ACCEPT_INET,(struct sockaddr *)&addr_inet,
                           sizeof(addr_inet));
}

int SocketAcceptUnixConnection(int sock, int no_delay)
{
  struct sockaddr_un addr_unix;

  return accept_connection(sock,no_delay,SOCKET_ERR_ACCEPT_UNIX,(struct sockaddr *)&addr_unix,
                           sizeof(addr_unix));
}

/* make sock non-blocking if no_delay; closes it on failure */
int SocketNodelayMode(int sock, int no_delay)
{
  if (no_delay && fcntl(sock,F_SETFL,O_NDELAY) != 0) {
    LogError(SOCKET_ERR_CONNECT_INET,"fcntl",errno,"O_NDELAY");
    close(sock);
    return -1;
  }
  return 0;
}

/*
 * connect(), and what the result means to the Router: the socket (connected, or
 * still connecting when non-blocking); -2, socket closed, when nobody is there
 * (refused, timed out, or the not_there errno); -1 for any other error, socket
 * still open for the caller to log and close.
 */
static int finish_connect(int sock, struct sockaddr *addr, socklen_t length, int not_there)
{
  if (connect(sock,addr,length) == 0)
    return sock;
  if (errno == ECONNREFUSED || errno == ETIMEDOUT || errno == not_there) {
    close(sock);
    return -2;
  }
  if (errno == EINPROGRESS)
    return sock;
  return -1;
}

/* connect to host:port; returns the socket, -2 if nobody answers, or -1 */
int SocketMakeInetConnection(char *host, int port, int no_delay)
{
  struct sockaddr_in addr_inet;
  uint32_t addr;
  int sock, rval;

  if (SocketGetAddr(host,&addr) != 0) {
    LogErrorHost(SOCKET_ERR_HOST_ADDR,"",0,host,0,"");
    return -1;
  }
  sock = socket(AF_INET,SOCK_STREAM,0);
  if (sock < 0) {
    LogError(SOCKET_ERR_CONNECT_INET,"socket",errno,"");
    return -1;
  }
  if (SocketNodelayMode(sock,no_delay) != 0)
    return -1;
  addr_inet.sin_family = AF_INET;
  addr_inet.sin_port = htons(port);
  addr_inet.sin_addr.s_addr = addr;
  rval = finish_connect(sock,(struct sockaddr *)&addr_inet,sizeof(addr_inet),ENETUNREACH);
  if (rval == -1) {
    LogErrorHost(SOCKET_ERR_CONNECT_INET,"connect",errno,host,port,"");
    close(sock);
  }
  return rval;
}

/* connect to the local socket for port; returns the socket, -2 if no server, or -1 */
int SocketMakeUnixConnection(int port, int no_delay)
{
  struct sockaddr_un addr_unix;
  int sock, length, rval;

  sock = socket(AF_UNIX,SOCK_STREAM,0);
  if (sock < 0) {
    LogError(SOCKET_ERR_CONNECT_UNIX,"socket",errno,"");
    return -1;
  }
  if (no_delay && fcntl(sock,F_SETFL,O_NDELAY) != 0) {
    LogError(SOCKET_ERR_CONNECT_UNIX,"fcntl",errno,"O_NDELAY");
    close(sock);
    return -1;
  }
  length = SocketUnixLoad(&addr_unix,port);
  rval = finish_connect(sock,(struct sockaddr *)&addr_unix,length,ENOENT);
  if (rval == -1) {
    LogError(SOCKET_ERR_CONNECT_UNIX,"connect",errno,"%s",addr_unix.sun_path);
    close(sock);
  }
  return rval;
}

/* set one socket buffer size and check the kernel granted it (Linux doubles
 * the value; anything from size to twice size is accepted) */
static int set_buffer(int sock, int option, int size, const char *what, const char *func)
{
  int old_size, new_size;
  socklen_t optlen;

  /* ORIGINAL BUG: the "was" size comes from SO_RCVBUF for both buffers */
  optlen = sizeof(old_size);
  getsockopt(sock,SOL_SOCKET,SO_RCVBUF,&old_size,&optlen);
  if (setsockopt(sock,SOL_SOCKET,option,&size,sizeof(size)) < 0) {
    LogError(SOCKET_ERR_BUFFER_SIZE,(char *)func,errno,"");
    return SOCKET_ERR_BUFFER_SIZE;
  }
  optlen = sizeof(new_size);
  getsockopt(sock,SOL_SOCKET,option,&new_size,&optlen);
  if (new_size < size || new_size > size * 2) {
    fprintf(stderr,"ERROR! %s size failed (was %d, asked %d, got %d)\n",what,old_size,size,new_size);
    LogError(SOCKET_ERR_BUFFER_SIZE,(char *)func,errno,"");
    return SOCKET_ERR_BUFFER_SIZE;
  }
  return 0;
}

/* set the buffer sizes (0: leave alone); either one also turns on TCP_NODELAY
 * and low-delay TOS. Returns 0 or SOCKET_ERR_BUFFER_SIZE. */
int SocketSetBufferSize(int sock, int sendbuf, int recvbuf)
{
  int flag;

  if (sendbuf != 0 && set_buffer(sock,SO_SNDBUF,sendbuf,"SO_SNDBUF","socket (snd)") != 0)
    return SOCKET_ERR_BUFFER_SIZE;
  if (recvbuf != 0 && set_buffer(sock,SO_RCVBUF,recvbuf,"SO_RCVBUF","socket (rcv)") != 0)
    return SOCKET_ERR_BUFFER_SIZE;
  if (sendbuf != 0 || recvbuf != 0) {
    /* (not supported on local sockets: EOPNOTSUPP is fine) */
    flag = 1;
    if (setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,&flag,sizeof(flag)) < 0 && errno != EOPNOTSUPP) {
      LogError(SOCKET_ERR_BUFFER_SIZE,"socket (TCP_NODELAY)",errno,"");
      return SOCKET_ERR_BUFFER_SIZE;
    }
    flag = IPTOS_LOWDELAY;
    if (setsockopt(sock,IPPROTO_IP,IP_TOS,&flag,sizeof(flag)) < 0 && errno != EOPNOTSUPP) {
      LogError(SOCKET_ERR_BUFFER_SIZE,"socket (IP_TOS)",errno,"");
      return SOCKET_ERR_BUFFER_SIZE;
    }
  }
  return 0;
}

int SocketClose(int sock)
{
  if (sock < 0)
    return -1;
  shutdown(sock,SHUT_RDWR);
  return close(sock);
}

int SocketCloseOnly(int sock)
{
  if (sock < 0)
    return -1;
  return close(sock);
}

int SocketCloseUnixServer(int sock, int port)
{
  struct sockaddr_un addr_unix;

  SocketUnixLoad(&addr_unix,port);
  unlink(addr_unix.sun_path);
  return close(sock);
}

/* host name or dotted address -> IPv4 address (network order) */
int SocketGetAddr(char *host, uint32_t *addr)
{
  struct hostent *hp;

  if (host == NULL || host[0] == '\0')
    return -1;
  *addr = inet_addr(host);
  if (*addr != INADDR_NONE)
    return 0;
  hp = gethostbyname(host);
  if (hp == NULL)
    return -1;
  memcpy(addr,hp->h_addr_list[0],4);
  return 0;
}

int SocketGetPeerAddr(int sock, uint32_t *addr)
{
  struct sockaddr_in addr_inet;
  socklen_t addr_len = sizeof(addr_inet);

  if (getpeername(sock,(struct sockaddr *)&addr_inet,&addr_len) < 0) {
    LogError(SOCKET_ERR_PEER_HOST,"getpeername",errno,"");
    return -1;
  }
  *addr = addr_inet.sin_addr.s_addr;
  return 0;
}

int SocketGetSockAddr(int sock, uint32_t *addr)
{
  struct sockaddr_in addr_inet;
  socklen_t addr_len = sizeof(addr_inet);

  if (getsockname(sock,(struct sockaddr *)&addr_inet,&addr_len) < 0) {
    LogError(SOCKET_ERR_LOCAL_HOST,"getsockname",errno,"");
    return -1;
  }
  *addr = addr_inet.sin_addr.s_addr;
  return 0;
}

/* IPv4 address -> host name (name_length bytes, always terminated) */
int SocketGetName(uint32_t addr, char *name, int name_length)
{
  struct in_addr address;
  struct hostent *hp;

  address.s_addr = addr;
  memset(name,0,name_length);
  hp = gethostbyaddr(&address,4,AF_INET);
  if (hp == NULL)
    return -1;
  strncpy(name,hp->h_name,name_length - 1);
  return 0;
}

int SocketIsLocalHost(char *host)
{
  char *host_name;
  int logger_value;
  int rvalue = 0;

  logger_value = LoggerDisable();
  if (SocketGetHostName(&host_name) == 0 && strcmp(host,host_name) == 0)
    rvalue = 1;
  LoggerRestore(logger_value);
  return rvalue;
}

/* this host's name, in a static buffer */
int SocketGetHostName(char **host_name)
{
  static char name[66];

  memset(name,0,sizeof(name));
  *host_name = name;
  if (gethostname(name,sizeof(name) - 1) != 0) {
    LogError(SOCKET_ERR_LOCAL_HOST,"gethostname",errno,"");
    return -1;
  }
  return 0;
}

/* this host's address (looked up again only when the host name changes) */
int SocketGetHostAddr(uint32_t *addr)
{
  static char localhost[66];
  static uint32_t localaddr;
  char *host_name;

  if (SocketGetHostName(&host_name) != 0)
    return -1;
  if (strncmp(host_name,localhost,sizeof(localhost) - 1) != 0) {
    strcpy(localhost,host_name);
    if (SocketGetAddr(localhost,&localaddr) != 0) {
      LogErrorHost(SOCKET_ERR_HOST_ADDR,"",0,localhost,0,"");
      return -1;
    }
  }
  *addr = localaddr;
  return 0;
}

/* dotted address, in inet_ntoa()'s static buffer */
char *SocketAddrStr(uint32_t addr)
{
  struct in_addr inaddr;

  inaddr.s_addr = addr;
  return inet_ntoa(inaddr);
}

/* the local socket address for port; returns its length */
static int SocketUnixLoad(struct sockaddr_un *addr_unix, int port)
{
  memset(addr_unix,0,sizeof(*addr_unix));
  addr_unix->sun_family = AF_UNIX;
  /* original: "/usr/tmp/UNIX_%04x" (SGI_L3_SOCKET_DIR overrides) */
  snprintf(addr_unix->sun_path,sizeof(addr_unix->sun_path),"%s/UNIX_%04x",l3path_socket_dir(),port);
  return strlen(addr_unix->sun_path) + 2;
}
