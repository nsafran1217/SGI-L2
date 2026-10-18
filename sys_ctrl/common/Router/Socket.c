/*
 * sys_ctrl/common/Router/Socket.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Socket.c
 */

struct sockaddr_un;

#include <unistd.h>
#include "../../l3/l2/smp.h"   /* needed by the reconstruction */
#include "Socket.h"
#include "SocketMsg.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <limits.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include "../sys/l3paths.h"   /* configurable paths (new) */
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static int SocketUnixLoad(struct sockaddr_un *addr_unix, int port);

int SocketExportInetConnection(int port)
{
  int *piVar1;
  int iVar2;
  char *pcVar3;
  char *format;
  int opt;
  int sock;
  struct sockaddr_in addr_inet;
  
  opt = 1;
  sock = socket(2,1,0);
  if (sock < 0) {
    pcVar3 = "";
    piVar1 = __errno_location();
    LogError(-400,"socket",*piVar1,pcVar3);
    sock = -1;
  }
  else {
    iVar2 = setsockopt(sock,1,2,&opt,4);
    if (iVar2 < 0) {
      pcVar3 = "SO_REUSEADDR";
      piVar1 = __errno_location();
      LogError(-400,"setsockopt",*piVar1,pcVar3);
      close(sock);
      sock = -1;
    }
    else {
      memset(&addr_inet,0,0x10);
      addr_inet.sin_family = 2;
      addr_inet.sin_port = htons((uint16_t)port);
      addr_inet.sin_addr.s_addr = 0;
      iVar2 = bind(sock,(struct sockaddr *)&addr_inet,0x10);
      if (iVar2 < 0) {
        format = "";
        pcVar3 = "";
        piVar1 = __errno_location();
        LogErrorHost(-400,"bind",*piVar1,pcVar3,port,format);
        close(sock);
        sock = -1;
      }
      else {
        iVar2 = listen(sock,5);
        if (iVar2 < 0) {
          pcVar3 = "";
          piVar1 = __errno_location();
          LogError(-400,"listen",*piVar1,pcVar3);
          close(sock);
          sock = -1;
        }
      }
    }
  }
  return sock;
}

int SocketExportUnixConnection(int port)
{
  int sock;
  int *piVar1;
  int length;
  int iVar2;
  char *pcVar3;
  struct sockaddr_un addr_unix;
  
  sock = socket(1,1,0);
  if (sock < 0) {
    pcVar3 = "";
    piVar1 = __errno_location();
    LogError(-0x191,"socket",*piVar1,pcVar3);
    sock = -1;
  }
  else {
    length = SocketUnixLoad(&addr_unix,port);
    unlink(addr_unix.sun_path);
    iVar2 = bind(sock,(struct sockaddr *)&addr_unix,length);
    if (iVar2 < 0) {
      pcVar3 = "%s";
      piVar1 = __errno_location();
      LogError(-0x191,"bind",*piVar1,pcVar3);
      close(sock);
      sock = -1;
    }
    else {
      iVar2 = listen(sock,5);
      if (iVar2 < 0) {
        pcVar3 = "";
        piVar1 = __errno_location();
        LogError(-0x191,"listen",*piVar1,pcVar3);
        close(sock);
        sock = -1;
      }
    }
  }
  return sock;
}

int SocketAcceptInetConnection(int sock, int no_delay)
{
  int conn_sock;
  int *piVar1;
  int iVar2;
  char *pcVar3;
  int addr_len;
  struct sockaddr_in addr_inet;
  
  addr_len = 0x10;
  conn_sock = accept(sock,(struct sockaddr *)&addr_inet,(socklen_t *)&addr_len);
  if (conn_sock < 0) {
    pcVar3 = "";
    piVar1 = __errno_location();
    LogError(-0x192,"accept",*piVar1,pcVar3);
    conn_sock = -1;
  }
  else if ((no_delay != 0) && (iVar2 = fcntl(conn_sock,4,0x800), iVar2 != 0)) {
    pcVar3 = "O_NDELAY";
    piVar1 = __errno_location();
    LogError(-0x192,"fcntl",*piVar1,pcVar3);
    close(conn_sock);
    conn_sock = -1;
  }
  return conn_sock;
}

int SocketAcceptUnixConnection(int sock, int no_delay)
{
  int conn_sock;
  int *piVar1;
  int iVar2;
  char *pcVar3;
  int addr_len;
  struct sockaddr_un addr_unix;
  
  addr_len = 0x6e;
  conn_sock = accept(sock,(struct sockaddr *)&addr_unix,(socklen_t *)&addr_len);
  if (conn_sock < 0) {
    pcVar3 = "";
    piVar1 = __errno_location();
    LogError(-0x193,"accept",*piVar1,pcVar3);
    conn_sock = -1;
  }
  else if ((no_delay != 0) && (iVar2 = fcntl(conn_sock,4,0x800), iVar2 != 0)) {
    pcVar3 = "O_NDELAY";
    piVar1 = __errno_location();
    LogError(-0x193,"fcntl",*piVar1,pcVar3);
    close(conn_sock);
    conn_sock = -1;
  }
  return conn_sock;
}

int SocketNodelayMode(int sock, int no_delay)
{
  int iVar1;
  int *piVar2;
  char *format;
  
  if ((no_delay != 0) && (iVar1 = fcntl(sock,4,0x800), iVar1 != 0)) {
    format = "O_NDELAY";
    piVar2 = __errno_location();
    LogError(-0x194,"fcntl",*piVar2,format);
    close(sock);
    return -1;
  }
  return 0;
}

int SocketMakeInetConnection(char *host, int port, int no_delay)
{
  int status;
  int sock;
  int *piVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  ulong addr;
  struct sockaddr_in addr_inet;
  
  status = SocketGetAddr(host,&addr);
  if (status == 0) {
    sock = socket(2,1,0);
    if (sock < 0) {
      pcVar4 = "";
      piVar1 = __errno_location();
      LogError(-0x194,"socket",*piVar1,pcVar4);
      iVar2 = -1;
    }
    else {
      iVar2 = SocketNodelayMode(sock,no_delay);
      if (iVar2 == 0) {
        addr_inet.sin_family = 2;
        addr_inet.sin_port = htons((uint16_t)port);
        addr_inet.sin_addr.s_addr = addr;
        iVar3 = connect(sock,(struct sockaddr *)&addr_inet,0x10);
        iVar2 = sock;
        if (iVar3 != 0) {
          piVar1 = __errno_location();
          iVar2 = *piVar1;
          if (iVar2 < 0x70) {
            if ((0x6d < iVar2) || (iVar2 == 0x65)) {
              close(sock);
              return -2;
            }
          }
          else if (iVar2 == 0x73) {
            return sock;
          }
          pcVar4 = "";
          piVar1 = __errno_location();
          LogErrorHost(-0x194,"connect",*piVar1,host,port,pcVar4);
          close(sock);
          iVar2 = -1;
        }
      }
    }
  }
  else {
    LogErrorHost(-0x196,"",0,host,0,"");
    iVar2 = -1;
  }
  return iVar2;
}

int SocketMakeUnixConnection(int port, int no_delay)
{
  int sock;
  int *piVar1;
  int iVar2;
  int length;
  char *pcVar3;
  struct sockaddr_un addr_unix;
  
  sock = socket(1,1,0);
  if (sock < 0) {
    pcVar3 = "";
    piVar1 = __errno_location();
    LogError(-0x195,"socket",*piVar1,pcVar3);
    sock = -1;
  }
  else if ((no_delay == 0) || (iVar2 = fcntl(sock,4,0x800), iVar2 == 0)) {
    length = SocketUnixLoad(&addr_unix,port);
    iVar2 = connect(sock,(struct sockaddr *)&addr_unix,length);
    if (iVar2 != 0) {
      piVar1 = __errno_location();
      iVar2 = *piVar1;
      if (iVar2 < 0x70) {
        if ((0x6d < iVar2) || (iVar2 == 2)) {
          close(sock);
          return -2;
        }
      }
      else if (iVar2 == 0x73) {
        return sock;
      }
      pcVar3 = "%s";
      piVar1 = __errno_location();
      LogError(-0x195,"connect",*piVar1,pcVar3);
      close(sock);
      sock = -1;
    }
  }
  else {
    pcVar3 = "O_NDELAY";
    piVar1 = __errno_location();
    LogError(-0x195,"fcntl",*piVar1,pcVar3);
    close(sock);
    sock = -1;
  }
  return sock;
}

int SocketSetBufferSize(int sock, int sendbuf, int recvbuf)
{
  int *piVar1;
  char *pcVar2;
  int flag;
  int old_recvbuf;
  int old_sendbuf;
  int size;
  int rval;
  int optlen;
  
  if (sendbuf != 0) {
    optlen = 4;
    getsockopt(sock,1,8,&old_sendbuf,(socklen_t *)&optlen);
    optlen = 4;
    rval = setsockopt(sock,1,7,&sendbuf,4);
    if (rval < 0) {
      pcVar2 = "";
      piVar1 = __errno_location();
      LogError(-0x199,"socket (snd)",*piVar1,pcVar2);
      return -0x199;
    }
    optlen = 4;
    getsockopt(sock,1,7,&size,(socklen_t *)&optlen);
    if ((size < sendbuf) || (sendbuf * 2 < size)) {
      fprintf(stderr,"ERROR! SO_SNDBUF size failed (was %d, asked %d, got %d)\n",old_sendbuf,sendbuf
              ,size);
      pcVar2 = "";
      piVar1 = __errno_location();
      LogError(-0x199,"socket (snd)",*piVar1,pcVar2);
      return -0x199;
    }
  }
  if (recvbuf != 0) {
    optlen = 4;
    getsockopt(sock,1,8,&old_recvbuf,(socklen_t *)&optlen);
    optlen = 4;
    rval = setsockopt(sock,1,8,&recvbuf,4);
    if (rval < 0) {
      pcVar2 = "";
      piVar1 = __errno_location();
      LogError(-0x199,"socket (rcv)",*piVar1,pcVar2);
      return -0x199;
    }
    optlen = 4;
    getsockopt(sock,1,8,&size,(socklen_t *)&optlen);
    if ((size < recvbuf) || (recvbuf * 2 < size)) {
      fprintf(stderr,"ERROR! SO_RCVBUF size failed (was %d, asked %d, got %d)\n",old_recvbuf,recvbuf
              ,size);
      pcVar2 = "";
      piVar1 = __errno_location();
      LogError(-0x199,"socket (rcv)",*piVar1,pcVar2);
      return -0x199;
    }
  }
  if ((sendbuf != 0) || (recvbuf != 0)) {
    flag = 1;
    optlen = 4;
    rval = setsockopt(sock,6,1,&flag,4);
    if ((rval < 0) && (piVar1 = __errno_location(), *piVar1 != 0x5f)) {
      pcVar2 = "";
      piVar1 = __errno_location();
      LogError(-0x199,"socket (TCP_NODELAY)",*piVar1,pcVar2);
      return -0x199;
    }
    flag = 0x10;
    optlen = 4;
    rval = setsockopt(sock,0,1,&flag,4);
    if ((rval < 0) && (piVar1 = __errno_location(), *piVar1 != 0x5f)) {
      pcVar2 = "";
      piVar1 = __errno_location();
      LogError(-0x199,"socket (IP_TOS)",*piVar1,pcVar2);
      return -0x199;
    }
  }
  return 0;
}

int SocketClose(int sock)
{
  int iVar1;
  
  if (sock < 0) {
    iVar1 = -1;
  }
  else {
    shutdown(sock,2);
    iVar1 = close(sock);
  }
  return iVar1;
}

int SocketCloseOnly(int sock)
{
  int iVar1;
  
  if (sock < 0) {
    iVar1 = -1;
  }
  else {
    iVar1 = close(sock);
  }
  return iVar1;
}

int SocketCloseUnixServer(int sock, int port)
{
  int iVar1;
  struct sockaddr_un addr_unix;
  
  SocketUnixLoad(&addr_unix,port);
  unlink(addr_unix.sun_path);
  iVar1 = close(sock);
  return iVar1;
}

int SocketGetAddr(char *host, long unsigned int *addr)
{
  size_t sVar1;
  int iVar2;
  in_addr_t iVar3;
  struct hostent *hp;
  
  if ((host == NULL) || (sVar1 = strlen(host), sVar1 == 0)) {
    iVar2 = -1;
  }
  else {
    iVar3 = inet_addr(host);
    *addr = iVar3;
    if (iVar3 == 0xffffffff) {
      hp = (struct hostent *)gethostbyname(host);
      if (hp == NULL) {
        iVar2 = -1;
      }
      else {
        memcpy(addr,*hp->h_addr_list,4);
        iVar2 = 0;
      }
    }
    else {
      iVar2 = 0;
    }
  }
  return iVar2;
}

int SocketGetPeerAddr(int sock, long unsigned int *addr)
{
  int iVar1;
  int *piVar2;
  char *format;
  int addr_len;
  struct sockaddr_in addr_inet;
  
  addr_len = 0x10;
  iVar1 = getpeername(sock,(struct sockaddr *)&addr_inet,(socklen_t *)&addr_len);
  if (iVar1 < 0) {
    format = "";
    piVar2 = __errno_location();
    LogError(-0x197,"getpeername",*piVar2,format);
    iVar1 = -1;
  }
  else {
    *addr = addr_inet.sin_addr.s_addr;
    iVar1 = 0;
  }
  return iVar1;
}

int SocketGetSockAddr(int sock, long unsigned int *addr)
{
  int iVar1;
  int *piVar2;
  char *format;
  int addr_len;
  struct sockaddr_in addr_inet;
  
  addr_len = 0x10;
  iVar1 = getsockname(sock,(struct sockaddr *)&addr_inet,(socklen_t *)&addr_len);
  if (iVar1 < 0) {
    format = "";
    piVar2 = __errno_location();
    LogError(-0x198,"getsockname",*piVar2,format);
    iVar1 = -1;
  }
  else {
    *addr = addr_inet.sin_addr.s_addr;
    iVar1 = 0;
  }
  return iVar1;
}

int SocketGetName(long unsigned int addr, char *name, int name_length)
{
  struct hostent *hp;
  int iVar1;
  struct in_addr address;
  
  address.s_addr = addr;
  memset(name,0,name_length);
  hp = (struct hostent *)gethostbyaddr(&address,4,2);
  if (hp == NULL) {
    iVar1 = -1;
  }
  else {
    strncpy(name,hp->h_name,name_length - 1);
    iVar1 = 0;
  }
  return iVar1;
}

int SocketIsLocalHost(char *host)
{
  int iVar1;
  int rvalue;
  char *host_name;
  int logger_value;
  
  rvalue = 0;
  logger_value = LoggerDisable();
  iVar1 = SocketGetHostName(&host_name);
  if (iVar1 == 0) {
    iVar1 = strcmp(host,host_name);
    if (iVar1 == 0) {
      rvalue = 1;
    }
  }
  LoggerRestore(logger_value);
  return rvalue;
}

int SocketGetHostName(char **host_name)
{
  static char name[66];
  int iVar1;
  int *piVar2;
  char *format;
  
  memset((void *)&name,0,0x42);
  *host_name = (char *)&name;
  iVar1 = gethostname((char *)&name,0x41);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    format = "";
    piVar2 = __errno_location();
    LogError(-0x198,"gethostname",*piVar2,format);
    iVar1 = -1;
  }
  return iVar1;
}

int SocketGetHostAddr(long unsigned int *addr)
{
  static char localhost[66];
  static long unsigned int localaddr;
  int iVar1;
  char *host_name;
  
  iVar1 = SocketGetHostName(&host_name);
  if (iVar1 == 0) {
    iVar1 = strncmp(host_name,(char *)&localhost,0x41);
    if (iVar1 != 0) {
      strcpy((char *)&localhost,host_name);
      iVar1 = SocketGetAddr((char *)&localhost,(ulong *)&localaddr);
      if (iVar1 != 0) {
        LogErrorHost(-0x196,"",0,(char *)&localhost,0,"");
        return -1;
      }
    }
    *addr = localaddr;
    iVar1 = 0;
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

char *SocketAddrStr(long unsigned int addr)
{
  char *pcVar1;
  struct in_addr inaddr;
  
  pcVar1 = inet_ntoa(*(struct in_addr *)&addr);
  return pcVar1;
}

static int SocketUnixLoad(struct sockaddr_un *addr_unix, int port)
{
  size_t sVar1;
  
  memset(addr_unix,0,0x6e);
  addr_unix->sun_family = 1;
  /* original: "/usr/tmp/UNIX_%04x" (SGI_L3_SOCKET_DIR overrides) */
  snprintf(addr_unix->sun_path,sizeof(addr_unix->sun_path),"%s/UNIX_%04x",l3path_socket_dir(),port);
  sVar1 = strlen(addr_unix->sun_path);
  return sVar1 + 2;
}
