/*
 * sys_ctrl/common/Router/SocketIO.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/SocketIO.c
 */

#include "SocketIO.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

int SocketRead(int fd, unsigned char *buffer, int len)
{
  int *piVar1;
  int nread;
  int nleft;
  
  for (nleft = len; 0 < nleft; nleft = nleft - nread) {
    piVar1 = __errno_location();
    *piVar1 = 0;
    nread = read(fd,buffer,nleft);
    piVar1 = __errno_location();
    if (*piVar1 == 0xb) {
      return len - nleft;
    }
    if (nread < 0) {
      return nread;
    }
    if (nread == 0) break;
    buffer = buffer + nread;
  }
  return len - nleft;
}

int SocketWrite(int fd, unsigned char *buffer, int len)
{
  int nwritten;
  int nleft;
  
  for (nleft = len; 0 < nleft; nleft = nleft - nwritten) {
    nwritten = write(fd,buffer,nleft);
    if (nwritten < 0) {
      return nwritten;
    }
    if (nwritten == 0) break;
    buffer = buffer + nwritten;
  }
  return len - nleft;
}
