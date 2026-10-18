/*
 * sys_ctrl/common/Router/SocketIO.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/SocketIO.c
 *
 * Read or write a whole buffer on a descriptor, looping over short transfers.
 */

#include <errno.h>
#include <unistd.h>
#include "SocketIO.h"

/* read up to len bytes; returns the number read (less at end of file or when a
 * non-blocking descriptor runs dry), or read()'s error */
int SocketRead(int fd, unsigned char *buffer, int len)
{
  int nleft, nread;

  for (nleft = len; nleft > 0; nleft -= nread) {
    errno = 0;
    nread = read(fd,buffer,nleft);
    if (errno == EAGAIN)
      return len - nleft;
    if (nread < 0)
      return nread;
    if (nread == 0)
      break;
    buffer += nread;
  }
  return len - nleft;
}

/* write len bytes; returns the number written, or write()'s error */
int SocketWrite(int fd, unsigned char *buffer, int len)
{
  int nleft, nwritten;

  for (nleft = len; nleft > 0; nleft -= nwritten) {
    nwritten = write(fd,buffer,nleft);
    if (nwritten < 0)
      return nwritten;
    if (nwritten == 0)
      break;
    buffer += nwritten;
  }
  return len - nleft;
}
