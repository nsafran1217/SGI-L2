/*
 * sys_ctrl/l3/l2/pty.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/pty.c
 */

#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/file.h>
#include "pty.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static char pty_name[12];

int pty_master(void)
{
  static char ptychar[5] = "pqrs";
  static char hexchar[17] = "0123456789abcdef";
  int master_fd;
  int iVar1;
  struct stat statbuff;
  char *ptr;
  int i;
  
  ptr = ptychar;
  while( true ) {
    if (*ptr == '\0') {
      return -1;
    }
    strcpy(pty_name,"/dev/ptyXY");
    pty_name[8] = *ptr;
    pty_name[9] = '0';
    master_fd = stat(pty_name,&statbuff);
    if (master_fd < 0) break;
    for (i = 0; i < 0x10; i = i + 1) {
      pty_name[9] = ((char *)&hexchar)[i];
      iVar1 = open(pty_name,2);
      if (-1 < iVar1) {
        return iVar1;
      }
    }
    ptr = ptr + 1;
  }
  return -1;
}

int pty_slave(int master_fd)
{
  int slave_fd;
  
  pty_name[5] = 't';
  slave_fd = open(pty_name,2);
  if (slave_fd < 0) {
    close(master_fd);
    slave_fd = -1;
  }
  return slave_fd;
}
