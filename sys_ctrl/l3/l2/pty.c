/*
 * sys_ctrl/l3/l2/pty.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/pty.c
 *
 * A pseudo-terminal for the console's "shell" command (smp_shell()), the
 * BSD way: the first free master /dev/pty[p-s][0-f], then its slave
 * /dev/tty... . Linux dropped BSD ptys (CONFIG_LEGACY_PTYS), so on current
 * kernels there is none and "shell" fails, with the original too.
 */

#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pty.h"

static char pty_name[12];      /* the master's name, then the slave's */

/* open a free master; -1 if there is none */
int pty_master(void)
{
  static const char ptychar[] = "pqrs";
  static const char hexchar[] = "0123456789abcdef";
  struct stat statbuff;
  const char *ptr;
  int fd;
  int i;

  for (ptr = ptychar; *ptr != '\0'; ptr++) {
    strcpy(pty_name,"/dev/ptyXY");
    pty_name[8] = *ptr;
    pty_name[9] = '0';
    if (stat(pty_name,&statbuff) < 0)       /* no such bank: stop */
      break;
    for (i = 0; i < 16; i++) {
      pty_name[9] = hexchar[i];
      fd = open(pty_name,O_RDWR);
      if (fd >= 0)
        return fd;
    }
  }
  return -1;
}

/* open the slave of the master pty_master() last opened; on failure close
 * the master and return -1 */
int pty_slave(int master_fd)
{
  int slave_fd;

  pty_name[5] = 't';                        /* /dev/ptyXY -> /dev/ttyXY */
  slave_fd = open(pty_name,O_RDWR);
  if (slave_fd < 0) {
    close(master_fd);
    return -1;
  }
  return slave_fd;
}
