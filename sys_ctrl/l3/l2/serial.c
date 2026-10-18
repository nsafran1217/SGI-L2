/*
 * sys_ctrl/l3/l2/serial.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/serial.c
 *
 * The L2's serial consoles: its own stdin/stdout, and on a PC-based L2 a
 * modem on the second serial port. Both are SMP sessions (smp.c).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "l2.h"
#include "serial.h"
#include "smp.h"
#include "enet.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */

SMP *serial_console;
SMP *serial_modem;
char *serial_com2;              /* the modem's device, if any */

/* start the consoles, unless l2 was told to use the network ones only */
void serial_init(void)
{
  int err;
  int fd;

  if (enet_only)
    return;
  serial_console = smp_init(&l2_console_id,0,1,serial_reset,0,IR_PORT_BIAS + SMP_PORT);
  if (l2_pc)
    serial_com2 = (char *)l3path_dev("ttyS1");   /* original: "/dev/ttyS1" */
  if (serial_com2 == NULL)
    return;
  errno = 0;
  fd = open(serial_com2,O_RDWR | O_EXCL);
  if (fd < 0) {
    err = errno;
    fprintf(stderr,"INFO: can\'t open modem port (%s): %s [%d]\n",serial_com2,strerror(err),err);
    return;
  }
  serial_modem = smp_init(&l2_modem_id,fd,fd,serial_reset,0,IR_PORT_BIAS + SMP_PORT);
}

/* an SMP's reset function: close its descriptor */
void serial_reset(int sd)
{
  close(sd);
}
