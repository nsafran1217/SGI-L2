/*
 * sys_ctrl/l3/l2/serial.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/serial.c
 */

#include "l2.h"
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include "../../common/Router/Socket.h"
#include "../../common/Router/Event.h"
#include <sys/time.h>
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../../common/sys/sysutils.h"
#include <pthread.h>
#include <sched.h>
#include "../../common/sys/Logger.h"
#include "../sys/LoggerMsg.h"
#include "../../common/IRouter/IRouter2Router.h"
#include "../../common/Router/Router.h"
#include "../../common/sys/PPP.h"
#include "../../common/sys/brick_types.h"
#include "../../common/main/EnetServer.h"
#include "../../common/main/L2Cfg.h"
#include "../../common/main/L1Cfg.h"
#include "l2_rev.h"
#include "serial.h"
#include "smp.h"
#include "enet.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

SMP *serial_console;
SMP *serial_modem;
char *serial_com2;

void serial_init(void)
{
  int *piVar1;
  int fd;
  char *pcVar2;
  int iVar3;
  
  if (enet_only == 0) {
    serial_console = smp_init(&l2_console_id,0,1,serial_reset,0,IR_PORT_BIAS + 0x1f41);
    if (l2_pc != 0) {
      serial_com2 = (char *)l3path_dev("ttyS1");   /* original: "/dev/ttyS1" */
    }
    if (serial_com2 != NULL) {
      piVar1 = __errno_location();
      *piVar1 = 0;
      fd = open(serial_com2,0x82);
      if (fd < 0) {
        piVar1 = __errno_location();
        iVar3 = *piVar1;
        piVar1 = __errno_location();
        pcVar2 = strerror(*piVar1);
        fprintf(stderr,"INFO: can\'t open modem port (%s): %s [%d]\n",serial_com2,pcVar2,iVar3);
      }
      else {
        serial_modem = smp_init(&l2_modem_id,fd,fd,serial_reset,0,IR_PORT_BIAS + 0x1f41);
      }
    }
  }
  return;
}

void serial_reset(int sd)
{
  close(sd);
  return;
}
