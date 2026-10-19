/*
 * sys_ctrl/l3/l2/serial.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/serial.c
 *
 * The L2's serial console, its own stdin/stdout: an SMP session (smp.c),
 * with -console or when stdin is a terminal. (A daemon's stdin is not: as
 * a service, l2 has only its network consoles, and its messages go to
 * stderr.)
 */

#include <unistd.h>
#include "l2.h"
#include "serial.h"
#include "smp.h"
#include "enet.h"

SMP *serial_console;
int serial_wanted;              /* -console */

/* start the console, unless l2 was told to use the network ones only */
void serial_init(void)
{
  if (enet_only || !(serial_wanted || isatty(0)))
    return;
  serial_console = smp_init(&l2_console_id,0,1,serial_reset,0,IR_PORT_BIAS + SMP_PORT);
}

/* an SMP's reset function: close its descriptor */
void serial_reset(int sd)
{
  close(sd);
}
