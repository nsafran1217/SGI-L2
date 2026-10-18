/*
 * sys_ctrl/l3/l2/route.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/route.c
 *
 * The console's "route" command: a request of ROUTE_ARGS zero arguments to
 * an L1's route task. Every L2 and L1 it passes fills in the next pair:
 * who it is (and whether the packet was a request or the response), the
 * ports it came in and left by, and a 16-bit timestamp. The response is
 * printed as the trace.
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "l2.h"
#include "route.h"
#include "irtr.h"
#include "../../common/sys/brick_types.h"

#define ROUTE_ARGS      64

/* an entry's first word: the response bit, and an L2 (its rack) or a brick */
#define ROUTE_L2        0x80000000
#define ROUTE_RSP       0x40000000
#define ROUTE_TYPE(v)   ((v) & 0x3ff)
#define ROUTE_RACK(v)   (((v) >> 10) & 0x3ff)
#define ROUTE_SLOT(v)   (((v) >> 20) & 0x3ff)
/* ... and its second: the ports (in, out) and the timestamp */
#define ROUTE_IN(v)     ((v) >> 24)
#define ROUTE_OUT(v)    (((v) >> 16) & 0xff)
#define ROUTE_TIME(v)   ((v) & 0xffff)

int route_pending;
static SMP *route_smp;
static IRAddress route_addr;

/* trace the route to the L1 at addr, for the console smp */
void route_process_request(IRAddress addr, SMP *smp)
{
  IRArgument argv[ROUTE_ARGS];
  IRPacket *p;

  if (route_pending)
    return;
  route_pending = 1;
  route_smp = smp;
  route_addr = IR_ADDR_WITH_TASK(addr,IR_L1_ROUTE);
  memset(argv,0,sizeof(argv));
  p = IRouterMakePacket(&l2_route_id,&route_addr,0,0,IR_REQ,2,ROUTE_ARGS,argv);
  IRouterSendPacket(NULL,p);
}

/* a port's name on a brick of this type (its ports are numbered from 1) */
char *pstr(int type, int port)
{
  static char *const chassis_1932[] = { "B0A", "B0B", "B1A", "B1B" };
  static char *const router_ports[] = {
    "N0A", "N0B", "N0C", "N0D", "N0E", "N0F", "N0G", "N0H",
    "N1A", "N1B", "N1C", "N1D", "N1E", "N1F", "N1G", "N1H",
    "N2A", "N2B", "N2C", "N2D", "N2E", "N2F", "N2G", "N2H",
    "N3A", "N3B", "N3C", "N3D", "N3E", "N3F", "N3G", "N3H",
  };
  static char *const chassis_191010[] = { "L0G", "L1H", "L2G", "L3H", "R3G", "R2H", "R1G", "R0H" };
  static char *const vortix[] = { "U-F", "U-G", "U-H", "U-A", "L-F", "L-G", "L-H", "L-A" };
  static char *const chassis_1955[] = { "LG", "LH", "RG", "RH" };
  static char *const numalink[] = { "NIA", "NIB", "NIC", "NID", "NIE", "NIF", "NIG", "NIH" };
  static char *const xio[] = { "IIA", "IIB", "IIC", "IID" };   /* ports 33-36 */
#define PORT(list) (port >= 1 && port <= (int)(sizeof(list) / sizeof(list[0])) ? list[port - 1] : "INV")

  switch (type) {
  case ',':
    return PORT(chassis_1932);
  case '-':
    return PORT(router_ports);
  case '.':
    return PORT(chassis_191010);
  case '}':
    return PORT(chassis_1955);
  case '@':
    if (port >= 33 && port <= 36)
      return xio[port - 33];
    return PORT(vortix);
  default:
    if (port >= 33 && port <= 36)
      return xio[port - 33];
    return PORT(numalink);
  }
#undef PORT
}

/* the trace: one line per hop, with the time since the one before */
void route_process_response(IRPacket *p)
{
  char buff[128];
  unsigned int last = 0;
  unsigned int val1;
  unsigned int val2;
  unsigned int ts;
  int type;
  int arg;

  if (p->_err != 0) {
    sprintf(buff,"ERROR: %s\n",IRFmtError(p->_err));
    smp_output(route_smp,buff,strlen(buff));
  }
  if (p->_argc == 0) {
    sprintf(buff,"no routing data available\n");
    smp_output(route_smp,buff,strlen(buff));
  }
  /* (the original read all ROUTE_ARGS whatever the packet held) */
  for (arg = 0; arg + 1 < p->_argc && arg < ROUTE_ARGS; arg += 2) {
    val1 = IRArg(p,arg);
    val2 = IRArg(p,arg + 1);
    if (val1 == 0)
      continue;
    ts = ROUTE_TIME(val2);
    if (val1 & ROUTE_L2) {
      sprintf(buff,"%s:     L2-%-5d   %3d (%3d)\n",val1 & ROUTE_RSP ? "RSP" : "REQ",
              val1 & 0x3fffffff,last == 0 ? 0 : (int)(ts - last),ts % 1000);
    }
    else {
      type = ROUTE_TYPE(val1);
      sprintf(buff,"%s: %s %03d%c%02d %s %3d (%d)\n",val1 & ROUTE_RSP ? "RSP" : "REQ",
              pstr(type,ROUTE_IN(val2)),ROUTE_RACK(val1),brickTypeToChar(type),ROUTE_SLOT(val1),
              pstr(type,ROUTE_OUT(val2)),last == 0 ? 0 : (int)(ts - last),ts);
    }
    smp_output(route_smp,buff,strlen(buff));
    last = ts;
  }
  IRouterFreePacket(p);
  route_pending = 0;
  smp_prompt(route_smp);
}

/* a route packet passing through: this L2's entry in the first free
 * argument */
void route_process(IRPacket *p)
{
  int arg;

  /* (the original looked at all ROUTE_ARGS, and could write one past them) */
  for (arg = 0; arg + 1 < p->_argc && arg < ROUTE_ARGS; arg++) {
    if (IRArg(p,arg) != 0)
      continue;
    p->_argv[arg]._val = (p->_clas == IR_RSP ? ROUTE_RSP : 0) | ROUTE_L2 | L2CfgLocal.rack;
    p->_argv[arg + 1]._val = ROUTE_TIME(time(NULL));
    return;
  }
}
