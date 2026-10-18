/*
 * sys_ctrl/l3/l2/route.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/route.c
 */

#include "irtr.h"   /* needed by the reconstruction */
#include <malloc.h>
#include <stddef.h>
#include "l2.h"
#include <stdio.h>
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
#include "route.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */
enum __anon_enum_48 {
    B2B_UART_MIN = 1,
    B2B_NIA = 1,
    B2B_NIB = 2,
    B2B_NIC = 3,
    B2B_NID = 4,
    B2B_NIE = 5,
    B2B_NIF = 6,
    B2B_NIG = 7,
    B2B_NIH = 8,
    B2B_N0A = 1,
    B2B_N0B = 2,
    B2B_N0C = 3,
    B2B_N0D = 4,
    B2B_N0E = 5,
    B2B_N0F = 6,
    B2B_N0G = 7,
    B2B_N0H = 8,
    B2B_N1A = 9,
    B2B_N1B = 10,
    B2B_N1C = 11,
    B2B_N1D = 12,
    B2B_N1E = 13,
    B2B_N1F = 14,
    B2B_N1G = 15,
    B2B_N1H = 16,
    B2B_N2A = 17,
    B2B_N2B = 18,
    B2B_N2C = 19,
    B2B_N2D = 20,
    B2B_N2E = 21,
    B2B_N2F = 22,
    B2B_N2G = 23,
    B2B_N2H = 24,
    B2B_N3A = 25,
    B2B_N3B = 26,
    B2B_N3C = 27,
    B2B_N3D = 28,
    B2B_N3E = 29,
    B2B_N3F = 30,
    B2B_N3G = 31,
    B2B_N3H = 32,
    B2B_NI_MAX = 32,
    B2B_IIA = 33,
    B2B_IIB = 34,
    B2B_IIC = 35,
    B2B_IID = 36,
    B2B_II_MAX = 36,
    B2B_SMP = 37,
    B2B_UART_MAX = 37,
    B2B_MAX_PORTS = 37,
    B2B_USB_MIN = 38,
    B2B_USB0 = 38,
    B2B_USB1 = 39,
    B2B_USB_MAX = 39,
    B2B_NET = 40,
};

int route_pending;
static SMP *route_smp;
static IRAddress route_addr;

void route_process_request(IRAddress addr, SMP *smp)
{
  IRPacket *p;
  int arg;
  int argc;
  IRArgument argv [64];
  
  if (route_pending == 0) {
    route_pending = 1;
    route_smp = smp;
    if ((addr & 0x80000000) == 0) {
      route_addr = addr & 0xffffffe0 | 0x17;
    }
    else {
      route_addr = addr & 0xc0ffffff | 0x17000000;
    }
    for (arg = 0; arg < 0x40; arg = arg + 1) {
      argv[arg]._clas = '\0';
      argv[arg]._frame = '\0';
      argv[arg]._val = 0;
      argv[arg]._size = 0;
    }
    p = IRouterMakePacket(&l2_route_id,&route_addr,0,0,0,2,0x40,argv);
    IRouterSendPacket(NULL,p);
  }
  return;
}

char *pstr(int type, int port)
{
  char *pcVar1;
  
  if (type == 0x2e) {
    switch(port) {
    case 1:
      return "L0G";
    case 2:
      return "L1H";
    case 3:
      return "L2G";
    case 4:
      return "L3H";
    case 5:
      return "R3G";
    case 6:
      return "R2H";
    case 7:
      return "R1G";
    case 8:
      return "R0H";
    default:
      return "INV";
    }
  }
  if (type < 0x2f) {
    if (type == 0x2c) {
      if (port == 2) {
        return "B0B";
      }
      if (port < 3) {
        if (port == 1) {
          return "B0A";
        }
      }
      else {
        if (port == 3) {
          return "B1A";
        }
        if (port == 4) {
          return "B1B";
        }
      }
      return "INV";
    }
    if (type == 0x2d) {
      switch(port) {
      case 1:
        return "N0A";
      case 2:
        return "N0B";
      case 3:
        return "N0C";
      case 4:
        return "N0D";
      case 5:
        return "N0E";
      case 6:
        return "N0F";
      case 7:
        return "N0G";
      case 8:
        return "N0H";
      case 9:
        return "N1A";
      case 10:
        return "N1B";
      case 0xb:
        return "N1C";
      case 0xc:
        return "N1D";
      case 0xd:
        return "N1E";
      case 0xe:
        return "N1F";
      case 0xf:
        return "N1G";
      case 0x10:
        return "N1H";
      case 0x11:
        return "N2A";
      case 0x12:
        return "N2B";
      case 0x13:
        return "N2C";
      case 0x14:
        return "N2D";
      case 0x15:
        return "N2E";
      case 0x16:
        return "N2F";
      case 0x17:
        return "N2G";
      case 0x18:
        return "N2H";
      case 0x19:
        return "N3A";
      case 0x1a:
        return "N3B";
      case 0x1b:
        return "N3C";
      case 0x1c:
        return "N3D";
      case 0x1d:
        return "N3E";
      case 0x1e:
        return "N3F";
      case 0x1f:
        return "N3G";
      case 0x20:
        return "N3H";
      default:
        return "INV";
      }
    }
  }
  else {
    if (type == 0x40) {
      if (true) {
        switch(port) {
        case 1:
          return "U-F";
        case 2:
          return "U-G";
        case 3:
          return "U-H";
        case 4:
          return "U-A";
        case 5:
          return "L-F";
        case 6:
          return "L-G";
        case 7:
          return "L-H";
        case 8:
          return "L-A";
        case 0x21:
          return "IIA";
        case 0x22:
          return "IIB";
        case 0x23:
          return "IIC";
        case 0x24:
          return "IID";
        }
      }
      return "INV";
    }
    if (type == 0x7d) {
      if (port == 2) {
        return "LH";
      }
      if (port < 3) {
        if (port == 1) {
          return "LG";
        }
      }
      else {
        if (port == 3) {
          return "RG";
        }
        if (port == 4) {
          return "RH";
        }
      }
      return "INV";
    }
  }
  if (false) {
switchD_08065f40_caseD_9:
    pcVar1 = "INV";
  }
  else {
    switch(port) {
    case 1:
      pcVar1 = "NIA";
      break;
    case 2:
      pcVar1 = "NIB";
      break;
    case 3:
      pcVar1 = "NIC";
      break;
    case 4:
      pcVar1 = "NID";
      break;
    case 5:
      pcVar1 = "NIE";
      break;
    case 6:
      pcVar1 = "NIF";
      break;
    case 7:
      pcVar1 = "NIG";
      break;
    case 8:
      pcVar1 = "NIH";
      break;
    default:
      goto switchD_08065f40_caseD_9;
    case 0x21:
      pcVar1 = "IIA";
      break;
    case 0x22:
      pcVar1 = "IIB";
      break;
    case 0x23:
      pcVar1 = "IIC";
      break;
    case 0x24:
      pcVar1 = "IID";
    }
  }
  return pcVar1;
}

void route_process_response(IRPacket *p)
{
  IRArgument *pIVar1;
  undefined *puVar2;
  char cVar3;
  char *pcVar4;
  size_t sVar5;
  uint val1;
  uint val2;
  uint uVar6;
  uint ts;
  char *pcVar7;
  int slot;
  int type;
  int iVar8;
  int iVar9;
  uint uVar10;
  undefined *puStack_cc;
  char *wpstr;
  char *rpstr;
  int rack;
  int wport;
  int rport;
  int rsp;
  uint last;
  int arg;
  char p2 [8];
  char p1 [8];
  char buff [128];
  
  if (p->_err != '\0') {
    pcVar4 = IRFmtError((uint)p->_err);
    sprintf(buff,"ERROR: %s\n",pcVar4);
    sVar5 = strlen(buff);
    smp_output(route_smp,buff,sVar5);
  }
  if (p->_argc == '\0') {
    sprintf(buff,"no routing data available\n");
    sVar5 = strlen(buff);
    smp_output(route_smp,buff,sVar5);
  }
  else {
    last = 0;
    for (arg = 0; arg < 0x40; arg = arg + 2) {
      if ((p->_argv[arg]._clas & 7) == 0) {
        val1 = p->_argv[arg]._val;
      }
      else {
        val1 = IRArg(p,arg);
      }
      if ((p->_argv[arg + 1]._clas & 7) == 0) {
        val2 = p->_argv[arg + 1]._val;
      }
      else {
        val2 = IRArg(p,arg + 1);
      }
      if (val1 != 0) {
        uVar6 = val2 & 0xffff;
        if ((val1 & 0x80000000) == 0) {
          slot = val1 >> 0x14 & 0x3ff;
          uVar6 = val1 >> 10 & 0x3ff;
          type = val1 & 0x3ff;
          ts = val2 & 0xffff;
          if (last == 0) {
            puStack_cc = NULL;
          }
          else {
            puStack_cc = (undefined *)(ts - last);
          }
          uVar10 = ts;
          pcVar4 = pstr(type,val2 >> 0x10 & 0xff);
          cVar3 = brickTypeToChar(type);
          iVar8 = (int)cVar3;
          iVar9 = (int)puStack_cc;
          pcVar7 = pstr(type,val2 >> 0x18);
          if ((val1 & 0x40000000) == 0) {
            puStack_cc = "REQ";
          }
          else {
            puStack_cc = "RSP";
          }
          sprintf(buff,"%s: %s %03d%c%02d %s %3d (%d)\n",puStack_cc,pcVar7,uVar6,iVar8,slot,pcVar4,
                  iVar9,uVar10);
          sVar5 = strlen(buff);
          smp_output(route_smp,buff,sVar5);
          last = ts;
        }
        else {
          if (last == 0) {
            puStack_cc = NULL;
          }
          else {
            puStack_cc = (undefined *)(uVar6 - last);
          }
          puVar2 = puStack_cc;
          if ((val1 & 0x40000000) == 0) {
            puStack_cc = "REQ";
          }
          else {
            puStack_cc = "RSP";
          }
          sprintf(buff,"%s:     L2-%-5d   %3d (%3d)\n",puStack_cc,val1 & 0x3fffffff,puVar2,
                  uVar6 % 1000);
          sVar5 = strlen(buff);
          smp_output(route_smp,buff,sVar5);
          last = uVar6;
        }
      }
    }
  }
  IRouterFreePacket(p);
  route_pending = 0;
  smp_prompt(route_smp);
  return;
}

void route_process(IRPacket *p)
{
  IRArgument *pIVar1;
  uint8 uVar2;
  uint uVar3;
  uint uVar4;
  uint val2;
  uint val1;
  int response;
  int arg;
  bool found;
  
  uVar2 = p->_clas;
  found = false;
  for (arg = 0; (!found && (arg < 0x40)); arg = arg + 1) {
    if ((p->_argv[arg]._clas & 7) == 0) {
      uVar3 = p->_argv[arg]._val;
    }
    else {
      uVar3 = IRArg(p,arg);
    }
    if (uVar3 == 0) {
      uVar4 = L2CfgLocal.rack | 0x80000000;
      uVar3 = time(NULL);
      p->_argv[arg]._val = (uint)(uVar2 == '\x01') << 0x1e | uVar4;
      val2 = uVar3 & 0xffff;
      p->_argv[arg + 1]._val = val2;
      found = true;
    }
  }
  return;
}
