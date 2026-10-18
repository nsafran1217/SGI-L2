/*
 * sys_ctrl/l3/main/nvram.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/main/nvram.c
 */

#include "../l2/l1.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include "../../common/sys/sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include "../../common/sys/syslog.h"
#include "../../common/sys/ipmi.h"
#include "nvram.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/sysutils.h"
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include "../../common/sys/Logger.h"
#include "../sys/LoggerMsg.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void nvramInitIUA(void);
static void nvramInitPIA(void);
static void nvramInitCH(void);
static void nvramNormalizePointers(ipmiCommonHeader *nvbuf, uint32 old_base, uint32 new_base);
static int nvramLoad(uint8 *buf, int size);
static int nvramSave(uint8 *buf, int size);

ipmiCommonHeader *nvramCH;
nvramProductInfoArea *nvramPIA;
nvramInternalUseArea *nvramIUA;
nvramLog *nvramLogStart;
nvramLog *nvramLogEnd;
int32 nvramCount;
int32 nvramSim;
static int nvram_lock;
static int nvram_initialized;
nvramInstance nvram;
static uint8 nvramTempCopy[16384];
static char nvram_save_path[100];
static char nvram_file[1024];   /* original: 40; paths are configurable now */

int nvramInit(int mode)
{
  nvramInternalUseArea *pnVar1;
  uint8 uVar2;
  int iVar3;
  bool bad_ch;
  bool bVar4;
  int bad_iua;
  int32 status;
  bool bad_log;
  
  bad_log = false;
  if (mode == 1) {
    if (nvram_initialized != 0) {
      return 0;
    }
  }
  else {
    if (nvramCount != 0) {
      syslog(4,"nvram.c",0x53,0,"nvram already initialized!");
      return 0;
    }
    nvramCount = 1;
  }
  iVar3 = nvramLoad(nvramTempCopy,0x4000);
  if (iVar3 < 0) {
    iVar3 = -1;
  }
  else {
    nvram_lock = 1;
    nvramCH = (ipmiCommonHeader *)nvramTempCopy;
    uVar2 = ipmiCheckCSum(nvramTempCopy,8);
    bad_ch = uVar2 != '\0';
    if (bad_ch) {
      nvramInitCH();
    }
    if ((nvramCH->version == 0) || (nvramCH->internal_use_area == 0)) {
      bad_ch = true;
      nvramInitCH();
    }
    nvramIUA = (nvramInternalUseArea *)(nvramTempCopy + (uint)nvramCH->internal_use_area * 8);
    uVar2 = ipmiCheckCSum((uint8 *)nvramIUA,0x82c);
    bVar4 = uVar2 != '\0';
    if (bVar4) {
      nvramInitIUA();
    }
    pnVar1 = nvramIUA;
    if (nvramIUA->version == 1) {
      nvramIUA->version = 0;
      *(byte *)pnVar1 = *(byte *)pnVar1 | 0x20;
      nvramIUA->multisys = 1;
      nvramSave(nvramTempCopy,0x4000);
    }
    nvramLogStart = (nvramLog *)(nvramIUA + 1);
    nvramLogEnd = (nvramLog *)(nvramTempCopy + 0x3ff8);
    if (((((nvramInternalUseArea *)nvramIUA->log_start != (nvramInternalUseArea *)nvramLogStart) ||
         ((uint8 *)nvramIUA->log_end != nvramTempCopy + 0x3ff8)) ||
        (nvramIUA->log_head < nvramIUA->log_start)) ||
       (((nvramIUA->log_end <= nvramIUA->log_head || (nvramIUA->log_tail < nvramIUA->log_start)) ||
        (nvramIUA->log_end <= nvramIUA->log_tail)))) {
      bad_log = true;
      nvramIUA->log_start = nvramLogStart;
      nvramIUA->log_end = nvramLogEnd;
      nvramLogReset();
    }
    if (bad_ch) {
      nvramLogInsert("checksum error (CH) - nvram reset.");
    }
    else if (bVar4) {
      nvramLogInsert("checksum error (IUA) - nvram reset.");
    }
    else if (bad_log) {
      nvramLogInsert("log size changed - log reset.");
    }
    nvram_lock = 0;
    if (mode == 3) {
      nvramSave(nvramTempCopy,0x4000);
    }
    nvram_initialized = mode;
    if ((bad_ch || bVar4) || bad_log) {
      iVar3 = -1;
    }
    else {
      iVar3 = 0;
    }
  }
  return iVar3;
}

int nvramReset(void)
{
  nvramInitCH();
  if (nvram_initialized == 3) {
    nvramSave(nvramTempCopy,0x4000);
  }
  return 0;
}

static void nvramInitIUA(void)
{
  nvramInternalUseArea *pnVar1;
  uint8 uVar2;
  
  memset(nvramIUA,0,0x82c);
  pnVar1 = nvramIUA;
  nvramIUA->version = 0;
  *(byte *)pnVar1 = *(byte *)pnVar1 | 0x20;
  nvramIUA->rack = '\0';
  nvramIUA->multisys = 1;
  uVar2 = ipmiCalcCSum((uint8 *)nvramIUA,0x82c);
  nvramIUA->checksum = uVar2;
  return;
}

static void nvramInitPIA(void)
{
  return;
}

static void nvramInitCH(void)
{
  ipmiCommonHeader *piVar1;
  byte bVar2;
  
  memset(nvramCH,0,8);
  piVar1 = nvramCH;
  nvramCH->version = 0;
  *(byte *)piVar1 = *(byte *)piVar1 | 0x10;
  nvramCH->internal_use_area = 1;
  bVar2 = ipmiCalcCSum((uint8 *)nvramCH,8);
  nvramCH->checksum = bVar2;
  nvramIUA = (nvramInternalUseArea *)(nvramTempCopy + (uint)nvramCH->internal_use_area * 8);
  nvramInitIUA();
  return;
}

void nvramSet(int32 location, uint32 value)
{
  nvramInternalUseArea *pnVar1;
  uint8 uVar2;
  
  pnVar1 = nvramIUA;
  if ((nvram_initialized & 3U) != 0) {
    switch(location) {
    case 1:
      nvramIUA->rack = (byte)value;
      break;
    case 2:
      nvramIUA->auto_powerup = value;
      break;
    case 3:
      memset(nvramIUA->system_serial_number,0,0x10);
      if (value != 0) {
        strncpy(nvramIUA->system_serial_number,(char *)value,0xf);
      }
      break;
    case 4:
      memset(nvramIUA->system_name,0,0x20);
      if (value != 0) {
        strncpy(nvramIUA->system_name,(char *)value,0x1f);
      }
      break;
    case 5:
      nvramIUA->multisys = value;
      break;
    case 6:
      nvramIUA->ip_addr = value;
      break;
    case 7:
      nvramIUA->ip_netmask = value;
      break;
    case 8:
      nvramIUA->ip_broadcast = value;
      break;
    case 9:
      nvramIUA->l2dsp_disabled = value;
      break;
    case 10:
      nvramIUA->l1usb_debug = value;
      break;
    case 0xb:
      nvramIUA->ping_min = value;
      break;
    case 0xc:
      nvramIUA->ping_max = value;
      break;
    case 0xd:
      nvramIUA->ping_sender = value;
      break;
    case 0xe:
      nvramIUA->ping_l2freq = value;
      break;
    case 0xf:
      nvramIUA->ping_l1freq = value;
      break;
    case 0x10:
      nvramIUA->dhcps_disabled = value;
      break;
    case 0x11:
      memset(nvramIUA->timezone,0,0x50);
      if (value != 0) {
        strncpy(nvramIUA->timezone,(char *)value,0x4f);
      }
      break;
    case 0x12:
      nvramIUA->modem_baud = (byte)value;
      break;
    case 0x13:
      memset(nvramIUA->password,0,0x10);
      if (value != 0) {
        strncpy(nvramIUA->password,(char *)value,0xf);
      }
      break;
    case 0x14:
      nvramIUA->autopower_delay = value;
      break;
    case 0x15:
      nvramIUA->slow_pwrup = value;
      break;
    case 0x16:
      nvramIUA->slot = (byte)value;
      break;
    case 0x17:
      nvramIUA->broadcast_timeout = (byte)value;
      break;
    case 0x18:
      nvramIUA->target_timeout = (byte)value;
      break;
    case 0x19:
      nvramIUA->ip_gateway = value;
      break;
    case 0x1a:
      nvramIUA->master_slave = value;
      break;
    default:
      goto switchD_08066c58_default;
    }
    uVar2 = ipmiCalcCSum((uint8 *)nvramIUA,0x82c);
    nvramIUA->checksum = uVar2;
    if (nvram_initialized == 3) {
      nvramSave(nvramTempCopy,0x4000);
    }
  }
switchD_08066c58_default:
  return;
}

uint32 nvramGet(int32 location)
{
  char *pcVar1;
  
  if ((nvram_initialized & 1U) == 0) {
    nvramInit(1);
  }
  switch(location) {
  case 1:
    pcVar1 = (char *)(uint)nvramIUA->rack;
    break;
  case 2:
    pcVar1 = nvramIUA->auto_powerup;
    break;
  case 3:
    pcVar1 = nvramIUA->system_serial_number;
    break;
  case 4:
    pcVar1 = nvramIUA->system_name;
    break;
  case 5:
    pcVar1 = nvramIUA->multisys;
    break;
  case 6:
    pcVar1 = (char *)nvramIUA->ip_addr;
    break;
  case 7:
    pcVar1 = (char *)nvramIUA->ip_netmask;
    break;
  case 8:
    pcVar1 = (char *)nvramIUA->ip_broadcast;
    break;
  case 9:
    pcVar1 = nvramIUA->l2dsp_disabled;
    break;
  case 10:
    pcVar1 = (char *)nvramIUA->l1usb_debug;
    break;
  case 0xb:
    pcVar1 = (char *)nvramIUA->ping_min;
    break;
  case 0xc:
    pcVar1 = (char *)nvramIUA->ping_max;
    break;
  case 0xd:
    pcVar1 = (char *)nvramIUA->ping_sender;
    break;
  case 0xe:
    pcVar1 = (char *)nvramIUA->ping_l2freq;
    break;
  case 0xf:
    pcVar1 = (char *)nvramIUA->ping_l1freq;
    break;
  case 0x10:
    pcVar1 = nvramIUA->dhcps_disabled;
    break;
  case 0x11:
    pcVar1 = nvramIUA->timezone;
    break;
  case 0x12:
    pcVar1 = (char *)(uint)nvramIUA->modem_baud;
    break;
  case 0x13:
    pcVar1 = nvramIUA->password;
    break;
  case 0x14:
    pcVar1 = (char *)nvramIUA->autopower_delay;
    break;
  case 0x15:
    pcVar1 = nvramIUA->slow_pwrup;
    break;
  case 0x16:
    pcVar1 = (char *)(uint)nvramIUA->slot;
    break;
  case 0x17:
    pcVar1 = (char *)(uint)nvramIUA->broadcast_timeout;
    break;
  case 0x18:
    pcVar1 = (char *)(uint)nvramIUA->target_timeout;
    break;
  case 0x19:
    pcVar1 = (char *)nvramIUA->ip_gateway;
    break;
  case 0x1a:
    pcVar1 = nvramIUA->master_slave;
    break;
  default:
    pcVar1 = (char *)0xffffffff;
  }
  return (uint32)pcVar1;
}

void nvramLogReset(void)
{
  uint8 uVar1;
  
  nvramIUA->log_head = nvramIUA->log_start;
  nvramIUA->log_tail = nvramIUA->log_start;
  uVar1 = ipmiCalcCSum((uint8 *)nvramIUA,0x82c);
  nvramIUA->checksum = uVar1;
  if (nvram_initialized == 3) {
    nvramSave(nvramTempCopy,0x4000);
  }
  return;
}

void nvramLogInsert(char *message)
{
  nvramLog **ppnVar1;
  int iVar2;
  char cVar3;
  char *pcVar4;
  nvramInternalUseArea *pnVar5;
  uint8 uVar6;
  int32 fre;
  int8 add_newline;
  int32 size;
  int tssize;
  char *tp;
  time_t tval;
  int32 status;
  
  tval = time(NULL);
  tp = (char *)&tval;
  tssize = 5;
  size = strlen(message);
  fre = (int)nvramIUA->log_end - (int)nvramIUA->log_start;
  cVar3 = message[size - 1];
  if (nvramIUA->log_head < nvramIUA->log_tail) {
    fre = (int32)(nvramIUA->log_head +
                 (int)(nvramIUA->log_end + (-(int)nvramIUA->log_tail - (int)nvramIUA->log_start)));
  }
  else if (nvramIUA->log_tail < nvramIUA->log_head) {
    fre = (int)nvramIUA->log_head - (int)nvramIUA->log_tail;
  }
  for (; fre <= (int)(size + 5U + (int)(cVar3 != '\n')); fre = fre + 1) {
    while (pcVar4 = nvramIUA->log_head, nvramIUA->log_head = nvramIUA->log_head + 1, *pcVar4 != '\n'
          ) {
      fre = fre + 1;
      if (nvramIUA->log_end <= nvramIUA->log_head) {
        nvramIUA->log_head = nvramIUA->log_start;
      }
    }
  }
  while (pnVar5 = nvramIUA, tssize = tssize + -1, tssize != -1) {
    if (tssize == 4) {
      *nvramIUA->log_tail = -0x10;
      ppnVar1 = &pnVar5->log_tail;
      *ppnVar1 = *ppnVar1 + 1;
    }
    else {
      *nvramIUA->log_tail = *tp;
      tp = tp + 1;
      ppnVar1 = &pnVar5->log_tail;
      *ppnVar1 = *ppnVar1 + 1;
    }
    if (nvramIUA->log_end <= nvramIUA->log_tail) {
      nvramIUA->log_tail = nvramIUA->log_start;
    }
  }
  while (pnVar5 = nvramIUA, iVar2 = size + -1, size != 0) {
    *nvramIUA->log_tail = *message;
    message = message + 1;
    ppnVar1 = &pnVar5->log_tail;
    *ppnVar1 = *ppnVar1 + 1;
    size = iVar2;
    if (nvramIUA->log_end <= nvramIUA->log_tail) {
      nvramIUA->log_tail = nvramIUA->log_start;
    }
  }
  if (cVar3 != '\n') {
    *nvramIUA->log_tail = '\n';
    ppnVar1 = &pnVar5->log_tail;
    *ppnVar1 = *ppnVar1 + 1;
    if (nvramIUA->log_end <= nvramIUA->log_tail) {
      nvramIUA->log_tail = nvramIUA->log_start;
    }
  }
  uVar6 = ipmiCalcCSum((uint8 *)nvramIUA,0x82c);
  nvramIUA->checksum = uVar6;
  if (nvram_initialized == 3) {
    nvramSave(nvramTempCopy,0x4000);
  }
  return;
}

void nvramLogFinsert(char *fmt, ...)
{
  char buff [160];
  va_list ap;
  
  /* ORIGINAL BUG (fixed, see ORIGINAL_BUGS.md): the original passed the va_list
   * to snprintf, not vsnprintf, so any % conversion printed garbage. */
  va_start(ap,fmt);
  vsnprintf(buff,0xa0,fmt,ap);
  va_end(ap);
  nvramLogInsert(buff);
  return;
}

char *nvramLogFetch(void)
{
  char *pcVar1;
  int bsize;
  struct tm *__tp;
  size_t sVar2;
  int32 size;
  uchar *tp;
  time_t tval;
  int tcnt;
  char *blkend;
  char *blkbeg;
  char *c;
  char *block2e;
  char *block2;
  char *block1e;
  char *block1;
  char *messages;
  
  size = 1;
  if (nvramIUA->log_head < nvramIUA->log_tail) {
    block1 = nvramIUA->log_head;
    block1e = nvramIUA->log_tail;
    block2 = NULL;
    block2e = NULL;
  }
  else {
    if (nvramIUA->log_tail <= nvramIUA->log_head) {
      pcVar1 = malloc(1);
      if (pcVar1 == NULL) {
        return NULL;
      }
      *pcVar1 = '\0';
      return pcVar1;
    }
    block1 = nvramIUA->log_head;
    block1e = nvramIUA->log_end;
    block2 = nvramIUA->log_start;
    block2e = nvramIUA->log_tail;
  }
  tcnt = 0;
  blkend = block1e;
  blkbeg = block1;
  while (blkbeg != NULL) {
    for (c = blkbeg; c < blkend; c = c + 1) {
      if (tcnt == 0) {
        if (*c == -0x10) {
          size = size + 0x12;
          tcnt = 4;
        }
        else {
          size = size + 1;
        }
      }
      else {
        tcnt = tcnt + -1;
      }
    }
    blkend = block2e;
    blkbeg = block2;
  }
  if (size < 100) {
    bsize = 100;
  }
  else {
    bsize = size + 1;
  }
  messages = malloc(bsize);
  if (messages == NULL) {
    messages = NULL;
  }
  else {
    tcnt = 0;
    size = 0;
    blkend = block1e;
    blkbeg = block1;
    while (blkbeg != NULL) {
      for (c = blkbeg; c < blkend; c = c + 1) {
        if (tcnt == 0) {
          if (*c == -0x10) {
            tp = (uchar *)&tval;
            tcnt = 4;
          }
          else {
            messages[size] = *c;
            size = size + 1;
          }
        }
        else {
          *tp = *c;
          tp = tp + 1;
          tcnt = tcnt + -1;
          if (tcnt == 0) {
            __tp = localtime(&tval);
            strftime(messages + size,0x13,"%m/%d/%y %X ",__tp);
            sVar2 = strlen(messages + size);
            size = size + sVar2;
          }
        }
      }
      blkend = block2e;
      blkbeg = block2;
    }
    messages[size] = '\0';
  }
  return messages;
}

static void nvramNormalizePointers(ipmiCommonHeader *nvbuf, uint32 old_base, uint32 new_base)
{
  uint8 uVar1;
  nvramInternalUseArea *tmpIUA;
  uint32 offset;
  
  tmpIUA = (nvramInternalUseArea *)(nvbuf + nvbuf->internal_use_area);
  offset = new_base - old_base;
  tmpIUA->log_start = tmpIUA->log_start + offset;
  tmpIUA->log_end = tmpIUA->log_end + offset;
  tmpIUA->log_head = tmpIUA->log_head + offset;
  tmpIUA->log_tail = tmpIUA->log_tail + offset;
  uVar1 = ipmiCalcCSum((uint8 *)tmpIUA,0x82c);
  tmpIUA->checksum = uVar1;
  return;
}

static int nvramLoad(uint8 *buf, int size)
{
  static int first = 1;
  int rval;
  int fd;
  int *piVar1;
  char *pcVar2;
  char *path;
  
  if (nvramSim == 0) {
    if (first != 0) {
      first = 0;
      /* original: "./.l2_NVRAM", or "./.l2_NVRAM.<bias/10>" (SGI_L2_NVRAM overrides) */
      snprintf(nvram_file,sizeof(nvram_file),"%s",l3path_nvram(IR_PORT_BIAS));
    }
    fd = open(nvram_file,0,0x1b6);
    if (fd < 0) {
      piVar1 = __errno_location();
      if (*piVar1 == 2) {
        syslog(6,"nvram.c",0x405,0,"NVRAM file \'%s\' doesn\'t exist.....initializing",nvram_file);
        memset(buf,0,size);
        close(fd);
        nvramSave(buf,size);
        rval = 0;
      }
      else {
        piVar1 = __errno_location();
        pcVar2 = LoggerDefaultMessage(*piVar1);
        syslog(1,"nvram.c",0x40c,0,"can\'t open the NVRAM file \'%s\' for reading: %s",nvram_file,
               pcVar2);
        close(fd);
        rval = -1;
      }
    }
    else {
      rval = read(fd,buf,size);
      if (rval < 0) {
        piVar1 = __errno_location();
        pcVar2 = LoggerDefaultMessage(*piVar1);
        syslog(1,"nvram.c",0x415,0,"can\'t read the NVRAM file \'%s\': %s",nvram_file,pcVar2);
        close(fd);
        rval = -1;
      }
      else {
        nvramNormalizePointers((ipmiCommonHeader *)buf,0,(uint32)buf);
        close(fd);
      }
    }
  }
  else {
    memset(buf,0,size);
    rval = 0;
  }
  return rval;
}

static int nvramSave(uint8 *buf, int size)
{
  int rval;
  int fd;
  int *piVar1;
  char *pcVar2;
  
  if (nvramSim == 0) {
    if (nvram_lock < 1) {
      fd = open(nvram_file,0x241,0x1b6);
      if (fd < 0) {
        piVar1 = __errno_location();
        pcVar2 = LoggerDefaultMessage(*piVar1);
        syslog(4,"nvram.c",0x434,0,"can\'t open the NVRAM file \'%s\' for writing: %s",nvram_file,
               pcVar2);
        close(fd);
        rval = -1;
      }
      else {
        nvramNormalizePointers((ipmiCommonHeader *)buf,(uint32)buf,0);
        rval = write(fd,buf,size);
        if (rval < 0) {
          piVar1 = __errno_location();
          pcVar2 = LoggerDefaultMessage(*piVar1);
          syslog(4,"nvram.c",0x43f,0,"can\'t write the NVRAM file \'%s\': %s",nvram_file,pcVar2);
        }
        nvramNormalizePointers((ipmiCommonHeader *)buf,0,(uint32)buf);
        close(fd);
        if (rval < 0) {
          rval = -1;
        }
      }
    }
    else {
      rval = -1;
    }
  }
  else {
    rval = 0;
  }
  return rval;
}
