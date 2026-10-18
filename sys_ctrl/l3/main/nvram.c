/*
 * sys_ctrl/l3/main/nvram.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/main/nvram.c
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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

/* The NVRAM image is the file's bytes: its layout must not depend on the host. */
_Static_assert(sizeof(nvramInternalUseArea) == 2092, "NVRAM internal use area layout");

/* log_* fields are offsets into the NVRAM image (see nvram.h) */
#define LOGPTR(off) ((nvramLog *)(nvramTempCopy + (off)))
#define LOGOFF(p)   ((uint32)((uint8 *)(p) - nvramTempCopy))

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
    if (nvramIUA->log_start != LOGOFF(nvramLogStart) || nvramIUA->log_end != 0x3ff8 ||
        nvramIUA->log_head < nvramIUA->log_start || nvramIUA->log_end <= nvramIUA->log_head ||
        nvramIUA->log_tail < nvramIUA->log_start || nvramIUA->log_end <= nvramIUA->log_tail) {
      bad_log = true;
      nvramIUA->log_start = LOGOFF(nvramLogStart);
      nvramIUA->log_end = LOGOFF(nvramLogEnd);
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
  
  memset(nvramIUA,0,sizeof(nvramInternalUseArea));
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
  
  memset(nvramCH,0,sizeof(ipmiCommonHeader));
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

void nvramSet(int32 location, uintptr_t value)   /* original: uint32 value; string fields pass a pointer */
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

/* Returns numbers and, for string fields, pointers: uintptr_t (the original's uint32)
 * holds either on any architecture. */
uintptr_t nvramGet(int32 location)
{
  uintptr_t val;
  
  if ((nvram_initialized & 1U) == 0) {
    nvramInit(1);
  }
  switch(location) {
  case 1:
    val = (uintptr_t)nvramIUA->rack;
    break;
  case 2:
    val = (uintptr_t)nvramIUA->auto_powerup;
    break;
  case 3:
    val = (uintptr_t)nvramIUA->system_serial_number;
    break;
  case 4:
    val = (uintptr_t)nvramIUA->system_name;
    break;
  case 5:
    val = (uintptr_t)nvramIUA->multisys;
    break;
  case 6:
    val = (uintptr_t)nvramIUA->ip_addr;
    break;
  case 7:
    val = (uintptr_t)nvramIUA->ip_netmask;
    break;
  case 8:
    val = (uintptr_t)nvramIUA->ip_broadcast;
    break;
  case 9:
    val = (uintptr_t)nvramIUA->l2dsp_disabled;
    break;
  case 10:
    val = (uintptr_t)nvramIUA->l1usb_debug;
    break;
  case 0xb:
    val = (uintptr_t)nvramIUA->ping_min;
    break;
  case 0xc:
    val = (uintptr_t)nvramIUA->ping_max;
    break;
  case 0xd:
    val = (uintptr_t)nvramIUA->ping_sender;
    break;
  case 0xe:
    val = (uintptr_t)nvramIUA->ping_l2freq;
    break;
  case 0xf:
    val = (uintptr_t)nvramIUA->ping_l1freq;
    break;
  case 0x10:
    val = (uintptr_t)nvramIUA->dhcps_disabled;
    break;
  case 0x11:
    val = (uintptr_t)nvramIUA->timezone;
    break;
  case 0x12:
    val = (uintptr_t)nvramIUA->modem_baud;
    break;
  case 0x13:
    val = (uintptr_t)nvramIUA->password;
    break;
  case 0x14:
    val = (uintptr_t)nvramIUA->autopower_delay;
    break;
  case 0x15:
    val = (uintptr_t)nvramIUA->slow_pwrup;
    break;
  case 0x16:
    val = (uintptr_t)nvramIUA->slot;
    break;
  case 0x17:
    val = (uintptr_t)nvramIUA->broadcast_timeout;
    break;
  case 0x18:
    val = (uintptr_t)nvramIUA->target_timeout;
    break;
  case 0x19:
    val = (uintptr_t)nvramIUA->ip_gateway;
    break;
  case 0x1a:
    val = (uintptr_t)nvramIUA->master_slave;
    break;
  default:
    val = 0xffffffff;
  }
  return val;
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

static void nvramLogPut(nvramInternalUseArea *iua, char c)
{
  *LOGPTR(iua->log_tail) = c;
  iua->log_tail++;
  if (iua->log_end <= iua->log_tail) {
    iua->log_tail = iua->log_start;
  }
}

/* Append a message to the NVRAM log ring: 0xf0, the time as 4 little-endian
 * bytes, the text, and a newline if it has none. Oldest messages are dropped
 * to make room. Same bytes as the original on any host. */
void nvramLogInsert(char *message)
{
  nvramInternalUseArea *iua = nvramIUA;
  uint32 tval = (uint32)time(NULL);
  int32 size = strlen(message);
  int add_newline = message[size - 1] != '\n';     /* as the original: no check for "" */
  int32 fre;
  int i;

  fre = iua->log_end - iua->log_start;
  if (iua->log_head < iua->log_tail) {
    fre = iua->log_head + (iua->log_end - iua->log_tail - iua->log_start);
  }
  else if (iua->log_tail < iua->log_head) {
    fre = iua->log_head - iua->log_tail;
  }
  for (; fre <= size + 5 + add_newline; fre++) {
    /* drop the oldest message (the original only wraps head inside the loop) */
    while (*LOGPTR(iua->log_head++) != '\n') {
      fre++;
      if (iua->log_end <= iua->log_head) {
        iua->log_head = iua->log_start;
      }
    }
  }
  nvramLogPut(iua, (char)0xf0);
  for (i = 0; i < 4; i++) {
    nvramLogPut(iua, (char)(tval >> (8 * i)));
  }
  for (i = 0; i < size; i++) {
    nvramLogPut(iua, message[i]);
  }
  if (add_newline) {
    nvramLogPut(iua, '\n');
  }
  iua->checksum = ipmiCalcCSum((uint8 *)iua,0x82c);
  if (nvram_initialized == 3) {
    nvramSave(nvramTempCopy,0x4000);
  }
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
  uint32 tbits;
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
    block1 = LOGPTR(nvramIUA->log_head);
    block1e = LOGPTR(nvramIUA->log_tail);
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
    block1 = LOGPTR(nvramIUA->log_head);
    block1e = LOGPTR(nvramIUA->log_end);
    block2 = LOGPTR(nvramIUA->log_start);
    block2e = LOGPTR(nvramIUA->log_tail);
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
            tbits = 0;          /* time follows as 4 little-endian bytes */
            tcnt = 4;
          }
          else {
            messages[size] = *c;
            size = size + 1;
          }
        }
        else {
          tbits |= (uint32)(uchar)*c << (8 * (4 - tcnt));
          tcnt = tcnt + -1;
          if (tcnt == 0) {
            tval = (time_t)tbits;
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

/* The original rebased the IUA's log pointers between the in-memory image
 * (absolute) and the file (offsets). They are offsets in both now, so only
 * the checksum is refreshed, as the original did after rebasing. */
static void nvramNormalizePointers(ipmiCommonHeader *nvbuf, uint32 old_base, uint32 new_base)
{
  nvramInternalUseArea *tmpIUA;

  (void)old_base;
  (void)new_base;
  tmpIUA = (nvramInternalUseArea *)(nvbuf + nvbuf->internal_use_area);
  tmpIUA->checksum = ipmiCalcCSum((uint8 *)tmpIUA,0x82c);
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
        nvramNormalizePointers((ipmiCommonHeader *)buf,0,0);
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
        nvramNormalizePointers((ipmiCommonHeader *)buf,0,0);
        rval = write(fd,buf,size);
        if (rval < 0) {
          piVar1 = __errno_location();
          pcVar2 = LoggerDefaultMessage(*piVar1);
          syslog(4,"nvram.c",0x43f,0,"can\'t write the NVRAM file \'%s\': %s",nvram_file,pcVar2);
        }
        nvramNormalizePointers((ipmiCommonHeader *)buf,0,0);
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
