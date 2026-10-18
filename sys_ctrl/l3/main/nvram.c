/*
 * sys_ctrl/l3/main/nvram.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/main/nvram.c
 *
 * The L2's settings and log, kept in a 16 KB image laid out like an IPMI
 * FRU: a common header, the internal use area (nvramInternalUseArea: the
 * settings, checksummed) and a log ring after it. On the hardware L2 this
 * is NVRAM; here it is a file (l3path_nvram(): ./.l2_NVRAM by default),
 * read whole at nvramInit() and, in NVRAM_READWRITE mode, written whole on
 * every change.
 *
 * The log ring holds messages as 0xf0, the time (4 bytes, little-endian),
 * the text and a newline; log_head is the oldest byte, log_tail where the
 * next message goes.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "nvram.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/sys/Logger.h"
#include "../../common/sys/ipmi.h"
#include "../../common/sys/l3paths.h"
#include "../sys/syslogLib.h"

#define IUA_SIZE        ((uint32)sizeof(nvramInternalUseArea))
#define LOG_MARK        0xf0    /* starts a message: the time follows */
#define LOG_TIME_BYTES  4
#define LOG_TIME_TEXT   18      /* "%m/%d/%y %X " */

static void nvramInitIUA(void);
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
int32 nvramSim;                 /* no file: start empty, never save */
static int nvram_lock;          /* no saving while nvramInit() checks the image */
static int nvram_initialized;   /* the mode nvramInit() was given */
nvramInstance nvram;
static uint8 nvramTempCopy[NVRAM_SIZE];
static char nvram_file[1024];   /* original: 40; paths are configurable now */

/* The NVRAM image is the file's bytes: its layout must not depend on the host. */
_Static_assert(sizeof(nvramInternalUseArea) == 2092, "NVRAM internal use area layout");

_Static_assert(offsetof(nvramInternalUseArea, ip_addr) == 56 &&
               offsetof(nvramInternalUseArea, autopower_delay) == 192 &&
               offsetof(nvramInternalUseArea, log_start) == 2072, "NVRAM field offsets");

/* multi-byte fields of the image are little-endian, as the i386 tools wrote them */
static uint32 nv32(const nvle32 *f)
{
  return (uint32)f->b[0] | (uint32)f->b[1] << 8 | (uint32)f->b[2] << 16 | (uint32)f->b[3] << 24;
}

static void nv32set(nvle32 *f, uint32 v)
{
  f->b[0] = (uint8)v;
  f->b[1] = (uint8)(v >> 8);
  f->b[2] = (uint8)(v >> 16);
  f->b[3] = (uint8)(v >> 24);
}

/* log_* fields are offsets into the NVRAM image (see nvram.h) */
#define LOGPTR(off) ((nvramLog *)(nvramTempCopy + (off)))
#define LOGOFF(p)   ((uint32)((uint8 *)(p) - nvramTempCopy))

/* the internal use area the common header points to */
static nvramInternalUseArea *iua_of(ipmiCommonHeader *ch)
{
  return (nvramInternalUseArea *)((uint8 *)ch + ch->internal_use_area * 8);
}

/* after a change to the settings */
static void iua_changed(void)
{
  nvramIUA->checksum = ipmiCalcCSum((uint8 *)nvramIUA,IUA_SIZE);
  if (nvram_initialized == NVRAM_READWRITE)
    nvramSave(nvramTempCopy,NVRAM_SIZE);
}

/*
 * Load the image and check it: a bad header or settings area is
 * initialized, a log ring that is not where this layout puts it is reset;
 * each logs why and makes the result -1. NVRAM_READONLY is quietly done
 * once (nvramGet() calls it); otherwise only the first call does anything.
 */
int nvramInit(int mode)
{
  int bad_ch, bad_iua, bad_log = 0;
  uint32 start, end;

  if (mode == NVRAM_READONLY) {
    if (nvram_initialized)
      return 0;
  }
  else {
    if (nvramCount != 0) {
      syslog(4,"nvram.c",83,0,"nvram already initialized!");
      return 0;
    }
    nvramCount = 1;
  }
  if (nvramLoad(nvramTempCopy,NVRAM_SIZE) < 0)
    return -1;
  nvram_lock = 1;

  nvramCH = (ipmiCommonHeader *)nvramTempCopy;
  bad_ch = ipmiCheckCSum(nvramTempCopy,sizeof(ipmiCommonHeader)) != 0;
  if (bad_ch)
    nvramInitCH();
  if (nvramCH->version == 0 || nvramCH->internal_use_area == 0) {
    bad_ch = 1;
    nvramInitCH();
  }
  nvramIUA = iua_of(nvramCH);
  bad_iua = ipmiCheckCSum((uint8 *)nvramIUA,IUA_SIZE) != 0;
  if (bad_iua)
    nvramInitIUA();
  if (nvramIUA->version == 1) {
    /* version 1 had no multisys setting. (Neither checksummed nor, with
     * nvram_lock set, saved here: the next change does both.) */
    nvramIUA->version = 2;
    nvramIUA->multisys = 1;
    nvramSave(nvramTempCopy,NVRAM_SIZE);
  }

  nvramLogStart = (nvramLog *)(nvramIUA + 1);
  nvramLogEnd = (nvramLog *)(nvramTempCopy + NVRAM_LOG_END);
  start = nv32(&nvramIUA->log_start);
  end = nv32(&nvramIUA->log_end);
  if (start != LOGOFF(nvramLogStart) || end != NVRAM_LOG_END ||
      nv32(&nvramIUA->log_head) < start || end <= nv32(&nvramIUA->log_head) ||
      nv32(&nvramIUA->log_tail) < start || end <= nv32(&nvramIUA->log_tail)) {
    bad_log = 1;
    nv32set(&nvramIUA->log_start,LOGOFF(nvramLogStart));
    nv32set(&nvramIUA->log_end,LOGOFF(nvramLogEnd));
    nvramLogReset();
  }
  if (bad_ch)
    nvramLogInsert("checksum error (CH) - nvram reset.");
  else if (bad_iua)
    nvramLogInsert("checksum error (IUA) - nvram reset.");
  else if (bad_log)
    nvramLogInsert("log size changed - log reset.");
  nvram_lock = 0;
  if (mode == NVRAM_READWRITE)
    nvramSave(nvramTempCopy,NVRAM_SIZE);
  nvram_initialized = mode;
  return bad_ch || bad_iua || bad_log ? -1 : 0;
}

/* back to factory settings ("nvram reset") */
int nvramReset(void)
{
  nvramInitCH();
  if (nvram_initialized == NVRAM_READWRITE)
    nvramSave(nvramTempCopy,NVRAM_SIZE);
  return 0;
}

/* empty settings, version 2 (rack 0, multisys on) */
static void nvramInitIUA(void)
{
  memset(nvramIUA,0,sizeof(nvramInternalUseArea));
  nvramIUA->version = 2;
  nvramIUA->rack = 0;
  nvramIUA->multisys = 1;
  nvramIUA->checksum = ipmiCalcCSum((uint8 *)nvramIUA,IUA_SIZE);
}

/* a header (version 1) with the settings right after it, initialized */
static void nvramInitCH(void)
{
  memset(nvramCH,0,sizeof(ipmiCommonHeader));
  nvramCH->version = 1;
  nvramCH->internal_use_area = 1;
  nvramCH->checksum = ipmiCalcCSum((uint8 *)nvramCH,sizeof(ipmiCommonHeader));
  nvramIUA = iua_of(nvramCH);
  nvramInitIUA();
}

/* copy a string setting, truncated, zero-filled */
static void set_string(char *field, size_t size, uintptr_t value)
{
  memset(field,0,size);
  if (value != 0)
    strncpy(field,(char *)value,size - 1);
}

/* change a setting (unless nvramInit() has not run) */
void nvramSet(int32 location, uintptr_t value)   /* original: uint32 value; string fields pass a pointer */
{
  nvramInternalUseArea *iua = nvramIUA;

  if (!(nvram_initialized & NVRAM_READWRITE))
    return;
  switch (location) {
  case NVRAM_RACK:              iua->rack = value; break;
  case NVRAM_AUTO_POWERUP:      iua->auto_powerup = value; break;
  case NVRAM_SERIAL:            set_string(iua->system_serial_number,sizeof(iua->system_serial_number),value); break;
  case NVRAM_SYSNAME:           set_string(iua->system_name,sizeof(iua->system_name),value); break;
  case NVRAM_MULTISYS:          iua->multisys = value; break;
  case NVRAM_IP_ADDR:           nv32set(&iua->ip_addr,value); break;
  case NVRAM_IP_NETMASK:        nv32set(&iua->ip_netmask,value); break;
  case NVRAM_IP_BROADCAST:      nv32set(&iua->ip_broadcast,value); break;
  case NVRAM_L2DSP_DISABLED:    iua->l2dsp_disabled = value; break;
  case NVRAM_L1USB_DEBUG:       nv32set(&iua->l1usb_debug,value); break;
  case NVRAM_PING_MIN:          nv32set(&iua->ping_min,value); break;
  case NVRAM_PING_MAX:          nv32set(&iua->ping_max,value); break;
  case NVRAM_PING_SENDER:       nv32set(&iua->ping_sender,value); break;
  case NVRAM_PING_L2FREQ:       nv32set(&iua->ping_l2freq,value); break;
  case NVRAM_PING_L1FREQ:       nv32set(&iua->ping_l1freq,value); break;
  case NVRAM_DHCPS_DISABLED:    iua->dhcps_disabled = value; break;
  case NVRAM_TIMEZONE:          set_string(iua->timezone,sizeof(iua->timezone),value); break;
  case NVRAM_MODEM_BAUD:        iua->modem_baud = value; break;
  case NVRAM_PASSWORD:          set_string(iua->password,sizeof(iua->password),value); break;
  case NVRAM_AUTOPOWER_DELAY:   nv32set(&iua->autopower_delay,value); break;
  case NVRAM_SLOW_PWRUP:        iua->slow_pwrup = value; break;
  case NVRAM_SLOT:              iua->slot = value; break;
  case NVRAM_BROADCAST_TIMEOUT: iua->broadcast_timeout = value; break;
  case NVRAM_TARGET_TIMEOUT:    iua->target_timeout = value; break;
  case NVRAM_IP_GATEWAY:        nv32set(&iua->ip_gateway,value); break;
  case NVRAM_MASTER_SLAVE:      iua->master_slave = value; break;
  default:
    return;
  }
  iua_changed();
}

/* a setting: a number, or for the string fields a pointer to the string
 * in the image; 0xffffffff for an unknown field. uintptr_t (the original's
 * uint32) holds either on any architecture. */
uintptr_t nvramGet(int32 location)
{
  nvramInternalUseArea *iua;

  if (!(nvram_initialized & NVRAM_READONLY))
    nvramInit(NVRAM_READONLY);
  iua = nvramIUA;
  switch (location) {
  case NVRAM_RACK:              return iua->rack;
  case NVRAM_AUTO_POWERUP:      return iua->auto_powerup;
  case NVRAM_SERIAL:            return (uintptr_t)iua->system_serial_number;
  case NVRAM_SYSNAME:           return (uintptr_t)iua->system_name;
  case NVRAM_MULTISYS:          return iua->multisys;
  case NVRAM_IP_ADDR:           return nv32(&iua->ip_addr);
  case NVRAM_IP_NETMASK:        return nv32(&iua->ip_netmask);
  case NVRAM_IP_BROADCAST:      return nv32(&iua->ip_broadcast);
  case NVRAM_L2DSP_DISABLED:    return iua->l2dsp_disabled;
  case NVRAM_L1USB_DEBUG:       return nv32(&iua->l1usb_debug);
  case NVRAM_PING_MIN:          return nv32(&iua->ping_min);
  case NVRAM_PING_MAX:          return nv32(&iua->ping_max);
  case NVRAM_PING_SENDER:       return nv32(&iua->ping_sender);
  case NVRAM_PING_L2FREQ:       return nv32(&iua->ping_l2freq);
  case NVRAM_PING_L1FREQ:       return nv32(&iua->ping_l1freq);
  case NVRAM_DHCPS_DISABLED:    return iua->dhcps_disabled;
  case NVRAM_TIMEZONE:          return (uintptr_t)iua->timezone;
  case NVRAM_MODEM_BAUD:        return iua->modem_baud;
  case NVRAM_PASSWORD:          return (uintptr_t)iua->password;
  case NVRAM_AUTOPOWER_DELAY:   return nv32(&iua->autopower_delay);
  case NVRAM_SLOW_PWRUP:        return iua->slow_pwrup;
  case NVRAM_SLOT:              return iua->slot;
  case NVRAM_BROADCAST_TIMEOUT: return iua->broadcast_timeout;
  case NVRAM_TARGET_TIMEOUT:    return iua->target_timeout;
  case NVRAM_IP_GATEWAY:        return nv32(&iua->ip_gateway);
  case NVRAM_MASTER_SLAVE:      return iua->master_slave;
  default:                      return 0xffffffff;
  }
}

/* empty the log */
void nvramLogReset(void)
{
  nvramIUA->log_head = nvramIUA->log_start;
  nvramIUA->log_tail = nvramIUA->log_start;   /* byte copies: no conversion */
  iua_changed();
}

/* the log ring's offsets in host order while a message is added */
typedef struct {
  uint32 start, end, head, tail;
} nvramLogRing;

static void nvramLogPut(nvramLogRing *r, char c)
{
  *LOGPTR(r->tail) = c;
  r->tail++;
  if (r->end <= r->tail) {
    r->tail = r->start;
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
  /* (the original looked at the byte before an empty message) */
  int add_newline = size == 0 || message[size - 1] != '\n';
  int32 fre;
  int i;
  nvramLogRing r;

  r.start = nv32(&iua->log_start);
  r.end = nv32(&iua->log_end);
  r.head = nv32(&iua->log_head);
  r.tail = nv32(&iua->log_tail);
  /* After nvramReset() the ring is all zero until the next nvramInit(); the
   * original went looking for a newline to drop and crashed l2. */
  if (r.end <= r.start || r.end - r.start <= (uint32)size + 6)
    return;
  fre = r.end - r.start;
  if (r.head < r.tail) {
    fre = r.head + (r.end - r.tail - r.start);
  }
  else if (r.tail < r.head) {
    fre = r.head - r.tail;
  }
  for (; fre <= size + 5 + add_newline; fre++) {
    /* drop the oldest message (the original only wraps head inside the loop) */
    while (*LOGPTR(r.head++) != '\n') {
      fre++;
      if (r.end <= r.head) {
        r.head = r.start;
      }
    }
  }
  nvramLogPut(&r, (char)LOG_MARK);
  for (i = 0; i < LOG_TIME_BYTES; i++) {
    nvramLogPut(&r, (char)(tval >> (8 * i)));
  }
  for (i = 0; i < size; i++) {
    nvramLogPut(&r, message[i]);
  }
  if (add_newline) {
    nvramLogPut(&r, '\n');
  }
  nv32set(&iua->log_head,r.head);
  nv32set(&iua->log_tail,r.tail);
  iua_changed();
}

void nvramLogFinsert(char *fmt, ...)
{
  char buff[160];
  va_list ap;

  /* ORIGINAL BUG (fixed, see ORIGINAL_BUGS.md): the original passed the va_list
   * to snprintf, not vsnprintf, so any % conversion printed garbage. */
  va_start(ap,fmt);
  vsnprintf(buff,sizeof(buff),fmt,ap);
  va_end(ap);
  nvramLogInsert(buff);
}

/* a run of the log ring */
struct log_span {
  nvramLog *beg, *end;
};

/*
 * The log as text, the times as "%m/%d/%y %X " (malloc()ed). A message's
 * time may continue in the next span.
 */
char *nvramLogFetch(void)
{
  uint32 head = nv32(&nvramIUA->log_head);
  uint32 tail = nv32(&nvramIUA->log_tail);
  struct log_span spans[2];
  int nspans, span, tcnt;
  uint32 tbits = 0;
  time_t tval;
  char *messages, *c;
  int size, bsize;

  if (head < tail) {
    spans[0].beg = LOGPTR(head);
    spans[0].end = LOGPTR(tail);
    nspans = 1;
  }
  else {
    /*
     * ORIGINAL BUG (kept, ORIGINAL_BUGS.md): the wrapped ring, head to
     * log_end then log_start to tail, was meant to be read here, but the
     * original tests head < tail a second time, so a log that has wrapped
     * reads as empty.
     */
    return strdup("");
  }

  /* measure */
  size = 1;
  tcnt = 0;
  for (span = 0; span < nspans; span++) {
    for (c = spans[span].beg; c < spans[span].end; c++) {
      if (tcnt != 0)
        tcnt--;
      else if ((unsigned char)*c == LOG_MARK) {
        size += LOG_TIME_TEXT;
        tcnt = LOG_TIME_BYTES;
      }
      else
        size++;
    }
  }
  bsize = size < 100 ? 100 : size + 1;
  messages = malloc(bsize);
  if (messages == NULL)
    return NULL;

  size = 0;
  tcnt = 0;
  for (span = 0; span < nspans; span++) {
    for (c = spans[span].beg; c < spans[span].end; c++) {
      if (tcnt == 0) {
        if ((unsigned char)*c == LOG_MARK) {
          tbits = 0;
          tcnt = LOG_TIME_BYTES;
        }
        else {
          messages[size++] = *c;
        }
        continue;
      }
      tbits |= (uint32)(unsigned char)*c << (8 * (LOG_TIME_BYTES - tcnt));
      if (--tcnt == 0) {
        tval = (time_t)tbits;
        strftime(messages + size,LOG_TIME_TEXT + 1,"%m/%d/%y %X ",localtime(&tval));
        size += strlen(messages + size);
      }
    }
  }
  messages[size] = '\0';
  return messages;
}

/* The original rebased the IUA's log pointers between the in-memory image
 * (absolute) and the file (offsets). They are offsets in both now, so only
 * the checksum is refreshed, as the original did after rebasing. (So a
 * damaged settings area in the file passes the check in nvramInit().) */
static void nvramNormalizePointers(ipmiCommonHeader *nvbuf, uint32 old_base, uint32 new_base)
{
  nvramInternalUseArea *iua = iua_of(nvbuf);

  (void)old_base;
  (void)new_base;
  iua->checksum = ipmiCalcCSum((uint8 *)iua,IUA_SIZE);
}

/* read the file; a missing one is created empty */
static int nvramLoad(uint8 *buf, int size)
{
  static int first = 1;
  int rval;
  int fd;

  if (nvramSim) {
    memset(buf,0,size);
    return 0;
  }
  if (first) {
    first = 0;
    /* original: "./.l2_NVRAM", or "./.l2_NVRAM.<bias/10>" (SGI_L2_NVRAM overrides) */
    snprintf(nvram_file,sizeof(nvram_file),"%s",l3path_nvram(IR_PORT_BIAS));
  }
  fd = open(nvram_file,O_RDONLY,0666);
  if (fd < 0) {
    if (errno == ENOENT) {
      syslog(6,"nvram.c",1029,0,"NVRAM file \'%s\' doesn\'t exist.....initializing",nvram_file);
      memset(buf,0,size);
      nvramSave(buf,size);
      return 0;
    }
    syslog(1,"nvram.c",1036,0,"can\'t open the NVRAM file \'%s\' for reading: %s",nvram_file,
           LoggerDefaultMessage(errno));
    return -1;
  }
  rval = read(fd,buf,size);
  if (rval < 0) {
    syslog(1,"nvram.c",1045,0,"can\'t read the NVRAM file \'%s\': %s",nvram_file,
           LoggerDefaultMessage(errno));
    close(fd);
    return -1;
  }
  nvramNormalizePointers((ipmiCommonHeader *)buf,0,0);
  close(fd);
  return rval;
}

/* write the file (not while nvramInit() holds nvram_lock) */
static int nvramSave(uint8 *buf, int size)
{
  int rval;
  int fd;

  if (nvramSim)
    return 0;
  if (nvram_lock > 0)
    return -1;
  fd = open(nvram_file,O_WRONLY | O_CREAT | O_TRUNC,0666);
  if (fd < 0) {
    syslog(4,"nvram.c",1076,0,"can\'t open the NVRAM file \'%s\' for writing: %s",nvram_file,
           LoggerDefaultMessage(errno));
    return -1;
  }
  nvramNormalizePointers((ipmiCommonHeader *)buf,0,0);
  rval = write(fd,buf,size);
  if (rval < 0)
    syslog(4,"nvram.c",1087,0,"can\'t write the NVRAM file \'%s\': %s",nvram_file,
           LoggerDefaultMessage(errno));
  nvramNormalizePointers((ipmiCommonHeader *)buf,0,0);
  close(fd);
  return rval < 0 ? -1 : rval;
}
