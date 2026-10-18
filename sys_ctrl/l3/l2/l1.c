/*
 * sys_ctrl/l3/l2/l1.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l1.c
 */

#include "../../common/Router/SocketIO.h"   /* needed by the reconstruction */
#include "dmp.h"   /* needed by the reconstruction */
#include "irtr.h"   /* needed by the reconstruction */
#include "l2.h"
#include "l1.h"
#include "smp.h"
#include "l2cmd.h"
#include "dest.h"
#include "cfg.h"
#include "format.h"
#include "serial.h"
#include "../main/nvram.h"
#include "l1net.h"
#include "l1sim.h"
#include "sgil1.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */
void dmp(char *s, unsigned char *bptr, int blen, int newline);

static char *l1_usb_path_str(sgil1_cfg_t *cfg, int format);

int l1_throttle_freq = 50;
unsigned char l1_pkt_in[1] = { 24 };
unsigned char l1_pkt_out[1] = "\r";
static char **l1_usbpath_list;
static int l1_usbpath_count;
static int l1_usbpath_size;
static int l1_do_ioctls = 1;
static int sgil1_rev;
int l1usb_debug;
EventID l1_throttle_timerid;
PPPInstance ppp;
unsigned char ppp_ibuf[8];
unsigned char ppp_obuf[256];
static int lasterr[64];
static int lastcnt[64];
static char lastdev[64][60];

int l1_fd_device(int fd)
{
  int dev;
  
  dev = 0;
  while( true ) {
    if (0x27 < dev) {
      return -1;
    }
    if (l2_l1_ports[dev].fd == fd) break;
    dev = dev + 1;
  }
  return dev;
}

int l1_open_usb(void)
{
  int *piVar1;
  char *pcVar2;
  int iVar3;
  int i;
  int status;
  int device;
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_open_usb() in\n");
  }
  l1usb_debug = nvramGet(10);
  if (l1usb_debug != 0) {
    fprintf(stderr,"INFO: initializing USB debug setting to %d from NVRAM\n",l1usb_debug);
  }
  l2_l1_device = (char *)l3path_dev("sgil1_cs");   /* original: "/dev/sgil1_cs" */
  l2_l1_control = open(l2_l1_device,0);
  if (l2_l1_control < 0) {
    piVar1 = __errno_location();
    pcVar2 = strerror(*piVar1);
    fprintf(stderr,"ERROR: can\'t open USB control %s, %s\n",l2_l1_device,pcVar2);
    iVar3 = -1;
  }
  else {
    fprintf(stderr,"INFO: opened USB control %s\n",l2_l1_device);
    iVar3 = ioctl(l2_l1_control,0x80045306,&sgil1_rev);
    if (iVar3 < 0) {
      sgil1_rev = 0;
    }
    if (l1_usbpath_count != 0) {
      if (sgil1_rev < 2) {
        fprintf(stderr,
                "ERROR:  the USB path option (-usbpath) was specified, but the L1 USB kernel\n        driver (rev %d) doesn\'t support it!\nPlease update your L1 USB kernel driver.\n"
                ,sgil1_rev);
        close(l2_l1_control);
        return -1;
      }
      fprintf(stderr,"INFO:  monitoring for L1 USB devices on the following USB paths:\n");
      for (i = 0; i < l1_usbpath_count; i = i + 1) {
        fprintf(stderr,"       %s\n",l1_usbpath_list[i]);
      }
    }
    iVar3 = ioctl(l2_l1_control,0x80045306,&sgil1_rev);
    if (iVar3 < 0) {
      sgil1_rev = 0;
    }
    l1_service_usb(0,0);
    EventAddInput(l2_l1_control,l1_service_usb,(EventData)0x0,"l1_open_usb");
    if (l2_debug != 0) {
      fprintf(stderr,"l1_open_usb() out\n");
    }
    iVar3 = 0;
  }
  return iVar3;
}

int l1_usb_ioctl(int fd, int request)
{
  int iVar1;
  
  if (l1_do_ioctls == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = ioctl(fd,request,0);
  }
  return iVar1;
}

int l1_flush_usb_device(int fd, int reset)
{
  int iVar1;
  int *piVar2;
  char *pcVar3;
  
  if (sgil1_rev < 1) {
    iVar1 = l1_usb_ioctl(fd,0x5302);
    if (iVar1 != 0) {
      piVar2 = __errno_location();
      pcVar3 = strerror(*piVar2);
      fprintf(stderr,"SGIL1_RESET_WRITE error, %s\n",pcVar3);
      iVar1 = l1_usb_ioctl(fd,0x5303);
      if (iVar1 != 0) {
        piVar2 = __errno_location();
        pcVar3 = strerror(*piVar2);
        fprintf(stderr,"SGIL1_RESET_DEVICE error, %s\n",pcVar3);
        return -1;
      }
      return 0;
    }
    iVar1 = l1_usb_ioctl(fd,0x5301);
    if (iVar1 != 0) {
      piVar2 = __errno_location();
      pcVar3 = strerror(*piVar2);
      fprintf(stderr,"SGIL1_RESET_READ error, %s\n",pcVar3);
      iVar1 = l1_usb_ioctl(fd,0x5303);
      if (iVar1 != 0) {
        piVar2 = __errno_location();
        pcVar3 = strerror(*piVar2);
        fprintf(stderr,"SGIL1_RESET_DEVICE error, %s\n",pcVar3);
        return -1;
      }
      return 0;
    }
  }
  else {
    iVar1 = l1_usb_ioctl(fd,0x5305);
    if (iVar1 != 0) {
      return -1;
    }
  }
  if ((reset == 0) || (iVar1 = l1_usb_ioctl(fd,0x5303), iVar1 == 0)) {
    iVar1 = 0;
  }
  else {
    piVar2 = __errno_location();
    pcVar3 = strerror(*piVar2);
    fprintf(stderr,"SGIL1_RESET_DEVICE error, %s\n",pcVar3);
    iVar1 = -1;
  }
  return iVar1;
}

static char *l1_usb_path_str(sgil1_cfg_t *cfg, int format)
{
  static char path[80];
  size_t sVar1;
  uint uVar2;
  char *pcVar3;
  int i;
  
  if (format == 0) {
    sprintf((char *)&path,"b%u;p",(uint)cfg->bus);
  }
  if (format == 1) {
    sprintf((char *)&path,"  bus: %u  path: ",(uint)cfg->bus);
  }
  if (format == 2) {
    sprintf((char *)&path,"b%u;p",(uint)cfg->bus);
  }
  for (i = 0; i < (int)(uint)cfg->level; i = i + 1) {
    if (i != 0) {
      strcat((char *)&path,"/");
    }
    uVar2 = (uint)cfg->path[i];
    pcVar3 = "%d";
    sVar1 = strlen((char *)&path);
    sprintf((char *)(sVar1 + 0x8095020),pcVar3,uVar2);
  }
  if (format == 0) {
    uVar2 = (uint)cfg->dev;
    pcVar3 = ";d%d";
    sVar1 = strlen((char *)&path);
    sprintf((char *)&path + sVar1,pcVar3,uVar2);
  }
  if (format == 1) {
    uVar2 = (uint)cfg->dev;
    pcVar3 = "  dev: %d";
    sVar1 = strlen((char *)&path);
    sprintf((char *)(sVar1 + 0x8095020),pcVar3,uVar2);
  }
  return (char *)&path;
}

int l1_open_usb_device(int device)
{
  int fd;
  int *piVar1;
  char *pcVar2;
  int plen;
  int llen;
  int iVar3;
  int iVar4;
  FILE *stream;
  EventID EVar5;
  sgil1_cfg_t cfg_;
  int i;
  char *path;
  sgil1_cfg_t cfg;
  char usbpath [40];
  char usb_cfg [60];
  char dev_name [512];   /* original: 20; the device dir is configurable now */
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_open_usb_device(%d) in\n",device);
  }
  if ((l1_usbpath_count != 0) && (1 < sgil1_rev)) {
    cfg.dev = (uchar)device;
    fd = ioctl(l2_l1_control,0xc0095307,&cfg);
    if (fd != 0) {
      piVar1 = __errno_location();
      pcVar2 = strerror(*piVar1);
      fprintf(stderr,"SGIL1_ST_READ_DEV_CFG error, %s\n",pcVar2);
      return -1;
    }
    pcVar2 = l1_usb_path_str(&cfg,2);
    plen = strlen(pcVar2);
    for (i = 0; i < l1_usbpath_count; i = i + 1) {
      llen = strlen(l1_usbpath_list[i]);
      iVar3 = strncmp(pcVar2,l1_usbpath_list[i],llen);
      if ((iVar3 == 0) &&
         (((llen < plen || (l1_usbpath_list[i][plen] == '\0')) || (l1_usbpath_list[i][plen] == '/'))
         )) break;
    }
    if (i == l1_usbpath_count) {
      return 0;
    }
  }
  sprintf(dev_name,"%s/sgil1_%d",l3path_dev_dir(),device);   /* original: "/dev/sgil1_%d" */
  usb_cfg[0] = '\0';
  usbpath[0] = '\0';
  iVar3 = open(dev_name,2);
  if (iVar3 < 0) {
    piVar1 = __errno_location();
    pcVar2 = strerror(*piVar1);
    fprintf(stderr,"ERROR: can\'t open %s, %s\n",dev_name,pcVar2);
    iVar3 = -1;
  }
  else {
    if (l1_do_ioctls != 0) {
      iVar4 = ioctl(iVar3,0x80095304,&cfg_);
      if (iVar4 == 0) {
        pcVar2 = l1_usb_path_str(&cfg_,1);
        strcpy(usb_cfg,pcVar2);
        pcVar2 = l1_usb_path_str(&cfg_,0);
        strcpy(usbpath,pcVar2);
        l1_flush_usb_device(iVar3,0);
      }
      else {
        piVar1 = __errno_location();
        if ((*piVar1 == 0x16) || (piVar1 = __errno_location(), *piVar1 == 0x19)) {
          l1_do_ioctls = 0;
        }
        else {
          piVar1 = __errno_location();
          pcVar2 = strerror(*piVar1);
          fprintf(stderr,"SGIL1_READ_CFG error, %s\n",pcVar2);
        }
      }
    }
    stream = stderr;
    if (l1usb_debug != 0) {
      stream = NULL;
    }
    fprintf(stream,"INFO: opened USB device at %s (%s)\n",usbpath,dev_name);
    if (l2_l1_local_port == -1) {
      l2_l1_local_port = device;
    }
    strcpy(l2_l1_ports[device].device,dev_name);
    strcpy(l2_l1_ports[device].usbpath,usbpath);
    l2_l1_ports[device].fd = iVar3;
    lasterr[iVar3] = 0;
    lastcnt[iVar3] = 0;
    iVar4 = L2CfgMAddPort(&L2CfgLocal,device,dev_name,usbpath,2,iVar3);
    if (iVar4 == -1) {
      fprintf(stderr,"ERROR: device is already in use.\n");
      iVar3 = -1;
    }
    else {
      EVar5 = EventAddTimeOut(0,750000,cfg_ping_l1,(EventData)device,"l1_open_usb_device");
      l2_l1_ports[device].timer = EVar5;
      EventAddInput(l2_l1_ports[device].fd,l1_read_packet,(EventData)device,"l1_open_usb_device");
      if (l2_debug != 0) {
        fprintf(stderr,"l1_open_usb_device() out, fd: %d\n",iVar3);
      }
      iVar3 = 0;
    }
  }
  return iVar3;
}

int l1_close_usb_device(int device, int reopen, char *who)
{
  EventID id;
  char *dname;
  int iVar1;
  int *piVar2;
  char *pcVar3;
  FILE *stream;
  int fd;
  int part;
  int slot;
  int rack;
  
  if (-1 < device) {
    if (l2_debug != 0) {
      fprintf(stderr,"l1_close_usb_device(%d) in\n",device);
    }
    id = l2_l1_ports[device].fd;
    if (-1 < (int)id) {
      dname = L2CfgMDeviceName(&L2CfgLocal,id);
      EventRemoveInput(id);
      EventRemoveTimeOut(l2_l1_ports[device].timer);
      l2_l1_ports[device].fd = -1;
      l2_l1_ports[device].status = 0;
      l2_l1_ports[device].wr_errcnt = 0;
      l2_l1_ports[device].rd_errcnt = 0;
      l2_l1_ports[device].timer = 0;
      smp_chkcon_changes(0);
      L2CfgMCfgPort(&L2CfgLocal,device,NULL);
      smp_chkcon_changes(1);
      iVar1 = close(id);
      if (iVar1 != 0) {
        piVar2 = __errno_location();
        pcVar3 = strerror(*piVar2);
        fprintf(stderr,"ERROR: can\'t close %s, %s - %s\n",dname,device * 0x48 + 0x820d0a4,pcVar3);
        return -1;
      }
      stream = stderr;
      if (l1usb_debug != 0) {
        stream = NULL;
      }
      fprintf(stream,"INFO: closed %s\n",dname);
      cfg_configcheck(1);
    }
    if (l2_debug != 0) {
      fprintf(stderr,"l1_close_usb_device() out\n");
    }
    if (reopen != 0) {
      EventAddTimeOut(5,0,l1_service_usb,(EventData)0x0,"l1_close_usb_device");
    }
  }
  return 0;
}

void l1_service_usb(int data, int fd)
{
  int devices;
  int *piVar1;
  char *pcVar2;
  int device;
  char status [40];
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_service_usb_device(%d) in\n",fd);
  }
  devices = read(l2_l1_control,status,0x28);
  if (devices < 1) {
    fprintf(stderr,"WARNING: can\'t read USB connection status, ");
    if (devices < 0) {
      piVar1 = __errno_location();
      pcVar2 = strerror(*piVar1);
      fprintf(stderr,"%s\n",pcVar2);
    }
    else {
      fprintf(stderr,"no devices\n");
    }
  }
  else {
    for (device = 0; device < devices; device = device + 1) {
      if (((int)status[device] != l2_l1_ports[device].status) && (status[device] == '\0')) {
        l2_l1_ports[device].status = (int)status[device];
        l1_close_usb_device(device,0,"[driver]");
      }
    }
    for (device = 0; device < devices; device = device + 1) {
      if (((int)status[device] != l2_l1_ports[device].status) && (status[device] != '\0')) {
        l2_l1_ports[device].status = (int)status[device];
        l1_open_usb_device(device);
      }
    }
    if (l2_debug != 0) {
      fprintf(stderr,"l1_service_usb_device() out\n");
    }
  }
  return;
}

int l1_close_usb(void)
{
  int device;
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_close_usb() in\n");
  }
  for (device = 0; device < 0x28; device = device + 1) {
    if (l2_l1_ports[device].status != 0) {
      l1_close_usb_device(device,0,"[app close]");
    }
  }
  EventRemoveInput(l2_l1_control);
  close(l2_l1_control);
  fprintf(stderr,"INFO: closed USB control %s\n",l2_l1_device);
  if (l2_debug != 0) {
    fprintf(stderr,"l1_close_usb() out\n");
  }
  return 0;
}

int l1_open_serial_direct(void)
{
  int *piVar1;
  int iVar2;
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_open_serial_direct() in\n");
  }
  l2_l1_ports[0].fd = l1_tty_open(l2_l1_serial_device);
  if (l2_l1_ports[0].fd < 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"ERROR: can\'t open device %s, errno: %d\n",l2_l1_serial_device,*piVar1);
    iVar2 = -1;
  }
  else {
    lasterr[l2_l1_ports[0].fd] = 0;
    lastcnt[l2_l1_ports[0].fd] = 0;
    if (l2_l1_local_port == -1) {
      l2_l1_local_port = 0;
    }
    strcpy(l2_l1_ports[0].device,l2_l1_serial_device);
    if (l2_debug != 0) {
      fprintf(stderr,"l1_open_serial_direct() out\n");
    }
    iVar2 = 0;
  }
  return iVar2;
}

int l1_close_serial_direct(void)
{
  int iVar1;
  int *piVar2;
  
  iVar1 = l1_tty_close(l2_l1_ports[0].fd);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    piVar2 = __errno_location();
    fprintf(stderr,"ERROR: can\'t close device %s, errno: %d\n",l2_l1_serial_device,*piVar2);
    iVar1 = -1;
  }
  return iVar1;
}

int l1_open_serial_enet(void)
{
  int *piVar1;
  int iVar2;
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_open_serial_enet() in\n");
  }
  l2_l1_ports[0].fd = SocketMakeInetConnection(l2_l1_serial_hostname,l2_l1_serial_hostport,0);
  if (l2_l1_ports[0].fd < 0) {
    piVar1 = __errno_location();
    fprintf(stderr," ERROR: can\'t open connection %s:%d, errno: %d\n",l2_l1_serial_hostname,
            l2_l1_serial_hostport,*piVar1);
    iVar2 = -1;
  }
  else {
    lasterr[l2_l1_ports[0].fd] = 0;
    lastcnt[l2_l1_ports[0].fd] = 0;
    if (l2_l1_local_port == -1) {
      l2_l1_local_port = 0;
    }
    strcpy(l2_l1_ports[0].device,"ENET");
    if (l2_debug != 0) {
      fprintf(stderr,"l1_open_serial_enet() out\n");
    }
    iVar2 = 0;
  }
  return iVar2;
}

int l1_close_serial_enet(void)
{
  int iVar1;
  int *piVar2;
  
  iVar1 = SocketClose(l2_l1_ports[0].fd);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    piVar2 = __errno_location();
    fprintf(stderr," ERROR: can\'t close connection %s:%d, errno: %d\n",l2_l1_serial_hostname,
            l2_l1_serial_hostport,*piVar2);
    iVar1 = -1;
  }
  return iVar1;
}

void l1_open(void)
{
  int *piVar1;
  int iVar2;
  char echo [1];
  int status;
  int device;
  bool initialized;
  
  status = 0;
  initialized = false;
  memset(l2_l1_ports,0,0xb40);
  for (device = 0; device < 0x28; device = device + 1) {
    l2_l1_ports[device].fd = -1;
  }
  if (l2_debug != 0) {
    fprintf(stderr,"l1_open() in\n");
  }
  switch(l2_l1_conn_mode) {
  case 0:
    break;
  case 1:
    status = l1net_export();
    break;
  case 2:
    status = l1_open_usb();
    break;
  case 3:
    status = l1_open_serial_direct();
    break;
  case 4:
    status = l1_open_serial_enet();
    break;
  case 5:
    status = l1sim_export();
  }
  if (status != 0) {
    fprintf(stderr,"FATAL: can\'t open connection to L1\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if ((l2_l1_conn_mode < 5) && (2 < l2_l1_conn_mode)) {
    PPPInit(&ppp,ppp_ibuf,8,ppp_obuf,0x100,0,1,0x10,0,l1_ppperr,NULL);
    if (l2_l1_conn_mode == 3) {
      status = write(l2_l1_ports[0].fd,"\r",1);
    }
    else if (l2_l1_conn_mode == 4) {
      status = SocketWrite(l2_l1_ports[0].fd,"\r",1);
    }
    if (status != 1) {
      piVar1 = __errno_location();
      fprintf(stderr,"FATAL: can\'t initiate L1 protocol, errno: %d\n",*piVar1);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    sleep(2);
    if (l2_l1_conn_mode == 3) {
      status = write(l2_l1_ports[0].fd,"\x18",1);
    }
    else if (l2_l1_conn_mode == 4) {
      status = SocketWrite(l2_l1_ports[0].fd,"\x18",1);
    }
    if (status != 1) {
      piVar1 = __errno_location();
      fprintf(stderr,"FATAL: can\'t initiate L1 protocol, errno: %d\n",*piVar1);
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    while (!initialized) {
      piVar1 = __errno_location();
      *piVar1 = 0;
      if (l2_debug != 0) {
        fprintf(stderr,"l1_open() waiting\n");
      }
      if (l2_l1_conn_mode == 3) {
        status = read(l2_l1_ports[0].fd,echo,1);
      }
      else if (l2_l1_conn_mode == 4) {
        status = SocketRead(l2_l1_ports[0].fd,(uchar *)echo,1);
      }
      if (status < 1) {
        piVar1 = __errno_location();
        fprintf(stderr,"FATAL: can\'t confirm L1 protocol, errno: %d\n",*piVar1);
                    /* WARNING: Subroutine does not return */
        exit(1);
      }
      if (l2_debug != 0) {
        piVar1 = __errno_location();
        fprintf(stderr,"l1_open() read %02x, status %d, errno %d\n",(int)echo[0],status,*piVar1);
      }
      if (echo[0] == '\x18') {
        iVar2 = SocketNodelayMode(l2_l1_ports[0].fd,1);
        if (iVar2 != 0) {
          piVar1 = __errno_location();
          fprintf(stderr,"FATAL: can\'t set delay mode on L1 connection, status: %d, errno: %d\n",
                  iVar2,*piVar1);
                    /* WARNING: Subroutine does not return */
          exit(1);
        }
        iVar2 = L2CfgMAddPort(&L2CfgLocal,0,l2_l1_serial_device,NULL,1,l2_l1_ports[0].fd);
        if (iVar2 == -1) {
          fprintf(stderr,"WARNING: device is already in use.\n");
          return;
        }
        EventAddTimeOut(1,0,cfg_ping_l1,(EventData)l2_l1_ports[0].fd,"l1_open");
        EventAddInput(l2_l1_ports[0].fd,l1_read_packet,(EventData)0x0,"l1_open");
        initialized = true;
        status = 0;
      }
    }
  }
  if (l2_debug != 0) {
    fprintf(stderr,"l1_open() out\n");
  }
  return;
}

void l1_close(int fd)
{
  int status;
  
  status = 0;
  switch(l2_l1_conn_mode) {
  case 0:
    break;
  case 1:
  case 5:
    l1net_close(fd);
    break;
  case 2:
    status = l1_close_usb();
    break;
  case 3:
    EventRemoveInput(l2_l1_ports[0].fd);
    if (l2_l1_ports[0].timer != 0) {
      EventRemoveTimeOut(l2_l1_ports[0].timer);
    }
    l2_l1_ports[0].timer = 0;
    smp_input_l1sysco(serial_console,0xd);
    status = l1_close_serial_direct();
    break;
  case 4:
    EventRemoveInput(l2_l1_ports[0].fd);
    if (l2_l1_ports[0].timer != 0) {
      EventRemoveTimeOut(l2_l1_ports[0].timer);
    }
    l2_l1_ports[0].timer = 0;
    smp_input_l1sysco(serial_console,0xd);
    status = l1_close_serial_enet();
  }
  if (status == 0) {
    return;
  }
  fprintf(stderr,"FATAL: can\'t close connection to L1\n");
                    /* WARNING: Subroutine does not return */
  exit(1);
}

void l1_tty_debug(int td)
{
  int iVar1;
  int *piVar2;
  struct termios termios;
  int i;
  
  iVar1 = tcgetattr(td,(struct termios *)&termios);
  if (iVar1 == -1) {
    piVar2 = __errno_location();
    fprintf(stderr,"WARNING: can\'t get termios, errno: %d\n",*piVar2);
  }
  else {
    fprintf(stderr,"---\niflag:  0x%04x\n",termios.c_iflag);
    fprintf(stderr,"oflag:  0x%04x\n",termios.c_oflag);
    fprintf(stderr,"cflag:  0x%04x\n",termios.c_cflag);
    fprintf(stderr,"lflag:  0x%04x\n",termios.c_lflag);
    fprintf(stderr,"ispeed:  %8d\n",termios.c_ispeed);
    fprintf(stderr,"ospeed:  %8d\n",termios.c_ospeed);
    for (i = 0; i < 0x20; i = i + 1) {
      fprintf(stderr,"cc_c[0x%2x]: 0x%04x\n",i,(uint)termios.c_cc[i]);
    }
  }
  return;
}

int l1_tty_open(char *device)
{
  int td;
  int *piVar1;
  int iVar2;
  struct termios termios;
  
  td = open(device,2);
  if (td == -1) {
    piVar1 = __errno_location();
    fprintf(stderr,"ERROR: can\'t open %s, errno %d\n",device,*piVar1);
    td = -1;
  }
  else {
    iVar2 = tcgetattr(td,(struct termios *)&termios);
    if (iVar2 == -1) {
      piVar1 = __errno_location();
      fprintf(stderr,"ERROR: can\'t get termios, errno %d.\n",*piVar1);
      td = -1;
    }
    else {
      termios.c_iflag = 5;
      termios.c_oflag = 0;
      termios.c_cflag = 0x800008b0;
      termios.c_lflag = 0;
      termios.c_ospeed = 0xf;
      termios.c_ispeed = 0xf;
      termios.c_cc[6] = '\x01';
      termios.c_cc[5] = '\0';
      iVar2 = tcsetattr(td,0,(struct termios *)&termios);
      if (iVar2 == -1) {
        piVar1 = __errno_location();
        fprintf(stderr,"ERROR: can\'t put termios, errno %d.\n",*piVar1);
        td = -1;
      }
    }
  }
  return td;
}

int l1_tty_close(int td)
{
  int iVar1;
  struct termios termios;
  
  iVar1 = close(td);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

int l1_usb_recover(int fd, int error)
{
  int iVar1;
  int reopen;
  char *who;
  int device;
  
  if ((error == 0x13) || (error == 0x16)) {
    who = "[no device]";
    reopen = 0;
    iVar1 = l1_fd_device(fd);
    l1_close_usb_device(iVar1,reopen,who);
    iVar1 = 0;
  }
  else {
    iVar1 = 1;
  }
  return iVar1;
}

int l1_read_usb(int fd, unsigned char **bptr, int blen)
{
  int dev;
  int *piVar1;
  int status;
  char *pcVar2;
  int iVar3;
  int dev_still_open;
  undefined4 uVar4;
  
  uVar4 = 0;
  dev_still_open = 1;
  dev = l1_fd_device(fd);
  if (l2_debug != 0) {
    fprintf(stderr,"l1_read_usb(%d,%x(%x),%d) in\n",fd,bptr,*bptr,blen,dev,1,uVar4);
  }
  piVar1 = __errno_location();
  *piVar1 = 0;
  status = read(fd,*bptr + 0x10,blen);
  if (status < 0) {
    piVar1 = __errno_location();
    dev_still_open = l1_usb_recover(fd,*piVar1);
    if (dev_still_open != 0) {
      l2_l1_ports[dev].rd_errcnt = l2_l1_ports[dev].rd_errcnt + 1;
      if (2 < l2_l1_ports[dev].rd_errcnt) {
        pcVar2 = L2CfgMDeviceName(&L2CfgLocal,fd);
        fprintf(NULL,"WARNING: closing %s after multiple read errors\n",pcVar2);
        l1_flush_usb_device(fd,1);
        l1_close_usb_device(dev,1,"[rd error]");
        dev_still_open = 0;
      }
      if ((dev_still_open != 0) && (iVar3 = l1_usb_ioctl(fd,0x5301), iVar3 != 0)) {
        piVar1 = __errno_location();
        dev_still_open = l1_usb_recover(fd,*piVar1);
        if (dev_still_open != 0) {
          if (l2_debug != 0) {
            piVar1 = __errno_location();
            pcVar2 = strerror(*piVar1);
            fprintf(stderr,"SGIL1_RESET_READ error, %s\n",pcVar2);
          }
          iVar3 = l1_usb_ioctl(fd,0x5303);
          if (iVar3 != 0) {
            piVar1 = __errno_location();
            dev_still_open = l1_usb_recover(fd,*piVar1);
            if (dev_still_open != 0) {
              piVar1 = __errno_location();
              pcVar2 = strerror(*piVar1);
              fprintf(stderr,"SGIL1_RESET_DEVICE error, %s\n",pcVar2);
            }
          }
        }
      }
      goto LAB_0804c4f1;
    }
  }
  l2_l1_ports[dev].rd_errcnt = 0;
LAB_0804c4f1:
  if (l2_debug != 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"l1_read_usb() out, status %d, errno %d\n",status,*piVar1);
  }
  if (1 < l2_debug) {
    dmp("READ",*bptr + 0x10,status,1);
  }
  if (dev_still_open == 0) {
    status = 0;
  }
  return status;
}

int l1_read_raw(int fd, unsigned char *bptr, int blen)
{
  int *piVar1;
  int status;
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_read_raw(%d,%x,%d) in\n",fd,bptr,blen);
  }
  piVar1 = __errno_location();
  *piVar1 = 0;
  status = SocketRead(fd,bptr,blen);
  if (l2_debug != 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"l1_read_raw() out, status %d, errno %d\n",status,*piVar1);
  }
  if (1 < l2_debug) {
    dmp("READ",bptr,status,1);
  }
  return status;
}

int l1_read_socket(int fd, unsigned char *bptr, int blen)
{
  int *piVar1;
  int status;
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_read_socket(%d,%x,%d) in\n",fd,bptr,blen);
  }
  piVar1 = __errno_location();
  *piVar1 = 0;
  status = SocketRead(fd,bptr,blen);
  if (l2_debug != 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"l1_read_socket() out, status %d, errno %d\n",status,*piVar1);
  }
  if (1 < l2_debug) {
    dmp("READ",bptr,status,1);
  }
  return status;
}

int l1_read_ppp(int fd, unsigned char **bptr, int32 blen)
{
  int status;
  code *rfcn;
  
  if (l2_l1_conn_mode == 3) {
    rfcn = l1_read_raw;
  }
  else if (l2_l1_conn_mode == 4) {
    rfcn = l1_read_socket;
  }
  if (l2_debug != 0) {
    fprintf(stderr,"l1_read_ppp(%d,%x,%d) in\n",fd,bptr,blen);
  }
  status = PPPRead(&ppp,rfcn,(void *)fd,bptr,blen);
  if (l2_debug != 0) {
    fprintf(stderr,"l1_read_ppp() out\n");
  }
  return status;
}

int l1_read_l1net(int fd, unsigned char **pbptr, int blen)
{
  uchar *puVar1;
  uint16_t uVar2;
  int *piVar3;
  int status;
  uchar *bptr;
  
  puVar1 = *pbptr;
  bptr = puVar1 + 0x10;
  piVar3 = __errno_location();
  *piVar3 = 0;
  status = SocketRead(fd,bptr,2);
  if (0 < status) {
    uVar2 = ntohs(*(uint16_t *)bptr);
    status = SocketRead(fd,puVar1 + 0x12,uVar2 - 2);
    if (0 < status) {
      status = status + 2;
    }
  }
  return status;
}

void l1_throttle_input(int throttle)
{
  int device;
  
  if (throttle == 0) {
    if (l1_throttle_timerid != 0) {
      EventRemoveTimeOut(l1_throttle_timerid);
      l1_throttle_timerid = 0;
    }
  }
  else {
    l1_throttle_timerid =
         EventAddTimeOut(0,l1_throttle_freq * 1000,l1_throttle_input,(EventData)0x1,
                         "L1 input throttle");
  }
  for (device = 0; device < 0x28; device = device + 1) {
    if (-1 < l2_l1_ports[device].fd) {
      EventEnableInput(l2_l1_ports[device].fd,1);
    }
  }
  return;
}

void l1_read_packet(int port, int fd)
{
  int status;
  char *pcVar1;
  FILE *pFVar2;
  int err;
  int task;
  int type;
  IRPacket *p;
  code *rfcn;
  
  rfcn = NULL;
  if (l1_throttle_timerid != 0) {
    EventEnableInput(fd,0);
  }
  switch(l2_l1_conn_mode) {
  case 1:
  case 5:
    rfcn = l1_read_l1net;
    break;
  case 2:
    rfcn = l1_read_usb;
    break;
  case 3:
  case 4:
    rfcn = l1_read_ppp;
  }
  if (l2_debug != 0) {
    fprintf(stderr,"l1_read_packet(%x,%d) in\n",port,fd);
  }
  status = IRouterReadPacket(&l2_id,rfcn,(void *)fd,&p);
  if (status == 0) {
    if (1 < lastcnt[fd]) {
      pFVar2 = stderr;
      if (l2_l1_conn_mode == 2) {
        pFVar2 = NULL;
      }
      fprintf(pFVar2,"WARNING: last error on %s repeated %d times\n",lastdev + fd,lastcnt[fd]);
    }
    lastcnt[fd] = 0;
    lasterr[fd] = 0;
    p->_client_data = (uint8 *)port;
    IRouterSendPacket(NULL,p);
  }
  else if (status == -0x26d) {
    if ((l2_l1_conn_mode == 1) || (l2_l1_conn_mode == 5)) {
      l1_close(fd);
    }
  }
  else if (status == lasterr[fd]) {
    lastcnt[fd] = lastcnt[fd] + 1;
  }
  else {
    if (1 < lastcnt[fd]) {
      pFVar2 = stderr;
      if (l2_l1_conn_mode == 2) {
        pFVar2 = NULL;
      }
      fprintf(pFVar2,"WARNING: last read error on %s repeated %d times\n",lastdev + fd,lastcnt[fd]);
    }
    lasterr[fd] = status;
    lastcnt[fd] = 1;
    pcVar1 = L2CfgMDeviceName(&L2CfgLocal,fd);
    strcpy(lastdev[fd],pcVar1);
    pcVar1 = LoggerDefaultMessage(status);
    pFVar2 = stderr;
    if (l2_l1_conn_mode == 2) {
      pFVar2 = NULL;
    }
    fprintf(pFVar2,"WARNING: can\'t read packet from %s:   %s\n",lastdev + fd,pcVar1);
  }
  if (l2_debug != 0) {
    fprintf(stderr,"l1_read_packet() out\n");
  }
  return;
}

int l1_write_usb(int fd, unsigned char *bptr, int blen)
{
  int dev;
  int status;
  int *piVar1;
  char *pcVar2;
  int iVar3;
  int dev_still_open;
  
  dev_still_open = 1;
  iVar3 = blen;
  dev = l1_fd_device(fd);
  if (l2_debug != 0) {
    fprintf(stderr,"l1_write_usb(%d,%x,%d) in\n",fd,bptr,blen,dev,1,iVar3);
  }
  status = write(fd,bptr,blen);
  if (status < 0) {
    piVar1 = __errno_location();
    dev_still_open = l1_usb_recover(fd,*piVar1);
    if (dev_still_open != 0) {
      l2_l1_ports[dev].wr_errcnt = l2_l1_ports[dev].wr_errcnt + 1;
      if (2 < l2_l1_ports[dev].wr_errcnt) {
        pcVar2 = L2CfgMDeviceName(&L2CfgLocal,fd);
        fprintf(NULL,"WARNING: closing %s after multiple write errors\n",pcVar2);
        l1_flush_usb_device(fd,1);
        l1_close_usb_device(dev,1,"[wr error]");
        dev_still_open = 0;
      }
      if ((dev_still_open != 0) && (iVar3 = l1_usb_ioctl(fd,0x5302), iVar3 != 0)) {
        piVar1 = __errno_location();
        dev_still_open = l1_usb_recover(fd,*piVar1);
        if (dev_still_open != 0) {
          if (l2_debug != 0) {
            piVar1 = __errno_location();
            pcVar2 = strerror(*piVar1);
            fprintf(stderr,"SGIL1_RESET_WRITE error, %s\n",pcVar2);
          }
          iVar3 = l1_usb_ioctl(fd,0x5303);
          if (iVar3 != 0) {
            piVar1 = __errno_location();
            dev_still_open = l1_usb_recover(fd,*piVar1);
            if (dev_still_open != 0) {
              piVar1 = __errno_location();
              pcVar2 = strerror(*piVar1);
              fprintf(stderr,"SGIL1_RESET_DEVICE error, %s\n",pcVar2);
            }
          }
        }
      }
      goto LAB_0804cddd;
    }
  }
  l2_l1_ports[dev].wr_errcnt = 0;
LAB_0804cddd:
  if (l2_debug != 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"l1_write_usb() out, status %d, errno %d\n",status,*piVar1);
  }
  if (1 < l2_debug) {
    dmp("WRITE",bptr,blen,1);
  }
  if (dev_still_open == 0) {
    status = 0;
  }
  return status;
}

int l1_write_raw(int fd, unsigned char *bptr, int blen)
{
  int status;
  int *piVar1;
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_write_raw(%d,%x,%d) in\n",fd,bptr,blen,blen);
  }
  status = write(fd,bptr,blen);
  if (1 < l2_debug) {
    dmp("WRITE",bptr,blen,1);
  }
  if (l2_debug != 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"l1_write_raw() out, status %d, errno %d\n",status,*piVar1);
  }
  return status;
}

int l1_write_socket(int fd, unsigned char *bptr, int blen)
{
  int status;
  int *piVar1;
  
  if (l2_debug != 0) {
    fprintf(stderr,"l1_write_socket(%d,%x,%d) in\n",fd,bptr,blen,blen);
  }
  status = SocketWrite(fd,bptr,blen);
  if (1 < l2_debug) {
    dmp("WRITE",bptr,blen,1);
  }
  if (l2_debug != 0) {
    piVar1 = __errno_location();
    fprintf(stderr,"l1_write_socket() out, status %d, errno %d\n",status,*piVar1);
  }
  return status;
}

int l1_write_ppp(int fd, unsigned char *bptr, int blen)
{
  int status;
  code *wfcn;
  
  if (l2_l1_conn_mode == 3) {
    wfcn = l1_write_raw;
  }
  else if (l2_l1_conn_mode == 4) {
    wfcn = l1_write_socket;
  }
  if (l2_debug != 0) {
    fprintf(stderr,"l1_write_ppp(%d,%x,%d) in\n",fd,bptr,blen);
  }
  status = PPPWrite(&ppp,wfcn,(void *)fd,bptr,blen);
  if (l2_debug != 0) {
    fprintf(stderr,"l1_write_ppp() out\n");
  }
  return status;
}

int l1_write_l1net(int fd, unsigned char *bptr, int blen)
{
  int status;
  
  status = SocketWrite(fd,bptr,blen);
  return status;
}

void l1_write_packet(int fd, IRPacket *p)
{
  int status;
  char *pcVar1;
  char *pcVar2;
  IRAddress IVar3;
  code *wfcn;
  IRAddress dest;
  
  wfcn = NULL;
  if (l2_debug != 0) {
    fprintf(stderr,"l1_write_packet(%d, %x) in\n",fd,p);
  }
  switch(l2_l1_conn_mode) {
  case 1:
  case 5:
    wfcn = l1_write_l1net;
    break;
  case 2:
    wfcn = l1_write_usb;
    break;
  case 3:
  case 4:
    wfcn = l1_write_ppp;
  }
  IVar3 = p->_dest;
  status = IRouterWritePacket(&l2_id,wfcn,(void *)fd,p);
  if ((status != 0) && (status != -0x26e)) {
    pcVar1 = LoggerDefaultMessage(status);
    pcVar2 = L2CfgMDeviceName(&L2CfgLocal,fd);
    fprintf(NULL,"WARNING: can\'t write to %s [0x%08x]:   %s\n",pcVar2,IVar3,pcVar1);
  }
  if (l2_debug != 0) {
    fprintf(stderr,"l1_write_packet() out\n");
  }
  return;
}

void l1_ppperr(void *arg, int err, char *bptr, int blen)
{
  char *pcVar1;
  
  pcVar1 = LoggerDefaultMessage(err);
  fprintf(stderr,"WARNING: PPP error %s\n",pcVar1);
  return;
}

int l1_parse_usbpath(char *usbpath)
{
  int iVar1;
  char *pcVar2;
  size_t sVar3;
  size_t sVar4;
  char *pcVar5;
  char *eptr;
  char path2 [100];
  char path [100];
  char c2;
  char c1;
  int pathno;
  int busno;
  int i;
  char *ccptr;
  char *cptr;
  
  if (l1_usbpath_list != NULL) {
    for (i = 0; i < l1_usbpath_count; i = i + 1) {
      if (l1_usbpath_list[i] != NULL) {
        free(l1_usbpath_list[i]);
      }
    }
    free(l1_usbpath_list);
  }
  l1_usbpath_list = malloc(0x28);
  if (l1_usbpath_list == NULL) {
    fprintf(stderr,"ERROR: -usbpath: could not allocate memory to store USB path\n");
    iVar1 = -1;
  }
  else {
    l1_usbpath_count = 0;
    l1_usbpath_size = 10;
    ccptr = strdup(usbpath);
    cptr = ccptr;
    while ((cptr != NULL && (*cptr != '\0'))) {
      path2[0] = '\0';
      memset(path2 + 1,0,99);
      pcVar5 = cptr;
      pcVar2 = strchr(cptr,0x2c);
      if (pcVar2 == NULL) {
        cptr = NULL;
      }
      else {
        *pcVar2 = '\0';
        cptr = pcVar2 + 1;
      }
      iVar1 = sscanf(pcVar5,"%[Bb]%d;%[Pp]%d%s",&c1,&busno,&c2,&pathno,path2);
      if ((iVar1 < 4) &&
         (iVar1 = sscanf(pcVar5,"%[Bb]%d%[Pp]%d%s",&c1,&busno,&c2,&pathno,path2), iVar1 < 4)) {
        fprintf(stderr,"ERROR: -usbpath: invalid USB path:   \'%s\'\n",pcVar5);
        return -1;
      }
      if (path2[0] != '\0') {
        sVar3 = strspn(path2,"/0123456789");
        sVar4 = strlen(path2);
        if (sVar3 != sVar4) {
          fprintf(stderr,"ERROR: -usbpath: invalid USB path:   \'%s\'\n",pcVar5);
          return -1;
        }
      }
      sprintf(path,"b%d;p%d%s",busno,pathno,path2);
      if (l1_usbpath_count == l1_usbpath_size) {
        l1_usbpath_size = l1_usbpath_size + 10;
        l1_usbpath_list = realloc(l1_usbpath_list,l1_usbpath_size * 4);
        if (l1_usbpath_list == NULL) {
          fprintf(stderr,"-usbpath: could not allocate memory to store USB path\n");
          return -1;
        }
      }
      pcVar5 = strdup(path);
      l1_usbpath_list[l1_usbpath_count] = pcVar5;
      l1_usbpath_count = l1_usbpath_count + 1;
    }
    free(ccptr);
    iVar1 = 0;
  }
  return iVar1;
}
