/*
 * sys_ctrl/l3/l2/l2.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l2.c
 *
 * The L2 controller emulator: options, then start every service (L1 links,
 * the L2/L3 network ports, the consoles, discovery, auto power up) and run
 * the event loop.
 */

#define _GNU_SOURCE     /* REG_EIP, REG_RIP */
#include <execinfo.h>
#include <mcheck.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>
#include "l2.h"
#include "l1.h"
#include "smp.h"
#include "power.h"
#include "serial.h"
#include "enet.h"
#include "cfg.h"
#include "cmd.h"
#include "discover.h"
#include "irtr.h"
#include "broadcast.h"
#include "target.h"
#include "../main/nvram.h"
#include "../sys/syslogLib.h"
#include "../../common/sys/syslog.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */

/* the network ports, plus IR_PORT_BIAS */
#define L3_CMD_PORT         8000
#define L3_QUIET_PORT       8002
#define L2_PEER_PORT        9001
#define L2_APP_PORT         9002
#define L2_APP_QUIET_PORT   9004

#define MAX_COPY            128     /* --copy */

static void syslog_msg(int level, char *msg);
static void l2_flow_control(void *data, RouterClient *client, int overflow);
static void syntax(void) __attribute__((noreturn));

char *l2_myname = "guess";
int l2_debug;
int l2_discover;
int l2_l1_conn_mode = L2_CONN_USB;
int l2_l1_local_port = -1;      /* the first L1 port in use */
int l2_pc;                      /* -pc: a PC-based L2 (modem port, discovery) */
int l2_hardware;
int l2_flow_hwater;
int l2_flow_lwater;
int l2_copynum;                 /* --copy */
L2L1Port l2_l1_ports[L2_L1_PORTS];
int l2_l1_control;              /* the sgil1 driver's control device */
char *l2_l1_device;
IRIdent l2_id;
IRIdent l2_console_id;
IRIdent l2_modem_id;
IRIdent l2_cfg_id;
IRIdent l2_lpbk_id;
IRIdent l2_route_id;
IRIdent l2_cmd_id;
IRIdent l2_cmdusr_id;
IRIdent l2_apwr_id;
char l2_current_version[32];
char l2_flash_version[32];
char l2_display_version[32];
uint32 l2_ip;

/* SIGSEGV, SIGBUS, SIGABRT: log a backtrace (eight addresses a line, the
 * faulting instruction first) and exit */
void oops_handler(int sig, siginfo_t *info, void *raw_uc)
{
  char rbuf[128 * 24 + 200];  /* (the original's 800 bytes held about 70 addresses) */
  void *bt[128];
  char *rptr;
  int bt_size;
  int i;

  bt_size = backtrace(bt,128);
  sprintf(rbuf,"L2 %d.%d.%d received fatal signal %d\n",L2_REV_MAJOR,L2_REV_MINOR,L2_REV_PATCH,sig);
  rptr = rbuf + strlen(rbuf);
  /* bt[1] is the signal trampoline: the faulting instruction instead */
#if defined(__i386__)
  bt[1] = (void *)((ucontext_t *)raw_uc)->uc_mcontext.gregs[REG_EIP];
#elif defined(__x86_64__)
  bt[1] = (void *)((ucontext_t *)raw_uc)->uc_mcontext.gregs[REG_RIP];
#endif
  for (i = 1; i < bt_size; i++) {
    sprintf(rptr,"%s%p%s",i % 8 == 1 ? "  TR: " : "",bt[i],
            i % 8 == 0 || i == bt_size - 1 ? "\n" : " ");
    rptr += strlen(rptr);
  }
  syslog(9,"l2.c",153,0,rbuf);
  exit(1);
}

/* syslogLib's output: errors (levels 0-2) and fatal ones (9) go to the
 * NVRAM log */
static void syslog_msg(int level, char *msg)
{
  if ((level >= 0 && level < 3) || level == 9)
    nvramLogInsert(msg);
}

static void ignore_signal(int sig)
{
  struct sigaction sa;

  sigaction(sig,NULL,&sa);
  sa.sa_handler = SIG_IGN;
  sigaction(sig,&sa,NULL);
}

/* start the L2 and run it; returns only if the event loop does */
static int run(void)
{
  struct sigaction sa;

  fprintf(stderr,"\n\nSGI L2 Controller\n");
  strcpy(l2_current_version,"");
  strcpy(l2_flash_version,"");
  strcpy(l2_display_version,"?.?");
  fprintf(stderr,"Current L2 version: %d.%d.%d \n\n",L2_REV_MAJOR,L2_REV_MINOR,L2_REV_PATCH);
  if (l2_l1_conn_mode == L2_CONN_NONE)
    fprintf(stderr,"WARNING: No connections will be made to L1\'s (-noconn)\n");
  nvramInit(NVRAM_READWRITE);
  if (nvramGet(NVRAM_BROADCAST_TIMEOUT) != 0)
    broadcast_response_timeout = nvramGet(NVRAM_BROADCAST_TIMEOUT);
  if (nvramGet(NVRAM_TARGET_TIMEOUT) != 0)
    target_response_timeout = nvramGet(NVRAM_TARGET_TIMEOUT);
  IRouterInit(l2_ip);
  IRouterInitID(&l2_id,0,0);           /* (task 0) */
  IRouterInitID(&l2_console_id,IR_L2_CONSOLE,0);
  IRouterInitID(&l2_modem_id,IR_L2_MODEM,0);
  IRouterInitID(&l2_cfg_id,IR_L2_CFG,0);
  IRouterInitID(&l2_cmd_id,IR_L2_CMD,0);
  IRouterInitID(&l2_cmdusr_id,IR_L2_CMDUSR,0);
  IRouterInitID(&l2_lpbk_id,IR_L2_LPBK,0);
  IRouterInitID(&l2_route_id,IR_L2_ROUTE,0);
  IRouterInitID(&l2_apwr_id,IR_L2_APWR,0);
  l2_flow_setup(l2_flow_hwater,l2_flow_lwater);
  L2CfgInitLocal(l2_ip,NULL);
  l1_open();
  EnetServerInit(&l2_id,cfg_connect,cfg_disconnect,cfg_establish,IRouterSendPacket);
  EnetServerStart(IR_PORT_BIAS + L2_PEER_PORT,2,"L2");
  EnetServerStart(IR_PORT_BIAS + L2_APP_PORT,2,"L2");
  EnetServerStart(IR_PORT_BIAS + L2_APP_QUIET_PORT,2,"L2");
  EnetServerStart(IR_PORT_BIAS + L3_CMD_PORT,2,"L2");
  EnetServerStart(IR_PORT_BIAS + L3_QUIET_PORT,2,"L2");
  cfg_init();
  enet_init();
  cmd_init();
  discover_init();
  power_init();
  ignore_signal(SIGINT);
  ignore_signal(SIGQUIT);
  ignore_signal(SIGCHLD);
  memset(&sa,0,sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_sigaction = oops_handler;
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV,&sa,NULL);
  sigaction(SIGBUS,&sa,NULL);
  sigaction(SIGABRT,&sa,NULL);
  serial_init();
  EventStart();
  /* (the exit status is the message's length, as in the original) */
  return fprintf(stderr,"ERROR: L2 event loop exited!\n");
}

int main(int argc, char **argv, char **envp)
{
  char mtbuf[100];
  char *myhost;
  char *pw;
  char *ssn;
  int i;

  syslogLibInit(syslog_msg);
  l2_myname = argv[0];
  if (SocketGetHostName(&myhost) == -1)
    myhost = "localhost";
  SocketGetAddr(myhost,&l2_ip);
  /* (an option's value is the next argument, whatever it is) */
  for (i = 1; i < argc; i++) {
    const char *arg = argv[i];
    int more = argc - 1 - i;    /* arguments after this one */

    if (strcmp(arg,"-net") == 0)
      l2_l1_conn_mode = L2_CONN_NET;
    else if (strcmp(arg,"-pc") == 0) {
      l2_pc = 1;
      l2_discover = 1;
    }
    else if (strcmp(arg,"-usb") == 0)
      l2_l1_conn_mode = L2_CONN_USB;
    else if (strcmp(arg,"-noconn") == 0)
      l2_l1_conn_mode = L2_CONN_NONE;
    else if (strcmp(arg,"--copy") == 0) {
      /* <n>: copy n of l2 on this host, its ports biased by 10 n */
      if (more == 0 || argv[i + 1][0] == '-') {
        fprintf(stderr,"%s: --copy option missing <copy#>\n",l2_myname);
        syntax();
      }
      l2_copynum = atoi(argv[++i]);
      if (l2_copynum < 0 || l2_copynum > MAX_COPY) {
        fprintf(stderr,"%s: --copy: copy %d invalid (must be 0 through 128)\n",l2_myname,
                l2_copynum);
        syntax();
      }
      IR_PORT_BIAS = l2_copynum * 10;
      printf("using copy %d    (biasing all network ports by %d)\n",l2_copynum,IR_PORT_BIAS);
    }
    else if (strcmp(arg,"-discover") == 0)
      l2_discover = 1;
    else if (strcmp(arg,"-nodiscover") == 0)
      l2_discover = 0;
    else if (strcmp(arg,"-usbpath") == 0) {
      if (more == 0 || l1_parse_usbpath(argv[++i]) != 0)
        syntax();
    }
    else if (strcmp(arg,"-debug") == 0)
      l2_debug++;
    else if (strcmp(arg,"-irtr") == 0)
      irtr_debug = -1;
    else if (strcmp(arg,"-nopwrchk") == 0)
      power_check++;
    else if (strcmp(arg,"-smpenet") == 0)
      enet_only = 1;
    else if (strcmp(arg,"--mtrace") == 0) {
      pw = getenv("MALLOC_TRACE");
      if (pw == NULL) {
        pw = mtbuf;
        snprintf(pw,sizeof(mtbuf),"%s/l2.mtrace",l3path_mtrace_dir());   /* original: /tmp */
        setenv("MALLOC_TRACE",pw,0);
      }
      printf("memory tracing invoked--output file \'%s\'\n",pw);
      mtrace();
    }
    else if (strcmp(arg,"-syncssn") == 0) {
      /* <ssn>: set the system serial number, unless l2 is running */
      if (more == 0)
        syntax();               /* (the original crashed) */
      nvramInit(NVRAM_READWRITE);
      ssn = (char *)nvramGet(NVRAM_SERIAL);
      if (strcmp(ssn,argv[i + 1]) != 0 && EnetServerCheck(IR_PORT_BIAS + L2_APP_QUIET_PORT) == 0)
        nvramSet(NVRAM_SERIAL,(uintptr_t)argv[i + 1]);
      exit(0);
    }
    else
      syntax();
  }
  return run();
}

char *l2_firmware_version(void)
{
  static char firmware_ver[20];

  if (firmware_ver[0] == '\0')
    sprintf(firmware_ver,"%d.%d.%d",L2_REV_MAJOR,L2_REV_MINOR,L2_REV_PATCH);
  return firmware_ver;
}

/* throttle L1 input while network clients fall behind */
void l2_flow_setup(int hwater, int lwater)
{
  RouterSetOutputMonitor(l2_flow_control,NULL,hwater,0,lwater,0);
}

static void l2_flow_control(void *data, RouterClient *client, int overflow)
{
  syslog(6,"l2.c",760,0,"RouterClient 0x%08lx   flow %d\n",(unsigned long)(uintptr_t)client,overflow);
  l1_throttle_input(overflow);
}

static void syntax(void)
{
  fprintf(stdout,
          "usage: %s -net | -usb | -noconn  [ -discover -nodiscover ] [ -usbpath <path>[,<path>...] ]\n"
          ,l2_myname);
  exit(0);
}
