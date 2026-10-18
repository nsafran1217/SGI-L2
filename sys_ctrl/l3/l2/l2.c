/*
 * sys_ctrl/l3/l2/l2.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l2.c
 */

#include <execinfo.h>
#include "cmd.h"   /* needed by the reconstruction */
#include "discover.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdlib.h>
#include <mcheck.h>
#include <signal.h>
#include "l2.h"
#include "l1.h"
#include "smp.h"
#include "power.h"
#include "serial.h"
#include "enet.h"
#include "cfg.h"
#include "../main/nvram.h"
#include "irtr.h"
#include "l1sim.h"
#include "../../common/sys/syslog.h"
#include "broadcast.h"
#include "target.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */
#include <ucontext.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void syslog_msg(int level, char *msg);
static void l2_flow_control(void *data, RouterClient *client, int overflow);
static void syntax(void);

char *l2_myname = "guess";
int l2_debug;
int l2_discover;
int l2_l1_conn_mode = 2;
int l2_l1_local_port = -1;
int l2_l1_serial_hostport = 2345;
int l2_pc;
int l2_hardware;
int l2_flow_hwater;
int l2_flow_lwater;
int l2_copynum;
char l2_l1_serial_device[512];   /* original: 32 */
char l2_l1_serial_hostname[32];
L2L1Port l2_l1_ports[40];
int l2_l1_control;
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

void oops_handler(int sig, siginfo_t *info, void *raw_uc)
{
  int bt_size;
  size_t sVar1;
  char *post;
  int iVar2;
  char *pre;
  int dump;
  char *rptr;
  char rbuf [800];
  void *bt [128];
  int i;
  ucontext_t *uc;
  
  bt_size = backtrace(bt,0x80);
  sprintf(rbuf,"L2 %d.%d.%d received fatal signal %d\n",1,0x3e,0,sig);
  sVar1 = strlen(rbuf);
  rptr = rbuf + sVar1;
  /* the faulting instruction: uc_mcontext.gregs[REG_EIP] (i386) / [REG_RIP] (x86-64) */
#if defined(__i386__)
  bt[1] = (void *)((ucontext_t *)raw_uc)->uc_mcontext.gregs[14];
#elif defined(__x86_64__)
  bt[1] = (void *)((ucontext_t *)raw_uc)->uc_mcontext.gregs[16];
#endif
  for (i = 1; i < bt_size; i = i + 1) {
    pre = "";
    iVar2 = i;
    if (i < 0) {
      iVar2 = i + 7;
    }
    if (i + (iVar2 >> 3) * -8 == 1) {
      pre = "  TR: ";
    }
    if (((i & 7U) == 0) || (i == bt_size + -1)) {
      post = "\n";
    }
    else {
      post = " ";
    }
    sprintf(rptr,"%s%p%s",pre,bt[i],post);
    sVar1 = strlen(rptr);
    rptr = rptr + sVar1;
  }
  syslog(9,"l2.c",153,0,rbuf);
  exit(1);
}

static void syslog_msg(int level, char *msg)
{
  if ((-1 < level) && ((level < 3 || (level == 9)))) {
    nvramLogInsert(msg);
  }
  return;
}

int main(int argc, char **argv, char **envp)
{
  char **ppcVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  char *old_ssn;
  uint32 uVar5;
  char mtbuf [100];
  char *pw;
  char *myhost;
  struct sigaction sa;
  int rack;
  
  rack = 0;
  syslogLibInit(syslog_msg);
  l2_myname = *argv;
  strcpy(l2_l1_serial_hostname,"local_host");
  strcpy(l2_l1_serial_device,l3path_dev("com2"));   /* original: "/dev/com2" */
  iVar2 = SocketGetHostName(&myhost);
  if (iVar2 == -1) {
    myhost = "localhost";
  }
  SocketGetAddr(myhost,&l2_ip);
  iVar2 = argc;
  ppcVar1 = argv;
  while( true ) {
    argv = ppcVar1;
    argc = iVar2;
    iVar2 = argc + -1;
    if (iVar2 == 0) {
      fprintf(stderr,"\n\nSGI L2 Controller\n");
      strcpy(l2_current_version,"");
      strcpy(l2_flash_version,"");
      strcpy(l2_display_version,"?.?");
      fprintf(stderr,"Current L2 version: %d.%d.%d \n\n",1,0x3e,0);
      if (l2_l1_conn_mode == 0) {
        fprintf(stderr,"WARNING: No connections will be made to L1\'s (-noconn)\n");
      }
      nvramInit(NVRAM_READWRITE);
      uVar5 = nvramGet(NVRAM_BROADCAST_TIMEOUT);
      if (uVar5 != 0) {
        broadcast_response_timeout = nvramGet(NVRAM_BROADCAST_TIMEOUT);
      }
      uVar5 = nvramGet(NVRAM_TARGET_TIMEOUT);
      if (uVar5 != 0) {
        target_response_timeout = nvramGet(NVRAM_TARGET_TIMEOUT);
      }
      if (rack != 0) {
        nvramSet(NVRAM_RACK,rack);
        nvramSet(NVRAM_SLOT,0);
      }
      IRouterInit(l2_ip);
      IRouterInitID(&l2_id,0,0);
      IRouterInitID(&l2_console_id,2,0);
      IRouterInitID(&l2_modem_id,7,0);
      IRouterInitID(&l2_cfg_id,4,0);
      IRouterInitID(&l2_cmd_id,3,0);
      IRouterInitID(&l2_cmdusr_id,0xc,0);
      IRouterInitID(&l2_lpbk_id,5,0);
      IRouterInitID(&l2_route_id,0xd,0);
      IRouterInitID(&l2_apwr_id,9,0);
      l2_flow_setup(l2_flow_hwater,l2_flow_lwater);
      L2CfgInitLocal(l2_ip,NULL);
      l1_open();
      EnetServerInit(&l2_id,cfg_password,cfg_connect,cfg_disconnect,cfg_establish,IRouterSendPacket)
      ;
      EnetServerStart(IR_PORT_BIAS + 0x2329,2,"L2");
      EnetServerStart(IR_PORT_BIAS + 0x232a,2,"L2");
      EnetServerStart(IR_PORT_BIAS + 0x232c,2,"L2");
      EnetServerStart(IR_PORT_BIAS + 8000,2,"L2");
      EnetServerStart(IR_PORT_BIAS + 0x1f42,2,"L2");
      cfg_init();
      enet_init();
      cmd_init();
      discover_init();
      power_init();
      sigaction(SIGINT,NULL,(struct sigaction *)&sa);
      sa.sa_handler = SIG_IGN;
      sigaction(SIGINT,(struct sigaction *)&sa,NULL);
      sigaction(SIGQUIT,NULL,(struct sigaction *)&sa);
      sa.sa_handler = SIG_IGN;
      sigaction(SIGQUIT,(struct sigaction *)&sa,NULL);
      sigaction(SIGCHLD,NULL,(struct sigaction *)&sa);
      sa.sa_handler = SIG_IGN;
      sigaction(SIGCHLD,(struct sigaction *)&sa,NULL);
      sigemptyset((sigset_t *)&sa.sa_mask);
      sa.sa_sigaction = oops_handler;   /* SA_SIGINFO handler */
      sa.sa_flags = SA_SIGINFO;
      sigaction(SIGSEGV,(struct sigaction *)&sa,NULL);
      sigaction(SIGBUS,(struct sigaction *)&sa,NULL);
      sigaction(SIGABRT,(struct sigaction *)&sa,NULL);
      serial_init();
      EventStart();
      iVar2 = fprintf(stderr,"ERROR: L2 event loop exited!\n");
      return iVar2;
    }
    ppcVar1 = argv + 1;
    iVar3 = strcmp(*ppcVar1,"-password");
    if (iVar3 == 0) break;
    iVar3 = strcmp(*ppcVar1,"-net");
    if (iVar3 == 0) {
      l2_l1_conn_mode = 1;
    }
    else {
      iVar3 = strcmp(*ppcVar1,"-pc");
      if (iVar3 == 0) {
        l2_pc = 1;
        l2_discover = 1;
      }
      else {
        iVar3 = strcmp(*ppcVar1,"-usb");
        if (iVar3 == 0) {
          l2_l1_conn_mode = 2;
        }
        else {
          iVar3 = strcmp(*ppcVar1,"-noconn");
          if (iVar3 == 0) {
            l2_l1_conn_mode = 0;
          }
          else {
            iVar3 = strcmp(*ppcVar1,"-l1sim_manual");
            if (iVar3 == 0) {
              l2_l1_conn_mode = 5;
              l1sim_auto = 0;
              nvramSim = 1;
              if (1 < iVar2) {
                rack = atoi(argv[2]);
                iVar2 = argc + -2;
                ppcVar1 = argv + 2;
              }
            }
            else {
              iVar3 = strcmp(*ppcVar1,"-l1sim");
              if (iVar3 == 0) {
                l2_l1_conn_mode = 5;
                if (1 < iVar2) {
                  rack = atoi(argv[2]);
                  iVar2 = argc + -2;
                  ppcVar1 = argv + 2;
                  if (1 < argc + -2) {
                    l1sim_partition = atoi(argv[3]);
                    iVar2 = argc + -3;
                    ppcVar1 = argv + 3;
                  }
                }
              }
              else {
                iVar3 = strcmp(*ppcVar1,"--copy");
                if (iVar3 == 0) {
                  if ((iVar2 < 2) || (*argv[2] == '-')) {
                    fprintf(stderr,"%s: --copy option missing <copy#>\n",l2_myname);
                    syntax();
                  }
                  else {
                    l2_copynum = atoi(argv[2]);
                    if ((l2_copynum < 0) || (0x80 < l2_copynum)) {
                      fprintf(stderr,"%s: --copy: copy %d invalid (must be 0 through 128)\n",
                              l2_myname,l2_copynum);
                      syntax();
                    }
                    IR_PORT_BIAS = l2_copynum * 10;
                    printf("using copy %d    (biasing all network ports by %d)\n",l2_copynum,
                           IR_PORT_BIAS);
                    iVar2 = argc + -2;
                    ppcVar1 = argv + 2;
                  }
                }
                else {
                  iVar3 = strcmp(*ppcVar1,"-discover");
                  if (iVar3 == 0) {
                    l2_discover = 1;
                  }
                  else {
                    iVar3 = strcmp(*ppcVar1,"-nodiscover");
                    if (iVar3 == 0) {
                      l2_discover = 0;
                    }
                    else {
                      iVar3 = strcmp(*ppcVar1,"-serial");
                      if (iVar3 == 0) {
                        if (iVar2 < 2) {
                          syntax();
                        }
                        else {
                          ppcVar1 = argv + 2;
                          iVar2 = argc + -2;
                          if (**ppcVar1 == '/') {
                            l2_l1_conn_mode = 3;
                            strcpy(l2_l1_serial_device,*ppcVar1);
                          }
                          else {
                            l2_l1_conn_mode = 4;
                            strcpy(l2_l1_serial_hostname,*ppcVar1);
                            if (1 < iVar2) {
                              sscanf(argv[3],"%d",&l2_l1_serial_hostport);
                              iVar2 = argc + -3;
                              ppcVar1 = argv + 3;
                            }
                          }
                        }
                      }
                      else {
                        iVar3 = strcmp(*ppcVar1,"-usbpath");
                        if (iVar3 == 0) {
                          if (iVar2 < 2) {
                            syntax();
                          }
                          else {
                            ppcVar1 = argv + 2;
                            iVar3 = l1_parse_usbpath(*ppcVar1);
                            iVar2 = argc + -2;
                            if (iVar3 != 0) {
                              syntax();
                            }
                          }
                        }
                        else {
                          iVar3 = strcmp(*ppcVar1,"-debug");
                          if (iVar3 == 0) {
                            l2_debug = l2_debug + 1;
                          }
                          else {
                            iVar3 = strcmp(*ppcVar1,"-irtr");
                            if (iVar3 == 0) {
                              irtr_debug = -1;
                            }
                            else {
                              iVar3 = strcmp(*ppcVar1,"-nopwrchk");
                              if (iVar3 == 0) {
                                power_check = power_check + 1;
                              }
                              else {
                                iVar3 = strcmp(*ppcVar1,"-smpenet");
                                if (iVar3 == 0) {
                                  enet_only = 1;
                                }
                                else {
                                  iVar3 = strcmp(*ppcVar1,"--mtrace");
                                  if (iVar3 == 0) {
                                    pw = getenv("MALLOC_TRACE");
                                    if (pw == NULL) {
                                      pw = mtbuf;
                                      sprintf(pw,"%s/l2.mtrace",l3path_mtrace_dir());   /* original: /tmp */
                                      setenv("MALLOC_TRACE",pw,0);
                                    }
                                    printf("memory tracing invoked--output file \'%s\'\n",pw);
                                    mtrace();
                                  }
                                  else {
                                    iVar3 = strcmp(*ppcVar1,"-syncssn");
                                    if (iVar3 == 0) {
                                      pcVar4 = argv[2];
                                      nvramInit(NVRAM_READWRITE);
                                      old_ssn = (char *)nvramGet(NVRAM_SERIAL);
                                      iVar2 = strcmp(old_ssn,pcVar4);
                                      if ((iVar2 != 0) &&
                                         (iVar2 = EnetServerCheck(IR_PORT_BIAS + 0x232c), iVar2 == 0
                                         )) {
                                        nvramSet(NVRAM_SERIAL,(uintptr_t)pcVar4);
                                      }
                                      exit(0);
                                    }
                                    syntax();
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  nvramInit(NVRAM_READWRITE);
  pcVar4 = (char *)nvramGet(NVRAM_PASSWORD);
  if ((pcVar4 != NULL) && (*pcVar4 != '\0')) {
    return 1;
  }
  return 0;
}

char *l2_firmware_version(void)
{
  static char firmware_ver[20];
  
  if (firmware_ver[0] == '\0') {
    sprintf((char *)&firmware_ver,"%d.%d.%d",1,0x3e,0);
  }
  return (char *)&firmware_ver;
}

void l2_flow_setup(int hwater, int lwater)
{
  RouterSetOutputMonitor(l2_flow_control,NULL,hwater,0,lwater,0);
  return;
}

static void l2_flow_control(void *data, RouterClient *client, int overflow)
{
  syslog(6,"l2.c",760,0,"RouterClient 0x%08lx   flow %d\n",(unsigned long)(uintptr_t)client,overflow);
  l1_throttle_input(overflow);
  return;
}

static void syntax(void)
{
  fprintf(stdout,
          "usage: %s -enet | -usb | -serial [ <device> | <ipaddr> <port>]  [ -noconn -discover -nodiscover ] [ -usbpath <path>[,<path>...] ]\n"
          ,l2_myname);
  exit(0);
}
