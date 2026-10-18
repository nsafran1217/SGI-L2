/*
 * sys_ctrl/l3/api/SCapi.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapi.c
 */

#include <ctype.h>
#include "SCapiL2.h"   /* needed by the reconstruction */
#include "../l2/l2cmd.h"   /* needed by the reconstruction */
#include "../l2/smp.h"   /* needed by the reconstruction */
#include "../sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <mcheck.h>
#include "SCapi.h"
#include "../../common/sys/syslog.h"
#include "../../common/Router/RouterMsg.h"
#include "../../common/sys/PPP.h"
#include "../../common/sys/BuffWrite.h"
#include "../../common/sys/FRU.h"
#include "L1Direct.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static int get_l2_rack(char *name);
static int is_os(void);
static int multi_system_check(sn1SC_L2 *list, int cnt);

static int sn1SCCount;
static IRClient *ir_client;
static int copynum;
static int serial_direct;
static int os_direct;
static int use_quiet_port;
static int response_timeout = 30;
static char l2_host[64];
static char l2_passwd[64];
static char l2_passwd_retrys;
static char l2_passwd_prompt = 1;
static char l2_iface[64];
static char l2_ssn[64];
static char l2_sysname[64];
static char l2_cname[128];
static char l2_scdev[64];
static int l2_rack;
static int l2_port;
static int l2_task;
static char *myname;
int ir_show;
int (*IRouterConnect)() = IRouterConnectL3;
void (*IRouterDisconnect)() = IRouterDisconnectL3;
int (*IRouterRequest)() = IRouterRequestL3;
int (*IRouterResponse)() = IRouterResponseL3;
int (*IRouterEvent)() = IRouterEventL3;
int (*IRouterGetPacket)() = IRouterGetPacketL3;
static IRIdent ir_id;

char *sn1SCUsage(void)
{
  static char *msg = "    --l2 <host>          hostname or IP address of L2 to connect to\n    --sc                 connect via dflt. system controller (lowest rack/slot)\n    --scdev <device>     connect via specified system controller device\n    --interface|--if <iface>  net interface (ie. eth0) of L2 network to connect to\n    --ssn <serial>[:<rack>]  serial number (ie. L01234567) of system to connect to\n    --sysname <name>[:<rack>]    system name of system to connect to\n    --pw <password>      L2 password\n    --irtr               (debug) show IRouter packets sent/received";
  static char *fullmsg;
  char *l1dmsg;
  size_t sVar1;
  size_t sVar2;
  
  if (fullmsg == NULL) {
    l1dmsg = L1DirectUsage();
    sVar1 = strlen(l1dmsg);
    sVar2 = strlen(msg);
    fullmsg = malloc(sVar2 + sVar1 + 3);
    strcpy(fullmsg,msg);
    strcat(fullmsg,"\n");
    strcat(fullmsg,l1dmsg);
  }
  return fullmsg;
}

static int get_l2_rack(char *name)
{
  char *__nptr;
  char *sep;
  int iVar1;
  char *rstr;
  
  sep = strchr(name,0x3a);
  if (sep == NULL) {
    iVar1 = 0;
  }
  else {
    *sep = '\0';
    __nptr = sep + 1;
    if ((*__nptr == '\0') || (iVar1 = isdigit((int)*__nptr), iVar1 == 0)) {
      iVar1 = -1;
    }
    else {
      l2_rack = atoi(__nptr);
      if (l2_rack < 1) {
        iVar1 = -1;
      }
      else {
        iVar1 = 1;
      }
    }
  }
  return iVar1;
}

char *SCFmtPkt(int seqnum, int clas, int argc, int err, IRAddress *to, IRAddress *from, char *bptr)
{
  char *pcVar1;
  char buf2 [32];
  char buf1 [32];
  char *temp_7bf4ebcf521;
  char *temp_7bfbfea47f4;
  
  IRFmtAddr(*to,buf1);
  IRFmtAddr(*from,buf2);
  temp_7bf4ebcf521 = buf2;
  temp_7bfbfea47f4 = buf1;
  pcVar1 = IRFmtClas(clas);
  sprintf(bptr,"PKT send:  %3d %s(%d,%d) D: %s S: %s",seqnum,pcVar1,argc,err,temp_7bfbfea47f4,
          temp_7bf4ebcf521);
  return bptr;
}

static int is_os(void)
{
  FILE *fp;
  char *pcVar1;
  int iVar2;
  char *cmd;
  char scdev [64];
  
  {
    /* original: "/bin/ls -1 /dev/snsc/*c*" (SGI_L3_DEV_DIR overrides /dev) */
    char lscmd[600];
    snprintf(lscmd,sizeof(lscmd),"/bin/ls -1 %s/snsc/*c* 2>/dev/null",l3path_dev_dir());
    fp = (FILE *)popen(lscmd,"r");
  }
  if ((fp == NULL) || (pcVar1 = fgets(scdev,0x40,(FILE *)fp), pcVar1 == NULL)) {
    if (fp != NULL) {
      pclose((FILE *)fp);
    }
    iVar2 = 0;
  }
  else {
    pclose((FILE *)fp);
    iVar2 = 1;
  }
  return iVar2;
}

int sn1SCParseCmdline(int *argc, char **argv, int *serial)
{
  int iVar1;
  int iVar2;
  char mtbuf [100];
  char *mtfile;
  int argsused;
  char *myfname;
  int tmp_argc;
  int orig_argc;
  int status;
  
  myname = *argv;
  myfname = strrchr(myname,0x2f);
  if (myfname == NULL) {
    myfname = myname;
  }
  if (serial != NULL) {
    serial_direct = *serial;
  }
  iVar1 = L1DirectParseCmdline(argc,argv,&serial_direct);
  status = (int)(iVar1 != 0);
  if (status == 0) {
    if (serial_direct != 0) {
      os_direct = 0;
    }
    tmp_argc = *argc;
    argv = argv + 1;
    orig_argc = tmp_argc;
    while (iVar1 = tmp_argc + -1, iVar1 != 0) {
      argsused = 0;
      iVar2 = strcmp(*argv,"--l2");
      if (iVar2 == 0) {
        if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
          fprintf(stderr,"%s: --l2 option missing <hostname>\n",myname);
          status = -1;
          break;
        }
        strcpy(l2_host,argv[1]);
        argsused = 2;
        os_direct = 0;
        serial_direct = 0;
        iVar1 = tmp_argc + -2;
      }
      else {
        iVar2 = strcmp(*argv,"--interface");
        if ((iVar2 == 0) || (iVar2 = strcmp(*argv,"--if"), iVar2 == 0)) {
          if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
            fprintf(stderr,"%s: %s option missing <net iface>\n",myname,*argv);
            status = -1;
            break;
          }
          iVar1 = isdigit((int)*argv[1]);
          if (iVar1 == 0) {
            strcpy(l2_iface,argv[1]);
          }
          else {
            sprintf(l2_iface,"eth%s",argv[1]);
          }
          argsused = 2;
          os_direct = 0;
          serial_direct = 0;
          iVar1 = tmp_argc + -2;
        }
        else {
          iVar2 = strcmp(*argv,"--ssn");
          if (iVar2 == 0) {
            if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
              fprintf(stderr,"%s: --ssn option missing <system serial number>\n",myname);
              status = -1;
              break;
            }
            strcpy(l2_ssn,argv[1]);
            iVar1 = get_l2_rack(l2_ssn);
            if (iVar1 < 0) {
              fprintf(stderr,"%s: bad rack number on --ssn option\n",myname);
              status = -1;
            }
            argsused = 2;
            os_direct = 0;
            serial_direct = 0;
            iVar1 = tmp_argc + -2;
          }
          else {
            iVar2 = strcmp(*argv,"--sysname");
            if (iVar2 == 0) {
              if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
                fprintf(stderr,"%s: --sysname option missing <name>\n",myname);
                status = -1;
                break;
              }
              strcpy(l2_sysname,argv[1]);
              iVar1 = get_l2_rack(l2_sysname);
              if (iVar1 < 0) {
                fprintf(stderr,"%s: bad rack number on --sysname option\n",myname);
                status = -1;
              }
              argsused = 2;
              os_direct = 0;
              serial_direct = 0;
              iVar1 = tmp_argc + -2;
            }
            else {
              iVar2 = strcmp(*argv,"--r");
              if ((iVar2 == 0) || (iVar2 = strcmp(*argv,"--rack"), iVar2 == 0)) {
                if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
                  fprintf(stderr,"%s: %s option missing <copy#>\n",*argv,myname);
                  status = -1;
                  break;
                }
                argsused = 2;
                l2_rack = atoi(argv[1]);
                iVar1 = tmp_argc + -2;
              }
              else {
                iVar2 = strcmp(*argv,"--pw");
                if (iVar2 == 0) {
                  if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
                    fprintf(stderr,"%s: --pw option missing <password>\n",myname);
                    status = -1;
                    break;
                  }
                  l2_passwd_prompt = '\0';
                  strcpy(l2_passwd,argv[1]);
                  argsused = 2;
                  iVar1 = tmp_argc + -2;
                }
                else {
                  iVar2 = strcmp(*argv,"--sc");
                  if (iVar2 == 0) {
                    sn1SCUseSCDevice(NULL);
                    argsused = 1;
                  }
                  else {
                    iVar2 = strcmp(*argv,"--scdev");
                    if (iVar2 == 0) {
                      if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
                        fprintf(stderr,"%s: --scdev option missing <device>\n",myname);
                        status = -1;
                        break;
                      }
                      sn1SCUseSCDevice(argv[1]);
                      argsused = 2;
                      iVar1 = tmp_argc + -2;
                    }
                    else {
                      iVar2 = strcmp(*argv,"--copy");
                      if (iVar2 == 0) {
                        if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
                          fprintf(stderr,"%s: --copy option missing <copy#>\n",myname);
                          status = -1;
                          break;
                        }
                        argsused = 2;
                        copynum = atoi(argv[1]);
                        if ((copynum < 0) || (0x80 < copynum)) {
                          fprintf(stderr,"%s: --copy: copy %d invalid (must be 0 through 128)\n",
                                  myname,copynum);
                          status = -1;
                          break;
                        }
                        IR_PORT_BIAS = copynum * 10;
                        printf("using copy %d    (biasing all network ports by %d)\n",copynum,
                               IR_PORT_BIAS);
                        iVar1 = tmp_argc + -2;
                      }
                      else {
                        iVar2 = strcmp(*argv,"--irtr");
                        if (iVar2 == 0) {
                          printf("dumping IR pkts\n");
                          ir_show = 1;
                          argsused = 1;
                        }
                        else {
                          iVar2 = strcmp(*argv,"--mtrace");
                          if (iVar2 == 0) {
                            mtfile = getenv("MALLOC_TRACE");
                            if (mtfile == NULL) {
                              mtfile = mtbuf;
                              sprintf(mtfile,"%s/%s.mtrace",l3path_mtrace_dir(),myfname);   /* original: /tmp */
                              setenv("MALLOC_TRACE",mtfile,0);
                            }
                            printf("memory tracing invoked--output file \'%s\'\n",mtfile);
                            mtrace();
                            argsused = 1;
                          }
                          else {
                            iVar2 = strcmp(*argv,"--quiet");
                            if (iVar2 == 0) {
                              use_quiet_port = 1;
                              argsused = 1;
                            }
                            else {
                              iVar2 = strcmp(*argv,"--timeout");
                              if (iVar2 == 0) {
                                if ((tmp_argc + -2 == 0) || (*argv[1] == '-')) {
                                  fprintf(stderr,"%s: --timeout option missing <value>\n",myname);
                                  status = -1;
                                  break;
                                }
                                argsused = 2;
                                response_timeout = atoi(argv[1]);
                                iVar1 = tmp_argc + -2;
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
      tmp_argc = iVar1;
      if (argsused == 0) {
        argv = argv + 1;
      }
      else {
        for (mtfile = NULL; (int)mtfile < tmp_argc; mtfile = mtfile + 1) {
          argv[(int)mtfile] = argv[(int)(mtfile + argsused)];
        }
        orig_argc = orig_argc - argsused;
      }
    }
    iVar1 = is_os();
    if ((iVar1 != 0) && (os_direct == 0)) {
      sn1SCUseSCDevice(NULL);
    }
    *argc = orig_argc;
    if (serial != NULL) {
      *serial = serial_direct;
    }
  }
  return status;
}

void sn1SCSetL2Host(char *host)
{
  strcpy(l2_host,host);
  return;
}

char *sn1SCGetL2Host(void)
{
  size_t sVar1;
  char *pcVar2;
  
  sVar1 = strlen(l2_host);
  if (sVar1 == 0) {
    pcVar2 = NULL;
  }
  else {
    pcVar2 = l2_host;
  }
  return pcVar2;
}

void sn1SCSetSysName(char *sysname)
{
  strcpy(l2_sysname,sysname);
  return;
}

char *sn1SCGetSysName(void)
{
  size_t sVar1;
  char *pcVar2;
  
  sVar1 = strlen(l2_sysname);
  if (sVar1 == 0) {
    pcVar2 = NULL;
  }
  else {
    pcVar2 = l2_sysname;
  }
  return pcVar2;
}

void sn1SCSetSSN(char *ssn)
{
  strcpy(l2_ssn,ssn);
  return;
}

char *sn1SCGetSSN(void)
{
  size_t sVar1;
  char *pcVar2;
  
  sVar1 = strlen(l2_ssn);
  if (sVar1 == 0) {
    pcVar2 = NULL;
  }
  else {
    pcVar2 = l2_ssn;
  }
  return pcVar2;
}

void sn1SCUseSCDevice(char *dev)
{
  FILE *fp;
  char *pcVar1;
  size_t sVar2;
  char *cmd;
  
  os_direct = 1;
  serial_direct = 0;
  if ((dev == NULL) || (*dev == '\0')) {
    {
    /* original: "/bin/ls -1 /dev/snsc/*c*" (SGI_L3_DEV_DIR overrides /dev) */
    char lscmd[600];
    snprintf(lscmd,sizeof(lscmd),"/bin/ls -1 %s/snsc/*c* 2>/dev/null",l3path_dev_dir());
    fp = (FILE *)popen(lscmd,"r");
  }
    if ((fp == NULL) || (pcVar1 = fgets(l2_scdev,0x40,(FILE *)fp), pcVar1 == NULL)) {
      fprintf(stderr,"Could not find an L1 Controller (/dev/snsc/*) to communicate with!\n");
      if (fp != NULL) {
        pclose((FILE *)fp);
      }
    }
    else {
      pclose((FILE *)fp);
      sVar2 = strlen(l2_scdev);
      if (l2_cname[sVar2 + 0x7f] == '\n') {
        sVar2 = strlen(l2_scdev);
        l2_cname[sVar2 + 0x7f] = '\0';
      }
    }
  }
  else {
    strcpy(l2_scdev,dev);
  }
  return;
}

int sn1SCInitPortAddr(char *cname, char *host, int task, int port, IRAddress addr)
{
  IRClient *pIVar1;
  int rval;
  int iVar2;
  
  if (sn1SCCount == 0) {
    sn1SCCount = 1;
    IRouterInit(0xffffffff);
    l2_port = port;
    IRouterInitID(&ir_id,0,0);
    ir_id.addr = addr;
  }
  if (((serial_direct == 0) && (os_direct == 0)) &&
     (pIVar1 = sn1SCClient(), pIVar1 != NULL)) {
    rval = -1;
  }
  else if (serial_direct == 0) {
    if (os_direct == 0) {
      if ((host == NULL) || (*host == '\0')) {
        iVar2 = sn1SCFindL2(l2_host);
        if (iVar2 < 0) {
          if (iVar2 != -1) {
            if (iVar2 == -2) {
              syslog(3,"SCapi.c",0x242,0,"could not find the specified host!");
              sn1SCCount = 0;
              return -300;
            }
            sn1SCCount = 0;
            return -300;
          }
          syslog(6,"SCapi.c",0x23f,0,"trying to connect to L2 @ localhost as a last resort");
          strcpy(l2_host,"localhost");
        }
      }
      else {
        strcpy(l2_host,host);
      }
    }
    else {
      IRouterConnect = IRouterConnectOS;
      IRouterDisconnect = IRouterDisconnectOS;
      IRouterRequest = IRouterRequestOS;
      IRouterResponse = IRouterResponseOS;
      IRouterEvent = IRouterEventOS;
      IRouterGetPacket = IRouterGetPacketOS;
      strcpy(l2_host,l2_scdev);
    }
    strncpy(l2_cname,cname,0x7f);
    l2_task = task;
    l2_passwd_retrys = '\0';
    rval = sn1SCReconnect();
    if (rval == 0) {
      rval = 0;
    }
    else {
      sn1SCCount = 0;
    }
  }
  else {
    rval = L1DirectConnect();
  }
  return rval;
}

int sn1SCInit(char *cname, char *host, int task)
{
  int iVar1;
  
  if (use_quiet_port == 0) {
    iVar1 = IR_PORT_BIAS + 8000;
  }
  else {
    iVar1 = IR_PORT_BIAS + 0x1f42;
  }
  iVar1 = sn1SCInitPortAddr(cname,host,task,iVar1,0x2ffff000);
  return iVar1;
}

int sn1SCInitL2App(char *cname, char *host, int task)
{
  int iVar1;
  
  if (use_quiet_port == 0) {
    iVar1 = IR_PORT_BIAS + 0x232a;
  }
  else {
    iVar1 = IR_PORT_BIAS + 0x232c;
  }
  iVar1 = sn1SCInitPortAddr(cname,host,task,iVar1,task & 0x1fU | 0x1ffff000);
  return iVar1;
}

int sn1SCReconnect(void)
{
  int rval;
  char *pcVar1;
  
  rval = (*IRouterConnect)(l2_cname,l2_host,l2_port,&ir_client,l2_task,sn1SCGetPassword);
  if (rval == 0) {
    l2_passwd_retrys = '\0';
  }
  else {
    pcVar1 = LoggerDefaultMessage(rval);
    syslog(3,"SCapi.c",0x27c,0,"IRouterConnect to %s failed: %s",l2_host,pcVar1);
  }
  return rval;
}

void sn1SCDisconnect(void)
{
  (*IRouterDisconnect)(ir_client);
  ir_client = NULL;
  return;
}

int sn1SCFindL2(char *host)
{
  int iVar1;
  char *__src;
  int l2_cnt;
  sn1SC_L2 *first_match_l2;
  sn1SC_L2 *l2;
  sn1SC_L2 *l2_list;
  int rval;
  int i;
  
  l2_cnt = 0;
  if ((serial_direct == 0) && (os_direct == 0)) {
    if (l2_host[0] == '\0') {
      iVar1 = sn1SCDiscoverL2(l2_iface,NULL,&l2_list,&l2_cnt,1);
      if (iVar1 < 0) {
        syslog(3,"SCapi.c",0x2be,0,"error discovering L2 controllers!");
      }
      if (l2_cnt == 0) {
        syslog(3,"SCapi.c",0x2c3,0,"could not find an L2 controller to connect to!");
        iVar1 = -1;
      }
      else {
        if ((l2_ssn[0] == '\0') && (l2_sysname[0] == '\0')) {
          iVar1 = multi_system_check(l2_list,l2_cnt);
          if (iVar1 < 0) {
            return -1;
          }
          i = 0;
          for (l2 = l2_list; ((l2_rack != 0 && (i < l2_cnt)) && (l2->rack != l2_rack)); l2 = l2 + 1)
          {
            if (first_match_l2 == NULL) {
              first_match_l2 = l2;
            }
            i = i + 1;
          }
        }
        else {
          first_match_l2 = NULL;
          l2 = l2_list;
          for (i = 0; i < l2_cnt; i = i + 1) {
            if (((l2_ssn[0] == '\0') || (iVar1 = strcmp(l2_ssn,l2->ssn), iVar1 == 0)) &&
               ((l2_sysname[0] == '\0' || (iVar1 = strcmp(l2_sysname,l2->sysname), iVar1 == 0)))) {
              if ((l2_rack == 0) || (l2->rack == l2_rack)) break;
              if (first_match_l2 == NULL) {
                first_match_l2 = l2;
              }
            }
            l2 = l2 + 1;
          }
        }
        if (i == l2_cnt) {
          l2 = NULL;
        }
        if (((l2_rack == 0) || (l2 != NULL)) || (first_match_l2 == NULL)) {
          if (l2 == NULL) {
            if (l2_ssn[0] == '\0') {
              if (l2_sysname[0] != '\0') {
                syslog(3,"SCapi.c",0x317,0,"no L2 controllers found with system name \'%s\'!",
                       l2_sysname);
              }
            }
            else {
              syslog(3,"SCapi.c",0x315,0,"no L2 controllers found with serial number \'%s\'!",l2_ssn
                    );
            }
            iVar1 = -2;
          }
          else {
            __src = inet_ntoa(*(struct in_addr *)&l2->ip_addr);
            strcpy(host,__src);
            iVar1 = 0;
          }
        }
        else {
          if (l2_ssn[0] == '\0') {
            if (l2_sysname[0] == '\0') {
              syslog(3,"SCapi.c",0x30b,0,"could not find rack %03d!",l2_rack);
            }
            else {
              syslog(3,"SCapi.c",0x308,0,"could not find rack %03d on system name \'%s\'!",l2_rack,
                     l2_sysname);
            }
          }
          else {
            syslog(3,"SCapi.c",0x305,0,"could not find rack %03d on serial number \'%s\'!",l2_rack,
                   l2_ssn);
          }
          iVar1 = -2;
        }
      }
    }
    else {
      if ((host != NULL) && (host != l2_host)) {
        strcpy(host,l2_host);
      }
      iVar1 = 0;
    }
  }
  else {
    iVar1 = -1;
  }
  return iVar1;
}

int sn1SCSocket(void)
{
  int iVar1;
  
  if (ir_client == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = ir_client->socket;
  }
  return iVar1;
}

char *sn1SCHost(void)
{
  char *pcVar1;
  
  if (ir_client == NULL) {
    pcVar1 = NULL;
  }
  else {
    pcVar1 = l2_host;
  }
  return pcVar1;
}

IRClient *sn1SCClient(void)
{
  RouterClient *pRVar1;
  
  if (((os_direct == 0) && (ir_client != NULL)) &&
     (pRVar1 = RouterFindClient(ir_client), pRVar1 == NULL)) {
    ir_client = NULL;
  }
  return ir_client;
}

int sn1SCCopy(void)
{
  return copynum;
}

int sn1SCIsQuiet(void)
{
  return use_quiet_port;
}

void sn1SCUseQuiet(void)
{
  use_quiet_port = 1;
  return;
}

int sn1SCReq(IRAddress *toaddr, int opcode, int argc, IRArgument *argv, uint32 *id)
{
  IRClient *pIVar1;
  int rval;
  int seqnum;
  int iVar2;
  char *pcVar3;
  char x [80];
  
  if (sn1SCCount == 0) {
    syslog(3,"SCapi.c",0x35f,0,"sn1SCReq: system controller library not initialized!\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (((serial_direct == 0) && (os_direct == 0)) &&
     (pIVar1 = sn1SCClient(), pIVar1 == NULL)) {
    rval = -0x12f;
  }
  else {
    seqnum = (int)ir_id.seqnum;
    if (serial_direct == 0) {
      iVar2 = (*IRouterRequest)(ir_client,&ir_id,toaddr,opcode,argc,argv,id);
      if (iVar2 != 0) {
        pcVar3 = LoggerDefaultMessage(iVar2);
        syslog(3,"SCapi.c",0x37c,0,"IRouterRequest failed: %s",pcVar3);
        return iVar2;
      }
    }
    else {
      iVar2 = L1DirectRequest(&ir_id,toaddr,opcode,argc,argv,(int *)id);
      if (iVar2 != 0) {
        pcVar3 = LoggerDefaultMessage(iVar2);
        syslog(3,"SCapi.c",0x375,0,"IRouterRequest failed: %s",pcVar3);
        return iVar2;
      }
    }
    if (ir_show != 0) {
      pcVar3 = SCFmtPkt(seqnum,0,argc,0,toaddr,&ir_id.addr,x);
      fprintf(stderr,"%s\n",pcVar3);
    }
    rval = 0;
  }
  return rval;
}

int sn1SCRsp(IRPacket **pkt, uint32 *id, int wait)
{
  int rval;
  IRClient *pIVar1;
  int iVar2;
  char *pcVar3;
  RouterClient *pRVar4;
  char x [80];
  
  if (sn1SCCount == 0) {
    rval = -1;
  }
  else if (((serial_direct == 0) && (os_direct == 0)) &&
          (pIVar1 = sn1SCClient(), pIVar1 == NULL)) {
    rval = -0x12f;
  }
  else {
    if (serial_direct == 0) {
      iVar2 = (*IRouterGetPacket)(&ir_id,pkt,0,wait,1);
      if (iVar2 != 0) {
        pcVar3 = LoggerDefaultMessage(iVar2);
        syslog(3,"SCapi.c",0x3ab,0,"IRouterGetPacket failed: %s",pcVar3);
        if (ir_client == NULL) {
          return iVar2;
        }
        pRVar4 = RouterFindClient(ir_client);
        if (pRVar4 != NULL) {
          return iVar2;
        }
        ir_client = NULL;
        return iVar2;
      }
    }
    else {
      iVar2 = L1DirectGetPacket(pkt,wait,1);
      if (iVar2 != 0) {
        pcVar3 = LoggerDefaultMessage(iVar2);
        syslog(3,"SCapi.c",0x3a5,0,"L1DirectGetPacket failed: %s",pcVar3);
        return iVar2;
      }
    }
    if (ir_show != 0) {
      pcVar3 = IRFmtPkt("PKT recv:",*pkt,x);
      fprintf(stderr,"%s\n",pcVar3);
    }
    if (id != NULL) {
      *id = (uint)CONCAT11((*pkt)->_seqnum1,(*pkt)->_seqnum0);
    }
    rval = 0;
  }
  return rval;
}

int sn1SCEvent(int opcode, int argc, IRArgument *argv)
{
  IRClient *pIVar1;
  char *pcVar2;
  char x [80];
  IRAddress toaddr;
  int seqnum;
  int rval;
  
  if (sn1SCCount == 0) {
    syslog(3,"SCapi.c",0x3dc,0,"sn1SCEvent: system controller library not initialized!\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (((serial_direct == 0) && (os_direct == 0)) &&
     (pIVar1 = sn1SCClient(), pIVar1 == NULL)) {
    return -0x12f;
  }
  seqnum = (int)ir_id.seqnum;
  if (serial_direct == 0) {
    rval = (*IRouterEvent)(ir_client,&ir_id,opcode,argc,argv);
    if (rval != 0) {
      pcVar2 = LoggerDefaultMessage(rval);
      syslog(3,"SCapi.c",0x3f8,0,"IRouterEvent failed: %s",pcVar2);
      return rval;
    }
  }
  else {
    rval = L1DirectEvent(&ir_id,opcode,argc,argv);
    if (rval != 0) {
      pcVar2 = LoggerDefaultMessage(rval);
      syslog(3,"SCapi.c",0x3f1,0,"IRouterRequest failed: %s",pcVar2);
      return rval;
    }
    rval = 0;
  }
  if (ir_show != 0) {
    toaddr = 0;
    pcVar2 = SCFmtPkt(seqnum,2,argc,0,&toaddr,&ir_id.addr,x);
    fprintf(stderr,"%s\n",pcVar2);
  }
  return 0;
}

int sn1SCPkt(IRPacket **pkt, int wait)
{
  int rval;
  IRClient *pIVar1;
  int iVar2;
  char *pcVar3;
  RouterClient *pRVar4;
  char x [80];
  
  if (sn1SCCount == 0) {
    rval = -1;
  }
  else if (((serial_direct == 0) && (os_direct == 0)) &&
          (pIVar1 = sn1SCClient(), pIVar1 == NULL)) {
    rval = -0x12f;
  }
  else {
    if (serial_direct == 0) {
      iVar2 = (*IRouterGetPacket)(&ir_id,pkt,0,wait,0);
      if (iVar2 != 0) {
        if (iVar2 != -0x26c) {
          pcVar3 = LoggerDefaultMessage(iVar2);
          syslog(3,"SCapi.c",0x42d,0,"IRouterGetPacket failed: %s",pcVar3);
        }
        if (ir_client == NULL) {
          return iVar2;
        }
        pRVar4 = RouterFindClient(ir_client);
        if (pRVar4 != NULL) {
          return iVar2;
        }
        ir_client = NULL;
        return iVar2;
      }
    }
    else {
      iVar2 = L1DirectGetPacket(pkt,wait,0);
      if (iVar2 != 0) {
        if (iVar2 == -0x26c) {
          return -0x26c;
        }
        pcVar3 = LoggerDefaultMessage(iVar2);
        syslog(3,"SCapi.c",0x424,0,"L1DirectGetPacket failed: %s",pcVar3);
        return iVar2;
      }
    }
    if (ir_show != 0) {
      pcVar3 = IRFmtPkt("PKT recv:",*pkt,x);
      fprintf(stderr,"%s\n",pcVar3);
    }
    rval = 0;
  }
  return rval;
}

int sn1SCSendRsp(int errcode, IRPacket *reqpkt, int argc, IRArgument *argv)
{
  IRClient *pIVar1;
  int rval;
  int seqnum;
  int iVar2;
  char *pcVar3;
  char x [80];
  
  if (sn1SCCount == 0) {
    syslog(3,"SCapi.c",0x452,0,"sn1SCReq: system controller library not initialized!\n");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  if (((serial_direct == 0) && (os_direct == 0)) &&
     (pIVar1 = sn1SCClient(), pIVar1 == NULL)) {
    rval = -0x12f;
  }
  else {
    seqnum = (int)ir_id.seqnum;
    if (serial_direct == 0) {
      iVar2 = (*IRouterResponse)(ir_client,&ir_id,errcode,reqpkt,argc,argv);
      if (iVar2 != 0) {
        pcVar3 = LoggerDefaultMessage(iVar2);
        syslog(3,"SCapi.c",0x470,0,"IRouterResponse failed: %s",pcVar3);
        return iVar2;
      }
    }
    else {
      iVar2 = L1DirectResponse(&ir_id,errcode,reqpkt,argc,argv);
      if (iVar2 != 0) {
        pcVar3 = LoggerDefaultMessage(iVar2);
        syslog(3,"SCapi.c",0x469,0,"IRouterResponse failed: %s",pcVar3);
        return iVar2;
      }
    }
    if (ir_show != 0) {
      pcVar3 = SCFmtPkt(seqnum,1,argc,0,&reqpkt->_src,&ir_id.addr,x);
      fprintf(stderr,"%s\n",pcVar3);
    }
    rval = 0;
  }
  return rval;
}

int sn1SCCmd(IRAddress *toaddr, int opcode, int argc, IRArgument *argv, IRPacket **rpkt, int wait)
{
  char *pcVar1;
  uint uVar2;
  uint32 rspid;
  uint32 reqid;
  int rval;
  
  rval = sn1SCReq(toaddr,opcode,argc,argv,&reqid);
  if (rval == 0) {
    while (rval = sn1SCRsp(rpkt,&rspid,wait), rval == 0) {
      if ((*rpkt)->_rev == '\0') {
        uVar2 = reqid & 0xff;
      }
      else {
        uVar2 = reqid & 0xffff;
      }
      if (uVar2 == rspid) {
        return 0;
      }
      syslog(4,"SCapi.c",0x49f,0,
             "sn1SCCmd: unexpected response (request ID did not match response ID!!)\n");
    }
    pcVar1 = LoggerDefaultMessage(rval);
    syslog(3,"SCapi.c",0x498,0,"sn1SCCmd: sn1SCRsp: %s\n",pcVar1);
  }
  else {
    pcVar1 = LoggerDefaultMessage(rval);
    syslog(3,"SCapi.c",0x490,0,"sn1SCCmd: sn1SCReq: %s\n",pcVar1);
  }
  return rval;
}

/* Reconstructed by hand: the original uses variable-length arrays, which threw
 * off Ghidra's stack tracking for the whole function. Logic and syslog line
 * numbers checked against the machine code. */
int sn1SCCmdParallel(IRAddress *toaddr, int ntargets, int opcode, int argc, IRArgument *argv, int share_args, IRPacket **rpkt, int *errlist, int *nerrs, int wait)
{
  IRAddress tmpaddr[ntargets];
  uint32 reqid[ntargets];
  IRPacket *rp;
  uint32 rspid;
  uint32 id;
  int offset;
  int errval = 0;
  int rerrcnt;
  int nrequests = 0;
  int rval;
  int t;

  memcpy(tmpaddr, toaddr, ntargets * sizeof(IRAddress));
  memset(errlist, 0, ntargets * sizeof(int));
  *nerrs = 0;
  for (t = 0; t < ntargets; t++) {
    offset = (share_args == 0 && argv != NULL) ? t * argc : 0;
    if (tmpaddr[t] != 0) {
      rval = sn1SCReq(&tmpaddr[t], opcode, argc, argv + offset, &reqid[t]);
      if (rval == 0) {
        nrequests++;
      }
      else {
        tmpaddr[t] = 0;
        errlist[t] = rval;
      }
    }
  }
  rerrcnt = 0;
  while (nrequests > 0) {
    rval = sn1SCRsp(&rp, &rspid, wait);
    if (rval != 0) {
      if (rval == -0x26c || rval == -0x12f) {
        errval = rval;
        break;
      }
      syslog(3, "SCapi.c", 1261, 0, "sn1SCCmdParallel: sn1SCRsp: %s\n", LoggerDefaultMessage(rval));
      if (rerrcnt++ >= 4) {
        errval = rval;
        break;
      }
      continue;
    }
    rerrcnt = 0;
    for (t = 0; t < ntargets; t++) {
      if (tmpaddr[t] != 0) {
        id = (rp->_rev == 0) ? (reqid[t] & 0xff) : (reqid[t] & 0xffff);
        if (id == rspid) {
          rpkt[t] = rp;
          tmpaddr[t] = 0;
          nrequests--;
          break;
        }
      }
    }
    if (t == ntargets) {
      syslog(3, "SCapi.c", 1308, 0, "sn1SCCmdParallel: response ID did not match any request ID!!\n");
    }
  }
  if (nrequests > 0) {
    for (t = 0; t < ntargets; t++) {
      if (tmpaddr[t] != 0 && errlist[t] == 0) {
        errlist[t] = errval;
      }
    }
  }
  if (errval == -0x26c) {
    errval = 0;
  }
  return errval;
}

int sn1SCTextCmd(IRAddress *toaddr, char *cmd, char **rsp)
{
  char *pcVar1;
  char *rstr;
  size_t sVar2;
  uint32 req_id;
  FILE *outf;
  int arg;
  int status;
  IRPacket *pkt;
  BuffWrite_t *bw;
  char *rptr;
  int ac;
  IRArgument av [2];
  
  av[0]._clas = '\0';
  av[0]._frame = '\0';
  av[0]._val = 0;
  av[0]._size = 0;
  av[1]._clas = '\n';
  av[1]._frame = '\0';
  av[1]._val = (uint32)strdup(cmd);
  pcVar1 = strdup(cmd);
  rstr = (char *)strlen(pcVar1);
  av[1]._size = (short)rstr + 1;
  ac = 2;
  rptr = malloc(0xa0);
  *rsp = rptr;
  *rptr = '\0';
  pcVar1 = strstr(cmd,"reboot");
  if (pcVar1 == NULL) {
    status = sn1SCCmd(toaddr,0,ac,av,&pkt,response_timeout);
    if (status == 0) {
      if (pkt->_err == '\0') {
        status = 0;
      }
      else {
        status = -600 - (uint)pkt->_err;
      }
      if (status == 0) {
        free(rptr);
        *rsp = NULL;
        bw = BuffWriteInit();
        BuffWrite(bw,"",0);
        for (arg = 0; arg < (int)(uint)pkt->_argc; arg = arg + 1) {
          if ((pkt->_argv[arg]._clas & 7) == 2) {
            if ((pkt->_argv[arg]._clas & 7) == 0) {
              req_id = pkt->_argv[arg]._val;
            }
            else {
              req_id = IRArg(pkt,arg);
            }
            BuffWrite(bw,(char *)req_id,-1);
            sVar2 = strlen((char *)req_id);
            if (*(char *)(sVar2 + req_id + -1) != '\n') {
              BuffWrite(bw,"\n",1);
            }
          }
        }
        pcVar1 = BuffWriteDone(bw,0);
        *rsp = pcVar1;
        if ((pkt->_argv[0]._clas & 7) == 0) {
          status = pkt->_argv[0]._val;
        }
        else {
          status = IRArg(pkt,0);
        }
      }
      else {
        pcVar1 = LoggerDefaultMessage(status);
        sprintf(rptr,"Command response ERROR: %s\n",pcVar1);
      }
    }
    else {
      pcVar1 = LoggerDefaultMessage(status);
      sprintf(rptr,"Command ERROR: %s\n",pcVar1);
    }
  }
  else {
    status = sn1SCReq(toaddr,0,ac,av,&req_id);
    if (status == 0) {
      status = 0;
    }
    else {
      pcVar1 = LoggerDefaultMessage(status);
      sprintf(rptr,"Command ERROR: %s\n",pcVar1);
    }
  }
  return status;
}

static int multi_system_check(sn1SC_L2 *list, int cnt)
{
  int iVar1;
  sn1SC_L2 **sys;
  int syscount;
  sn1SC_L2 *syslist [30];
  int l2;
  
  syscount = 0;
  memset(syslist,0,0x78);
  for (l2 = 0; l2 < cnt; l2 = l2 + 1) {
    sys = syslist;
    while ((*sys != NULL &&
           ((*sys == (sn1SC_L2 *)0xffffff30 ||
            (iVar1 = strcmp(list[l2].ssn,(*sys)->ssn), iVar1 != 0))))) {
      sys = sys + 1;
    }
    if (*sys != NULL) break;
    *sys = list + l2;
    syscount = syscount + 1;
  }
  if (syscount != 1) {
    fprintf(stderr,
            "ERROR: Multiple systems detected!\nYou must use the --l2 <host/IP>, --sysname <name>, or --ssn <serial number>\ncommand-line option to specify which system you wish to connect to.\nUse the \'l2find\' utility (/stand/sysco/bin/l2find) to see the list of\nL2s available to connect to.\n"
           );
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  return 0;
}

char *sn1SCGetPassword(IRClient *client)
{
  char cVar1;
  char *pw;
  
  cVar1 = l2_passwd_retrys;
  if (l2_passwd_prompt == '\0') {
    pw = l2_passwd;
  }
  else {
    l2_passwd_retrys = l2_passwd_retrys + '\x01';
    if ('\0' < cVar1) {
      l2_passwd[0] = '\0';
      printf("incorrect password\n");
    }
    if (l2_passwd[0] == '\0') {
      pw = getpass("L2 Password:");
      if (pw == NULL) {
        pw = NULL;
      }
      else if (l2_passwd[0] == '\0') {
        strcpy(l2_passwd,pw);
      }
    }
    else {
      pw = l2_passwd;
    }
  }
  return pw;
}

int sn1SCSetResponseTimeout(int new_to)
{
  int iVar1;
  int old_to;
  
  iVar1 = response_timeout;
  response_timeout = new_to;
  return iVar1;
}
