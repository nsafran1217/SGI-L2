/*
 * sys_ctrl/l3/api/SCapi.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2term.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/api/SCapi.c
 *
 * The system controller API of the L3 tools: one connection per process,
 * to an L2 over the network (IRouterL3.c). sn1SCParseCmdline() takes the
 * common options.
 * SCapiConn.c is the same for several network connections.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <mcheck.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "SCapi.h"
#include "SCapiL2.h"
#include "../IRouter/IRouterL3.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/Router/Router.h"
#include "../../common/Router/RouterMsg.h"
#include "../../common/sys/BuffWrite.h"
#include "../../common/sys/Logger.h"
#include "../../common/sys/l3paths.h"   /* configurable paths (new) */
#include "../sys/syslogLib.h"

#define L2_CMD_PORT     8000    /* plus IR_PORT_BIAS */
#define L2_QUIET_PORT   8002
#define L2_APP_PORT     9002    /* an L2 application's (sn1SCInitL2App()) */
#define L2_APP_QUIET_PORT 9004
#define MAX_COPY        128     /* --copy */
#define TIMEOUT_ERR     IR_ERRNO(IRERR_TIMEOUT)

/* our IRouter address: an L3, or an L2 task (rack and slot all ones) */
#define L3_ADDR         IR_ADDR_MAKE(IR_ADDR_L3, 0x3ff, 0x3f, 0, 0)
#define L2_TASK_ADDR(t) IR_ADDR_MAKE(IR_ADDR_L2, 0x3ff, 0x3f, 0, (t) & 0x1f)

static int get_l2_rack(char *name);
static int multi_system_check(sn1SC_L2 *list, int cnt);

static int sn1SCCount;
static IRClient *ir_client;
static int copynum;
static int use_quiet_port;
static int response_timeout = 30;
static char l2_host[64];
static char l2_iface[64];
static char l2_ssn[64];
static char l2_sysname[64];
static char l2_cname[128];
static int l2_rack;
static int l2_port;
static int l2_task;
static char *myname;
int ir_show;                    /* --irtr */
/* the IRouter in use: the L3 one, over the network */
int (*IRouterConnect)() = IRouterConnectL3;
void (*IRouterDisconnect)() = IRouterDisconnectL3;
int (*IRouterRequest)() = IRouterRequestL3;
int (*IRouterResponse)() = IRouterResponseL3;
int (*IRouterEvent)() = IRouterEventL3;
int (*IRouterGetPacket)() = IRouterGetPacketL3;
static IRIdent ir_id;

/* copy a string into a field, truncated (the original strcpy()ed) */
static void set_field(char *field, size_t size, const char *value)
{
  snprintf(field,size,"%s",value);
}

/* the option help of sn1SCParseCmdline() */
char *sn1SCUsage(void)
{
  static char *msg =
    "    --l2 <host>          hostname or IP address of L2 to connect to\n"
    "    --interface|--if <iface>  net interface (ie. eth0) of L2 network to connect to\n"
    "    --ssn <serial>[:<rack>]  serial number (ie. L01234567) of system to connect to\n"
    "    --sysname <name>[:<rack>]    system name of system to connect to\n"
    "    --irtr               (debug) show IRouter packets sent/received";

  return msg;
}

/* "<name>[:<rack>]": cut off the rack into l2_rack; 1 if there was one,
 * 0 if not, -1 if it is not a number of 1 or more */
static int get_l2_rack(char *name)
{
  char *sep, *rstr;

  sep = strchr(name,':');
  if (sep == NULL)
    return 0;
  *sep = '\0';
  rstr = sep + 1;
  if (*rstr == '\0' || !isdigit((unsigned char)*rstr))
    return -1;
  l2_rack = atoi(rstr);
  return l2_rack < 1 ? -1 : 1;
}

/* a packet we send, for --irtr */
char *SCFmtPkt(int seqnum, int clas, int argc, int err, IRAddress *to, IRAddress *from, char *bptr)
{
  char buf1[32], buf2[32];

  IRFmtAddr(*to,buf1);
  IRFmtAddr(*from,buf2);
  sprintf(bptr,"PKT send:  %3d %s(%d,%d) D: %s S: %s",seqnum,IRFmtClas(clas),argc,err,buf1,buf2);
  return bptr;
}

/* the value of the option at args[0], or NULL if it has none (the last
 * argument, or the next one is an option) */
static char *option_value(char **args, int remaining)
{
  if (remaining < 2 || *args[1] == '-')
    return NULL;
  return args[1];
}

/*
 * Take the system controller options out of argv (*argc adjusted): which
 * L2 (--l2, --interface, --ssn, --sysname, --rack), --copy, --irtr,
 * --mtrace, --quiet, --timeout. Returns 0, or -1 after a message for a bad
 * option (parsing stops at one missing its value).
 */
int sn1SCParseCmdline(int *argc, char **argv)
{
  char mtbuf[100];
  char *mtfile, *myfname, *opt, *val;
  char **args;
  int remaining;                /* arguments from args[0] on */
  int new_argc, used, status;

  myname = argv[0];
  myfname = strrchr(myname,'/');
  if (myfname == NULL)
    myfname = myname;           /* (else it keeps the '/', as in the original) */
  status = 0;

  args = argv + 1;
  remaining = *argc - 1;
  new_argc = *argc;
  while (remaining > 0) {
    opt = args[0];
    val = option_value(args,remaining);
    used = 0;
    if (strcmp(opt,"--l2") == 0) {
      if (val == NULL) {
        fprintf(stderr,"%s: --l2 option missing <hostname>\n",myname);
        status = -1;
        break;
      }
      set_field(l2_host,sizeof(l2_host),val);
      used = 2;
    }
    else if (strcmp(opt,"--interface") == 0 || strcmp(opt,"--if") == 0) {
      if (val == NULL) {
        fprintf(stderr,"%s: %s option missing <net iface>\n",myname,opt);
        status = -1;
        break;
      }
      if (isdigit((unsigned char)*val))
        snprintf(l2_iface,sizeof(l2_iface),"eth%s",val);
      else
        set_field(l2_iface,sizeof(l2_iface),val);
      used = 2;
    }
    else if (strcmp(opt,"--ssn") == 0) {
      if (val == NULL) {
        fprintf(stderr,"%s: --ssn option missing <system serial number>\n",myname);
        status = -1;
        break;
      }
      set_field(l2_ssn,sizeof(l2_ssn),val);
      if (get_l2_rack(l2_ssn) < 0) {
        fprintf(stderr,"%s: bad rack number on --ssn option\n",myname);
        status = -1;            /* (and carries on) */
      }
      used = 2;
    }
    else if (strcmp(opt,"--sysname") == 0) {
      if (val == NULL) {
        fprintf(stderr,"%s: --sysname option missing <name>\n",myname);
        status = -1;
        break;
      }
      set_field(l2_sysname,sizeof(l2_sysname),val);
      if (get_l2_rack(l2_sysname) < 0) {
        fprintf(stderr,"%s: bad rack number on --sysname option\n",myname);
        status = -1;
      }
      used = 2;
    }
    else if (strcmp(opt,"--r") == 0 || strcmp(opt,"--rack") == 0) {
      if (val == NULL) {
        /* (SGI's message, with the option and program name swapped) */
        fprintf(stderr,"%s: %s option missing <copy#>\n",opt,myname);
        status = -1;
        break;
      }
      used = 2;
      l2_rack = atoi(val);
    }
    else if (strcmp(opt,"--copy") == 0) {
      if (val == NULL) {
        fprintf(stderr,"%s: --copy option missing <copy#>\n",myname);
        status = -1;
        break;
      }
      used = 2;
      copynum = atoi(val);
      if (copynum < 0 || copynum > MAX_COPY) {
        fprintf(stderr,"%s: --copy: copy %d invalid (must be 0 through 128)\n",myname,copynum);
        status = -1;
        break;
      }
      IR_PORT_BIAS = copynum * 10;
      printf("using copy %d    (biasing all network ports by %d)\n",copynum,IR_PORT_BIAS);
    }
    else if (strcmp(opt,"--irtr") == 0) {
      printf("dumping IR pkts\n");
      ir_show = 1;
      used = 1;
    }
    else if (strcmp(opt,"--mtrace") == 0) {
      mtfile = getenv("MALLOC_TRACE");
      if (mtfile == NULL) {
        mtfile = mtbuf;
        snprintf(mtfile,sizeof(mtbuf),"%s/%s.mtrace",l3path_mtrace_dir(),myfname);   /* original: /tmp */
        setenv("MALLOC_TRACE",mtfile,0);
      }
      printf("memory tracing invoked--output file \'%s\'\n",mtfile);
      mtrace();
      used = 1;
    }
    else if (strcmp(opt,"--quiet") == 0) {
      use_quiet_port = 1;
      used = 1;
    }
    else if (strcmp(opt,"--timeout") == 0) {
      if (val == NULL) {
        fprintf(stderr,"%s: --timeout option missing <value>\n",myname);
        status = -1;
        break;
      }
      used = 2;
      response_timeout = atoi(val);
    }

    if (used == 0) {            /* not ours: leave it */
      args++;
      remaining--;
      continue;
    }
    /* take it out, moving the rest (and argv's NULL) down */
    remaining -= used;
    memmove(args,args + used,(remaining + 1) * sizeof(char *));
    new_argc -= used;
  }
  *argc = new_argc;
  return status;
}

void sn1SCSetL2Host(char *host)
{
  set_field(l2_host,sizeof(l2_host),host);
}

char *sn1SCGetL2Host(void)
{
  return l2_host[0] == '\0' ? NULL : l2_host;
}

void sn1SCSetSysName(char *sysname)
{
  set_field(l2_sysname,sizeof(l2_sysname),sysname);
}

char *sn1SCGetSysName(void)
{
  return l2_sysname[0] == '\0' ? NULL : l2_sysname;
}

void sn1SCSetSSN(char *ssn)
{
  set_field(l2_ssn,sizeof(l2_ssn),ssn);
}

char *sn1SCGetSSN(void)
{
  return l2_ssn[0] == '\0' ? NULL : l2_ssn;
}

/*
 * Connect as cname (task, port, our IRouter address addr) to host, or the
 * L2 sn1SCFindL2() picks, or as sn1SCParseCmdline() chose. 0 or an error;
 * -1 if already connected.
 */
int sn1SCInitPortAddr(char *cname, char *host, int task, int port, IRAddress addr)
{
  int rval;

  if (sn1SCCount == 0) {
    sn1SCCount = 1;
    IRouterInit(0xffffffff);
    l2_port = port;
    IRouterInitID(&ir_id,0,0);
    ir_id.addr = addr;
  }
  if (sn1SCClient() != NULL)
    return -1;
  if (host != NULL && *host != '\0') {
    set_field(l2_host,sizeof(l2_host),host);
  }
  else {
    rval = sn1SCFindL2(l2_host);
    if (rval == -1) {
      syslog(6,"SCapi.c",575,0,"trying to connect to L2 @ localhost as a last resort");
      strcpy(l2_host,"localhost");
    }
    else if (rval < 0) {
      if (rval == -2)
        syslog(3,"SCapi.c",578,0,"could not find the specified host!");
      sn1SCCount = 0;
      return ROUTER_ERR_CONNECT_FAILED;
    }
  }
  strncpy(l2_cname,cname,sizeof(l2_cname) - 1);
  l2_task = task;
  rval = sn1SCReconnect();
  if (rval != 0)
    sn1SCCount = 0;
  return rval;
}

/* an L3 tool on the L2's command port */
int sn1SCInit(char *cname, char *host, int task)
{
  return sn1SCInitPortAddr(cname,host,task,
                           IR_PORT_BIAS + (use_quiet_port ? L2_QUIET_PORT : L2_CMD_PORT),L3_ADDR);
}

/* a program acting as L2 task task, on the L2's application port */
int sn1SCInitL2App(char *cname, char *host, int task)
{
  return sn1SCInitPortAddr(cname,host,task,
                           IR_PORT_BIAS + (use_quiet_port ? L2_APP_QUIET_PORT : L2_APP_PORT),
                           L2_TASK_ADDR(task));
}

int sn1SCReconnect(void)
{
  int rval;

  /* (no password: an L2 that asks for one gets an empty one) */
  rval = IRouterConnect(l2_cname,l2_host,l2_port,&ir_client,l2_task,NULL);
  if (rval != 0) {
    syslog(3,"SCapi.c",636,0,"IRouterConnect to %s failed: %s",l2_host,LoggerDefaultMessage(rval));
    return rval;
  }
  return 0;
}

void sn1SCDisconnect(void)
{
  IRouterDisconnect(ir_client);
  ir_client = NULL;
}

/* does the L2 match --ssn and --sysname (each if given)? */
static int l2_matches(sn1SC_L2 *l2)
{
  return (l2_ssn[0] == '\0' || strcmp(l2_ssn,l2->ssn) == 0) &&
         (l2_sysname[0] == '\0' || strcmp(l2_sysname,l2->sysname) == 0);
}

/*
 * The L2 to connect to, as a dotted address into host: --l2's host, or
 * by discovery the first L2 matching --ssn/--sysname and --rack (with
 * neither, the only system's). -1 if there are no L2s (or we are not on
 * the network), -2 if none matches.
 */
int sn1SCFindL2(char *host)
{
  sn1SC_L2 *l2_list = NULL;
  sn1SC_L2 *l2;
  sn1SC_L2 *first_match_l2 = NULL;      /* (in the system, but another rack) */
  int l2_cnt = 0;
  int i, rval;

  if (l2_host[0] != '\0') {
    if (host != NULL && host != l2_host)
      strcpy(host,l2_host);
    return 0;
  }
  if (sn1SCDiscoverL2(l2_iface,NULL,&l2_list,&l2_cnt,1) < 0)
    syslog(3,"SCapi.c",702,0,"error discovering L2 controllers!");
  if (l2_cnt == 0) {
    syslog(3,"SCapi.c",707,0,"could not find an L2 controller to connect to!");
    free(l2_list);
    return -1;
  }
  if (l2_ssn[0] == '\0' && l2_sysname[0] == '\0') {
    multi_system_check(l2_list,l2_cnt);         /* (exits if there are several) */
    /*
     * The first L2, or with --rack the first in that rack. (The original
     * did not initialize first_match_l2 on this path, so whether a missing
     * rack got its "could not find rack" message depended on the stack.)
     */
    for (i = 0; l2_rack != 0 && i < l2_cnt && l2_list[i].rack != l2_rack; i++)
      if (first_match_l2 == NULL)
        first_match_l2 = &l2_list[i];
  }
  else {
    for (i = 0; i < l2_cnt; i++) {
      if (!l2_matches(&l2_list[i]))
        continue;
      if (l2_rack == 0 || l2_list[i].rack == l2_rack)
        break;
      if (first_match_l2 == NULL)
        first_match_l2 = &l2_list[i];
    }
  }
  l2 = i < l2_cnt ? &l2_list[i] : NULL;

  if (l2_rack != 0 && l2 == NULL && first_match_l2 != NULL) {
    if (l2_ssn[0] != '\0')
      syslog(3,"SCapi.c",773,0,"could not find rack %03d on serial number \'%s\'!",l2_rack,l2_ssn);
    else if (l2_sysname[0] != '\0')
      syslog(3,"SCapi.c",776,0,"could not find rack %03d on system name \'%s\'!",l2_rack,l2_sysname);
    else
      syslog(3,"SCapi.c",779,0,"could not find rack %03d!",l2_rack);
    rval = -2;
  }
  else if (l2 == NULL) {
    if (l2_ssn[0] != '\0')
      syslog(3,"SCapi.c",789,0,"no L2 controllers found with serial number \'%s\'!",l2_ssn);
    else if (l2_sysname[0] != '\0')
      syslog(3,"SCapi.c",791,0,"no L2 controllers found with system name \'%s\'!",l2_sysname);
    rval = -2;
  }
  else {
    strcpy(host,inet_ntoa(*(struct in_addr *)&l2->ip_addr));
    rval = 0;
  }
  free(l2_list);                /* (the original kept it) */
  return rval;
}

int sn1SCSocket(void)
{
  return ir_client == NULL ? -1 : ir_client->socket;
}

char *sn1SCHost(void)
{
  return ir_client == NULL ? NULL : l2_host;
}

/* the client, NULL if the network connection has gone */
IRClient *sn1SCClient(void)
{
  if (ir_client != NULL && RouterFindClient(ir_client) == NULL)
    ir_client = NULL;
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
}

/* is there no network connection (when there should be one)? */
static int connection_gone(void)
{
  return sn1SCClient() == NULL;
}

/* drop the client if the network connection has gone */
static void check_client(void)
{
  if (ir_client != NULL && RouterFindClient(ir_client) == NULL)
    ir_client = NULL;
}

/* send a request; *id (if not NULL) is its sequence number */
int sn1SCReq(IRAddress *toaddr, int opcode, int argc, IRArgument *argv, uint32 *id)
{
  char x[80];
  int seqnum;
  int rval;

  if (sn1SCCount == 0) {
    syslog(3,"SCapi.c",863,0,"sn1SCReq: system controller library not initialized!\n");
    exit(1);
  }
  if (connection_gone())
    return ROUTER_ERR_LOST;
  seqnum = ir_id.seqnum;
  rval = IRouterRequest(ir_client,&ir_id,toaddr,opcode,argc,argv,id);
  if (rval != 0) {
    syslog(3,"SCapi.c",892,0,"IRouterRequest failed: %s",LoggerDefaultMessage(rval));
    return rval;
  }
  if (ir_show)
    fprintf(stderr,"%s\n",SCFmtPkt(seqnum,IR_REQ,argc,0,toaddr,&ir_id.addr,x));
  return 0;
}

/* wait for a response; *id (if not NULL) its sequence number */
int sn1SCRsp(IRPacket **pkt, uint32 *id, int wait)
{
  char x[80];
  int rval;

  if (sn1SCCount == 0)
    return -1;
  if (connection_gone())
    return ROUTER_ERR_LOST;
  rval = IRouterGetPacket(&ir_id,pkt,NULL,wait,1);
  if (rval != 0) {
    syslog(3,"SCapi.c",939,0,"IRouterGetPacket failed: %s",LoggerDefaultMessage(rval));
    check_client();
    return rval;
  }
  if (ir_show)
    fprintf(stderr,"%s\n",IRFmtPkt("PKT recv:",*pkt,x));
  if (id != NULL)
    *id = IR_SEQNUM(*pkt);
  return 0;
}

/* send an event */
int sn1SCEvent(int opcode, int argc, IRArgument *argv)
{
  IRAddress toaddr;
  char x[80];
  int seqnum;
  int rval;

  if (sn1SCCount == 0) {
    syslog(3,"SCapi.c",988,0,"sn1SCEvent: system controller library not initialized!\n");
    exit(1);
  }
  if (connection_gone())
    return ROUTER_ERR_LOST;
  seqnum = ir_id.seqnum;
  rval = IRouterEvent(ir_client,&ir_id,opcode,argc,argv);
  if (rval != 0) {
    syslog(3,"SCapi.c",1016,0,"IRouterEvent failed: %s",LoggerDefaultMessage(rval));
    return rval;
  }
  if (ir_show) {
    toaddr = 0;
    fprintf(stderr,"%s\n",SCFmtPkt(seqnum,IR_EVT,argc,0,&toaddr,&ir_id.addr,x));
  }
  return 0;
}

/* wait for any packet (a timeout is not logged) */
int sn1SCPkt(IRPacket **pkt, int wait)
{
  char x[80];
  int rval;

  if (sn1SCCount == 0)
    return -1;
  if (connection_gone())
    return ROUTER_ERR_LOST;
  rval = IRouterGetPacket(&ir_id,pkt,NULL,wait,0);
  if (rval != 0) {
    if (rval != TIMEOUT_ERR)
      syslog(3,"SCapi.c",1069,0,"IRouterGetPacket failed: %s",LoggerDefaultMessage(rval));
    check_client();
    return rval;
  }
  if (ir_show)
    fprintf(stderr,"%s\n",IRFmtPkt("PKT recv:",*pkt,x));
  return 0;
}

/* answer a request */
int sn1SCSendRsp(int errcode, IRPacket *reqpkt, int argc, IRArgument *argv)
{
  char x[80];
  int seqnum;
  int rval;

  if (sn1SCCount == 0) {
    syslog(3,"SCapi.c",1106,0,"sn1SCReq: system controller library not initialized!\n");
    exit(1);
  }
  if (connection_gone())
    return ROUTER_ERR_LOST;
  seqnum = ir_id.seqnum;
  rval = IRouterResponse(ir_client,&ir_id,errcode,reqpkt,argc,argv);
  if (rval != 0) {
    syslog(3,"SCapi.c",1136,0,"IRouterResponse failed: %s",LoggerDefaultMessage(rval));
    return rval;
  }
  if (ir_show)
    fprintf(stderr,"%s\n",SCFmtPkt(seqnum,IR_RSP,argc,0,&reqpkt->_src,&ir_id.addr,x));
  return 0;
}

/* does a response's sequence number (8 bits in revision 0 packets) match
 * the request's? */
static int response_matches(IRPacket *rsp, uint32 reqid, uint32 rspid)
{
  return (rsp->_rev == 0 ? (reqid & 0xff) : (reqid & 0xffff)) == rspid;
}

/* a request and its response, skipping responses to other requests */
int sn1SCCmd(IRAddress *toaddr, int opcode, int argc, IRArgument *argv, IRPacket **rpkt, int wait)
{
  uint32 reqid, rspid;
  int rval;

  rval = sn1SCReq(toaddr,opcode,argc,argv,&reqid);
  if (rval != 0) {
    syslog(3,"SCapi.c",1168,0,"sn1SCCmd: sn1SCReq: %s\n",LoggerDefaultMessage(rval));
    return rval;
  }
  while ((rval = sn1SCRsp(rpkt,&rspid,wait)) == 0) {
    if (response_matches(*rpkt,reqid,rspid))
      return 0;
    syslog(4,"SCapi.c",1183,0,"sn1SCCmd: unexpected response (request ID did not match response ID!!)\n");
  }
  syslog(3,"SCapi.c",1176,0,"sn1SCCmd: sn1SCRsp: %s\n",LoggerDefaultMessage(rval));
  return rval;
}

/*
 * The same request to ntargets addresses at once; see
 * sn1SCConnCmdParallel() (SCapiConn.c).
 *
 * Reconstructed by hand: the original uses variable-length arrays, which threw
 * off Ghidra's stack tracking for the whole function. Logic and syslog line
 * numbers checked against the machine code.
 */
int sn1SCCmdParallel(IRAddress *toaddr, int ntargets, int opcode, int argc, IRArgument *argv, int share_args, IRPacket **rpkt, int *errlist, int *nerrs, int wait)
{
  IRAddress tmpaddr[ntargets];  /* the targets still waiting */
  uint32 reqid[ntargets];
  IRPacket *rp;
  uint32 rspid;
  int offset;
  int errval = 0;
  int rerrcnt = 0;
  int nrequests = 0;
  int rval;
  int t;

  memcpy(tmpaddr,toaddr,ntargets * sizeof(IRAddress));
  memset(errlist,0,ntargets * sizeof(int));
  *nerrs = 0;
  for (t = 0; t < ntargets; t++) {
    offset = (share_args == 0 && argv != NULL) ? t * argc : 0;
    if (tmpaddr[t] == 0)
      continue;
    rval = sn1SCReq(&tmpaddr[t],opcode,argc,argv + offset,&reqid[t]);
    if (rval == 0) {
      nrequests++;
    }
    else {
      tmpaddr[t] = 0;
      errlist[t] = rval;
    }
  }
  while (nrequests > 0) {
    rval = sn1SCRsp(&rp,&rspid,wait);
    if (rval != 0) {
      if (rval == TIMEOUT_ERR || rval == ROUTER_ERR_LOST) {
        errval = rval;
        break;
      }
      syslog(3,"SCapi.c",1261,0,"sn1SCCmdParallel: sn1SCRsp: %s\n",LoggerDefaultMessage(rval));
      if (rerrcnt++ >= 4) {
        errval = rval;
        break;
      }
      continue;
    }
    rerrcnt = 0;
    for (t = 0; t < ntargets; t++) {
      if (tmpaddr[t] != 0 && response_matches(rp,reqid[t],rspid)) {
        rpkt[t] = rp;
        tmpaddr[t] = 0;
        nrequests--;
        break;
      }
    }
    if (t == ntargets)
      syslog(3,"SCapi.c",1308,0,"sn1SCCmdParallel: response ID did not match any request ID!!\n");
  }
  if (nrequests > 0) {
    for (t = 0; t < ntargets; t++)
      if (tmpaddr[t] != 0 && errlist[t] == 0)
        errlist[t] = errval;
  }
  return errval == TIMEOUT_ERR ? 0 : errval;
}

/*
 * A text command (as typed at the L2 or L1 prompt) to toaddr; *rsp gets the
 * response's lines (malloc()ed), or an error message. Returns the command's
 * status (the response's first argument) or an error. A "reboot" is only
 * sent: no response comes.
 */
int sn1SCTextCmd(IRAddress *toaddr, char *cmd, char **rsp)
{
  IRArgument av[2];
  IRPacket *pkt;
  BuffWrite_t *bw;
  uint32 req_id;
  char *rptr, *line;
  int status, arg;

  memset(&av[0],0,sizeof(av[0]));
  av[1]._clas = IR_ARG_FREE | IR_ARG_STRING;
  av[1]._frame = 0;
  av[1]._val = IR_PTR_VAL(strdup(cmd));
  av[1]._size = (short)strlen(cmd) + 1;   /* the original measured a second, leaked strdup(cmd) */
  rptr = malloc(0xa0);
  *rsp = rptr;
  *rptr = '\0';

  if (strstr(cmd,"reboot") != NULL) {
    status = sn1SCReq(toaddr,0,2,av,&req_id);
    if (status != 0)
      sprintf(rptr,"Command ERROR: %s\n",LoggerDefaultMessage(status));
    return status;
  }
  status = sn1SCCmd(toaddr,0,2,av,&pkt,response_timeout);
  if (status != 0) {
    sprintf(rptr,"Command ERROR: %s\n",LoggerDefaultMessage(status));
    return status;
  }
  if (pkt->_err != 0) {
    status = IR_ERRNO(pkt->_err);
    sprintf(rptr,"Command response ERROR: %s\n",LoggerDefaultMessage(status));
    return status;
  }
  free(rptr);
  *rsp = NULL;
  bw = BuffWriteInit();
  BuffWrite(bw,"",0);
  /* the string arguments, each a line */
  for (arg = 0; arg < pkt->_argc; arg++) {
    if (IR_ARG_TYPE(pkt->_argv[arg]) != IR_ARG_STRING)
      continue;
    line = (char *)IRArg(pkt,arg);
    BuffWrite(bw,line,-1);
    /* (the original looked before an empty line for its newline) */
    if (*line == '\0' || line[strlen(line) - 1] != '\n')
      BuffWrite(bw,"\n",1);
  }
  *rsp = BuffWriteDone(bw,0);
  return (int)IRArg(pkt,0);
}

/*
 * Exit with a message if discovery found more than one system (we were
 * not told which). The count stops at the first L2 whose system was seen
 * before, so only systems before that one count: SGI's check, kept.
 */
static int multi_system_check(sn1SC_L2 *list, int cnt)
{
  sn1SC_L2 *syslist[30];
  int syscount = 0;
  int l2, s;

  memset(syslist,0,sizeof(syslist));
  for (l2 = 0; l2 < cnt; l2++) {
    for (s = 0; syslist[s] != NULL && strcmp(list[l2].ssn,syslist[s]->ssn) != 0; s++)
      ;
    if (syslist[s] != NULL)
      break;
    if (s == 29)
      break;                    /* (the original ran off the list) */
    syslist[s] = &list[l2];
    syscount++;
  }
  if (syscount != 1) {
    fprintf(stderr,"ERROR: Multiple systems detected!\n"
            "You must use the --l2 <host/IP>, --sysname <name>, or --ssn <serial number>\n"
            "command-line option to specify which system you wish to connect to.\n"
            "Use the \'l2find\' utility (/stand/sysco/bin/l2find) to see the list of\n"
            "L2s available to connect to.\n");
    exit(-1);
  }
  return 0;
}

int sn1SCSetResponseTimeout(int new_to)
{
  int old_to = response_timeout;

  response_timeout = new_to;
  return old_to;
}
