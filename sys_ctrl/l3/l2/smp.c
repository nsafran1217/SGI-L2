/*
 * sys_ctrl/l3/l2/smp.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/smp.c
 */

#define _GNU_SOURCE     /* ptsname() */
#include <ctype.h>
#include "cfg.h"   /* needed by the reconstruction */
#include "irtr.h"   /* needed by the reconstruction */
#include "power.h"   /* needed by the reconstruction */
#include "pty.h"   /* needed by the reconstruction */
#include "l2.h"
#include <stdio.h>
#include <stddef.h>
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
#include "smp.h"
#include "format.h"
#include "lpbk.h"
#include "route.h"
#include "broadcast.h"
#include "reqrspq.h"
#include "l2cmd.h"
#include "enet.h"
#include "serial.h"
#include "../main/nvram.h"
#include "../../common/sys/ipmi.h"
#include "../../common/sys/FRU.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */
char *format_address(IRAddress addr);   /* defined in format's module; not in a header (name clash with a static elsewhere) */
struct __anon_struct_41 {
    int configured;
    int c_iflag;
    int c_oflag;
    int c_lflag;
    int c_cflag;
    int c_cc[32];
    int ospeed;
    int ispeed;
};

static void smp_process_queue(SMP *smp);
static void smp_timeout(L2CMD *c, int to, void *data);
static void smp_etimeout(L2CMD *c, char *msg, void *data);
static void smp_command_done(L2CMD *c, void *data, char *crsp, int rval);
static void smp_event(int opcode, int group, char *bptr);

SMP *smp_list;
int smp_count;
int smp_debug;
int smp_input_debug;
int smp_console_debug;
static char *smp_cc[32] = { "INTR", "QUIT", "ERASE", "KILL", "EOF", "EOL", "EOL2", "MIN", "TIME", "SWTCH", "START", "STOP", "SUSP", "REPRINT", "DISCARD", "WERASE", "LNEXT", "RPRNT", "FLUSHO" };
static struct __anon_struct_41 smp_tty[256];
static char vbuf[1024];

SMP *smp_init(IRIdent *id, int rfd, int wfd, void (*rfcn)(), uint32 host, int port)
{
  SMP *smp;
  SMPGroup *pSVar1;
  L2CMD *pLVar2;
  unsigned int uVar3;
  char *pw;
  uint32 uVar4;
  int taskid;
  int iVar5;
  int baud;
  
  smp_input_debug = 0;
  smp_console_debug = 0;
  smp = malloc(sizeof(SMP));
  memset(smp,0,sizeof(SMP));
  smp->host = host;
  smp->rfd = rfd;
  smp->wfd = wfd;
  smp->rfcn = rfcn;
  smp->id = id;
  if ((id->addr & 0x80000000) == 0) {
    taskid = id->addr & 0x1f;
  }
  else {
    taskid = id->addr >> 0x18 & 0x3f;
  }
  if (taskid == 7) {
    iVar5 = 1;
  }
  else {
    iVar5 = smp->rfd;
  }
  smp->grpid = iVar5;
  pSVar1 = malloc(sizeof(SMPGroup));
  smp->grp = pSVar1;
  memset(smp->grp,0,sizeof(*smp->grp));
  smp->grp->id = smp->grpid;
  smp->grp->confilter = 0;
  smp->grp->count = 1;
  smp->grp->clen = 0x80;
  smp->grp->cptr = smp->grp->cbuf;
  smp->grp->mode = 0;
  pLVar2 = l2cmd_init(smp->id,smp_timeout,smp_etimeout,smp_command_done,smp);
  smp->grp->l2cmd = pLVar2;
  if ((id->addr & 0x80000000) == 0) {
    uVar3 = id->addr & 0x1f;
  }
  else {
    uVar3 = id->addr >> 0x18 & 0x3f;
  }
  if ((((uVar3 != 2) && (uVar3 != 7)) && (pw = (char *)nvramGet(0x13), pw != NULL)) &&
     (*pw != '\0')) {
    smp->password = 1;
  }
  smp->next = smp_list;
  smp_count = smp_count + 1;
  baud = 0xf;
  if ((id->addr & 0x80000000) == 0) {
    uVar3 = id->addr & 0x1f;
  }
  else {
    uVar3 = id->addr >> 0x18 & 0x3f;
  }
  smp_list = smp;
  if (uVar3 == 7) {
    uVar4 = nvramGet(0x12);
    if (uVar4 == 1) {
      baud = 0xe;
    }
    else if (uVar4 == 2) {
      baud = 0xd;
    }
    else {
      nvramSet(0x12,0);
    }
  }
  smp_tty_config(smp->rfd,baud);
  EventAddInput(smp->rfd,smp_read,(EventData)smp,"smp_init");
  smp_event(1,smp->grpid,NULL);
  smp_prompt(smp);
  return smp;
}

void smp_free(SMP *smp)
{
  int *piVar1;
  SMPGroup *pSVar2;
  SMP *curr;
  SMP *prev;
  
  curr = smp_list;
  while( true ) {
    if (curr == NULL) {
      return;
    }
    if (curr == smp) break;
    prev = curr;
    curr = curr->next;
  }
  smp_event(3,curr->grpid,NULL);
  smp_tty_reconfig(smp->rfd);
  if (curr == smp_list) {
    smp_list = curr->next;
  }
  else {
    prev->next = curr->next;
  }
  EventRemoveInput(curr->rfd);
  if (curr->rfcn != NULL) {
    (*smp->rfcn)(curr->rfd);
  }
  pSVar2 = curr->grp;
  piVar1 = &pSVar2->count;
  *piVar1 = *piVar1 + -1;
  if (pSVar2->count == 0) {
    l2cmd_free(curr->grp->l2cmd);
    free(curr->grp);
  }
  free(curr);
  smp_count = smp_count + -1;
  return;
}

void smp_cleanup(void)
{
  int *piVar1;
  SMPGroup *pSVar2;
  char *pcVar3;
  char x [100];
  SMP *curr;
  SMP *prev;
  
  for (curr = smp_list; curr != NULL; curr = curr->next) {
    if (curr->hung == 0) {
      prev = curr;
    }
    else {
      pcVar3 = SocketAddrStr(curr->host);
      sprintf(x,"INFO: SMP session %d from %s appears hung, closing.\n",curr->grpid,pcVar3);
      nvramLogFinsert(x);
      fprintf(stderr,x);
      smp_event(3,curr->grpid,NULL);
      smp_tty_reconfig(curr->rfd);
      if (curr == smp_list) {
        smp_list = curr->next;
      }
      else {
        prev->next = curr->next;
      }
      EventRemoveInput(curr->rfd);
      if (curr->rfcn != NULL) {
        (*curr->rfcn)(curr->rfd);
      }
      pSVar2 = curr->grp;
      piVar1 = &pSVar2->count;
      *piVar1 = *piVar1 + -1;
      if (pSVar2->count == 0) {
        l2cmd_free(curr->grp->l2cmd);
        free(curr->grp);
      }
      free(curr);
    }
  }
  return;
}

void smp_reset(void)
{
  while (smp_list != NULL) {
    smp_free(smp_list);
  }
  return;
}

int smp_is_valid(SMP *smp)
{
  SMP *tsmp;
  
  for (tsmp = smp_list; (tsmp != NULL && (tsmp != smp)); tsmp = tsmp->next) {
  }
  return (unsigned int)(tsmp != NULL);
}

void smp_baud(int baud)
{
  unsigned int uVar1;
  SMP *s;
  
  nvramSet(0x12,baud);
  if (baud == 1) {
    baud = 0xe;
  }
  else if ((baud < 2) && (baud == 0)) {
    baud = 0xf;
  }
  else {
    baud = 0xd;
  }
  s = smp_list;
  do {
    if (s == NULL) {
      return;
    }
    if ((s->id->addr & 0x80000000) == 0) {
      if (s->id->addr >> 0x1c == 0xe) goto LAB_0804e280;
    }
    else if (s->id->addr >> 0x1e == 2) {
LAB_0804e280:
      if ((s->id->addr & 0x80000000) == 0) {
        uVar1 = s->id->addr & 0x1f;
      }
      else {
        uVar1 = s->id->addr >> 0x18 & 0x3f;
      }
      if (uVar1 == 7) {
        smp_tty_config(s->rfd,baud);
        return;
      }
    }
    s = s->next;
  } while( true );
}

int smp_console_count(unsigned char *pselect)
{
  int iVar1;
  int count;
  SMP *smp;
  
  count = 0;
  if (pselect != NULL) {
    memset(pselect,0,0x100);
  }
  for (smp = smp_list; smp != NULL; smp = smp->next) {
    iVar1 = smp->grp->mode;
    if ((iVar1 < 3) && (0 < iVar1)) {
      if ((pselect != NULL) && ((smp->grp->partition != 0 && (smp->grp->partition < 0x100)))
         ) {
        pselect[smp->grp->partition] = '\x01';
      }
      count = count + 1;
    }
  }
  return count;
}

int smp_get_mode(SMP *smp)
{
  return smp->grp->mode;
}

int smp_set_mode(SMP *smp, int mode)
{
  smp->grp->mode = mode;
  cfg_check_console_events();
  return mode;
}

IRAddress smp_get_l1addr(SMP *smp)
{
  return smp->grp->l1addr;
}

IRAddress smp_set_l1addr(SMP *smp, IRAddress l1addr)
{
  IRAddress IVar1;
  
  if ((l1addr & 0x80000000) == 0) {
    IVar1 = (l1addr & 0xffffffe0) | 2;
  }
  else {
    IVar1 = (l1addr & 0xc0ffffff) | 0x2000000;
  }
  smp->grp->l1addr = IVar1;
  return IVar1;
}

IRAddress smp_get_conaddr(SMP *smp, IRAddress *raddr, int *override)
{
  IRAddress addr;
  
  addr = smp->grp->conaddr;
  if (addr == 0) {
    addr = L2CfgMGetConsole(&L2CfgLocal,smp->grp->partition);
    if (raddr != NULL) {
      *raddr = addr;
    }
    if (override != NULL) {
      *override = 0;
    }
  }
  else {
    if (raddr != NULL) {
      *raddr = addr;
    }
    if (override != NULL) {
      *override = 1;
    }
  }
  return addr;
}

IRAddress smp_set_conaddr(SMP *smp, IRAddress new_conaddr)
{
  IRAddress IVar1;
  L2CfgL1 *cfg;
  char *pcVar2;
  IRAddress old_conaddr;
  SMP *s;
  int slot;
  int rack;
  char buff [128];
  
  IVar1 = smp->grp->conaddr;
  if (new_conaddr == 0) {
    smp->grp->conaddr = 0;
    smp->grp->confilter = 0;
    new_conaddr = 0;
  }
  else {
    cfg = L2CfgMFindBrickCfg(&L2CfgLocal,new_conaddr >> 0x12 & 0x3ff,new_conaddr >> 0xc & 0x3f,0);
    if (cfg == NULL) {
      new_conaddr = 0;
    }
    else if (((((((cfg->type == 'C') || (cfg->type == '3')) || (cfg->type == '5')) ||
               (((cfg->type == '4' || (cfg->type == 'A')) ||
                ((cfg->type == '6' || ((cfg->type == '9' || (cfg->type == '7')))))))) ||
              ((cfg->type == '8' ||
               (((cfg->type == '0' || (cfg->type == 'Q')) || (cfg->type == '@')))))) ||
             (((cfg->type == 'O' || (cfg->type == 'B')) ||
              (((cfg->type == 'F' || ((cfg->type == 'L' || (cfg->type == 'M')))) ||
               (cfg->type == '$')))))) ||
            ((((cfg->type == ',' || (cfg->type == '}')) || (cfg->type == '.')) || (cfg->type == '{')
             ))) {
      smp->grp->conaddr = new_conaddr;
      smp->grp->confilter = 0;
      pcVar2 = format_caddress(new_conaddr,0);
      sprintf(buff,"INFO: default system console override, changed to: %s\n",pcVar2);
      smp_output(smp,buff,-1);
    }
    else {
      new_conaddr = 0;
    }
  }
  return new_conaddr;
}

int smp_get_partition(SMP *smp)
{
  return smp->grp->partition;
}

int smp_set_partition(SMP *smp, int partition)
{
  IRAddress addr;
  
  if (partition == 0) {
    smp->grp->partition = 0;
    smp->grp->conaddr = 0;
    smp->grp->confilter = 0;
    cfg_check_console_events();
    addr = 0;
  }
  else {
    addr = L2CfgMGetConsole(&L2CfgLocal,partition);
    if (addr == 0) {
      addr = 0;
    }
    else {
      smp->grp->partition = partition;
      smp->grp->conaddr = 0;
      smp->grp->confilter = 0;
      cfg_check_console_events();
    }
  }
  return addr;
}

IRAddress smp_get_confilter(SMP *smp)
{
  return smp->grp->confilter;
}

IRAddress smp_set_confilter(SMP *smp, IRAddress confilter)
{
  smp->grp->confilter = confilter;
  return confilter;
}

void smp_query(SMP *smp, int verbose, char **results)
{
  size_t sVar1;
  unsigned char *puVar2;
  unsigned int uVar3;
  uint32 uVar4;
  IRAddress IVar5;
  char *pcVar6;
  char *pcVar7;
  int override;
  IRAddress addr;
  int count;
  char *rptr;
  SMP *s;
  
  count = 0;
  for (s = smp_list; s != NULL; s = s->next) {
    count = count + 1;
  }
  rptr = malloc((count + 2) * 0x50);
  *results = rptr;
  strcpy(rptr,"Session Who          Baud  Group Mode              Console          \n");
  sVar1 = strlen(rptr);
  rptr = rptr + sVar1;
  strcpy(rptr,"------- ------------ ----- ----- ----------------- -----------------\n");
  sVar1 = strlen(rptr);
  rptr = rptr + sVar1;
  for (s = smp_list; s != NULL; s = s->next) {
    if (s == smp) {
      puVar2 = ">>> ";
    }
    else {
      puVar2 = "    ";
    }
    sprintf(rptr,"%s%3d ",puVar2,s->grpid);
    sVar1 = strlen(rptr);
    rptr = rptr + sVar1;
    if ((s->id->addr & 0x80000000) == 0) {
      uVar3 = s->id->addr >> 0x1c;
    }
    else if (s->id->addr >> 0x1e == 2) {
      uVar3 = 0xe;
    }
    else {
      uVar3 = 0xf;
    }
    if (uVar3 == 0xe) {
      if ((s->id->addr & 0x80000000) == 0) {
        uVar3 = s->id->addr & 0x1f;
      }
      else {
        uVar3 = s->id->addr >> 0x18 & 0x3f;
      }
      if (uVar3 == 2) {
        strcpy(rptr,"console port 38400 ");
      }
      else if (uVar3 == 7) {
        strcpy(rptr,"modem port   ");
        uVar4 = nvramGet(0x12);
        if (uVar4 == 1) {
          strcat(rptr,"19200 ");
        }
        else if (uVar4 == 0) {
          strcat(rptr,"38400 ");
        }
        else if (uVar4 == 2) {
          strcat(rptr," 9600 ");
        }
        else {
          sVar1 = strlen(rptr);
          rptr = rptr + sVar1;
          uVar4 = nvramGet(0x12);
          sprintf(rptr,"%5d ",uVar4);
        }
      }
      else {
        strcpy(rptr,"unknown        n/a ");
      }
    }
    else if (uVar3 == 0xf) {
      strcpy(rptr,"network port   n/a ");
    }
    sVar1 = strlen(rptr);
    rptr = rptr + sVar1;
    sprintf(rptr,"%5d ",s->grp->id);
    sVar1 = strlen(rptr);
    rptr = rptr + sVar1;
    switch(s->grp->mode) {
    case 0:
      strcpy(rptr,"L2                ");
      break;
    case 1:
      strcpy(rptr,"console           ");
      break;
    case 2:
      strcpy(rptr,"console (escaped) ");
      break;
    case 3:
      strcpy(rptr,"L1                ");
      break;
    case 4:
      strcpy(rptr,"L1 (escaped)      ");
      break;
    case 5:
      strcpy(rptr,"shell             ");
      break;
    default:
      sprintf(rptr,"unknown (%4d)   ",s->grp->mode);
    }
    sVar1 = strlen(rptr);
    rptr = rptr + sVar1;
    IVar5 = smp_get_conaddr(s,&addr,&override);
    if (IVar5 == 0) {
      sprintf(rptr,"not defined\n");
    }
    else {
      if (override == 0) {
        pcVar6 = "(default)";
      }
      else {
        pcVar6 = "(override)";
      }
      pcVar7 = format_caddress(addr,s->grp->partition);
      sprintf(rptr,"%s %s\n",pcVar7,pcVar6);
    }
    sVar1 = strlen(rptr);
    rptr = rptr + sVar1;
  }
  return;
}

int smp_join(SMP *smp, int group)
{
  int *piVar1;
  int iVar2;
  SMP *s2;
  SMP *s1;
  char buff [128];
  SMPGroup *g;
  
  if ((smp->grp == NULL) || (smp->grp->id != group)) {
    for (s1 = smp_list; s1 != NULL; s1 = s1->next) {
      if (group == s1->grp->id) {
        g = smp->grp;
        smp->grp = NULL;
        if ((g == NULL) || (g->count = g->count + -1, g->count != 0)) {
          s2 = smp_list;
          while ((g != NULL && (s2 != NULL))) {
            if ((s2->grp != NULL) && (s2->grp->id == g->id)) {
              s2->grp->cptr = s2->grp->cbuf;
              *s2->grp->cptr = '\0';
              sprintf(buff,"INFO: SMP session %d left",smp->rfd);
              smp_output(s2,buff,-1);
              smp_input(s2,"\r",1);
              s2 = NULL;
            }
            if (s2 == NULL) {
              s2 = NULL;
            }
            else {
              s2 = s2->next;
            }
          }
        }
        else {
          l2cmd_free(g->l2cmd);
          free(g);
        }
        s1->grp->cptr = s1->grp->cbuf;
        *s1->grp->cptr = '\0';
        sprintf(buff,"\nINFO: SMP session %d joined this group\n",smp->rfd);
        smp_output(s1,buff,-1);
        piVar1 = &s1->grp->count;
        *piVar1 = *piVar1 + 1;
        smp->grp = s1->grp;
        return 0;
      }
    }
    iVar2 = -1;
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}

int smp_leave(SMP *smp)
{
  int iVar1;
  SMPGroup *pSVar2;
  L2CMD *pLVar3;
  SMPGroup *g;
  SMP *s;
  char buff [128];
  
  if (smp->grp->id == smp->rfd) {
    iVar1 = -1;
  }
  else {
    iVar1 = smp_join(smp,smp->rfd);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      pSVar2 = smp->grp;
      smp->grp = NULL;
      pSVar2->count = pSVar2->count + -1;
      if (pSVar2->count == 0) {
        l2cmd_free(pSVar2->l2cmd);
        free(pSVar2);
      }
      else {
        s = smp_list;
        while (s != NULL) {
          if ((s->grp != NULL) && (s->grp->id == pSVar2->id)) {
            s->grp->cptr = s->grp->cbuf;
            *s->grp->cptr = '\0';
            sprintf(buff,"INFO: SMP session %d left",smp->rfd);
            smp_output(s,buff,-1);
            smp_input(s,"\r",1);
            s = NULL;
          }
          if (s == NULL) {
            s = NULL;
          }
          else {
            s = s->next;
          }
        }
      }
      pSVar2 = malloc(sizeof(SMPGroup));
      smp->grp = pSVar2;
      memset(smp->grp,0,sizeof(*smp->grp));
      smp->grp->id = smp->grpid;
      smp->grp->confilter = 0;
      smp->grp->count = 1;
      smp->grp->clen = 0x80;
      smp->grp->cptr = smp->grp->cbuf;
      smp_set_mode(smp,0);
      pLVar3 = l2cmd_init(smp->id,smp_timeout,smp_etimeout,smp_command_done,smp);
      smp->grp->l2cmd = pLVar3;
      iVar1 = 0;
    }
  }
  return iVar1;
}

void smp_input_l1sysco(SMP *smp, int c)
{
  IRPacket *p;
  IRArgument argv [2];
  char c_;
  
  argv[0]._clas = '\0';
  argv[0]._frame = '\0';
  argv[0]._val = 0;
  argv[0]._size = 0;
  argv[1]._clas = '\0';
  argv[1]._frame = '\0';
  argv[1]._val = (uint32)(char)c;
  argv[1]._size = 0;
  p = IRouterMakePacket(smp->id,&smp->grp->l1addr,0,0,0,2,2,argv);
  if (p == NULL) {
    fprintf(stderr,"WARNING: can\'t create packet for L1.\n");
  }
  else {
    l2cmd_queue_response(smp->grp->l2cmd,smp->id->seqnum - 1,smp->grp->l1addr,10);
    EventEnableInput(smp->rfd,0);
    IRouterSendPacket(smp->id,p);
  }
  return;
}

void smp_input_console(SMP *smp, int c)
{
  IRAddress IVar1;
  int slot;
  IRPacket *p;
  IRAddress addr;
  IRArgument argv [2];
  char c_;
  
  argv[0]._clas = '\0';
  argv[0]._frame = '\0';
  argv[0]._val = 0;
  argv[0]._size = 0;
  argv[1]._clas = '\0';
  argv[1]._frame = '\0';
  argv[1]._val = (uint32)(char)c;
  argv[1]._size = 0;
  IVar1 = smp_get_conaddr(smp,NULL,NULL);
  if ((IVar1 & 0x80000000) == 0) {
    slot = IVar1 & 0x1f;
  }
  else {
    slot = IVar1 >> 0x18 & 0x3f;
  }
  if ((IVar1 & 0x80000000) == 0) {
    addr = (IVar1 & 0xffffffe0) | 5;
  }
  else {
    addr = (IVar1 & 0xc0ffffff) | 0x5000000;
  }
  p = IRouterMakePacket(smp->id,&addr,slot,0,0,2,2,argv);
  if (p == NULL) {
    fprintf(stderr,"WARNING: can\'t create packet for console.\n");
  }
  else {
    l2cmd_queue_response(smp->grp->l2cmd,smp->id->seqnum - 1,addr,0x14);
    EventEnableInput(smp->rfd,0);
    IRouterSendPacket(smp->id,p);
  }
  return;
}

void smp_input(SMP *smp, char *rbuf, int rlen)
{
  char **ppcVar1;
  char cVar2;
  SMPGroup *pSVar3;
  int *piVar4;
  char *pw;
  IRAddress IVar5;
  char *__s1;
  int iVar6;
  char tmp_ [5];
  char tmp [8];
  char *rptr;
  IRAddress conaddr;
  char buff [80];
  
  piVar4 = __errno_location();
  *piVar4 = 0;
  if (1 < smp_input_debug) {
    printf("** smp input %02x, mode %d, rfd %d, session %d\n",(int)*rbuf,smp->grp->mode,smp->rfd,
           smp->grp->id);
    fflush(stdout);
  }
  if (smp->grp->mode == 5) {
    write(smp->grp->shell,rbuf,rlen);
    return;
  }
  if (smp->password == 0) {
    cVar2 = *rbuf;
    if (cVar2 == '\x04') {
      if (smp->grp->mode == 0) {
        conaddr = smp_chkcon_present(smp);
        if (conaddr == 0) {
          return;
        }
        smp_console(smp,conaddr,0);
        return;
      }
      if (smp->grp->mode == 3) {
        smp_output(smp,"\nERROR: can\'t enter console mode from L1 mode via L2\n",-1);
        pw = format_address(smp->grp->l1addr);
        sprintf(buff,"\nre-entering L1 mode %s, <CTRL-T> to escape to L2\n",pw);
        smp_output(smp,buff,-1);
        smp_input_l1sysco(smp,10);
        return;
      }
    }
    else if (cVar2 < '\x05') {
      if (cVar2 == '\0') {
        return;
      }
    }
    else if (cVar2 == '\x14') {
      switch(smp->grp->mode) {
      case 0:
        return;
      case 1:
        smp_set_mode(smp,2);
        if (smp->grp->cptr == smp->grp->cbuf) {
          smp_output(smp,"\nescaping to L2 system controller\n",-1);
          smp_prompt(smp);
          return;
        }
        return;
      case 2:
        return;
      case 3:
        smp_set_mode(smp,4);
        if (smp->grp->cptr == smp->grp->cbuf) {
          smp_output(smp,"\nescaping to L2 system controller, <CTRL_T> to send escape to L1\n",-1);
          smp_prompt(smp);
          return;
        }
        return;
      case 4:
        if (smp->grp->cptr == smp->grp->cbuf) {
          smp_set_mode(smp,3);
          return;
        }
        return;
      }
    }
  }
  switch(smp->grp->mode) {
  case 0:
  case 2:
  case 4:
    cVar2 = *rbuf;
    if (cVar2 == '\n') {
LAB_0804f6b7:
      if ((smp->grp->lpbk_pending != 0) || (route_pending != 0)) {
        if (smp->grp->lpbk_pending != 0) {
          smp_output(smp,"\nno response from loopback command",-1);
        }
        smp->grp->lpbk_pending = 0;
        if (route_pending != 0) {
          smp_output(smp,"\nno response from route command",-1);
        }
        route_pending = 0;
      }
      smp_output(smp,"\n",-1);
      if ((smp->grp->cbuf[0] != '\0') || (smp->password != 0)) {
        rptr = NULL;
        smp->grp->l2cmd->data = smp;
        if (smp->password == 0) {
          l2cmd_process(smp->grp->l2cmd,smp->grp->cbuf,&rptr,NULL);
        }
        else {
          __s1 = (char *)nvramGet(0x13);
          if ((__s1 == NULL) || (*__s1 == '\0')) {
            smp->password = 0;
          }
          else {
            iVar6 = strcmp(__s1,smp->grp->cbuf);
            if (iVar6 == 0) {
              smp->password = 0;
            }
            else {
              smp_output(smp,"incorrect password\n",-1);
              iVar6 = smp->password;
              smp->password = smp->password + 1;
              if (((2 < iVar6) && (smp != serial_console)) && (smp != serial_modem)) {
                smp_output(smp,"disconnecting after 3 failed password attempts\n",-1);
                smp_free(smp);
              }
            }
          }
        }
        iVar6 = smp_is_valid(smp);
        if (iVar6 == 0) {
          return;
        }
        if (rptr != NULL) {
          smp_output(smp,rptr,-1);
          free(rptr);
        }
        smp->grp->cptr = smp->grp->cbuf;
        *smp->grp->cptr = '\0';
      }
      if (((smp->grp->l2cmd->busy == 0) && (smp->grp->lpbk_pending == 0)) && (route_pending == 0)) {
        smp_command_done(smp->grp->l2cmd,smp,NULL,0);
      }
    }
    else {
      if (cVar2 < '\v') {
        if (cVar2 == '\x03') {
          if (smp->password != 0) {
            smp->grp->cptr = smp->grp->cbuf;
            *smp->grp->cptr = '\0';
            smp_output(smp,"\n",-1);
            smp_prompt(smp);
            return;
          }
          while (smp->grp->cptr != smp->grp->cbuf) {
            smp_input(smp,"\b",1);
          }
          return;
        }
        if (cVar2 != '\b') {
LAB_0804f905:
          if (smp->grp->cbuf + smp->grp->clen <= smp->grp->cptr) {
            smp_output(smp,"\a",1);
            return;
          }
          pSVar3 = smp->grp;
          *pSVar3->cptr = *rbuf;
          ppcVar1 = &pSVar3->cptr;
          *ppcVar1 = *ppcVar1 + 1;
          *smp->grp->cptr = '\0';
          if (smp->password != 0) {
            return;
          }
          iVar6 = isprint((int)*rbuf);
          if (iVar6 != 0) {
            smp_output(smp,rbuf,1);
            return;
          }
          if (('\0' < *rbuf) && (*rbuf < '\x1b')) {
            sprintf(tmp,"^%c",(int)(char)(*rbuf | 0x40));
            smp_output(smp,tmp,-1);
            return;
          }
          sprintf(tmp_,"\\%03d",(int)*rbuf);
          smp_output(smp,tmp_,-1);
          return;
        }
      }
      else {
        if (cVar2 == '\r') goto LAB_0804f6b7;
        if (cVar2 != '\x7f') goto LAB_0804f905;
      }
      if (smp->grp->cbuf < smp->grp->cptr) {
        ppcVar1 = &smp->grp->cptr;
        *ppcVar1 = *ppcVar1 + -1;
        if (smp->password == 0) {
          iVar6 = isprint((int)*smp->grp->cptr);
          if (iVar6 == 0) {
            if ((*smp->grp->cptr < '\x01') || ('\x1a' < *smp->grp->cptr)) {
              smp_output(smp,"\b\b\b\b    \b\b\b\b",-1);
            }
            else {
              smp_output(smp,"\b\b  \b\b",-1);
            }
          }
          else {
            smp_output(smp,"\b \b",-1);
          }
        }
        *smp->grp->cptr = '\0';
      }
    }
    break;
  case 1:
    IVar5 = smp_chkcon_present(smp);
    if (IVar5 != 0) {
      smp_input_console(smp,(int)*rbuf);
    }
    break;
  case 3:
    smp_input_l1sysco(smp,(int)*rbuf);
  }
  return;
}

void smp_output(SMP *smp, char *bptr, int blen)
{
  SMP *s;
  
  smp_event(2,smp->grp->id,bptr);
  for (s = smp_list; s != NULL; s = s->next) {
    if ((s->grp != NULL) && (s->grp->id == smp->grp->id)) {
      smp_write(s,bptr,blen);
    }
  }
  return;
}

void smp_prompt(SMP *smp)
{
  char *__s;
  char *pptr;
  char *pcVar1;
  size_t sVar2;
  char *s;
  char prompt [128];
  
  if (smp->password == 0) {
    if ((false) || (L2CfgLocal.sysname[0] == '\0')) {
      if ((false) || (L2CfgLocal.ssn[0] == '\0')) {
        s = "?";
      }
      else {
        s = L2CfgLocal.ssn;
      }
    }
    else {
      s = L2CfgLocal.sysname;
    }
    prompt[0] = '\0';
    if (L2CfgLocal.net.msmode == 1) {
      sprintf(prompt,"WARNING: This is a secondary L2, system controller access is limited...\n");
    }
    __s = prompt + strlen(prompt);
    if ((L2CfgLocal.rack == 0) || (L2CfgLocal.rack == -1)) {
      pcVar1 = SocketAddrStr(l2_ip);
      sprintf(__s,"%s-%s-",s,pcVar1);
    }
    else {
      sprintf(__s,"%s-%03d-",s,L2CfgLocal.rack);
    }
    sVar2 = strlen(__s);
    if ((smp->grp == NULL) || (smp->grp->partition == 0)) {
      sprintf(__s + sVar2,"L2>");
    }
    else {
      sprintf(__s + sVar2,"L2:p%d>",smp->grp->partition);
    }
    smp_output(smp,prompt,-1);
  }
  else {
    smp_output(smp,"Password: ",-1);
  }
  return;
}

IRAddress smp_chkcon_present(SMP *smp)
{
  IRAddress addr;
  char buff [100];
  
  addr = smp_get_conaddr(smp,NULL,NULL);
  if (addr == 0) {
    if (smp->grp->partition == 0) {
      sprintf(buff,"\nINFO: ERROR: no system console defined\n");
    }
    else {
      sprintf(buff,"\nINFO: ERROR: no system console for partition %d defined\n",smp->grp->partition
             );
    }
    smp_output(smp,buff,-1);
    smp_set_mode(smp,0);
    smp_prompt(smp);
    addr = 0;
  }
  return addr;
}

void smp_chkcon_changes(int get_check)
{
  IRAddress addr;
  static L2CfgSysCon syscon_snap[256];
  int iVar1;
  char *pcVar2;
  char buff [128];
  IRAddress old_conaddr;
  int p;
  SMP *smp;
  IRAddress new_conaddr;
  
  if (get_check == 0) {
    memcpy((void *)&syscon_snap,L2CfgLocal.syscon,0x400);
  }
  else {
    iVar1 = memcmp((void *)&syscon_snap,L2CfgLocal.syscon,0x400);
    if (iVar1 != 0) {
      for (p = 0; p < 0x100; p = p + 1) {
        new_conaddr = ((L2CfgSysCon *)&syscon_snap)[p].detected;
        addr = L2CfgLocal.syscon[p].detected;
        if (new_conaddr != addr) {
          for (smp = smp_list; smp != NULL; smp = smp->next) {
            if ((((smp_console_debug != 0) && (smp->grp->conaddr == 0)) &&
                (smp->grp->partition == p)) && ((smp->grp->mode == 1 || (smp->grp->mode == 2)))) {
              if (p == 0) {
                smp_output(smp,"INFO: system console ",-1);
              }
              else {
                sprintf(buff,"INFO: partition %d system console ",p);
                smp_output(smp,buff,-1);
              }
              if (addr == 0) {
                pcVar2 = format_caddress(new_conaddr,0);
                sprintf(buff,"on %s lost\n",pcVar2);
              }
              else {
                pcVar2 = format_caddress(addr,0);
                sprintf(buff,"changed: %s\n",pcVar2);
              }
              smp_output(smp,buff,-1);
            }
          }
        }
      }
    }
  }
  return;
}

int smp_shell(SMP *smp, char *cmd)
{
  int master_fd;
  int iVar1;
  __pid_t _Var2;
  int slave_fd;
  char *argv [4];
  struct sigaction sa;
  
  master_fd = pty_master();
  if (master_fd < 0) {
    iVar1 = -1;
  }
  else {
    _Var2 = fork();
    smp->grp->shell = _Var2;
    if (_Var2 == 0) {
      sigaction(2,NULL,(struct sigaction *)&sa);
      sa.sa_handler = SIG_DFL;
      sigaction(2,(struct sigaction *)&sa,NULL);
      sigaction(3,NULL,(struct sigaction *)&sa);
      sa.sa_handler = SIG_DFL;
      sigaction(3,(struct sigaction *)&sa,NULL);
      _Var2 = setsid();
      if (_Var2 < 0) {
        fprintf(stderr,"INFO: can\'t set session ID\n");
      }
      slave_fd = pty_slave(master_fd);
      if (slave_fd < 0) {
        fprintf(stderr,"ERROR: can\'t open pty slave\n");
                    /* WARNING: Subroutine does not return */
        exit(0);
      }
      close(master_fd);
      dup2(slave_fd,0);
      dup2(slave_fd,1);
      dup2(slave_fd,2);
      close(slave_fd);
      argv[0] = "sh";
      if (cmd == NULL) {
        argv[1] = "-i";
        argv[2] = NULL;
      }
      else {
        argv[1] = "-c";
        argv[2] = cmd;
        argv[3] = NULL;
      }
      execv("/bin/sh",argv);
                    /* WARNING: Subroutine does not return */
      exit(0x7f);
    }
    EventAddInput(master_fd,smp_echo,(EventData)smp,"smp_shell");
    smp_set_mode(smp,5);
    smp->grp->shell = master_fd;
    iVar1 = 0;
  }
  return iVar1;
}

void smp_process_packet(SMP *smp, IRPacket *p, int source, void (*w)())
{
  char *sptr;
  int slen;
  char *pcVar1;
  uint32_t uVar2;
  int slen_;
  char *sptr_;
  int arg;
  
  if (l2_debug != 0) {
    fprintf(stderr,"smp_process_packet(%x) in\n",p);
  }
  for (arg = 0; arg < (int)(unsigned int)p->_argc; arg = arg + 1) {
    if ((p->_argv[arg]._clas & 7) == 2) {
      if ((p->_argv[arg]._clas & 7) == 0) {
        sptr = (char *)IR_VAL_PTR(p->_argv[arg]._val);
      }
      else {
        sptr = (char *)IRArg(p,arg);
      }
      slen = strlen(sptr);
      if (source != 0) {
        uVar2 = 0xffffffff;
        pcVar1 = format_address(p->_src);
        (*w)(smp,pcVar1,uVar2);
        if (source == 2) {
          (*w)(smp,":\n",0xffffffff);
        }
        else {
          (*w)(smp," ",0xffffffff);
        }
        source = 0;
      }
      (*w)(smp,sptr,slen);
    }
  }
  if (l2_debug != 0) {
    fprintf(stderr,"smp_process_packet out\n");
  }
  return;
}

void smp_process_event(IRPacket *p)
{
  int type;
  int task;
  unsigned int uVar1;
  L2CfgL1 *cfg;
  IRAddress faddr;
  IRAddress IVar2;
  L2CfgL1 *pLVar3;
  IRAddress saddr;
  int slot;
  int rack;
  IRAddress src_;
  IRAddress src;
  SMP *smp;
  
  uVar1 = p->_src;
  if ((uVar1 & 0x80000000) == 0) {
    type = uVar1 >> 0x1c;
  }
  else if (uVar1 >> 0x1e == 2) {
    type = 0xe;
  }
  else {
    type = 0xf;
  }
  if ((uVar1 & 0x80000000) == 0) {
    task = uVar1 & 0x1f;
  }
  else {
    task = uVar1 >> 0x18 & 0x3f;
  }
  smp = smp_list;
  do {
    if (smp == NULL) {
      smp_cleanup();
      return;
    }
    if ((type == 0) && (task == 1)) {
      smp_process_packet(smp,p,1,smp_write);
    }
    else if (((type == 0xe) || (type == 1)) && (task == 2)) {
      if ((p->_argv[0]._clas & 7) == 0) {
        if ((p->_argv[0]._clas & 7) == 0) {
          uVar1 = p->_argv[0]._val;
        }
        else {
          uVar1 = IRArg(p,0);
        }
        if (uVar1 == 4) {
          smp_process_packet(smp,p,1,smp_write);
        }
      }
    }
    else if ((type == 0) && (task == 5)) {
      if ((smp->grp->mode == 1) &&
         (((smp->grp->conaddr != 0 || (smp->grp->partition == 0)) ||
          ((cfg = L2CfgMFindBrickCfg(&L2CfgLocal,p->_src >> 0x12 & 0x3ff,p->_src >> 0xc & 0x3f,0),
           cfg != NULL &&
           ((cfg != NULL && (cfg->partition == smp->grp->partition)))))))) {
        if (smp->grp->confilter != 0) {
          uVar1 = p->_src;
          faddr = smp_get_conaddr(smp,NULL,NULL);
          if ((uVar1 & 0x80000000) == 0) {
            IVar2 = (uVar1 & 0xffffffe0) | (unsigned int)(p->_pdata_auth >> 3);
          }
          else {
            IVar2 = (uVar1 & 0xc0ffffff) | (unsigned int)(p->_pdata_auth >> 3) << 0x18;
          }
          if (IVar2 != faddr) goto LAB_080504e9;
        }
        smp_process_packet(smp,p,0,smp_write);
      }
    }
    else if (((smp->grp->conaddr != 0) || (smp->grp->partition == 0)) ||
            ((pLVar3 = L2CfgMFindBrickCfg(&L2CfgLocal,p->_src >> 0x12 & 0x3ff,p->_src >> 0xc & 0x3f,
                                          0), pLVar3 != NULL &&
             ((pLVar3->partition == '\0' || (pLVar3->partition == smp->grp->partition)))))) {
      smp_process_packet(smp,p,1,smp_write);
    }
LAB_080504e9:
    smp = smp->next;
  } while( true );
}

void q(SMP *smp)
{
  int print_source;
  int iVar1;
  char *pcVar2;
  unsigned int uVar3;
  IRPacket *pkt;
  IRAddress dest;
  int task;
  int type;
  unsigned int seqn;
  
  if (((smp->grp->mode == 0) || (smp->grp->mode == 2)) || (smp->grp->mode == 4)) {
    print_source = smp->grp->l2cmd->q->rspq_max_length;
  }
  else {
    print_source = 0;
  }
  iVar1 = rspq_get(smp->grp->l2cmd->q,&seqn,&dest,&pkt);
  if (iVar1 == -1) goto LAB_08050890;
  if (pkt == NULL) {
    smp_output(smp,"\n",-1);
    if (1 < print_source) {
      smp_output(smp,"L2 SMP ",-1);
    }
    smp_output(smp,"ERROR: no response from ",-1);
    iVar1 = -1;
    pcVar2 = format_address(dest);
    smp_output(smp,pcVar2,iVar1);
    smp_output(smp,"\n",-1);
  }
  else if (pkt->_err == '\0') {
    if ((pkt->_src & 0x80000000) == 0) {
      type = pkt->_src >> 0x1c;
    }
    else if (pkt->_src >> 0x1e == 2) {
      type = 0xe;
    }
    else {
      type = 0xf;
    }
    if ((pkt->_src & 0x80000000) == 0) {
      task = pkt->_src & 0x1f;
    }
    else {
      task = pkt->_src >> 0x18 & 0x3f;
    }
    if (task == 3) {
      if ((pkt->_argv[0]._clas & 7) != 0) {
        uVar3 = IRArg(pkt,0);
        if (uVar3 != 0) goto LAB_08050790;
        goto LAB_08050817;
      }
      if (pkt->_argv[0]._val == 0) goto LAB_08050817;
LAB_08050790:
      iVar1 = -1;
      pcVar2 = format_address(pkt->_src);
      smp_output(smp,pcVar2,iVar1);
      smp_output(smp," ",-1);
      if (pkt->_argc < 2) {
        smp_output(smp,"ERROR: no error description given\n",-1);
      }
      else {
        iVar1 = -1;
        if ((pkt->_argv[1]._clas & 7) == 0) {
          pcVar2 = (char *)IR_VAL_PTR(pkt->_argv[1]._val);
        }
        else {
          pcVar2 = (char *)IRArg(pkt,1);
        }
        smp_output(smp,pcVar2,iVar1);
      }
    }
    else {
LAB_08050817:
      if (print_source == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = 2;
      }
      smp_process_packet(smp,pkt,iVar1,smp_output);
    }
    IRouterFreePacket(pkt);
  }
  else {
    if (1 < print_source) {
      iVar1 = -1;
      pcVar2 = format_address(pkt->_src);
      smp_output(smp,pcVar2,iVar1);
      smp_output(smp," ",-1);
    }
    smp_output(smp,"\nERROR: couldn\'t send packet to ",-1);
    iVar1 = -1;
    pcVar2 = format_address(dest);
    smp_output(smp,pcVar2,iVar1);
    smp_output(smp,", ",-1);
    iVar1 = -1;
    pcVar2 = IRFmtError((unsigned int)pkt->_err);
    smp_output(smp,pcVar2,iVar1);
    smp_output(smp,"\n",-1);
    IRouterFreePacket(pkt);
  }
  iVar1 = rspq_empty(smp->grp->l2cmd->q);
  if (iVar1 == 0) {
    EventAddTimeOut(0,10000,q,(EventData)smp,"smp_process_queue");
    return;
  }
LAB_08050890:
  rspq_reset(smp->grp->l2cmd->q);
  EventEnableInput(smp->rfd,1);
  iVar1 = broadcast(smp->grp->l2cmd->q,smp->id);
  if (iVar1 == 0) {
    reqq_reset(smp->grp->l2cmd->q);
    l2cmd_process_response(smp->grp->l2cmd,NULL,0);
  }
  return;
}

static void smp_process_queue(SMP *smp)
{
  int task;
  int type;
  unsigned int seqn;
  
  rspq_timeout_clr(smp->grp->l2cmd->q);
  q(smp);
  return;
}

static void smp_timeout(L2CMD *c, int to, void *data)
{
  smp_process_queue(data);
  return;
}

static void smp_etimeout(L2CMD *c, char *msg, void *data)
{
  if ((msg != NULL) && (*msg != '\0')) {
    smp_output(data,msg,-1);
  }
  return;
}

void smp_process_response(IRPacket *p)
{
  int rpend;
  char x_ [80];
  char x [80];
  IRAddress dest;
  SMP *smp;
  
  smp = smp_list;
  while ((smp != NULL && (p->_dest != smp->id->addr))) {
    smp = smp->next;
  }
  if (smp == NULL) {
    IRouterFreePacket(p);
  }
  else {
    rpend = rspq_update(smp->grp->l2cmd->q,p);
    if (rpend == -1) {
      if (smp_debug != 0) {
        IRFmtPkt("SMP late response",p,x);
        fprintf(stderr,"%s\n",x);
      }
      IRFmtPkt("SMP late response",p,x_);
      nvramLogInsert(x_);
      IRouterFreePacket(p);
    }
    else if (rpend == 0) {
      smp_process_queue(smp);
    }
    else if (smp_debug != 0) {
      fprintf(stderr,"responses pending %d\n",rpend);
    }
  }
  return;
}

static void smp_command_done(L2CMD *c, void *data, char *crsp, int rval)
{
  int *piVar1;
  int iVar2;
  IRAddress conaddr;
  char *pcVar3;
  L2CfgL1 *cfg;
  SMP *smp;
  char buff [80];
  
  smp = (__typeof__(smp))data;   /* Ghidra merged smp into data */
  if (crsp != NULL) {
    smp_output(data,crsp,-1);
  }
  iVar2 = reqq_empty(c->q);
  if ((iVar2 != 0) && (iVar2 = rspq_empty(c->q), iVar2 != 0)) {
    c->busy = 0;
    if (smp->grp->mode == 2) {
      conaddr = smp_chkcon_present(data);
      if (conaddr == 0) {
        return;
      }
      smp_console(data,conaddr,1);
    }
    else if (smp->grp->mode == 4) {
      pcVar3 = format_address(smp->grp->l1addr);
      sprintf(buff,"\nre-entering L1 mode %s, <CTRL-T> to escape to L2\n",pcVar3);
      smp_output(data,buff,-1);
      smp_set_mode(data,3);
    }
    else if (smp->grp->mode == 3) {
      cfg = L2CfgMFindBrickCfg(&L2CfgLocal,
                               smp->grp->l1addr >> 0x12 & 0x3ff,
                               smp->grp->l1addr >> 0xc & 0x3f,0);
      if ((cfg != NULL) && (cfg->console_enabled != '\0')) {
        smp_output(data,"L1 appears to be in console mode, switching it to L1 mode\n",-1);
        smp_input_l1sysco(data,0x14);
        smp_input_l1sysco(data,0x6c);
        smp_input_l1sysco(data,0x31);
        smp_input_l1sysco(data,10);
      }
    }
    else if (smp->grp->mode == 0) {
      smp_prompt(data);
    }
    if (smp->grp->ilen != 0) {
      while (smp->grp->ilen != 0) {
        piVar1 = &smp->grp->ilen;
        *piVar1 = *piVar1 + -1;
        smp_input(data,&smp->grp->ibuf[smp->grp->ilen],1);
      }
    }
  }
  return;
}

void smp_read(SMP *smp)
{
  static char rbuf[2];
  int *piVar1;
  int iVar2;
  int rbytes;
  ssize_t sVar3;
  
  piVar1 = __errno_location();
  *piVar1 = 0;
  iVar2 = rspq_empty(smp->grp->l2cmd->q);
  if (iVar2 == 0) {
    if (((smp->grp->ilen < 1) &&
        (((smp->grp->mode == 0 || (smp->grp->mode == 2)) || (smp->grp->mode == 4)))) &&
       (rbytes = read(smp->rfd,smp->grp->ibuf + smp->grp->ilen,1), 0 < rbytes)) {
      if (smp->grp->ibuf[smp->grp->ilen] == '\x03') {
        reqrspq_reset(smp->grp->l2cmd->q);
        EventEnableInput(smp->rfd,1);
        smp->grp->ilen = 0;
        smp_command_done(smp->grp->l2cmd,smp,NULL,0);
      }
      else {
        piVar1 = &smp->grp->ilen;
        *piVar1 = *piVar1 + 1;
      }
    }
  }
  else {
    if (smp->grp->ilen != 0) {
      while (smp->grp->ilen != 0) {
        piVar1 = &smp->grp->ilen;
        *piVar1 = *piVar1 + -1;
        smp_input(smp,smp->grp->ibuf + smp->grp->ilen,1);
      }
    }
    sVar3 = read(smp->rfd,(char *)&rbuf,1);
    if (sVar3 < 1) {
      if ((smp->id->addr & 0x80000000) == 0) {
        if (smp->id->addr >> 0x1c != 0xf) {
          return;
        }
      }
      else if (smp->id->addr >> 0x1e == 2) {
        return;
      }
      smp_free(smp);
    }
    else {
      smp_input(smp,(char *)&rbuf,1);
    }
  }
  return;
}

void smp_write(SMP *smp, char *ibptr, int iblen)
{
  unsigned char *pbVar1;
  static char obuff[4096];
  static int oblen;
  static char *obptr;
  int *piVar2;
  int iVar3;
  int status;
  int iVar4;
  int __d1;
  char __result;
  char x___ [256];
  char x__ [256];
  char x_ [128];
  struct timeval dtime;
  struct timeval mtime;
  char x [256];
  int __d0;
  int fdmax;
  struct timeval wtime;
  fd_set wrset;
  int mode;
  
  if (smp->hung == 0) {
    if (iblen == -1) {
      iblen = strlen(ibptr);
    }
    if (iblen != 0) {
      oblen = 0;
      obptr = obuff;
      do {
        while ((iblen != 0 && ((unsigned int)oblen < 0xfff))) {
          if (*ibptr == '\n') {
            *obptr = '\r';
            obptr = obptr + 1;
            *obptr = '\n';
            oblen = oblen + 2;
          }
          else {
            *obptr = *ibptr;
            oblen = oblen + 1;
          }
          iblen = iblen + -1;
          ibptr = ibptr + 1;
          obptr = obptr + 1;
        }
        wtime.tv_sec = 5;
        wtime.tv_usec = 0;
        iVar3 = smp->wfd;
        FD_ZERO(&wrset);
        FD_SET(smp->wfd, &wrset);
        piVar2 = __errno_location();
        *piVar2 = 0;
        iVar3 = select(iVar3 + 1,NULL,(fd_set *)&wrset,NULL,(struct timeval *)&wtime);
        if (iVar3 < 0) {
          piVar2 = __errno_location();
          sprintf(x,"SMP %d (%d) select error %d",smp->grpid,smp_count,*piVar2);
          nvramLogFinsert(x);
          smp->hung = 1;
          return;
        }
        dtime.tv_sec = -wtime.tv_sec + 5;
        dtime.tv_usec = -wtime.tv_usec;
        if (dtime.tv_usec < 0) {
          dtime.tv_sec = -wtime.tv_sec + 4;
          dtime.tv_usec = dtime.tv_usec + 1000000;
        }
        if ((0 < dtime.tv_sec) || (0 < dtime.tv_usec)) {
          sprintf(x_,"SMP %d waited %d.%06d",smp->grpid,dtime.tv_sec,dtime.tv_usec);
          nvramLogFinsert(x_);
        }
        if (FD_ISSET(smp->wfd, &wrset) == 0) {
          sprintf(x__,"SMP %d (%d) select timeout",smp->grpid,smp_count);
          nvramLogFinsert(x__);
          smp->hung = 1;
          return;
        }
        piVar2 = __errno_location();
        *piVar2 = 0;
        status = write(smp->wfd,(void *)&obuff,oblen);
        if ((status < 0) && (piVar2 = __errno_location(), *piVar2 == 0xb)) {
          sprintf(x__,"SMP %d (%d) write would block",smp->grpid,smp_count);
          nvramLogFinsert(x__);
          smp->hung = 1;
          return;
        }
        if (status < 0) {
          piVar2 = __errno_location();
          sprintf(x,"SMP %d (%d) write error %d",smp->grpid,smp_count,*piVar2);
          nvramLogFinsert(x);
          smp->hung = 1;
          return;
        }
        if (status == oblen) {
          oblen = 0;
          obptr = (char *)&obuff;
        }
        else {
          sprintf(x___,"SMP %d (%d) partial write %d/%d",smp->grpid,smp_count,status,oblen);
          nvramLogFinsert(x___);
          if (status != 0) {
            memmove(obuff,obuff + status,oblen - status);
            obptr = obuff + status;
            oblen = status;
          }
        }
      } while ((iblen != 0) || (oblen != 0));
    }
  }
  return;
}

void smp_echo(SMP *smp)
{
  int blen;
  char buff [512];
  
  blen = read(smp->grp->shell,buff,0x200);
  if (blen < 1) {
    EventRemoveInput(smp->grp->shell);
    close(smp->grp->shell);
    smp_set_mode(smp,0);
    smp_prompt(smp);
  }
  else {
    smp_output(smp,buff,blen);
  }
  return;
}

void smp_console(SMP *smp, IRAddress conaddr, int reenter)
{
  int iVar1;
  char *pcVar2;
  unsigned char *puVar3;
  char buff [200];
  
  iVar1 = power_status(conaddr >> 0x12 & 0x3ff,conaddr >> 0xc & 0x3f);
  if (iVar1 == 0) {
    pcVar2 = format_caddress(conaddr,smp->grp->partition);
    sprintf(buff,"\nWARNING: power on %s appears off\n",pcVar2);
    smp_output(smp,buff,-1);
  }
  pcVar2 = format_caddress(conaddr,smp->grp->partition);
  if (reenter == 0) {
    puVar3 = "";
  }
  else {
    puVar3 = "re-";
  }
  sprintf(buff,"\n%sentering system console mode (%s), <CTRL_T> to escape to L2\n",puVar3,pcVar2);
  smp_output(smp,buff,-1);
  iVar1 = L2CfgMAdviseConsole(&L2CfgLocal,buff,smp->grp->partition,conaddr);
  if (iVar1 != 0) {
    smp_output(smp,buff,-1);
  }
  smp_set_mode(smp,1);
  smp->grp->cptr = smp->grp->cbuf;
  cfg_check_console_events();
  return;
}

void smp_tty_config(int fd, int baud)
{
  int iVar1;
  char *pcVar2;
  int *piVar3;
  speed_t sVar4;
  struct termios termios;
  
  iVar1 = isatty(fd);
  if ((iVar1 != 0) || (pcVar2 = ptsname(fd), pcVar2 != NULL)) {
    iVar1 = tcgetattr(fd,(struct termios *)&termios);
    if (iVar1 == -1) {
      piVar3 = __errno_location();
      fprintf(stderr,"ERROR: can\'t get termios, errno: %d\n",*piVar3);
    }
    else {
      smp_tty[fd].c_iflag = termios.c_iflag;
      smp_tty[fd].c_oflag = termios.c_oflag;
      smp_tty[fd].c_lflag = termios.c_lflag;
      smp_tty[fd].c_cflag = termios.c_cflag;
      memcpy(smp_tty[fd].c_cc,termios.c_cc,0x20);
      sVar4 = cfgetospeed((struct termios *)&termios);
      smp_tty[fd].ospeed = sVar4;
      sVar4 = cfgetispeed((struct termios *)&termios);
      smp_tty[fd].ispeed = sVar4;
      smp_tty[fd].configured = 1;
      termios.c_iflag = (termios.c_iflag & 0xffffe83f) | 0x20;
      termios.c_oflag = termios.c_oflag | 1;
      termios.c_lflag = termios.c_lflag & 0xfffffff5;
      if (l2_pc == 0) {
        termios.c_cflag = termios.c_cflag | 0x80000000;
      }
      termios.c_cc[0] = '\0';
      termios.c_cc[10] = '\0';
      termios.c_cc[6] = '\x01';
      termios.c_cc[2] = '\b';
      termios.c_cc[3] = '\v';
      cfsetospeed((struct termios *)&termios,baud);
      cfsetispeed((struct termios *)&termios,baud);
      iVar1 = tcsetattr(fd,0,(struct termios *)&termios);
      if (iVar1 == -1) {
        piVar3 = __errno_location();
        fprintf(stderr,"ERROR: can\'t set termios, errno: %d\n",*piVar3);
      }
    }
  }
  return;
}

void smp_tty_reconfig(int fd)
{
  int iVar1;
  int *piVar2;
  struct termios termios;
  
  if (smp_tty[fd].configured != 0) {
    iVar1 = tcgetattr(0,(struct termios *)&termios);
    if (iVar1 == -1) {
      piVar2 = __errno_location();
      fprintf(stderr,"ERROR: can\'t get termios, errno: %d.\n",*piVar2);
    }
    else {
      termios.c_iflag = smp_tty[fd].c_iflag;
      termios.c_oflag = smp_tty[fd].c_oflag;
      termios.c_lflag = smp_tty[fd].c_lflag;
      memcpy(termios.c_cc,smp_tty[fd].c_cc,0x20);
      cfsetospeed((struct termios *)&termios,smp_tty[fd].ospeed);
      cfsetispeed((struct termios *)&termios,smp_tty[fd].ispeed);
      iVar1 = tcsetattr(fd,0,(struct termios *)&termios);
      if (iVar1 == -1) {
        piVar2 = __errno_location();
        fprintf(stderr,"ERROR: can\'t set termios, errno; %d.\n",*piVar2);
      }
    }
    smp_tty[fd].configured = 0;
  }
  return;
}

void smp_tty_debug(int fd)
{
  int iVar1;
  int *piVar2;
  char *local_EAX_298;
  char index [8];
  struct termios termios;
  int i;
  
  iVar1 = tcgetattr(fd,(struct termios *)&termios);
  if (iVar1 == -1) {
    piVar2 = __errno_location();
    fprintf(stderr,"WARNING: can\'t get termios, errno: %d\n",*piVar2);
  }
  else {
    fprintf(stderr,"---\niflag:  0x%04x\n",termios.c_iflag);
    fprintf(stderr,"oflag:  0x%04x\n",termios.c_oflag);
    fprintf(stderr,"cflag:  0x%04x\n",termios.c_cflag);
    fprintf(stderr,"lflag:  0x%04x\n",termios.c_lflag);
    fprintf(stderr,"ispeed: 0x%08x\n",termios.c_ispeed);
    fprintf(stderr,"ospeed: 0x%08x\n",termios.c_ospeed);
    for (i = 0; i < 0x20; i = i + 1) {
      sprintf(index,"0x%02x",i);
      local_EAX_298 = smp_cc[i];
      if (smp_cc[i] == NULL) {
        local_EAX_298 = index;
      }
      fprintf(stderr,"%2d cc_c[%-8s]: 0x%04x\n",fd,local_EAX_298,(unsigned int)termios.c_cc[i]);
    }
  }
  return;
}

static void smp_event(int opcode, int group, char *bptr)
{
  size_t sVar1;
  IRPacket *p;
  char *b;
  IRArgument argv [3];
  
  argv[0]._clas = '\0';
  argv[0]._frame = '\0';
  argv[0]._val = opcode;
  argv[0]._size = 0;
  argv[1]._clas = '\0';
  argv[1]._frame = '\0';
  argv[1]._val = group;
  argv[1]._size = 0;
  if (bptr == NULL) {
    argv[2]._clas = '\0';
    argv[2]._frame = '\0';
    argv[2]._val = 0;
    argv[2]._size = 0;
  }
  else {
    argv[2]._val = IR_PTR_VAL(strdup(bptr));
    argv[2]._clas = '\n';
    argv[2]._frame = '\0';
    sVar1 = strlen((char *)IR_VAL_PTR(argv[2]._val));
    argv[2]._size = (short)sVar1 + 1;
  }
  p = IRouterMakePacket(&l2_console_id,NULL,0,(unsigned int)(opcode != 4),2,2,3,argv);
  if (p != NULL) {
    IRouterSendPacket(&l2_console_id,p);
  }
  return;
}

/* All of l2's printed output goes to the connected SMP clients (or stderr
 * when there are none); console_event marks text that is also an event for
 * the consoles (opcode 4) rather than plain output (opcode 2). */
static int smp_vprintf(int console_event, const char *format, va_list ap)
{
  static int active;
  int rval;
  SMP *smp;

  if (active)
    return 0;
  active = 1;
  rval = vsprintf(vbuf,format,ap);
  if ((smp_list == NULL) && (enet_only == 0)) {
    write(2,vbuf,strlen(vbuf));
  }
  else {
    smp_event(console_event ? 4 : 2,-1,vbuf);
    for (smp = smp_list; smp != NULL; smp = smp->next) {
      smp_write(smp,vbuf,strlen(vbuf));
    }
  }
  active = 0;
  return rval;
}

/* Replaces libc's fprintf in l2. SGI's code passes a NULL stream for console
 * events; l2_console_printf() says so by name. (The volatile read: glibc
 * declares stream nonnull, which would let the compiler drop the test.) */
int fprintf(FILE *restrict stream, const char *restrict format, ...)
{
  va_list ap;
  int rval;

  va_start(ap,format);
  rval = smp_vprintf(*(FILE *volatile *)&stream == NULL,format,ap);
  va_end(ap);
  return rval;
}

int l2_console_printf(const char *format, ...)
{
  va_list ap;
  int rval;

  va_start(ap,format);
  rval = smp_vprintf(1,format,ap);
  va_end(ap);
  return rval;
}
