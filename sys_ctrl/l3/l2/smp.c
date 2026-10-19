/*
 * sys_ctrl/l3/l2/smp.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/smp.c
 *
 * SMP: the L2's consoles (its serial console and modem, and telnet-style
 * network sessions, serial.c and enet.c). A session reads a command line
 * with simple editing and runs it through l2cmd.c; in console mode its
 * keys go to the system console's brick and the console output comes back
 * as events; in L1 mode they go to one L1's command processor. Sessions in
 * a group share the line, the mode and the output.
 *
 * l2's fprintf() is here too: everything l2 prints goes to the sessions.
 */

#define _GNU_SOURCE     /* ptsname() */
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>
#include "l2.h"
#include "smp.h"
#include "broadcast.h"
#include "cfg.h"
#include "enet.h"
#include "format.h"
#include "irtr.h"
#include "power.h"
#include "pty.h"
#include "route.h"
#include "serial.h"
#include "../main/nvram.h"

#define KEY_CTRL(c)        ((c) & 0x1f)
#define LINE_MAX_LEN    128     /* SMPGroup.cbuf */
#define MAX_FDS         256     /* smp_tty[] */
#define OUT_MAX         4096    /* smp_write()'s buffer */

/* smp_event() opcodes: the console events l2gui and other clients follow */
enum { SMP_EV_OPEN = 1, SMP_EV_OUTPUT = 2, SMP_EV_CLOSE = 3, SMP_EV_CONSOLE = 4 };

/* a terminal's settings before smp_tty_config(), to put back */
typedef struct {
    int configured;
    struct termios t;
} SMPTty;

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
static SMPTty smp_tty[MAX_FDS];
static char vbuf[1024];

/* a new group of one: its own line buffer and command state */
static SMPGroup *new_group(SMP *smp)
{
  SMPGroup *g = malloc(sizeof(SMPGroup));

  memset(g,0,sizeof(*g));
  g->id = smp->grpid;
  g->confilter = 0;
  g->count = 1;
  g->clen = LINE_MAX_LEN;
  g->cptr = g->cbuf;
  return g;
}

/* a new session on rfd/wfd: rfcn closes it; host is the peer's address
 * for network sessions */
SMP *smp_init(IRIdent *id, int rfd, int wfd, void (*rfcn)(), uint32 host, int port)
{
  int task = IR_ADDR_TASK(id->addr);
  SMP *smp;
  char *pw;
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
  smp->grpid = task == IR_L2_MODEM ? 1 : smp->rfd;
  smp->grp = new_group(smp);
  smp->grp->mode = SMP_MODE_L2;
  smp->grp->l2cmd = l2cmd_init(smp->id,smp_timeout,smp_etimeout,smp_command_done,smp);
  /* sessions other than the serial ones log in, if the L2 has a password */
  if (task != IR_L2_CONSOLE && task != IR_L2_MODEM) {
    pw = (char *)nvramGet(NVRAM_PASSWORD);
    if (pw != NULL && *pw != '\0')
      smp->password = 1;
  }
  smp->next = smp_list;
  smp_count++;
  smp_list = smp;
  baud = B38400;
  if (task == IR_L2_MODEM) {
    switch (nvramGet(NVRAM_MODEM_BAUD)) {
    case 1:
      baud = B19200;
      break;
    case 2:
      baud = B9600;
      break;
    default:
      nvramSet(NVRAM_MODEM_BAUD,0);
    }
  }
  smp_tty_config(smp->rfd,baud);
  EventAddInput(smp->rfd,smp_read,(EventData)smp,"smp_init");
  smp_event(SMP_EV_OPEN,smp->grpid,NULL);
  smp_prompt(smp);
  return smp;
}

/* close a session (prev: the one before it in smp_list, or NULL) */
static void close_session(SMP *smp, SMP *prev)
{
  smp_event(SMP_EV_CLOSE,smp->grpid,NULL);
  smp_tty_reconfig(smp->rfd);
  if (prev == NULL)
    smp_list = smp->next;
  else
    prev->next = smp->next;
  EventRemoveInput(smp->rfd);
  if (smp->rfcn != NULL)
    smp->rfcn(smp->rfd);
  if (--smp->grp->count == 0) {
    l2cmd_free(smp->grp->l2cmd);
    free(smp->grp);
  }
  free(smp);
}

void smp_free(SMP *smp)
{
  SMP *prev = NULL;
  SMP *curr;

  for (curr = smp_list; curr != NULL && curr != smp; curr = curr->next)
    prev = curr;
  if (curr == NULL)
    return;
  close_session(curr,prev);
  smp_count--;
}

/* close the sessions whose output blocked (smp_write()) */
void smp_cleanup(void)
{
  SMP *prev = NULL;
  SMP *next;
  SMP *curr;
  char x[100];

  for (curr = smp_list; curr != NULL; curr = next) {
    /* (the original took the next one from the session it had freed, and
     * did not count it gone) */
    next = curr->next;
    if (!curr->hung) {
      prev = curr;
      continue;
    }
    sprintf(x,"INFO: SMP session %d from %s appears hung, closing.\n",curr->grpid,SocketAddrStr(curr->host));
    nvramLogFinsert("%s",x);
    fprintf(stderr,"%s",x);
    close_session(curr,prev);
    smp_count--;
  }
}

void smp_reset(void)
{
  while (smp_list != NULL)
    smp_free(smp_list);
}

int smp_is_valid(SMP *smp)
{
  SMP *tsmp;

  for (tsmp = smp_list; tsmp != NULL && tsmp != smp; tsmp = tsmp->next)
    ;
  return tsmp != NULL;
}

/* "smp modem baud": 0 38400, 1 19200, 2 9600 */
void smp_baud(int baud)
{
  SMP *s;

  nvramSet(NVRAM_MODEM_BAUD,baud);
  baud = baud == 1 ? B19200 : baud == 0 ? B38400 : B9600;
  for (s = smp_list; s != NULL; s = s->next) {
    if (IR_ADDR_TYPE(s->id->addr) == IR_ADDR_IP && IR_ADDR_TASK(s->id->addr) == IR_L2_MODEM) {
      smp_tty_config(s->rfd,baud);
      return;
    }
  }
}

/* the sessions in console mode, and (into pselect, if given) the
 * partitions they follow */
int smp_console_count(unsigned char *pselect)
{
  int count = 0;
  SMP *smp;

  if (pselect != NULL)
    memset(pselect,0,0x100);
  for (smp = smp_list; smp != NULL; smp = smp->next) {
    if (smp->grp->mode != SMP_MODE_CONSOLE && smp->grp->mode != SMP_MODE_CONSOLE_ESC)
      continue;
    if (pselect != NULL && smp->grp->partition != 0 && smp->grp->partition < 0x100)
      pselect[smp->grp->partition] = 1;
    count++;
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

/* the L1 for L1 mode: its command processor (task IR_L1_SMP) */
IRAddress smp_set_l1addr(SMP *smp, IRAddress l1addr)
{
  smp->grp->l1addr = IR_ADDR_WITH_TASK(l1addr,IR_L1_SMP);
  return smp->grp->l1addr;
}

/* the session's system console: its override, else its partition's;
 * *override says which */
IRAddress smp_get_conaddr(SMP *smp, IRAddress *raddr, int *override)
{
  IRAddress addr = smp->grp->conaddr;
  int over = addr != 0;

  if (addr == 0)
    addr = L2CfgMGetConsole(&L2CfgLocal,smp->grp->partition);
  if (raddr != NULL)
    *raddr = addr;
  if (override != NULL)
    *override = over;
  return addr;
}

/* override the system console (0: back to the default); only a compute
 * brick's. Returns the new override, 0 if refused. */
IRAddress smp_set_conaddr(SMP *smp, IRAddress new_conaddr)
{
  char buff[128];
  L2CfgL1 *cfg;

  if (new_conaddr == 0) {
    smp->grp->conaddr = 0;
    smp->grp->confilter = 0;
    return 0;
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(new_conaddr),IR_ADDR_SLOT(new_conaddr),0);
  if (cfg == NULL || !brickIsCompute(cfg->type))
    return 0;
  smp->grp->conaddr = new_conaddr;
  smp->grp->confilter = 0;
  sprintf(buff,"INFO: default system console override, changed to: %s\n",format_caddress(new_conaddr,0));
  smp_output(smp,buff,-1);
  return new_conaddr;
}

int smp_get_partition(SMP *smp)
{
  return smp->grp->partition;
}

/* follow a partition (0: none), if it has a console; returns that */
int smp_set_partition(SMP *smp, int partition)
{
  IRAddress addr = 0;

  if (partition != 0) {
    addr = L2CfgMGetConsole(&L2CfgLocal,partition);
    if (addr == 0)
      return 0;
  }
  smp->grp->partition = partition;
  smp->grp->conaddr = 0;
  smp->grp->confilter = 0;
  cfg_check_console_events();
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

/* "smp": the sessions, into *results (malloc()ed) */
void smp_query(SMP *smp, int verbose, char **results)
{
  static const char *const modes[] = {
    "L2                ", "console           ", "console (escaped) ",
    "L1                ", "L1 (escaped)      ", "shell             ",
  };
  IRAddress addr;
  int override;
  int count = 0;
  char *rptr;
  SMP *s;

  for (s = smp_list; s != NULL; s = s->next)
    count++;
  /* (the original allowed 80 bytes a line, short of a long console name) */
  rptr = malloc((count + 2) * 160);
  *results = rptr;
  rptr += sprintf(rptr,"Session Who          Baud  Group Mode              Console          \n");
  rptr += sprintf(rptr,"------- ------------ ----- ----- ----------------- -----------------\n");
  for (s = smp_list; s != NULL; s = s->next) {
    rptr += sprintf(rptr,"%s%3d ",s == smp ? ">>> " : "    ",s->grpid);
    if (IR_ADDR_TYPE(s->id->addr) == IR_ADDR_IP) {
      switch (IR_ADDR_TASK(s->id->addr)) {
      case IR_L2_CONSOLE:
        rptr += sprintf(rptr,"console port 38400 ");
        break;
      case IR_L2_MODEM:
        rptr += sprintf(rptr,"modem port   ");
        switch (nvramGet(NVRAM_MODEM_BAUD)) {
        case 1:
          rptr += sprintf(rptr,"19200 ");
          break;
        case 0:
          rptr += sprintf(rptr,"38400 ");
          break;
        case 2:
          rptr += sprintf(rptr," 9600 ");
          break;
        default:
          rptr += sprintf(rptr,"%5d ",(int)nvramGet(NVRAM_MODEM_BAUD));
        }
        break;
      default:
        rptr += sprintf(rptr,"unknown        n/a ");
      }
    }
    else if (IR_ADDR_TYPE(s->id->addr) == IR_ADDR_IP_OTHER)
      rptr += sprintf(rptr,"network port   n/a ");
    rptr += sprintf(rptr,"%5d ",s->grp->id);
    if (s->grp->mode >= 0 && s->grp->mode < (int)(sizeof(modes) / sizeof(modes[0])))
      rptr += sprintf(rptr,"%s",modes[s->grp->mode]);
    else
      rptr += sprintf(rptr,"unknown (%4d)   ",s->grp->mode);
    if (smp_get_conaddr(s,&addr,&override) == 0)
      rptr += sprintf(rptr,"not defined\n");
    else
      rptr += sprintf(rptr,"%s %s\n",format_caddress(addr,s->grp->partition),
                      override ? "(override)" : "(default)");
  }
}

/* tell the first other session of g that smp left it */
static void left_group(SMP *smp, SMPGroup *g)
{
  char buff[128];
  SMP *s;

  for (s = smp_list; s != NULL; s = s->next) {
    if (s->grp == NULL || s->grp->id != g->id)
      continue;
    s->grp->cptr = s->grp->cbuf;
    *s->grp->cptr = '\0';
    sprintf(buff,"INFO: SMP session %d left",smp->rfd);
    smp_output(s,buff,-1);
    smp_input(s,"\r",1);
    return;
  }
}

/* "smp join <group>": share that group's line; -1 if there is none */
int smp_join(SMP *smp, int group)
{
  char buff[128];
  SMPGroup *g;
  SMP *s1;

  if (smp->grp != NULL && smp->grp->id == group)
    return 0;
  for (s1 = smp_list; s1 != NULL; s1 = s1->next) {
    if (s1->grp->id != group)
      continue;
    g = smp->grp;
    smp->grp = NULL;
    if (g != NULL && --g->count == 0) {
      l2cmd_free(g->l2cmd);
      free(g);
    }
    else if (g != NULL)
      left_group(smp,g);
    s1->grp->cptr = s1->grp->cbuf;
    *s1->grp->cptr = '\0';
    sprintf(buff,"\nINFO: SMP session %d joined this group\n",smp->rfd);
    smp_output(s1,buff,-1);
    s1->grp->count++;
    smp->grp = s1->grp;
    return 0;
  }
  return -1;
}

/* "smp leave": back to a group of one */
int smp_leave(SMP *smp)
{
  SMPGroup *g;

  if (smp->grp->id == smp->rfd)
    return -1;
  /* (the session's own group, if another session joined it) */
  if (smp_join(smp,smp->rfd) == 0)
    return 0;
  g = smp->grp;
  smp->grp = NULL;
  if (--g->count == 0) {
    l2cmd_free(g->l2cmd);
    free(g);
  }
  else
    left_group(smp,g);
  smp->grp = new_group(smp);
  smp_set_mode(smp,SMP_MODE_L2);
  smp->grp->l2cmd = l2cmd_init(smp->id,smp_timeout,smp_etimeout,smp_command_done,smp);
  return 0;
}

/* one key to the L1 of L1 mode (its answer awaited for 10 seconds) */
void smp_input_l1sysco(SMP *smp, int c)
{
  IRArgument argv[2];
  IRPacket *p;

  memset(argv,0,sizeof(argv));
  argv[1]._val = (uint32)(char)c;
  p = IRouterMakePacket(smp->id,&smp->grp->l1addr,0,0,IR_REQ,2,2,argv);
  if (p == NULL) {
    fprintf(stderr,"WARNING: can\'t create packet for L1.\n");
    return;
  }
  l2cmd_queue_response(smp->grp->l2cmd,smp->id->seqnum - 1,smp->grp->l1addr,10);
  EventEnableInput(smp->rfd,0);
  IRouterSendPacket(smp->id,p);
}

/* one key to the system console: its brick's IR_L1_BDR task, the CPU (the
 * console address's task) as pdata (its answer awaited for 20 seconds) */
void smp_input_console(SMP *smp, int c)
{
  IRAddress conaddr = smp_get_conaddr(smp,NULL,NULL);
  IRAddress addr = IR_ADDR_WITH_TASK(conaddr,IR_L1_BDR);
  IRArgument argv[2];
  IRPacket *p;

  memset(argv,0,sizeof(argv));
  argv[1]._val = (uint32)(char)c;
  p = IRouterMakePacket(smp->id,&addr,IR_ADDR_TASK(conaddr),0,IR_REQ,2,2,argv);
  if (p == NULL) {
    fprintf(stderr,"WARNING: can\'t create packet for console.\n");
    return;
  }
  l2cmd_queue_response(smp->grp->l2cmd,smp->id->seqnum - 1,addr,20);
  EventEnableInput(smp->rfd,0);
  IRouterSendPacket(smp->id,p);
}

/* echo a key typed into the line: printable as itself, control
 * characters as ^X, others as \nnn */
static void echo_key(SMP *smp, char c)
{
  char tmp[8];   /* original: 5, overflowed by "\\-128" (a negative char) */

  if (isprint((int)c)) {
    /* (a string: smp_event() copies the text whole) */
    tmp[0] = c;
    tmp[1] = '\0';
    smp_output(smp,tmp,1);
  }
  else if (c > 0 && c < 27) {
    sprintf(tmp,"^%c",(int)(char)(c | 0x40));
    smp_output(smp,tmp,-1);
  }
  else {
    sprintf(tmp,"\\%03d",(int)c);
    smp_output(smp,tmp,-1);
  }
}

/* rub out the line's last character on the screen */
static void rub_out(SMP *smp)
{
  SMPGroup *g = smp->grp;

  if (g->cptr <= g->cbuf)
    return;
  g->cptr--;
  if (!smp->password) {
    if (isprint((int)*g->cptr))
      smp_output(smp,"\b \b",-1);
    else if (*g->cptr < 1 || *g->cptr > 26)
      smp_output(smp,"\b\b\b\b    \b\b\b\b",-1);
    else
      smp_output(smp,"\b\b  \b\b",-1);
  }
  *g->cptr = '\0';
}

/* the line is complete: run it (or check it as the password) */
static void run_line(SMP *smp)
{
  SMPGroup *g = smp->grp;
  char *rptr;
  char *pw;

  if (g->lpbk_pending || route_pending) {
    if (g->lpbk_pending)
      smp_output(smp,"\nno response from loopback command",-1);
    g->lpbk_pending = 0;
    if (route_pending)
      smp_output(smp,"\nno response from route command",-1);
    route_pending = 0;
  }
  smp_output(smp,"\n",-1);
  if (g->cbuf[0] != '\0' || smp->password) {
    rptr = NULL;
    g->l2cmd->data = smp;
    if (!smp->password)
      l2cmd_process(g->l2cmd,g->cbuf,&rptr,NULL);
    else {
      pw = (char *)nvramGet(NVRAM_PASSWORD);
      if (pw == NULL || *pw == '\0' || strcmp(pw,g->cbuf) == 0)
        smp->password = 0;
      else {
        smp_output(smp,"incorrect password\n",-1);
        /* network sessions get three tries */
        if (smp->password++ > 2 && smp != serial_console && smp != serial_modem) {
          smp_output(smp,"disconnecting after 3 failed password attempts\n",-1);
          smp_free(smp);
        }
      }
    }
    if (!smp_is_valid(smp))
      return;
    g = smp->grp;
    if (rptr != NULL) {
      smp_output(smp,rptr,-1);
      free(rptr);
    }
    g->cptr = g->cbuf;
    *g->cptr = '\0';
  }
  if (!g->l2cmd->busy && !g->lpbk_pending && !route_pending)
    smp_command_done(g->l2cmd,smp,NULL,0);
}

/* the escapes that work in any mode: CTRL-D for console mode, CTRL-T
 * out of console or L1 mode; 1 if the key was one */
static int escape_key(SMP *smp, char c)
{
  SMPGroup *g = smp->grp;
  IRAddress conaddr;
  char buff[80];

  if (c == '\0')
    return 1;
  if (c == KEY_CTRL('D')) {
    if (g->mode == SMP_MODE_L2) {
      conaddr = smp_chkcon_present(smp);
      if (conaddr != 0)
        smp_console(smp,conaddr,0);
      return 1;
    }
    if (g->mode == SMP_MODE_L1) {
      smp_output(smp,"\nERROR: can\'t enter console mode from L1 mode via L2\n",-1);
      sprintf(buff,"\nre-entering L1 mode %s, <CTRL-T> to escape to L2\n",format_address(g->l1addr));
      smp_output(smp,buff,-1);
      smp_input_l1sysco(smp,'\n');
      return 1;
    }
    return 0;
  }
  if (c != KEY_CTRL('T'))
    return 0;
  switch (g->mode) {
  case SMP_MODE_CONSOLE:
    smp_set_mode(smp,SMP_MODE_CONSOLE_ESC);
    if (g->cptr == g->cbuf) {
      smp_output(smp,"\nescaping to L2 system controller\n",-1);
      smp_prompt(smp);
    }
    return 1;
  case SMP_MODE_L1:
    smp_set_mode(smp,SMP_MODE_L1_ESC);
    if (g->cptr == g->cbuf) {
      smp_output(smp,"\nescaping to L2 system controller, <CTRL_T> to send escape to L1\n",-1);
      smp_prompt(smp);
    }
    return 1;
  case SMP_MODE_L1_ESC:
    /* (CTRL-T again: back to the L1, if the line is empty) */
    if (g->cptr == g->cbuf)
      smp_set_mode(smp,SMP_MODE_L1);
    return 1;
  case SMP_MODE_L2:
  case SMP_MODE_CONSOLE_ESC:
    return 1;
  }
  return 0;
}

/* a key (the first of rbuf) from the session */
void smp_input(SMP *smp, char *rbuf, int rlen)
{
  SMPGroup *g = smp->grp;
  char c = *rbuf;

  errno = 0;
  if (smp_input_debug > 1) {
    printf("** smp input %02x, mode %d, rfd %d, session %d\n",(int)c,g->mode,smp->rfd,g->id);
    fflush(stdout);
  }
  if (g->mode == SMP_MODE_SHELL) {
    write(g->shell,rbuf,rlen);
    return;
  }
  if (!smp->password && escape_key(smp,c))
    return;
  switch (g->mode) {
  case SMP_MODE_L2:
  case SMP_MODE_CONSOLE_ESC:
  case SMP_MODE_L1_ESC:
    /* the L2's command line */
    switch (c) {
    case '\n':
    case '\r':
      run_line(smp);
      return;
    case KEY_CTRL('C'):
      if (smp->password) {
        g->cptr = g->cbuf;
        *g->cptr = '\0';
        smp_output(smp,"\n",-1);
        smp_prompt(smp);
        return;
      }
      while (g->cptr != g->cbuf)
        smp_input(smp,"\b",1);
      return;
    case '\b':
    case 127:
      rub_out(smp);
      return;
    }
    /* (one byte for the NUL: the original took a 128th character, whose
     * NUL went into clen, and the line was full from then on) */
    if (g->cptr >= g->cbuf + g->clen - 1) {
      smp_output(smp,"\a",1);
      return;
    }
    *g->cptr++ = c;
    *g->cptr = '\0';
    if (!smp->password)
      echo_key(smp,c);
    break;
  case SMP_MODE_CONSOLE:
    if (smp_chkcon_present(smp) != 0)
      smp_input_console(smp,c);
    break;
  case SMP_MODE_L1:
    smp_input_l1sysco(smp,c);
    break;
  }
}

/* output to every session of smp's group (and as an event) */
void smp_output(SMP *smp, char *bptr, int blen)
{
  SMP *s;

  smp_event(SMP_EV_OUTPUT,smp->grp->id,bptr);
  for (s = smp_list; s != NULL; s = s->next)
    if (s->grp != NULL && s->grp->id == smp->grp->id)
      smp_write(s,bptr,blen);
}

/* "<sysname or ssn or ?>-<rack, or the IP address>-L2>" (with the
 * partition: "L2:p<n>>"), or the password prompt */
void smp_prompt(SMP *smp)
{
  char prompt[128];
  const char *s;
  char *p;

  if (smp->password) {
    smp_output(smp,"Password: ",-1);
    return;
  }
  if (L2CfgLocal.sysname[0] != '\0')
    s = L2CfgLocal.sysname;
  else if (L2CfgLocal.ssn[0] != '\0')
    s = L2CfgLocal.ssn;
  else
    s = "?";
  prompt[0] = '\0';
  if (L2CfgLocal.net.msmode == 1)
    sprintf(prompt,"WARNING: This is a secondary L2, system controller access is limited...\n");
  p = prompt + strlen(prompt);
  if (L2CfgLocal.rack == 0 || L2CfgLocal.rack == -1)
    p += sprintf(p,"%s-%s-",s,SocketAddrStr(l2_ip));
  else
    p += sprintf(p,"%s-%03d-",s,L2CfgLocal.rack);
  if (smp->grp == NULL || smp->grp->partition == 0)
    sprintf(p,"L2>");
  else
    sprintf(p,"L2:p%d>",smp->grp->partition);
  smp_output(smp,prompt,-1);
}

/* the session's system console, or 0 (and back to L2 mode) if it has none */
IRAddress smp_chkcon_present(SMP *smp)
{
  IRAddress addr;
  char buff[100];

  addr = smp_get_conaddr(smp,NULL,NULL);
  if (addr != 0)
    return addr;
  if (smp->grp->partition == 0)
    sprintf(buff,"\nINFO: ERROR: no system console defined\n");
  else
    sprintf(buff,"\nINFO: ERROR: no system console for partition %d defined\n",smp->grp->partition);
  smp_output(smp,buff,-1);
  smp_set_mode(smp,SMP_MODE_L2);
  smp_prompt(smp);
  return 0;
}

/* around a configuration change: 0 snapshots the detected system consoles,
 * 1 tells console sessions (with smp_console_debug) about changes */
void smp_chkcon_changes(int get_check)
{
  static L2CfgSysCon syscon_snap[256];
  IRAddress old_conaddr;
  IRAddress addr;
  char buff[128];
  SMP *smp;
  int p;

  if (get_check == 0) {
    memcpy(syscon_snap,L2CfgLocal.syscon,sizeof(syscon_snap));
    return;
  }
  if (memcmp(syscon_snap,L2CfgLocal.syscon,sizeof(syscon_snap)) == 0)
    return;
  for (p = 0; p < 256; p++) {
    old_conaddr = syscon_snap[p].detected;
    addr = L2CfgLocal.syscon[p].detected;
    if (old_conaddr == addr)
      continue;
    for (smp = smp_list; smp != NULL; smp = smp->next) {
      if (!smp_console_debug || smp->grp->conaddr != 0 || smp->grp->partition != p ||
          (smp->grp->mode != SMP_MODE_CONSOLE && smp->grp->mode != SMP_MODE_CONSOLE_ESC))
        continue;
      if (p == 0)
        smp_output(smp,"INFO: system console ",-1);
      else {
        sprintf(buff,"INFO: partition %d system console ",p);
        smp_output(smp,buff,-1);
      }
      if (addr == 0)
        sprintf(buff,"on %s lost\n",format_caddress(old_conaddr,0));
      else
        sprintf(buff,"changed: %s\n",format_caddress(addr,0));
      smp_output(smp,buff,-1);
    }
  }
}

/* "shell [<command>]": /bin/sh on a pty, its output to the session */
int smp_shell(SMP *smp, char *cmd)
{
  struct sigaction sa;
  char *argv[4];
  int master_fd;
  int slave_fd;
  pid_t pid;

  master_fd = pty_master();
  if (master_fd < 0)
    return -1;
  pid = fork();
  smp->grp->shell = pid;
  if (pid == 0) {
    sigaction(SIGINT,NULL,&sa);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGQUIT,NULL,&sa);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGQUIT,&sa,NULL);
    if (setsid() < 0)
      fprintf(stderr,"INFO: can\'t set session ID\n");
    slave_fd = pty_slave(master_fd);
    if (slave_fd < 0) {
      fprintf(stderr,"ERROR: can\'t open pty slave\n");
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
    exit(0x7f);
  }
  EventAddInput(master_fd,smp_echo,(EventData)smp,"smp_shell");
  smp_set_mode(smp,SMP_MODE_SHELL);
  smp->grp->shell = master_fd;
  return 0;
}

/* a packet's text arguments to smp through w (smp_write: this session,
 * smp_output: its group); source: first "<address> " (1) or
 * "<address>:\n" (2) */
void smp_process_packet(SMP *smp, IRPacket *p, int source, void (*w)())
{
  char *sptr;
  int arg;

  if (l2_debug)
    fprintf(stderr,"smp_process_packet(%lx) in\n",(unsigned long)(uintptr_t)p);
  for (arg = 0; arg < p->_argc; arg++) {
    if (IR_ARG_TYPE(p->_argv[arg]) != IR_ARG_STRING)
      continue;
    sptr = (char *)IRArg(p,arg);
    if (source) {
      w(smp,format_address(p->_src),-1);
      w(smp,source == 2 ? ":\n" : " ",-1);
      source = 0;
    }
    w(smp,sptr,(int)strlen(sptr));
  }
  if (l2_debug)
    fprintf(stderr,"smp_process_packet out\n");
}

/* an event: L1 console output (IR_L1_BDR) to the console sessions that
 * follow its partition (and, with a filter, its CPU); L1 command
 * processor events, L2 console events of kind 4 and the rest to every
 * session that follows that partition */
void smp_process_event(IRPacket *p)
{
  IRAddress src = p->_src;
  int type = IR_ADDR_TYPE(src);
  int task = IR_ADDR_TASK(src);
  L2CfgL1 *cfg;
  SMP *smp;

  for (smp = smp_list; smp != NULL; smp = smp->next) {
    if (type == IR_ADDR_L1 && task == IR_L1_IROUTER)
      smp_process_packet(smp,p,1,smp_write);
    else if ((type == IR_ADDR_IP || type == IR_ADDR_L2) && task == IR_L2_CONSOLE) {
      if (IR_ARG_TYPE(p->_argv[0]) == IR_ARG_VALUE && p->_argv[0]._val == SMP_EV_CONSOLE)
        smp_process_packet(smp,p,1,smp_write);
    }
    else if (type == IR_ADDR_L1 && task == IR_L1_BDR) {
      if (smp->grp->mode != SMP_MODE_CONSOLE)
        continue;
      if (smp->grp->conaddr == 0 && smp->grp->partition != 0) {
        cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(src),IR_ADDR_SLOT(src),0);
        if (cfg == NULL || cfg->partition != smp->grp->partition)
          continue;
      }
      /* the filter: only the console's own CPU (the pdata) */
      if (smp->grp->confilter != 0 &&
          IR_ADDR_WITH_TASK(src,p->_pdata_auth >> 3) != smp_get_conaddr(smp,NULL,NULL))
        continue;
      smp_process_packet(smp,p,0,smp_write);
    }
    else {
      if (smp->grp->conaddr == 0 && smp->grp->partition != 0) {
        cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(src),IR_ADDR_SLOT(src),0);
        if (cfg == NULL || (cfg->partition != 0 && cfg->partition != smp->grp->partition))
          continue;
      }
      smp_process_packet(smp,p,1,smp_write);
    }
  }
  smp_cleanup();
}

/* the command's next response (q() is SGI's name): its text, or why there
 * is none; then the next one 10 ms later, or, when all are in, the next
 * requests or the end of the command */
void q(SMP *smp)
{
  int mode;
  int print_source = 0;
  IRAddress dest;
  unsigned int seqn;
  IRPacket *pkt;
  char *text;

  /* (the original went on with a session that had gone in the meantime) */
  if (!smp_is_valid(smp))
    return;
  mode = smp->grp->mode;
  if (mode == SMP_MODE_L2 || mode == SMP_MODE_CONSOLE_ESC || mode == SMP_MODE_L1_ESC)
    print_source = smp->grp->l2cmd->q->rspq_max_length;
  if (rspq_get(smp->grp->l2cmd->q,&seqn,&dest,&pkt) == -1)
    goto done;
  if (pkt == NULL) {
    smp_output(smp,"\n",-1);
    if (print_source > 1)
      smp_output(smp,"L2 SMP ",-1);
    smp_output(smp,"ERROR: no response from ",-1);
    smp_output(smp,format_address(dest),-1);
    smp_output(smp,"\n",-1);
  }
  else if (pkt->_err == 0) {
    if (IR_ADDR_TASK(pkt->_src) == IR_L1_CMD &&
        (IR_ARG_TYPE(pkt->_argv[0]) == IR_ARG_VALUE ? pkt->_argv[0]._val : IRArg(pkt,0)) != 0) {
      /* a command that failed: its description */
      smp_output(smp,format_address(pkt->_src),-1);
      smp_output(smp," ",-1);
      if (pkt->_argc < 2)
        smp_output(smp,"ERROR: no error description given\n",-1);
      else {
        text = IR_ARG_TYPE(pkt->_argv[1]) == IR_ARG_VALUE ? (char *)IR_VAL_PTR(pkt->_argv[1]._val)
                                                           : (char *)IRArg(pkt,1);
        smp_output(smp,text,-1);
      }
    }
    else
      smp_process_packet(smp,pkt,print_source ? 2 : 0,smp_output);
    IRouterFreePacket(pkt);
  }
  else {
    if (print_source > 1) {
      smp_output(smp,format_address(pkt->_src),-1);
      smp_output(smp," ",-1);
    }
    smp_output(smp,"\nERROR: couldn\'t send packet to ",-1);
    smp_output(smp,format_address(dest),-1);
    smp_output(smp,", ",-1);
    smp_output(smp,IRFmtError(pkt->_err),-1);
    smp_output(smp,"\n",-1);
    IRouterFreePacket(pkt);
  }
  if (!rspq_empty(smp->grp->l2cmd->q)) {
    EventAddTimeOut(0,10000,q,(EventData)smp,"smp_process_queue");
    return;
  }
done:
  rspq_reset(smp->grp->l2cmd->q);
  EventEnableInput(smp->rfd,1);
  if (broadcast(smp->grp->l2cmd->q,smp->id) == 0) {
    reqq_reset(smp->grp->l2cmd->q);
    l2cmd_process_response(smp->grp->l2cmd,NULL,0);
  }
}

static void smp_process_queue(SMP *smp)
{
  rspq_timeout_clr(smp->grp->l2cmd->q);
  q(smp);
}

static void smp_timeout(L2CMD *c, int to, void *data)
{
  smp_process_queue(data);
}

static void smp_etimeout(L2CMD *c, char *msg, void *data)
{
  if (msg != NULL && *msg != '\0')
    smp_output(data,msg,-1);
}

/* a response to a session's request (addressed to the session) */
void smp_process_response(IRPacket *p)
{
  char x[80];
  SMP *smp;
  int rpend;

  for (smp = smp_list; smp != NULL && p->_dest != smp->id->addr; smp = smp->next)
    ;
  if (smp == NULL) {
    IRouterFreePacket(p);
    return;
  }
  rpend = rspq_update(smp->grp->l2cmd->q,p);
  if (rpend == -1) {
    IRFmtPkt("SMP late response",p,x);
    if (smp_debug)
      fprintf(stderr,"%s\n",x);
    nvramLogInsert(x);
    IRouterFreePacket(p);
  }
  else if (rpend == 0)
    smp_process_queue(smp);
  else if (smp_debug)
    fprintf(stderr,"responses pending %d\n",rpend);
}

/* l2cmd.c: a command's output (crsp), and when it is all done, back to the
 * session's mode, then the keys typed meanwhile */
static void smp_command_done(L2CMD *c, void *data, char *crsp, int rval)
{
  SMP *smp = data;
  IRAddress conaddr;
  L2CfgL1 *cfg;
  char buff[80];

  if (crsp != NULL)
    smp_output(smp,crsp,-1);
  if (!reqq_empty(c->q) || !rspq_empty(c->q))
    return;
  c->busy = 0;
  switch (smp->grp->mode) {
  case SMP_MODE_CONSOLE_ESC:
    conaddr = smp_chkcon_present(smp);
    if (conaddr == 0)
      return;
    smp_console(smp,conaddr,1);
    break;
  case SMP_MODE_L1_ESC:
    sprintf(buff,"\nre-entering L1 mode %s, <CTRL-T> to escape to L2\n",format_address(smp->grp->l1addr));
    smp_output(smp,buff,-1);
    smp_set_mode(smp,SMP_MODE_L1);
    break;
  case SMP_MODE_L1:
    cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(smp->grp->l1addr),IR_ADDR_SLOT(smp->grp->l1addr),0);
    if (cfg != NULL && cfg->console_enabled) {
      /* CTRL-T, "l1": the L1's own way out of console mode */
      smp_output(smp,"L1 appears to be in console mode, switching it to L1 mode\n",-1);
      smp_input_l1sysco(smp,KEY_CTRL('T'));
      smp_input_l1sysco(smp,'l');
      smp_input_l1sysco(smp,'1');
      smp_input_l1sysco(smp,'\n');
    }
    break;
  case SMP_MODE_L2:
    smp_prompt(smp);
    break;
  }
  while (smp->grp->ilen != 0) {
    smp->grp->ilen--;
    smp_input(smp,&smp->grp->ibuf[smp->grp->ilen],1);
  }
}

/* the session's input is readable: a key. While a command runs, one key
 * is kept (CTRL-C instead aborts the command); network sessions end at
 * EOF. */
void smp_read(SMP *smp)
{
  static char rbuf[2];
  SMPGroup *g = smp->grp;

  errno = 0;
  if (!rspq_empty(g->l2cmd->q)) {
    if (g->ilen < 1 && (g->mode == SMP_MODE_L2 || g->mode == SMP_MODE_CONSOLE_ESC ||
                        g->mode == SMP_MODE_L1_ESC) &&
        read(smp->rfd,g->ibuf + g->ilen,1) > 0) {
      if (g->ibuf[g->ilen] == KEY_CTRL('C')) {
        reqrspq_reset(g->l2cmd->q);
        EventEnableInput(smp->rfd,1);
        g->ilen = 0;
        smp_command_done(g->l2cmd,smp,NULL,0);
      }
      else
        g->ilen++;
    }
    return;
  }
  while (g->ilen != 0) {
    g->ilen--;
    smp_input(smp,g->ibuf + g->ilen,1);
  }
  if (read(smp->rfd,rbuf,1) < 1) {
    /* (the serial consoles stay) */
    if (IR_ADDR_TYPE(smp->id->addr) == IR_ADDR_IP_OTHER)
      smp_free(smp);
    return;
  }
  smp_input(smp,rbuf,1);
}

/* write to one session, newlines as CR LF; a session that can't take its
 * output within 5 seconds is marked hung (smp_cleanup() closes it) */
void smp_write(SMP *smp, char *ibptr, int iblen)
{
  static char obuff[OUT_MAX];
  static int oblen;
  static char *obptr;
  struct timeval wtime;
  struct timeval dtime;
  fd_set wrset;
  char x[256];
  int status;

  if (smp->hung)
    return;
  if (iblen == -1)
    iblen = strlen(ibptr);
  if (iblen == 0)
    return;
  oblen = 0;
  obptr = obuff;
  do {
    while (iblen != 0 && (unsigned int)oblen < OUT_MAX - 1) {
      if (*ibptr == '\n') {
        *obptr++ = '\r';
        oblen++;
      }
      *obptr++ = *ibptr++;
      oblen++;
      iblen--;
    }
    wtime.tv_sec = 5;
    wtime.tv_usec = 0;
    FD_ZERO(&wrset);
    FD_SET(smp->wfd,&wrset);
    errno = 0;
    if (select(smp->wfd + 1,NULL,&wrset,NULL,&wtime) < 0) {
      sprintf(x,"SMP %d (%d) select error %d",smp->grpid,smp_count,errno);
      nvramLogFinsert("%s",x);
      smp->hung = 1;
      return;
    }
    /* (Linux's select() leaves the time left in wtime; only a wait of a
     * 2.4 kernel's tick, 10 ms, or more is logged, as SGI's l2 saw them) */
    dtime.tv_sec = 5 - wtime.tv_sec;
    dtime.tv_usec = -wtime.tv_usec;
    if (dtime.tv_usec < 0) {
      dtime.tv_sec = 4 - wtime.tv_sec;
      dtime.tv_usec += 1000000;
    }
    if (dtime.tv_sec > 0 || dtime.tv_usec >= 10000) {
      sprintf(x,"SMP %d waited %d.%06d",smp->grpid,(int)dtime.tv_sec,(int)dtime.tv_usec);
      nvramLogFinsert("%s",x);
    }
    if (!FD_ISSET(smp->wfd,&wrset)) {
      sprintf(x,"SMP %d (%d) select timeout",smp->grpid,smp_count);
      nvramLogFinsert("%s",x);
      smp->hung = 1;
      return;
    }
    errno = 0;
    status = write(smp->wfd,obuff,oblen);
    if (status < 0 && errno == EAGAIN) {
      sprintf(x,"SMP %d (%d) write would block",smp->grpid,smp_count);
      nvramLogFinsert("%s",x);
      smp->hung = 1;
      return;
    }
    if (status < 0) {
      sprintf(x,"SMP %d (%d) write error %d",smp->grpid,smp_count,errno);
      nvramLogFinsert("%s",x);
      smp->hung = 1;
      return;
    }
    if (status == oblen) {
      oblen = 0;
      obptr = obuff;
    }
    else {
      sprintf(x,"SMP %d (%d) partial write %d/%d",smp->grpid,smp_count,status,oblen);
      nvramLogFinsert("%s",x);
      if (status != 0) {
        /* (the original kept the written length as what was left) */
        memmove(obuff,obuff + status,oblen - status);
        oblen -= status;
        obptr = obuff + oblen;
      }
    }
  } while (iblen != 0 || oblen != 0);
}

/* the shell's output; at its end, back to L2 mode */
void smp_echo(SMP *smp)
{
  char buff[512];
  int blen;

  /* (terminated: smp_event() copies the text whole; the original read
   * all 512 bytes and left it unterminated) */
  blen = read(smp->grp->shell,buff,sizeof(buff) - 1);
  if (blen < 1) {
    EventRemoveInput(smp->grp->shell);
    close(smp->grp->shell);
    smp_set_mode(smp,SMP_MODE_L2);
    smp_prompt(smp);
    return;
  }
  buff[blen] = '\0';
  smp_output(smp,buff,blen);
}

/* into console mode on conaddr (reenter: back from an escape) */
void smp_console(SMP *smp, IRAddress conaddr, int reenter)
{
  char buff[200];

  if (power_status(IR_ADDR_RACK(conaddr),IR_ADDR_SLOT(conaddr)) == 0) {
    sprintf(buff,"\nWARNING: power on %s appears off\n",format_caddress(conaddr,smp->grp->partition));
    smp_output(smp,buff,-1);
  }
  sprintf(buff,"\n%sentering system console mode (%s), <CTRL_T> to escape to L2\n",reenter ? "re-" : "",
          format_caddress(conaddr,smp->grp->partition));
  smp_output(smp,buff,-1);
  if (L2CfgMAdviseConsole(&L2CfgLocal,buff,smp->grp->partition,conaddr) != 0)
    smp_output(smp,buff,-1);
  smp_set_mode(smp,SMP_MODE_CONSOLE);
  smp->grp->cptr = smp->grp->cbuf;
  cfg_check_console_events();
}

/* a session on a terminal (or pty): raw input, no echo, at baud, the old
 * settings kept for smp_tty_reconfig() */
void smp_tty_config(int fd, int baud)
{
  struct termios termios;

  if (!isatty(fd) && ptsname(fd) == NULL)
    return;
  if (tcgetattr(fd,&termios) == -1) {
    fprintf(stderr,"ERROR: can\'t get termios, errno: %d\n",errno);
    return;
  }
  /* (the original wrote past smp_tty[] for descriptors from 256) */
  if (fd >= 0 && fd < MAX_FDS) {
    smp_tty[fd].t = termios;
    smp_tty[fd].configured = 1;
  }
  termios.c_iflag = (termios.c_iflag & ~(INLCR | IGNCR | ICRNL | IUCLC | IXON | IXOFF)) | ISTRIP;
  termios.c_oflag |= OPOST;
  termios.c_lflag &= ~(ICANON | ECHO);
  if (!l2_pc)
    termios.c_cflag |= CRTSCTS;
  termios.c_cc[VINTR] = 0;
  termios.c_cc[VSUSP] = 0;
  termios.c_cc[VMIN] = 1;
  termios.c_cc[VERASE] = '\b';
  termios.c_cc[VKILL] = '\v';
  cfsetospeed(&termios,baud);
  cfsetispeed(&termios,baud);
  if (tcsetattr(fd,TCSANOW,&termios) == -1)
    fprintf(stderr,"ERROR: can\'t set termios, errno: %d\n",errno);
}

/* put a terminal's settings back (all but the control flags, on top of
 * descriptor 0's: as the original) */
void smp_tty_reconfig(int fd)
{
  struct termios termios;

  if (fd < 0 || fd >= MAX_FDS || !smp_tty[fd].configured)
    return;
  if (tcgetattr(0,&termios) == -1)
    fprintf(stderr,"ERROR: can\'t get termios, errno: %d.\n",errno);
  else {
    termios.c_iflag = smp_tty[fd].t.c_iflag;
    termios.c_oflag = smp_tty[fd].t.c_oflag;
    termios.c_lflag = smp_tty[fd].t.c_lflag;
    memcpy(termios.c_cc,smp_tty[fd].t.c_cc,sizeof(termios.c_cc));
    cfsetospeed(&termios,cfgetospeed(&smp_tty[fd].t));
    cfsetispeed(&termios,cfgetispeed(&smp_tty[fd].t));
    if (tcsetattr(fd,TCSANOW,&termios) == -1)
      fprintf(stderr,"ERROR: can\'t set termios, errno; %d.\n",errno);
  }
  smp_tty[fd].configured = 0;
}

void smp_tty_debug(int fd)
{
  struct termios termios;
  char index[8];
  int i;

  if (tcgetattr(fd,&termios) == -1) {
    fprintf(stderr,"WARNING: can\'t get termios, errno: %d\n",errno);
    return;
  }
  fprintf(stderr,"---\niflag:  0x%04x\n",termios.c_iflag);
  fprintf(stderr,"oflag:  0x%04x\n",termios.c_oflag);
  fprintf(stderr,"cflag:  0x%04x\n",termios.c_cflag);
  fprintf(stderr,"lflag:  0x%04x\n",termios.c_lflag);
  fprintf(stderr,"ispeed: 0x%08x\n",termios.c_ispeed);
  fprintf(stderr,"ospeed: 0x%08x\n",termios.c_ospeed);
  for (i = 0; i < 0x20; i++) {
    sprintf(index,"0x%02x",i);
    fprintf(stderr,"%2d cc_c[%-8s]: 0x%04x\n",fd,smp_cc[i] != NULL ? smp_cc[i] : index,
            (unsigned int)termios.c_cc[i]);
  }
}

/* a console event for clients that follow the consoles (l2gui) */
static void smp_event(int opcode, int group, char *bptr)
{
  IRArgument argv[3];
  IRPacket *p;
  char *b;

  memset(argv,0,sizeof(argv));
  argv[0]._val = opcode;
  argv[1]._val = group;
  if (bptr != NULL) {
    b = strdup(bptr);
    argv[2]._clas = IR_ARG_STRING | IR_ARG_FREE;
    argv[2]._val = IR_PTR_VAL(b);
    argv[2]._size = strlen(b) + 1;
  }
  p = IRouterMakePacket(&l2_console_id,NULL,0,opcode != SMP_EV_CONSOLE,IR_EVT,2,3,argv);
  if (p != NULL)
    IRouterSendPacket(&l2_console_id,p);
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
  /* (the original vsprintf()ed into the 1024 bytes) */
  rval = vsnprintf(vbuf,sizeof(vbuf),format,ap);
  if (smp_list == NULL && !enet_only)
    write(2,vbuf,strlen(vbuf));
  else {
    smp_event(console_event ? SMP_EV_CONSOLE : SMP_EV_OUTPUT,-1,vbuf);
    for (smp = smp_list; smp != NULL; smp = smp->next)
      smp_write(smp,vbuf,strlen(vbuf));
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
