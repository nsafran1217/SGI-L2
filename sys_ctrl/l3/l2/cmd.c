/*
 * sys_ctrl/l3/l2/cmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/cmd.c
 *
 * The L2's command task: requests from L3 tools and other L2s (a command
 * line) run through l2cmd.c, and the text that comes back, from this L2 and
 * from the bricks and L2s it asked, is collected into a cmd_response and
 * sent as the response, in arguments of at most ARG_MAX bytes. A second L2CMD
 * runs commands for l2cmd.c's own use (cmd_setup_usr_response()), its
 * responses going to a callback.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "l2.h"
#include "cmd.h"
#include "broadcast.h"
#include "discover.h"
#include "format.h"
#include "irtr.h"

#define ARG_MAX     0xfffe      /* text in one response argument */
#define MAX_ARGS    256         /* cmd_argv[] */

static void cmd_timeout(L2CMD *c, int to, void *data);
static void cmd_etimeout(L2CMD *c, char *msg, void *data);
static void cmd_send_response(L2CMD *c, void *data, char *sptr, int rval);
static void cmd_process_queue(L2CMD *c);
static void cmd_process_queue_usr(L2CMD *c);

static int cmd_argc;
static L2CMD *cmd_l2cmd;
static L2CMD *cmd_l2cmd_usr;
static int cmd_usr_avail = 1;
static cmd_packet_cb *cmd_usr_cb;
static void *cmd_usr_data;
static IRArgument cmd_argv[MAX_ARGS];   /* the response being built */
static cmd_response cmd_rsp;
static cmd_response cmd_rsp_usr;
/* the request being answered */
static IRAddress cmd_src_addr;
static int cmd_src_seqn;
static int cmd_src_prev;
static int cmd_src_pdata;

/* --- the response text --- */

static void rsp_init(cmd_response *r)
{
  memset(r,0,sizeof(*r));
  r->size = 0x400;
  r->sptr = malloc(r->size);
  r->eptr = r->sptr;
  *r->sptr = '\0';
}

static void rsp_clear(cmd_response *r)
{
  r->slen = 0;
  *r->sptr = '\0';
  r->eptr = r->sptr;
}

/* make room to append n bytes; eptr is then the end of the text. (eptr
 * stays at the start of the text appended last, slen at where it starts.) */
static void rsp_room(cmd_response *r, size_t n)
{
  r->slen += strlen(r->eptr != NULL ? r->eptr : "");
  if ((size_t)r->size <= r->slen + n + 0x10) {
    r->size += n + 0x200;
    r->sptr = realloc(r->sptr,r->size);
  }
  r->eptr = r->sptr + r->slen;
}

static void rsp_append(cmd_response *r, const char *text)
{
  rsp_room(r,strlen(text));
  strcat(r->eptr,text);
}

void cmd_init(void)
{
  cmd_l2cmd = l2cmd_init(&l2_cmd_id,cmd_timeout,cmd_etimeout,cmd_send_response,NULL);
  cmd_l2cmd_usr = l2cmd_init(&l2_cmdusr_id,cmd_timeout,NULL,NULL,NULL);
  rsp_init(&cmd_rsp);
  rsp_init(&cmd_rsp_usr);
}

/* the L2CMD for an internal command whose responses go to rsp_cb; NULL
 * while one is running */
L2CMD *cmd_setup_usr_response(cmd_packet_cb *rsp_cb, void *data)
{
  if (!cmd_usr_avail)
    return NULL;
  cmd_usr_cb = rsp_cb;
  cmd_usr_data = data;
  cmd_usr_avail = 0;
  dest_reset(cmd_l2cmd_usr->dest);
  cmd_rsp_usr.status = 0;
  rsp_clear(&cmd_rsp_usr);
  return cmd_l2cmd_usr;
}

/* a command request (argument 1 the command line) */
void cmd_process_request(IRPacket *req)
{
  IRArgument argv[2];
  IRAddress addr;
  IRPacket *rsp;
  char *rptr = NULL;
  char *cmd;
  int status;

  cmd = IR_ARG_TYPE(req->_argv[1]) == IR_ARG_VALUE ? (char *)IR_VAL_PTR(req->_argv[1]._val)
                                                   : (char *)IRArg(req,1);
  if (!cmd_l2cmd->busy) {
    dest_reset(cmd_l2cmd->dest);
    cmd_src_seqn = IR_SEQNUM(req);
    cmd_src_addr = req->_src;
    cmd_src_prev = req->_rev;
    cmd_src_pdata = req->_pdata_auth >> 3;
    memset(&cmd_argv[0],0,sizeof(cmd_argv[0]));
    cmd_argc = 1;
    cmd_rsp.status = 0;
    rsp_clear(&cmd_rsp);
    status = l2cmd_process(cmd_l2cmd,cmd,&rptr,NULL);
    if (status != 0)
      cmd_argv[0]._val = 0xffffffff;
    if (rptr != NULL) {
      rsp_append(&cmd_rsp,rptr);
      free(rptr);
    }
    IRouterFreePacket(req);
    if (!cmd_l2cmd->busy)       /* done here; else when the responses are in */
      l2cmd_process_response(cmd_l2cmd,cmd_rsp.sptr,cmd_rsp.status);
    return;
  }
  /* busy with another: only what this L2 can answer itself */
  status = l2cmd_process(NULL,cmd,&rptr,NULL);
  memset(argv,0,sizeof(argv));
  if (status != 0) {
    free(rptr);                 /* (the original leaked it) */
    argv[0]._val = 0xffffffff;
    rptr = strdup("ERROR: command library is busy\n");
  }
  else if (rptr != NULL && *rptr == '\0') {
    free(rptr);
    rptr = NULL;
  }
  if (rptr != NULL) {
    argv[1]._clas = IR_ARG_STRING | IR_ARG_FREE;
    argv[1]._val = IR_PTR_VAL(rptr);
    argv[1]._size = strlen(rptr) + 1;
  }
  addr = req->_src;
  rsp = IRouterMakePacket(&l2_cmd_id,&addr,req->_pdata_auth >> 3,0,IR_RSP,req->_rev,2,argv);
  if (rsp == NULL)
    fprintf(stderr,"ERROR: can\'t create packet for command response.\n");
  else {
    rsp->_seqnum0 = req->_seqnum0;
    rsp->_seqnum1 = req->_seqnum1;
    IRouterSendPacket(NULL,rsp);
  }
  IRouterFreePacket(req);
}

static void cmd_timeout(L2CMD *c, int to, void *data)
{
  if (c == cmd_l2cmd)
    cmd_process_queue(c);
  else
    cmd_process_queue_usr(c);
}

static void cmd_etimeout(L2CMD *c, char *msg, void *data)
{
}

/* add len bytes of text as the response's next argument */
static void add_text_arg(const char *text, size_t len)
{
  char *arg;

  if (cmd_argc >= MAX_ARGS)
    return;                     /* (the original wrote past cmd_argv) */
  arg = malloc(len + 1);
  memcpy(arg,text,len);
  arg[len] = '\0';
  cmd_argv[cmd_argc]._clas = IR_ARG_STRING | IR_ARG_FREE;
  cmd_argv[cmd_argc]._frame = 0;
  cmd_argv[cmd_argc]._val = IR_PTR_VAL(arg);
  cmd_argv[cmd_argc]._size = len + 1;
  cmd_argc++;
}

/*
 * l2cmd.c's output for the command: collected while requests or responses
 * are outstanding, else (the last) sent as the response with status rval,
 * the text split at line ends into arguments of at most ARG_MAX bytes.
 */
static void cmd_send_response(L2CMD *c, void *data, char *sptr, int rval)
{
  const char *aptr;             /* the argument's start */
  const char *eptr;             /* the end of its last whole line */
  const char *nptr;             /* the end of the next line */
  IRPacket *rsp;

  if (!reqq_empty(c->q) || !rspq_empty(c->q)) {
    rsp_room(&cmd_rsp,strlen(sptr));
    strcat(cmd_rsp.sptr,sptr);
    return;
  }
  c->busy = 0;
  cmd_argv[0]._clas = IR_ARG_VALUE;
  cmd_argv[0]._frame = 0;
  cmd_argv[0]._val = rval;
  cmd_argv[0]._size = 0;
  for (aptr = eptr = sptr; *aptr != '\0'; ) {
    nptr = strchr(eptr,'\n');
    nptr = nptr != NULL ? nptr + 1 : eptr + strlen(eptr);
    if (nptr - aptr > ARG_MAX) {
      /* (a single line that long: cut it. The original looped forever.) */
      if (eptr == aptr)
        eptr = aptr + ARG_MAX;
    }
    else {
      eptr = nptr;
      if (*nptr != '\0')
        continue;
    }
    add_text_arg(aptr,eptr - aptr);
    aptr = eptr;
  }
  rsp = IRouterMakePacket(c->id,&cmd_src_addr,cmd_src_pdata,0,IR_RSP,cmd_src_prev,cmd_argc,cmd_argv);
  if (rsp == NULL)
    fprintf(stderr,"ERROR: can\'t create packet for command response.\n");
  else {
    rsp->_seqnum0 = cmd_src_seqn;
    rsp->_seqnum1 = cmd_src_seqn >> 8;
    IRouterSendPacket(NULL,rsp);
  }
  cmd_argc = 0;
}

/*
 * The responses are in (or the time is up): pass each, in order, to pktcb,
 * NULL for the missing ones, then send the next requests. process_rsp: when
 * all are done, the collected text is the command's output.
 */
static void cmd_process_queue_int(L2CMD *c, cmd_packet_cb *pktcb, void *data, cmd_response *cmd_rsp, int process_rsp)
{
  RSPQ *qe = NULL;
  IRAddress dest;
  IRPacket *rsp;
  unsigned int seqn;
  int rsplen = 0;
  int left;

  rspq_timeout_clr(c->q);
  while ((qe = rspq_peek(c->q,qe,&seqn,&dest,&rsp)) != NULL)
    rsplen += cmd_estimate_packet_rsplen(rsp,c,&dest,c->q->rspq_length,cmd_rsp,data);
  rsp_room(cmd_rsp,rsplen);
  do {
    if (rspq_get(c->q,&seqn,&dest,&rsp) == -1)
      break;
    left = c->q->rspq_length;
    pktcb(rsp,c,&dest,c->q->rspq_length,cmd_rsp,data);
    if (rsp != NULL)
      IRouterFreePacket(rsp);
    discover_service();
  } while (left != 0);
  cmd_rsp->slen = strlen(cmd_rsp->sptr);
  cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
  if (c->q->rspq_length == 0)
    rspq_reset(c->q);
  if (broadcast(c->q,c->id) == 0) {
    reqq_reset(c->q);
    if (process_rsp)
      l2cmd_process_response(c,cmd_rsp->sptr,cmd_rsp->status);
  }
}

static void cmd_process_queue(L2CMD *c)
{
  cmd_process_queue_int(c,cmd_process_packet_default,NULL,&cmd_rsp,1);
}

static void cmd_process_queue_usr(L2CMD *c)
{
  cmd_process_queue_int(c,cmd_usr_cb,cmd_usr_data,&cmd_rsp_usr,0);
  if (reqq_empty(c->q) && rspq_empty(c->q)) {
    cmd_usr_avail = 1;
    rsp_clear(&cmd_rsp_usr);
  }
}

/* a response to one of the command task's requests */
void cmd_process_response(IRPacket *rsp)
{
  int rpend;

  rpend = rspq_update(cmd_l2cmd->q,rsp);
  if (rpend == -1)
    IRouterFreePacket(rsp);
  else if (rpend == 0)
    cmd_process_queue(cmd_l2cmd);
}

void cmd_process_response_usr(IRPacket *rsp)
{
  int rpend;

  if (cmd_usr_avail)
    return;
  rpend = rspq_update(cmd_l2cmd_usr->q,rsp);
  if (rpend == -1)
    IRouterFreePacket(rsp);
  else if (rpend == 0)
    cmd_process_queue_usr(cmd_l2cmd_usr);
}

/* the default handling of a response: its text, or an error line; each
 * under its source's address if the command went to several */
int cmd_process_packet_default(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data)
{
  int print_source = c->q->rspq_max_length;

  if (rsp == NULL) {
    cmd_rsp->status = -1;
    rsp_room(cmd_rsp,100);
    strcat(cmd_rsp->eptr,"\n");
    if (print_source) {
      strcat(cmd_rsp->eptr,format_address(c->id->addr));
      strcat(cmd_rsp->eptr,":\n");
    }
    strcat(cmd_rsp->eptr,"ERROR: no response from ");
    strcat(cmd_rsp->eptr,format_address(*dest));
    strcat(cmd_rsp->eptr,"\n");
  }
  else if (rsp->_err == 0)
    cmd_process_packet_args(rsp,c,dest,cmd_rsp,print_source);
  else {
    cmd_rsp->status = -1;
    rsp_room(cmd_rsp,200);
    if (print_source) {
      strcat(cmd_rsp->eptr,format_address(rsp->_src));
      strcat(cmd_rsp->eptr," ");
    }
    strcat(cmd_rsp->eptr,"ERROR: couldn\'t send packet to ");
    strcat(cmd_rsp->eptr,format_address(*dest));
    strcat(cmd_rsp->eptr,", ");
    strcat(cmd_rsp->eptr,IRFmtError(rsp->_err));
    strcat(cmd_rsp->eptr,"\n");
    /* (the original freed rsp here too: its caller frees it) */
  }
  return 0;
}

/* a response's text arguments; a non-zero status (argument 0) makes the
 * command's status -1. With print_source, under "<dest>:" (just "<dest>"
 * when the status is an error). */
int cmd_process_packet_args(IRPacket *rsp, L2CMD *c, IRAddress *dest, cmd_response *cmd_rsp, int print_source)
{
  const char *text;
  int arg;

  if (IRArg(rsp,0) != 0)
    cmd_rsp->status = -1;
  for (arg = 0; arg < rsp->_argc; arg++) {
    if (IR_ARG_TYPE(rsp->_argv[arg]) != IR_ARG_STRING)
      continue;
    if (print_source && dest != NULL) {
      rsp_room(cmd_rsp,20);
      strcat(cmd_rsp->eptr,format_address(*dest));
      if (IRArg(rsp,0) == 0)
        strcat(cmd_rsp->eptr,":\n");
      dest = NULL;
    }
    text = (const char *)IRArg(rsp,arg);
    rsp_append(cmd_rsp,text);
  }
  return 0;
}

/* about how much text cmd_process_packet_default() adds for rsp */
int cmd_estimate_packet_rsplen(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data)
{
  int arglen = 0;
  int arg;

  if (rsp == NULL)
    return 100;
  if (rsp->_err != 0)
    return 200;
  for (arg = 0; arg < rsp->_argc; arg++) {
    if (IR_ARG_TYPE(rsp->_argv[arg]) != IR_ARG_STRING)
      continue;
    if (c->q->rspq_max_length != 0 && dest != NULL)
      arglen += 20;
    arglen += rsp->_argv[arg]._size;
  }
  return arglen;
}
