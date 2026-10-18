/*
 * sys_ctrl/common/sys/Cmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/Cmd.c
 *
 * The command-line parser of the L2 command processor. A command table
 * (Cmd[]) lists the accepted forms, each a list of tokens: a word ("a|b"
 * alternatives) or a token type (CMD_EXP, CMD_RANGE, ...; see Cmd.h).
 * CmdProcess() tries the forms in order, the given table's or else every
 * table CmdAddCmds() registered, and calls the first that matches the whole
 * line with what it parsed (CmdData).
 */

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Cmd.h"
#include "../../l3/sys/syslogLib.h"

#define CMD_LISTS 10            /* tables CmdAddCmds() can register */

int cmdlistcnt;
Cmd *cmdlist[CMD_LISTS];
int cmdlistnum[CMD_LISTS];

static int match_text(char *cmd_word, char *text);
static int match_range(char *X, int xmax, char *s);

int CmdAddCmds(Cmd *cmds, int num_cmds)
{
  if (cmdlistcnt == CMD_LISTS) {
    syslog(9,"../../common/sys/Cmd.c",47,0,"CmdAddCmds: command list full!");
    return -1;                  /* (the original stored past the end) */
  }
  cmdlist[cmdlistcnt] = cmds;
  cmdlistnum[cmdlistcnt] = num_cmds;
  cmdlistcnt++;
  return 0;
}

/* the clist'th table to search: the given one alone, or the registered ones */
static int command_list(Cmd *cmds_in, int num_cmds_in, int clist, Cmd **cmds, int *num_cmds)
{
  if (cmds_in != NULL) {
    *cmds = cmds_in;
    *num_cmds = num_cmds_in;
    return clist == 0;
  }
  if (clist >= cmdlistcnt)
    return 0;
  *cmds = cmdlist[clist];
  *num_cmds = cmdlistnum[clist];
  return 1;
}

/* the type of a token, or CMD_WORD for a word */
static uintptr_t token_type(char *tok)
{
  return (uintptr_t)tok < CMD_WORD_MIN ? (uintptr_t)tok : CMD_WORD;
}

/*
 * strtoul() as on i386, whose unsigned long is 32 bits: out of range values
 * saturate, and "-n" wraps modulo 2^32.
 */
static unsigned int strtou32(char *s, char **end, int base)
{
  unsigned long value = strtoul(s,end,base);

#if ULONG_MAX > UINT_MAX
  if (value > UINT_MAX) {
    while (isspace((unsigned char)*s))
      s++;
    if (*s == '-' && -value <= UINT_MAX)
      return (unsigned int)value;
    return UINT_MAX;
  }
#endif
  return value;
}

/*
 * CMD_RANGE: "*" or "all"; "rack|r <rng> [slot|s <rng>]"; or
 * "partition|p <rng>". *cptr is strtok()'s first argument; cmd and cmdcpy
 * as in match_command(). Returns 0 if it matches.
 */
static int match_dest(CmdData *cd, char **cptr, char *cmd, char *cmdcpy)
{
  char *tok;

  tok = strtok(*cptr," ");
  if (tok == NULL)
    return -1;
  if (strcmp(tok,"*") == 0 || strcmp(tok,"all") == 0) {
    match_range(cd->rlist,sizeof(cd->rlist),"**");
    match_range(cd->slist,sizeof(cd->slist),"**");
    memset(cd->plist,0,sizeof(cd->plist));
    return 0;
  }
  if (strcmp(tok,"r") == 0 || strcmp(tok,"rack") == 0) {
    tok = strtok(NULL," ");
    if (tok == NULL || match_range(cd->rlist,sizeof(cd->rlist),tok) != 0)
      return -1;
    /* (a rack range must be followed by something) */
    tok = strtok(NULL," ");
    if (tok == NULL)
      return -1;
    if (strcmp(tok,"s") != 0 && strcmp(tok,"slot") != 0) {
      /*
       * No slots: every slot, and give the word back to strtok() by
       * scanning the line again past "r <rng>". (This assumes the range
       * starts the line, as it does in every table.)
       */
      match_range(cd->slist,sizeof(cd->slist),"**");
      strcpy(cmdcpy,cmd);
      strtok(cmdcpy," ");
      strtok(NULL," ");
      memset(cd->plist,0,sizeof(cd->plist));
      return 0;
    }
    tok = strtok(NULL," ");
    if (tok == NULL || match_range(cd->slist,sizeof(cd->slist),tok) != 0)
      return -1;
    memset(cd->plist,0,sizeof(cd->plist));
    return 0;
  }
  if (strcmp(tok,"p") == 0 || strcmp(tok,"partition") == 0) {
    tok = strtok(NULL," ");
    if (tok == NULL || match_range(cd->plist,sizeof(cd->plist),tok) != 0)
      return -1;
    memset(cd->rlist,0,sizeof(cd->rlist));
    memset(cd->slist,0,sizeof(cd->slist));
    return 0;
  }
  return -1;
}

/*
 * CMD_RACKSLOT: "<rack><c><slot>", e.g. 001c05 (but not an IP address).
 * The original indexed the lists with rack % 256 and slot % 256 although
 * there are 64 slots; a slot of 128 or more wrote past CmdData onto the
 * stack. Numbers outside the lists now select nothing, as slots 64-127 did.
 */
static int match_rackslot(CmdData *cd, char *tok)
{
  unsigned int *exp = cd->exp_stack + cd->exp_max;
  int rack, slot;
  char type;

  if (sscanf(tok,"%d.%d.%d.%d",(int *)&exp[0],(int *)&exp[1],(int *)&exp[2],(int *)&exp[3]) == 4)
    return -1;
  if (sscanf(tok,"%d%c%d",&rack,&type,&slot) != 3)
    return -1;
  memset(cd->rlist,0,sizeof(cd->rlist));
  memset(cd->slist,0,sizeof(cd->slist));
  if (rack >= 0)
    cd->rlist[rack % 256] = CMD_RANGE_ONE;
  if (slot >= 0 && slot % 256 < (int)sizeof(cd->slist))
    cd->slist[slot % 256] = CMD_RANGE_ONE;
  memset(cd->plist,0,sizeof(cd->plist));
  return 0;
}

/*
 * Match one table token against the next word of the line. Returns what
 * goes into CmdData.toks: the word, or for the address and destination
 * types the type itself; NULL if it does not match.
 */
static char *match_token(char *want, CmdData *cd, char **cptr, char *cmd, char *cmdcpy)
{
  static const int bases[] = { 0, 0, 10, 16, 8 };   /* CMD_EXP .. CMD_OCT */
  unsigned int *exp;
  char *tok, *end;

  switch (token_type(want)) {
  case CMD_EXP:
  case CMD_DEC:
  case CMD_HEX:
  case CMD_OCT:
    tok = strtok(*cptr," ");
    if (tok == NULL)
      return NULL;
    cd->exp_stack[cd->exp_max++] = strtou32(tok,&end,bases[(uintptr_t)want]);
    return *end == '\0' ? tok : NULL;

  case CMD_STR:
    tok = strtok(*cptr," ");
    if (tok == NULL)
      return NULL;
    cd->str_stack[cd->str_max++] = tok;
    return tok;

  case CMD_REST:
    tok = strtok(*cptr,"");
    if (tok == NULL)
      return NULL;
    cd->str_stack[cd->str_max++] = tok;
    return tok;

  case CMD_IP:
    tok = strtok(*cptr," ");
    if (tok == NULL)
      return NULL;
    exp = cd->exp_stack + cd->exp_max;
    if (sscanf(tok,"%d.%d.%d.%d",(int *)&exp[0],(int *)&exp[1],(int *)&exp[2],(int *)&exp[3]) != 4)
      return NULL;
    cd->str_stack[cd->str_max++] = tok;
    cd->exp_max += 4;
    return want;

  case CMD_PORT_L1:
    tok = strtok(*cptr," ");
    if (tok == NULL)
      return NULL;
    exp = cd->exp_stack + cd->exp_max;
    if (sscanf(tok,":%d:%d",(int *)&exp[0],(int *)&exp[1]) != 2)
      return NULL;
    cd->str_stack[cd->str_max++] = tok;
    cd->exp_max += 2;
    return want;

  case CMD_IP_PORT_L1:
    tok = strtok(*cptr," ");
    if (tok == NULL)
      return NULL;
    exp = cd->exp_stack + cd->exp_max;
    if (sscanf(tok,"%d.%d.%d.%d:%d:%d",(int *)&exp[0],(int *)&exp[1],(int *)&exp[2],
               (int *)&exp[3],(int *)&exp[4],(int *)&exp[5]) != 6)
      return NULL;
    cd->str_stack[cd->str_max++] = tok;
    cd->exp_max += 6;
    return want;

  case CMD_RANGE:
    return match_dest(cd,cptr,cmd,cmdcpy) == 0 ? want : NULL;

  case CMD_RACKSLOT:
    tok = strtok(*cptr," ");
    if (tok == NULL || match_rackslot(cd,tok) != 0)
      return NULL;
    return want;

  case CMD_WORD:
    tok = strtok(*cptr," ");
    if (tok == NULL || match_text(want,tok) != 0)
      return NULL;
    return tok;

  default:                      /* CMD_BAY, which only usage text knows */
    return NULL;
  }
}

/*
 * Does the line match the command form? Fills in cd and *cmdname, the
 * first word matched. cmdcpy is the copy of the line strtok() splits.
 * (The lists in cd keep what earlier forms left in them.)
 */
static int match_command(Cmd *form, char *cmd, char *cmdcpy, CmdData *cd, char **cmdname)
{
  char *cptr = cmdcpy;
  char *tok;
  int in_tok, out_tok = 0;

  strcpy(cmdcpy,cmd);
  cd->exp_max = 0;
  cd->str_max = 0;
  *cmdname = NULL;
  for (in_tok = 0; in_tok < CMD_TOKS && form->toks[in_tok] != CMD_END; in_tok++) {
    tok = match_token(form->toks[in_tok],cd,&cptr,cmd,cmdcpy);
    if (tok == NULL)
      return 0;
    cd->toks[out_tok++] = tok;
    if (*cmdname == NULL && token_type(tok) == CMD_WORD)
      *cmdname = tok;
    cptr = NULL;
  }
  if (strtok(cptr,"") != NULL)  /* words left over */
    return 0;
  if (out_tok < CMD_TOKS)
    cd->toks[out_tok] = NULL;
  return 1;
}

/* call the matched command; a -2 from it means bad arguments */
static int run_command(Cmd *form, CmdData *cd, char **results, void *data, char *cmdname)
{
  int rval;

  rval = form->func(cd,results,data);
  if (rval == -2) {
    if (results == NULL)
      return -1;
    free(*results);
    /*
     * The original printed toks[0] into 80 bytes: a long word overflowed
     * it, and a form starting with a type (a destination) crashed. It is
     * the first word now, which toks[0] is otherwise.
     */
    if (cmdname == NULL)
      cmdname = "";
    *results = malloc(strlen(cmdname) + 50);
    sprintf(*results,"ERROR: invalid arguments for \'%s\' command\n",cmdname);
    return -1;
  }
  if (results != NULL && *results != NULL && **results == '\0') {
    free(*results);
    *results = NULL;
  }
  return rval;
}

/*
 * Parse cmd, and in mode CMD_EXECUTE run it; otherwise return the matching
 * form's index in its table. Returns CMD_ERR_EMPTY for a blank line and
 * CMD_ERR_ERROR, with a message in *results, when nothing matches.
 */
int CmdProcess(int mode, char *cmd, char **results, Cmd *cmds_in, int num_cmds_in, void *data)
{
  char cmdcpy[256];
  char *cmdname = NULL;
  CmdData cd;
  Cmd *cmds;
  int num_cmds, clist, current;

  if (results != NULL)
    *results = NULL;
  memset(&cd,0,sizeof(cd));
  if (cmd == NULL)
    return CMD_ERR_EMPTY;
  while (isspace((unsigned char)*cmd))
    cmd++;
  if (*cmd == '\0')
    return CMD_ERR_EMPTY;
  if (strlen(cmd) >= sizeof(cmdcpy))
    goto nomatch;               /* (the original copied it anyway) */

  for (clist = 0; command_list(cmds_in,num_cmds_in,clist,&cmds,&num_cmds); clist++) {
    for (current = 0; current < num_cmds; current++) {
      if (!match_command(&cmds[current],cmd,cmdcpy,&cd,&cmdname))
        continue;
      cd.params = cmds[current].params;
      if (mode != CMD_EXECUTE)
        return current;
      return run_command(&cmds[current],&cd,results,data,cmdname);
    }
  }

 nomatch:
  /*
   * cmdname is from the last form tried, so "invalid arguments" only shows
   * when the last form of the last table starts with the same word. (In
   * l2's table the last form, <command>, matches every line.)
   */
  if (results != NULL) {
    if (cmdname == NULL) {
      *results = strdup("ERROR: command not found.\n");
    }
    else {
      *results = malloc(2 * strlen(cmdname) + 60);
      sprintf(*results,"ERROR: invalid arguments for \'%s\' command, try \"help %s\"\n",
              cmdname,cmdname);
    }
  }
  return CMD_ERR_ERROR;
}

/*
 * The word a form is listed under in help: its first word, or the second
 * after a leading type. "<command>" for a form that takes any command;
 * a destination type (CMD_IP up to dest_max) followed by <command> sets
 * *dest_cmd. (CmdHelpAll() and CmdHelpCmd() differ in dest_max and in what
 * they do with such forms.)
 */
static char *command_word(Cmd *form, uintptr_t dest_max, int *dest_cmd)
{
  uintptr_t first = token_type(form->toks[0]);

  *dest_cmd = 0;
  if (first == CMD_REST)
    return "<command>";
  if (first == CMD_WORD)
    return form->toks[0];
  if (first >= CMD_IP && first <= dest_max && token_type(form->toks[1]) == CMD_REST) {
    *dest_cmd = 1;
    return "<command>";
  }
  return form->toks[1];
}

/*
 * The list of command words into rptr, four to a line; a word is left out
 * when the one before it starts with it. Hidden commands only if showall.
 */
void CmdHelpAll(Cmd *cmds_in, int num_cmds_in, int showall, char *rptr)
{
  char *lptr = rptr;            /* the last word listed */
  char *name;
  Cmd *cmds;
  int num_cmds, clist, current, count, dest_cmd;

  strcpy(rptr,"Commands are:\n");
  rptr += strlen(rptr);
  for (clist = 0; command_list(cmds_in,num_cmds_in,clist,&cmds,&num_cmds); clist++) {
    count = 0;
    for (current = 0; current < num_cmds; current++) {
      if (cmds[current].visibility != 0 && !showall)
        continue;
      name = command_word(&cmds[current],CMD_RACKSLOT,&dest_cmd);
      if (dest_cmd)             /* (not listed) */
        continue;
      if (strncmp(lptr,name,strlen(name)) == 0)
        continue;
      lptr = rptr;
      sprintf(rptr,"%-19s",name);
      count++;
      if ((count & 3) == 0)
        strcat(rptr,"\n");
      rptr += strlen(rptr);
    }
  }
  strcpy(rptr,"\nenter \'hlp <cmd>\' for more help on a single command.\n");
}

/*
 * Usage text for a command, in a static buffer. (Ghidra could not recover
 * the original's jump table; this follows the machine code and the table
 * at 0x0808ff18.)
 */
char *CmdFormat(Cmd *cmds, int cmd)
{
  static char fmt[256];   /* ORIGINAL BUG: 40 bytes in the original, overflowed by long usages */
  static const char *const type_fmt[CMD_WORD] = {
    NULL,                       /* CMD_END */
    "<exp> ",
    "<decimal exp> ",
    "<hex exp> ",
    "<octal exp> ",
    "<str> ",
    "<command> ",
    "<ip> ",
    ":<port>:<l1> ",
    "<ip>:<port>:<l1> ",
    "rack|r <rng> [ slot|s <rng> ] ",
    "<rack>.<slot> ",
    "s|b<rng> ",
  };
  uintptr_t t;
  int tok;

  fmt[0] = '\0';
  for (tok = 0; tok < CMD_TOKS && cmds[cmd].toks[tok] != CMD_END; tok++) {
    t = token_type(cmds[cmd].toks[tok]);
    if (t < CMD_WORD) {
      strcat(fmt,type_fmt[t]);
    }
    else {
      strcat(fmt,cmds[cmd].toks[tok]);
      strcat(fmt," ");
    }
  }
  return fmt;
}

/*
 * Usage and description of the commands listed under the word which (all
 * of them if NULL), in a malloc()ed *rrptr: "usage\n\tdescription\n" each.
 */
void CmdHelpCmd(Cmd *cmds_in, int num_cmds_in, char *which, int showall, char **rrptr)
{
  char *rptr, *name, *desc;
  Cmd *cmds;
  int num_cmds, clist, current, pass, dest_cmd;
  size_t count = 0;

  *rrptr = NULL;
  /* pass 0 measures, pass 1 writes */
  for (pass = 0; pass < 2; pass++) {
    if (pass == 1) {
      rptr = malloc(count + 100);
      *rrptr = rptr;
      if (rptr == NULL)
        return;
      *rptr = '\0';
      if (count == 0) {
        sprintf(rptr,"ERROR: command %s not found.\n",which);
        return;
      }
    }
    for (clist = 0; command_list(cmds_in,num_cmds_in,clist,&cmds,&num_cmds); clist++) {
      for (current = 0; current < num_cmds; current++) {
        if (cmds[current].visibility != 0 && !showall)
          continue;
        name = command_word(&cmds[current],CMD_BAY,&dest_cmd);
        if (which != NULL && match_text(name,which) != 0)
          continue;
        desc = cmds[current].desc != NULL ? cmds[current].desc : "-";
        if (pass == 0) {
          count += strlen(CmdFormat(cmds,current)) + strlen(desc) + 4;
        }
        else {
          sprintf(rptr,"%s\n\t%s\n",CmdFormat(cmds,current),desc);
          rptr += strlen(rptr);
        }
      }
    }
  }
}

/* is text one of the '|'-separated alternatives of cmd_word? 0 if so */
static int match_text(char *cmd_word, char *text)
{
  size_t len = strlen(text);
  char *bar;

  for (;;) {
    bar = strchr(cmd_word,'|');
    if (bar == NULL)
      return strcmp(cmd_word,text) == 0 ? 0 : 1;
    if ((size_t)(bar - cmd_word) == len && strncmp(cmd_word,text,len) == 0)
      return 0;
    cmd_word = bar + 1;
  }
}

int CmdMatchRange(char *X, int xmax, char *s)
{
  return match_range(X,xmax,s);
}

/* mark n2..n1 in X: one entry, or first, middle and last */
static void mark_range(char *X, int n2, int n1)
{
  int n;

  if (n2 == n1) {
    X[n2] = CMD_RANGE_ONE;
    return;
  }
  X[n2] = CMD_RANGE_FIRST;
  for (n = n2 + 1; n < n1; n++)
    X[n] = CMD_RANGE_MID;
  X[n1] = CMD_RANGE_LAST;
}

/*
 * Parse a range list into X[xmax]: "*" or "all" (every entry
 * CMD_RANGE_ALL), "**" (every entry CMD_RANGE_ANY: no range given), or
 * numbers and n-m ranges separated by commas. Returns nonzero on a syntax
 * error, a number xmax or larger, or a range that runs backwards (X keeps
 * what was marked before it). In "1-2-3" the second '-' starts a new range,
 * dropping 1-2.
 */
static int match_range(char *X, int xmax, char *s)
{
  int range = 0;
  int n1, n2 = 0;
  size_t len;

  memset(X,CMD_RANGE_NONE,xmax);
  if (strcmp(s,"*") == 0 || strcmp(s,"all") == 0) {
    memset(X,CMD_RANGE_ALL,xmax);
    return 0;
  }
  if (strcmp(s,"**") == 0) {
    memset(X,CMD_RANGE_ANY,xmax);
    return 0;
  }
  while (*s != '\0') {
    len = strspn(s,"0123456789");
    if (len == 0 || sscanf(s,"%d",&n1) != 1 || n1 >= xmax)
      return 1;
    if (s[len] == '-') {
      n2 = n1;
      range = 1;
      s += len + 1;
      if (*s == '\0')
        return 1;
      continue;
    }
    if (range) {
      if (n1 < n2)
        return 1;
      mark_range(X,n2,n1);
      range = 0;
    }
    else {
      X[n1] = CMD_RANGE_ONE;
    }
    if (s[len] == ',') {
      s += len + 1;
      if (*s == '\0')
        return 1;
    }
    else {
      s += len;
      if (*s != '\0')           /* (something else after the number) */
        return 1;
    }
  }
  return 0;
}
