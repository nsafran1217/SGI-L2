/*
 * sys_ctrl/common/sys/Cmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/Cmd.c
 */

#include "../../l3/sys/syslogLib.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <ctype.h>
#include "Cmd.h"
#include "syslog.h"
#include "sysctl_types.h"
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static int match_text(char *cmd_word, char *text);
static int match_range(char *X, int xmax, char *s);

int cmdlistcnt;
Cmd *cmdlist[10];
int cmdlistnum[10];

int CmdAddCmds(Cmd *cmds, int num_cmds)
{
  if (cmdlistcnt == 10) {
    syslog(9,"../../common/sys/Cmd.c",0x2f,0,"CmdAddCmds: command list full!");
  }
  cmdlist[cmdlistcnt] = cmds;
  cmdlistnum[cmdlistcnt] = num_cmds;
  cmdlistcnt = cmdlistcnt + 1;
  return 0;
}

int CmdProcess(int mode, char *cmd, char **results, Cmd *cmds_in, int num_cmds_in, void *data)
{
  size_t sVar1;
  int iVar2;
  int rval;
  ulong uVar3;
  int iVar4;
  char *pcVar5;
  char *current_tok_str;
  int base;
  Cmd *cmds;
  char *cmdname;
  char type;
  int slot;
  int rack;
  char *tmp;
  char *tok;
  char *cptr;
  char cmdcpy [256];
  int skip_out_tok;
  int out_tok;
  int in_tok;
  int current_cmd;
  int clist;
  CmdData cd;
  int num_cmds;
  bool match_state;
  
  cmdname = NULL;
  if (results != NULL) {
    *results = NULL;
  }
  memset(&cd,0,500);
  if (cmd != NULL) {
    while ((*(ushort *)(__ctype_b + *cmd * 2) & 0x2000) != 0) {
      cmd = cmd + 1;
    }
    sVar1 = strlen(cmd);
    if (sVar1 != 0) {
      clist = 0;
      do {
        if (cmds_in == NULL) {
          if (cmdlistcnt <= clist) goto LAB_080812f0;
        }
        else if (0 < clist) {
LAB_080812f0:
          if (results != NULL) {
            pcVar5 = malloc(100);
            *results = pcVar5;
            if (cmdname == NULL) {
              strcpy(*results,"ERROR: command not found.\n");
            }
            else {
              sprintf(*results,"ERROR: invalid arguments for \'%s\' command, try \"help %s\"\n",
                      cmdname,cmdname);
            }
          }
          return -800;
        }
        iVar2 = num_cmds_in;
        num_cmds = (int)cmds_in;
        if (cmds_in == NULL) {
          num_cmds = (int)cmdlist[clist];
          iVar2 = cmdlistnum[clist];
        }
        for (current_cmd = 0; current_cmd < iVar2; current_cmd = current_cmd + 1) {
          cptr = cmdcpy;
          strcpy(cptr,cmd);
          cd.exp_max = 0;
          cd.str_max = 0;
          match_state = true;
          cmdname = NULL;
          in_tok = 0;
          out_tok = 0;
          while (match_state) {
            pcVar5 = *(char **)(num_cmds + current_cmd * 0x44 + in_tok * 4);
            switch(pcVar5) {
            case NULL:
              tok = strtok(cptr,"");
              if (tok == NULL) {
                cd.toks[out_tok] = NULL;
                cd.params = (uint *)(num_cmds + current_cmd * 0x44 + 0x2c);
                if (mode != 1) {
                  return current_cmd;
                }
                rval = (**(code **)(num_cmds + current_cmd * 0x44 + 0x28))(&cd,results,data);
                if (rval == -2) {
                  if ((results != NULL) && (*results != NULL)) {
                    free(*results);
                  }
                  pcVar5 = malloc(0x50);
                  *results = pcVar5;
                  sprintf(*results,"ERROR: invalid arguments for \'%s\' command\n",cd.toks[0]);
                  return -1;
                }
                if (results == NULL) {
                  return rval;
                }
                if (*results != NULL) {
                  if (**results == '\0') {
                    free(*results);
                    *results = NULL;
                    return rval;
                  }
                  return rval;
                }
                return rval;
              }
              match_state = false;
              break;
            case (char *)0x1:
            case (char *)0x2:
            case (char *)0x3:
            case (char *)0x4:
              if (pcVar5 == (char *)0x2) {
                base = 10;
              }
              else if ((int)pcVar5 < 3) {
                if (pcVar5 == (char *)0x1) {
                  base = 0;
                }
              }
              else if (pcVar5 == (char *)0x3) {
                base = 0x10;
              }
              else if (pcVar5 == (char *)0x4) {
                base = 8;
              }
              tok = strtok(cptr," ");
              if (tok == NULL) {
                match_state = false;
              }
              else {
                uVar3 = strtoul(tok,&tmp,base);
                cd.exp_stack[cd.exp_max] = uVar3;
                cd.exp_max = cd.exp_max + 1;
                sVar1 = strlen(tok);
                if (tok + sVar1 == tmp) goto LAB_08081272;
                match_state = false;
              }
              break;
            case (char *)0x5:
              tok = strtok(cptr," ");
              if (tok == NULL) {
                match_state = false;
              }
              else {
                cd.str_stack[cd.str_max] = tok;
                cd.str_max = cd.str_max + 1;
LAB_08081272:
                if (true) {
                  cd.toks[out_tok] = tok;
                  out_tok = out_tok + 1;
                }
                if ((cmdname == NULL) && ((char *)0x3e8 < tok)) {
                  cmdname = tok;
                }
                cptr = NULL;
              }
              break;
            case (char *)0x6:
              tok = strtok(cptr,"");
              if (tok != NULL) {
                cd.str_stack[cd.str_max] = tok;
                cd.str_max = cd.str_max + 1;
                goto LAB_08081272;
              }
              match_state = false;
              break;
            case (char *)0x7:
              tok = strtok(cptr," ");
              if (tok == NULL) {
                match_state = false;
              }
              else {
                iVar4 = sscanf(tok,"%d.%d.%d.%d",cd.exp_stack + cd.exp_max,
                               cd.exp_stack + cd.exp_max + 1,cd.exp_stack + cd.exp_max + 2,
                               cd.exp_stack + cd.exp_max + 3);
                if (iVar4 == 4) {
                  cd.str_stack[cd.str_max] = tok;
                  cd.str_max = cd.str_max + 1;
                  cd.exp_max = cd.exp_max + 4;
                  tok = (char *)0x7;
                  goto LAB_08081272;
                }
                match_state = false;
              }
              break;
            case (char *)0x8:
              tok = strtok(cptr," ");
              if (tok == NULL) {
                match_state = false;
              }
              else {
                iVar4 = sscanf(tok,":%d:%d",cd.exp_stack + cd.exp_max,cd.exp_stack + cd.exp_max + 1)
                ;
                if (iVar4 == 2) {
                  cd.str_stack[cd.str_max] = tok;
                  cd.str_max = cd.str_max + 1;
                  cd.exp_max = cd.exp_max + 2;
                  tok = (char *)0x8;
                  goto LAB_08081272;
                }
                match_state = false;
              }
              break;
            case (char *)0x9:
              tok = strtok(cptr," ");
              if (tok == NULL) {
                match_state = false;
              }
              else {
                iVar4 = sscanf(tok,"%d.%d.%d.%d:%d:%d",cd.exp_stack + cd.exp_max,
                               cd.exp_stack + cd.exp_max + 1,cd.exp_stack + cd.exp_max + 2,
                               cd.exp_stack + cd.exp_max + 3,cd.exp_stack + cd.exp_max + 4,
                               cd.exp_stack + cd.exp_max + 5);
                if (iVar4 == 6) {
                  cd.str_stack[cd.str_max] = tok;
                  cd.str_max = cd.str_max + 1;
                  cd.exp_max = cd.exp_max + 6;
                  tok = (char *)0x9;
                  goto LAB_08081272;
                }
                match_state = false;
              }
              break;
            case (char *)0xa:
              tok = strtok(cptr," ");
              if (tok == NULL) {
                match_state = false;
              }
              else {
                iVar4 = strcmp(tok,"*");
                if ((iVar4 == 0) || (iVar4 = strcmp(tok,"all"), iVar4 == 0)) {
                  match_range(cd.rlist,0x100,"**");
                  match_range(cd.slist,0x40,"**");
                  memset(cd.plist,0,0x40);
                  tok = (char *)0xa;
                  goto LAB_08081272;
                }
                iVar4 = strcmp(tok,"r");
                if ((iVar4 == 0) || (iVar4 = strcmp(tok,"rack"), iVar4 == 0)) {
                  tok = strtok(NULL," ");
                  if (tok == NULL) {
                    match_state = false;
                  }
                  else {
                    iVar4 = match_range(cd.rlist,0x100,tok);
                    if (iVar4 == 0) {
                      tok = strtok(NULL," ");
                      if (tok == NULL) {
                        match_state = false;
                        tok = NULL;
                      }
                      else {
                        iVar4 = strcmp(tok,"s");
                        if ((iVar4 != 0) && (iVar4 = strcmp(tok,"slot"), iVar4 != 0)) {
                          match_range(cd.slist,0x40,"**");
                          cptr = cmdcpy;
                          strcpy(cptr,cmd);
                          strtok(cptr," ");
                          strtok(NULL," ");
                          memset(cd.plist,0,0x40);
                          tok = (char *)0xa;
                          goto LAB_08081272;
                        }
                        tok = strtok(NULL," ");
                        if (tok == NULL) {
                          match_state = false;
                        }
                        else {
                          iVar4 = match_range(cd.slist,0x40,tok);
                          if (iVar4 == 0) {
                            memset(cd.plist,0,0x40);
                            goto LAB_08081210;
                          }
                          match_state = false;
                        }
                      }
                    }
                    else {
                      match_state = false;
                    }
                  }
                }
                else {
                  iVar4 = strcmp(tok,"p");
                  if ((iVar4 == 0) || (iVar4 = strcmp(tok,"partition"), iVar4 == 0)) {
                    tok = strtok(NULL," ");
                    if (tok == NULL) {
                      match_state = false;
                    }
                    else {
                      iVar4 = match_range(cd.plist,0x40,tok);
                      if (iVar4 == 0) {
                        memset(cd.rlist,0,0x100);
                        memset(cd.slist,0,0x40);
LAB_08081210:
                        tok = (char *)0xa;
                        goto LAB_08081272;
                      }
                      match_state = false;
                    }
                  }
                  else {
                    match_state = false;
                  }
                }
              }
              break;
            case (char *)0xb:
              tok = strtok(cptr," ");
              if (tok == NULL) {
                match_state = false;
              }
              else {
                iVar4 = sscanf(tok,"%d.%d.%d.%d",cd.exp_stack + cd.exp_max,
                               cd.exp_stack + cd.exp_max + 1,cd.exp_stack + cd.exp_max + 2,
                               cd.exp_stack + cd.exp_max + 3);
                if (iVar4 == 4) {
                  match_state = false;
                }
                else {
                  iVar4 = sscanf(tok,"%d%c%d",&rack,&type,&slot);
                  if (iVar4 == 3) {
                    memset(cd.rlist,0,0x100);
                    memset(cd.slist,0,0x40);
                    iVar4 = rack;
                    if (rack < 0) {
                      iVar4 = rack + 0xff;
                    }
                    *(undefined1 *)((int)&cd + rack + (iVar4 >> 8) * -0x100 + 0x74) = 1;
                    iVar4 = slot;
                    if (slot < 0) {
                      iVar4 = slot + 0xff;
                    }
                    *(undefined1 *)((int)&cd + slot + (iVar4 >> 8) * -0x100 + 0x174) = 1;
                    memset(cd.plist,0,0x40);
                    tok = (char *)0xb;
                    goto LAB_08081272;
                  }
                  match_state = false;
                }
              }
              break;
            default:
              tok = strtok(cptr," ");
              if (tok == NULL) {
                match_state = false;
              }
              else {
                iVar4 = match_text(pcVar5,tok);
                if (iVar4 == 0) goto LAB_08081272;
                match_state = false;
              }
            }
            in_tok = in_tok + 1;
          }
        }
        clist = clist + 1;
      } while( true );
    }
  }
  return -0x321;
}

void CmdHelpAll(Cmd *cmds_in, int num_cmds_in, int showall, char *rptr)
{
  size_t sVar1;
  int iVar2;
  int iVar3;
  Cmd *cmds;
  int count;
  char *cptr;
  char *lptr;
  int clist;
  int current_cmd;
  int num_cmds;
  
  lptr = rptr;
  strcpy(rptr,"Commands are:\n");
  sVar1 = strlen(rptr);
  rptr = rptr + sVar1;
  clist = 0;
  do {
    if (cmds_in == NULL) {
      if (cmdlistcnt <= clist) goto LAB_08081558;
    }
    else if (0 < clist) {
LAB_08081558:
      strcpy(rptr,"\nenter \'hlp <cmd>\' for more help on a single command.\n");
      return;
    }
    iVar2 = num_cmds_in;
    num_cmds = (int)cmds_in;
    if (cmds_in == NULL) {
      num_cmds = (int)cmdlist[clist];
      iVar2 = cmdlistnum[clist];
    }
    count = 0;
    for (current_cmd = 0; current_cmd < iVar2; current_cmd = current_cmd + 1) {
      if ((*(int *)(num_cmds + 0x40 + current_cmd * 0x44) == 0) || (showall != 0)) {
        cptr = *(char **)(num_cmds + current_cmd * 0x44);
        if (cptr == (char *)0x6) {
          cptr = "<command>";
        }
        else if (((int)cptr < 6) || (0xb < (int)cptr)) {
          if (cptr < (char *)0x3e8) {
            cptr = *(char **)(num_cmds + 4 + current_cmd * 0x44);
          }
        }
        else {
          cptr = *(char **)(num_cmds + 4 + current_cmd * 0x44);
          if (cptr == (char *)0x6) goto LAB_08081546;
        }
        sVar1 = strlen(cptr);
        iVar3 = strncmp(lptr,cptr,sVar1);
        if (iVar3 != 0) {
          lptr = rptr;
          sprintf(rptr,"%-19s",cptr);
          count = count + 1;
          if ((count & 3U) == 0) {
            strcat(rptr,"\n");
          }
          sVar1 = strlen(rptr);
          rptr = rptr + sVar1;
        }
      }
LAB_08081546:
    }
    clist = clist + 1;
  } while( true );
}

char *CmdFormat(Cmd *cmds, int cmd)
{
  static char fmt[40];
  char *pcVar1;
  int tok;
  
  fmt[0] = '\0';
  tok = 0;
  while( true ) {
    if (cmds[cmd].toks[tok] < (char *)0xd) break;
    strcat((char *)&fmt,cmds[cmd].toks[tok]);
    strcat((char *)&fmt," ");
    tok = tok + 1;
  }
                    /* WARNING: Could not recover jumptable at 0x080815c2. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  pcVar1 = (char *)(*(code *)(&PTR_LAB_0808ff18)[(int)cmds[cmd].toks[tok]])();
  return pcVar1;
}

void CmdHelpCmd(Cmd *cmds_in, int num_cmds_in, char *which, int showall, char **rrptr)
{
  Cmd *cmds_00;
  size_t sVar1;
  int iVar2;
  int iVar3;
  char *s2;
  char *pcVar4;
  size_t sVar5;
  char s1 [80];
  Cmd *cmds;
  char *cptr;
  char *rptr;
  int count;
  int clist;
  int current_cmd;
  int num_cmds;
  
  count = 0;
  *rrptr = NULL;
  clist = 0;
  do {
    if (cmds_in == NULL) {
      if (cmdlistcnt <= clist) goto LAB_08081970;
    }
    else if (0 < clist) {
LAB_08081970:
      rptr = malloc(count + 100);
      *rrptr = rptr;
      if (rptr != NULL) {
        *rptr = '\0';
        if (count != 0) {
          clist = 0;
          do {
            if (cmds_in == NULL) {
              if (cmdlistcnt <= clist) {
                return;
              }
            }
            else if (0 < clist) {
              return;
            }
            iVar2 = num_cmds_in;
            cmds_00 = cmds_in;
            if (cmds_in == NULL) {
              iVar2 = cmdlistnum[clist];
              cmds_00 = cmdlist[clist];
            }
            for (current_cmd = 0; current_cmd < iVar2; current_cmd = current_cmd + 1) {
              if ((cmds_00[current_cmd].visibility == 0) || (showall != 0)) {
                cptr = cmds_00[current_cmd].toks[0];
                if (cptr == (char *)0x6) {
                  cptr = "<command>";
                }
                else if (((int)cptr < 6) || (0xc < (int)cptr)) {
                  if (cptr < (char *)0x3e8) {
                    cptr = cmds_00[current_cmd].toks[1];
                  }
                }
                else {
                  cptr = cmds_00[current_cmd].toks[1];
                  if (cptr == (char *)0x6) {
                    cptr = "<command>";
                  }
                }
                if ((which == NULL) || (iVar3 = match_text(cptr,which), iVar3 == 0)) {
                  s2 = CmdFormat(cmds_00,current_cmd);
                  strcpy(s1,s2);
                  pcVar4 = cmds_00[current_cmd].desc;
                  if (cmds_00[current_cmd].desc == NULL) {
                    pcVar4 = "-";
                  }
                  sprintf(rptr,"%s\n\t%s\n",s1,pcVar4);
                  sVar5 = strlen(rptr);
                  rptr = rptr + sVar5;
                }
              }
            }
            clist = clist + 1;
          } while( true );
        }
        sprintf(rptr,"ERROR: command %s not found.\n",which);
      }
      return;
    }
    iVar2 = num_cmds_in;
    num_cmds = (int)cmds_in;
    if (cmds_in == NULL) {
      num_cmds = (int)cmdlist[clist];
      iVar2 = cmdlistnum[clist];
    }
    for (current_cmd = 0; current_cmd < iVar2; current_cmd = current_cmd + 1) {
      if ((*(int *)(num_cmds + 0x40 + current_cmd * 0x44) == 0) || (showall != 0)) {
        cptr = *(char **)(num_cmds + current_cmd * 0x44);
        if (cptr == (char *)0x6) {
          cptr = "<command>";
        }
        else if (((int)cptr < 6) || (0xc < (int)cptr)) {
          if (cptr < (char *)0x3e8) {
            cptr = *(char **)(num_cmds + 4 + current_cmd * 0x44);
          }
        }
        else {
          cptr = *(char **)(num_cmds + 4 + current_cmd * 0x44);
          if (cptr == (char *)0x6) {
            cptr = "<command>";
          }
        }
        if ((which == NULL) || (iVar3 = match_text(cptr,which), iVar3 == 0)) {
          pcVar4 = CmdFormat((Cmd *)num_cmds,current_cmd);
          strcpy(s1,pcVar4);
          pcVar4 = *(char **)(num_cmds + 0x3c + current_cmd * 0x44);
          if (*(int *)(num_cmds + 0x3c + current_cmd * 0x44) == 0) {
            pcVar4 = "-";
          }
          sVar5 = strlen(s1);
          sVar1 = strlen(pcVar4);
          count = sVar1 + sVar5 + count + 4;
        }
      }
    }
    clist = clist + 1;
  } while( true );
}

static int match_text(char *cmd_word, char *text)
{
  int iVar1;
  char command [50];
  char *next_tok;
  char *cptr;
  
  cptr = command;
  strncpy(cptr,cmd_word,0x31);
  command[0x31] = '\0';
  while( true ) {
    next_tok = strchr(cptr,0x7c);
    if (next_tok != NULL) {
      *next_tok = '\0';
      next_tok = next_tok + 1;
    }
    iVar1 = strcmp(cptr,text);
    if (iVar1 == 0) break;
    cptr = next_tok;
    if (next_tok == NULL) {
      return 1;
    }
  }
  return 0;
}

int CmdMatchRange(char *X, int xmax, char *s)
{
  int iVar1;
  
  iVar1 = match_range(X,xmax,s);
  return iVar1;
}

static int match_range(char *X, int xmax, char *s)
{
  int iVar1;
  size_t sVar2;
  int error;
  int x;
  int n2;
  int n1;
  bool range;
  
  range = false;
  error = 0;
  memset(X,0,xmax);
  iVar1 = strcmp(s,"*");
  if ((iVar1 == 0) || (iVar1 = strcmp(s,"all"), iVar1 == 0)) {
    memset(X,5,xmax);
    error = 0;
  }
  else {
    iVar1 = strcmp(s,"**");
    if (iVar1 == 0) {
      memset(X,6,xmax);
      error = 0;
    }
    else {
      while ((error == 0 && (sVar2 = strlen(s), sVar2 != 0))) {
        sVar2 = strspn(s,"0123456789");
        if (sVar2 == 0) {
          error = 1;
        }
        else {
          iVar1 = sscanf(s,"%d",&n1);
          if (iVar1 == 1) {
            if (n1 < xmax) {
              if (s[sVar2] == ',') {
                if (range) {
                  if (n1 < n2) {
                    error = 1;
                  }
                  else {
                    if (n2 == n1) {
                      X[n2] = '\x01';
                      n2 = n2 + 1;
                    }
                    else {
                      X[n2] = '\x02';
                      iVar1 = n2;
                      while (n2 = iVar1 + 1, n2 < n1) {
                        X[n2] = '\x03';
                        iVar1 = n2;
                      }
                      X[n2] = '\x04';
                      n2 = iVar1 + 2;
                    }
                    range = false;
                  }
                }
                else {
                  X[n1] = '\x01';
                }
                s = s + sVar2 + 1;
                if (*s == '\0') {
                  error = 1;
                }
              }
              else if (s[sVar2] == '-') {
                n2 = n1;
                range = true;
                s = s + sVar2 + 1;
                sVar2 = strlen(s);
                if (sVar2 == 0) {
                  error = 1;
                }
              }
              else {
                if (range) {
                  if (n1 < n2) {
                    error = 1;
                  }
                  else {
                    if (n2 == n1) {
                      X[n2] = '\x01';
                      n2 = n2 + 1;
                    }
                    else {
                      X[n2] = '\x02';
                      iVar1 = n2;
                      while (n2 = iVar1 + 1, n2 < n1) {
                        X[n2] = '\x03';
                        iVar1 = n2;
                      }
                      X[n2] = '\x04';
                      n2 = iVar1 + 2;
                    }
                    range = false;
                  }
                }
                else {
                  X[n1] = '\x01';
                }
                s = s + sVar2;
                sVar2 = strlen(s);
                if (sVar2 != 0) {
                  error = 1;
                }
              }
            }
            else {
              error = 1;
            }
          }
          else {
            error = 1;
          }
        }
      }
    }
  }
  return error;
}
