/*
 * sys_ctrl/l3/gui/config.cc
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/config.cc
 *
 * The command destination ("r 1,3 s *", "p 2", ...): parsed with the L2's
 * command parser into rack/slot/partition selection lists.
 */

#include <string.h>
#include "l2gui.h"
#include "config.h"

static char dest_str[100];
CmdData *parse_data_ptr;
static CmdData dest_data;

static int snap_dest(CmdData *cptr, char **results);

/* the destination prefix alone, as a command: CmdProcess fills the lists */
static Cmd dest_cmd[1] = {
  { { (char *)10 }, (CmdCallback *)snap_dest, { 0 }, "" },
};

int config_init(char *dest)
{
  config_set_command_dest(dest);
  return 0;
}

int config_set_command_dest(char *str)
{
  strcpy(dest_str, str);
  config_parse_dest(str, &dest_data);
  mainwin_update_dest(str);
  return 0;
}

char *config_command_dest(void)
{
  return dest_str;
}

int config_dest_includes_l1(L2CfgL1 *l1)
{
  return dest_data.rlist[l1->rack] && dest_data.slist[l1->slot] &&
         dest_data.plist[l1->partition];
}

static int snap_dest(CmdData *cptr, char **results)
{
  memcpy(parse_data_ptr, cptr, sizeof(CmdData));
  return 0;
}

int config_parse_dest(char *str, CmdData *data)
{
  memset(data, 0, sizeof(CmdData));
  parse_data_ptr = data;
  CmdProcess(1, str, NULL, dest_cmd, 1, NULL);
  if (config_popcnt(data->rlist, sizeof(data->rlist)) == 0) {
    /* a partition destination: every rack and slot */
    memset(data->rlist, 5, sizeof(data->rlist));
    memset(data->slist, 5, sizeof(data->slist));
  }
  else {
    memset(data->plist, 5, sizeof(data->plist));
  }
  return 0;
}

int config_popcnt(char *s, int slen)
{
  int c = 0;

  while (slen--)
    if (*s++)
      c++;
  return c;
}
