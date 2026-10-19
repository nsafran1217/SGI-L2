/*
 * sys_ctrl/l3/l2/l2cmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l2cmd.c
 *
 * The L2's commands (the console's, l2cmd's and other L2s'): the command
 * table for Cmd.c and a function per command. A command's immediate
 * output goes in *results; commands for bricks and other L2s queue
 * requests on the L2CMD (broadcast.c, target.c), and their responses come
 * back through the L2CMD's owner (smp.c, cmd.c). Commands that need several
 * rounds (pbay, version summary) use the command task's second L2CMD with
 * a response callback (cmd_setup_usr_response()).
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include "l2.h"
#include "l2cmd.h"
#include "broadcast.h"
#include "cfg.h"
#include "cmd.h"
#include "dest.h"
#include "discover.h"
#include "format.h"
#include "irtr.h"
#include "l1.h"
#include "lpbk.h"
#include "power.h"
#include "reqrspq.h"
#include "route.h"
#include "smp.h"
#include "target.h"
#include "../api/SCapiL2.h"
#include "../main/nvram.h"
#include "../../common/sys/Cmd.h"
#include "../../common/sys/MemUsage.h"

#define L2CMD_FORMS     ((int)(sizeof(l2cmd_cmds) / sizeof(l2cmd_cmds[0])))
#define FORM_CATCH_ALL  (L2CMD_FORMS - 2)   /* the last two forms: "[<target>] <command>" */
#define L2_PEER_PORT    9001    /* plus IR_PORT_BIAS */
#define L1REQ_REBOOT    0x4002  /* the request task's reboot */

/* one of this L2's tasks (rack and slot all ones) */
#define LOCAL_L2_TASK(t) IR_ADDR_MAKE(IR_ADDR_L2,0x3ff,0x3f,0,t)
struct _pbay_data {
    char **snlist;
    char **snconns;
    int *snnum;
    IRAddress *snaddr;
    int sncnt;
    int stage;
    int errcnt;
    L2CMD *orig_c;
    char *cmd;
};
typedef struct _pbay_data pbay_data;
struct _ver_summary_data {
    int quiet;
    char **verslist;
    int *versnum;
    int verscnt;
    int errcnt;
    char *ptype;
    L2CMD *orig_c;
};
typedef struct _ver_summary_data ver_summary_data;

static int check_smp(SMP *smp, char **results);
static void l2cmd_timeout(int to, void *data);
static void l2cmd_etimeout(char *msg, void *data);
static int l2cmd_broadcast(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_autopower(CmdData *cptr, char **results);
static int l2cmd_config(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_connect(CmdData *cptr, char **results);
static int l2cmd_rtc(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_demo(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_help(CmdData *cptr, char **results);
static int l2cmd_l2dbg(CmdData *cptr, char **results);
static void load_timer(void);
static int l2cmd_destination(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_env(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_l1(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_l2(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_loopback(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_route(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_hreboot_l1(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_nvram(CmdData *cptr, char **results);
static int l2cmd_reset(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_rackid(CmdData *cptr, char **results);
static int l2cmd_pbay(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_quit(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_ping(CmdData *cptr, char **results);
static int l2cmd_l2dsp(CmdData *cptr, char **results);
static int format_l2find_entry(char *rptr, sn1SC_L2 *l2);
static int l2cmd_l2find(CmdData *cptr, char **results);
static int l2cmd_smp(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_serial(CmdData *cptr, char **results);
static int l2cmd_sysname(CmdData *cptr, char **results);
static int l2cmd_multisys(CmdData *cptr, char **results);
static int l2cmd_psmode(CmdData *cptr, char **results);
static int l2cmd_log(CmdData *cptr, char **results);
static int l2cmd_select(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_tty(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_version(CmdData *cptr, char **results);
static int ver_summary_rsp(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data);
static int l2cmd_version_summary(CmdData *cptr, char **results, L2CMD *c);
static int cc(char *src, char *tgt);
static int l2cmd_l2cmd(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_l1cmd(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_cmd(CmdData *cptr, char **results, L2CMD *c);
static char *response(char **rptr, int size);
static int BRICK_TASKNUM(int btype, int slab, int subchan);

static uint32 l2dsp_debug_state;
static int load_debug;
static EventID load_timerid;
static uint32 l2_misc_debug;
Cmd l2cmd_cmds[] = {
  { .toks = { "router|io|compute|other", CMD_TOK(CMD_REST) }, .func = l2cmd_broadcast, .desc = "targets command to class of bricks" },
  { .toks = { "autopower|apwr" }, .func = l2cmd_autopower, .desc = "shows current auto power up setting" },
  { .toks = { "autopower|apwr", "on" }, .func = l2cmd_autopower, .params = { 1 }, .desc = "enables auto power on" },
  { .toks = { "autopower|apwr", "off" }, .func = l2cmd_autopower, .params = { 2 }, .desc = "disables auto power on" },
  { .toks = { "autopower|apwr", "abort" }, .func = l2cmd_autopower, .params = { 3 }, .desc = "aborts auto power on" },
  { .toks = { "autopower|apwr", "delay", CMD_TOK(CMD_EXP) }, .func = l2cmd_autopower, .params = { 4 }, .desc = "sets delay (in seconds) before auto-powerup" },
  { .toks = { "config|cfg" }, .func = l2cmd_config, .params = { 0, 1, 1 }, .desc = "shows configuration information (normal)" },
  { .toks = { "config|cfg", "summary|s" }, .func = l2cmd_config, .params = { 0, 0, 1 }, .desc = "shows configuration information (summary)" },
  { .toks = { "config|cfg", "verbose|v" }, .func = l2cmd_config, .params = { 0, 2, 1 }, .desc = "shows configuration information (verbose)" },
  { .toks = { "config|cfg", "l2" }, .func = l2cmd_config, .params = { 0, 1 }, .desc = "shows L2 configuration information (normal)" },
  { .toks = { "config|cfg", "l2", "verbose|v" }, .func = l2cmd_config, .params = { 0, 2 }, .desc = "shows L2 configuration information (verbose)" },
  { .toks = { "config|cfg", "re|rescan" }, .func = l2cmd_config, .params = { 1 }, .desc = "forces L1 config update" },
  { .toks = { "config|cfg", "auto" }, .func = l2cmd_config, .params = { 2 }, .desc = "enables automatic L1 config updates" },
  { .toks = { "config|cfg", "man|manual" }, .func = l2cmd_config, .params = { 3 }, .desc = "disables automatic L1 config updates" },
  { .toks = { "config|cfg", "print" }, .func = l2cmd_config, .params = { 4 }, .desc = "debugging only (local config)" },
  { .toks = { "config|cfg", "print", "all" }, .func = l2cmd_config, .params = { 4, 1 }, .desc = "debugging only (full config)" },
  { .toks = { "config|cfg", "l|list" }, .func = l2cmd_config, .params = { 5 }, .desc = "shows configuration information (list)" },
  { .toks = { "config|cfg", "t|times" }, .func = l2cmd_config, .params = { 6 }, .desc = "shows various L2 process information" },
  { .toks = { "connect", CMD_TOK(CMD_STR) }, .func = l2cmd_connect, .desc = "connects to L2 at host specified" },
  { .toks = { "date", "tz" }, .func = l2cmd_rtc, .params = { 2 }, .desc = "display current timezone settings" },
  { .toks = { "date", "tz", CMD_TOK(CMD_STR) }, .func = l2cmd_rtc, .params = { 3 }, .desc = "set UNIX timezone string (ex: date tz CST6CDT)" },
  { .toks = { "date" }, .func = l2cmd_rtc, .desc = "display current L2 date and time" },
  { .toks = { "date", "raw" }, .func = l2cmd_rtc, .params = { 5 }, .desc = "display current L2 time" },
  { .toks = { "date", "sync" }, .func = l2cmd_rtc, .params = { 6 }, .desc = "set all L1's and L2's to this L2's timezone and time" },
  { .toks = { "date", CMD_TOK(CMD_STR) }, .func = l2cmd_rtc, .params = { 1 }, .desc = "set L2 date and time (date MMDDhhmm[[CC]YY][.ss])" },
  { .toks = { "date", CMD_TOK(CMD_STR), CMD_TOK(CMD_STR) }, .func = l2cmd_rtc, .params = { 4 }, .desc = "set L2 timezone and date" },
  { .toks = { "demo" }, .func = l2cmd_demo, .desc = "dumps the contents of the L2 demo database" },
  { .toks = { "demo", "current", CMD_TOK(CMD_EXP) }, .func = l2cmd_demo, .params = { 1 }, .desc = "selects the specified msgno as the default message" },
  { .toks = { "demo", CMD_TOK(CMD_EXP), CMD_TOK(CMD_REST) }, .func = l2cmd_demo, .params = { 2 }, .desc = "sets the value of the specified msgno in the demo database" },
  { .toks = { "destination|dest" }, .func = l2cmd_destination, .desc = "shows default destination(s)" },
  { .toks = { CMD_TOK(CMD_RANGE), "destination|dest" }, .func = l2cmd_destination, .params = { 1 }, .desc = "sets default destination to selected racks and slots" },
  { .toks = { "destination|dest", "reset|rst" }, .func = l2cmd_destination, .params = { 2 }, .desc = "resets default default to all rack and slots" },
  { .toks = { "env", "summary|s" }, .func = l2cmd_env, .desc = "shows environmental status summary" },
  { .toks = { CMD_TOK(CMD_RANGE), "env", "summary|s" }, .func = l2cmd_env, .params = { 1 }, .desc = "shows environmental status summary" },
  { .toks = { "help|hlp" }, .func = l2cmd_help, .desc = "get list of commands" },
  { .toks = { "help|hlp", CMD_TOK(CMD_STR) }, .func = l2cmd_help, .params = { 1 }, .desc = "get help on a single command." },
  { .toks = { CMD_TOK(CMD_RANGE), "hreboot_l1" }, .func = l2cmd_hreboot_l1, .desc = "use the L1REQ_REBOOT request to reboot the L1", .visibility = 1 },
  { .toks = { CMD_TOK(CMD_RACKSLOT), "hreboot_l1" }, .func = l2cmd_hreboot_l1, .desc = "use the L1REQ_REBOOT request to reboot the L1", .visibility = 1 },
  { .toks = { "let", "atlantis", "rise" }, .func = l2cmd_help, .params = { 0, 1 }, .desc = "get complete list of commands", .visibility = 1 },
  { .toks = { "let", CMD_TOK(CMD_STR), "rise" }, .func = l2cmd_help, .params = { 1, 1 }, .desc = "get complete help on a single command.", .visibility = 1 },
  { .toks = { "l2dbg" }, .func = l2cmd_l2dbg, .params = { (unsigned int)-1 }, .desc = "show current L2 debug states" },
  { .toks = { "l2dbg", "malloc", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .desc = "set irouter malloc/free debug level" },
  { .toks = { "l2dbg", "packets", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 1 }, .desc = "set irouter packet debug level" },
  { .toks = { "l2dbg", "packets" }, .func = l2cmd_l2dbg, .params = { 1, 1 }, .desc = "show packet usage and high water" },
  { .toks = { "l2dbg", "packets", "reset" }, .func = l2cmd_l2dbg, .params = { 1, 3 }, .desc = "reset packet usage and high water counters" },
  { .toks = { "l2dbg", "config", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 2 }, .desc = "set L2 configuration debug level" },
  { .toks = { "l2dbg", "meminfo|mem" }, .func = l2cmd_l2dbg, .params = { 3 }, .desc = "display dynamic memory usage" },
  { .toks = { "l2dbg", "smp", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 4 }, .desc = "set SMP input debug level" },
  { .toks = { "l2dbg", "broadcast", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 5 }, .desc = "set broadcast debug level" },
  { .toks = { "l2dbg", "discovery|disc", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 6 }, .desc = "set L2 discovery debug level" },
  { .toks = { "l2dbg", "usb", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 7 }, .desc = "set L2 USB debug level (0=off,1=debug,2=verbose)" },
  { .toks = { "l2dbg", "e|estat" }, .func = l2cmd_l2dbg, .params = { 8 }, .desc = "report Event processor stats" },
  { .toks = { "l2dbg", "e|estat", "r|reset" }, .func = l2cmd_l2dbg, .params = { 8, 1 }, .desc = "report Event processor stats and reset to zero" },
  { .toks = { "l2dbg", "sbuf", CMD_TOK(CMD_EXP), CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 9 }, .desc = "set L2<->L2 socket send/recv buffer size" },
  { .toks = { "l2dbg", "events", "io" }, .func = l2cmd_l2dbg, .params = { 10 }, .desc = "show I/O events" },
  { .toks = { "l2dbg", "events", "timers" }, .func = l2cmd_l2dbg, .params = { 11 }, .desc = "show timer event" },
  { .toks = { "l2dbg", "console", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 12 }, .desc = "show console tracking messages" },
  { .toks = { "l2dbg", "qstat" }, .func = l2cmd_l2dbg, .params = { 19 }, .desc = "show Router client queue statistics" },
  { .toks = { "l2dbg", "qstat", "reset" }, .func = l2cmd_l2dbg, .params = { 20 }, .desc = "resets cumulative queue statistics for each Router client" },
  { .toks = { "l2dbg", "load", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 21 }, .desc = "enable/disable simulated L2 load" },
  { .toks = { "l2dbg", "flow", CMD_TOK(CMD_EXP), CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 22 }, .desc = "set net conn flow ctrl (high/low water mark pkt count)" },
  { .toks = { "l2dbg", "throttle", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 23 }, .desc = "set L1 input throttle frequency (msecs)" },
  { .toks = { "l2dbg", "brspto", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 24 }, .desc = "set broadcast response timeout limit" },
  { .toks = { "l2dbg", "trspto", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 25 }, .desc = "set target response timeout limit" },
  { .toks = { "l2dbg", "misc", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 26 }, .desc = "set misc. L2 debug flag", .visibility = 1 },
  { .toks = { "l2dbg", "smp", "response", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 28 }, .desc = "debug SMP responses" },
  { .toks = { "l2dbg", "str", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dbg, .params = { 29 }, .desc = "debug SMP string processing" },
  { .toks = { "l1" }, .func = l2cmd_l1, .desc = "engages L1 command processor" },
  { .toks = { CMD_TOK(CMD_RANGE), "l1" }, .func = l2cmd_l1, .params = { 1 }, .desc = "engages L1 command processor at rack and slot" },
  { .toks = { CMD_TOK(CMD_RACKSLOT), "l1" }, .func = l2cmd_l1, .params = { 1 }, .desc = "engages L1 command processor at rack and slot" },
  { .toks = { CMD_TOK(CMD_RANGE), "l1", CMD_TOK(CMD_REST) }, .func = l2cmd_l1cmd, .params = { 1 }, .desc = "sends L1 command to selected L1(s)" },
  { .toks = { CMD_TOK(CMD_RACKSLOT), "l1", CMD_TOK(CMD_REST) }, .func = l2cmd_l1cmd, .params = { 1 }, .desc = "sends L1 command to selected L1" },
  { .toks = { CMD_TOK(CMD_IP_PORT_L1), CMD_TOK(CMD_REST) }, .func = l2cmd_l1cmd, .params = { 2 }, .desc = "sends L1 command to L1 at ip:port:L1" },
  { .toks = { "l1", CMD_TOK(CMD_REST) }, .func = l2cmd_l1cmd, .desc = "sends L1 command to default destinations" },
  { .toks = { "l2" }, .func = l2cmd_l2, .desc = "engages L2 command processor" },
  { .toks = { CMD_TOK(CMD_RANGE), "l2" }, .func = l2cmd_l2, .params = { 1 }, .desc = "engages L2 command processor at specified rack" },
  { .toks = { "l2", CMD_TOK(CMD_REST) }, .func = l2cmd_l2cmd, .params = { 3 }, .desc = "sends L2 command to local l2" },
  { .toks = { CMD_TOK(CMD_RANGE), "l2", CMD_TOK(CMD_REST) }, .func = l2cmd_l2cmd, .params = { 1 }, .desc = "sends L2 command to selected L2(s)" },
  { .toks = { "l2dsp|l2display", "debug", CMD_TOK(CMD_EXP) }, .func = l2cmd_l2dsp, .desc = "set L2 display debug flags" },
  { .toks = { "l2dsp|l2display", "debug" }, .func = l2cmd_l2dsp, .params = { 1 }, .desc = "show L2 display debug flags" },
  { .toks = { "l2dsp|l2display", "enable" }, .func = l2cmd_l2dsp, .params = { 2 }, .desc = "enable touch-screen input from the L2 display" },
  { .toks = { "l2dsp|l2display", "disable" }, .func = l2cmd_l2dsp, .params = { 3 }, .desc = "lock the L2 display (disable touch-screen input)" },
  { .toks = { "l2dsp|l2display" }, .func = l2cmd_l2dsp, .params = { 4 }, .desc = "show the L2 display lock setting" },
  { .toks = { "l2find" }, .func = l2cmd_l2find, .desc = "print list of L2's on the same subnet as this one" },
  { .toks = { "log" }, .func = l2cmd_log, .desc = "dump log" },
  { .toks = { "log", "clear|reset" }, .func = l2cmd_log, .params = { 1 }, .desc = "clear log" },
  { .toks = { "log", "insert", CMD_TOK(CMD_REST) }, .func = l2cmd_log, .params = { 2 }, .desc = "insert entry into log" },
  { .toks = { CMD_TOK(CMD_RACKSLOT), "loopback", CMD_TOK(CMD_EXP), CMD_TOK(CMD_EXP) }, .func = l2cmd_loopback, .desc = "loopback data to L1 (size,count)" },
  { .toks = { CMD_TOK(CMD_RACKSLOT), "loopback", CMD_TOK(CMD_EXP), CMD_TOK(CMD_EXP), CMD_TOK(CMD_EXP) }, .func = l2cmd_loopback, .params = { 1 }, .desc = "loopback data to L1 (session, size, count)" },
  { .toks = { CMD_TOK(CMD_RANGE), "route" }, .func = l2cmd_route, .desc = "trace route to L1" },
  { .toks = { CMD_TOK(CMD_RACKSLOT), "route" }, .func = l2cmd_route, .desc = "trace route to L1" },
  { .toks = { "nvram", "reset" }, .func = l2cmd_nvram, .desc = "return L2 NVRAM settings to factory default" },
  { .toks = { "ping" }, .func = l2cmd_ping, .desc = "show L2 to L2/L1 ping configuration" },
  { .toks = { "ping", "min", CMD_TOK(CMD_EXP) }, .func = l2cmd_ping, .params = { 1 }, .desc = "sets L2 to L2 ping response minumum" },
  { .toks = { "ping", "max", CMD_TOK(CMD_EXP) }, .func = l2cmd_ping, .params = { 2 }, .desc = "sets L2 to L2 ping response maximum" },
  { .toks = { "ping", "l2", CMD_TOK(CMD_EXP) }, .func = l2cmd_ping, .params = { 3 }, .desc = "sets L2 to L2 ping frequency in seconds" },
  { .toks = { "ping", "sender", CMD_TOK(CMD_EXP) }, .func = l2cmd_ping, .params = { 4 }, .desc = "enables (1) or disables (0) sender ping as valid response" },
  { .toks = { "ping", "l1", CMD_TOK(CMD_EXP) }, .func = l2cmd_ping, .params = { 5 }, .desc = "sets L2 to L1 ping frequency in seconds" },
  { .toks = { "ping", "throttle", CMD_TOK(CMD_EXP) }, .func = l2cmd_ping, .params = { 6 }, .desc = "set L2 configuration throttle frequency" },
  { .toks = { "ping", "reset" }, .func = l2cmd_ping, .params = { 7 }, .desc = "resets L2 to L2/L1 ping configuration to defaults" },
  { .toks = { "pbay", "cfg|config" }, .func = l2cmd_pbay, .desc = "report the bricks connected to each PowerBay" },
  { .toks = { "pbay", CMD_TOK(CMD_REST) }, .func = l2cmd_pbay, .desc = "send pbay <command> to one L1 connected to each PowerBay" },
  { .toks = { CMD_TOK(CMD_RANGE), "pbay", "cfg|config" }, .func = l2cmd_pbay, .params = { 1 }, .desc = "report the bricks connected to each PowerBay" },
  { .toks = { CMD_TOK(CMD_RANGE), "pbay", CMD_TOK(CMD_REST) }, .func = l2cmd_pbay, .params = { 1 }, .desc = "send pbay <command> to one L1 connected to each PowerBay" },
  { .toks = { "power|pwr" }, .func = l2cmd_power, .desc = "show power status of each selected brick" },
  { .toks = { "power|pwr", "up|u" }, .func = l2cmd_power, .params = { 0, 1 }, .desc = "powers up each selected brick" },
  { .toks = { "power|pwr", "down|d" }, .func = l2cmd_power, .params = { 0, 2 }, .desc = "powers down each selected brick" },
  { .toks = { "power|pwr", "summary|s" }, .func = l2cmd_power, .params = { 0, 3 }, .desc = "power status summary" },
  { .toks = { "power|pwr", "delay" }, .func = l2cmd_power, .params = { 0, 4 }, .desc = "shows delay between power commands" },
  { .toks = { "power|pwr", "delay", CMD_TOK(CMD_EXP) }, .func = l2cmd_power, .params = { 0, 5 }, .desc = "sets delay between power commands in milliseconds" },
  { .toks = { "power|pwr", "mode" }, .func = l2cmd_power, .params = { 0, 6 }, .desc = "shows current power mode (fast/slow)", .visibility = 1 },
  { .toks = { "power|pwr", "mode", "slow|fast" }, .func = l2cmd_power, .params = { 0, 7 }, .desc = "sets fast (RTRs parallel), or old/slow (RTRs in series) powerup", .visibility = 1 },
  { .toks = { CMD_TOK(CMD_RANGE), "power|pwr" }, .func = l2cmd_power, .params = { 1 }, .desc = "show power status of each selected brick" },
  { .toks = { CMD_TOK(CMD_RANGE), "power|pwr", "up|u" }, .func = l2cmd_power, .params = { 1, 1 }, .desc = "powers up each selected brick" },
  { .toks = { CMD_TOK(CMD_RANGE), "power|pwr", "down|d" }, .func = l2cmd_power, .params = { 1, 2 }, .desc = "powers down each selected brick" },
  { .toks = { CMD_TOK(CMD_RANGE), "power|pwr", "summary|s" }, .func = l2cmd_power, .params = { 1, 3 }, .desc = "power status summary" },
  { .toks = { "quit" }, .func = l2cmd_quit, .desc = "exit the L2" },
  { .toks = { "rackid" }, .func = l2cmd_rackid, .desc = "print the rack ID of the L2" },
  { .toks = { "rackid", CMD_TOK(CMD_DEC) }, .func = l2cmd_rackid, .params = { 1 }, .desc = "set the rack ID for the L2" },
  { .toks = { "reset|rst" }, .func = l2cmd_reset, .desc = "reset each selected brick" },
  { .toks = { CMD_TOK(CMD_RANGE), "reset|rst" }, .func = l2cmd_reset, .params = { 1 }, .desc = "reset each selected brick" },
  { .toks = { "select|sel" }, .func = l2cmd_select, .params = { 0, 1 }, .desc = "shows system console information" },
  { .toks = { "select|sel", "terse|t" }, .func = l2cmd_select, .desc = "shows system console information - terse version" },
  { .toks = { "select|sel", "subchannel|sub|s", "console|con" }, .func = l2cmd_select, .params = { 1 }, .desc = "sets 'console' subchannel for console I/O, current brick" },
  { .toks = { "select|sel", "subchannel|sub|s", "a|b|c|d" }, .func = l2cmd_select, .params = { 2 }, .desc = "sets selected CPU subchannel for console I/O, current brick" },
  { .toks = { "select|sel", "subchannel|sub|s", CMD_TOK(CMD_EXP) }, .func = l2cmd_select, .params = { 3 }, .desc = "sets selected CPU subchannel for console I/O, current brick" },
  { .toks = { "select|sel", "subchannel|sub|s", CMD_TOK(CMD_STR) }, .func = l2cmd_select, .params = { 4 }, .desc = "sets selected CPU subchannel for console I/O, current brick (multi-node/brick)" },
  { .toks = { "select|sel", CMD_TOK(CMD_EXP), CMD_TOK(CMD_EXP) }, .func = l2cmd_select, .params = { 5 }, .desc = "sets rack and slot for console I/O, subchannel ?" },
  { .toks = { "select|sel", CMD_TOK(CMD_RACKSLOT) }, .func = l2cmd_select, .params = { 5 }, .desc = "sets rack and slot for console I/O, subchannel ?" },
  { .toks = { "select|sel", "reset|rst" }, .func = l2cmd_select, .params = { 6 }, .desc = "reset console I/O selections to defaults" },
  { .toks = { "select|sel", "partition|part|p", CMD_TOK(CMD_EXP) }, .func = l2cmd_select, .params = { 7 }, .desc = "sets partition (and system console) for console access" },
  { .toks = { "select|sel", "filter", "on" }, .func = l2cmd_select, .params = { 9, 1 }, .desc = "enables console output filter" },
  { .toks = { "select|sel", "filter", "off" }, .func = l2cmd_select, .params = { 9 }, .desc = "disables console output filter" },
  { .toks = { "select|sel", CMD_TOK(CMD_EXP), CMD_TOK(CMD_EXP), CMD_TOK(CMD_STR) }, .func = l2cmd_select, .params = { 10 }, .desc = "sets select rack, slot and subchannel for console I/O" },
  { .toks = { "smp" }, .func = l2cmd_smp, .desc = "show status of SMP connections" },
  { .toks = { "smp", "verbose|v" }, .func = l2cmd_smp, .params = { 0, 1 }, .desc = "show status of SMP connections (verbose)" },
  { .toks = { "smp", "join", CMD_TOK(CMD_EXP) }, .func = l2cmd_smp, .params = { 1 }, .desc = "joins to specified SMP group" },
  { .toks = { "smp", "leave" }, .func = l2cmd_smp, .params = { 2 }, .desc = "leaves the current SMP group" },
  { .toks = { "serial" }, .func = l2cmd_serial, .desc = "shows the L2 system serial number" },
  { .toks = { "serial", "set", CMD_TOK(CMD_STR) }, .func = l2cmd_serial, .params = { 1 }, .desc = "sets the L2 system serial number" },
  { .toks = { "multisys|msys" }, .func = l2cmd_multisys, .desc = "show current setting for multiple system network sharing" },
  { .toks = { "multisys|msys", "on" }, .func = l2cmd_multisys, .params = { 1 }, .desc = "enable multiple systems on same network (L2's talk by system SN)" },
  { .toks = { "multisys|msys", "off" }, .func = l2cmd_multisys, .params = { 2 }, .desc = "disable multiple systems on same network (L2's talk to all L2's)" },
  { .toks = { "share", "net" }, .func = l2cmd_multisys, .desc = "show current setting for multiple system network sharing" },
  { .toks = { "share", "net", "on" }, .func = l2cmd_multisys, .params = { 1 }, .desc = "enable multiple systems on same network (L2's talk by system SN)" },
  { .toks = { "share", "net", "off" }, .func = l2cmd_multisys, .params = { 2 }, .desc = "disable multiple systems on same network (L2's talk to all L2's)" },
  { .toks = { "psmode|ps" }, .func = l2cmd_psmode, .desc = "query L2 primary/secondary mode" },
  { .toks = { "psmode|ps", "none|n|secondary|s|primary|p" }, .func = l2cmd_psmode, .params = { 1 }, .desc = "set L2 primary/secondary mode" },
  { .toks = { "psmode|ps", "none|n|secondary-external|sx|primary-external|px" }, .func = l2cmd_psmode, .params = { 1, 1 }, .desc = "set L2 primary/secondary mode" },
  { .toks = { "sysname" }, .func = l2cmd_sysname, .desc = "shows the system name" },
  { .toks = { "sysname", "reset" }, .func = l2cmd_sysname, .params = { 2 }, .desc = "resets the system name" },
  { .toks = { "sysname", CMD_TOK(CMD_STR) }, .func = l2cmd_sysname, .params = { 1 }, .desc = "set the system name" },
  { .toks = { "version|ver" }, .func = l2cmd_version, .desc = "show L2 firmware version (use \"l1 version\" for L1 firmware revisions)" },
  { .toks = { "version|ver", "v|verbose" }, .func = l2cmd_version, .params = { 1 }, .desc = "show L2 firmware version with L2 emulator and display firmware versions" },
  { .toks = { "version|ver", "s|summary" }, .func = l2cmd_version_summary, .desc = "display summary of L1 and L2 firmware versions currently running in the system" },
  { .toks = { "version|ver", "c|check" }, .func = l2cmd_version_summary, .params = { 1 }, .desc = "display any L1 or L2 firmware versions mismatches" },
  { .toks = { CMD_TOK(CMD_RANGE), "version|ver", "s|summary" }, .func = l2cmd_version_summary, .desc = "display summary of L1 and L2 firmware versions currently running in the system" },
  { .toks = { CMD_TOK(CMD_RANGE), "version|ver", "c|check" }, .func = l2cmd_version_summary, .params = { 1 }, .desc = "display any L1 or L2 firmware versions mismatches" },
  { .toks = { "tty" }, .func = l2cmd_tty, .desc = "show tty configuration", .visibility = 1 },
  { .toks = { CMD_TOK(CMD_RACKSLOT), CMD_TOK(CMD_REST) }, .func = l2cmd_l1cmd, .params = { 1 }, .desc = "sends L1 command to selected L1" },
  { .toks = { CMD_TOK(CMD_IP), CMD_TOK(CMD_REST) }, .func = l2cmd_l2cmd, .params = { 2 }, .desc = "sends L2 command to selected L2" },
  { .toks = { CMD_TOK(CMD_RANGE), CMD_TOK(CMD_REST) }, .func = l2cmd_cmd, .params = { 1 }, .desc = "sends L2/L1 command to selected racks (and slots)" },
  { .toks = { CMD_TOK(CMD_REST) }, .func = l2cmd_cmd, .desc = "sends L2/L1 command to default destinations" },
};

/* 1 if smp is a live session; else 0 and an error in *results */
static int check_smp(SMP *smp, char **results)
{
  if (smp_is_valid(smp))
    return 1;
  response(results,120);
  sprintf(*results,"ERROR: this command must be run from an SMP (terminal) session (i.e. via l2term or telnet to the L2)\n");
  return 0;
}

/* the queue's timeouts, to the L2CMD's owner */
static void l2cmd_timeout(int to, void *data)
{
  L2CMD *c = data;

  if (c->tofunc != NULL)
    c->tofunc(c,to,c->data);
}

static void l2cmd_etimeout(char *msg, void *data)
{
  L2CMD *c = data;

  if (c->etofunc != NULL)
    c->etofunc(c,msg,c->data);
}

/* a command context for one owner (a console session, the command task):
 * its queues, its default destination, and its callbacks */
L2CMD *l2cmd_init(IRIdent *id, l2cmd_timeout_cb *tofunc, l2cmd_etimeout_cb *etofunc, l2cmd_response_cb *rspfunc, void *data)
{
  L2CMD *c;

  c = malloc(sizeof(L2CMD));
  memset(c,0,sizeof(L2CMD));
  c->id = id;
  c->q = reqrspq_init(tofunc != NULL ? l2cmd_timeout : NULL,etofunc != NULL ? l2cmd_etimeout : NULL,c);
  c->dest = dest_init();
  c->tofunc = tofunc;
  c->rspfunc = rspfunc;
  c->etofunc = etofunc;
  c->data = data;
  return c;
}

void l2cmd_free(L2CMD *c)
{
  reqrspq_free(c->q);
  dest_free(c->dest);
  free(c);
}

/* run a command line; its immediate output in *rptr (malloc()ed) */
int l2cmd_process(L2CMD *c, char *command, char **rptr, void *data)
{
  if (*command == '\0')
    return 0;
  *rptr = NULL;
  return CmdProcess(CMD_EXECUTE,command,rptr,l2cmd_cmds,L2CMD_FORMS,c);
}

/* a command's (later) output, to the owner */
int l2cmd_process_response(L2CMD *c, char *rsp, int rval)
{
  if (c->rspfunc == NULL)
    return -1;
  if (reqq_empty(c->q) && rspq_empty(c->q))
    c->busy &= ~1;
  c->rspfunc(c,c->data,rsp,rval);
  return 0;
}

/* await the response to request seqn to dest (timeout seconds, if given) */
int l2cmd_queue_response(L2CMD *c, unsigned int seqn, IRAddress dest, int timeout)
{
  rspq_put(c->q,seqn,dest);
  if (timeout != 0)
    rspq_timeout_set(c->q,timeout);
  c->busy |= 1;
  return 0;
}

/* "router|io|compute|other <command>": to every brick of that class */
static int l2cmd_broadcast(CmdData *cptr, char **results, L2CMD *c)
{
  static const struct { const char *word; int type; } classes[] = {
    { "router", BCAST_ROUTER }, { "io", BCAST_IO }, { "compute", BCAST_COMPUTE }, { "other", BCAST_OTHER },
  };
  DEST orig_dest;
  int status = -1;
  size_t i;

  if (c == NULL)
    return -1;
  response(results,320);
  memcpy(&orig_dest,c->dest,sizeof(DEST));
  dest_reset(c->dest);
  dest_l1(c->dest,NULL);
  for (i = 0; i < sizeof(classes) / sizeof(classes[0]); i++)
    if (strcmp(cptr->toks[0],classes[i].word) == 0)
      status = broadcast_l1(c,BCAST_PARALLEL,cptr->str_stack[0],1,0,classes[i].type,NULL,1);
  memcpy(c->dest,&orig_dest,sizeof(DEST));
  if (status != 0) {
    strcpy(*results,"ERROR: no destination set.\n");
    return -1;
  }
  return 0;
}

/* "autopower [on|off|abort|delay <seconds>]" */
static int l2cmd_autopower(CmdData *cptr, char **results)
{
  int delay;

  response(results,80);
  switch (cptr->params[0]) {
  case 1:
    nvramSet(NVRAM_AUTO_POWERUP,1);
    break;
  case 2:
    nvramSet(NVRAM_AUTO_POWERUP,0);
    break;
  case 3:
    power_abort = 1;
    strcpy(*results,"auto power up abortd\n");
    return 0;
  case 4:
    if (cptr->exp_stack[0] < 30) {
      strcpy(*results,"ERROR: minimum auto powerup delay is 30 seconds\n");
      return 0;
    }
    nvramSet(NVRAM_AUTOPOWER_DELAY,cptr->exp_stack[0]);
    break;
  }
  delay = nvramGet(NVRAM_AUTOPOWER_DELAY);
  if (delay <= 30)
    delay = 30;
  sprintf(*results,"auto powerup %s\nauto powerup delay %d seconds\n",
          nvramGet(NVRAM_AUTO_POWERUP) ? "enabled" : "disabled",delay);
  return 0;
}

/* "config ...": params[0] the form, [1] [2] L2CfgMPrint()'s */
static int l2cmd_config(CmdData *cptr, char **results, L2CMD *c)
{
  char *cstr;
  char *estr;
  int elapsed;
  int which;
  int p;

  switch (cptr->params[0]) {
  case 0:
    L2CfgMPrint(&L2CfgLocal,results,cptr->params[1],cptr->params[2]);
    break;
  case 1:       /* rescan */
    if (cfg_auto_rescan) {
      response(results,160);
      strcpy(*results,"WARNING: config auto-scan is enabled; skipping manual rescan\n");
      break;
    }
    for (p = 0; p < L2_L1_PORTS; p++)
      if (l2_l1_ports[p].fd != -1)
        cfg_ping_l1(p);
    cfg_l2ping(0);
    break;
  case 2:       /* auto */
    cfg_setup_configcheck(5);
    cfg_setup_l2ping(cfg_ping_l2_frequency);
    break;
  case 3:       /* manual */
    cfg_setup_configcheck(0);
    cfg_setup_l2ping(0);
    break;
  case 4:       /* print [all]: the configuration text */
    which = cptr->params[1] != 0;
    cstr = strdup(L2CfgMQuery(&L2CfgLocal,which,1));
    estr = strdup(L2CfgMQuery(&L2CfgLocal,which | 2,1));
    response(results,strlen(cstr) + strlen(estr) + 3);
    sprintf(*results,"%s\n%s\n",cstr,estr);
    free(cstr);
    free(estr);
    break;
  case 5:       /* list */
    L2CfgMPrintX(&L2CfgLocal,results);
    break;
  case 6:       /* times */
    *results = malloc(80);
    elapsed = time(NULL) - cfg_start_time;
    sprintf(*results,"uptime: %5d:%02d:%02d pid: %d\n",elapsed / 3600,elapsed % 3600 / 60,elapsed % 60,
            getpid());
    break;
  }
  return 0;
}

/* "connect <host>": to another L2 */
static int l2cmd_connect(CmdData *cptr, char **results)
{
  response(results,80);
  if (EnetServerConnect(cptr->str_stack[0],IR_PORT_BIAS + L2_PEER_PORT) != 0) {
    /* (the host cut short: the original's buffer held only 80 bytes) */
    snprintf(*results,80,"can\'t connect to %s, port %d\n",cptr->str_stack[0],IR_PORT_BIAS + L2_PEER_PORT);
    return -1;
  }
  snprintf(*results,80,"connection to %s initiated\n",cptr->str_stack[0]);
  return 0;
}

/* the date and time, as "date" shows it */
static void show_date(char *buff)
{
  time_t now = time(NULL);

  strftime(buff,32,"%m/%d/%Y %X %Z\n",localtime(&now));
}

/* "date ...": params[0] 0 show, 1 set, 2 show the timezone, 3 set it, 4
 * set both (1, 3 and 4 refused), 5 raw, 6 sync */
static int l2cmd_rtc(CmdData *cptr, char **results, L2CMD *c)
{
  char cmd[120];
  char buff[128];
  time_t now;
  char *tz;

  response(results,120);
  /* (the host's clock and timezone are the host's business: setting them
   * is refused, as the original did unless -pc) */
  if (cptr->params[0] == 1 || cptr->params[0] == 3 || cptr->params[0] == 4) {
    sprintf(*results,"INFO: cannot set date/timezone when running the L2 emulator on a PC\n");
    return 0;
  }
  switch (cptr->params[0]) {
  case 0:
    show_date(*results);
    break;
  case 2:
    tz = getenv("TZ");
    /* (the original strcpy()ed it into the 120 bytes) */
    snprintf(*results,120,"%s\n",tz != NULL ? tz : "<not set>");
    break;
  case 5:
    now = time(NULL);
    sprintf(*results,"%d\n",(int)now);
    break;
  case 6:       /* sync: the date command to every L1 and L2 */
    sprintf(buff,"date sync %lx",(unsigned long)(uintptr_t)c);
    nvramLogInsert(buff);
    if (c == NULL)
      return -1;
    now = time(NULL);
    tz = getenv("TZ");
    strftime(cmd,sizeof(cmd),"date %m%d%H%M%Y.%S ",localtime(&now));
    strncat(cmd,tz != NULL ? tz : "",sizeof(cmd) - strlen(cmd) - 1);
    if (dest_l1(c->dest,cptr) == 0) {
      sprintf(*results,"WARNING: no L1s found to sync\n");
      return -1;
    }
    if (broadcast_l1(c,BCAST_PARALLEL,cmd,1,0,BCAST_ALL,NULL,1) != 0) {
      strcpy(*results,"ERROR: no destination set.\n");
      return -1;
    }
    dest_l2(c->dest,cptr);
    if (broadcast_l2(c,results,cmd,1,0,1) != 0) {
      strcpy(*results,"ERROR: destination set.\n");
      return -1;
    }
    sprintf(*results,"WARNING: cannot sync timezone when running the L2 emulator on a PC\n");
    break;
  }
  return 0;
}

/* "demo ...": the L2 display's demo database (its task IR_L2_DEMO) */
static int l2cmd_demo(CmdData *cptr, char **results, L2CMD *c)
{
  IRArgument rarg[2];

  if (c == NULL)
    return -1;
  memset(rarg,0,sizeof(rarg));
  switch (cptr->params[0]) {
  case 0:       /* dump */
    target_pkt(c,LOCAL_L2_TASK(IR_L2_DEMO),9,0,NULL,1,0,1);
    break;
  case 1:       /* current <msgno> */
    rarg[0]._val = cptr->exp_stack[0];
    target_pkt(c,LOCAL_L2_TASK(IR_L2_DEMO),1,1,rarg,1,0,1);
    break;
  case 2:       /* <msgno> <text> */
    rarg[0]._val = cptr->exp_stack[0];
    rarg[1]._clas = IR_ARG_STRING;
    rarg[1]._val = IR_PTR_VAL(cptr->str_stack[0]);
    rarg[1]._size = strlen(cptr->str_stack[0]) + 1;
    target_pkt(c,LOCAL_L2_TASK(IR_L2_DEMO),3,2,rarg,1,0,1);
    break;
  }
  return 0;
}

/* "help [<command>]" (params[1]: with the hidden commands) */
static int l2cmd_help(CmdData *cptr, char **results)
{
  if (cptr->params[0] == 0) {
    response(results,0x14f0);
    CmdHelpAll(l2cmd_cmds,L2CMD_FORMS,cptr->params[1],*results);
    strcat(*results,
           "\nThe general form of a command is: <target> <command>\n\nA <target> (optional) has serveral forms:\n\n<rack>.<slot>        \n   targets a single L1\n<ip>:<port>:<l1>     \n   targets a single L1 without a rack and slot set\nrack|r <rng> [ slot|s <rng> ] \n   targets a group of racks and slots\npartition|p <rng>\n   targets a group of L1s in a partition\n\nA <rng> is a comma or dashed seperated list of numbers.  A <rng> of \"rack 2,4\"\ntargets racks 2 and 4.  A <rng> of \"rack 2-4\" targets racks 2, 3 and 4.\n\nA <rng> of \"*\" or \"all\" can be used to target all racks or slots.  An \"*\"\nor \"all\" alone targets all racks and slots depending on the command.\n\nIf no <target> is specfied and <command> is an L2 command it is executed on the\nlocal L2 only.  If the command is not understood by the L2, it is passed to all\nL1s in the default destination (the \"destination\" command shows the default \ndestinations).\n\nIf a <target> is specified and <command> is an L2 command it is executed on the\ntargeted L2s.  If the command is not understood by the L2, it is passed to all\nL1s in the target list.\n\nFor overlapping L2 and L1 commands, preceed the <command> with \"l1\" to over-\nride the L2 interpretation. \n");
  }
  else if (cptr->params[0] == 1) {
    CmdHelpCmd(l2cmd_cmds,L2CMD_FORMS,cptr->str_stack[0],cptr->params[1],results);
    if (*results == NULL) {
      response(results,160);
      sprintf(*results,"ERROR: memory allocation error.\n");
      return -1;
    }
  }
  return 0;
}

/* "l2dbg events timers": the time and every pending timer */
static void list_timers(char **results)
{
  struct timeval cur_time;
  EventTimerEntry *e;
  int count = 0;
  char *rptr;

  for (e = EventTimerQueue; e != NULL; e = e->next)
    count++;
  /* (the original's 4096 bytes held about 60 timers) */
  rptr = response(results,(count + 3) * 100);
  gettimeofday(&cur_time,NULL);
  rptr += sprintf(rptr,"%4d.%06d CURRENT TIME\n",(int)cur_time.tv_sec,(int)cur_time.tv_usec);
  rptr += sprintf(rptr,"L1 ping is %s\n",cfg_auto_rescan ? "on" : "off");
  for (e = EventTimerQueue; e != NULL; e = e->next)
    rptr += sprintf(rptr,"%4d.%06d %s\n",(int)e->timer_value.tv_sec,(int)e->timer_value.tv_usec,e->desc);
  sprintf(rptr,"Event timer errors: %d\n",EventTimerErrors);
}

/* "l2dbg events io": every descriptor being watched */
static void list_io(char **results)
{
  EventIOEntry *io;
  char *rptr;
  int fd;

  /* (the original's 4096 bytes held about 30 descriptors) */
  rptr = response(results,(EventIOListSize + 2) * 150);
  for (fd = 0; fd < EventIOListSize; fd++) {
    io = &EventIOList[fd];
    if (io->input_func == NULL && io->output_func == NULL)
      continue;
    rptr += sprintf(rptr,"%3d %s %s/%s\n",fd,
                    io->input_func != NULL && io->output_func != NULL ? "I/O"
                    : io->input_func == NULL ? "-/O" : "I/-",
                    io->input_desc[0] != '\0' ? io->input_desc : "-",
                    io->output_desc[0] != '\0' ? io->output_desc : "-");
  }
  /* (the timer error count, as the original) */
  sprintf(rptr,"Event I/O errors: %d\n",EventTimerErrors);
}

/* "l2dbg": every setting */
static void show_debug(char **results, int sbufsize, int rbufsize)
{
  char *rptr = response(results,700);

  rptr += sprintf(rptr,"irouter malloc debugging %d\n",IRouterDebugMallocFree);
  rptr += sprintf(rptr,"irouter packet debugging %d\n",irtr_debug);
  rptr += sprintf(rptr,"L2 configuration debugging %d\n",L2CfgDebug);
  rptr += sprintf(rptr,"SMP input debugging %d\n",smp_input_debug);
  rptr += sprintf(rptr,"console tracking debugging %d\n",smp_console_debug);
  rptr += sprintf(rptr,"broadcast debugging %d\n",broadcast_debug);
  rptr += sprintf(rptr,"discovery debugging %X\n",discover_debug);
  rptr += sprintf(rptr,"USB debugging %d\n",(int)nvramGet(NVRAM_L1USB_DEBUG));
  rptr += sprintf(rptr,"L2 load debugging %d\n",load_debug);
  rptr += sprintf(rptr,"L2 net conn flow ctrl     hwater %d  lwater %d\n",l2_flow_hwater,l2_flow_lwater);
  rptr += sprintf(rptr,"L1 input throttle %s (%d msec)\n",l1_throttle_timerid != 0 ? "enabled" : "disabled",
                  l1_throttle_freq);
  rptr += sprintf(rptr,"socket send bufsize %d, receive bufsize %d\n",sbufsize,rbufsize);
  rptr += sprintf(rptr,"broadcast response timeout %d\n",broadcast_response_timeout);
  rptr += sprintf(rptr,"target response timeout %d\n",target_response_timeout);
  if (l2_misc_debug != 0)
    sprintf(rptr,"L2 misc. debug flag 0x%08x\n",l2_misc_debug);
}

/* "l2dbg ...": params[0] the form (the table's order), -1 for the list */
static int l2cmd_l2dbg(CmdData *cptr, char **results)
{
  static const char s[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  static int socket_sbufsize;
  static int socket_rbufsize;
  unsigned int arg = cptr->exp_stack[0];
  char *rptr;
  unsigned int n;
  int rval;

  switch (cptr->params[0]) {
  case 0:       /* malloc */
    IRouterDebugMallocFree = arg;
    break;
  case 1:       /* packets [<n>|reset] */
    if (cptr->params[1] == 0)
      irtr_debug = arg;
    else
      sprintf(response(results,80),"packets: total %d, outstanding %d, maximum %d\n",IRouterTotalPackets,
              IRouterOutstandingPackets,IRouterMaxPackets);
    break;
  case 2:       /* config */
    L2CfgDebug = arg;
    break;
  case 3:       /* meminfo */
    rptr = MemUsageBuf();
    strcpy(response(results,strlen(rptr) + 1),rptr);
    break;
  case 4:       /* smp */
    smp_input_debug = arg;
    break;
  case 5:       /* broadcast */
    broadcast_debug = arg;
    break;
  case 6:       /* discovery */
    discover_debug = arg;
    break;
  case 7:       /* usb */
    l1usb_debug = arg;
    nvramSet(NVRAM_L1USB_DEBUG,l1usb_debug);
    sprintf(response(results,80),"storing USB debug setting %d in NVRAM\n",l1usb_debug);
    break;
  case 8:       /* estat [reset] */
    rptr = response(results,100);
    sprintf(rptr,"%s\n",EventStats(cptr->params[1]));
    break;
  case 9:       /* sbuf <send> <receive> */
    socket_sbufsize = cptr->exp_stack[0];
    socket_rbufsize = cptr->exp_stack[1];
    rval = RouterSetBufferSize(socket_sbufsize,socket_rbufsize);
    if (rval < 0)
      sprintf(response(results,100),"ERROR: can\'t set buffer size, %s\n",LoggerDefaultMessage(rval));
    break;
  case 10:      /* events io */
    list_io(results);
    break;
  case 11:      /* events timers */
    list_timers(results);
    break;
  case 12:      /* console */
    smp_console_debug = arg;
    break;
  case 19:      /* qstat */
    *results = RouterDumpQStats(NULL,NULL);
    break;
  case 20:      /* qstat reset */
    RouterResetQStats(NULL);
    break;
  case 21:      /* load <rate> */
    load_debug = arg;
    if (load_debug == 0) {
      if (load_timerid != 0) {
        EventRemoveTimeOut(load_timerid);
        load_timerid = 0;
      }
    }
    else if (load_timerid == 0)
      load_timer();
    break;
  case 22:      /* flow <high> <low> */
    l2_flow_hwater = cptr->exp_stack[0];
    l2_flow_lwater = cptr->exp_stack[1];
    l2_flow_setup(l2_flow_hwater,l2_flow_lwater);
    break;
  case 23:      /* throttle */
    l1_throttle_freq = arg;
    break;
  case 24:      /* brspto */
    broadcast_response_timeout = arg;
    nvramSet(NVRAM_BROADCAST_TIMEOUT,broadcast_response_timeout);
    break;
  case 25:      /* trspto */
    target_response_timeout = arg;
    nvramSet(NVRAM_TARGET_TIMEOUT,target_response_timeout);
    break;
  case 26:      /* misc */
    l2_misc_debug = arg;
    break;
  case 28:      /* smp response */
    smp_debug = arg;
    break;
  case 29:      /* str <length>: lines of random length, to test the consoles */
    rptr = response(results,arg + 80);
    for (n = 0; n < arg; n += 64) {
      strcpy(rptr,s);
      strcpy(rptr + rand() % 63,"\n");
      rptr += strlen(rptr);
    }
    break;
  case (unsigned int)-1:
    show_debug(results,socket_sbufsize,socket_rbufsize);
    break;
  }
  return 0;
}

/* "l2dbg load": a busy L2, load_debug times a second */
static void load_timer(void)
{
  usleep(100);
  load_timerid = EventAddTimeOut(0,(unsigned long)(1000000 / (long long)load_debug),load_timer,NULL,
                                 "simulated L2 loading");
}

/* "destination": show it; "<target> destination": set it; "destination
 * reset" */
static int l2cmd_destination(CmdData *cptr, char **results, L2CMD *c)
{
  char sel[2048];
  int port;
  char *rptr;
  int slot;
  int rack;
  int addr;
  int l1;
  int ip;

  if (c == NULL)
    return -1;
  switch (cptr->params[0]) {
  case 0:
    dest_l1(c->dest,NULL);
    dest_print(c->dest,sel);
    /* (the original allowed 40 bytes a brick, and that for the selection
     * too, which can be far longer) */
    rptr = response(results,strlen(sel) + 2 + c->dest->count * 100);
    rptr += sprintf(rptr,"%s\n",sel);
    for (addr = 0; addr < c->dest->count; addr++) {
      rack = IR_ADDR_RACK(c->dest->list[addr]);
      slot = IR_ADDR_SLOT(c->dest->list[addr]);
      if (L2CfgMFindBrickIP(&L2CfgLocal,rack,slot,&ip,&port,&l1) == -1)
        rptr += sprintf(rptr,"invalid destination\n");
      else
        rptr += sprintf(rptr,"%s (%s:%d:%d)\n",format_address(c->dest->list[addr]),SocketAddrStr(ip),port,l1);
    }
    break;
  case 1:
    response(results,160);
    if (dest_l1(c->dest,cptr) == 0) {
      sprintf(*results,"ERROR: no L1s found to match that destination\n");
      break;
    }
    dest_default(c->dest,cptr);
    dest_l1(c->dest,NULL);
    sprintf(*results,"%d default destination(s) set\n",c->dest->count);
    break;
  case 2:
    dest_reset(c->dest);
    response(results,160);
    sprintf(*results,"default destination reset to all bricks and slots\n");
    break;
  }
  return 0;
}

/* "[<target>] env summary": each brick's environmental state, from its
 * last report (L2CfgL1.env_state) */
static int l2cmd_env(CmdData *cptr, char **results, L2CMD *c)
{
  static const struct { unsigned int bit; const char *text; } conditions[] = {
    { 0x8, "auto powered down" }, { 0x10, "power warning" }, { 0x20, "power fault" },
    { 0x40, "temperature advisory" }, { 0x80, "temperature critical" }, { 0x100, "temperature fault" },
    { 0x200, "fan warning" }, { 0x400, "fan fault" }, { 0x800, "VRM fault" }, { 0x1000, "48V fault" },
    { 0x40000000, "test condition" }, { 0x80000000, "other condition" },
  };
  L2CfgL1 *l1cfg;
  IRAddress l1addr;
  unsigned int state;
  int l1_count = 0;
  int msg_count;
  char *rptr;
  size_t i;
  int addr;

  if (c == NULL)
    return -1;
  if (cptr->params[0] == 0)
    cptr = NULL;                /* the default destination */
  if (dest_l1(c->dest,cptr) == 0) {
    response(results,160);
    sprintf(*results,"ERROR: no L1s found to match that destination\n");
    return -1;
  }
  /* (the original allowed 160 bytes a brick, short of all its conditions) */
  rptr = response(results,c->dest->count * 320 + 64);
  for (addr = 0; addr < c->dest->count; addr++) {
    l1addr = c->dest->list[addr];
    l1cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(l1addr),IR_ADDR_SLOT(l1addr),0);
    if (l1cfg == NULL)
      continue;
    state = l1cfg->env_state;
    if (state == 1)             /* all is well */
      continue;
    l1_count++;
    if (state == 0) {
      rptr += sprintf(rptr,"%s: environmental summary not supported\n",L2CfgMAddrStr(&L2CfgLocal,l1addr,0));
      continue;
    }
    rptr += sprintf(rptr,"%s:",L2CfgMAddrStr(&L2CfgLocal,l1addr,0));
    if (state & 2) {
      rptr += sprintf(rptr,state & 4 ? " monitoring disabled on error\n" : " monitoring disabled\n");
      continue;
    }
    msg_count = 0;
    for (i = 0; i < sizeof(conditions) / sizeof(conditions[0]); i++)
      if (state & conditions[i].bit)
        rptr += sprintf(rptr,"%s %s",msg_count++ != 0 ? "," : "",conditions[i].text);
    rptr += sprintf(rptr,"\n");
  }
  if (l1_count == 0)
    sprintf(rptr,"all environmental condition appear normal\n");
  return 0;
}

/* "[<target>] l1": the session into L1 mode (with the default destination,
 * which must be one brick) */
static int l2cmd_l1(CmdData *cptr, char **results, L2CMD *c)
{
  IRAddress l1addr;
  int count;

  if (c == NULL)
    return -1;
  if (!check_smp(c->data,results))
    return 0;
  response(results,160);
  count = dest_l1(c->dest,cptr->params[0] == 0 ? NULL : cptr);
  if (cptr->params[0] == 1 && count == 0) {
    sprintf(*results,"ERROR: no L1s found to match that destination\n");
    return -1;
  }
  if (count != 1) {
    sprintf(*results,cptr->params[0] == 0 ? "ERROR: default destination contains multiple L1 addresses\n"
                                          : "ERROR: current destination contains multiple L1 addresses\n");
    return -1;
  }
  l1addr = c->dest->list[0];
  smp_set_l1addr(c->data,l1addr);
  smp_set_mode(c->data,SMP_MODE_L1);
  sprintf(*results,"entering L1 mode %s, <CTRL-T> to escape to L2\n",format_address(l1addr));
  return 0;
}

/* "l2": the session back to L2 mode ("<target> l2" is not supported) */
static int l2cmd_l2(CmdData *cptr, char **results, L2CMD *c)
{
  if (c == NULL)
    return -1;
  if (!check_smp(c->data,results))
    return 0;
  response(results,160);
  if (cptr->params[0] == 1) {
    strcpy(*results,"INFO: remote L2 mode not yet supported.\n");
    return -1;
  }
  smp_set_mode(c->data,SMP_MODE_L2);
  strcpy(*results,"L2 command processor engaged, <CTRL-D> for console mode.\n");
  return 0;
}

/* "<brick> loopback [<session>] <size> <count>" (lpbk.c) */
static int l2cmd_loopback(CmdData *cptr, char **results, L2CMD *c)
{
  SMP *smp;
  int count;

  response(results,160);
  if (c == NULL)
    return -1;
  if (!check_smp(c->data,results))
    return 0;
  count = dest_l1(c->dest,cptr);
  if (count == 0) {
    sprintf(*results,"ERROR: no L1s found to match that destination\n");
    return -1;
  }
  if (count != 1 && cptr->params[0] != 2) {
    sprintf(*results,"ERROR: default destination contains multiple L1 addresses\n");
    return -1;
  }
  switch (cptr->params[0]) {
  case 1:
    lpbk(cptr->exp_stack[0],c->dest->list[0],cptr->exp_stack[1],cptr->exp_stack[2],c->data);
    break;
  case 2:       /* (no form has it: the session's system console) */
    smp = c->data;
    lpbk(smp->grp->partition,smp_get_conaddr(smp,NULL,NULL),cptr->exp_stack[0],cptr->exp_stack[1],smp);
    break;
  default:
    lpbk(0,c->dest->list[0],cptr->exp_stack[0],cptr->exp_stack[1],c->data);
  }
  return 0;
}

/* "<brick> route" (route.c) */
static int l2cmd_route(CmdData *cptr, char **results, L2CMD *c)
{
  int count;

  response(results,160);
  if (c == NULL)
    return -1;
  if (!check_smp(c->data,results))
    return 0;
  count = dest_l1(c->dest,cptr);
  if (count == 0) {
    sprintf(*results,"ERROR: no L1s found to match that destination\n");
    return -1;
  }
  if (count != 1) {
    sprintf(*results,"ERROR: default destination contains multiple L1 addresses\n");
    return -1;
  }
  route_process_request(c->dest->list[0],c->data);
  return 0;
}

/* "<brick> hreboot_l1": the L1's reboot request (to its request task) */
static int l2cmd_hreboot_l1(CmdData *cptr, char **results, L2CMD *c)
{
  IRArgument argv[1];
  IRAddress addr;
  IRPacket *p;
  int count;

  response(results,160);
  if (c == NULL)
    return -1;
  count = dest_l1(c->dest,cptr);
  if (count == 0) {
    sprintf(*results,"ERROR: no L1s found to match that destination\n");
    return -1;
  }
  if (count != 1) {
    sprintf(*results,"ERROR: default destination contains multiple L1 addresses\n");
    return -1;
  }
  addr = IR_ADDR_WITH_TASK(c->dest->list[0],IR_L1_REQ);
  memset(argv,0,sizeof(argv));
  argv[0]._val = L1REQ_REBOOT;
  p = IRouterMakePacket(c->id,&addr,0,0,IR_REQ,2,1,argv);
  IRouterSendPacket(NULL,p);
  return 0;
}

/* "nvram reset" */
static int l2cmd_nvram(CmdData *cptr, char **results)
{
  response(results,160);
  nvramReset();
  strcpy(*results,"nvram contents cleared, reboot required (some NVRAM values are cached)");
  return 0;
}

/* a command for an L1's command task, queued without a response marker */
static IRPacket *l1_command(L2CMD *c, int rack, int slot, const char *cmd)
{
  IRAddress addr = IR_ADDR_MAKE(IR_ADDR_L1,rack,slot & 0x3f,0,IR_L1_CMD);
  IRArgument argv[2];
  char *copy = strdup(cmd);

  memset(argv,0,sizeof(argv));
  argv[1]._clas = IR_ARG_STRING | IR_ARG_FREE;
  argv[1]._val = IR_PTR_VAL(copy);
  argv[1]._size = strlen(copy) + 1;
  return IRouterMakePacket(c->id,&addr,0,0,IR_REQ,2,2,argv);
}

static int is_router(int type)
{
  return type == 'R' || type == 'D' || type == '-';
}

/* "power up", fast (the default): routers first, in two groups of slots,
 * then the I/O bricks, then the rest, each group delay ms after the last;
 * then reset. For a partition, every router that is off. */
static int power_up_fast(L2CMD *c, CmdData *cptr, char **results, int delay)
{
  static const uint8 slist[25] = { 1, 2, 5, 6, 9, 10, 13, 14, 17, 18, 21, 22, 25, 26, 29, 30, 33, 34, 37, 38,
                                   41, 42, 45, 46, 49 };
  const char *pwrcmd = "power up hold";
  int partition = c->dest->type == 2;
  DEST orig_dest;
  int slots[50];
  int flags = 0;
  int slot;
  int i;

  if (partition) {
    /* routers are in no partition: all of them, if off */
    flags = BCAST_POWER_OFF;
    memcpy(&orig_dest,c->dest,sizeof(DEST));
    dest_reset(c->dest);
    dest_l1(c->dest,NULL);
    pwrcmd = "power up";
  }
  for (i = 0; i < 2; i++) {
    for (slot = 0; slot < 25; slot++)
      slots[slot] = slist[slot] + i * 2;
    slots[slot] = -1;
    if (broadcast_l1(c,BCAST_PARALLEL,(char *)pwrcmd,1,0,flags | BCAST_ROUTER,slots,0) != 0) {
      strcpy(*results,"ERROR: no destination set.\n");
      return -1;
    }
  }
  if (partition) {
    memcpy(c->dest,&orig_dest,sizeof(DEST));
    dest_l1(c->dest,cptr->params[0] == 0 ? NULL : cptr);
  }
  return 0;
}

/* "power up", slow (NVRAM): routers one at a time; for a partition, each
 * L2's routers that are off (the first L1 of each port) */
static int power_up_slow(L2CMD *c, char **results, int delay)
{
  L2CfgPort *port;
  L2Cfg *node;
  int p;

  if (c->dest->type != 2) {
    if (broadcast_l1(c,BCAST_SERIAL,"power up hold",1,0,BCAST_ROUTER,NULL,0) != 0) {
      strcpy(*results,"ERROR: no destination set.\n");
      return -1;
    }
    return 0;
  }
  for (node = &L2CfgLocal; node != NULL; node = (L2Cfg *)node->net.next) {
    for (p = 0; p < L2CFG_PORTS; p++) {
      port = &node->port_list[p];
      if (port->state != L2CFG_PORT_CONFIGURED || !port->l1cfg->configured ||
          !is_router(port->l1cfg->type) || port->l1cfg->power_state != 0)
        continue;
      reqq_put(c->q,l1_command(c,port->l1cfg->rack,port->l1cfg->slot,"power up"),1,0);
      reqq_put(c->q,NULL,0,-1);
      reqq_put(c->q,NULL,0,delay);
    }
  }
  return 0;
}

/* "power down" of a partition: the routers too, if every brick outside
 * the destination is off */
static void power_down_routers(L2CMD *c)
{
  L2CfgL1 *l1c;
  L2Cfg *node;
  int others = 0;
  int others_off = 0;
  int found;
  int port;
  int l1;
  int i;

  for (node = &L2CfgLocal; node != NULL; node = (L2Cfg *)node->net.next) {
    for (port = 0; port < L2CFG_PORTS; port++) {
      if (node->port_list[port].state != L2CFG_PORT_CONFIGURED)
        continue;
      for (l1 = 0; l1 < node->port_list[port].l1count; l1++) {
        l1c = &node->port_list[port].l1cfg[l1];
        if (!l1c->configured || is_router(l1c->type))
          continue;
        for (found = 0, i = 0; !found && i < c->dest->count; i++)
          found = IR_ADDR_RACK(c->dest->list[i]) == l1c->rack && IR_ADDR_SLOT(c->dest->list[i]) == l1c->slot;
        if (!found) {
          others++;
          if (l1c->power_state == 0)
            others_off++;
        }
      }
    }
  }
  if (others_off != others)
    return;
  for (node = &L2CfgLocal; node != NULL; node = (L2Cfg *)node->net.next) {
    for (port = 0; port < L2CFG_PORTS; port++) {
      if (node->port_list[port].state != L2CFG_PORT_CONFIGURED)
        continue;
      for (l1 = 0; l1 < node->port_list[port].l1count; l1++) {
        l1c = &node->port_list[port].l1cfg[l1];
        if (l1c->configured && is_router(l1c->type) && l1c->power_state != 0)
          reqq_put(c->q,l1_command(c,l1c->rack,l1c->slot,"power down"),1,0);
      }
    }
  }
}

/* "power summary": how many bricks are on and off, and their margins */
static void power_summary(L2CMD *c, char *rptr)
{
  int m[6] = { 0 };             /* default, low, normal, high, custom, other */
  int on = 0, off = 0, other = 0;
  L2CfgL1 *l1cfg;
  int i;

  for (i = 0; i < c->dest->count; i++) {
    l1cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(c->dest->list[i]),IR_ADDR_SLOT(c->dest->list[i]),0);
    if (l1cfg == NULL)
      continue;
    /* (ORIGINAL BUG, kept: power_state is a uint8, so the original's "other"
     * case of -1 never matches) */
    if (l1cfg->power_state == 0)
      off++;
    else if (l1cfg->power_state == 1)
      on++;
    if (l1cfg->margin_state <= 5)
      m[l1cfg->margin_state]++;
  }
  if (other + off == 0)
    rptr += sprintf(rptr,"all %d bricks appear powered on\n",c->dest->count);
  else if (other + on == 0)
    rptr += sprintf(rptr,"all %d bricks appear powered off\n",c->dest->count);
  else
    rptr += sprintf(rptr,"power: %d on, %d off, %d other\n",on,off,other);
  if (m[0] + m[2] + m[3] + m[4] + m[5] == 0)
    sprintf(rptr,"all %d bricks appear margined low\n",c->dest->count);
  else if (m[0] + m[1] + m[3] + m[4] + m[5] == 0)
    sprintf(rptr,"all %d bricks appear margined normal\n",c->dest->count);
  else if (m[0] + m[1] + m[2] + m[4] + m[5] == 0)
    sprintf(rptr,"all %d bricks appear margined high\n",c->dest->count);
  else
    sprintf(rptr,"margin: %d default, %d low, %d normal, %d high, %d custom, %d other\n",m[0],m[1],m[2],m[3],
            m[4],m[5]);
}

/* "[<target>] power ...": params[0] whether a target is given, [1] 0
 * status, 1 up, 2 down, 3 summary, 4 delay, 5 set delay, 6 mode, 7 set
 * mode */
int l2cmd_power(CmdData *cptr, char **results, L2CMD *c)
{
  static int delay = 500;       /* ms between groups */
  DEST orig_dest;
  int slots[50];
  int slow;
  int slot;

  if (c == NULL)
    return -1;
  response(results,320);
  if (dest_l1(c->dest,cptr->params[0] == 0 ? NULL : cptr) == 0) {
    sprintf(*results,"ERROR: no L1s found to match that destination\n");
    return -1;
  }
  switch (cptr->params[1]) {
  case 0:
    if (broadcast_l1(c,BCAST_PARALLEL,"power check",1,0,BCAST_ALL,NULL,1) != 0) {
      strcpy(*results,"ERROR: no destination set.\n");
      return -1;
    }
    break;
  case 1:
    if (dest_pcheck(c->dest,cptr,*results) != 0)
      return -1;
    /* (into *results: the version check's own output replaces this
     * command's, as the original) */
    memcpy(&orig_dest,c->dest,sizeof(DEST));
    l2cmd_process(c,"ver check",results,NULL);
    memcpy(c->dest,&orig_dest,sizeof(DEST));
    slow = nvramGet(NVRAM_SLOW_PWRUP) != 0;
    if ((slow ? power_up_slow(c,results,delay) : power_up_fast(c,cptr,results,delay)) != 0)
      return -1;
    /* then I/O, and the rest, slot by slot */
    for (slot = 1; slot <= 40; slot++) {
      slots[slot - 1] = slot;
      slots[slot] = -1;
    }
    if (broadcast_l1(c,BCAST_PARALLEL,"power up hold",1,delay,BCAST_IO,slots,0) != 0 ||
        broadcast_l1(c,BCAST_PARALLEL,"power up hold",1,delay * 2,BCAST_COMPUTE | BCAST_OTHER,slots,0) != 0 ||
        broadcast_l1(c,BCAST_PARALLEL,"reset",1,0,BCAST_ALL,NULL,1) != 0) {
      strcpy(*results,"ERROR: no destination set.\n");
      return -1;
    }
    break;
  case 2:
    if (dest_pcheck(c->dest,cptr,*results) != 0)
      return -1;
    if (c->dest->type == 2)
      power_down_routers(c);
    if (broadcast_l1(c,BCAST_PARALLEL,"power down",1,0,BCAST_ALL,NULL,1) != 0) {
      strcpy(*results,"ERROR: no destination set.\n");
      return -1;
    }
    break;
  case 3:
    power_summary(c,*results);
    break;
  case 4:
    sprintf(*results,"delay is set to %d milliseconds\n",delay);
    break;
  case 5:
    delay = cptr->exp_stack[0];
    break;
  case 6:
    slow = nvramGet(NVRAM_SLOW_PWRUP) != 0;
    sprintf(*results,"power up mode is %s (power up RTRs in %s)\n",slow ? "slow" : "fast",
            slow ? "series" : "parallel");
    break;
  case 7:
    nvramSet(NVRAM_SLOW_PWRUP,*cptr->toks[2] == 's');
    break;
  }
  return 0;
}

/* "[<target>] reset": every brick, after a version check */
static int l2cmd_reset(CmdData *cptr, char **results, L2CMD *c)
{
  DEST orig_dest;

  if (c == NULL)
    return -1;
  response(results,320);
  if (dest_l1(c->dest,cptr->params[0] == 0 ? NULL : cptr) == 0) {
    sprintf(*results,"ERROR: no L1s found to match that destination\n");
    return -1;
  }
  if (dest_pcheck(c->dest,cptr,*results) != 0)
    return -1;
  memcpy(&orig_dest,c->dest,sizeof(DEST));
  l2cmd_process(c,"ver check",results,NULL);
  memcpy(c->dest,&orig_dest,sizeof(DEST));
  if (broadcast_l1(c,BCAST_PARALLEL,"reset",1,0,BCAST_ALL,NULL,1) != 0) {
    strcpy(*results,"ERROR: no destination set.\n");
    return -1;
  }
  return 0;
}

/* "rackid [<rack>]" */
static int l2cmd_rackid(CmdData *cptr, char **results)
{
  response(results,320);
  if (cptr->params[0] == 0)
    sprintf(*results,"rack ID is %d\n",L2CfgLocal.rack);
  else if (cptr->params[0] == 1) {
    nvramSet(NVRAM_RACK,cptr->exp_stack[0]);
    L2CfgMEventRack(&L2CfgLocal);
    sprintf(*results,"rack ID set to %d\n",L2CfgLocal.rack);
  }
  return 0;
}

/* make room to append n bytes to a command's output (as cmd.c does);
 * returns where to append */
static char *rsp_room(cmd_response *r, size_t n)
{
  r->slen += strlen(r->eptr != NULL ? r->eptr : "");
  if ((size_t)r->size <= r->slen + n + 0x10) {
    r->size += n + 0x200;
    r->sptr = realloc(r->sptr,r->size);
  }
  r->eptr = r->sptr + r->slen;
  return r->eptr;
}

/* a response's text argument (arg 1), its last newline dropped */
static char *rsp_text(IRPacket *rsp)
{
  char *text = IR_ARG_TYPE(rsp->_argv[1]) == IR_ARG_VALUE ? (char *)IR_VAL_PTR(rsp->_argv[1]._val)
                                                          : (char *)IRArg(rsp,1);
  size_t len = strlen(text);

  /* (the original looked before an empty text) */
  if (len > 0 && text[len - 1] == '\n')
    text[len - 1] = '\0';
  return text;
}

/* append " <word>" to a growing string */
static void append_word(char **s, const char *word)
{
  size_t len = *s != NULL ? strlen(*s) : 0;

  *s = realloc(*s,len + strlen(word) + 2);
  sprintf(*s + len,"%s ",word);
}

/*
 * The responses for "pbay": first (stage 0) each L1's "pbay serial", the
 * serial number of the PowerBay it is on, collected by PowerBay; with a
 * command, then (stage 1) "pbay <command>" to one L1 of each PowerBay, its
 * output under the PowerBay. Errors are listed first.
 */
int pbay_rsp(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data)
{
  pbay_data *pd = data;
  char emsg[100] = "";
  char cmd[100];
  char *rptr;
  char *text;
  size_t n;
  int i;

  if (pd->snlist == NULL) {
    /* (room for every brick, all on different PowerBays) */
    pd->snlist = calloc(pktsleft + 1,sizeof(*pd->snlist));
    pd->snconns = calloc(pktsleft + 1,sizeof(*pd->snconns));
    pd->snnum = calloc(pktsleft + 1,sizeof(*pd->snnum));
    pd->snaddr = calloc(pktsleft + 1,sizeof(*pd->snaddr));
  }
  /* (messages from the L1 cut to emsg: the original sprintf()ed them) */
  if (rsp == NULL)
    snprintf(emsg,sizeof(emsg),"ERROR: no response from %s\n",format_address(*dest));
  else if (rsp->_err != 0)
    snprintf(emsg,sizeof(emsg),"ERROR: couldn\'t send packet to %s, %s\n",format_address(*dest),
             IRFmtError(rsp->_err));
  else if (pd->stage == 0) {
    if ((IR_ARG_TYPE(rsp->_argv[0]) == IR_ARG_VALUE ? rsp->_argv[0]._val : IRArg(rsp,0)) != 0)
      snprintf(emsg,sizeof(emsg),"%s:  %s\n",format_address(*dest),rsp_text(rsp));
    else if (rsp->_argc < 2)
      snprintf(emsg,sizeof(emsg),"%s:  Pbay busy initializing or PBay communication failure\n",
               format_address(*dest));
    else {
      text = rsp_text(rsp);
      for (i = 0; i < pd->sncnt && strcmp(pd->snlist[i],text) != 0; i++)
        ;
      if (i == pd->sncnt) {
        pd->snlist[i] = strdup(text);
        pd->snaddr[i] = *dest;
        pd->sncnt++;
      }
      pd->snnum[i]++;
      /* (the original's 100 bytes held 14 bricks) */
      append_word(&pd->snconns[i],format_address(*dest));
    }
  }
  if (pd->stage == 0) {
    if (emsg[0] != '\0') {
      if (pd->errcnt == 0)
        sprintf(rsp_room(cmd_rsp,100),"WARNING: ERRORS while reading PowerBay serial numbers from L1 Controllers:\n");
      pd->errcnt++;
      rptr = rsp_room(cmd_rsp,strlen(emsg) + 4);
      strcat(rptr,"    ");
      strcat(rptr,emsg);
    }
  }
  else {
    for (i = 0; i < pd->sncnt && pd->snaddr[i] != *dest; i++)
      ;
    sprintf(rsp_room(cmd_rsp,50),"%s:   [PowerBay %s]\n",format_address(*dest),
            i == pd->sncnt ? "?????????????" : pd->snlist[i]);
    if (emsg[0] == '\0')
      cmd_process_packet_args(rsp,c,dest,cmd_rsp,0);
    else
      strcat(rsp_room(cmd_rsp,strlen(emsg)),emsg);
  }
  if (pktsleft != 0)
    return 0;

  /* all are in */
  for (n = 0, i = 0; i < pd->sncnt; i++)
    n += strlen(pd->snlist[i]) + (pd->snconns[i] != NULL ? strlen(pd->snconns[i]) : 0) + 16;
  rptr = rsp_room(cmd_rsp,n + pd->sncnt * 80);
  cmd_rsp->status = pd->errcnt == 0 && cmd_rsp->status != -1 ? 0 : -1;
  if (pd->stage == 0 && pd->errcnt != 0)
    rptr += sprintf(rptr,"\n");
  if (pd->cmd == NULL) {
    for (i = 0; i < pd->sncnt; i++)
      rptr += sprintf(rptr,"PowerBay %s: %s\n",pd->snlist[i],pd->snconns[i] != NULL ? pd->snconns[i] : "");
  }
  else if (pd->stage == 0 && pd->sncnt > 0) {
    /* the command, to the first L1 found on each PowerBay */
    snprintf(cmd,sizeof(cmd),"pbay %s",pd->cmd);
    dest_reset(c->dest);
    memcpy(c->dest->list,pd->snaddr,pd->sncnt * sizeof(pd->snaddr[0]));
    c->dest->count = pd->sncnt;
    c->dest->type = 1;
    pd->stage = 1;
    reqrspq_reset(c->q);
    broadcast_l1(c,BCAST_PARALLEL,cmd,1,0,BCAST_ALL,NULL,1);
    if (c->q->rspq_pending > 0)
      return 0;
    strcat(rsp_room(cmd_rsp,80),"ERROR: pbay command not sent to any L1\'s due to previous errors!\n");
    cmd_rsp->status = -1;
  }
  pd->orig_c->busy &= ~2;
  l2cmd_process_response(pd->orig_c,cmd_rsp->sptr,cmd_rsp->status);
  for (i = 0; i < pd->sncnt; i++) {
    free(pd->snlist[i]);
    free(pd->snconns[i]);
  }
  free(pd->snlist);
  free(pd->snconns);
  free(pd->snnum);
  free(pd->snaddr);
  free(pd->cmd);
  free(pd);
  return 0;
}

/* "[<target>] pbay cfg" or "[<target>] pbay <command>" (pbay_rsp()) */
static int l2cmd_pbay(CmdData *cptr, char **results, L2CMD *c)
{
  pbay_data *pd;
  L2CMD *tc;

  response(results,320);
  if (c == NULL)
    return -1;
  pd = calloc(1,sizeof(pbay_data));
  if (pd == NULL) {
    strcpy(*results,"ERROR: could not allocate memory to store internal command data\n");
    return -1;
  }
  pd->orig_c = c;
  if (cptr->str_max != 0)
    pd->cmd = strdup(cptr->str_stack[0]);
  if (dest_l1(c->dest,cptr->params[0] == 0 ? NULL : cptr) == 0) {
    strcpy(*results,"WARNING: ERRORS occurred while executing the pbay command:\n");
    strcat(*results,"    WARNING: no L1s found to match that destination\n");
    free(pd->cmd);              /* (the original leaked it) */
    free(pd);
    return -1;
  }
  tc = cmd_setup_usr_response(pbay_rsp,pd);
  if (tc == NULL) {
    strcpy(*results,"ERROR: user command processor is busy\n");
    free(pd->cmd);
    free(pd);
    return -1;
  }
  memcpy(tc->dest,c->dest,sizeof(DEST));
  c->busy |= 2;
  if (dest_l1(tc->dest,cptr) == 0) {
    strcat(*results,"WARNING: no L1s found to match that destination\n");
    free(pd->cmd);
    free(pd);
    return -1;
  }
  if (broadcast_l1(tc,BCAST_PARALLEL,"pbay serial",1,0,BCAST_ALL,NULL,1) != 0) {
    response(results,160);
    strcpy(*results,"ERROR: no (L1) destination set.\n");
    free(pd->cmd);
    free(pd);
    return -1;
  }
  return 0;
}

void quit(void)
{
  smp_reset();
  exit(0);
}

/* "quit": l2 exits */
static int l2cmd_quit(CmdData *cptr, char **results, L2CMD *c)
{
  smp_reset();
  exit(2);
}

/* "ping [min|max|l2|sender|l1|throttle <n>|reset]": the L2 and L1 pings */
static int l2cmd_ping(CmdData *cptr, char **results)
{
  unsigned int arg = cptr->exp_stack[0];

  switch (cptr->params[0]) {
  case 1:
    cfg_ping_response_minimum = arg;
    nvramSet(NVRAM_PING_MIN,cfg_ping_response_minimum);
    break;
  case 2:
    cfg_ping_response_maximum = arg;
    nvramSet(NVRAM_PING_MAX,cfg_ping_response_maximum);
    break;
  case 3:
    cfg_ping_l2_frequency = arg;
    nvramSet(NVRAM_PING_L2FREQ,cfg_ping_l2_frequency);
    break;
  case 4:
    cfg_ping_sender_valid = arg == 0 ? 2 : 1;   /* (NVRAM's 0 is unset) */
    nvramSet(NVRAM_PING_SENDER,cfg_ping_sender_valid);
    break;
  case 5:
    cfg_ping_l1_frequency = arg;
    nvramSet(NVRAM_PING_L1FREQ,cfg_ping_l1_frequency);
    break;
  case 6:
    cfg_throttle_frequency = arg;
    break;
  case 7:
    cfg_ping_reset();
    break;
  }
  response(results,160);
  sprintf(*results,"L2<->L2 freq: %d, min: %d, max: %d\nping from sender valid: %s; L2<->L1 freq: %d\ncfg throttle %d\n",
          cfg_ping_l2_frequency,cfg_ping_response_minimum,cfg_ping_response_maximum,
          cfg_ping_sender_valid == 1 ? "yes" : "no",cfg_ping_l1_frequency,cfg_throttle_frequency);
  return 0;
}

/* "l2dsp debug [<flags>]|enable|disable": the L2 display */
static int l2cmd_l2dsp(CmdData *cptr, char **results)
{
  switch (cptr->params[0]) {
  case 0:
    l2dsp_debug_state = cptr->exp_stack[0];
    /* fall through */
  case 1:
    response(results,160);
    sprintf(*results,"L2 display debug flags set to \'0x%08x\'",l2dsp_debug_state);
    break;
  case 2:
  case 3:
    nvramSet(NVRAM_L2DSP_DISABLED,cptr->params[0] == 3);
    L2CfgMEventDisplayDisable(&L2CfgLocal);
    /* fall through */
  case 4:
    response(results,160);
    sprintf(*results,"L2 display input %s\n",nvramGet(NVRAM_L2DSP_DISABLED) ? "disabled" : "enabled");
    break;
  }
  return 0;
}

/* one line of "l2find" */
static int format_l2find_entry(char *rptr, sn1SC_L2 *l2)
{
  sprintf(rptr,"%15s %-8s %-16.16s  %03d %-12.12s",SocketAddrStr(l2->ip_addr),l2->ssn,l2->sysname,
          l2->rack,l2->version);
  if (L2CfgMFindNode(&L2CfgLocal,l2->ip_addr,0,NULL) != NULL)
    strcat(rptr,"  (CONNECTED)");
  strcat(rptr,"\n");
  return 0;
}

/* one section of "l2find": the L2s for which which() holds, under title
 * (and the banner before the first section) */
static char *l2find_section(char *rptr, sn1SC_L2 *l2_list, int l2_cnt, const char *myssn,
                            int (*which)(sn1SC_L2 *, const char *), const char *title, const char **banner)
{
  int first = 1;
  int i;

  for (i = 0; i < l2_cnt; i++) {
    if (!which(&l2_list[i],myssn))
      continue;
    if (*banner != NULL) {
      rptr += sprintf(rptr,"%s",*banner);
      *banner = NULL;
    }
    if (first) {
      first = 0;
      rptr += sprintf(rptr,"%s",title);
    }
    format_l2find_entry(rptr,&l2_list[i]);
    rptr += strlen(rptr);
  }
  return rptr;
}

static int same_ssn(sn1SC_L2 *l2, const char *myssn)
{
  return myssn != NULL && *myssn != '\0' && strcmp(myssn,l2->ssn) == 0;
}

static int no_ssn(sn1SC_L2 *l2, const char *myssn)
{
  return l2->ssn[0] == '\0';
}

static int other_ssn(sn1SC_L2 *l2, const char *myssn)
{
  return l2->ssn[0] != '\0' && myssn != NULL && strcmp(myssn,l2->ssn) != 0;
}

/* "l2find": discover the L2s on the network, by system serial number */
static int l2cmd_l2find(CmdData *cptr, char **results)
{
  const char *banner =
      "IP              SSN      NAME             RACK FIRMWARE\n"
      "--------------- -------- ---------------- ---- ------------\n";
  sn1SC_L2 *l2_list;
  const char *myssn;
  int l2_cnt = 0;
  char *rptr;

  if (sn1SCDiscoverL2(NULL,NULL,&l2_list,&l2_cnt,1) < 0) {
    response(results,160);
    strcpy(*results,"error discovering L2\'s!\n");
    return -1;
  }
  /* (the original allowed 80 bytes an L2 and 200 for the rest, short of
   * three sections' titles and long serial numbers) */
  rptr = response(results,l2_cnt * 120 + 400);
  rptr += sprintf(rptr,"%d L2\'s discovered:\n\n",l2_cnt);
  myssn = (const char *)nvramGet(NVRAM_SERIAL);
  if (discover_debug)
    fprintf(stderr,"l2find:  myssn = %s\n",myssn);
  rptr = l2find_section(rptr,l2_list,l2_cnt,myssn,same_ssn,"[ L2\'s with matching System Serial Number ]\n",&banner);
  rptr = l2find_section(rptr,l2_list,l2_cnt,myssn,no_ssn,"[ L2\'s with System Serial Number NOT set ]\n",&banner);
  l2find_section(rptr,l2_list,l2_cnt,myssn,other_ssn,"[ L2\'s with different System Serial Numbers ]\n",&banner);
  return 0;
}

/* "smp [verbose]|join <group>|leave" */
static int l2cmd_smp(CmdData *cptr, char **results, L2CMD *c)
{
  if (c == NULL)
    return -1;
  if (cptr->params[0] != 0 && !check_smp(c->data,results))
    return 0;
  switch (cptr->params[0]) {
  case 0:
    smp_query(c->data,cptr->params[1],results);
    break;
  case 1:
    if (smp_join(c->data,cptr->exp_stack[0]) != 0) {
      response(results,160);
      strcpy(*results,"ERROR: no such SMP group found\n");
      return -1;
    }
    break;
  case 2:
    if (smp_leave(c->data) != 0) {
      response(results,160);
      strcpy(*results,"ERROR: you are already in your own group\n");
      return -1;
    }
    break;
  }
  return 0;
}

/* a system serial number: a letter of [LMNPRTUWYZ], then 0 to 3, then six
 * digits */
static int valid_ssn(const char *s)
{
  int i;

  if (strlen(s) != 8 || s[0] < 'L' || s[0] > 'Z' || strchr("OQSVX",s[0]) != NULL || s[1] < '0' ||
      s[1] > '3')
    return 0;
  for (i = 2; i < 8; i++)
    if (!isdigit((int)s[i]))
      return 0;
  return 1;
}

/* "serial [set <ssn>]" */
static int l2cmd_serial(CmdData *cptr, char **results)
{
  char *ssn;

  /* (room for the bad number in the message: the original had 320 bytes) */
  response(results,320 + (cptr->params[0] == 1 ? strlen(cptr->str_stack[0]) : 0));
  if (cptr->params[0] == 1) {
    ssn = cptr->str_stack[0];
    if (!valid_ssn(ssn)) {
      sprintf(*results,"ERROR: invalid system serial number \'%s\'\n",ssn);
      strcat(*results,"System serial number must be [LMNPRTUWYZ]0000000 through [LMNPRTUWYZ]3999999\n");
      return -1;
    }
    nvramSet(NVRAM_SERIAL,(uintptr_t)ssn);
    L2CfgMEventSystemSN(&L2CfgLocal);
  }
  else if (cptr->params[0] != 0)
    return 0;
  ssn = (char *)nvramGet(NVRAM_SERIAL);
  sprintf(*results,"L2 system serial number: %s.\n",ssn != NULL && *ssn != '\0' ? ssn : "not set");
  return 0;
}

/* "sysname [<name>|reset]" */
static int l2cmd_sysname(CmdData *cptr, char **results)
{
  char *name;

  response(results,160);
  if (cptr->params[0] == 1 || cptr->params[0] == 2) {
    nvramSet(NVRAM_SYSNAME,(uintptr_t)(cptr->params[0] == 1 ? cptr->str_stack[0] : ""));
    L2CfgMEventSystemName(&L2CfgLocal);
  }
  name = (char *)nvramGet(NVRAM_SYSNAME);
  sprintf(*results,"L2 system name: %s.\n",name != NULL && *name != '\0' ? name : "not set");
  return 0;
}

/* "multisys [on|off]" (also "share net") */
static int l2cmd_multisys(CmdData *cptr, char **results)
{
  response(results,160);
  if (cptr->params[0] == 1)
    nvramSet(NVRAM_MULTISYS,1);
  else if (cptr->params[0] == 2)
    nvramSet(NVRAM_MULTISYS,0);
  if (nvramGet(NVRAM_MULTISYS) == 1)
    sprintf(*results,"L2 multiple system network support enabled.\nL2\'s will only connect to L2\'s with same system SN\n");
  else
    sprintf(*results,"L2 multiple system network support disabled.\nL2\'s will connect to ALL other L2\'s on the subnet\n");
  return 0;
}

/* "psmode [none|secondary|primary...]": the primary/secondary mode, from
 * the next start */
static int l2cmd_psmode(CmdData *cptr, char **results)
{
  static const char *const now[] = {
    "Primary/Secondary mode is currently disabled.\n", "L2 is currently a secondary L2.\n",
    "L2 is currently a primary L2.\n",
  };
  static const char *const next[] = {
    "Primary/Secondary mode will be disabled after reboot.\n", "L2 will be a secondary L2 after reboot.\n",
    "L2 will be a primary L2 after reboot.\n",
  };
  char *rptr = response(results,160);
  unsigned int mode;

  if (cptr->params[0] == 1) {
    switch (*cptr->toks[1]) {
    case 'n':
      nvramSet(NVRAM_MASTER_SLAVE,0);
      break;
    case 's':
      nvramSet(NVRAM_MASTER_SLAVE,1);
      break;
    case 'p':
      nvramSet(NVRAM_MASTER_SLAVE,2);
      break;
    }
  }
  else if (cptr->params[0] != 0)
    return 0;
  mode = L2CfgLocal.net.msmode;
  if (mode <= 2)
    rptr += sprintf(rptr,"%s",now[mode]);
  else
    rptr += sprintf(rptr,"WARNING: unknown primary/secondary mode %d.\n",mode);
  mode = nvramGet(NVRAM_MASTER_SLAVE);
  if (mode != L2CfgLocal.net.msmode) {
    if (mode <= 2)
      sprintf(rptr,"%s",next[mode]);
    else
      sprintf(rptr,"WARNING: unknown primary/secondary mode %d\n",mode);
  }
  return 0;
}

/* "log [clear|insert <text>]" */
static int l2cmd_log(CmdData *cptr, char **results)
{
  switch (cptr->params[0]) {
  case 0:
    *results = nvramLogFetch();
    if (*results == NULL) {
      response(results,160);
      strcpy(*results,"memory allocation error.\n");
    }
    else if (**results == '\0') {
      response(results,160);
      strcpy(*results,"log is empty.\n");
    }
    break;
  case 1:
    nvramLogReset();
    response(results,160);
    strcpy(*results,"log reset.\n");
    break;
  case 2:
    nvramLogInsert(cptr->str_stack[0]);
    response(results,160);
    strcpy(*results,"log entry made.\n");
    break;
  default:
    response(results,160);
    sprintf(*results,"unknown log command.\n");
    return -1;
  }
  return 0;
}

static int is_chassis(int type)
{
  return type == ',' || type == '}' || type == '.';
}

/* bricks whose CPUs are in slabs (format.c's), the chassis included */
static int has_slabs(int type)
{
  return type == '5' || type == '@' || type == '6' || type == '$' || is_chassis(type);
}

/* the console address on conaddr's brick for unit (a slab, or for a
 * chassis the address's task) and subchannel */
static IRAddress console_address(IRAddress conaddr, int type, int unit, int subch)
{
  int num;

  if (is_chassis(type)) {
    num = (BRICK_TASKNUM(type,0,subch) & 0x7f) << 5;
    if (!IR_ADDR_IS_IP(conaddr))
      return (conaddr & 0xfffff000) | num | (unit & 0x1f);
    return (conaddr & 0xc0fff01f) | num | (unit & 0x3f) << 24;
  }
  num = BRICK_TASKNUM(type,unit,subch);
  return (IR_ADDR_IS_IP(conaddr) ? conaddr & 0xc0fff01f : conaddr & 0xfffff000) | (num & 0x7f) << 5;
}

/* "console<n>", "con<n>" or "<n><letter>" on conaddr's brick of type;
 * 0 for a bad one (*errmsg says) */
static IRAddress parse_subchannel(const char *s, IRAddress conaddr, int type, const char **errmsg)
{
  char *endp;
  long unit;

  if (strncmp(s,"console",7) == 0)
    return console_address(conaddr,type,strtol(s + 7,NULL,0),4);
  if (strncmp(s,"con",3) == 0)
    return console_address(conaddr,type,strtol(s + 3,NULL,0),4);
  if (strlen(s) < 2) {
    *errmsg = "ERROR: bad subchanel selection.\n";
    return 0;
  }
  unit = strtol(s,&endp,0);
  return console_address(conaddr,type,unit,tolower((int)*endp) - 'a');
}

/* the session's system console and its brick, for changing its
 * subchannel; NULL (and an error in rptr) if there is none */
static L2CfgL1 *console_brick(L2CMD *c, IRAddress *conaddr, char *rptr)
{
  L2CfgL1 *cfg;

  if (smp_get_conaddr(c->data,conaddr,NULL) == 0) {
    strcpy(rptr,"ERROR: no system console address defined\n");
    return NULL;
  }
  cfg = L2CfgMFindBrickCfg(&L2CfgLocal,IR_ADDR_RACK(*conaddr),IR_ADDR_SLOT(*conaddr),0);
  if (cfg == NULL)
    strcpy(rptr,"ERROR: current console references non-existant brick\n");
  return cfg;
}

/* "select" without changes: every partition's console, as detected */
static char *list_consoles(char *rptr)
{
  IRAddress detected;
  int first = 1;
  int partition;

  *rptr = '\0';
  for (partition = 0; partition < 256; partition++) {
    detected = L2CfgLocal.syscon[partition].detected;
    if (detected == 0)
      continue;
    if (partition == 0)
      rptr += sprintf(rptr,"known system consoles (non-partitioned)\n\n");
    else if (first) {
      rptr += sprintf(rptr,"\nknown system consoles (partitioned)\n\n");
      first = 0;
    }
    if (partition == 0)
      rptr += sprintf(rptr,"\t");
    else
      rptr += sprintf(rptr,"\tpartition %2d: ",partition);
    rptr += sprintf(rptr,"%s - L2 detected\n",format_address(detected));
  }
  rptr += sprintf(rptr,"\ncurrent system console\n\n");
  return rptr;
}

/*
 * "select ...": the session's system console. params[0]: 0 show (params[1]
 * with the list), 1 the brick's console subchannel, 2 CPU a-d, 3 a
 * subchannel number, 4 a named subchannel, 5 a brick, 6 reset, 7 a
 * partition, 9 the output filter, 10 brick and subchannel. Then the
 * selection, and advice.
 */
static int l2cmd_select(CmdData *cptr, char **results, L2CMD *c)
{
  const char *errmsg = "ERROR: not a valid system console address\n\t- subchannel may be invalid.\n";
  char *rptr = response(results,0x5004);
  IRAddress conaddr;
  L2CfgL1 *cfg;
  int partition;
  int filtered;
  int overrode;
  int rack;
  int slot;

  if (c == NULL)
    return -1;
  if (!check_smp(c->data,results))
    return 0;
  switch (cptr->params[0]) {
  case 0:
    L2CfgMGetConsole(&L2CfgLocal,-1);
    if (cptr->params[1] != 0)
      rptr = list_consoles(rptr);
    break;
  case 1:       /* subchannel console */
  case 2:       /* subchannel a|b|c|d */
  case 3:       /* subchannel <n> */
    if ((cfg = console_brick(c,&conaddr,*results)) == NULL)
      return -1;
    if (has_slabs(cfg->type)) {
      strcpy(*results,cptr->params[0] == 1 ? "not valid on this brick - use \'console0|con0|console1...\'\n"
                                           : "not valid on this brick - use \'0a|0c|1a...\'\n");
      return -1;
    }
    if (cptr->params[0] == 1)
      conaddr = (conaddr & 0xfffff01f) | 4 << 5;
    else if (cptr->params[0] == 2)
      conaddr = (conaddr & 0xfffff01f) | ((tolower((int)*cptr->toks[2]) - 'a') & 0x7f) << 5;
    else
      conaddr = (conaddr & 0xfffff01f) | (cptr->exp_stack[0] & 0x7f) << 5;
    if (smp_set_conaddr(c->data,conaddr) == 0) {
      strcpy(*results,errmsg);
      return -1;
    }
    break;
  case 4:       /* subchannel console<n>|con<n>|<n><cpu> */
    if ((cfg = console_brick(c,&conaddr,*results)) == NULL)
      return -1;
    conaddr = parse_subchannel(cptr->str_stack[0],conaddr,cfg->type,&errmsg);
    if (conaddr == 0 || smp_set_conaddr(c->data,conaddr) == 0) {
      strcpy(*results,errmsg);
      return -1;
    }
    break;
  case 5:       /* <rack> <slot>: its console subchannel */
    rack = cptr->exp_stack[0];
    slot = cptr->exp_stack[1];
    cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
    if (cfg == NULL) {
      strcpy(*results,"ERROR: not a valid system console address\n");
      return -1;
    }
    conaddr = IR_ADDR_MAKE(IR_ADDR_L1,rack & 0x3ff,slot & 0x3f,0,0);
    if (!is_chassis(cfg->type))
      conaddr |= (cfg->console_subchannel & 0x7f) << 5 | ((cfg->console_subchannel >> 8) & 0x1f);
    if (smp_set_conaddr(c->data,conaddr) == 0) {
      strcpy(*results,"ERROR: not a valid system console address\n");
      return -1;
    }
    break;
  case 7:       /* partition <n> (0: reset) */
    partition = cptr->exp_stack[0];
    if (partition != 0) {
      if (partition < 0 || partition > 255) {
        sprintf(*results,"ERROR: invalid partition, partitions are 1 through %d\n",255);
        return -1;
      }
      if (smp_set_partition(c->data,partition) == 0) {
        sprintf(*results,"ERROR: no system console found for that partition\n");
        return -1;
      }
      /* the default destination: the partition. (The original marked
       * partitions past the 64-entry list too, writing past it.) */
      if (partition < (int)sizeof(cptr->plist)) {
        cptr->plist[partition] = 1;
        dest_default(c->dest,cptr);
      }
      break;
    }
    /* fall through */
  case 6:       /* reset */
    partition = smp_get_partition(c->data);
    smp_set_partition(c->data,0);
    smp_set_conaddr(c->data,0);
    if (partition != 0)
      dest_reset(c->dest);
    break;
  case 9:       /* filter on|off */
    smp_set_confilter(c->data,cptr->params[1]);
    break;
  case 10:      /* <rack> <slot> <subchannel> */
    rack = cptr->exp_stack[0];
    slot = cptr->exp_stack[1];
    cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
    if (cfg == NULL) {
      strcpy(*results,"ERROR: not a valid system console address\n");
      return -1;
    }
    conaddr = parse_subchannel(cptr->str_stack[0],IR_ADDR_MAKE(IR_ADDR_L1,rack & 0x3ff,slot & 0x3f,0,0),
                               cfg->type,&errmsg);
    if (conaddr == 0 || smp_set_conaddr(c->data,conaddr) == 0) {
      strcpy(*results,errmsg);
      return -1;
    }
    break;
  }
  partition = smp_get_partition(c->data);
  filtered = smp_get_confilter(c->data);
  smp_get_conaddr(c->data,&conaddr,&overrode);
  if (partition == 0 || overrode || filtered) {
    rptr += sprintf(rptr,"console input: %s%s\n",conaddr == 0 ? "not defined" : format_caddress(conaddr,0),
                    conaddr != 0 && overrode ? " (CAUTION: default overrode!)" : "");
    rptr += sprintf(rptr,"console output: %s\n",filtered ? "filtered" : "not filtered");
  }
  else {
    rptr += sprintf(rptr,"console input: partition %d, %s\n",partition,
                    conaddr == 0 ? "not defined" : format_caddress(conaddr,0));
    rptr += sprintf(rptr,"console output: any brick partition %d\n",partition);
  }
  L2CfgMAdviseConsole(&L2CfgLocal,rptr,partition,conaddr);
  return 0;
}

/* "tty" (hidden): the session's terminal settings, to stderr */
static int l2cmd_tty(CmdData *cptr, char **results, L2CMD *c)
{
  if (c == NULL)
    return -1;
  if (!check_smp(c->data,results))
    return 0;
  smp_tty_debug(((SMP *)c->data)->rfd);
  smp_tty_debug(((SMP *)c->data)->wfd);
  return 0;
}

/* "version [verbose]" */
static int l2cmd_version(CmdData *cptr, char **results)
{
  response(results,160);
  sprintf(*results,"L2 version: %d.%d.%d\n",L2_REV_MAJOR,L2_REV_MINOR,L2_REV_PATCH);
  return 0;
}

/*
 * The responses for "version summary|check": each controller's "ver"
 * ("L1 <words> <version>" or "L2 ..."), the versions counted; the L2s'
 * round first, then the L1s'. quiet (check): only problems.
 */
static int ver_summary_rsp(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data)
{
  ver_summary_data *sd = data;
  char version[16];
  char junk2[20];
  char junk1[2];   /* ORIGINAL BUG (fixed): char junk1, but %[12] stores a NUL too */
  char emsg[100] = "";
  char *text;
  char *rptr;
  int all_ok;
  int i;

  if (sd->verslist == NULL) {
    sd->verslist = calloc(pktsleft + 1,sizeof(*sd->verslist));
    sd->versnum = calloc(pktsleft + 1,sizeof(*sd->versnum));
    sd->ptype = IR_ADDR_TYPE(*dest) == IR_ADDR_L1 ? "L1" : "L2";
  }
  /* (messages with the controller's text cut to emsg: the original
   * sprintf()ed them) */
  if (rsp == NULL)
    snprintf(emsg,sizeof(emsg),"    ERROR: no response from %s\n",format_address(*dest));
  else if (rsp->_err != 0)
    snprintf(emsg,sizeof(emsg),"    ERROR: couldn\'t send packet to %s, %s\n",format_address(*dest),
             IRFmtError(rsp->_err));
  else {
    text = IR_ARG_TYPE(rsp->_argv[1]) == IR_ARG_VALUE ? (char *)IR_VAL_PTR(rsp->_argv[1]._val)
                                                      : (char *)IRArg(rsp,1);
    if ((IR_ARG_TYPE(rsp->_argv[0]) == IR_ARG_VALUE ? rsp->_argv[0]._val : IRArg(rsp,0)) != 0)
      snprintf(emsg,sizeof(emsg),"    %s:  %s\n",format_address(*dest),text);
    /* (the original's %[^0-9] had no width for junk2's 20 bytes) */
    else if (text == NULL || sscanf(text,"L%1[12]%19[^0-9]%15s",junk1,junk2,version) < 2)
      snprintf(emsg,sizeof(emsg),"    ERROR: could not get flash version of %s\n",format_address(*dest));
    else {
      for (i = 0; i < sd->verscnt && strcmp(sd->verslist[i],version) != 0; i++)
        ;
      if (i == sd->verscnt)
        sd->verslist[sd->verscnt++] = strdup(version);
      sd->versnum[i]++;
    }
  }
  if (emsg[0] != '\0' && !sd->quiet) {
    if (sd->errcnt == 0)
      sprintf(rsp_room(cmd_rsp,100),"%sWARNING: ERRORS occurred while reading flash versions from %s Controllers:\n",
              strcmp(sd->ptype,"L1") == 0 ? "\n" : "",sd->ptype);
    sd->errcnt++;
    strcat(rsp_room(cmd_rsp,strlen(emsg)),emsg);
  }
  if (pktsleft != 0)
    return 0;

  /* this round is in */
  rptr = rsp_room(cmd_rsp,sd->verscnt * 80);
  cmd_rsp->status = cmd_rsp->status == -1 || sd->errcnt != 0 ? -1 : 0;
  if (sd->errcnt != 0)
    rptr += sprintf(rptr,"\n");
  all_ok = 0;
  if (sd->verscnt == 1 && !sd->quiet) {
    if (sd->versnum[0] == 1)
      rptr += sprintf(rptr,"%s Controller is running firmware version %s\n",sd->ptype,sd->verslist[0]);
    else
      rptr += sprintf(rptr,"%s%d %s Controllers are running firmware version %s\n",sd->errcnt == 0 ? "All " : "",
                      sd->versnum[0],sd->ptype,sd->verslist[0]);
    all_ok = 1;
  }
  else if (sd->verscnt > 1) {
    rptr += sprintf(rptr,"WARNING: multiple %s Controller firmware versions detected!\n",sd->ptype);
    for (i = 0; i < sd->verscnt; i++)
      rptr += sprintf(rptr,"%d %s Controllers are running firmware version %s\n",sd->versnum[i],sd->ptype,
                      sd->verslist[i]);
    all_ok = 1;
  }
  if (all_ok && sd->errcnt != 0)
    sprintf(rptr,"%d %s Controller(s) could not be checked due to error(s)\n",sd->errcnt,sd->ptype);
  for (i = 0; i < sd->verscnt; i++)
    free(sd->verslist[i]);
  free(sd->verslist);
  free(sd->versnum);
  sd->verslist = NULL;
  sd->versnum = NULL;
  sd->verscnt = 0;
  sd->errcnt = 0;
  if (c->q->reqq_length < 1) {  /* the L1s' round was the last */
    sd->orig_c->busy &= ~2;
    l2cmd_process_response(sd->orig_c,cmd_rsp->sptr,cmd_rsp->status);
    free(sd);
  }
  return 0;
}

/* "[<target>] version summary|check": "ver" to every L2, then every L1
 * (ver_summary_rsp()) */
static int l2cmd_version_summary(CmdData *cptr, char **results, L2CMD *c)
{
  ver_summary_data *sd;
  char emsg[120] = "";
  L2CMD *tc;

  response(results,320);
  if (c == NULL)
    return -1;
  sd = calloc(1,sizeof(ver_summary_data));
  if (sd == NULL) {
    strcpy(*results,"ERROR: could not allocate memory to store internal command data\n");
    return -1;
  }
  sd->quiet = cptr->params[0] == 1;
  sd->orig_c = c;
  if (dest_l2(c->dest,cptr) == 0)
    strcat(emsg,"    WARNING: no L2s found to match that destination\n");
  if (dest_l1(c->dest,cptr) == 0)
    strcat(emsg,"    WARNING: no L1s found to match that destination\n");
  if (emsg[0] != '\0') {
    strcpy(*results,"WARNING: ERRORS occurred while reading L1/L2 Controller firmware versions:\n");
    strcat(*results,emsg);
    free(sd);
    return -1;
  }
  tc = cmd_setup_usr_response(ver_summary_rsp,sd);
  if (tc == NULL) {
    strcpy(*results,"ERROR: user command processor is busy\n");
    free(sd);
    return -1;
  }
  memcpy(tc->dest,c->dest,sizeof(DEST));
  c->busy |= 2;
  if (dest_l2(tc->dest,cptr) == 0)
    strcat(*results,"WARNING: no L2s found to match that destination\n");
  else if (tc->dest->count > 0 && broadcast_l2(tc,NULL,"ver",1,0,0) != 0) {
    response(results,160);
    strcpy(*results,"ERROR: no (L2) destination set.\n");
    c->busy &= ~2;
    free(sd);
    return -1;
  }
  if (dest_l1(tc->dest,cptr) == 0) {
    strcat(*results,"WARNING: no L1s found to match that destination\n");
    return -1;
  }
  if (broadcast_l1(tc,BCAST_PARALLEL,"ver",1,0,BCAST_ALL,NULL,1) != 0) {
    response(results,160);
    strcpy(*results,"ERROR: no (L1) destination set.\n");
    return -1;
  }
  return 0;
}

/* whether src starts with tgt, spaces ignored in both (-1 if so) */
static int cc(char *src, char *tgt)
{
  char *s = strdup(src);
  char *t = strdup(tgt);
  char *p;
  int rval;

  for (p = s; *p != '\0'; )
    if (*p == ' ')
      memmove(p,p + 1,strlen(p));
    else
      p++;
  for (p = t; *p != '\0'; )
    if (*p == ' ')
      memmove(p,p + 1,strlen(p));
    else
      p++;
  rval = strncmp(t,s,strlen(t)) == 0 ? -1 : 0;
  free(s);
  free(t);
  return rval;
}

/* CmdProcess()'s match of a command line: a form of the table, or not
 * (no match, or only the catch-all forms that pass it on) */
static int is_l2_command(char *cmd)
{
  int form = CmdProcess(0,cmd,NULL,l2cmd_cmds,L2CMD_FORMS,NULL);

  return form != CMD_ERR_ERROR && !(form >= FORM_CATCH_ALL && form < L2CMD_FORMS);
}

/* "<target> l2 <command>", "<ip> <command>": an L2 command to other L2s.
 * params[0] 1 by racks, 2 by IP address, 3 to this L2 (refused) */
static int l2cmd_l2cmd(CmdData *cptr, char **results, L2CMD *c)
{
  char *cmd = NULL;
  int ip;

  if (c == NULL)
    return -1;
  if (cptr->params[0] == 1)
    cmd = cptr->str_stack[0];
  else if (cptr->params[0] == 2)
    cmd = cptr->str_stack[1];
  if (cmd != NULL && !is_l2_command(cmd)) {
    response(results,160);
    sprintf(*results,"ERROR: invalid L2 command or target/broadcast attempted\n");
    return -1;
  }
  if (cmd != NULL && cc(cmd,"date sync") != 0) {
    response(results,160);
    sprintf(*results,"ERROR: command not supported in targeted/broadcast format\n");
    return -1;
  }
  switch (cptr->params[0]) {
  case 0:
  case 1:
    if (dest_l2(c->dest,cptr) == 0) {
      response(results,160);
      sprintf(*results,"no L2s found to match that destination\n");
      return -1;
    }
    if (broadcast_l2(c,results,cptr->str_stack[0],1,0,1) != 0) {
      response(results,160);
      strcpy(*results,"ERROR: invalid destination.\n");
      return -1;
    }
    break;
  case 2:
    ip = htonl(cptr->exp_stack[0] << 24 | cptr->exp_stack[1] << 16 | cptr->exp_stack[2] << 8 |
               cptr->exp_stack[3]);
    if (target_l2(c,results,ip,cptr->str_stack[1],1,0,1) != 0) {
      response(results,160);
      strcpy(*results,"ERROR: invalid destination.\n");
      return -1;
    }
    break;
  case 3:
    response(results,160);
    strcpy(*results,"ERROR: targeting local L2 is redundant.\n");
    return -1;
  }
  return 0;
}

/* whether the first or second word of the command line starts with word */
static int starts(CmdData *cptr, const char *word)
{
  size_t len = strlen(word);

  return (cptr->str_stack[0] != NULL && strncmp(cptr->str_stack[0],word,len) == 0) ||
         (cptr->str_stack[1] != NULL && strncmp(cptr->str_stack[1],word,len) == 0);
}

/* "[<target>] l1 <command>", "<ip>:<port>:<l1> <command>": an L1 command.
 * params[0] 0/1 by destination, 2 by address */
static int l2cmd_l1cmd(CmdData *cptr, char **results, L2CMD *c)
{
  int rspexp = 1;               /* reboot_l1 and abort have no response */
  int ip;

  if (c == NULL)
    return -1;
  if (starts(cptr,"reboot_l1") || starts(cptr,"abort"))
    rspexp = 0;
  if (cptr->str_stack[0] != NULL && strncmp(cptr->str_stack[0],"*",1) == 0) {
    response(results,160);
    sprintf(*results,"ERROR: invalid broadcast attempted\n");
    return -1;
  }
  if (cptr->str_stack[0] != NULL &&
      (strncmp(cptr->str_stack[0],"reset",5) == 0 || strncmp(cptr->str_stack[0],"rst",3) == 0 ||
       strncmp(cptr->str_stack[0],"nmi",3) == 0)) {
    /* not across partitions by default */
    response(results,160);
    if (dest_pcheck(c->dest,cptr,*results) != 0)
      return -1;
    free(*results);
    *results = NULL;
  }
  if (cptr->params[0] < 2) {
    if (dest_l1(c->dest,cptr) == 0) {
      response(results,160);
      sprintf(*results,"ERROR: no L1s found to match that destination\n");
      return -1;
    }
    if (broadcast_l1(c,BCAST_PARALLEL,cptr->str_stack[0],rspexp,0,BCAST_ALL,NULL,1) != 0) {
      response(results,160);
      strcpy(*results,"ERROR: no destination set.\n");
      return -1;
    }
  }
  else if (cptr->params[0] == 2) {
    ip = htonl(cptr->exp_stack[0] << 24 | cptr->exp_stack[1] << 16 | cptr->exp_stack[2] << 8 |
               cptr->exp_stack[3]);
    if (cptr->exp_stack[5] != 0) {
      response(results,160);
      strcpy(*results,"ERROR: destination is too remote, try a more direct connection\n");
      return -1;
    }
    if (target_l1(c,ip,cptr->exp_stack[4],0,cptr->str_stack[1],rspexp,0,1) != 0) {
      response(results,160);
      strcpy(*results,"ERROR: invalid destination.\n");
      return -1;
    }
  }
  return 0;
}

/* "[<target>] <command>": an L2 command if it is one (not with a slot
 * list), else an L1 command */
static int l2cmd_cmd(CmdData *cptr, char **results, L2CMD *c)
{
  int i;

  if (c == NULL)
    return -1;
  if (cptr->slist[0] != CMD_RANGE_ANY)
    for (i = 0; i < (int)sizeof(cptr->slist); i++)
      if (cptr->slist[i] != 0)
        return l2cmd_l1cmd(cptr,results,c);
  if (is_l2_command(cptr->str_stack[0]))
    return l2cmd_l2cmd(cptr,results,c);
  return l2cmd_l1cmd(cptr,results,c);
}

/* a new zeroed response buffer in *rptr (freeing the old) */
static char *response(char **rptr, int size)
{
  free(*rptr);
  *rptr = malloc(size);
  if (*rptr != NULL)
    memset(*rptr,0,size);
  return *rptr;
}

/* a console address's number on a brick of btype: slab and subchannel
 * (format.c's BRICK_TASKNUM_SLAB() and BRICK_TASKNUM_SUBCHAN() undone) */
static int BRICK_TASKNUM(int btype, int slab, int subchan)
{
  switch (btype) {
  case '6':
    return slab * 24 + subchan % 24;
  case '@':
    return slab * 20 + subchan % 20;
  default:
    return slab * 32 + subchan % 32;
  }
}
