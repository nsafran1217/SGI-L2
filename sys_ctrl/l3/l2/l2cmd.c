/*
 * sys_ctrl/l3/l2/l2cmd.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/l2/l2cmd.c
 */

#include <ctype.h>
#include "../../common/sys/MemUsage.h"   /* needed by the reconstruction */
#include "../../common/sys/minfo.h"   /* needed by the reconstruction */
#include "../api/SCapiL2.h"   /* needed by the reconstruction */
#include "discover.h"   /* needed by the reconstruction */
#include "route.h"   /* needed by the reconstruction */
#include <arpa/inet.h>
#include <sys/types.h>
#include <stddef.h>
#include <time.h>
#include <netinet/in.h>
#include <limits.h>
#include <syslimits.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sys/stat.h>
#include <malloc.h>
#include "l2.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
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
#include "../../common/sys/Cmd.h"
#include "../api/SCapi.h"
#include "../../common/sys/FRU.h"
#include "l2cmd.h"
#include "reqrspq.h"
#include "dest.h"
#include "cmd.h"
#include "irtr.h"
#include "format.h"
#include "broadcast.h"
#include "target.h"
#include "enet.h"
#include "smp.h"
#include "cfg.h"
#include "lpbk.h"
#include "../main/nvram.h"
#include "power.h"
#include "serial.h"
#include "l1.h"
#include "../l2demo/l2demo.h"
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */
char *format_address(IRAddress addr);   /* defined in format's module; not in a header (name clash with a static elsewhere) */
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
static int l2cmd_password(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_pbay(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_quit(CmdData *cptr, char **results, L2CMD *c);
static void reboot(void);
static int l2cmd_reboot(CmdData *cptr, char **results);
static void haltl2(void);
static int l2cmd_haltl2(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_ping(CmdData *cptr, char **results);
static int l2cmd_l2dsp(CmdData *cptr, char **results);
static int format_l2find_entry(char *rptr, sn1SC_L2 *l2);
static int l2cmd_l2find(CmdData *cptr, char **results);
static int l2cmd_shell(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_smp(CmdData *cptr, char **results, L2CMD *c);
static int l2cmd_serial(CmdData *cptr, char **results);
static int l2cmd_sysname(CmdData *cptr, char **results);
static int l2cmd_multisys(CmdData *cptr, char **results);
static int l2cmd_psmode(CmdData *cptr, char **results);
static int l2cmd_dhcps(CmdData *cptr, char **results);
static int l2cmd_ip(CmdData *cptr, char **results);
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
Cmd l2cmd_cmds[190] = { { .toks = { "router|io|compute|other", (char *)6 }, .func = l2cmd_broadcast, .desc = "targets command to class of bricks" }, { .toks = { "autopower|apwr" }, .func = l2cmd_autopower, .desc = "shows current auto power up setting" }, { .toks = { "autopower|apwr", "on" }, .func = l2cmd_autopower, .params = { 1 }, .desc = "enables auto power on" }, { .toks = { "autopower|apwr", "off" }, .func = l2cmd_autopower, .params = { 2 }, .desc = "disables auto power on" }, { .toks = { "autopower|apwr", "abort" }, .func = l2cmd_autopower, .params = { 3 }, .desc = "aborts auto power on" }, { .toks = { "autopower|apwr", "delay", (char *)1 }, .func = l2cmd_autopower, .params = { 4 }, .desc = "sets delay (in seconds) before auto-powerup" }, { .toks = { "config|cfg" }, .func = l2cmd_config, .params = { 0, 1, 1 }, .desc = "shows configuration information (normal)" }, { .toks = { "config|cfg", "summary|s" }, .func = l2cmd_config, .params = { 0, 0, 1 }, .desc = "shows configuration information (summary)" }, { .toks = { "config|cfg", "verbose|v" }, .func = l2cmd_config, .params = { 0, 2, 1 }, .desc = "shows configuration information (verbose)" }, { .toks = { "config|cfg", "l2" }, .func = l2cmd_config, .params = { 0, 1 }, .desc = "shows L2 configuration information (normal)" }, { .toks = { "config|cfg", "l2", "verbose|v" }, .func = l2cmd_config, .params = { 0, 2 }, .desc = "shows L2 configuration information (verbose)" }, { .toks = { "config|cfg", "re|rescan" }, .func = l2cmd_config, .params = { 1 }, .desc = "forces L1 config update" }, { .toks = { "config|cfg", "auto" }, .func = l2cmd_config, .params = { 2 }, .desc = "enables automatic L1 config updates" }, { .toks = { "config|cfg", "man|manual" }, .func = l2cmd_config, .params = { 3 }, .desc = "disables automatic L1 config updates" }, { .toks = { "config|cfg", "print" }, .func = l2cmd_config, .params = { 4 }, .desc = "debugging only (local config)" }, { .toks = { "config|cfg", "print", "all" }, .func = l2cmd_config, .params = { 4, 1 }, .desc = "debugging only (full config)" }, { .toks = { "config|cfg", "l|list" }, .func = l2cmd_config, .params = { 5 }, .desc = "shows configuration information (list)" }, { .toks = { "config|cfg", "t|times" }, .func = l2cmd_config, .params = { 6 }, .desc = "shows various L2 process information" }, { .toks = { "connect", (char *)5 }, .func = l2cmd_connect, .desc = "connects to L2 at host specified" }, { .toks = { "date", "tz" }, .func = l2cmd_rtc, .params = { 2 }, .desc = "display current timezone settings" }, { .toks = { "date", "tz", (char *)5 }, .func = l2cmd_rtc, .params = { 3 }, .desc = "set UNIX timezone string (ex: date tz CST6CDT)" }, { .toks = { "date" }, .func = l2cmd_rtc, .desc = "display current L2 date and time" }, { .toks = { "date", "raw" }, .func = l2cmd_rtc, .params = { 5 }, .desc = "display current L2 time" }, { .toks = { "date", "sync" }, .func = l2cmd_rtc, .params = { 6 }, .desc = "set all L1's and L2's to this L2's timezone and time" }, { .toks = { "date", (char *)5 }, .func = l2cmd_rtc, .params = { 1 }, .desc = "set L2 date and time (date MMDDhhmm[[CC]YY][.ss])" }, { .toks = { "date", (char *)5, (char *)5 }, .func = l2cmd_rtc, .params = { 4 }, .desc = "set L2 timezone and date" }, { .toks = { "demo" }, .func = l2cmd_demo, .desc = "dumps the contents of the L2 demo database" }, { .toks = { "demo", "current", (char *)1 }, .func = l2cmd_demo, .params = { 1 }, .desc = "selects the specified msgno as the default message" }, { .toks = { "demo", (char *)1, (char *)6 }, .func = l2cmd_demo, .params = { 2 }, .desc = "sets the value of the specified msgno in the demo database" }, { .toks = { "destination|dest" }, .func = l2cmd_destination, .desc = "shows default destination(s)" }, { .toks = { (char *)10, "destination|dest" }, .func = l2cmd_destination, .params = { 1 }, .desc = "sets default destination to selected racks and slots" }, { .toks = { "destination|dest", "reset|rst" }, .func = l2cmd_destination, .params = { 2 }, .desc = "resets default default to all rack and slots" }, { .toks = { "dhcpserver|dhcps" }, .func = l2cmd_dhcps, .desc = "show current DHCP server setting" }, { .toks = { "dhcpserver|dhcps", "on|enable" }, .func = l2cmd_dhcps, .params = { 1 }, .desc = "enables startup of DHCP server (if no other DHCP server found)" }, { .toks = { "dhcpserver|dhcps", "off|disable" }, .func = l2cmd_dhcps, .params = { 2 }, .desc = "disables startup of DHCP server" }, { .toks = { "env", "summary|s" }, .func = l2cmd_env, .desc = "shows environmental status summary" }, { .toks = { (char *)10, "env", "summary|s" }, .func = l2cmd_env, .params = { 1 }, .desc = "shows environmental status summary" }, { .toks = { "help|hlp" }, .func = l2cmd_help, .desc = "get list of commands" }, { .toks = { "help|hlp", (char *)5 }, .func = l2cmd_help, .params = { 1 }, .desc = "get help on a single command." }, { .toks = { (char *)10, "hreboot_l1" }, .func = l2cmd_hreboot_l1, .desc = "use the L1REQ_REBOOT request to reboot the L1", .visibility = 1 }, { .toks = { (char *)11, "hreboot_l1" }, .func = l2cmd_hreboot_l1, .desc = "use the L1REQ_REBOOT request to reboot the L1", .visibility = 1 }, { .toks = { "ip" }, .func = l2cmd_ip, .desc = "shows static IP address settings" }, { .toks = { "ip", "gw|gateway", (char *)5 }, .func = l2cmd_ip, .params = { 3 }, .desc = "set the L2's static IP gateway address" }, { .toks = { "ip", (char *)5, (char *)5 }, .func = l2cmd_ip, .params = { 1 }, .desc = "set the L2's static IP config: <addr> <netmask>" }, { .toks = { "ip", (char *)5, (char *)5, (char *)5 }, .func = l2cmd_ip, .params = { 2 }, .desc = "set the L2's static IP config: <addr> <netmask> <broadcast>" }, { .toks = { "ip", "clear|reset" }, .func = l2cmd_ip, .params = { 4 }, .desc = "clears static IP address settings" }, { .toks = { "let", "atlantis", "rise" }, .func = l2cmd_help, .params = { 0, 1 }, .desc = "get complete list of commands", .visibility = 1 }, { .toks = { "let", (char *)5, "rise" }, .func = l2cmd_help, .params = { 1, 1 }, .desc = "get complete help on a single command.", .visibility = 1 }, { .toks = { "l2dbg" }, .func = l2cmd_l2dbg, .params = { 4294967295 }, .desc = "show current L2 debug states" }, { .toks = { "l2dbg", "malloc", (char *)1 }, .func = l2cmd_l2dbg, .desc = "set irouter malloc/free debug level" }, { .toks = { "l2dbg", "packets", (char *)1 }, .func = l2cmd_l2dbg, .params = { 1 }, .desc = "set irouter packet debug level" }, { .toks = { "l2dbg", "packets" }, .func = l2cmd_l2dbg, .params = { 1, 1 }, .desc = "show packet usage and high water" }, { .toks = { "l2dbg", "packets", "reset" }, .func = l2cmd_l2dbg, .params = { 1, 3 }, .desc = "reset packet usage and high water counters" }, { .toks = { "l2dbg", "config", (char *)1 }, .func = l2cmd_l2dbg, .params = { 2 }, .desc = "set L2 configuration debug level" }, { .toks = { "l2dbg", "meminfo|mem" }, .func = l2cmd_l2dbg, .params = { 3 }, .desc = "display dynamic memory usage" }, { .toks = { "l2dbg", "smp", (char *)1 }, .func = l2cmd_l2dbg, .params = { 4 }, .desc = "set SMP input debug level" }, { .toks = { "l2dbg", "broadcast", (char *)1 }, .func = l2cmd_l2dbg, .params = { 5 }, .desc = "set broadcast debug level" }, { .toks = { "l2dbg", "discovery|disc", (char *)1 }, .func = l2cmd_l2dbg, .params = { 6 }, .desc = "set L2 discovery debug level" }, { .toks = { "l2dbg", "usb", (char *)1 }, .func = l2cmd_l2dbg, .params = { 7 }, .desc = "set L2 USB debug level (0=off,1=debug,2=verbose)" }, { .toks = { "l2dbg", "e|estat" }, .func = l2cmd_l2dbg, .params = { 8 }, .desc = "report Event processor stats" }, { .toks = { "l2dbg", "e|estat", "r|reset" }, .func = l2cmd_l2dbg, .params = { 8, 1 }, .desc = "report Event processor stats and reset to zero" }, { .toks = { "l2dbg", "sbuf", (char *)1, (char *)1 }, .func = l2cmd_l2dbg, .params = { 9 }, .desc = "set L2<->L2 socket send/recv buffer size" }, { .toks = { "l2dbg", "events", "io" }, .func = l2cmd_l2dbg, .params = { 10 }, .desc = "show I/O events" }, { .toks = { "l2dbg", "events", "timers" }, .func = l2cmd_l2dbg, .params = { 11 }, .desc = "show timer event" }, { .toks = { "l2dbg", "console", (char *)1 }, .func = l2cmd_l2dbg, .params = { 12 }, .desc = "show console tracking messages" }, { .toks = { "l2dbg", "mstat|ms" }, .func = l2cmd_l2dbg, .params = { 13 }, .desc = "show malloc history" }, { .toks = { "l2dbg", "mmap|mm" }, .func = l2cmd_l2dbg, .params = { 14 }, .desc = "show malloc map" }, { .toks = { "l2dbg", "mreset" }, .func = l2cmd_l2dbg, .params = { 15 }, .desc = "reset malloc profiling" }, { .toks = { "l2dbg", "menable" }, .func = l2cmd_l2dbg, .params = { 16 }, .desc = "enable malloc profiling" }, { .toks = { "l2dbg", "mdisable" }, .func = l2cmd_l2dbg, .params = { 17 }, .desc = "disable malloc profiling" }, { .toks = { "l2dbg", "mmalloc", (char *)1 }, .func = l2cmd_l2dbg, .params = { 18 }, .desc = "allocate a buffer" }, { .toks = { "l2dbg", "qstat" }, .func = l2cmd_l2dbg, .params = { 19 }, .desc = "show Router client queue statistics" }, { .toks = { "l2dbg", "qstat", "reset" }, .func = l2cmd_l2dbg, .params = { 20 }, .desc = "resets cumulative queue statistics for each Router client" }, { .toks = { "l2dbg", "load", (char *)1 }, .func = l2cmd_l2dbg, .params = { 21 }, .desc = "enable/disable simulated L2 load" }, { .toks = { "l2dbg", "flow", (char *)1, (char *)1 }, .func = l2cmd_l2dbg, .params = { 22 }, .desc = "set net conn flow ctrl (high/low water mark pkt count)" }, { .toks = { "l2dbg", "throttle", (char *)1 }, .func = l2cmd_l2dbg, .params = { 23 }, .desc = "set L1 input throttle frequency (msecs)" }, { .toks = { "l2dbg", "brspto", (char *)1 }, .func = l2cmd_l2dbg, .params = { 24 }, .desc = "set broadcast response timeout limit" }, { .toks = { "l2dbg", "trspto", (char *)1 }, .func = l2cmd_l2dbg, .params = { 25 }, .desc = "set target response timeout limit" }, { .toks = { "l2dbg", "misc", (char *)1 }, .func = l2cmd_l2dbg, .params = { 26 }, .desc = "set misc. L2 debug flag", .visibility = 1 }, { .toks = { "l2dbg", "dump|d", (char *)5, (char *)1, (char *)1 }, .func = l2cmd_l2dbg, .params = { 27 }, .desc = "l2dbg dump|d a|x <addr> <len>" }, { .toks = { "l2dbg", "smp", "response", (char *)1 }, .func = l2cmd_l2dbg, .params = { 28 }, .desc = "debug SMP responses" }, { .toks = { "l2dbg", "str", (char *)1 }, .func = l2cmd_l2dbg, .params = { 29 }, .desc = "debug SMP string processing" }, { .toks = { "l1" }, .func = l2cmd_l1, .desc = "engages L1 command processor" }, { .toks = { (char *)10, "l1" }, .func = l2cmd_l1, .params = { 1 }, .desc = "engages L1 command processor at rack and slot" }, { .toks = { (char *)11, "l1" }, .func = l2cmd_l1, .params = { 1 }, .desc = "engages L1 command processor at rack and slot" }, { .toks = { (char *)10, "l1", (char *)6 }, .func = l2cmd_l1cmd, .params = { 1 }, .desc = "sends L1 command to selected L1(s)" }, { .toks = { (char *)11, "l1", (char *)6 }, .func = l2cmd_l1cmd, .params = { 1 }, .desc = "sends L1 command to selected L1" }, { .toks = { (char *)9, (char *)6 }, .func = l2cmd_l1cmd, .params = { 2 }, .desc = "sends L1 command to L1 at ip:port:L1" }, { .toks = { "l1", (char *)6 }, .func = l2cmd_l1cmd, .desc = "sends L1 command to default destinations" }, { .toks = { "l2" }, .func = l2cmd_l2, .desc = "engages L2 command processor" }, { .toks = { (char *)10, "l2" }, .func = l2cmd_l2, .params = { 1 }, .desc = "engages L2 command processor at specified rack" }, { .toks = { "l2", (char *)6 }, .func = l2cmd_l2cmd, .params = { 3 }, .desc = "sends L2 command to local l2" }, { .toks = { (char *)10, "l2", (char *)6 }, .func = l2cmd_l2cmd, .params = { 1 }, .desc = "sends L2 command to selected L2(s)" }, { .toks = { "l2dsp|l2display", "debug", (char *)1 }, .func = l2cmd_l2dsp, .desc = "set L2 display debug flags" }, { .toks = { "l2dsp|l2display", "debug" }, .func = l2cmd_l2dsp, .params = { 1 }, .desc = "show L2 display debug flags" }, { .toks = { "l2dsp|l2display", "enable" }, .func = l2cmd_l2dsp, .params = { 2 }, .desc = "enable touch-screen input from the L2 display" }, { .toks = { "l2dsp|l2display", "disable" }, .func = l2cmd_l2dsp, .params = { 3 }, .desc = "lock the L2 display (disable touch-screen input)" }, { .toks = { "l2dsp|l2display" }, .func = l2cmd_l2dsp, .params = { 4 }, .desc = "show the L2 display lock setting" }, { .toks = { "l2find" }, .func = l2cmd_l2find, .desc = "print list of L2's on the same subnet as this one" }, { .toks = { "log" }, .func = l2cmd_log, .desc = "dump log" }, { .toks = { "log", "clear|reset" }, .func = l2cmd_log, .params = { 1 }, .desc = "clear log" }, { .toks = { "log", "insert", (char *)6 }, .func = l2cmd_log, .params = { 2 }, .desc = "insert entry into log" }, { .toks = { (char *)11, "loopback", (char *)1, (char *)1 }, .func = l2cmd_loopback, .desc = "loopback data to L1 (size,count)" }, { .toks = { (char *)11, "loopback", (char *)1, (char *)1, (char *)1 }, .func = l2cmd_loopback, .params = { 1 }, .desc = "loopback data to L1 (session, size, count)" }, { .toks = { (char *)10, "route" }, .func = l2cmd_route, .desc = "trace route to L1" }, { .toks = { (char *)11, "route" }, .func = l2cmd_route, .desc = "trace route to L1" }, { .toks = { "nvram", "reset" }, .func = l2cmd_nvram, .desc = "return L2 NVRAM settings to factory default" }, { .toks = { "ping" }, .func = l2cmd_ping, .desc = "show L2 to L2/L1 ping configuration" }, { .toks = { "ping", "min", (char *)1 }, .func = l2cmd_ping, .params = { 1 }, .desc = "sets L2 to L2 ping response minumum" }, { .toks = { "ping", "max", (char *)1 }, .func = l2cmd_ping, .params = { 2 }, .desc = "sets L2 to L2 ping response maximum" }, { .toks = { "ping", "l2", (char *)1 }, .func = l2cmd_ping, .params = { 3 }, .desc = "sets L2 to L2 ping frequency in seconds" }, { .toks = { "ping", "sender", (char *)1 }, .func = l2cmd_ping, .params = { 4 }, .desc = "enables (1) or disables (0) sender ping as valid response" }, { .toks = { "ping", "l1", (char *)1 }, .func = l2cmd_ping, .params = { 5 }, .desc = "sets L2 to L1 ping frequency in seconds" }, { .toks = { "ping", "throttle", (char *)1 }, .func = l2cmd_ping, .params = { 6 }, .desc = "set L2 configuration throttle frequency" }, { .toks = { "ping", "reset" }, .func = l2cmd_ping, .params = { 7 }, .desc = "resets L2 to L2/L1 ping configuration to defaults" }, { .toks = { "password|pw" }, .func = l2cmd_password, .desc = "display L2 password status" }, { .toks = { "password|pw", "set", (char *)5 }, .func = l2cmd_password, .params = { 1 }, .desc = "set/change the password required to access this L2" }, { .toks = { "password|pw", "clear" }, .func = l2cmd_password, .params = { 2 }, .desc = "clear the L2 password (only allowed from L2 Console/Modem serial ports)" }, { .toks = { "password|pw", "clear", (char *)5 }, .func = l2cmd_password, .params = { 3 }, .desc = "clear the L2 password (<str> is current L2 password)" }, { .toks = { "pbay", "cfg|config" }, .func = l2cmd_pbay, .desc = "report the bricks connected to each PowerBay" }, { .toks = { "pbay", (char *)6 }, .func = l2cmd_pbay, .desc = "send pbay <command> to one L1 connected to each PowerBay" }, { .toks = { (char *)10, "pbay", "cfg|config" }, .func = l2cmd_pbay, .params = { 1 }, .desc = "report the bricks connected to each PowerBay" }, { .toks = { (char *)10, "pbay", (char *)6 }, .func = l2cmd_pbay, .params = { 1 }, .desc = "send pbay <command> to one L1 connected to each PowerBay" }, { .toks = { "power|pwr" }, .func = l2cmd_power, .desc = "show power status of each selected brick" }, { .toks = { "power|pwr", "up|u" }, .func = l2cmd_power, .params = { 0, 1 }, .desc = "powers up each selected brick" }, { .toks = { "power|pwr", "down|d" }, .func = l2cmd_power, .params = { 0, 2 }, .desc = "powers down each selected brick" }, { .toks = { "power|pwr", "summary|s" }, .func = l2cmd_power, .params = { 0, 3 }, .desc = "power status summary" }, { .toks = { "power|pwr", "delay" }, .func = l2cmd_power, .params = { 0, 4 }, .desc = "shows delay between power commands" }, { .toks = { "power|pwr", "delay", (char *)1 }, .func = l2cmd_power, .params = { 0, 5 }, .desc = "sets delay between power commands in milliseconds" }, { .toks = { "power|pwr", "mode" }, .func = l2cmd_power, .params = { 0, 6 }, .desc = "shows current power mode (fast/slow)", .visibility = 1 }, { .toks = { "power|pwr", "mode", "slow|fast" }, .func = l2cmd_power, .params = { 0, 7 }, .desc = "sets fast (RTRs parallel), or old/slow (RTRs in series) powerup", .visibility = 1 }, { .toks = { (char *)10, "power|pwr" }, .func = l2cmd_power, .params = { 1 }, .desc = "show power status of each selected brick" }, { .toks = { (char *)10, "power|pwr", "up|u" }, .func = l2cmd_power, .params = { 1, 1 }, .desc = "powers up each selected brick" }, { .toks = { (char *)10, "power|pwr", "down|d" }, .func = l2cmd_power, .params = { 1, 2 }, .desc = "powers down each selected brick" }, { .toks = { (char *)10, "power|pwr", "summary|s" }, .func = l2cmd_power, .params = { 1, 3 }, .desc = "power status summary" }, { .toks = { "quit" }, .func = l2cmd_quit, .desc = "exit the L2" }, { .toks = { "halt_l2" }, .func = l2cmd_haltl2, .desc = "halt the L2" }, { .toks = { "rackid" }, .func = l2cmd_rackid, .desc = "print the rack ID of the L2" }, { .toks = { "rackid", (char *)2 }, .func = l2cmd_rackid, .params = { 1 }, .desc = "set the rack ID for the L2" }, { .toks = { "reboot_l2" }, .func = l2cmd_reboot, .desc = "reboot the L2 controller" }, { .toks = { "reboot_l2", "force" }, .func = l2cmd_reboot, .params = { 1 }, .desc = "reboot the L2 controller even if the firmware image is invalid" }, { .toks = { "reset|rst" }, .func = l2cmd_reset, .desc = "reset each selected brick" }, { .toks = { (char *)10, "reset|rst" }, .func = l2cmd_reset, .params = { 1 }, .desc = "reset each selected brick" }, { .toks = { "select|sel" }, .func = l2cmd_select, .params = { 0, 1 }, .desc = "shows system console information" }, { .toks = { "select|sel", "terse|t" }, .func = l2cmd_select, .desc = "shows system console information - terse version" }, { .toks = { "select|sel", "subchannel|sub|s", "console|con" }, .func = l2cmd_select, .params = { 1 }, .desc = "sets 'console' subchannel for console I/O, current brick" }, { .toks = { "select|sel", "subchannel|sub|s", "a|b|c|d" }, .func = l2cmd_select, .params = { 2 }, .desc = "sets selected CPU subchannel for console I/O, current brick" }, { .toks = { "select|sel", "subchannel|sub|s", (char *)1 }, .func = l2cmd_select, .params = { 3 }, .desc = "sets selected CPU subchannel for console I/O, current brick" }, { .toks = { "select|sel", "subchannel|sub|s", (char *)5 }, .func = l2cmd_select, .params = { 4 }, .desc = "sets selected CPU subchannel for console I/O, current brick (multi-node/brick)" }, { .toks = { "select|sel", (char *)1, (char *)1 }, .func = l2cmd_select, .params = { 5 }, .desc = "sets rack and slot for console I/O, subchannel ?" }, { .toks = { "select|sel", (char *)11 }, .func = l2cmd_select, .params = { 5 }, .desc = "sets rack and slot for console I/O, subchannel ?" }, { .toks = { "select|sel", "reset|rst" }, .func = l2cmd_select, .params = { 6 }, .desc = "reset console I/O selections to defaults" }, { .toks = { "select|sel", "partition|part|p", (char *)1 }, .func = l2cmd_select, .params = { 7 }, .desc = "sets partition (and system console) for console access" }, { .toks = { "select|sel", "filter", "on" }, .func = l2cmd_select, .params = { 9, 1 }, .desc = "enables console output filter" }, { .toks = { "select|sel", "filter", "off" }, .func = l2cmd_select, .params = { 9 }, .desc = "disables console output filter" }, { .toks = { "select|sel", (char *)1, (char *)1, (char *)5 }, .func = l2cmd_select, .params = { 10 }, .desc = "sets select rack, slot and subchannel for console I/O" }, { .toks = { "smp" }, .func = l2cmd_smp, .desc = "show status of SMP connections" }, { .toks = { "smp", "verbose|v" }, .func = l2cmd_smp, .params = { 0, 1 }, .desc = "show status of SMP connections (verbose)" }, { .toks = { "smp", "join", (char *)1 }, .func = l2cmd_smp, .params = { 1 }, .desc = "joins to specified SMP group" }, { .toks = { "smp", "leave" }, .func = l2cmd_smp, .params = { 2 }, .desc = "leaves the current SMP group" }, { .toks = { "smp", "modem", "baud", "9600" }, .func = l2cmd_smp, .params = { 3, 2 }, .desc = "sets modem port baud rate to 9600" }, { .toks = { "smp", "modem", "baud", "19200" }, .func = l2cmd_smp, .params = { 3, 1 }, .desc = "sets modem port baud rate to 19200" }, { .toks = { "smp", "modem", "baud", "38400" }, .func = l2cmd_smp, .params = { 3 }, .desc = "sets modem port baud rate to 38400" }, { .toks = { "serial" }, .func = l2cmd_serial, .desc = "shows the L2 system serial number" }, { .toks = { "serial", "set", (char *)5 }, .func = l2cmd_serial, .params = { 1 }, .desc = "sets the L2 system serial number" }, { .toks = { "multisys|msys" }, .func = l2cmd_multisys, .desc = "show current setting for multiple system network sharing" }, { .toks = { "multisys|msys", "on" }, .func = l2cmd_multisys, .params = { 1 }, .desc = "enable multiple systems on same network (L2's talk by system SN)" }, { .toks = { "multisys|msys", "off" }, .func = l2cmd_multisys, .params = { 2 }, .desc = "disable multiple systems on same network (L2's talk to all L2's)" }, { .toks = { "share", "net" }, .func = l2cmd_multisys, .desc = "show current setting for multiple system network sharing" }, { .toks = { "share", "net", "on" }, .func = l2cmd_multisys, .params = { 1 }, .desc = "enable multiple systems on same network (L2's talk by system SN)" }, { .toks = { "share", "net", "off" }, .func = l2cmd_multisys, .params = { 2 }, .desc = "disable multiple systems on same network (L2's talk to all L2's)" }, { .toks = { "psmode|ps" }, .func = l2cmd_psmode, .desc = "query L2 primary/secondary mode" }, { .toks = { "psmode|ps", "none|n|secondary|s|primary|p" }, .func = l2cmd_psmode, .params = { 1 }, .desc = "set L2 primary/secondary mode" }, { .toks = { "psmode|ps", "none|n|secondary-external|sx|primary-external|px" }, .func = l2cmd_psmode, .params = { 1, 1 }, .desc = "set L2 primary/secondary mode" }, { .toks = { "sysname" }, .func = l2cmd_sysname, .desc = "shows the system name" }, { .toks = { "sysname", "reset" }, .func = l2cmd_sysname, .params = { 2 }, .desc = "resets the system name" }, { .toks = { "sysname", (char *)5 }, .func = l2cmd_sysname, .params = { 1 }, .desc = "set the system name" }, { .toks = { "shell|!" }, .func = l2cmd_shell, .desc = "escape to L3/L2 OS" }, { .toks = { "shell|!", (char *)6 }, .func = l2cmd_shell, .params = { 1 }, .desc = "send <command> to the L3/L2 OS" }, { .toks = { "version|ver" }, .func = l2cmd_version, .desc = "show L2 firmware version (use \"l1 version\" for L1 firmware revisions)" }, { .toks = { "version|ver", "v|verbose" }, .func = l2cmd_version, .params = { 1 }, .desc = "show L2 firmware version with L2 emulator and display firmware versions" }, { .toks = { "version|ver", "s|summary" }, .func = l2cmd_version_summary, .desc = "display summary of L1 and L2 firmware versions currently running in the system" }, { .toks = { "version|ver", "c|check" }, .func = l2cmd_version_summary, .params = { 1 }, .desc = "display any L1 or L2 firmware versions mismatches" }, { .toks = { (char *)10, "version|ver", "s|summary" }, .func = l2cmd_version_summary, .desc = "display summary of L1 and L2 firmware versions currently running in the system" }, { .toks = { (char *)10, "version|ver", "c|check" }, .func = l2cmd_version_summary, .params = { 1 }, .desc = "display any L1 or L2 firmware versions mismatches" }, { .toks = { "tty" }, .func = l2cmd_tty, .desc = "show tty configuration", .visibility = 1 }, { .toks = { (char *)11, (char *)6 }, .func = l2cmd_l1cmd, .params = { 1 }, .desc = "sends L1 command to selected L1" }, { .toks = { (char *)7, (char *)6 }, .func = l2cmd_l2cmd, .params = { 2 }, .desc = "sends L2 command to selected L2" }, { .toks = { (char *)10, (char *)6 }, .func = l2cmd_cmd, .params = { 1 }, .desc = "sends L2/L1 command to selected racks (and slots)" }, { .toks = { (char *)6 }, .func = l2cmd_cmd, .desc = "sends L2/L1 command to default destinations" } };

static int check_smp(SMP *smp, char **results)
{
  int iVar1;
  
  iVar1 = smp_is_valid(smp);
  if (iVar1 == 0) {
    response(results,0x78);
    sprintf(*results,
            "ERROR: this command must be run from an SMP (terminal) session (i.e. via l2term or telnet to the L2)\n"
           );
  }
  return (uint)(iVar1 != 0);
}

static void l2cmd_timeout(int to, void *data)
{
  L2CMD *c;
  
  c = (__typeof__(c))data;   /* Ghidra merged c into data */
  if (c->tofunc != 0) {
    (*c->tofunc)(data,to,c->data);
  }
  return;
}

static void l2cmd_etimeout(char *msg, void *data)
{
  L2CMD *c;
  
  c = (__typeof__(c))data;   /* Ghidra merged c into data */
  if (c->etofunc != 0) {
    (*c->etofunc)(data,msg,c->data);
  }
  return;
}

L2CMD *l2cmd_init(IRIdent *id, l2cmd_timeout_cb *tofunc, l2cmd_etimeout_cb *etofunc, l2cmd_response_cb *rspfunc, void *data)
{
  L2CMD *c;
  code *etofunc_00;
  code *tofunc_00;
  REQRSPQ *pRVar1;
  DEST *pDVar2;
  
  c = malloc(sizeof(L2CMD));
  memset(c,0,sizeof(L2CMD));
  c->id = id;
  if (etofunc == NULL) {
    etofunc_00 = NULL;
  }
  else {
    etofunc_00 = l2cmd_etimeout;
  }
  if (tofunc == NULL) {
    tofunc_00 = NULL;
  }
  else {
    tofunc_00 = l2cmd_timeout;
  }
  pRVar1 = reqrspq_init(tofunc_00,etofunc_00,c);
  c->q = pRVar1;
  pDVar2 = dest_init();
  c->dest = pDVar2;
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
  return;
}

int l2cmd_process(L2CMD *c, char *command, char **rptr, void *data)
{
  size_t sVar1;
  int iVar2;
  int status;
  
  if ((*command == '\0') || (sVar1 = strlen(command), sVar1 == 0)) {
    iVar2 = 0;
  }
  else {
    *rptr = NULL;
    iVar2 = CmdProcess(1,command,rptr,(Cmd *)&l2cmd_cmds,0xbe,c);
  }
  return iVar2;
}

int l2cmd_process_response(L2CMD *c, char *rsp, int rval)
{
  int iVar1;
  
  if (c->rspfunc == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = reqq_empty(c->q);
    if (iVar1 != 0) {
      iVar1 = rspq_empty(c->q);
      if (iVar1 != 0) {
        c->busy = c->busy & 0xfffffffe;
      }
    }
    (*(code *)c->rspfunc)(c,c->data,rsp,rval);
    iVar1 = 0;
  }
  return iVar1;
}

int l2cmd_queue_response(L2CMD *c, unsigned int seqn, IRAddress dest, int timeout)
{
  rspq_put(c->q,seqn,dest);
  if (timeout != 0) {
    rspq_timeout_set(c->q,timeout);
  }
  c->busy = c->busy | 1;
  return 0;
}

static int l2cmd_broadcast(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  int status;
  DEST orig_dest;
  
  status = -1;
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    response(results,0x140);
    memcpy(&orig_dest,c->dest,sizeof(DEST));
    dest_reset(c->dest);
    dest_l1(c->dest,NULL);
    iVar1 = strcmp(cptr->toks[0],"router");
    if (iVar1 == 0) {
      status = broadcast_l1(c,1,cptr->str_stack[0],1,0,1,NULL,1);
    }
    else {
      iVar1 = strcmp(cptr->toks[0],"io");
      if (iVar1 == 0) {
        status = broadcast_l1(c,1,cptr->str_stack[0],1,0,2,NULL,1);
      }
      else {
        iVar1 = strcmp(cptr->toks[0],"compute");
        if (iVar1 == 0) {
          status = broadcast_l1(c,1,cptr->str_stack[0],1,0,4,NULL,1);
        }
        else {
          iVar1 = strcmp(cptr->toks[0],"other");
          if (iVar1 == 0) {
            status = broadcast_l1(c,1,cptr->str_stack[0],1,0,0x80,NULL,1);
          }
        }
      }
    }
    memcpy(c->dest,&orig_dest,0x1188);
    if (status == 0) {
      iVar1 = 0;
    }
    else {
      strcpy(*results,"ERROR: no destination set.\n");
      iVar1 = -1;
    }
  }
  return iVar1;
}

static int l2cmd_autopower(CmdData *cptr, char **results)
{
  uint32 uVar1;
  char *pcVar2;
  int delay;
  
  response(results,0x50);
  switch(*cptr->params) {
  case 0:
    break;
  case 1:
    nvramSet(2,1);
    break;
  case 2:
    nvramSet(2,0);
    break;
  case 3:
    power_abort = 1;
    strcpy(*results,"auto power up abortd\n");
    return 0;
  case 4:
    if (cptr->exp_stack[0] < 0x1e) {
      strcpy(*results,"ERROR: minimum auto powerup delay is 30 seconds\n");
      return 0;
    }
    nvramSet(0x14,cptr->exp_stack[0]);
  }
  delay = nvramGet(0x14);
  if (delay < 0x1f) {
    delay = 0x1e;
  }
  uVar1 = nvramGet(2);
  if (uVar1 == 0) {
    pcVar2 = "disabled";
  }
  else {
    pcVar2 = "enabled";
  }
  sprintf(*results,"auto powerup %s\nauto powerup delay %d seconds\n",pcVar2,delay);
  return 0;
}

static int l2cmd_config(CmdData *cptr, char **results, L2CMD *c)
{
  char *pcVar1;
  size_t sVar2;
  size_t sVar3;
  char *pcVar4;
  time_t tVar5;
  __pid_t _Var6;
  int elapsed;
  int rval;
  char *ptr;
  char cmd [160];
  char fname [60];
  char *estr;
  char *cstr;
  char *rptr;
  int which;
  int p;
  
  switch(*cptr->params) {
  case 0:
    L2CfgMPrint(&L2CfgLocal,results,cptr->params[1],cptr->params[2]);
    break;
  case 1:
    if (cfg_auto_rescan == 0) {
      for (p = 0; (uint)p < 0x28; p = p + 1) {
        if (l2_l1_ports[p].fd != -1) {
          cfg_ping_l1(p);
        }
      }
      cfg_l2ping(0);
    }
    else {
      response(results,0xa0);
      strcpy(*results,"WARNING: config auto-scan is enabled; skipping manual rescan\n");
    }
    break;
  case 2:
    cfg_setup_configcheck(5);
    cfg_setup_l2ping(cfg_ping_l2_frequency);
    break;
  case 3:
    cfg_setup_configcheck(0);
    cfg_setup_l2ping(0);
    break;
  case 4:
    which = (int)(cptr->params[1] != 0);
    pcVar4 = L2CfgMQuery(&L2CfgLocal,which,1);
    pcVar4 = strdup(pcVar4);
    pcVar1 = L2CfgMQuery(&L2CfgLocal,which | 2,1);
    pcVar1 = strdup(pcVar1);
    sVar2 = strlen(pcVar4);
    sVar3 = strlen(pcVar1);
    response(results,sVar3 + sVar2 + 3);
    strcpy(*results,pcVar4);
    strcat(*results,"\n");
    strcat(*results,pcVar1);
    strcat(*results,"\n");
    free(pcVar4);
    free(pcVar1);
    break;
  case 5:
    L2CfgMPrintX(&L2CfgLocal,results);
    break;
  case 6:
    pcVar4 = malloc(0x50);
    *results = pcVar4;
    tVar5 = time(NULL);
    elapsed = tVar5 - cfg_start_time;
    _Var6 = getpid();
    sprintf(*results,"uptime: %5d:%02d:%02d pid: %d\n",elapsed / 0xe10,(elapsed % 0xe10) / 0x3c,
            elapsed % 0x3c,_Var6);
  }
  return 0;
}

static int l2cmd_connect(CmdData *cptr, char **results)
{
  int rval;
  int iVar1;
  
  response(results,0x50);
  rval = EnetServerConnect(cptr->str_stack[0],IR_PORT_BIAS + 0x2329);
  if (rval == 0) {
    sprintf(*results,"connection to %s initiated\n",cptr->str_stack[0]);
    iVar1 = 0;
  }
  else {
    sprintf(*results,"can\'t connect to %s, port %d\n",cptr->str_stack[0],IR_PORT_BIAS + 0x2329);
    iVar1 = -1;
  }
  return iVar1;
}

static int l2cmd_rtc(CmdData *cptr, char **results, L2CMD *c)
{
  static char *tzptr;
  uint uVar1;
  int *piVar2;
  char *pcVar3;
  struct tm *ptVar4;
  int rval;
  int iVar5;
  char buff [128];
  int scnt;
  char cmd [120];
  char *tzstr;
  time_t now;
  
  scnt = 0;
  response(results,0x78);
  uVar1 = *cptr->params;
  if (((uVar1 == 1) || (((uVar1 != 0 && (uVar1 < 5)) && (2 < uVar1)))) && (l2_pc == 0)) {
    sprintf(*results,"INFO: cannot set date/timezone when running the L2 emulator on a PC\n");
    return 0;
  }
  switch(*cptr->params) {
  case 0:
    goto switchD_080557f5_caseD_0;
  case 1:
    goto switchD_080557f5_caseD_1;
  case 2:
    pcVar3 = getenv("TZ");
    if (pcVar3 == NULL) {
      pcVar3 = "<not set>";
    }
    strcpy(*results,pcVar3);
    strcat(*results,"\n");
    break;
  case 4:
    scnt = 1;
  case 3:
    for (tzstr = cptr->str_stack[scnt]; *tzstr != '\0'; tzstr = tzstr + 1) {
      iVar5 = toupper((int)*tzstr);
      *tzstr = (char)iVar5;
    }
    nvramSet(0x11,(uintptr_t)cptr->str_stack[scnt]);
    iVar5 = 1;
    pcVar3 = (char *)nvramGet(0x11);
    setenv("TZ",pcVar3,iVar5);
    if (*cptr->params != 3) {
switchD_080557f5_caseD_1:
      sprintf(cmd,"(date %s; hwclock -u --systohc) >/dev/null 2>/dev/null",cptr->str_stack[0]);
      iVar5 = system(cmd);
      if ((iVar5 != 0) && ((iVar5 != -1 || (piVar2 = __errno_location(), *piVar2 != 10)))) {
        sprintf(*results,"ERROR: Invalid date \'%s\'\n",cptr->str_stack[0]);
        return 0;
      }
switchD_080557f5_caseD_0:
      now = time(NULL);
      ptVar4 = localtime(&now);
      strftime(*results,0x20,"%m/%d/%Y %X %Z\n",ptVar4);
    }
    break;
  case 5:
    now = time(NULL);
    sprintf(*results,"%d\n",now);
    break;
  case 6:
    sprintf(buff,"date sync %x",c);
    nvramLogInsert(buff);
    if (c == NULL) {
      return -1;
    }
    now = time(NULL);
    pcVar3 = getenv("TZ");
    ptVar4 = localtime(&now);
    strftime(cmd,0x78,"date %m%d%H%M%Y.%S ",ptVar4);
    if (pcVar3 == NULL) {
      pcVar3 = "";
    }
    strcat(cmd,pcVar3);
    rval = dest_l1(c->dest,cptr);
    if (rval == 0) {
      sprintf(*results,"WARNING: no L1s found to sync\n");
      return -1;
    }
    iVar5 = broadcast_l1(c,1,cmd,1,0,0xff,NULL,1);
    if (iVar5 != 0) {
      strcpy(*results,"ERROR: no destination set.\n");
      return -1;
    }
    dest_l2(c->dest,cptr);
    iVar5 = broadcast_l2(c,results,cmd,1,0,1);
    if (iVar5 != 0) {
      strcpy(*results,"ERROR: destination set.\n");
      return -1;
    }
    if (l2_pc == 0) {
      sprintf(*results,"WARNING: cannot sync timezone when running the L2 emulator on a PC\n");
    }
  }
  return 0;
}

static int l2cmd_demo(CmdData *cptr, char **results, L2CMD *c)
{
  uint uVar1;
  int iVar2;
  size_t sVar3;
  IRArgument rarg [2];
  IRAddress addr;
  int rval;
  
  if (c == NULL) {
    iVar2 = -1;
  }
  else {
    uVar1 = *cptr->params;
    if (uVar1 == 1) {
      rarg[0]._clas = '\0';
      rarg[0]._frame = '\0';
      rarg[0]._val = cptr->exp_stack[0];
      rarg[0]._size = 0;
      target_pkt(c,0x1ffff00b,1,1,rarg,1,0,1);
    }
    else if (uVar1 == 0) {
      target_pkt(c,0x1ffff00b,9,0,NULL,1,0,1);
    }
    else if (uVar1 == 2) {
      rarg[0]._clas = '\0';
      rarg[0]._frame = '\0';
      rarg[0]._val = cptr->exp_stack[0];
      rarg[0]._size = 0;
      rarg[1]._clas = '\x02';
      rarg[1]._frame = '\0';
      rarg[1]._val = IR_PTR_VAL(cptr->str_stack[0]);
      sVar3 = strlen(cptr->str_stack[0]);
      rarg[1]._size = (short)sVar3 + 1;
      target_pkt(c,0x1ffff00b,3,2,rarg,1,0,1);
    }
    iVar2 = 0;
  }
  return iVar2;
}

static int l2cmd_help(CmdData *cptr, char **results)
{
  if (*cptr->params == 0) {
    response(results,0x14f0);
    CmdHelpAll((Cmd *)&l2cmd_cmds,0xbe,cptr->params[1],*results);
    strcat(*results,
           "\nThe general form of a command is: <target> <command>\n\nA <target> (optional) has serveral forms:\n\n<rack>.<slot>        \n   targets a single L1\n<ip>:<port>:<l1>     \n   targets a single L1 without a rack and slot set\nrack|r <rng> [ slot|s <rng> ] \n   targets a group of racks and slots\npartition|p <rng>\n   targets a group of L1s in a partition\n\nA <rng> is a comma or dashed seperated list of numbers.  A <rng> of \"rack 2,4\"\ntargets racks 2 and 4.  A <rng> of \"rack 2-4\" targets racks 2, 3 and 4.\n\nA <rng> of \"*\" or \"all\" can be used to target all racks or slots.  An \"*\"\nor \"all\" alone targets all racks and slots depending on the command.\n\nIf no <target> is specfied and <command> is an L2 command it is executed on the\nlocal L2 only.  If the command is not understood by the L2, it is passed to all\nL1s in the default destination (the \"destination\" command shows the default \ndestinations).\n\nIf a <target> is specified and <command> is an L2 command it is executed on the\ntargeted L2s.  If the command is not understood by the L2, it is passed to all\nL1s in the target list.\n\nFor overlapping L2 and L1 commands, preceed the <command> with \"l1\" to over-\nride the L2 interpretation. \n"
          );
  }
  else if ((*cptr->params == 1) &&
          (CmdHelpCmd((Cmd *)&l2cmd_cmds,0xbe,cptr->str_stack[0],cptr->params[1],results),
          *results == NULL)) {
    response(results,0xa0);
    sprintf(*results,"ERROR: memory allocation error.\n");
    return -1;
  }
  return 0;
}

static int l2cmd_l2dbg(CmdData *cptr, char **results)
{
  char cVar1;
  static int socket_sbufsize;
  static int socket_rbufsize;
  static char *p;
  static char *s = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  char *pcVar2;
  size_t sVar3;
  char *pcVar4;
  int rval;
  undefined *puVar5;
  uint uVar6;
  int iVar7;
  uint32 uVar8;
  int byte;
  uchar fmt;
  int fd_;
  struct timeval cur_time;
  EventTimerEntry *e;
  uintptr_t dump_addr;
  int dump_len;
  int fd;
  char *rptr;
  
  uVar6 = *cptr->params;
  if (uVar6 == 0xf) {
    MInfoReset();
  }
  else if (uVar6 < 0x10) {
    if (uVar6 == 7) {
      l1usb_debug = cptr->exp_stack[0];
      nvramSet(10,l1usb_debug);
      pcVar2 = response(results,0x50);
      sprintf(pcVar2,"storing USB debug setting %d in NVRAM\n",l1usb_debug);
    }
    else if (uVar6 < 8) {
      if (uVar6 == 3) {
        pcVar2 = MemUsageBuf();
        sVar3 = strlen(pcVar2);
        response(results,sVar3 + 1);
        strcpy(*results,pcVar2);
      }
      else if (uVar6 < 4) {
        if (uVar6 == 1) {
          if (cptr->params[1] == 0) {
            irtr_debug = cptr->exp_stack[0];
          }
          else {
            pcVar2 = response(results,0x50);
            sprintf(pcVar2,"packets: total %d, outstanding %d, maximum %d\n",IRouterTotalPackets,
                    IRouterOutstandingPackets,IRouterMaxPackets);
          }
        }
        else if (uVar6 < 2) {
          IRouterDebugMallocFree = cptr->exp_stack[0];
        }
        else {
          L2CfgDebug = cptr->exp_stack[0];
        }
      }
      else if (uVar6 == 5) {
        broadcast_debug = cptr->exp_stack[0];
      }
      else if (uVar6 < 6) {
        smp_input_debug = cptr->exp_stack[0];
      }
      else {
        discover_debug = cptr->exp_stack[0];
      }
    }
    else if (uVar6 == 0xb) {
      pcVar2 = response(results,0x1000);
      gettimeofday((struct timeval *)&cur_time,NULL);
      sprintf(pcVar2,"%4d.%06d CURRENT TIME\n",cur_time.tv_sec,cur_time.tv_usec);
      sVar3 = strlen(pcVar2);
      pcVar2 = pcVar2 + sVar3;
      if (cfg_auto_rescan == 0) {
        puVar5 = "off";
      }
      else {
        puVar5 = "on";
      }
      sprintf(pcVar2,"L1 ping is %s\n",puVar5);
      sVar3 = strlen(pcVar2);
      rptr = pcVar2 + sVar3;
      for (e = EventTimerQueue; e != NULL; e = e->next) {
        sprintf(rptr,"%4d.%06d %s\n",(e->timer_value).tv_sec,(e->timer_value).tv_usec,e->desc);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      sprintf(rptr,"Event timer errors: %d\n",EventTimerErrors);
    }
    else if (uVar6 < 0xc) {
      if (uVar6 == 9) {
        socket_sbufsize = cptr->exp_stack[0];
        socket_rbufsize = cptr->exp_stack[1];
        rval = RouterSetBufferSize(socket_sbufsize,socket_rbufsize);
        if (rval < 0) {
          pcVar2 = response(results,100);
          pcVar4 = LoggerDefaultMessage(rval);
          sprintf(pcVar2,"ERROR: can\'t set buffer size, %s\n",pcVar4);
        }
      }
      else if (uVar6 < 10) {
        pcVar2 = response(results,100);
        pcVar4 = EventStats(cptr->params[1]);
        strcpy(pcVar2,pcVar4);
        strcat(pcVar2,"\n");
      }
      else {
        rptr = response(results,0x1000);
        for (fd = 0; fd < EventIOListSize; fd = fd + 1) {
          if ((EventIOList[fd].input_func != NULL) ||
             (EventIOList[fd].output_func != NULL)) {
            if (EventIOList[fd].output_desc[0] == '\0') {
              pcVar2 = "-";
            }
            else {
              pcVar2 = EventIOList[fd].output_desc;
            }
            if (EventIOList[fd].input_desc[0] == '\0') {
              pcVar4 = "-";
            }
            else {
              pcVar4 = EventIOList[fd].input_desc;
            }
            if ((EventIOList[fd].input_func == NULL) ||
               (EventIOList[fd].output_func == NULL)) {
              if (EventIOList[fd].input_func == NULL) {
                puVar5 = "-/O";
              }
              else {
                puVar5 = "I/-";
              }
            }
            else {
              puVar5 = "I/O";
            }
            sprintf(rptr,"%3d %s %s/%s\n",fd,puVar5,pcVar4,pcVar2);
            sVar3 = strlen(rptr);
            rptr = rptr + sVar3;
          }
        }
        sprintf(rptr,"Event I/O errors: %d\n",EventTimerErrors);
      }
    }
    else if (uVar6 == 0xd) {
      MInfoStatPrint(results);
    }
    else if (uVar6 < 0xe) {
      smp_console_debug = cptr->exp_stack[0];
    }
    else {
      MInfoMapPrint(results);
    }
  }
  else if (uVar6 == 0x17) {
    l1_throttle_freq = cptr->exp_stack[0];
  }
  else if (uVar6 < 0x18) {
    if (uVar6 == 0x13) {
      pcVar2 = RouterDumpQStats(NULL,NULL);
      *results = pcVar2;
    }
    else if (uVar6 < 0x14) {
      if (uVar6 == 0x11) {
        MInfoDisable();
      }
      else if (uVar6 < 0x12) {
        MInfoEnable(results);
      }
      else {
        if (p != NULL) {
          free(p);
        }
        p = malloc(cptr->exp_stack[0]);
        MInfoMapPrint(results);
      }
    }
    else if (uVar6 == 0x15) {
      load_debug = cptr->exp_stack[0];
      if (load_debug == 0) {
        if (load_timerid != 0) {
          EventRemoveTimeOut(load_timerid);
          load_timerid = 0;
        }
      }
      else if (load_timerid == 0) {
        load_timer();
      }
    }
    else if (uVar6 < 0x16) {
      RouterResetQStats(NULL);
    }
    else {
      l2_flow_hwater = cptr->exp_stack[0];
      l2_flow_lwater = cptr->exp_stack[1];
      l2_flow_setup(l2_flow_hwater,l2_flow_lwater);
    }
  }
  else if (uVar6 == 0x1b) {
    /* memory dump: the address is a 32-bit command argument (the i386 address space) */
    dump_addr = (uintptr_t)(uint)cptr->exp_stack[0];
    dump_len = cptr->exp_stack[1];
    cVar1 = *cptr->str_stack[0];
    rptr = response(results,(((uint)dump_len >> 3) + 1) * 0x50);
    while (dump_len != 0) {
      sprintf(rptr,"%08x: ",(uint)dump_addr);
      sVar3 = strlen(rptr);
      rptr = rptr + sVar3;
      byte = 0;
      for (; (byte < 0x10 && (dump_len != 0)); dump_len = dump_len + -1) {
        if (cVar1 == 'a') {
          iVar7 = isprint((uint)*(unsigned char *)dump_addr);
          if (iVar7 == 0) {
            uVar6 = 0x3f;
          }
          else {
            uVar6 = (uint)*(unsigned char *)dump_addr;
          }
          sprintf(rptr,"%c ",uVar6);
        }
        else {
          sprintf(rptr,"%02x ",(uint)*(unsigned char *)dump_addr);
        }
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
        byte = byte + 1;
        dump_addr = dump_addr + 1;
      }
      strcat(rptr,"\n");
      sVar3 = strlen(rptr);
      rptr = rptr + sVar3;
    }
  }
  else if (uVar6 < 0x1c) {
    if (uVar6 == 0x19) {
      target_response_timeout = cptr->exp_stack[0];
      nvramSet(0x18,target_response_timeout);
    }
    else if (uVar6 < 0x1a) {
      broadcast_response_timeout = cptr->exp_stack[0];
      nvramSet(0x17,broadcast_response_timeout);
    }
    else {
      l2_misc_debug = cptr->exp_stack[0];
    }
  }
  else if (uVar6 == 0x1d) {
    rptr = response(results,cptr->exp_stack[0] + 0x50);
    for (fd_ = 0; (uint)fd_ < cptr->exp_stack[0]; fd_ = fd_ + 0x40) {
      strcpy(rptr,s);
      pcVar2 = "\n";
      iVar7 = rand();
      strcpy(rptr + iVar7 % 0x3f,pcVar2);
      sVar3 = strlen(rptr);
      rptr = rptr + sVar3;
    }
  }
  else if (uVar6 < 0x1d) {
    smp_debug = cptr->exp_stack[0];
  }
  else if (uVar6 == 0xffffffff) {
    pcVar2 = response(results,700);
    sprintf(pcVar2,"irouter malloc debugging %d\n",IRouterDebugMallocFree);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"irouter packet debugging %d\n",irtr_debug);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"L2 configuration debugging %d\n",L2CfgDebug);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"SMP input debugging %d\n",smp_input_debug);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"console tracking debugging %d\n",smp_console_debug);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"broadcast debugging %d\n",broadcast_debug);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"discovery debugging %X\n",discover_debug);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    uVar8 = nvramGet(10);
    sprintf(pcVar2,"USB debugging %d\n",uVar8);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"L2 load debugging %d\n",load_debug);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"L2 net conn flow ctrl     hwater %d  lwater %d\n",l2_flow_hwater,l2_flow_lwater)
    ;
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    if (l1_throttle_timerid == 0) {
      pcVar4 = "disabled";
    }
    else {
      pcVar4 = "enabled";
    }
    sprintf(pcVar2,"L1 input throttle %s (%d msec)\n",pcVar4,l1_throttle_freq);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"socket send bufsize %d, receive bufsize %d\n",socket_sbufsize,socket_rbufsize);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"broadcast response timeout %d\n",broadcast_response_timeout);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"target response timeout %d\n",target_response_timeout);
    sVar3 = strlen(pcVar2);
    if (l2_misc_debug != 0) {
      sprintf(pcVar2 + sVar3,"L2 misc. debug flag 0x%08x\n",l2_misc_debug);
      strlen(pcVar2 + sVar3);
    }
  }
  return 0;
}

static void load_timer(void)
{
  usleep(100);
  load_timerid = EventAddTimeOut(0,(ulong)(1000000 / (longlong)load_debug),load_timer,(EventData)0x0
                                 ,"simulated L2 loading");
  return;
}

static int l2cmd_destination(CmdData *cptr, char **results, L2CMD *c)
{
  uint uVar1;
  int iVar2;
  size_t sVar3;
  char *pcVar4;
  char *pcVar5;
  int iVar6;
  int port_;
  int ip_;
  IRAddress l1addr;
  int slot;
  int rack;
  int addr;
  int l1;
  int port;
  int ip;
  char *rptr;
  
  if (c == NULL) {
    iVar2 = -1;
  }
  else {
    uVar1 = *cptr->params;
    if (uVar1 == 1) {
      rptr = response(results,0xa0);
      iVar2 = dest_l1(c->dest,cptr);
      if (iVar2 == 0) {
        sprintf(*results,"ERROR: no L1s found to match that destination\n");
        iVar2 = 0;
      }
      else {
        dest_default(c->dest,cptr);
        dest_l1(c->dest,NULL);
        sprintf(*results,"%d default destination(s) set\n",c->dest->count);
        iVar2 = 0;
      }
    }
    else if (uVar1 == 0) {
      dest_l1(c->dest,NULL);
      rptr = response(results,(c->dest->count + 1) * 0x28);
      dest_print(c->dest,rptr);
      strcat(rptr,"\n");
      sVar3 = strlen(rptr);
      rptr = rptr + sVar3;
      for (addr = 0; addr < c->dest->count; addr = addr + 1) {
        rack = c->dest->list[addr] >> 0x12 & 0x3ff;
        slot = c->dest->list[addr] >> 0xc & 0x3f;
        iVar2 = L2CfgMFindBrickIP(&L2CfgLocal,rack,slot,&ip_,&port_,&l1);
        if (iVar2 == -1) {
          sprintf(rptr,"invalid destination\n");
        }
        else {
          iVar2 = port_;
          iVar6 = l1;
          pcVar4 = SocketAddrStr(ip_);
          pcVar5 = format_address(c->dest->list[addr]);
          sprintf(rptr,"%s (%s:%d:%d)\n",pcVar5,pcVar4,iVar2,iVar6);
        }
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      iVar2 = 0;
    }
    else if (uVar1 == 2) {
      dest_reset(c->dest);
      rptr = response(results,0xa0);
      sprintf(*results,"default destination reset to all bricks and slots\n");
      iVar2 = 0;
    }
    else {
      iVar2 = 0;
    }
  }
  return iVar2;
}

static int l2cmd_env(CmdData *cptr, char **results, L2CMD *c)
{
  uint addr_00;
  int iVar1;
  L2CfgL1 *l1cfg;
  char *pcVar2;
  undefined *puVar3;
  size_t sVar4;
  bool bVar5;
  IRAddress l1addr;
  int l1_count;
  int msg_count;
  char *rptr;
  int addr;
  uint state;
  
  l1_count = 0;
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    if (*cptr->params == 0) {
      cptr = NULL;
    }
    iVar1 = dest_l1(c->dest,cptr);
    if (iVar1 == 0) {
      response(results,0xa0);
      sprintf(*results,"ERROR: no L1s found to match that destination\n");
      iVar1 = -1;
    }
    else {
      response(results,c->dest->count * 0xa0);
      rptr = *results;
      for (addr = 0; addr < c->dest->count; addr = addr + 1) {
        addr_00 = c->dest->list[addr];
        l1cfg = L2CfgMFindBrickCfg(&L2CfgLocal,addr_00 >> 0x12 & 0x3ff,addr_00 >> 0xc & 0x3f,0);
        if (l1cfg != NULL) {
          state = l1cfg->env_state;
          if (state == 0) {
            pcVar2 = L2CfgMAddrStr(&L2CfgLocal,addr_00,0);
            sprintf(rptr,"%s: environmental summary not supported\n",pcVar2);
            l1_count = l1_count + 1;
          }
          else if (state != 1) {
            l1_count = l1_count + 1;
            pcVar2 = L2CfgMAddrStr(&L2CfgLocal,addr_00,0);
            sprintf(rptr,"%s:",pcVar2);
            sVar4 = strlen(rptr);
            rptr = rptr + sVar4;
            if ((state & 2) == 0) {
              bVar5 = (state & 8) != 0;
              if (bVar5) {
                sprintf(rptr," auto powered down");
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
              }
              msg_count = (int)bVar5;
              if ((state & 0x10) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s power warning",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x20) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s power fault",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x40) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s temperature advisory",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x80) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s temperature critical",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x100) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s temperature fault",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x200) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s fan warning",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x400) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s fan fault",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x800) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s VRM fault",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x1000) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s 48V fault",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x40000000) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s test condition",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
                msg_count = msg_count + 1;
              }
              if ((state & 0x80000000) != 0) {
                if (msg_count == 0) {
                  puVar3 = "";
                }
                else {
                  puVar3 = ",";
                }
                sprintf(rptr,"%s other condition",puVar3);
                sVar4 = strlen(rptr);
                rptr = rptr + sVar4;
              }
              strcat(rptr,"\n");
            }
            else if ((state & 4) == 0) {
              sprintf(rptr," monitoring disabled\n");
            }
            else {
              sprintf(rptr," monitoring disabled on error\n");
            }
          }
          sVar4 = strlen(rptr);
          rptr = rptr + sVar4;
        }
      }
      if (l1_count == 0) {
        sprintf(rptr,"all environmental condition appear normal\n");
      }
      iVar1 = 0;
    }
  }
  return iVar1;
}

static int l2cmd_l1(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  char *pcVar2;
  IRAddress l1addr;
  int slot;
  int rack;
  int l1;
  int port;
  int ip;
  
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = check_smp(c->data,results);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      response(results,0xa0);
      if (*cptr->params == 0) {
        iVar1 = dest_l1(c->dest,NULL);
        if (iVar1 != 1) {
          sprintf(*results,"ERROR: default destination contains multiple L1 addresses\n");
          return -1;
        }
        l1addr = c->dest->list[0];
        smp_set_l1addr(c->data,l1addr);
      }
      else if (*cptr->params == 1) {
        iVar1 = dest_l1(c->dest,cptr);
        if (iVar1 == 0) {
          sprintf(*results,"ERROR: no L1s found to match that destination\n");
          return -1;
        }
        if (iVar1 != 1) {
          sprintf(*results,"ERROR: current destination contains multiple L1 addresses\n");
          return -1;
        }
        l1addr = c->dest->list[0];
        smp_set_l1addr(c->data,l1addr);
      }
      smp_set_mode(c->data,3);
      pcVar2 = format_address(l1addr);
      sprintf(*results,"entering L1 mode %s, <CTRL-T> to escape to L2\n",pcVar2);
      iVar1 = 0;
    }
  }
  return iVar1;
}

static int l2cmd_l2(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = check_smp(c->data,results);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      response(results,0xa0);
      if (*cptr->params == 0) {
        smp_set_mode(c->data,0);
        strcpy(*results,"L2 command processor engaged, <CTRL-D> for console mode.\n");
      }
      else if (*cptr->params == 1) {
        strcpy(*results,"INFO: remote L2 mode not yet supported.\n");
        return -1;
      }
      iVar1 = 0;
    }
  }
  return iVar1;
}

static int l2cmd_loopback(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  IRAddress addr;
  uint length;
  uint count;
  SMP *smp;
  
  response(results,0xa0);
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = check_smp(c->data,results);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = dest_l1(c->dest,cptr);
      if (iVar1 == 0) {
        sprintf(*results,"ERROR: no L1s found to match that destination\n");
        iVar1 = -1;
      }
      else if ((iVar1 == 1) || (*cptr->params == 2)) {
        if (*cptr->params == 1) {
          lpbk(cptr->exp_stack[0],c->dest->list[0],cptr->exp_stack[1],cptr->exp_stack[2],c->data);
        }
        else if (*cptr->params == 2) {
          smp = c->data;
          count = cptr->exp_stack[1];
          length = cptr->exp_stack[0];
          addr = smp_get_conaddr(c->data,NULL,NULL);
          lpbk(smp->grp->partition,addr,length,count,smp);
        }
        else {
          lpbk(0,c->dest->list[0],cptr->exp_stack[0],cptr->exp_stack[1],c->data);
        }
        iVar1 = 0;
      }
      else {
        sprintf(*results,"ERROR: default destination contains multiple L1 addresses\n");
        iVar1 = -1;
      }
    }
  }
  return iVar1;
}

static int l2cmd_route(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  
  response(results,0xa0);
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = check_smp(c->data,results);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = dest_l1(c->dest,cptr);
      if (iVar1 == 0) {
        sprintf(*results,"ERROR: no L1s found to match that destination\n");
        iVar1 = -1;
      }
      else if (iVar1 == 1) {
        route_process_request(c->dest->list[0],c->data);
        iVar1 = 0;
      }
      else {
        sprintf(*results,"ERROR: default destination contains multiple L1 addresses\n");
        iVar1 = -1;
      }
    }
  }
  return iVar1;
}

static int l2cmd_hreboot_l1(CmdData *cptr, char **results, L2CMD *c)
{
  uint uVar1;
  int iVar2;
  IRArgument argv [1];
  IRAddress addr;
  IRPacket *p;
  
  response(results,0xa0);
  if (c == NULL) {
    iVar2 = -1;
  }
  else {
    iVar2 = dest_l1(c->dest,cptr);
    if (iVar2 == 0) {
      sprintf(*results,"ERROR: no L1s found to match that destination\n");
      iVar2 = -1;
    }
    else if (iVar2 == 1) {
      uVar1 = c->dest->list[0];
      if ((uVar1 & 0x80000000) == 0) {
        addr = uVar1 & 0xffffffe0 | 6;
      }
      else {
        addr = uVar1 & 0xc0ffffff | 0x6000000;
      }
      argv[0]._clas = '\0';
      argv[0]._frame = '\0';
      argv[0]._val = 0x4002;
      argv[0]._size = 0;
      p = IRouterMakePacket(c->id,&addr,0,0,0,2,1,argv);
      IRouterSendPacket(NULL,p);
      iVar2 = 0;
    }
    else {
      sprintf(*results,"ERROR: default destination contains multiple L1 addresses\n");
      iVar2 = -1;
    }
  }
  return iVar2;
}

static int l2cmd_nvram(CmdData *cptr, char **results)
{
  response(results,0xa0);
  nvramReset();
  strcpy(*results,"nvram contents cleared, reboot required (some NVRAM values are cached)");
  return 0;
}

int l2cmd_power(CmdData *cptr, char **results, L2CMD *c)
{
  uint8 uVar1;
  uint uVar2;
  static int delay = 500;
  int iVar3;
  CmdData *cptr_00;
  uint32 uVar4;
  IRPacket *pkt;
  size_t sVar5;
  L2CfgL1 *l1cfg;
  char *rptr;
  int pmode;
  char *pcVar6;
  undefined *puVar7;
  uint8 *puVar8;
  uint8 *puVar9;
  bool bVar10;
  IRAddress l1addr;
  int addr__;
  int margin_other;
  char *cptr__;
  IRAddress addr_;
  int found;
  uint8 slist [25];
  char *pwrcmd;   /* Ghidra: 'addr' (a reused stack slot) */
  DEST orig_dest_;
  char *cptr_;
  IRAddress addr;
  int argc;
  IRArgument argv [2];
  IRPacket *p;
  int port;
  L2Cfg *node;
  DEST orig_dest;
  int slots [50];
  int slot;
  int flags;
  int i;
  
  flags = 0;
  if (c == NULL) {
    iVar3 = -1;
  }
  else {
    response(results,0x140);
    cptr_00 = cptr;
    if (*cptr->params == 0) {
      cptr_00 = NULL;
    }
    iVar3 = dest_l1(c->dest,cptr_00);
    if (iVar3 == 0) {
      sprintf(*results,"ERROR: no L1s found to match that destination\n");
      iVar3 = -1;
    }
    else {
      switch(cptr->params[1]) {
      case 0:
        iVar3 = broadcast_l1(c,1,"power check",1,0,0xff,NULL,1);
        if (iVar3 != 0) {
          strcpy(*results,"ERROR: no destination set.\n");
          return -1;
        }
        break;
      case 1:
        iVar3 = dest_pcheck(c->dest,cptr,*results);
        if (iVar3 != 0) {
          return -1;
        }
        memcpy(&orig_dest,c->dest,sizeof(DEST));
        l2cmd_process(c,"ver check",results,NULL);
        memcpy(c->dest,&orig_dest,0x1188);
        uVar4 = nvramGet(0x15);
        if (uVar4 == 0) {
          pwrcmd = "power up hold";
          bVar10 = c->dest->type == 2;
          if (bVar10) {
            flags = 0x10000;
            memcpy(&orig_dest_,c->dest,sizeof(DEST));
            dest_reset(c->dest);
            dest_l1(c->dest,NULL);
            pwrcmd = "power up";
          }
          for (i = 0; i < 2; i = i + 1) {
            {
              /* the original's initializer for a local 'uint8 slist[25]' */
              static const uint8 slist_init[25] = { 1, 2, 5, 6, 9, 10, 13, 14, 17, 18, 21, 22, 25, 26, 29, 30, 33, 34, 37, 38, 41, 42, 45, 46, 49 };
              memcpy(slist, slist_init, sizeof(slist_init));
            }
            for (slot = 0; (uint)slot < 0x19; slot = slot + 1) {
              slots[slot] = (uint)slist[slot] + i * 2;
            }
            slots[slot] = -1;
            iVar3 = broadcast_l1(c,1,pwrcmd,1,0,flags | 1,slots,0);
            if (iVar3 != 0) {
              strcpy(*results,"ERROR: no destination set.\n");
              return -1;
            }
          }
          if (bVar10) {
            memcpy(c->dest,&orig_dest_,0x1188);
            if (*cptr->params == 0) {
              cptr = NULL;
            }
            dest_l1(c->dest,cptr);
          }
        }
        else if (c->dest->type == 2) {
          for (node = &L2CfgLocal; node != NULL; node = (L2Cfg *)(node->net).next) {
            for (port = 0; port < 0x28; port = port + 1) {
              if ((((node->port_list[port].state == 2) &&
                   ((node->port_list[port].l1cfg)->configured != '\0')) &&
                  (((node->port_list[port].l1cfg)->type == 'R' ||
                   (((node->port_list[port].l1cfg)->type == 'D' ||
                    ((node->port_list[port].l1cfg)->type == '-')))))) &&
                 ((node->port_list[port].l1cfg)->power_state == '\0')) {
                addr = ((uint)(node->port_list[port].l1cfg)->rack << 6 |
                       (uint)((node->port_list[port].l1cfg)->slot & 0x3f)) << 0xc | 3;
                argv[1]._val = IR_PTR_VAL(strdup("power up"));
                argv[0]._clas = '\0';
                argv[0]._frame = '\0';
                argv[0]._val = 0;
                argv[0]._size = 0;
                argv[1]._clas = '\n';
                argv[1]._frame = '\0';
                sVar5 = strlen((char *)IR_VAL_PTR(argv[1]._val));
                argv[1]._size = (short)sVar5 + 1;
                pkt = IRouterMakePacket(c->id,&addr,0,0,0,2,2,argv);
                reqq_put(c->q,pkt,1,0);
                reqq_put(c->q,NULL,0,-1);
                reqq_put(c->q,NULL,0,delay);
              }
            }
          }
        }
        else {
          iVar3 = broadcast_l1(c,2,"power up hold",1,0,1,NULL,0);
          if (iVar3 != 0) {
            strcpy(*results,"ERROR: no destination set.\n");
            return -1;
          }
        }
        for (slot = 1; slot < 0x29; slot = slot + 1) {
          slots[slot + -1] = slot;
          slots[slot] = -1;
        }
        iVar3 = broadcast_l1(c,1,"power up hold",1,delay,2,slots,0);
        if (iVar3 != 0) {
          strcpy(*results,"ERROR: no destination set.\n");
          return -1;
        }
        iVar3 = broadcast_l1(c,1,"power up hold",1,delay * 2,0x84,slots,0);
        if (iVar3 != 0) {
          strcpy(*results,"ERROR: no destination set.\n");
          return -1;
        }
        iVar3 = broadcast_l1(c,1,"reset",1,0,0xff,NULL,1);
        if (iVar3 != 0) {
          strcpy(*results,"ERROR: no destination set.\n");
          return -1;
        }
        break;
      case 2:
        iVar3 = dest_pcheck(c->dest,cptr,*results);
        if (iVar3 != 0) {
          return -1;
        }
        if (c->dest->type == 2) {
          /* power routers down only when every other brick outside the destination is off */
          int others = 0, others_off = 0;
          L2CfgL1 *l1c;
          for (node = &L2CfgLocal; node != NULL; node = (L2Cfg *)(node->net).next) {
            for (port = 0; port < 0x28; port = port + 1) {
              if (node->port_list[port].state == 2) {
                for (argc = 0; argc < node->port_list[port].l1count; argc = argc + 1) {
                  l1c = &node->port_list[port].l1cfg[argc];
                  found = 0;
                  if (l1c->configured != '\0' && l1c->type != 'R' && l1c->type != 'D' &&
                      l1c->type != '-') {
                    for (addr__ = 0; found == 0 && addr__ < c->dest->count; addr__ = addr__ + 1) {
                      if ((c->dest->list[addr__] >> 0x12 & 0x3ff) == (uint)l1c->rack &&
                          (c->dest->list[addr__] >> 0xc & 0x3f) == (uint)l1c->slot) {
                        found = 1;
                      }
                    }
                    if (found == 0) {
                      others = others + 1;
                      if (l1c->power_state == '\0') {
                        others_off = others_off + 1;
                      }
                    }
                  }
                }
              }
            }
          }
          if (others_off == others) {
            for (node = &L2CfgLocal; node != NULL; node = (L2Cfg *)(node->net).next) {
              for (port = 0; port < 0x28; port = port + 1) {
                if (node->port_list[port].state == 2) {
                  for (argc = 0; argc < node->port_list[port].l1count; argc = argc + 1) {
                    l1c = &node->port_list[port].l1cfg[argc];
                    if (l1c->configured != '\0' &&
                        (l1c->type == 'R' || l1c->type == 'D' || l1c->type == '-') &&
                        l1c->power_state != '\0') {
                      addr_ = ((uint)l1c->rack << 6 | (uint)(l1c->slot & 0x3f)) << 0xc | 3;
                      argv[1]._val = IR_PTR_VAL(strdup("power down"));
                      argv[0]._clas = '\0';
                      argv[0]._frame = '\0';
                      argv[0]._val = 0;
                      argv[0]._size = 0;
                      argv[1]._clas = '\n';
                      argv[1]._frame = '\0';
                      sVar5 = strlen((char *)IR_VAL_PTR(argv[1]._val));
                      argv[1]._size = (short)sVar5 + 1;
                      pkt = IRouterMakePacket(c->id,&addr_,0,0,0,2,2,argv);
                      reqq_put(c->q,pkt,1,0);
                    }
                  }
                }
              }
            }
          }
        }
        iVar3 = broadcast_l1(c,1,"power down",1,0,0xff,NULL,1);
        if (iVar3 != 0) {
          strcpy(*results,"ERROR: no destination set.\n");
          return -1;
        }
        break;
      case 3:
        {
          int on = 0, off = 0, other = 0;
          int m_default = 0, m_low = 0, m_normal = 0, m_high = 0, m_custom = 0, m_other = 0;
          pcVar6 = *results;
          for (addr__ = 0; addr__ < c->dest->count; addr__ = addr__ + 1) {
            uVar2 = c->dest->list[addr__];
            l1cfg = L2CfgMFindBrickCfg(&L2CfgLocal,uVar2 >> 0x12 & 0x3ff,uVar2 >> 0xc & 0x3f,0);
            if (l1cfg != NULL) {
              /* ORIGINAL BUG: power_state is a uint8, so the original's 'case -1' (other) never matches */
              if (l1cfg->power_state == 0) {
                off = off + 1;
              }
              else if (l1cfg->power_state == 1) {
                on = on + 1;
              }
              switch(l1cfg->margin_state) {
              case '\0':
                m_default = m_default + 1;
                break;
              case '\x01':
                m_low = m_low + 1;
                break;
              case '\x02':
                m_normal = m_normal + 1;
                break;
              case '\x03':
                m_high = m_high + 1;
                break;
              case '\x04':
                m_custom = m_custom + 1;
                break;
              case '\x05':
                m_other = m_other + 1;
              }
            }
          }
          if (other + off == 0) {
            sprintf(pcVar6,"all %d bricks appear powered on\n",c->dest->count);
          }
          else if (other + on == 0) {
            sprintf(pcVar6,"all %d bricks appear powered off\n",c->dest->count);
          }
          else {
            sprintf(pcVar6,"power: %d on, %d off, %d other\n",on,off,other);
          }
          pcVar6 = pcVar6 + strlen(pcVar6);
          if (m_custom + m_normal + m_other + m_high + m_default == 0) {
            sprintf(pcVar6,"all %d bricks appear margined low\n",c->dest->count);
          }
          else if (m_custom + m_other + m_default + m_low + m_high == 0) {
            sprintf(pcVar6,"all %d bricks appear margined normal\n",c->dest->count);
          }
          else if (m_custom + m_normal + m_other + m_default + m_low == 0) {
            sprintf(pcVar6,"all %d bricks appear margined high\n",c->dest->count);
          }
          else {
            sprintf(pcVar6,"margin: %d default, %d low, %d normal, %d high, %d custom, %d other\n",
                    m_default,m_low,m_normal,m_high,m_custom,m_other);
          }
        }
        break;
      case 4:
        sprintf(*results,"delay is set to %d milliseconds\n",delay);
        break;
      case 5:
        delay = cptr->exp_stack[0];
        break;
      case 6:
        pmode = nvramGet(0x15);
        if (pmode == 0) {
          pcVar6 = "parallel";
          puVar7 = "fast";
        }
        else {
          pcVar6 = "series";
          puVar7 = "slow";
        }
        sprintf(*results,"power up mode is %s (power up RTRs in %s)\n",puVar7,pcVar6);
        break;
      case 7:
        nvramSet(0x15,(uint)(*cptr->toks[2] == 's'));
      }
      iVar3 = 0;
    }
  }
  return iVar3;
}

static int l2cmd_reset(CmdData *cptr, char **results, L2CMD *c)
{
  static int delay = 500;
  int iVar1;
  CmdData *cptr_00;
  DEST orig_dest;
  int slots [50];
  int slot;
  
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    response(results,0x140);
    cptr_00 = cptr;
    if (*cptr->params == 0) {
      cptr_00 = NULL;
    }
    iVar1 = dest_l1(c->dest,cptr_00);
    if (iVar1 == 0) {
      sprintf(*results,"ERROR: no L1s found to match that destination\n");
      iVar1 = -1;
    }
    else {
      iVar1 = dest_pcheck(c->dest,cptr,*results);
      if (iVar1 == 0) {
        memcpy(&orig_dest,c->dest,sizeof(DEST));
        l2cmd_process(c,"ver check",results,NULL);
        memcpy(c->dest,&orig_dest,0x1188);
        iVar1 = broadcast_l1(c,1,"reset",1,0,0xff,NULL,1);
        if (iVar1 == 0) {
          iVar1 = 0;
        }
        else {
          strcpy(*results,"ERROR: no destination set.\n");
          iVar1 = -1;
        }
      }
      else {
        iVar1 = -1;
      }
    }
  }
  return iVar1;
}

static int l2cmd_rackid(CmdData *cptr, char **results)
{
  response(results,0x140);
  if (*cptr->params == 0) {
    sprintf(*results,"rack ID is %d\n",L2CfgLocal.rack);
  }
  else if (*cptr->params == 1) {
    nvramSet(1,cptr->exp_stack[0]);
    L2CfgMEventRack(&L2CfgLocal);
    sprintf(*results,"rack ID set to %d\n",L2CfgLocal.rack);
  }
  return 0;
}

static int l2cmd_password(CmdData *cptr, char **results, L2CMD *c)
{
  uint uVar1;
  char *pcVar2;
  char *pw;
  int iVar3;
  int pw_changed;
  
  response(results,0x140);
  uVar1 = *cptr->params;
  if (uVar1 == 1) {
    nvramSet(0x13,(uintptr_t)cptr->str_stack[0]);
    sprintf(*results,"L2 password changed\n");
  }
  else if (uVar1 == 0) {
    pcVar2 = (char *)nvramGet(0x13);
    if ((pcVar2 == NULL) || (*pcVar2 == '\0')) {
      sprintf(*results,"No L2 password set\n");
    }
    else {
      sprintf(*results,"L2 password set (password is required to access this L2)\n");
    }
  }
  else if (uVar1 < 4) {
    pw = (char *)nvramGet(0x13);
    if ((*cptr->params == 3) && (iVar3 = strcmp(pw,cptr->str_stack[0]), iVar3 != 0)) {
      sprintf(*results,"ERROR: password specified is not the current L2 password.\n");
      return -1;
    }
    nvramSet(0x13,(uintptr_t)"");   /* clear the password */
    sprintf(*results,"L2 password cleared\n");
  }
  return 0;
}

int pbay_rsp(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data)
{
  int *piVar1;
  void *pvVar2;
  char *serial;
  uint uVar3;
  char *pcVar4;
  size_t sVar5;
  char *pcVar6;
  char *pcVar7;
  int iVar8;
  char cmd [100];
  char *errstr;
  L2CMD *dc;
  char *rptr;
  char emsg [100];
  int i;
  pbay_data *pd;
  
  pd = (__typeof__(pd))data;   /* Ghidra merged pd into data */
  emsg[0] = '\0';
  memset(emsg + 1,0,99);
  strlen(cmd_rsp->sptr);
  if (pd->snlist == 0) {
    pvVar2 = calloc(pktsleft + 1,sizeof(*pd->snlist));
    pd->snlist = pvVar2;
    pvVar2 = calloc(pktsleft + 1,sizeof(*pd->snconns));
    pd->snconns = pvVar2;
    pvVar2 = calloc(pktsleft + 1,sizeof(*pd->snnum));
    pd->snnum = pvVar2;
    pvVar2 = calloc(pktsleft + 1,sizeof(*pd->snaddr));
    pd->snaddr = pvVar2;
  }
  if (rsp == NULL) {
    serial = format_address(*dest);
    sprintf(emsg,"ERROR: no response from %s\n",serial);
  }
  else if (rsp->_err == '\0') {
    if (pd->stage == 0) {
      if ((rsp->_argv[0]._clas & 7) == 0) {
        uVar3 = rsp->_argv[0]._val;
      }
      else {
        uVar3 = IRArg(rsp,0);
      }
      if (uVar3 != 0) {
        if ((rsp->_argv[1]._clas & 7) == 0) {
          pcVar4 = (char *)IR_VAL_PTR(rsp->_argv[1]._val);
        }
        else {
          pcVar4 = (char *)IRArg(rsp,1);
        }
        sVar5 = strlen(pcVar4);
        if (pcVar4[sVar5 - 1] == '\n') {
          sVar5 = strlen(pcVar4);
          pcVar4[sVar5 - 1] = '\0';
        }
        pcVar6 = format_address(*dest);
        sprintf(emsg,"%s:  %s\n",pcVar6,pcVar4);
        goto LAB_08059522;
      }
    }
    if ((pd->stage == 0) && (rsp->_argc < 2)) {
      pcVar4 = format_address(*dest);
      sprintf(emsg,"%s:  Pbay busy initializing or PBay communication failure\n",pcVar4);
    }
    else if (pd->stage == 0) {
      if ((rsp->_argv[1]._clas & 7) == 0) {
        pcVar4 = (char *)IR_VAL_PTR(rsp->_argv[1]._val);
      }
      else {
        pcVar4 = (char *)IRArg(rsp,1);
      }
      sVar5 = strlen(pcVar4);
      if (pcVar4[sVar5 - 1] == '\n') {
        sVar5 = strlen(pcVar4);
        pcVar4[sVar5 - 1] = '\0';
      }
      for (i = 0; i < pd->sncnt; i = i + 1) {
        iVar8 = strcmp(pd->snlist[i],pcVar4);
        if (iVar8 == 0) {
          piVar1 = &pd->snnum[i];
          *piVar1 = *piVar1 + 1;
          break;
        }
      }
      if (i == pd->sncnt) {
        pcVar4 = strdup(pcVar4);
        pd->snlist[i] = pcVar4;
        pvVar2 = calloc(100,1);
        pd->snconns[i] = pvVar2;
        piVar1 = &pd->snnum[i];
        *piVar1 = *piVar1 + 1;
        pd->snaddr[i] = *dest;
        pd->sncnt = pd->sncnt + 1;
      }
      pcVar4 = format_address(*dest);
      strcat(pd->snconns[i],pcVar4);
      strcat(pd->snconns[i]," ");
    }
  }
  else {
    pcVar4 = IRFmtError((uint)rsp->_err);
    pcVar6 = format_address(*dest);
    sprintf(emsg,"ERROR: couldn\'t send packet to %s, %s\n",pcVar6,pcVar4);
  }
LAB_08059522:
  if (pd->stage == 0) {
    if (emsg[0] != '\0') {
      if (pd->errcnt == 0) {
        pcVar4 = cmd_rsp->eptr;
        if (cmd_rsp->eptr == NULL) {
          pcVar4 = "";
        }
        sVar5 = strlen(pcVar4);
        iVar8 = sVar5 + cmd_rsp->slen;
        cmd_rsp->slen = iVar8;
        if (cmd_rsp->size <= iVar8 + 0x74) {
          sVar5 = cmd_rsp->size + 0x264;
          cmd_rsp->size = sVar5;
          pcVar4 = realloc(cmd_rsp->sptr,sVar5);
          cmd_rsp->sptr = pcVar4;
        }
        cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
        pcVar4 = cmd_rsp->sptr;
        iVar8 = cmd_rsp->slen;
        sprintf(pcVar4 + iVar8,
                "WARNING: ERRORS while reading PowerBay serial numbers from L1 Controllers:\n");
        strlen(pcVar4 + iVar8);
      }
      pd->errcnt = pd->errcnt + 1;
      pcVar4 = cmd_rsp->eptr;
      if (cmd_rsp->eptr == NULL) {
        pcVar4 = "";
      }
      sVar5 = strlen(pcVar4);
      iVar8 = sVar5 + cmd_rsp->slen;
      cmd_rsp->slen = iVar8;
      sVar5 = strlen(emsg);
      if ((uint)cmd_rsp->size <= sVar5 + iVar8 + 0x14) {
        iVar8 = cmd_rsp->size;
        sVar5 = strlen(emsg);
        sVar5 = sVar5 + iVar8 + 0x204;
        cmd_rsp->size = sVar5;
        pcVar4 = realloc(cmd_rsp->sptr,sVar5);
        cmd_rsp->sptr = pcVar4;
      }
      cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
      pcVar4 = cmd_rsp->sptr + cmd_rsp->slen;
      strcat(pcVar4,"    ");
      strcat(pcVar4,emsg);
      strlen(pcVar4);
    }
  }
  else {
    for (i = 0; (i < pd->sncnt &&
                (pd->snaddr[i] != *dest)); i = i + 1) {
    }
    pcVar4 = cmd_rsp->eptr;
    if (cmd_rsp->eptr == NULL) {
      pcVar4 = "";
    }
    sVar5 = strlen(pcVar4);
    iVar8 = sVar5 + cmd_rsp->slen;
    cmd_rsp->slen = iVar8;
    if (cmd_rsp->size <= iVar8 + 0x42) {
      sVar5 = cmd_rsp->size + 0x232;
      cmd_rsp->size = sVar5;
      pcVar4 = realloc(cmd_rsp->sptr,sVar5);
      cmd_rsp->sptr = pcVar4;
    }
    cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
    pcVar4 = cmd_rsp->sptr + cmd_rsp->slen;
    if (i == pd->sncnt) {
      pcVar6 = "?????????????";
    }
    else {
      pcVar6 = pd->snlist[i];
    }
    pcVar7 = format_address(*dest);
    sprintf(pcVar4,"%s:   [PowerBay %s]\n",pcVar7,pcVar6);
    sVar5 = strlen(pcVar4);
    rptr = pcVar4 + sVar5;
    if (emsg[0] == '\0') {
      cmd_process_packet_args(rsp,c,dest,cmd_rsp,0);
    }
    else {
      pcVar4 = cmd_rsp->eptr;
      if (cmd_rsp->eptr == NULL) {
        pcVar4 = "";
      }
      sVar5 = strlen(pcVar4);
      iVar8 = sVar5 + cmd_rsp->slen;
      cmd_rsp->slen = iVar8;
      sVar5 = strlen(emsg);
      if ((uint)cmd_rsp->size <= sVar5 + iVar8 + 0x10) {
        iVar8 = cmd_rsp->size;
        sVar5 = strlen(emsg);
        sVar5 = sVar5 + iVar8 + 0x200;
        cmd_rsp->size = sVar5;
        pcVar4 = realloc(cmd_rsp->sptr,sVar5);
        cmd_rsp->sptr = pcVar4;
      }
      cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
      rptr = cmd_rsp->sptr + cmd_rsp->slen;
      strcat(rptr,emsg);
    }
    strlen(rptr);
  }
  if (pktsleft == 0) {
    pcVar4 = cmd_rsp->eptr;
    if (cmd_rsp->eptr == NULL) {
      pcVar4 = "";
    }
    sVar5 = strlen(pcVar4);
    iVar8 = sVar5 + cmd_rsp->slen;
    cmd_rsp->slen = iVar8;
    if (cmd_rsp->size <= iVar8 + pd->sncnt * 0x50 + 0x10) {
      sVar5 = cmd_rsp->size + 0x200 + pd->sncnt * 0x50;
      cmd_rsp->size = sVar5;
      pcVar4 = realloc(cmd_rsp->sptr,sVar5);
      cmd_rsp->sptr = pcVar4;
    }
    cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
    rptr = cmd_rsp->sptr + cmd_rsp->slen;
    if ((pd->errcnt == 0) && (cmd_rsp->status != -1)) {
      iVar8 = 0;
    }
    else {
      iVar8 = -1;
    }
    cmd_rsp->status = iVar8;
    if ((pd->stage == 0) && (pd->errcnt != 0)) {
      strcat(rptr,"\n");
      sVar5 = strlen(rptr);
      rptr = rptr + sVar5;
    }
    if (pd->cmd == 0) {
      for (i = 0; i < pd->sncnt; i = i + 1) {
        sprintf(rptr,"PowerBay %s: %s\n",pd->snlist[i],
                pd->snconns[i]);
        sVar5 = strlen(rptr);
        rptr = rptr + sVar5;
      }
    }
    else if ((pd->stage == 0) && (0 < pd->sncnt)) {
      sprintf(cmd,"pbay %s",pd->cmd);
      dest_reset(c->dest);
      memcpy(c->dest->list,pd->snaddr,pd->sncnt * 4);
      c->dest->count = pd->sncnt;
      c->dest->type = 1;
      pd->stage = 1;
      reqrspq_reset(c->q);
      broadcast_l1(c,1,cmd,1,0,0xff,NULL,1);
      if (0 < c->q->rspq_pending) {
        return 0;
      }
      pcVar4 = cmd_rsp->eptr;
      if (cmd_rsp->eptr == NULL) {
        pcVar4 = "";
      }
      sVar5 = strlen(pcVar4);
      iVar8 = sVar5 + cmd_rsp->slen;
      cmd_rsp->slen = iVar8;
      if (cmd_rsp->size <= iVar8 + 0x60) {
        sVar5 = cmd_rsp->size + 0x250;
        cmd_rsp->size = sVar5;
        pcVar4 = realloc(cmd_rsp->sptr,sVar5);
        cmd_rsp->sptr = pcVar4;
      }
      cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
      strcat(cmd_rsp->sptr + cmd_rsp->slen,
             "ERROR: pbay command not sent to any L1\'s due to previous errors!\n");
      cmd_rsp->status = -1;
    }
    pd->orig_c->busy =
         pd->orig_c->busy & 0xfffffffd;
    l2cmd_process_response(pd->orig_c,cmd_rsp->sptr,cmd_rsp->status);
    for (i = 0; i < pd->sncnt; i = i + 1) {
      free(pd->snlist[i]);
      free(pd->snconns[i]);
    }
    free(pd->snlist);
    free(pd->snconns);
    free(pd->snnum);
    free(pd->snaddr);
    if (pd->cmd != 0) {
      free(pd->cmd);
    }
    free(data);
  }
  return 0;
}

static int l2cmd_pbay(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  void *data;
  char *pcVar2;
  CmdData *cptr_00;
  L2CMD *tc;
  pbay_data *pd;
  
  response(results,0x140);
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    data = calloc(sizeof(pbay_data),1);
    if (data == NULL) {
      strcpy(*results,"ERROR: could not allocate memory to store internal command data\n");
      iVar1 = -1;
    }
    else {
      ((pbay_data *)data)->orig_c = c;
      if (cptr->str_max != 0) {
        pcVar2 = strdup(cptr->str_stack[0]);
        ((pbay_data *)data)->cmd = pcVar2;
      }
      cptr_00 = cptr;
      if (*cptr->params == 0) {
        cptr_00 = NULL;
      }
      iVar1 = dest_l1(c->dest,cptr_00);
      if (iVar1 == 0) {
        strcpy(*results,"WARNING: ERRORS occurred while executing the pbay command:\n");
        strcat(*results,"    WARNING: no L1s found to match that destination\n");
        iVar1 = -1;
      }
      else {
        tc = cmd_setup_usr_response(pbay_rsp,data);
        if (tc == NULL) {
          strcpy(*results,"ERROR: user command processor is busy\n");
          free(((pbay_data *)data)->cmd);
          free(data);
          iVar1 = -1;
        }
        else {
          memcpy(tc->dest,c->dest,0x1188);
          c->busy = c->busy | 2;
          iVar1 = dest_l1(tc->dest,cptr);
          if (iVar1 == 0) {
            strcat(*results,"WARNING: no L1s found to match that destination\n");
            free(((pbay_data *)data)->cmd);
            free(data);
            iVar1 = -1;
          }
          else {
            iVar1 = broadcast_l1(tc,1,"pbay serial",1,0,0xff,NULL,1);
            if (iVar1 == 0) {
              iVar1 = 0;
            }
            else {
              response(results,0xa0);
              strcpy(*results,"ERROR: no (L1) destination set.\n");
              free(((pbay_data *)data)->cmd);
              free(data);
              iVar1 = -1;
            }
          }
        }
      }
    }
  }
  return iVar1;
}

void quit(void)
{
  smp_reset();
                    /* WARNING: Subroutine does not return */
  exit(0);
}

static int l2cmd_quit(CmdData *cptr, char **results, L2CMD *c)
{
  if (l2_pc != 0) {
    response(results,0xa0);
    sprintf(*results,"INFO: can\'t quit PC L2\n      use \'halt_l2\' to shutdown\n");
    return 0;
  }
  smp_reset();
                    /* WARNING: Subroutine does not return */
  exit(2);
}

static void reboot(void)
{
  if (l2_pc == 0) {
    system("/sbin/reboot");
  }
  else {
    system("init 6");
  }
  return;
}

static int l2cmd_reboot(CmdData *cptr, char **results)
{
  int iVar1;
  
  response(results,0x140);
  if (l2_pc == 0) {
    strcpy(*results,"INFO: \'reboot_l2\' command only supported on the hardware/PC L2\n");
    iVar1 = -1;
  }
  else {
    EventAddTimeOut(5,0,reboot,(EventData)0x0,"l2cmd_reboot");
    response(results,0xa0);
    strcpy(*results,"will reboot in 5 seconds...\n");
    iVar1 = 0;
  }
  return iVar1;
}

static void haltl2(void)
{
  system("init 0");
  return;
}

static int l2cmd_haltl2(CmdData *cptr, char **results, L2CMD *c)
{
  char *pcVar1;
  
  if (l2_pc == 0) {
    response(results,0x140);
    strcpy(*results,"INFO: halt command only supported on the PC L2\n");
  }
  EventAddTimeOut(5,0,haltl2,(EventData)0x0,"l2cmd_halt");
  response(results,0xa0);
  pcVar1 = strcpy(*results,"will halt in 5 seconds...\n");
  /* the original returned strcpy's result: a (positive) i386 heap address */
  return (int)((uintptr_t)pcVar1 & 0x7fffffff);
}

static int l2cmd_ping(CmdData *cptr, char **results)
{
  undefined *puVar1;
  
  switch(*cptr->params) {
  case 0:
    break;
  case 1:
    cfg_ping_response_minimum = cptr->exp_stack[0];
    nvramSet(0xb,cfg_ping_response_minimum);
    break;
  case 2:
    cfg_ping_response_maximum = cptr->exp_stack[0];
    nvramSet(0xc,cfg_ping_response_maximum);
    break;
  case 3:
    cfg_ping_l2_frequency = cptr->exp_stack[0];
    nvramSet(0xe,cfg_ping_l2_frequency);
    break;
  case 4:
    if (cptr->exp_stack[0] == 0) {
      cfg_ping_sender_valid = 2;
    }
    else {
      cfg_ping_sender_valid = 1;
    }
    nvramSet(0xd,cfg_ping_sender_valid);
    break;
  case 5:
    cfg_ping_l1_frequency = cptr->exp_stack[0];
    nvramSet(0xf,cfg_ping_l1_frequency);
    break;
  case 6:
    cfg_throttle_frequency = cptr->exp_stack[0];
    break;
  case 7:
    cfg_ping_reset();
  }
  response(results,0xa0);
  if (cfg_ping_sender_valid == 1) {
    puVar1 = "yes";
  }
  else {
    puVar1 = "no";
  }
  sprintf(*results,
          "L2<->L2 freq: %d, min: %d, max: %d\nping from sender valid: %s; L2<->L1 freq: %d\ncfg throttle %d\n"
          ,cfg_ping_l2_frequency,cfg_ping_response_minimum,cfg_ping_response_maximum,puVar1,
          cfg_ping_l1_frequency,cfg_throttle_frequency);
  return 0;
}

static int l2cmd_l2dsp(CmdData *cptr, char **results)
{
  uint32 uVar1;
  char *pcVar2;
  
  switch(*cptr->params) {
  case 0:
    l2dsp_debug_state = cptr->exp_stack[0];
  case 1:
    response(results,0xa0);
    sprintf(*results,"L2 display debug flags set to \'0x%08x\'",l2dsp_debug_state);
    break;
  case 2:
  case 3:
    nvramSet(9,(uint)(*cptr->params == 3));
    L2CfgMEventDisplayDisable(&L2CfgLocal);
  case 4:
    response(results,0xa0);
    uVar1 = nvramGet(9);
    if (uVar1 == 0) {
      pcVar2 = "enabled";
    }
    else {
      pcVar2 = "disabled";
    }
    sprintf(*results,"L2 display input %s\n",pcVar2);
  }
  return 0;
}

static int format_l2find_entry(char *rptr, sn1SC_L2 *l2)
{
  char *pcVar1;
  L2CfgNode *pLVar2;
  char *pcVar3;
  char *pcVar4;
  int iVar5;
  char *pcVar6;
  char ssn [40];
  char name [40];
  
  name[0] = '\0';
  memset(name + 1,0,0x27);
  ssn[0] = '\0';
  memset(ssn + 1,0,0x27);
  if (l2->sysname[0] != '\0') {
    sprintf(name,"%s",l2->sysname);
  }
  if (l2->ssn[0] != '\0') {
    sprintf(ssn,"%s",l2->ssn);
  }
  pcVar6 = l2->version;
  iVar5 = l2->rack;
  pcVar4 = name;
  pcVar3 = ssn;
  pcVar1 = SocketAddrStr(l2->ip_addr);
  sprintf(rptr,"%15s %-8s %-16.16s  %03d %-12.12s",pcVar1,pcVar3,pcVar4,iVar5,pcVar6);
  pLVar2 = L2CfgMFindNode(&L2CfgLocal,l2->ip_addr,0,NULL);
  if (pLVar2 != NULL) {
    strcat(rptr,"  (CONNECTED)");
  }
  strcat(rptr,"\n");
  return 0;
}

static int l2cmd_l2find(CmdData *cptr, char **results)
{
  bool bVar1;
  int iVar2;
  char *pcVar3;
  size_t sVar4;
  char *banner;
  char name [40];
  char *rptr;
  char *myssn;
  int l2c;
  int first;
  int l2_cnt;
  sn1SC_L2 *l2;
  sn1SC_L2 *l2_list;
  
  l2_cnt = 0;
  banner = 
  "IP              SSN      NAME             RACK FIRMWARE\n--------------- -------- ---------------- ---- ------------\n"
  ;
  iVar2 = sn1SCDiscoverL2(NULL,NULL,&l2_list,&l2_cnt,1);
  if (iVar2 < 0) {
    response(results,0xa0);
    strcpy(*results,"error discovering L2\'s!\n");
    iVar2 = -1;
  }
  else {
    pcVar3 = response(results,l2_cnt * 0x50 + 200);
    sprintf(pcVar3,"%d L2\'s discovered:\n\n",l2_cnt);
    sVar4 = strlen(pcVar3);
    rptr = pcVar3 + sVar4;
    pcVar3 = (char *)nvramGet(3);
    if (discover_debug != 0) {
      fprintf(stderr,"l2find:  myssn = %s\n",pcVar3);
    }
    bVar1 = true;
    l2 = l2_list;
    l2c = l2_cnt;
    while (((l2c != 0 && (pcVar3 != NULL)) && (*pcVar3 != '\0'))) {
      iVar2 = strcmp(pcVar3,l2->ssn);
      if (iVar2 == 0) {
        if (banner != NULL) {
          sprintf(rptr,banner);
          sVar4 = strlen(rptr);
          rptr = rptr + sVar4;
          banner = NULL;
        }
        if (bVar1) {
          bVar1 = false;
          sprintf(rptr,"[ L2\'s with matching System Serial Number ]\n");
          sVar4 = strlen(rptr);
          rptr = rptr + sVar4;
        }
        format_l2find_entry(rptr,l2);
        sVar4 = strlen(rptr);
        rptr = rptr + sVar4;
      }
      l2 = l2 + 1;
      l2c = l2c + -1;
    }
    bVar1 = true;
    l2 = l2_list;
    for (l2c = l2_cnt; l2c != 0; l2c = l2c + -1) {
      if (l2->ssn[0] == '\0') {
        if (banner != NULL) {
          sprintf(rptr,banner);
          sVar4 = strlen(rptr);
          rptr = rptr + sVar4;
          banner = NULL;
        }
        if (bVar1) {
          bVar1 = false;
          sprintf(rptr,"[ L2\'s with System Serial Number NOT set ]\n");
          sVar4 = strlen(rptr);
          rptr = rptr + sVar4;
        }
        format_l2find_entry(rptr,l2);
        sVar4 = strlen(rptr);
        rptr = rptr + sVar4;
      }
      l2 = l2 + 1;
    }
    bVar1 = true;
    l2 = l2_list;
    for (l2c = l2_cnt; l2c != 0; l2c = l2c + -1) {
      if (((l2->ssn[0] != '\0') && (pcVar3 != NULL)) &&
         (iVar2 = strcmp(pcVar3,l2->ssn), iVar2 != 0)) {
        if (banner != NULL) {
          sprintf(rptr,banner);
          sVar4 = strlen(rptr);
          rptr = rptr + sVar4;
          banner = NULL;
        }
        if (bVar1) {
          bVar1 = false;
          sprintf(rptr,"[ L2\'s with different System Serial Numbers ]\n");
          sVar4 = strlen(rptr);
          rptr = rptr + sVar4;
        }
        format_l2find_entry(rptr,l2);
        sVar4 = strlen(rptr);
        rptr = rptr + sVar4;
      }
      l2 = l2 + 1;
    }
    iVar2 = 0;
  }
  return iVar2;
}

static int l2cmd_shell(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  char *cmd;
  
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = check_smp(c->data,results);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else if (c->data == NULL) {
      response(results,0xa0);
      sprintf(*results,"ERROR: remote shell not supported.\n");
      iVar1 = -1;
    }
    else {
      if (*cptr->params == 0) {
        cmd = NULL;
      }
      else {
        cmd = cptr->str_stack[0];
      }
      iVar1 = smp_shell(c->data,cmd);
      if (iVar1 == 0) {
        iVar1 = 0;
      }
      else {
        response(results,0xa0);
        sprintf(*results,"ERROR: can\'t start a shell.\n");
        iVar1 = -1;
      }
    }
  }
  return iVar1;
}

static int l2cmd_smp(CmdData *cptr, char **results, L2CMD *c)
{
  uint uVar1;
  int iVar2;
  
  if (c == NULL) {
    iVar2 = -1;
  }
  else if ((*cptr->params == 0) || (iVar2 = check_smp(c->data,results), iVar2 != 0)) {
    uVar1 = *cptr->params;
    if (uVar1 == 1) {
      iVar2 = smp_join(c->data,cptr->exp_stack[0]);
      if (iVar2 != 0) {
        response(results,0xa0);
        strcpy(*results,"ERROR: no such SMP group found\n");
        return -1;
      }
    }
    else if (uVar1 == 0) {
      smp_query(c->data,cptr->params[1],results);
    }
    else if (uVar1 == 2) {
      iVar2 = smp_leave(c->data);
      if (iVar2 != 0) {
        response(results,0xa0);
        strcpy(*results,"ERROR: you are already in your own group\n");
        return -1;
      }
    }
    else if (uVar1 == 3) {
      smp_baud(cptr->params[1]);
      response(results,0xa0);
      strcpy(*results,"modem port baud rate changed\n");
    }
    iVar2 = 0;
  }
  else {
    iVar2 = 0;
  }
  return iVar2;
}

static int l2cmd_serial(CmdData *cptr, char **results)
{
  char *__s;
  size_t sVar1;
  int iVar2;
  char *ssn;
  char sernum [9];
  
  response(results,0x140);
  if (*cptr->params != 0) {
    if (*cptr->params != 1) {
      return 0;
    }
    __s = cptr->str_stack[0];
    sVar1 = strlen(__s);
    if ((((((sVar1 != 8) || (*__s < 'L')) || ('Z' < *__s)) || ((*__s == 'O' || (*__s == 'Q')))) ||
        (((*__s == 'S' || ((*__s == 'V' || (*__s == 'X')))) || (__s[1] < '0')))) ||
       (((('3' < __s[1] || (iVar2 = isdigit((int)__s[2]), iVar2 == 0)) ||
         (iVar2 = isdigit((int)__s[3]), iVar2 == 0)) ||
        (((iVar2 = isdigit((int)__s[4]), iVar2 == 0 || (iVar2 = isdigit((int)__s[5]), iVar2 == 0))
         || ((iVar2 = isdigit((int)__s[6]), iVar2 == 0 || (iVar2 = isdigit((int)__s[7]), iVar2 == 0)
             ))))))) {
      sprintf(*results,"ERROR: invalid system serial number \'%s\'\n",__s);
      strcat(*results,
             "System serial number must be [LMNPRTUWYZ]0000000 through [LMNPRTUWYZ]3999999\n");
      return -1;
    }
    nvramSet(3,(uintptr_t)__s);
    L2CfgMEventSystemSN(&L2CfgLocal);
  }
  ssn = (char *)nvramGet(3);
  if ((ssn == NULL) || (sVar1 = strlen(ssn), sVar1 == 0)) {
    ssn = "not set";
  }
  sprintf(*results,"L2 system serial number: %s.\n",ssn);
  return 0;
}

static int l2cmd_sysname(CmdData *cptr, char **results)
{
  uint uVar1;
  char *name;
  size_t sVar2;
  
  response(results,0xa0);
  uVar1 = *cptr->params;
  if (uVar1 == 1) {
    nvramSet(4,(uintptr_t)cptr->str_stack[0]);
    L2CfgMEventSystemName(&L2CfgLocal);
  }
  else if ((uVar1 != 0) && (uVar1 == 2)) {
    nvramSet(4,(uintptr_t)"");   /* clear the system name */
    L2CfgMEventSystemName(&L2CfgLocal);
  }
  name = (char *)nvramGet(4);
  if ((name == NULL) || (sVar2 = strlen(name), sVar2 == 0)) {
    name = "not set";
  }
  sprintf(*results,"L2 system name: %s.\n",name);
  return 0;
}

static int l2cmd_multisys(CmdData *cptr, char **results)
{
  uint32 uVar1;
  
  response(results,0xa0);
  if (*cptr->params == 1) {
    nvramSet(5,1);
  }
  else if (*cptr->params == 2) {
    nvramSet(5,0);
  }
  uVar1 = nvramGet(5);
  if (uVar1 == 1) {
    sprintf(*results,
            "L2 multiple system network support enabled.\nL2\'s will only connect to L2\'s with same system SN\n"
           );
  }
  else {
    sprintf(*results,
            "L2 multiple system network support disabled.\nL2\'s will connect to ALL other L2\'s on the subnet\n"
           );
  }
  return 0;
}

static int l2cmd_psmode(CmdData *cptr, char **results)
{
  char cVar1;
  char *pcVar2;
  char *rptr;
  uint32 uVar3;
  
  pcVar2 = response(results,0xa0);
  if (*cptr->params != 0) {
    if (*cptr->params != 1) {
      return 0;
    }
    cVar1 = *cptr->toks[1];
    if (cVar1 == 'p') {
      nvramSet(0x1a,2);
    }
    else if (cVar1 < 'q') {
      if (cVar1 == 'n') {
        nvramSet(0x1a,0);
      }
    }
    else if (cVar1 == 's') {
      nvramSet(0x1a,1);
    }
  }
  if (L2CfgLocal.net.msmode == 1) {
    sprintf(pcVar2,"L2 is currently a secondary L2.\n");
  }
  else if (L2CfgLocal.net.msmode == 0) {
    sprintf(pcVar2,"Primary/Secondary mode is currently disabled.\n");
  }
  else if (L2CfgLocal.net.msmode == 2) {
    sprintf(pcVar2,"L2 is currently a primary L2.\n");
  }
  else {
    sprintf(pcVar2,"WARNING: unknown primary/secondary mode %d.\n",L2CfgLocal.net.msmode);
  }
  pcVar2 = pcVar2 + strlen(pcVar2);
  uVar3 = nvramGet(0x1a);
  if (uVar3 != L2CfgLocal.net.msmode) {
    uVar3 = nvramGet(0x1a);
    if (uVar3 == 1) {
      sprintf(pcVar2,"L2 will be a secondary L2 after reboot.\n");
    }
    else if (uVar3 == 0) {
      sprintf(pcVar2,"Primary/Secondary mode will be disabled after reboot.\n");
    }
    else if (uVar3 == 2) {
      sprintf(pcVar2,"L2 will be a primary L2 after reboot.\n");
    }
    else {
      uVar3 = nvramGet(0x1a);
      sprintf(pcVar2,"WARNING: unknown primary/secondary mode %d\n",uVar3);
    }
  }
  return 0;
}

static int l2cmd_dhcps(CmdData *cptr, char **results)
{
  int curval;
  uint32 uVar1;
  char *rptr;
  
  curval = nvramGet(0x10);
  response(results,0x140);
  if (*cptr->params == 1) {
    nvramSet(0x10,0);
  }
  else if (*cptr->params == 2) {
    nvramSet(0x10,1);
  }
  uVar1 = nvramGet(0x10);
  if (uVar1 == 1) {
    sprintf(*results,"DHCP server startup DISABLED (this L2 will never start a DHCP server).\n");
  }
  else {
    sprintf(*results,"DHCP server startup enabled (if no other DHCP server is found).\n");
  }
  uVar1 = nvramGet(0x10);
  if (curval != uVar1) {
    strcat(*results,"(this setting takes effect after the next L2 reboot)\n");
  }
  return 0;
}

static int l2cmd_ip(CmdData *cptr, char **results)
{
  int iVar1;
  char *pcVar2;
  size_t sVar3;
  uint32 network;
  uint32 ip_gateway;
  uint32 ip_broadcast;
  uint32 ip_netmask;
  uint32 ip_addr;
  char *rptr;
  
  if ((l2_pc == 0) && (l2_hardware == 0)) {
    response(results,0xa0);
    strcpy(*results,"INFO:  ip command only supported on the Hardware/PC L2\n");
    iVar1 = -1;
  }
  else {
    rptr = response(results,0x140);
    switch(*cptr->params) {
    case 0:
      ip_addr = nvramGet(6);
      ip_netmask = nvramGet(7);
      ip_broadcast = nvramGet(8);
      ip_gateway = nvramGet(0x19);
      if ((ip_addr == 0) || (ip_addr == 0xffffffff)) {
        sprintf(rptr,"static IP address not currently set\n");
      }
      else {
        pcVar2 = inet_ntoa(*(struct in_addr *)&ip_addr);
        sprintf(rptr,"addr: %s   ",pcVar2);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
        pcVar2 = inet_ntoa(*(struct in_addr *)&ip_netmask);
        sprintf(rptr,"mask: %s   ",pcVar2);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
        pcVar2 = inet_ntoa(*(struct in_addr *)&ip_broadcast);
        sprintf(rptr,"bcast: %s   ",pcVar2);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
        if (ip_gateway == 0) {
          pcVar2 = inet_ntoa(*(struct in_addr *)&ip_gateway);
          sprintf(rptr,"gateway: <not set>\n",pcVar2);
        }
        else {
          pcVar2 = inet_ntoa(*(struct in_addr *)&ip_gateway);
          sprintf(rptr,"gateway: %s\n",pcVar2);
        }
      }
      break;
    case 1:
    case 2:
      iVar1 = inet_aton(cptr->str_stack[0],(struct in_addr *)&ip_addr);
      if (iVar1 < 0) {
        sprintf(rptr,"ERROR: \'%s\' is not a valid IP address\n",cptr->str_stack[0]);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      iVar1 = inet_aton(cptr->str_stack[1],(struct in_addr *)&ip_netmask);
      if (iVar1 < 0) {
        sprintf(rptr,"ERROR: \'%s\' is not a valid IP netmask\n",cptr->str_stack[1]);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
      }
      if (*cptr->params == 2) {
        iVar1 = inet_aton(cptr->str_stack[2],(struct in_addr *)&ip_broadcast);
        if (iVar1 < 0) {
          sprintf(rptr,"ERROR: \'%s\' is not a valid IP broadcast address\n",cptr->str_stack[2]);
          sVar3 = strlen(rptr);
          rptr = rptr + sVar3;
        }
      }
      else {
        ip_broadcast = ip_addr & ip_netmask | ~ip_netmask;
      }
      if (rptr == *results) {
        nvramSet(6,ip_addr);
        nvramSet(7,ip_netmask);
        nvramSet(8,ip_broadcast);
        pcVar2 = inet_ntoa(*(struct in_addr *)&ip_addr);
        sprintf(rptr,"addr: %s   ",pcVar2);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
        pcVar2 = inet_ntoa(*(struct in_addr *)&ip_netmask);
        sprintf(rptr,"netmask: %s   ",pcVar2);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
        pcVar2 = inet_ntoa(*(struct in_addr *)&ip_broadcast);
        sprintf(rptr,"broadcast addr: %s\n",pcVar2);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
        sprintf(rptr,"(L2 reboot required to use this static address)\n");
      }
      break;
    case 3:
      iVar1 = inet_aton(cptr->str_stack[0],(struct in_addr *)&ip_gateway);
      if (iVar1 < 0) {
        sprintf(rptr,"ERROR: \'%s\' is not a valid IP address\n",cptr->str_stack[0]);
        strlen(rptr);
      }
      else {
        nvramSet(0x19,ip_gateway);
        pcVar2 = inet_ntoa(*(struct in_addr *)&ip_gateway);
        sprintf(rptr,"gateway addr: %s\n",pcVar2);
        sVar3 = strlen(rptr);
        rptr = rptr + sVar3;
        sprintf(rptr,"(L2 reboot required to use new gateway address)\n");
      }
      break;
    case 4:
      nvramSet(6,0);
      nvramSet(7,0);
      nvramSet(8,0);
      nvramSet(0x19,0);
    }
    iVar1 = 0;
  }
  return iVar1;
}

static int l2cmd_log(CmdData *cptr, char **results)
{
  uint uVar1;
  char *pcVar2;
  
  uVar1 = *cptr->params;
  if (uVar1 == 1) {
    nvramLogReset();
    response(results,0xa0);
    strcpy(*results,"log reset.\n");
  }
  else if (uVar1 == 0) {
    pcVar2 = nvramLogFetch();
    *results = pcVar2;
    if (*results == NULL) {
      response(results,0xa0);
      strcpy(*results,"memory allocation error.\n");
    }
    else if (**results == '\0') {
      response(results,0xa0);
      strcpy(*results,"log is empty.\n");
    }
  }
  else {
    if (uVar1 != 2) {
      response(results,0xa0);
      sprintf(*results,"unknown log command.\n");
      return -1;
    }
    nvramLogInsert(cptr->str_stack[0]);
    response(results,0xa0);
    strcpy(*results,"log entry made.\n");
  }
  return 0;
}

static int l2cmd_select(CmdData *cptr, char **results, L2CMD *c)
{
  int subc;
  IRAddress IVar1;
  int iVar2;
  uint uVar3;
  char *pcVar4;
  char *pcVar5;
  size_t sVar6;
  uint uVar7;
  IRAddress detected_;
  char *endp;
  IRAddress detected;
  int first;
  int locate;
  L2CfgL1 *cfg;
  int slot;
  int rack;
  int filtered;
  int overrode;
  int partition;
  IRAddress conaddr;
  char *rptr;
  
  rptr = response(results,0x5004);
  locate = 0;
  if (c == NULL) {
    return -1;
  }
  subc = check_smp(c->data,results);
  if (subc == 0) {
    return 0;
  }
  if (true) {
    switch(*cptr->params) {
    case 0:
      L2CfgMGetConsole(&L2CfgLocal,-1);
      if (cptr->params[1] != 0) {
        first = 1;
        detected = (L2CfgLocal.syscon)->detected;
        *rptr = '\0';
        for (partition = 0; partition < 0x100; partition = partition + 1) {
          detected_ = L2CfgLocal.syscon[partition].detected;
          if ((partition == 0) && (detected_ != 0)) {
            strcpy(rptr,"known system consoles (non-partitioned)\n\n");
            sVar6 = strlen(rptr);
            rptr = rptr + sVar6;
          }
          if (detected_ != 0) {
            if ((partition != 0) && (first != 0)) {
              strcpy(rptr,"\nknown system consoles (partitioned)\n\n");
              sVar6 = strlen(rptr);
              rptr = rptr + sVar6;
              first = 0;
            }
            if (partition == 0) {
              strcpy(rptr,"\t");
            }
            else {
              sprintf(rptr,"\tpartition %2d: ",partition);
            }
            sVar6 = strlen(rptr);
            rptr = rptr + sVar6;
            pcVar5 = format_address(detected_);
            sprintf(rptr,"%s - L2 detected\n",pcVar5);
            sVar6 = strlen(rptr);
            rptr = rptr + sVar6;
          }
        }
        strcat(rptr,"\ncurrent system console\n\n");
        sVar6 = strlen(rptr);
        rptr = rptr + sVar6;
      }
      break;
    case 1:
      IVar1 = smp_get_conaddr(c->data,&conaddr,NULL);
      if (IVar1 == 0) {
        strcpy(*results,"ERROR: no system console address defined\n");
        strlen(rptr);
        return -1;
      }
      cfg = L2CfgMFindBrickCfg(&L2CfgLocal,conaddr >> 0x12 & 0x3ff,conaddr >> 0xc & 0x3f,0);
      if (cfg == NULL) {
        strcpy(*results,"ERROR: current console references non-existant brick\n");
        return -1;
      }
      if ((((cfg->type == '5') || (cfg->type == '@')) ||
          ((cfg->type == '6' || (((cfg->type == '$' || (cfg->type == ',')) || (cfg->type == '}')))))
          ) || (cfg->type == '.')) {
        strcpy(*results,"not valid on this brick - use \'console0|con0|console1...\'\n");
        return -1;
      }
      conaddr = conaddr & 0xfffff01f | 0x80;
      conaddr = smp_set_conaddr(c->data,conaddr);
      if (conaddr == 0) {
        strcpy(*results,
               "ERROR: not a valid system console address\n\t- subchannel may be invalid.\n");
        return -1;
      }
      break;
    case 2:
      IVar1 = smp_get_conaddr(c->data,&conaddr,NULL);
      if (IVar1 == 0) {
        strcpy(*results,"ERROR: no system console address defined\n");
        strlen(rptr);
        return -1;
      }
      cfg = L2CfgMFindBrickCfg(&L2CfgLocal,conaddr >> 0x12 & 0x3ff,conaddr >> 0xc & 0x3f,0);
      if (cfg == NULL) {
        strcpy(*results,"ERROR: current console references non-existant brick\n");
        return -1;
      }
      if ((((((cfg->type == '5') || (cfg->type == '@')) || (cfg->type == '6')) ||
           ((cfg->type == '$' || (cfg->type == ',')))) || (cfg->type == '}')) || (cfg->type == '.'))
      {
        strcpy(*results,"not valid on this brick - use \'0a|0c|1a...\'\n");
        return -1;
      }
      iVar2 = tolower((int)*cptr->toks[2]);
      conaddr = conaddr & 0xfffff01f | (iVar2 - 0x61U & 0x7f) << 5;
      conaddr = smp_set_conaddr(c->data,conaddr);
      if (conaddr == 0) {
        strcpy(*results,
               "ERROR: not a valid system console address\n\t- subchannel may be invalid.\n");
        return -1;
      }
      break;
    case 3:
      IVar1 = smp_get_conaddr(c->data,&conaddr,NULL);
      if (IVar1 == 0) {
        strcpy(*results,"ERROR: no system console address defined\n");
        strlen(rptr);
        return -1;
      }
      cfg = L2CfgMFindBrickCfg(&L2CfgLocal,conaddr >> 0x12 & 0x3ff,conaddr >> 0xc & 0x3f,0);
      if (cfg == NULL) {
        strcpy(*results,"ERROR: current console references non-existant brick\n");
        return -1;
      }
      if ((((cfg->type == '5') || (cfg->type == '@')) ||
          ((cfg->type == '6' || ((cfg->type == '$' || (cfg->type == ',')))))) ||
         ((cfg->type == '}' || (cfg->type == '.')))) {
        strcpy(*results,"not valid on this brick - use \'0a|0c|1a...\'\n");
        return -1;
      }
      conaddr = conaddr & 0xfffff01f | (cptr->exp_stack[0] & 0x7f) << 5;
      conaddr = smp_set_conaddr(c->data,conaddr);
      if (conaddr == 0) {
        strcpy(*results,
               "ERROR: not a valid system console address\n\t- subchannel may be invalid.\n");
        return -1;
      }
      break;
    case 4:
      IVar1 = smp_get_conaddr(c->data,&conaddr,NULL);
      if (IVar1 == 0) {
        strcpy(*results,"ERROR: no system console address defined\n");
        strlen(rptr);
        return -1;
      }
      cfg = L2CfgMFindBrickCfg(&L2CfgLocal,conaddr >> 0x12 & 0x3ff,conaddr >> 0xc & 0x3f,0);
      if (cfg == NULL) {
        strcpy(*results,"ERROR: current console references non-existant brick\n");
        return -1;
      }
      iVar2 = strncmp(cptr->str_stack[0],"console",7);
      if (iVar2 == 0) {
        detected_ = strtol(cptr->str_stack[0] + 7,NULL,0);
        if (((cfg->type == ',') || (cfg->type == '}')) || (cfg->type == '.')) {
          uVar3 = BRICK_TASKNUM((uint)cfg->type,0,4);
          uVar3 = (uVar3 & 0x7f) << 5;
          if ((conaddr & 0x80000000) == 0) {
            conaddr = conaddr & 0xfffff000 | uVar3 | detected_ & 0x1f;
          }
          else {
            conaddr = conaddr & 0xc0fff01f | uVar3 | (detected_ & 0x3f) << 0x18;
          }
        }
        else {
          uVar3 = BRICK_TASKNUM((uint)cfg->type,detected_,4);
          if ((conaddr & 0x80000000) == 0) {
            uVar7 = conaddr & 0xfffff000;
          }
          else {
            uVar7 = conaddr & 0xc0fff01f;
          }
          conaddr = uVar7 | (uVar3 & 0x7f) << 5;
        }
      }
      else {
        iVar2 = strncmp(cptr->str_stack[0],"con",3);
        if (iVar2 == 0) {
          detected_ = strtol(cptr->str_stack[0] + 3,NULL,0);
          if (((cfg->type == ',') || (cfg->type == '}')) || (cfg->type == '.')) {
            uVar3 = BRICK_TASKNUM((uint)cfg->type,0,4);
            uVar3 = (uVar3 & 0x7f) << 5;
            if ((conaddr & 0x80000000) == 0) {
              conaddr = conaddr & 0xfffff000 | uVar3 | detected_ & 0x1f;
            }
            else {
              conaddr = conaddr & 0xc0fff01f | uVar3 | (detected_ & 0x3f) << 0x18;
            }
          }
          else {
            uVar3 = BRICK_TASKNUM((uint)cfg->type,detected_,4);
            if ((conaddr & 0x80000000) == 0) {
              uVar7 = conaddr & 0xfffff000;
            }
            else {
              uVar7 = conaddr & 0xc0fff01f;
            }
            conaddr = uVar7 | (uVar3 & 0x7f) << 5;
          }
        }
        else {
          sVar6 = strlen(cptr->str_stack[0]);
          if (sVar6 < 2) {
            sprintf(*results,"ERROR: bad subchanel selection.\n");
            return -1;
          }
          detected = strtol(cptr->str_stack[0],&endp,0);
          if (endp == NULL) {
            first = 0;
          }
          else {
            iVar2 = tolower((int)*endp);
            first = iVar2 + -0x61;
          }
          if (((cfg->type == ',') || (cfg->type == '}')) || (cfg->type == '.')) {
            uVar3 = BRICK_TASKNUM((uint)cfg->type,0,first);
            uVar3 = (uVar3 & 0x7f) << 5;
            if ((conaddr & 0x80000000) == 0) {
              conaddr = conaddr & 0xfffff000 | uVar3 | detected & 0x1f;
            }
            else {
              conaddr = conaddr & 0xc0fff01f | uVar3 | (detected & 0x3f) << 0x18;
            }
          }
          else {
            uVar3 = BRICK_TASKNUM((uint)cfg->type,detected,first);
            if ((conaddr & 0x80000000) == 0) {
              uVar7 = conaddr & 0xfffff000;
            }
            else {
              uVar7 = conaddr & 0xc0fff01f;
            }
            conaddr = uVar7 | (uVar3 & 0x7f) << 5;
          }
        }
      }
      conaddr = smp_set_conaddr(c->data,conaddr);
      if (conaddr == 0) {
        strcpy(*results,
               "ERROR: not a valid system console address\n\t- subchannel may be invalid.\n");
        return -1;
      }
      break;
    case 5:
      rack = cptr->exp_stack[0];
      slot = cptr->exp_stack[1];
      cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
      if (cfg == NULL) {
        strcpy(*results,"ERROR: not a valid system console address\n");
        return -1;
      }
      uVar3 = (rack & 0x3ffU) << 6;
      conaddr = (uVar3 | slot & 0x3fU) << 0xc;
      if (((cfg->type != ',') && (cfg->type != '}')) && (cfg->type != '.')) {
        uVar7 = (cfg->console_subchannel & 0x7f) << 5;
        if (true) {
          conaddr = conaddr | uVar7 | cfg->console_subchannel >> 8 & 0x1f;
        }
        else {
          conaddr = (uVar3 & 0xc0fff | slot & 0x3fU) << 0xc | uVar7 |
                    (cfg->console_subchannel >> 8 & 0x3f) << 0x18;
        }
      }
      conaddr = smp_set_conaddr(c->data,conaddr);
      if (conaddr == 0) {
        strcpy(*results,"ERROR: not a valid system console address\n");
        return -1;
      }
      break;
    case 7:
      partition = cptr->exp_stack[0];
      if (partition != 0) {
        if ((partition < 0) || (0xff < partition)) {
          sprintf(*results,"ERROR: invalid partition, partitions are 1 through %d\n",0xff);
          return -1;
        }
        iVar2 = smp_set_partition(c->data,partition);
        if (iVar2 == 0) {
          if (partition == 0) {
            sprintf(*results,"ERROR: no system console found\n");
          }
          else {
            sprintf(*results,"ERROR: no system console found for that partition\n");
          }
          return -1;
        }
        if (partition != 0) {
          cptr->plist[partition] = '\x01';
          dest_default(c->dest,cptr);
        }
        break;
      }
      partition = 0;
    case 6:
      partition = smp_get_partition(c->data);
      smp_set_partition(c->data,0);
      smp_set_conaddr(c->data,0);
      if (partition != 0) {
        dest_reset(c->dest);
      }
      break;
    case 9:
      smp_set_confilter(c->data,cptr->params[1]);
      break;
    case 10:
      rack = cptr->exp_stack[0];
      slot = cptr->exp_stack[1];
      cfg = L2CfgMFindBrickCfg(&L2CfgLocal,rack,slot,0);
      if (cfg == NULL) {
        strcpy(*results,"ERROR: not a valid system console address\n");
        return -1;
      }
      conaddr = ((rack & 0x3ffU) << 6 | slot & 0x3fU) << 0xc;
      iVar2 = strncmp(cptr->str_stack[0],"console",7);
      if (iVar2 == 0) {
        detected = strtol(cptr->str_stack[0] + 7,NULL,0);
        if (((cfg->type == ',') || (cfg->type == '}')) || (cfg->type == '.')) {
          uVar3 = BRICK_TASKNUM((uint)cfg->type,0,4);
          uVar3 = (uVar3 & 0x7f) << 5;
          if ((conaddr & 0x80000000) == 0) {
            conaddr = conaddr & 0xfffff000 | uVar3 | detected & 0x1f;
          }
          else {
            conaddr = conaddr & 0xc0fff01f | uVar3 | (detected & 0x3f) << 0x18;
          }
        }
        else {
          uVar3 = BRICK_TASKNUM((uint)cfg->type,detected,4);
          if ((conaddr & 0x80000000) == 0) {
            uVar7 = conaddr & 0xfffff000;
          }
          else {
            uVar7 = conaddr & 0xc0fff01f;
          }
          conaddr = uVar7 | (uVar3 & 0x7f) << 5;
        }
      }
      else {
        iVar2 = strncmp(cptr->str_stack[0],"con",3);
        if (iVar2 == 0) {
          detected = strtol(cptr->str_stack[0] + 3,NULL,0);
          if (((cfg->type == ',') || (cfg->type == '}')) || (cfg->type == '.')) {
            uVar3 = BRICK_TASKNUM((uint)cfg->type,0,4);
            uVar3 = (uVar3 & 0x7f) << 5;
            if ((conaddr & 0x80000000) == 0) {
              conaddr = conaddr & 0xfffff000 | uVar3 | detected & 0x1f;
            }
            else {
              conaddr = conaddr & 0xc0fff01f | uVar3 | (detected & 0x3f) << 0x18;
            }
          }
          else {
            uVar3 = BRICK_TASKNUM((uint)cfg->type,detected,4);
            if ((conaddr & 0x80000000) == 0) {
              uVar7 = conaddr & 0xfffff000;
            }
            else {
              uVar7 = conaddr & 0xc0fff01f;
            }
            conaddr = uVar7 | (uVar3 & 0x7f) << 5;
          }
        }
        else {
          sVar6 = strlen(cptr->str_stack[0]);
          if (sVar6 < 2) {
            sprintf(*results,"ERROR: bad subchanel selection.\n");
            return -1;
          }
          first = strtol(cptr->str_stack[0],&endp,0);
          if (endp == NULL) {
            iVar2 = 0;
          }
          else {
            iVar2 = tolower((int)*endp);
            iVar2 = iVar2 + -0x61;
          }
          if (((cfg->type == ',') || (cfg->type == '}')) || (cfg->type == '.')) {
            uVar3 = BRICK_TASKNUM((uint)cfg->type,0,iVar2);
            uVar3 = (uVar3 & 0x7f) << 5;
            if ((conaddr & 0x80000000) == 0) {
              conaddr = conaddr & 0xfffff000 | uVar3 | first & 0x1fU;
            }
            else {
              conaddr = conaddr & 0xc0fff01f | uVar3 | (first & 0x3fU) << 0x18;
            }
          }
          else {
            uVar3 = BRICK_TASKNUM((uint)cfg->type,first,iVar2);
            if ((conaddr & 0x80000000) == 0) {
              uVar7 = conaddr & 0xfffff000;
            }
            else {
              uVar7 = conaddr & 0xc0fff01f;
            }
            conaddr = uVar7 | (uVar3 & 0x7f) << 5;
          }
        }
      }
      conaddr = smp_set_conaddr(c->data,conaddr);
      if (conaddr == 0) {
        strcpy(*results,
               "ERROR: not a valid system console address\n\t- subchannel may be invalid.\n");
        return -1;
      }
    }
  }
  partition = smp_get_partition(c->data);
  filtered = smp_get_confilter(c->data);
  smp_get_conaddr(c->data,&conaddr,&overrode);
  if (((partition == 0) || (overrode != 0)) || (filtered != 0)) {
    if ((conaddr == 0) || (overrode == 0)) {
      pcVar5 = "";
    }
    else {
      pcVar5 = " (CAUTION: default overrode!)";
    }
    if (conaddr == 0) {
      pcVar4 = "not defined";
    }
    else {
      pcVar4 = format_caddress(conaddr,0);
    }
    sprintf(rptr,"console input: %s%s\n",pcVar4,pcVar5);
    sVar6 = strlen(rptr);
    rptr = rptr + sVar6;
    if (filtered == 0) {
      pcVar5 = "not filtered";
    }
    else {
      pcVar5 = "filtered";
    }
    sprintf(rptr,"console output: %s\n",pcVar5);
    sVar6 = strlen(rptr);
    rptr = rptr + sVar6;
  }
  else {
    if (conaddr == 0) {
      pcVar5 = "not defined";
    }
    else {
      pcVar5 = format_caddress(conaddr,0);
    }
    sprintf(rptr,"console input: partition %d, %s\n",partition,pcVar5);
    sVar6 = strlen(rptr);
    rptr = rptr + sVar6;
    sprintf(rptr,"console output: any brick partition %d\n",partition);
    sVar6 = strlen(rptr);
    rptr = rptr + sVar6;
  }
  sVar6 = strlen(rptr);
  rptr = rptr + sVar6;
  L2CfgMAdviseConsole(&L2CfgLocal,rptr,partition,conaddr);
  return 0;
}

static int l2cmd_tty(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    iVar1 = check_smp(c->data,results);
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      smp_tty_debug(((SMP *)c->data)->rfd);
      smp_tty_debug(((SMP *)c->data)->wfd);
      iVar1 = 0;
    }
  }
  return iVar1;
}

static int l2cmd_version(CmdData *cptr, char **results)
{
  uint uVar1;
  int verbose;
  
  uVar1 = *cptr->params;
  response(results,0xa0);
  sprintf(*results,"L2 version: %d.%d.%d\n",1,0x3e,0);
  return 0;
}

static int ver_summary_rsp(IRPacket *rsp, L2CMD *c, IRAddress *dest, int pktsleft, cmd_response *cmd_rsp, void *data)
{
  int *piVar1;
  size_t sVar2;
  void *pvVar3;
  char *verstr;
  char *pcVar4;
  uint uVar5;
  char *errtext;
  char *pcVar6;
  undefined *puVar7;
  int iVar8;
  char *uVar9;
  char *rptr_;
  char version [16];
  char junk2 [20];
  char junk1[2];   /* ORIGINAL BUG: char junk1, but %[12] stores a NUL too */
  char *rptr;
  char emsg [100];
  int i;
  ver_summary_data *sd;
  bool print_errcnt;
  
  sd = (__typeof__(sd))data;   /* Ghidra merged sd into data */
  emsg[0] = '\0';
  memset(emsg + 1,0,99);
  sVar2 = strlen(cmd_rsp->sptr);
  rptr = cmd_rsp->sptr + sVar2;
  if (sd->verslist == 0) {
    pvVar3 = calloc(pktsleft + 1,sizeof(*sd->verslist));
    sd->verslist = pvVar3;
    pvVar3 = calloc(pktsleft + 1,sizeof(*sd->versnum));
    sd->versnum = pvVar3;
    if (((*dest & 0x80000000) == 0) && (*dest >> 0x1c == 0)) {
      puVar7 = "L1";
    }
    else {
      puVar7 = "L2";
    }
    sd->ptype = puVar7;
  }
  if (rsp == NULL) {
    verstr = format_address(*dest);
    sprintf(emsg,"    ERROR: no response from %s\n",verstr);
  }
  else if (rsp->_err == '\0') {
    if ((rsp->_argv[0]._clas & 7) == 0) {
      uVar5 = rsp->_argv[0]._val;
    }
    else {
      uVar5 = IRArg(rsp,0);
    }
    if (uVar5 == 0) {
      if ((rsp->_argv[1]._clas & 7) == 0) {
        pcVar6 = (char *)IR_VAL_PTR(rsp->_argv[1]._val);
      }
      else {
        pcVar6 = (char *)IRArg(rsp,1);
      }
      iVar8 = sscanf(pcVar6,"L%[12]%[^0-9]%15s",junk1,junk2,version);
      if (iVar8 < 2) {
        pcVar6 = format_address(*dest);
        sprintf(emsg,"    ERROR: could not get flash version of %s\n",pcVar6);
      }
      else {
        for (i = 0; i < sd->verscnt; i = i + 1) {
          iVar8 = strcmp(sd->verslist[i],version);
          if (iVar8 == 0) {
            piVar1 = &sd->versnum[i];
            *piVar1 = *piVar1 + 1;
            break;
          }
        }
        if (i == sd->verscnt) {
          pcVar6 = strdup(version);
          sd->verslist[sd->verscnt] = pcVar6;
          piVar1 = &sd->versnum[sd->verscnt];
          *piVar1 = *piVar1 + 1;
          sd->verscnt = sd->verscnt + 1;
        }
      }
    }
    else {
      /* 64-bit: the error text as a pointer, not through a uint */
      if ((rsp->_argv[1]._clas & 7) == 0) {
        errtext = (char *)IR_VAL_PTR(rsp->_argv[1]._val);
      }
      else {
        errtext = (char *)IRArg(rsp,1);
      }
      pcVar6 = format_address(*dest);
      sprintf(emsg,"    %s:  %s\n",pcVar6,errtext);
    }
  }
  else {
    pcVar6 = IRFmtError((uint)rsp->_err);
    pcVar4 = format_address(*dest);
    sprintf(emsg,"    ERROR: couldn\'t send packet to %s, %s\n",pcVar4,pcVar6);
  }
  if ((emsg[0] != '\0') && (sd->quiet == 0)) {
    if (sd->errcnt == 0) {
      pcVar6 = cmd_rsp->eptr;
      if (cmd_rsp->eptr == NULL) {
        pcVar6 = "";
      }
      sVar2 = strlen(pcVar6);
      iVar8 = sVar2 + cmd_rsp->slen;
      cmd_rsp->slen = iVar8;
      if (cmd_rsp->size <= iVar8 + 0x74) {
        sVar2 = cmd_rsp->size + 0x264;
        cmd_rsp->size = sVar2;
        pcVar6 = realloc(cmd_rsp->sptr,sVar2);
        cmd_rsp->sptr = pcVar6;
      }
      cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
      rptr = cmd_rsp->sptr + cmd_rsp->slen;
      uVar9 = sd->ptype;
      iVar8 = strcmp(sd->ptype,"L1");
      if (iVar8 == 0) {
        puVar7 = "\n";
      }
      else {
        puVar7 = "";
      }
      sprintf(rptr,"%sWARNING: ERRORS occurred while reading flash versions from %s Controllers:\n",
              puVar7,uVar9);
      sVar2 = strlen(rptr);
      rptr = rptr + sVar2;
    }
    sd->errcnt = sd->errcnt + 1;
    pcVar6 = cmd_rsp->eptr;
    if (cmd_rsp->eptr == NULL) {
      pcVar6 = "";
    }
    sVar2 = strlen(pcVar6);
    iVar8 = sVar2 + cmd_rsp->slen;
    cmd_rsp->slen = iVar8;
    sVar2 = strlen(emsg);
    if ((uint)cmd_rsp->size <= sVar2 + iVar8 + 0x10) {
      iVar8 = cmd_rsp->size;
      sVar2 = strlen(emsg);
      sVar2 = sVar2 + iVar8 + 0x200;
      cmd_rsp->size = sVar2;
      pcVar6 = realloc(cmd_rsp->sptr,sVar2);
      cmd_rsp->sptr = pcVar6;
    }
    cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
    rptr = cmd_rsp->sptr + cmd_rsp->slen;
    strcat(rptr,emsg);
    sVar2 = strlen(rptr);
    rptr = rptr + sVar2;
  }
  if (pktsleft == 0) {
    print_errcnt = false;
    strlen(cmd_rsp->sptr);
    pcVar6 = cmd_rsp->eptr;
    if (cmd_rsp->eptr == NULL) {
      pcVar6 = "";
    }
    sVar2 = strlen(pcVar6);
    iVar8 = sVar2 + cmd_rsp->slen;
    cmd_rsp->slen = iVar8;
    if (cmd_rsp->size <= iVar8 + sd->verscnt * 0x50 + 0x10) {
      sVar2 = cmd_rsp->size + 0x200 + sd->verscnt * 0x50;
      cmd_rsp->size = sVar2;
      pcVar6 = realloc(cmd_rsp->sptr,sVar2);
      cmd_rsp->sptr = pcVar6;
    }
    cmd_rsp->eptr = cmd_rsp->sptr + cmd_rsp->slen;
    rptr_ = cmd_rsp->sptr + cmd_rsp->slen;
    if ((cmd_rsp->status == -1) || (sd->errcnt != 0)) {
      iVar8 = -1;
    }
    else {
      iVar8 = 0;
    }
    cmd_rsp->status = iVar8;
    if (sd->errcnt != 0) {
      strcat(rptr_,"\n");
      sVar2 = strlen(rptr_);
      rptr_ = rptr_ + sVar2;
    }
    if ((sd->verscnt == 1) && (sd->quiet == 0)) {
      if (*sd->versnum == 1) {
        sprintf(rptr_,"%s Controller is running firmware version %s\n",
                sd->ptype,*sd->verslist);
      }
      else {
        if (sd->errcnt == 0) {
          puVar7 = "All ";
        }
        else {
          puVar7 = "";
        }
        sprintf(rptr_,"%s%d %s Controllers are running firmware version %s\n",puVar7,
                *sd->versnum,sd->ptype,
                *sd->verslist);
      }
      sVar2 = strlen(rptr_);
      rptr_ = rptr_ + sVar2;
      print_errcnt = true;
    }
    else if (1 < sd->verscnt) {
      sprintf(rptr_,"WARNING: multiple %s Controller firmware versions detected!\n",
              sd->ptype);
      sVar2 = strlen(rptr_);
      rptr_ = rptr_ + sVar2;
      for (i = 0; i < sd->verscnt; i = i + 1) {
        sprintf(rptr_,"%d %s Controllers are running firmware version %s\n",
                sd->versnum[i],sd->ptype,
                sd->verslist[i]);
        sVar2 = strlen(rptr_);
        rptr_ = rptr_ + sVar2;
      }
      print_errcnt = true;
    }
    if ((print_errcnt) && (sd->errcnt != 0)) {
      sprintf(rptr_,"%d %s Controller(s) could not be checked due to error(s)\n",
              sd->errcnt,sd->ptype);
    }
    for (i = 0; i < sd->verscnt; i = i + 1) {
      free(sd->verslist[i]);
    }
    free(sd->verslist);
    free(sd->versnum);
    sd->verslist = 0;
    sd->versnum = 0;
    sd->verscnt = 0;
    sd->errcnt = 0;
    if (c->q->reqq_length < 1) {
      sd->orig_c->busy =
           sd->orig_c->busy & 0xfffffffd;
      l2cmd_process_response(sd->orig_c,cmd_rsp->sptr,cmd_rsp->status);
      free(data);
    }
  }
  return 0;
}

static int l2cmd_version_summary(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  uint *data;
  L2CMD *tc;
  char emsg [80];
  ver_summary_data *sd;
  char *rptr;
  
  emsg[0] = '\0';
  memset(emsg + 1,0,0x4f);
  response(results,0x140);
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    sd = calloc(sizeof(ver_summary_data),1);
    data = (uint *)sd;
    if (data == NULL) {
      strcpy(*results,"ERROR: could not allocate memory to store internal command data\n");
      iVar1 = -1;
    }
    else {
      sd->quiet = (int)(*cptr->params == 1);
      sd->orig_c = c;
      iVar1 = dest_l2(c->dest,cptr);
      if (iVar1 == 0) {
        strcat(emsg,"    WARNING: no L2s found to match that destination\n");
      }
      iVar1 = dest_l1(c->dest,cptr);
      if (iVar1 == 0) {
        strcat(emsg,"    WARNING: no L1s found to match that destination\n");
      }
      if (emsg[0] == '\0') {
        tc = cmd_setup_usr_response(ver_summary_rsp,data);
        if (tc == NULL) {
          strcpy(*results,"ERROR: user command processor is busy\n");
          free(data);
          iVar1 = -1;
        }
        else {
          memcpy(tc->dest,c->dest,0x1188);
          c->busy = c->busy | 2;
          iVar1 = dest_l2(tc->dest,cptr);
          if (iVar1 == 0) {
            strcat(*results,"WARNING: no L2s found to match that destination\n");
          }
          else if ((0 < tc->dest->count) &&
                  (iVar1 = broadcast_l2(tc,NULL,"ver",1,0,0), iVar1 != 0)) {
            response(results,0xa0);
            strcpy(*results,"ERROR: no (L2) destination set.\n");
            c->busy = c->busy & 0xfffffffd;
            free(data);
            return -1;
          }
          iVar1 = dest_l1(tc->dest,cptr);
          if (iVar1 == 0) {
            strcat(*results,"WARNING: no L1s found to match that destination\n");
            iVar1 = -1;
          }
          else {
            iVar1 = broadcast_l1(tc,1,"ver",1,0,0xff,NULL,1);
            if (iVar1 == 0) {
              iVar1 = 0;
            }
            else {
              response(results,0xa0);
              strcpy(*results,"ERROR: no (L1) destination set.\n");
              iVar1 = -1;
            }
          }
        }
      }
      else {
        strcpy(*results,
               "WARNING: ERRORS occurred while reading L1/L2 Controller firmware versions:\n");
        strcat(*results,emsg);
        free(data);
        iVar1 = -1;
      }
    }
  }
  return iVar1;
}

static int cc(char *src, char *tgt)
{
  char *s;
  char *t;
  size_t sVar1;
  int iVar2;
  char *tptr;
  char *sptr;
  
  s = strdup(src);
  t = strdup(tgt);
  sptr = s;
  while (tptr = t, *sptr != '\0') {
    if (*sptr == ' ') {
      sVar1 = strlen(sptr);
      memmove(sptr,sptr + 1,sVar1);
    }
    else {
      sptr = sptr + 1;
    }
  }
  while (*tptr != '\0') {
    if (*tptr == ' ') {
      sVar1 = strlen(tptr);
      memmove(tptr,tptr + 1,sVar1);
    }
    else {
      tptr = tptr + 1;
    }
  }
  sVar1 = strlen(t);
  iVar2 = strncmp(t,s,sVar1);
  if (iVar2 == 0) {
    free(s);
    free(t);
    iVar2 = -1;
  }
  else {
    free(s);
    free(t);
    iVar2 = 0;
  }
  return iVar2;
}

static int l2cmd_l2cmd(CmdData *cptr, char **results, L2CMD *c)
{
  uint uVar1;
  int iVar2;
  int ip;
  int rspexp;
  char *cmd;
  
  if (c == NULL) {
    iVar2 = -1;
  }
  else {
    cmd = NULL;
    if (*cptr->params == 1) {
      cmd = cptr->str_stack[0];
    }
    else if (*cptr->params == 2) {
      cmd = cptr->str_stack[1];
    }
    if ((cmd == NULL) ||
       ((iVar2 = CmdProcess(0,cmd,NULL,(Cmd *)&l2cmd_cmds,0xbe,NULL), iVar2 != -800
        && (((iVar2 < -800 || (0xbd < iVar2)) || (iVar2 < 0xbc)))))) {
      if ((cmd == NULL) || (iVar2 = cc(cmd,"date sync"), iVar2 == 0)) {
        uVar1 = *cptr->params;
        if (uVar1 == 2) {
          ip = htonl(cptr->exp_stack[0] << 0x18 | cptr->exp_stack[1] << 0x10 |
                     cptr->exp_stack[2] << 8 | cptr->exp_stack[3]);
          iVar2 = target_l2(c,results,ip,cptr->str_stack[1],1,0,1);
          if (iVar2 != 0) {
            response(results,0xa0);
            strcpy(*results,"ERROR: invalid destination.\n");
            return -1;
          }
        }
        else if (uVar1 < 2) {
          iVar2 = dest_l2(c->dest,cptr);
          if (iVar2 == 0) {
            response(results,0xa0);
            sprintf(*results,"no L2s found to match that destination\n");
            return -1;
          }
          iVar2 = broadcast_l2(c,results,cptr->str_stack[0],1,0,1);
          if (iVar2 != 0) {
            response(results,0xa0);
            strcpy(*results,"ERROR: invalid destination.\n");
            return -1;
          }
        }
        else if (uVar1 == 3) {
          response(results,0xa0);
          strcpy(*results,"ERROR: targeting local L2 is redundant.\n");
          return -1;
        }
        iVar2 = 0;
      }
      else {
        response(results,0xa0);
        sprintf(*results,"ERROR: command not supported in targeted/broadcast format\n");
        iVar2 = -1;
      }
    }
    else {
      response(results,0xa0);
      sprintf(*results,"ERROR: invalid L2 command or target/broadcast attempted\n");
      iVar2 = -1;
    }
  }
  return iVar2;
}

static int l2cmd_l1cmd(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  int ip;
  int rspexp;
  int l1;
  int port;
  
  rspexp = 1;
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    if (((cptr->str_stack[0] != NULL) &&
        (iVar1 = strncmp(cptr->str_stack[0],"reboot_l1",9), iVar1 == 0)) ||
       ((cptr->str_stack[1] != NULL &&
        (iVar1 = strncmp(cptr->str_stack[1],"reboot_l1",9), iVar1 == 0)))) {
      rspexp = 0;
    }
    if (((cptr->str_stack[0] != NULL) &&
        (iVar1 = strncmp(cptr->str_stack[0],"abort",5), iVar1 == 0)) ||
       ((cptr->str_stack[1] != NULL &&
        (iVar1 = strncmp(cptr->str_stack[1],"abort",5), iVar1 == 0)))) {
      rspexp = 0;
    }
    if ((cptr->str_stack[0] == NULL) ||
       (iVar1 = strncmp(cptr->str_stack[0],"*",1), iVar1 != 0)) {
      if ((cptr->str_stack[0] != NULL) &&
         (((iVar1 = strncmp(cptr->str_stack[0],"reset",5), iVar1 == 0 ||
           (iVar1 = strncmp(cptr->str_stack[0],"rst",3), iVar1 == 0)) ||
          (iVar1 = strncmp(cptr->str_stack[0],"nmi",3), iVar1 == 0)))) {
        response(results,0xa0);
        iVar1 = dest_pcheck(c->dest,cptr,*results);
        if (iVar1 != 0) {
          return -1;
        }
        free(*results);
        *results = NULL;
      }
      if (*cptr->params < 2) {
        iVar1 = dest_l1(c->dest,cptr);
        if (iVar1 == 0) {
          response(results,0xa0);
          sprintf(*results,"ERROR: no L1s found to match that destination\n");
          return -1;
        }
        iVar1 = broadcast_l1(c,1,cptr->str_stack[0],rspexp,0,0xff,NULL,1);
        if (iVar1 != 0) {
          response(results,0xa0);
          strcpy(*results,"ERROR: no destination set.\n");
          return -1;
        }
      }
      else if (*cptr->params == 2) {
        ip = htonl(cptr->exp_stack[0] << 0x18 | cptr->exp_stack[1] << 0x10 | cptr->exp_stack[2] << 8
                   | cptr->exp_stack[3]);
        if (cptr->exp_stack[5] != 0) {
          response(results,0xa0);
          strcpy(*results,"ERROR: destination is too remote, try a more direct connection\n");
          return -1;
        }
        iVar1 = target_l1(c,ip,cptr->exp_stack[4],0,cptr->str_stack[1],rspexp,0,1);
        if (iVar1 != 0) {
          response(results,0xa0);
          strcpy(*results,"ERROR: invalid destination.\n");
          return -1;
        }
      }
      iVar1 = 0;
    }
    else {
      response(results,0xa0);
      sprintf(*results,"ERROR: invalid broadcast attempted\n");
      iVar1 = -1;
    }
  }
  return iVar1;
}

static int l2cmd_cmd(CmdData *cptr, char **results, L2CMD *c)
{
  int iVar1;
  int i;
  int l2cmd;
  
  if (c == NULL) {
    iVar1 = -1;
  }
  else {
    if (cptr->slist[0] != '\x06') {
      for (i = 0; i < 0x40; i = i + 1) {
        if (cptr->slist[i] != '\0') {
          iVar1 = l2cmd_l1cmd(cptr,results,c);
          return iVar1;
        }
      }
    }
    iVar1 = CmdProcess(0,cptr->str_stack[0],NULL,(Cmd *)&l2cmd_cmds,0xbe,NULL);
    if ((iVar1 == -800) || (((-0x321 < iVar1 && (iVar1 < 0xbe)) && (0xbb < iVar1)))) {
      iVar1 = l2cmd_l1cmd(cptr,results,c);
    }
    else {
      iVar1 = l2cmd_l2cmd(cptr,results,c);
    }
  }
  return iVar1;
}

static char *response(char **rptr, int size)
{
  char *pcVar1;
  char *c;
  
  if (*rptr != NULL) {
    free(*rptr);
  }
  pcVar1 = malloc(size);
  *rptr = pcVar1;
  if (*rptr != NULL) {
    memset(*rptr,0,size);
  }
  return *rptr;
}

static int BRICK_TASKNUM(int btype, int slab, int subchan)
{
  int iVar1;
  
  if (btype == 0x36) {
    iVar1 = slab * 0x18 + subchan % 0x18;
  }
  else {
    if (btype < 0x37) {
      if (btype == 0x2e) {
        iVar1 = subchan;
        if (subchan < 0) {
          iVar1 = subchan + 0x1f;
        }
        return slab * 0x20 + subchan + (iVar1 >> 5) * -0x20;
      }
    }
    else if (btype == 0x40) {
      return slab * 0x14 + subchan % 0x14;
    }
    iVar1 = subchan;
    if (subchan < 0) {
      iVar1 = subchan + 0x1f;
    }
    iVar1 = slab * 0x20 + subchan + (iVar1 >> 5) * -0x20;
  }
  return iVar1;
}
