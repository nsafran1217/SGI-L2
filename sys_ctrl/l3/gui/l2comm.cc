/*
 * sys_ctrl/l3/gui/l2comm.cc
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2gui.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/l3/gui/l2comm.cc
 *
 * The connection to the L2: configuration events update the windows, and
 * text commands go to the L2's command task.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
extern "C" {
#include "../../common/sys/syslog.h"
#include "../sys/syslogLib.h"   /* SGI syslog() (needed by the reconstruction) */
#include "../../common/sys/Logger.h"
#include "../../common/Router/RouterMsg.h"
#include "../api/SCapi.h"
#include "../main/SysCfg.h"
}
#include "l2comm.h"
#include "l2gui.h"

static l2comm_packet_cb *packet_handler;
static void *packet_handler_data;
static int packet_handler_types;        /* bit (1 << _clas) for each class handled */
static uint32 txt_seqnum = 0xffffffff;
static l2comm_packet_cb *txt_handler;
static void *txt_handler_data;
static void *handler_handle;

static void l2comm_input(int sd, void *data);
static int l2comm_get_text_response(IRPacket *pkt, void *data);

/* IRAddress fields, as IRFmtAddr decodes them */
static int addr_type(IRAddress a)
{
  if ((a & 0x80000000) == 0)
    return a >> 28;
  return (a >> 30 == 2) ? 0xe : 0xf;
}

static int addr_task(IRAddress a)
{
  return (a & 0x80000000) == 0 ? (a & 0x1f) : ((a >> 24) & 0x3f);
}

int l2comm_init(void)
{
  static int first = 1;
  int attempt = 0;
  int status;

  mainwin_actions(0);
  if (first)
    mainwin_update_status("Connecting to L2 Controller...");
  else
    mainwin_update_status("Reconnecting to L2 Controller...");
  while ((status = sn1SCInitL2App("l2gui", NULL, 6)) < 0) {
    if (attempt > 2) {
      syslog(3, "l2comm.cc", 70, 0, "Connection failed: %s", LoggerDefaultMessage(status));
      syslog(3, "l2comm.cc", 72, 0, "Multiple connection failures--giving up!\n");
      exit(-1);
    }
    syslog(3, "l2comm.cc", 62, 0, "Connection failed: %s", LoggerDefaultMessage(status));
    syslog(6, "l2comm.cc", 64, 0, "retrying connection in 10 seconds...");
    mainwin_update_status("L2 Controller connect failed, retrying...");
    fl_sleep(10.0);
    attempt++;
  }
  mainwin_update_status("Connected to L2 Controller!");
  Fl::add_fd(sn1SCSocket(), FL_READ, l2comm_input, NULL);
  SysCfgConnInit(NULL, myname);
  destwin_update_config();
  mainwin_update_config();
  first = 0;
  return 0;
}

static void l2comm_input(int sd, void *data)
{
  IRPacket *pkt;
  int rval;
  int clas;

  for (;;) {
    rval = sn1SCPkt(&pkt, 0);
    if (rval != 0) {
      if (rval != -620)                 /* no packet waiting */
        syslog(4, "l2comm.cc", 160, 0, "Error while reading from L2 connection: %s",
               LoggerDefaultMessage(rval));
      if (rval == -303) {               /* connection lost */
        Fl::remove_fd(sd);
        l2comm_init();
      }
      return;
    }
    clas = pkt->_clas;
    if (clas <= 2) {
      /* configuration events (and responses) from the L2's config task */
      if (clas != 0 && (addr_type(pkt->_src) == 1 || addr_type(pkt->_src) == 0xe) &&
          addr_task(pkt->_src) == IR_L2_CFG) {
        SysCfgConnProcessEvent(NULL, myname, pkt);
        mainwin_update_config();
        destwin_update_config();
      }
      if ((packet_handler_types >> clas & 1) && packet_handler)
        packet_handler(pkt, packet_handler_data);
    }
    IRouterFreePacket(pkt);
  }
}

void *l2comm_add_packet_handler(int pkt_types, l2comm_packet_cb *handler_cb, void *data)
{
  if (packet_handler) {
    fprintf(stderr, "FATAL ERROR:  %s: packet handler already defined!\n",
            "l2comm_add_packet_handler");
    exit(-1);
  }
  packet_handler = handler_cb;
  packet_handler_data = data;
  packet_handler_types = pkt_types;
  return &packet_handler;
}

void l2comm_remove_packet_handler(void *handle)
{
  if (handle == &packet_handler) {
    packet_handler = NULL;
    packet_handler_data = NULL;
    packet_handler_types = 0;
  }
  else {
    fprintf(stderr, "WARNING: %s: invalid handle specified\n", "l2comm_remove_packet_handler");
  }
}

int l2comm_send_text_command(char *cmd, l2comm_packet_cb *handler, void *data)
{
  IRAddress addr;
  IRArgument av[2];
  int rval;

  txt_handler = handler;
  txt_handler_data = data;
  handler_handle = l2comm_add_packet_handler(1 << 1, l2comm_get_text_response, NULL);
  addr = 0x1ffff003;                    /* the local L2's command task (IR_L2_CMD) */
  av[0]._clas = 0;
  av[0]._frame = 0;
  av[0]._val = 0;
  av[0]._size = 0;
  av[1]._clas = 2;
  av[1]._frame = 0;
  av[1]._val = IR_PTR_VAL(cmd);
  av[1]._size = strlen(cmd) + 1;
  rval = sn1SCReq(&addr, 0, 2, av, &txt_seqnum);
  if (rval < 0)
    l2comm_remove_packet_handler(handler_handle);
  else
    rval = 0;
  return rval;
}

static int l2comm_get_text_response(IRPacket *pkt, void *data)
{
  if (txt_seqnum == 0xffffffff) {
    syslog(3, "l2comm.cc", 279, 0, "%s: not currently waiting for a text response packet!\n",
           "l2comm_get_text_response");
    l2comm_remove_packet_handler(handler_handle);
  }
  if (pkt->_clas == 1 && (uint32)(pkt->_seqnum1 << 8 | pkt->_seqnum0) == txt_seqnum) {
    txt_handler(pkt, txt_handler_data);
    txt_seqnum = 0xffffffff;
    l2comm_remove_packet_handler(handler_handle);
  }
  return 0;
}
