/*
 * sys_ctrl/l3/l2api/l2api.c
 *
 * New in the modern tree. l2api: an HTTP API to an L2, for scripts and
 * for a web version of l2gui and l2term. It is an L3 client of the L2
 * like l2term (SCapi.c, SysCfg.c), and serves
 *
 *   GET  /api/v1/l2        the L2s of the system, and whether l2api is connected (JSON)
 *   GET  /api/v1/config    the bricks: rack, slot, type, partition, power (JSON)
 *   POST /api/v1/command   an L2 command, as l2cmd runs it: {"command": "..."}
 *                          or the command as plain text; {"status", "output"}
 *   POST /api/v1/power     {"action": "up|down|reset|status", "target": "<rack/slot>"}
 *   GET  /api/v1/console   WebSocket: the L2's console (its SMP port, as l2term)
 *   GET  /api/v1/events    server-sent events: "config" when the bricks change,
 *                          "l2" when the L2s or the connection do
 *
 * and with --www <dir>, the files there (a web interface). It listens on
 * 127.0.0.1:8080 unless --listen says otherwise, and has no
 * authentication of its own: put a reverse proxy (with TLS and a password)
 * in front of it before letting other machines in.
 *
 * One poll() loop. The HTTP sockets are not the Router's events (Event.c),
 * because the system controller API runs that loop while it waits for a
 * response; requests are therefore served one at a time, a command for as
 * long as the L2 takes to answer it.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "http.h"
#include "../api/SCapi.h"
#include "../main/SysCfg.h"
#include "../../common/IRouter/IRouter.h"
#include "../../common/Router/Router.h"
#include "../../common/Router/Socket.h"
#include "../../common/sys/Logger.h"
#include "../../common/sys/brick_types.h"
#include "stdbuf.h"   /* (new) */

#define SMP_PORT        8001    /* the L2's console, plus IR_PORT_BIAS */
#define L3_TASK         4       /* as l2term: configuration events come */
#define RECONNECT_SECS  5
#define MAX_CONNS       100     /* clients at once (two descriptors each, at most) */
#define MAX_POLL        (2 + 2 * MAX_CONNS)
#define REQUEST_SECS    30      /* to send a whole request */

static char *myname;
static char listen_spec[256] = "127.0.0.1:8080";
static const char *www;         /* --www */
static http_conn *conns;
static int l2_up;               /* connected to the L2 */
static time_t next_connect;
static char *last_config;       /* the configuration JSON last sent as an event */
static char *last_l2s;          /* and the L2s' */

/* --- JSON --- */

typedef struct {
  char *s;
  size_t len, cap;
} jbuf;

static void jb_add(jbuf *b, const char *s, size_t n)
{
  char *p;

  if (b->len + n + 1 > b->cap) {
    p = realloc(b->s,b->len + n + 4096);
    if (p == NULL)
      return;
    b->s = p;
    b->cap = b->len + n + 4096;
  }
  memcpy(b->s + b->len,s,n);
  b->len += n;
  b->s[b->len] = '\0';
}

#define jb_lit(b, s) jb_add(b, s, sizeof(s) - 1)

static void jb_printf(jbuf *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void jb_printf(jbuf *b, const char *fmt, ...)
{
  char tmp[512];
  va_list ap;
  int n;

  va_start(ap,fmt);
  n = vsnprintf(tmp,sizeof(tmp),fmt,ap);
  va_end(ap);
  jb_add(b,tmp,n < (int)sizeof(tmp) ? (size_t)n : sizeof(tmp) - 1);
}

/* s as a JSON string */
static void jb_str(jbuf *b, const char *s)
{
  char esc[8];

  jb_lit(b,"\"");
  for (; *s != '\0'; s++) {
    unsigned char c = *s;
    if (c == '"' || c == '\\') {
      esc[0] = '\\';
      esc[1] = c;
      jb_add(b,esc,2);
    }
    else if (c == '\n')
      jb_lit(b,"\\n");
    else if (c == '\r')
      jb_lit(b,"\\r");
    else if (c == '\t')
      jb_lit(b,"\\t");
    else if (c < 0x20 || c >= 0x7f) {
      snprintf(esc,sizeof(esc),"\\u%04x",c);   /* (the L2's text is Latin-1) */
      jb_add(b,esc,6);
    }
    else
      jb_add(b,(char *)&c,1);
  }
  jb_lit(b,"\"");
}

/* a string member of a JSON object (the requests' small ones): its value,
 * unescaped, into out; 0 if there is no such member */
static int json_member(const char *json, const char *name, char *out, size_t size)
{
  char key[64];
  const char *p;
  size_t n = 0;

  snprintf(key,sizeof(key),"\"%s\"",name);
  p = strstr(json,key);
  if (p == NULL)
    return 0;
  p += strlen(key);
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    p++;
  if (*p++ != ':')
    return 0;
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
    p++;
  if (*p++ != '"')
    return 0;
  for (; *p != '\0' && *p != '"' && n + 1 < size; p++) {
    if (*p == '\\' && p[1] != '\0') {
      p++;
      switch (*p) {
      case 'n': out[n++] = '\n'; break;
      case 't': out[n++] = '\t'; break;
      case 'r': out[n++] = '\r'; break;
      case 'u':                 /* (only Latin-1 is any use to an L2) */
        if (strlen(p) >= 5) {
          out[n++] = (char)strtol((char[]){ p[1], p[2], p[3], p[4], 0 },NULL,16);
          p += 4;
        }
        break;
      default: out[n++] = *p; break;
      }
    }
    else
      out[n++] = *p;
  }
  out[n] = '\0';
  return 1;
}

static void reply_json(http_conn *c, int code, jbuf *b)
{
  jb_lit(b,"\n");
  http_reply(c,code,"application/json",b->s,b->len);
  free(b->s);
}

static void reply_error(http_conn *c, int code, const char *msg)
{
  jbuf b = { 0 };

  jb_lit(&b,"{\"error\": ");
  jb_str(&b,msg);
  jb_lit(&b,"}");
  reply_json(c,code,&b);
}

/* --- the L2 --- */

static void l2_connect(void)
{
  if (time(NULL) < next_connect)
    return;
  next_connect = time(NULL) + RECONNECT_SECS;
  /* (NULL: --l2's host, or the L2 discovery finds) */
  if (sn1SCClient() == NULL && sn1SCInit(myname,NULL,L3_TASK) != 0)
    return;
  SysCfgConnInit(NULL,myname);
  l2_up = 1;
  fprintf(stderr,"%s: connected to the L2 at %s\n",myname,sn1SCHost());
}

static void config_json(jbuf *b);
static void l2s_json(jbuf *b);

/* b (malloc()ed JSON) to the event streams as event, if it is not what
 * *last holds; *last keeps it */
static void event_if_new(const char *event, jbuf *b, char **last)
{
  http_conn *c;

  if (*last != NULL && strcmp(*last,b->s) == 0) {
    free(b->s);
    return;
  }
  free(*last);
  *last = b->s;
  for (c = conns; c != NULL; c = c->next)
    if (c->state == HTTP_EVENTS)
      events_send(c,event,*last);
}

/* events from the L2: a new configuration, or new L2s, go to the event
 * streams */
static void l2_service(void)
{
  IRPacket *p;
  jbuf b = { 0 }, l = { 0 };
  int status;

  for (;;) {
    p = NULL;
    status = sn1SCPkt(&p,0);
    if (status == ROUTER_ERR_LOST) {
      fprintf(stderr,"%s: lost the L2\n",myname);
      l2_up = 0;
      l2s_json(&l);
      event_if_new("l2",&l,&last_l2s);
      return;
    }
    if (status != 0)
      break;
    if (p->_clas == IR_EVT)
      SysCfgConnProcessEvent(NULL,myname,p);
    IRouterFreePacket(p);
  }
  config_json(&b);
  event_if_new("config",&b,&last_config);
  l2s_json(&l);
  event_if_new("l2",&l,&last_l2s);
}

/* an L2 command; its status (0 if it worked) and output (malloc()ed) */
static int l2_command(const char *cmd, char **out)
{
  IRAddress addr = IR_ADDR_MAKE(IR_ADDR_L2,0x3ff,0x3f,0,IR_L2_CMD);   /* the L2's command task */
  char *rsp = NULL;
  char *text = strdup(cmd);
  int status;

  status = sn1SCTextCmd(&addr,text,&rsp);
  free(text);
  *out = rsp != NULL ? rsp : strdup("");
  if (sn1SCClient() == NULL)
    l2_up = 0;
  return status;
}

static void l2s_json(jbuf *b)
{
  SysCfgL2 *l2;
  int i;

  jb_lit(b,"{\"host\": ");
  jb_str(b,sn1SCHost() != NULL ? sn1SCHost() : "");
  jb_printf(b,", \"connected\": %s, \"l2s\": [",l2_up ? "true" : "false");
  for (i = 0; l2_up && i < SysCfgL2Count; i++) {
    l2 = SysCfgL2List[i];
    jb_printf(b,"%s\n  {\"ip\": ",i == 0 ? "" : ",");
    jb_str(b,SocketAddrStr(l2->net.ip_addr));
    jb_printf(b,", \"rack\": %d, \"serial\": ",l2->rack);
    jb_str(b,l2->ssn);
    jb_lit(b,", \"sysname\": ");
    jb_str(b,l2->sysname);
    jb_printf(b,", \"mode\": \"%s\", \"display_disabled\": %s}",
              l2->net.msmode == 1 ? "secondary" : l2->net.msmode == 2 ? "primary" : "none",
              l2->l2dsp_disabled ? "true" : "false");
  }
  jb_lit(b,"]}");
}

static void config_json(jbuf *b)
{
  SysCfgL1 *l1;
  char name[16];
  int i;

  jb_lit(b,"{\"bricks\": [");
  for (i = 0; l2_up && i < SysCfgL1Count; i++) {
    l1 = SysCfgL1List[i];
    snprintf(name,sizeof(name),"%03d%c%02d",l1->rack,brickTypeToChar(l1->type),l1->slot);
    jb_printf(b,"%s\n  {\"name\": \"%s\", \"rack\": %d, \"slot\": %d, \"type\": ",i == 0 ? "" : ",",
              name,l1->rack,l1->slot);
    jb_str(b,brickConvertType(l1->type));
    jb_printf(b,", \"partition\": %d, \"power\": %s, \"console\": %s, \"brick_serial\": ",l1->partition,
              l1->power_state ? "true" : "false",l1->console_enabled ? "true" : "false");
    jb_str(b,l1->brick_sn);
    jb_lit(b,", \"system_serial\": ");
    jb_str(b,l1->system_sn);
    jb_lit(b,"}");
  }
  jb_lit(b,"]}");
}

/* --- requests --- */

static void command_reply(http_conn *c, const char *cmd)
{
  jbuf b = { 0 };
  char *out;
  int status;

  if (!l2_up) {
    reply_error(c,503,"not connected to an L2");
    return;
  }
  status = l2_command(cmd,&out);
  jb_printf(&b,"{\"status\": %d, \"output\": ",status);
  jb_str(&b,out);
  if (status != 0) {
    jb_lit(&b,", \"message\": ");
    jb_str(&b,LoggerDefaultMessage(status));
  }
  jb_lit(&b,"}");
  free(out);
  reply_json(c,status == 0 ? 200 : 502,&b);
}

/* POST /api/v1/command: {"command": "..."}, or the command as text */
static void do_command(http_conn *c)
{
  const char *body = http_body(c);
  char cmd[1024];
  size_t n;

  if (*body == '{') {
    if (!json_member(body,"command",cmd,sizeof(cmd))) {
      reply_error(c,400,"no \"command\"");
      return;
    }
  }
  else {
    snprintf(cmd,sizeof(cmd),"%s",body);
    n = strlen(cmd);
    while (n > 0 && (cmd[n - 1] == '\n' || cmd[n - 1] == '\r'))
      cmd[--n] = '\0';
  }
  if (cmd[0] == '\0' || strpbrk(cmd,"\r\n") != NULL) {
    reply_error(c,400,"one command, one line");
    return;
  }
  command_reply(c,cmd);
}

/* POST /api/v1/power: {"action": "up|down|reset|status", "target": "..."} */
static void do_power(http_conn *c)
{
  const char *body = http_body(c);
  char action[32], target[128] = "", cmd[200];
  const char *verb;

  if (!json_member(body,"action",action,sizeof(action))) {
    reply_error(c,400,"no \"action\"");
    return;
  }
  json_member(body,"target",target,sizeof(target));
  if (strspn(target,"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ,.*-") !=
      strlen(target)) {
    reply_error(c,400,"a target is rack and slot words (e.g. \"r 1 s 7\")");
    return;
  }
  if (strcmp(action,"up") == 0)
    verb = "power up";
  else if (strcmp(action,"down") == 0)
    verb = "power down";
  else if (strcmp(action,"reset") == 0)
    verb = "reset";
  else if (strcmp(action,"status") == 0)
    verb = "power";
  else {
    reply_error(c,400,"action: up, down, reset or status");
    return;
  }
  snprintf(cmd,sizeof(cmd),"%s%s%s",target,target[0] != '\0' ? " " : "",verb);
  command_reply(c,cmd);
}

/* GET /api/v1/console: a WebSocket to the L2's console */
static void do_console(http_conn *c)
{
  int fd;

  if (!c->upgrade || c->ws_key[0] == '\0') {
    reply_error(c,400,"a WebSocket upgrade, please");
    return;
  }
  if (!l2_up) {
    reply_error(c,503,"not connected to an L2");
    return;
  }
  fd = SocketMakeInetConnection(sn1SCHost(),IR_PORT_BIAS + SMP_PORT,1);
  if (fd < 0) {
    reply_error(c,502,"can't reach the L2's console");
    return;
  }
  ws_accept(c);
  fcntl(fd,F_SETFL,fcntl(fd,F_GETFL) | O_NONBLOCK);
  c->relay = fd;
}

static void console_input(http_conn *c, int opcode, const unsigned char *data, size_t len)
{
  if (c->relay >= 0 && write(c->relay,data,len) != (ssize_t)len)
    fprintf(stderr,"%s: console write: %s\n",myname,strerror(errno));
}

static const char *mime_type(const char *path)
{
  static const struct {
    const char *ext, *type;
  } types[] = {
    { ".html", "text/html; charset=utf-8" }, { ".js", "text/javascript" },
    { ".css", "text/css" }, { ".json", "application/json" }, { ".svg", "image/svg+xml" },
    { ".png", "image/png" }, { ".ico", "image/x-icon" }, { ".xpm", "image/x-xpixmap" },
  };
  const char *ext = strrchr(path,'.');
  size_t i;

  for (i = 0; ext != NULL && i < sizeof(types) / sizeof(types[0]); i++)
    if (strcmp(ext,types[i].ext) == 0)
      return types[i].type;
  return "application/octet-stream";
}

/* GET of a file under --www (a query string is the page's own) */
static void do_file(http_conn *c)
{
  char path[1024];
  struct stat st;
  char *data;
  FILE *fp;
  size_t n = strcspn(c->path,"?");

  if (strstr(c->path,"..") != NULL) {
    reply_error(c,400,"bad path");
    return;
  }
  snprintf(path,sizeof(path),"%s%.*s%s",www,(int)n,c->path,
           n == 0 || c->path[n - 1] == '/' ? "index.html" : "");
  fp = fopen(path,"rb");
  if (fp == NULL || fstat(fileno(fp),&st) != 0 || !S_ISREG(st.st_mode)) {
    if (fp != NULL)
      fclose(fp);
    reply_error(c,404,"no such file");
    return;
  }
  data = malloc(st.st_size + 1);
  if (data != NULL && fread(data,1,st.st_size,fp) == (size_t)st.st_size)
    http_reply(c,200,mime_type(path),data,st.st_size);
  else
    reply_error(c,500,"can't read the file");
  free(data);
  fclose(fp);
}

/* the endpoints: whether path is one, and if so whether method suits it */
static int endpoint(const char *path, int get, int post, int *allowed)
{
  static const struct {
    const char *path;
    int post;
  } api[] = {
    { "/api/v1/l2", 0 }, { "/api/v1/config", 0 }, { "/api/v1/command", 1 },
    { "/api/v1/power", 1 }, { "/api/v1/console", 0 }, { "/api/v1/events", 0 },
  };
  size_t i;

  for (i = 0; i < sizeof(api) / sizeof(api[0]); i++)
    if (strcmp(path,api[i].path) == 0) {
      *allowed = api[i].post ? post : get;
      return 1;
    }
  return 0;
}

static void route(http_conn *c)
{
  int get = strcmp(c->method,"GET") == 0 || strcmp(c->method,"HEAD") == 0;
  int post = strcmp(c->method,"POST") == 0;
  int allowed;
  jbuf b = { 0 };

  if (endpoint(c->path,get,post,&allowed) && !allowed)
    reply_error(c,405,"wrong method for this endpoint");
  else if (strcmp(c->path,"/api/v1/l2") == 0 && get) {
    l2s_json(&b);
    reply_json(c,200,&b);
  }
  else if (strcmp(c->path,"/api/v1/config") == 0 && get) {
    config_json(&b);
    reply_json(c,200,&b);
  }
  else if (strcmp(c->path,"/api/v1/command") == 0 && post)
    do_command(c);
  else if (strcmp(c->path,"/api/v1/power") == 0 && post)
    do_power(c);
  else if (strcmp(c->path,"/api/v1/console") == 0 && get)
    do_console(c);
  else if (strcmp(c->path,"/api/v1/events") == 0 && get) {
    events_start(c);
    config_json(&b);
    events_send(c,"config",b.s);
    free(b.s);
    b.s = NULL;
    b.len = b.cap = 0;
    l2s_json(&b);
    events_send(c,"l2",b.s);
    free(b.s);
  }
  else if (strncmp(c->path,"/api/",5) == 0)
    reply_error(c,404,"no such endpoint (see /api/v1/l2, /config, /command, /power, /console, "
                      "/events)");
  else if (www != NULL && get)
    do_file(c);
  else if (strcmp(c->path,"/") == 0 && get) {
    jb_lit(&b,"{\"api\": \"/api/v1\"}");
    reply_json(c,200,&b);
  }
  else
    reply_error(c,404,"not found");
}

/* --- the loop --- */

/* (closed after this round of the loop) */
static void drop(http_conn *c)
{
  c->state = HTTP_DEAD;
}

/* close the dropped connections, those whose response is out, and those
 * that have taken too long to send a request or to take a response */
static void reap(void)
{
  http_conn **pp = &conns;
  http_conn *c;
  long now = (long)time(NULL);

  while ((c = *pp) != NULL) {
    if (http_flush(c) < 0 || c->state == HTTP_DEAD || (c->state == HTTP_REPLYING && c->outlen == 0) ||
        ((c->state == HTTP_READING || c->state == HTTP_REPLYING) && now - c->since > REQUEST_SECS)) {
      *pp = c->next;
      if (c->relay >= 0)
        close(c->relay);
      http_close(c);
    }
    else
      pp = &c->next;
  }
}

/* the client's socket is readable */
static void client_input(http_conn *c)
{
  int n = http_read(c);

  if (n == 0) {
    drop(c);
    return;
  }
  switch (c->state) {
  case HTTP_READING:
    switch (http_request_done(c)) {
    case 1:
      route(c);
      break;
    case -1:
      http_reply(c,400,"text/plain","bad request\n",12);
      break;
    }
    break;
  case HTTP_WEBSOCKET:
    if (ws_read_frames(c,console_input) != 0)
      drop(c);
    break;
  default:                      /* (nothing more is expected) */
    c->inlen = 0;
    break;
  }
}

/* the L2's console said something: to the WebSocket */
static void relay_input(http_conn *c)
{
  char buf[4096];
  ssize_t n = read(c->relay,buf,sizeof(buf));

  if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
    ws_send(c,WS_CLOSE,"",0);
    drop(c);
    return;
  }
  if (n > 0)
    ws_send(c,WS_BINARY,buf,n);
}

static void serve(int lfd)
{
  struct pollfd fds[MAX_POLL];
  http_conn *who[MAX_POLL];
  int kind[MAX_POLL];           /* 0 listener, 1 L2, 2 client, 3 relay */
  time_t last_service = 0;
  http_conn *c, *next_c;
  int n, i, l2fd, l2_input, nconns;

  for (;;) {
    if (!l2_up)
      l2_connect();
    n = 0;
    fds[n].fd = lfd;
    fds[n].events = POLLIN;
    kind[n++] = 0;
    l2fd = l2_up ? sn1SCSocket() : -1;
    if (l2fd >= 0) {
      fds[n].fd = l2fd;
      fds[n].events = POLLIN;
      kind[n++] = 1;
    }
    for (c = conns; c != NULL; c = c->next) {
      fds[n].fd = c->fd;
      fds[n].events = (c->state != HTTP_REPLYING ? POLLIN : 0) | (c->outlen > 0 ? POLLOUT : 0);
      who[n] = c;
      kind[n++] = 2;
      if (c->relay >= 0) {
        fds[n].fd = c->relay;
        fds[n].events = POLLIN;
        who[n] = c;
        kind[n++] = 3;
      }
    }
    if (poll(fds,n,1000) < 0 && errno != EINTR)
      break;
    l2_input = 0;
    for (i = 0; i < n; i++) {
      if (fds[i].revents == 0 || (kind[i] >= 2 && who[i]->state == HTTP_DEAD))
        continue;
      if (kind[i] == 0) {
        c = http_accept(lfd);
        for (nconns = 0, next_c = conns; next_c != NULL; next_c = next_c->next)
          nconns++;
        if (c != NULL && nconns >= MAX_CONNS) {
          http_reply(c,503,"text/plain","too many clients\n",17);
          http_flush(c);
          http_close(c);
        }
        else if (c != NULL) {
          c->next = conns;
          conns = c;
        }
      }
      else if (kind[i] == 1)
        l2_input = 1;
      else if (kind[i] == 2 && (fds[i].revents & (POLLIN | POLLHUP | POLLERR)))
        client_input(who[i]);
      else if (kind[i] == 3)
        relay_input(who[i]);
    }
    /* the L2's events, and once a second its Router's timers */
    if (l2_up && (l2_input || time(NULL) != last_service)) {
      l2_service();
      last_service = time(NULL);
    }
    reap();
  }
}

static void usage(void)
{
  fprintf(stderr,"usage: %s [--listen [<host>:]<port>] [--www <dir>] [sysco options]\n"
                 "  --listen   where to serve HTTP (127.0.0.1:8080; 0.0.0.0:8080 for every interface)\n"
                 "  --www      serve the files in <dir> too (a web interface)\n"
                 "System Controller command options\n%s\n",myname,sn1SCUsage());
  exit(1);
}

int main(int argc, char **argv)
{
  int lfd;
  int i;

  stdout_buffered();
  myname = argv[0];
  signal(SIGPIPE,SIG_IGN);
  if (sn1SCParseCmdline(&argc,argv) < 0)
    usage();
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i],"--listen") == 0 && i + 1 < argc)
      snprintf(listen_spec,sizeof(listen_spec),"%s",argv[++i]);
    else if (strcmp(argv[i],"--www") == 0 && i + 1 < argc)
      www = argv[++i];
    else
      usage();
  }
  lfd = http_listen(listen_spec);
  if (lfd < 0) {
    fprintf(stderr,"%s: can't listen on %s: %s\n",myname,listen_spec,strerror(errno));
    return 1;
  }
  fprintf(stderr,"%s: serving http://%s/api/v1/\n",myname,listen_spec);
  serve(lfd);
  return 1;
}
