/*
 * sys_ctrl/l3/utils/l2telnetd.c
 *
 * New in the modern tree. l2telnetd: an L2's console for telnet clients,
 * started by inetd or systemd (contrib/systemd/sgi-l2-telnet.socket) with
 * the client's connection on stdin and stdout. It connects to the L2's SMP
 * port, as l2term does, and copies between the two, speaking just enough
 * telnet for that: it asks the client to send each key as typed and to
 * leave the echo to the L2 (WILL ECHO, WILL SUPPRESS-GO-AHEAD), takes the
 * client's option negotiation out of what it sends on, and gives the L2
 * what a raw tty would (CR for the client's CR LF or CR NUL). The client's
 * escape (CTRL-], then quit) ends the session; "quit" on the console ends
 * the L2.
 *
 *   l2telnetd [--l2 <host>] [--port <port>]     (localhost, 8001)
 */

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define SMP_PORT  "8001"        /* l2's console (smp.h) */

#define IAC       255
#define DONT      254
#define DO        253
#define WONT      252
#define WILL      251
#define SB        250
#define SE        240
#define OPT_ECHO  1
#define OPT_SGA   3

static const char *myname;

/* what the client sends, through the states of its telnet commands */
static enum { DATA, CMD, OPT, SUB, SUB_IAC, CR } state;

static int write_all(int fd, const unsigned char *buf, size_t len)
{
  ssize_t n;

  while (len > 0) {
    n = write(fd,buf,len);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
      return -1;
    buf += n;
    len -= n;
  }
  return 0;
}

/* the client's bytes in buf (n of them) as the L2 is to get them, in
 * place; their number */
static size_t from_client(unsigned char *buf, size_t n)
{
  size_t i, out = 0;
  unsigned char c;

  for (i = 0; i < n; i++) {
    c = buf[i];
    switch (state) {
    case CR:
      state = DATA;
      if (c == '\n' || c == '\0')       /* (CR was sent already) */
        break;
      /* fall through */
    case DATA:
      if (c == IAC)
        state = CMD;
      else {
        buf[out++] = c;
        if (c == '\r')
          state = CR;
      }
      break;
    case CMD:
      if (c == IAC) {                   /* a 255 of the data */
        buf[out++] = c;
        state = DATA;
      }
      else if (c == SB)
        state = SUB;
      else if (c >= WILL && c <= DONT)
        state = OPT;
      else
        state = DATA;                   /* (NOP, AYT and the like: ignored) */
      break;
    case OPT:                           /* (any option: neither asked for nor refused) */
      state = DATA;
      break;
    case SUB:
      if (c == IAC)
        state = SUB_IAC;
      break;
    case SUB_IAC:
      state = c == SE ? DATA : SUB;
      break;
    }
  }
  return out;
}

/* the L2's bytes to the client: a 255 doubled */
static int to_client(const unsigned char *buf, size_t n)
{
  static const unsigned char iac_iac[2] = { IAC, IAC };
  const unsigned char *p;
  size_t len;

  while (n > 0) {
    p = memchr(buf,IAC,n);
    len = p != NULL ? (size_t)(p - buf) : n;
    if (write_all(1,buf,len) != 0)
      return -1;
    if (p == NULL)
      break;
    if (write_all(1,iac_iac,2) != 0)
      return -1;
    buf = p + 1;
    n -= len + 1;
  }
  return 0;
}

/* a connection to the L2, or -1 with why in msg */
static int connect_l2(const char *host, const char *port, char *msg, size_t size)
{
  struct addrinfo hints, *res, *ai;
  int fd = -1;
  int rc;

  memset(&hints,0,sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rc = getaddrinfo(host,port,&hints,&res);
  if (rc != 0) {
    snprintf(msg,size,"can\'t find the L2 %s, %s",host,gai_strerror(rc));
    return -1;
  }
  for (ai = res; ai != NULL; ai = ai->ai_next) {
    fd = socket(ai->ai_family,ai->ai_socktype,ai->ai_protocol);
    if (fd < 0)
      continue;
    if (connect(fd,ai->ai_addr,ai->ai_addrlen) == 0)
      break;
    close(fd);
    fd = -1;
  }
  if (fd < 0)
    snprintf(msg,size,"can\'t connect to the L2 at %s:%s, %s",host,port,strerror(errno));
  freeaddrinfo(res);
  return fd;
}

static void syntax(void)
{
  fprintf(stderr,"usage: %s [--l2 <host>] [--port <port>]\n"
                 "  (a telnet client's connection on stdin and stdout, from inetd or systemd)\n",myname);
  exit(2);
}

int main(int argc, char **argv)
{
  static const unsigned char hello[] = { IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA };
  const char *host = "localhost";
  const char *port = SMP_PORT;
  unsigned char buf[4096];
  struct pollfd fds[2];
  char msg[200];
  ssize_t n;
  size_t len;
  int one = 1;
  int l2;
  int i;

  myname = argv[0];
  for (i = 1; i < argc; i++) {
    if (strcmp(argv[i],"--l2") == 0 && i + 1 < argc)
      host = argv[++i];
    else if (strcmp(argv[i],"--port") == 0 && i + 1 < argc)
      port = argv[++i];
    else
      syntax();
  }
  signal(SIGPIPE,SIG_IGN);
  /* (each key as typed: no waiting to fill a packet; fails on a pipe) */
  setsockopt(1,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
  l2 = connect_l2(host,port,msg,sizeof(msg) - 2);
  if (l2 < 0) {
    fprintf(stderr,"%s: %s\n",myname,msg);
    strcat(msg,"\r\n");
    write_all(1,(unsigned char *)msg,strlen(msg));
    return 1;
  }
  setsockopt(l2,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));
  if (write_all(1,hello,sizeof(hello)) != 0)
    return 0;

  fds[0].fd = 0;
  fds[0].events = POLLIN;
  fds[1].fd = l2;
  fds[1].events = POLLIN;
  for (;;) {
    if (poll(fds,2,-1) < 0) {
      if (errno == EINTR)
        continue;
      fprintf(stderr,"%s: poll: %s\n",myname,strerror(errno));
      return 1;
    }
    if (fds[0].revents != 0) {
      n = read(0,buf,sizeof(buf));
      if (n <= 0)
        break;                          /* the client has gone */
      len = from_client(buf,n);
      if (write_all(l2,buf,len) != 0)
        break;
    }
    if (fds[1].revents != 0) {
      n = read(l2,buf,sizeof(buf));
      if (n <= 0)
        break;                          /* the L2 has closed the console (quit) */
      if (to_client(buf,n) != 0)
        break;
    }
  }
  return 0;
}
