/*
 * Equivalence test for the system controller device's chunk framing
 * (l3/IRouter/IRouterOS.c): frames of every size cut into chunks by the
 * rewritten and the original pipe_out(), and chunk sequences (good ones and
 * broken ones) put back together by both pipe_in()s. Run by
 * tests/unit/snsc_test.sh.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PREFIX_OFF 16           /* (IR_FRAME_PREFIX: room before the wire frame) */

int new_pipe_out(int fd, unsigned char *pptr, int plen);
int orig_pipe_out(int fd, unsigned char *pptr, int plen);
int new_pipe_in(int fd, unsigned char **pptr, int plen);
int orig_pipe_in(int fd, unsigned char **pptr, int plen);

/* (never called: the IRouter calls of the rest of the file) */
void syslog(int level, char *fl, int ln, int msgno, char *fmt, ...) {}
void *IRouterMakePacket() { abort(); }
int IRouterWritePacket() { abort(); }
int IRouterReadPacket() { abort(); }
void IRouterFreePacket() { abort(); }

static int sv[2];
static int failures, compared;

/* everything written to sv[0], as "len:bytes" per chunk */
static int drain(unsigned char *out)
{
  unsigned char chunk[256];
  int n, len = 0;

  while ((n = recv(sv[1], chunk, sizeof(chunk), MSG_DONTWAIT)) > 0) {
    out[len++] = n;
    memcpy(out + len, chunk, n);
    len += n;
  }
  return len;
}

static void check_out(unsigned char *frame, int plen, int n)
{
  static unsigned char a[4000], b[4000];
  int ra, rb, la, lb;

  ra = new_pipe_out(sv[0], frame, plen);
  la = drain(a);
  rb = orig_pipe_out(sv[0], frame, plen);
  lb = drain(b);
  compared++;
  if (ra != rb || la != lb || memcmp(a, b, la) != 0) {
    printf("FAIL  pipe_out %d (%d bytes)\n", n, plen);
    failures++;
  }
}

/* send chunks (the same for both) and read a frame back */
static void check_in(unsigned char chunks[][128], int *lens, int nchunks, int plen, int n, int orig_ok)
{
  unsigned char abuf[2000], bbuf[2000], *ap = abuf, *bp = bbuf;
  int i, ra, rb;
  unsigned char junk[256];

  memset(abuf, 0xaa, sizeof(abuf));
  memset(bbuf, 0xaa, sizeof(bbuf));
  for (i = 0; i < nchunks; i++)
    send(sv[1], chunks[i], lens[i], 0);
  ra = new_pipe_in(sv[0], &ap, plen);
  while (recv(sv[0], junk, sizeof(junk), MSG_DONTWAIT) > 0)
    ;
  if (!orig_ok) {
    if (ra >= 0) {
      printf("FAIL  pipe_in %d (new only): %d\n", n, ra);
      failures++;
    }
    return;
  }
  for (i = 0; i < nchunks; i++)
    send(sv[1], chunks[i], lens[i], 0);
  rb = orig_pipe_in(sv[0], &bp, plen);
  while (recv(sv[0], junk, sizeof(junk), MSG_DONTWAIT) > 0)
    ;
  compared++;
  if (ra != rb || memcmp(abuf, bbuf, sizeof(abuf)) != 0) {
    printf("FAIL  pipe_in %d: %d vs %d\n", n, ra, rb);
    failures++;
  }
}

int main(void)
{
  static unsigned char frame[1100], chunks[40][128];
  int lens[40];
  unsigned int seed = 5;
  int run, plen, i, n, off, kind;

  socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);

  for (run = 0; run < 3000; run++) {
    plen = 1 + rand_r(&seed) % (run < 500 ? 260 : 1024);
    for (i = 0; i < plen; i++)
      frame[i] = rand_r(&seed);
    check_out(frame, plen, run);
  }

  for (run = 0; run < 3000; run++) {
    /* a frame as pipe_out() would send it */
    plen = 20 + rand_r(&seed) % 1000;
    n = 0;
    for (off = 0; off < plen; off += 118) {
      int blen = plen - off < 118 ? plen - off : 118;
      memset(chunks[n], 0, 9);
      chunks[n][4] = '0';
      chunks[n][5] = off == 0 ? 1 + rand_r(&seed) % 2 : 3;
      if (off == 0) {
        chunks[n][6] = rand_r(&seed) % 4;
        chunks[n][7] = plen >> 8;
        chunks[n][8] = plen;
      }
      for (i = 0; i < blen; i++)
        chunks[n][9 + i] = rand_r(&seed);
      lens[n++] = 9 + blen;
    }
    /* and broken */
    kind = rand_r(&seed) % 8;
    switch (kind) {
    case 0: chunks[0][5] = 0; break;                       /* bad chunk type */
    case 1: chunks[0][5] = 4; break;
    case 2: if (n > 1) chunks[1][5] = 1; break;            /* a new frame inside */
    case 3: chunks[0][7] = 0; chunks[0][8] = 10; break;    /* more data than said */
    case 4: chunks[0][4] = '1'; break;
    case 6: if (lens[n - 1] < 128) chunks[n - 1][lens[n - 1]++] = 0x55; break;   /* one byte too many */
    }
    check_in(chunks, lens, n, kind == 5 ? plen - 1 : 1100, run, 1);
  }
  /* a chunk shorter than its header (the original copied a negative size) */
  memset(chunks[0], 0, 9);
  chunks[0][4] = '0';
  chunks[0][5] = 1;
  chunks[0][8] = 5;
  lens[0] = 4;
  check_in(chunks, lens, 1, 1100, -1, 0);

  if (failures == 0)
    printf("PASS  snsc: %d chunkings and reassemblies compared with the original\n", compared);
  return failures != 0;
}
