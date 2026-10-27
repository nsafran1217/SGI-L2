/*
 * stdbuf.h: stdout buffered as glibc buffers it, whatever the C library.
 *
 * glibc makes stdout fully buffered when it is not a terminal. musl (the
 * static release builds) line-buffers it until its first write finds no
 * terminal, so the first line comes out at once: ahead of messages on
 * stderr that glibc's build puts first, and even when glibc's build loses
 * it in the buffer (l2 killed). Each tool's main() calls this first, so
 * that both builds write the same transcripts (tests/golden).
 */
#ifndef STDBUF_H
#define STDBUF_H

#include <stdio.h>
#include <unistd.h>

static inline void stdout_buffered(void)
{
  if (!isatty(1))
    setvbuf(stdout,NULL,_IOFBF,BUFSIZ);
}

#endif /* STDBUF_H */
