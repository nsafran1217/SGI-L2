/*
 * sys_ctrl/common/sys/minfo.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/minfo.c
 *
 * Malloc profiling for l2's "l2dbg menable/mstat/mmap/mreset/mdisable":
 * glibc's malloc hooks route every allocation through here, which keeps
 * the live blocks in an address-ordered list (up to POOL_SIZE of them) and
 * counts allocations by size in 1 KB buckets.
 */

#include <malloc.h>
#include <mcheck.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "minfo.h"
#include "../../l3/main/nvram.h"

/* glibc 2.34 removed the malloc hooks this module installs. Without them the
 * names below are plain variables: the module builds and its commands work,
 * but nothing calls through them, so allocation tracking records nothing
 * (see DEVIATIONS.md). With an older glibc the real hooks are used. */
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
static void *minfo_malloc_hook, *minfo_realloc_hook, *minfo_memalign_hook, *minfo_free_hook;
#define __malloc_hook minfo_malloc_hook
#define __realloc_hook minfo_realloc_hook
#define __memalign_hook minfo_memalign_hook
#define __free_hook minfo_free_hook
#endif

#define POOL_SIZE     8192      /* blocks tracked at once */
#define MAX_TRACKED   0x100000  /* larger blocks are not tracked */
#define BUCKETS       (MAX_TRACKED >> 10)       /* 1 KB each */
#define HIST_SIZE     104857    /* (SGI's size; only BUCKETS are used) */
#define CHUNK_HEADER  4         /* the i386 glibc chunk header before a block */
#define FREED_FILL    0x55      /* freed blocks are overwritten with this */

struct LIST_S {
    int inuse;
    void *addr;                 /* the chunk: the block less its header */
    size_t size;                /* usable size plus the header */
    size_t usize;               /* the size asked for */
    void *caller;
    struct LIST_S *next;
};
typedef struct LIST_S LIST;

static void *mmalloc(size_t size, void *caller);
static void *mrealloc(void *oldptr, size_t newsize, void *caller);
static void *mmemalign(size_t boundary, size_t size, void *caller);
static void mfree(void *ptr, void *caller);

static LIST *head;              /* by address */
static int entries;
static void *omalloc;           /* glibc's hooks before ours */
static void *orealloc;
static void *ofree;
static void *omemalign;
static int initialized;
static LIST pool[POOL_SIZE];
static int mhist[HIST_SIZE];    /* all allocations, by size */
static int mcurr[HIST_SIZE];    /* live blocks, by size */
static int mhole[HIST_SIZE];    /* gaps between live blocks, by size */

/* our hooks call malloc() etc. with glibc's hook back in place */
static void restore_malloc(void)
{
  __malloc_hook = omalloc;
}

static void override_malloc(void)
{
  __malloc_hook = mmalloc;
}

static void restore_realloc(void)
{
  __realloc_hook = orealloc;
}

static void override_realloc(void)
{
  __realloc_hook = mrealloc;
}

static void restore_memalign(void)
{
  __memalign_hook = omemalign;
}

static void override_memalign(void)
{
  __memalign_hook = mmemalign;
}

static void restore_free(void)
{
  __free_hook = ofree;
}

static void override_free(void)
{
  __free_hook = mfree;
}

static void restore(void)
{
  __malloc_hook = omalloc;
  __realloc_hook = orealloc;
  __memalign_hook = omemalign;
  __free_hook = ofree;
}

static void override(void)
{
  if (omalloc == NULL) {
    /* (SGI's debugging output; the second line prints the saved hook) */
    fprintf(stderr,"free %lx free_hook %lx ofree %lx\n",(unsigned long)(uintptr_t)free,
            (unsigned long)(uintptr_t)__free_hook,(unsigned long)(uintptr_t)ofree);
    omalloc = __malloc_hook;
    orealloc = __realloc_hook;
    omemalign = __memalign_hook;
    ofree = __free_hook;
    fprintf(stderr,"free %lx free_hook %lx ofree %lx\n",(unsigned long)(uintptr_t)free,
            (unsigned long)(uintptr_t)__free_hook,(unsigned long)(uintptr_t)__free_hook);
  }
  __malloc_hook = mmalloc;
  __realloc_hook = mrealloc;
  __memalign_hook = mmemalign;
  __free_hook = mfree;
}

/* add a block (usize asked for, size usable) to the list, in address order;
 * a block already there means the heap is corrupt: log it and abort */
static void list_insert(char *addr, size_t usize, size_t size, void *caller, char *who)
{
  char *chunk = addr - CHUNK_HEADER;
  LIST *new = NULL, *curr, *last = NULL;
  int index;

  if (size >= MAX_TRACKED)
    return;
  for (index = 0; new == NULL && index < POOL_SIZE; index++)
    if (!pool[index].inuse)
      new = &pool[index];
  if (new == NULL)
    return;                     /* (the pool is full: not tracked) */
  new->inuse = 1;
  new->addr = chunk;
  new->size = size + CHUNK_HEADER;
  new->usize = usize;
  new->caller = caller;
  new->next = NULL;

  if (head == NULL) {
    head = new;
  }
  else if (chunk < (char *)head->addr) {
    new->next = head;
    head = new;
  }
  else {
    for (curr = head; curr != NULL && (char *)curr->addr < chunk; curr = curr->next)
      last = curr;
    if (curr != NULL && (char *)curr->addr == chunk) {
      nvramLogFinsert("%s: curr %lx addr %lx size %zx usize %zx, new %lx addr %lx size %zx usize %zx",
                      who,(unsigned long)(uintptr_t)curr,(unsigned long)(uintptr_t)curr->addr,
                      curr->size,curr->usize,(unsigned long)(uintptr_t)new,
                      (unsigned long)(uintptr_t)addr,size,usize);
      muntrace();
      abort();
    }
    new->next = curr;
    last->next = new;
  }
  entries++;
}

/* drop a block from the list; 1 if it was there */
int list_delete(char *addr, char *who)
{
  char *chunk = addr - CHUNK_HEADER;
  LIST *curr, *last = NULL;

  for (curr = head; curr != NULL && (char *)curr->addr != chunk; curr = curr->next)
    last = curr;
  if (curr == NULL)
    return 0;
  curr->inuse = 0;
  if (last == NULL)
    head = curr->next;
  else
    last->next = curr->next;
  entries--;
  return 1;
}

static int get_arena(void)
{
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
  return (int)mallinfo2().arena;   /* mallinfo() is deprecated since glibc 2.33 */
#else
  return mallinfo().arena;
#endif
}

/* count an allocation of size usable bytes */
static void count_block(size_t size)
{
  if (size < MAX_TRACKED) {
    mhist[size >> 10]++;
    mcurr[size >> 10]++;
  }
}

static void *mmalloc(size_t size, void *caller)
{
  size_t usable;
  void *ptr;

  get_arena();                  /* (the original read it and did nothing with it) */
  restore_malloc();
  ptr = malloc(size);
  override_malloc();
  if (ptr == NULL)
    return NULL;
  usable = malloc_usable_size(ptr);
  list_insert(ptr,size,usable,caller,"malloc");
  count_block(usable);
  return ptr;
}

static void *mrealloc(void *oldptr, size_t newsize, void *caller)
{
  size_t oldsize = 0, usable;
  void *newptr;

  uintptr_t oldaddr = (uintptr_t)oldptr;        /* (only compared once realloc() has it) */

  if (oldptr != NULL)
    oldsize = malloc_usable_size(oldptr);
  get_arena();
  restore_realloc();
  newptr = realloc(oldptr,newsize);
  override_realloc();
  if (newptr == NULL)
    return NULL;
  usable = malloc_usable_size(newptr);
  if (oldaddr != 0 && list_delete((char *)oldaddr,"realloc") && oldsize < MAX_TRACKED)
    mcurr[oldsize >> 10]--;
  list_insert(newptr,newsize,usable,caller,"realloc");
  count_block(usable);
  return newptr;
}

static void *mmemalign(size_t boundary, size_t size, void *caller)
{
  size_t usable;
  void *ptr;

  get_arena();
  restore_memalign();
  ptr = memalign(boundary,size);
  override_memalign();
  if (ptr == NULL)
    return NULL;
  usable = malloc_usable_size(ptr);
  list_insert(ptr,size,usable,caller,"memalign");
  count_block(usable);
  return ptr;
}

static void mfree(void *ptr, void *caller)
{
  size_t size;
  int listed;

  size = malloc_usable_size(ptr);
  memset(ptr,FREED_FILL,size);
  listed = list_delete(ptr,"free");     /* (before the free: the same as after) */
  restore_free();
  free(ptr);
  override_free();
  if (listed && size < MAX_TRACKED)
    mcurr[size >> 10]--;
}

void MInfoReset(void)
{
  if (!initialized)
    return;
  head = NULL;
  entries = 0;
  memset(mhist,0,sizeof(mhist));
  memset(mcurr,0,sizeof(mcurr));
  memset(mhole,0,sizeof(mhole));
  memset(pool,0,sizeof(pool));
}

void MInfoEnable(char **rptr)
{
  if (!initialized) {
    initialized = 1;
    override();
  }
}

void MInfoDisable(void)
{
  if (initialized) {
    initialized = 0;
    restore();
    MInfoReset();
  }
}

/* the gap between a block and the next, or 0 */
static size_t hole_after(LIST *curr)
{
  char *end = (char *)curr->addr + curr->size;

  if (curr->next == NULL || end >= (char *)curr->next->addr)
    return 0;
  return (char *)curr->next->addr - end;
}

static char *not_enabled(void)
{
  return strdup("malloc profiling not enabled\n");
}

/* a histogram's nonzero buckets and their total */
static char *print_buckets(char *ptr, const char *title, int *hist)
{
  int index, total = 0;

  ptr += sprintf(ptr,"%s",title);
  for (index = 0; index < BUCKETS; index++) {
    if (hist[index] != 0) {
      ptr += sprintf(ptr,"%4d-%4dK %8d\n",index,index + 1,hist[index]);
      total += hist[index];
    }
  }
  ptr += sprintf(ptr,"total %13d\n\n",total);
  return ptr;
}

/* "l2dbg mstat": allocations by size, cumulative and current, and the holes */
void MInfoStatPrint(char **rptr)
{
  LIST *curr;
  size_t hole;
  int index, lines = 0, avail = 0, used = 0;
  char *ptr;

  if (!initialized) {
    *rptr = not_enabled();
    return;
  }
  /* (more than enough lines: the original counts blocks, not buckets; but
   * its 100 bytes for the rest were too few with under three blocks) */
  for (index = 0; index < BUCKETS; index++)
    lines += mhist[index] + mcurr[index];
  for (curr = head; curr != NULL; curr = curr->next)
    if (hole_after(curr) != 0)
      lines++;
  restore_malloc();
  ptr = malloc(lines * 30 + 200);
  *rptr = ptr;
  override_malloc();

  ptr = print_buckets(ptr,"cumulative:\n",mhist);
  ptr = print_buckets(ptr,"current:\n",mcurr);
  memset(mhole,0,sizeof(mhole));
  for (curr = head; curr != NULL; curr = curr->next) {
    used += curr->size;
    hole = hole_after(curr);
    if (hole != 0) {
      /* (the original counted any size: past 100 MB, out of mhole; buckets
       * past 1 MB are never printed) */
      if (hole < MAX_TRACKED)
        mhole[hole >> 10]++;
      avail += hole;
    }
  }
  ptr = print_buckets(ptr,"holes:\n",mhole);
  ptr += sprintf(ptr,"available memory %10d\n",avail);
  ptr += sprintf(ptr,"used memory      %10d\n",used);
  sprintf(ptr,"entries          %10d\n",entries);
}

/* "l2dbg mmap": the live blocks and holes in address order */
void MInfoMapPrint(char **rptr)
{
  LIST *curr;
  size_t hole;
  int holes = 0;
  char *ptr;

  if (!initialized) {
    *rptr = not_enabled();
    return;
  }
  for (curr = head; curr != NULL; curr = curr->next)
    if (hole_after(curr) != 0)
      holes++;
  /* (40 bytes a line in the original, too few for 64-bit addresses) */
  restore_malloc();
  ptr = malloc((entries + holes * 2) * 80 + 100);
  *rptr = ptr;
  override_malloc();
  if (head == NULL || head->next == NULL) {
    strcpy(ptr,"No memory allocated yet\n");
    return;
  }
  for (curr = head; curr != NULL; curr = curr->next) {
    ptr += sprintf(ptr,"%08lx-%08lx %10d %lx\n",(unsigned long)(uintptr_t)curr->addr,
                   (unsigned long)(uintptr_t)((char *)curr->addr + curr->size),(int)curr->usize,
                   (unsigned long)(uintptr_t)curr->caller);
    hole = hole_after(curr);
    if (hole != 0)
      ptr += sprintf(ptr,"%08lx-%08lx %10d HOLE\n",
                     (unsigned long)(uintptr_t)((char *)curr->addr + curr->size),
                     (unsigned long)(uintptr_t)curr->next->addr,(int)hole);
  }
}
