/*
 * sys_ctrl/common/sys/minfo.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/sys/minfo.c
 */

#include <mcheck.h>
#include "minfo.h"   /* needed by the reconstruction */
#include "../../l3/l2/smp.h"   /* needed by the reconstruction */
#include "../../l3/main/nvram.h"   /* needed by the reconstruction */
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <malloc.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

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

struct LIST_S {
    int inuse;
    void *addr;
    size_t size;
    size_t usize;
    void *caller;
    struct LIST_S *next;
};
typedef struct LIST_S LIST;

static void restore_malloc(void);
static void override_malloc(void);
static void restore_realloc(void);
static void override_realloc(void);
static void restore_memalign(void);
static void override_memalign(void);
static void restore_free(void);
static void override_free(void);
static void restore(void);
static void override(void);
static void list_insert(char *addr, size_t usize, size_t size, void *caller, char *who);
static void minit(void);
static int get_arena(void);
static void chk_arena(void *caller, char *who, size_t arena, void *addr, size_t size);
static void *mmalloc(size_t size, void *caller);
static void *mrealloc(void *oldptr, size_t newsize, void *caller);
static void *mmemalign(size_t boundary, size_t size, void *caller);
static void mfree(void *ptr, void *caller);

static LIST *head;
static int entries;
static void *omalloc;
static void *orealloc;
static void *ofree;
static void *omemalign;
static int initialized;
static LIST pool[8192];
static int mhist[104857];
static int mcurr[104857];
static int mhole[104857];

static void restore_malloc(void)
{
  __malloc_hook = omalloc;
  return;
}

static void override_malloc(void)
{
  __malloc_hook = mmalloc;
  return;
}

static void restore_realloc(void)
{
  __realloc_hook = orealloc;
  return;
}

static void override_realloc(void)
{
  __realloc_hook = mrealloc;
  return;
}

static void restore_memalign(void)
{
  __memalign_hook = omemalign;
  return;
}

static void override_memalign(void)
{
  __memalign_hook = mmemalign;
  return;
}

static void restore_free(void)
{
  __free_hook = ofree;
  return;
}

static void override_free(void)
{
  __free_hook = mfree;
  return;
}

static void restore(void)
{
  __malloc_hook = omalloc;
  __realloc_hook = orealloc;
  __memalign_hook = omemalign;
  __free_hook = ofree;
  return;
}

static void override(void)
{
  if (omalloc == NULL) {
    fprintf(stderr,"free %x free_hook %x ofree %x\n",free,__free_hook,ofree);
    omalloc = __malloc_hook;
    orealloc = __realloc_hook;
    omemalign = __memalign_hook;
    ofree = __free_hook;
    fprintf(stderr,"free %x free_hook %x ofree %x\n",free,__free_hook,__free_hook);
  }
  __malloc_hook = mmalloc;
  __realloc_hook = mrealloc;
  __memalign_hook = mmemalign;
  __free_hook = mfree;
  return;
}

static void list_insert(char *addr, size_t usize, size_t size, void *caller, char *who)
{
  char *pcVar1;
  LIST *last;
  LIST *curr;
  int index;
  LIST *new;
  
  if (size < 0x100000) {
    new = NULL;
    for (index = 0; (new == NULL && (index < 0x2000)); index = index + 1) {
      if (pool[index].inuse == 0) {
        new = pool + index;
      }
    }
    if (new != NULL) {
      new->inuse = 1;
      pcVar1 = addr + -4;
      new->addr = pcVar1;
      new->size = size + 4;
      new->usize = usize;
      new->caller = caller;
      new->next = NULL;
      if (head == NULL) {
        head = new;
      }
      else if (pcVar1 < (char *)head->addr) {
        new->next = head;
        head = new;
      }
      else {
        for (curr = head; (curr != NULL && ((char *)curr->addr < pcVar1)); curr = curr->next) {
          last = curr;
        }
        if (curr == NULL) {
          last->next = new;
        }
        else {
          if (pcVar1 == curr->addr) {
            /* arguments restored from the machine code (Ghidra dropped them) */
            nvramLogFinsert("%s: curr %x addr %x size %x usize %x, new %x addr %x size %x usize %x",
                            who,curr,curr->addr,curr->size,curr->usize,new,addr,size,usize);
            muntrace();
                    /* WARNING: Subroutine does not return */
            abort();
          }
          new->next = curr;
          last->next = new;
        }
      }
      entries = entries + 1;
    }
  }
  return;
}

int list_delete(char *addr, char *who)
{
  int iVar1;
  LIST *last;
  LIST *curr;
  
  if (head == NULL) {
    iVar1 = 0;
  }
  else if (head->addr == addr + -4) {
    head->inuse = 0;
    head = head->next;
    entries = entries + -1;
    iVar1 = 1;
  }
  else {
    for (curr = head; (curr != NULL && (curr->addr != addr + -4)); curr = curr->next) {
      last = curr;
    }
    if (curr == NULL) {
      iVar1 = 0;
    }
    else {
      curr->inuse = 0;
      last->next = curr->next;
      entries = entries + -1;
      iVar1 = 1;
    }
  }
  return iVar1;
}

static void minit(void)
{
  if (initialized == 0) {
    initialized = 1;
    omalloc = __malloc_hook;
    orealloc = __realloc_hook;
    omemalign = __memalign_hook;
    ofree = __free_hook;
    override();
  }
  return;
}

static int get_arena(void)
{
  struct mallinfo info;
  
  info = mallinfo();
  return info.arena;
}

static void chk_arena(void *caller, char *who, size_t arena, void *addr, size_t size)
{
  struct LIST_S *pLVar1;
  size_t sVar2;
  size_t holesize;
  int holecount;
  size_t holemin;
  size_t holemax;
  LIST *next;
  LIST *curr;
  struct mallinfo info;
  
  info = mallinfo();
  holecount = 0;
  holemax = 0;
  holemin = 0;
  for (curr = head; curr != NULL; curr = curr->next) {
    pLVar1 = curr->next;
    if ((pLVar1 != NULL) && ((void *)((char *)curr->addr + curr->size) < pLVar1->addr)) {
      holesize = (int)((char *)pLVar1->addr - ((char *)curr->addr + curr->size));
      sVar2 = holemin;
      if ((size <= holesize) &&
         ((sVar2 = holesize, holemin != 0 && (sVar2 = holesize, holemin <= holesize)))) {
        sVar2 = holemin;
      }
      holemin = sVar2;
      if (size <= holesize) {
        holecount = holecount + 1;
      }
      if (holemax < holesize) {
        holemax = holesize;
      }
    }
  }
  if ((arena < (uint)info.arena) &&
     (nvramLogFinsert(">>>>> 0x%x %s more core: %d -> %d (%d@%x)\n",caller,who,arena,info.arena,size,addr),
      holecount != 0)) {
    nvramLogFinsert(">>>>> %d holes where found (%d:%d)\n",holecount,holemin,holemax);
  }
  return;
}

static void *mmalloc(size_t size, void *caller)
{
  size_t arena;
  void *ptr;
  uint size_00;
  size_t usize;
  uchar *cptr;
  
  arena = get_arena();
  restore_malloc();
  ptr = malloc(size);
  override_malloc();
  if (ptr == NULL) {
    ptr = NULL;
  }
  else {
    size_00 = malloc_usable_size(ptr);
    list_insert(ptr,size,size_00,caller,"malloc");
    if (size_00 < 0x100000) {
      mhist[size_00 >> 10] = mhist[size_00 >> 10] + 1;
      mcurr[size_00 >> 10] = mcurr[size_00 >> 10] + 1;
    }
  }
  return ptr;
}

static void *mrealloc(void *oldptr, size_t newsize, void *caller)
{
  void *newptr;
  uint size;
  int iVar1;
  size_t unewsize;
  size_t oldsize;
  size_t arena;
  
  oldsize = 0;
  if (oldptr != NULL) {
    oldsize = malloc_usable_size(oldptr);
  }
  get_arena();
  restore_realloc();
  newptr = realloc(oldptr,newsize);
  override_realloc();
  if (newptr == NULL) {
    newptr = NULL;
  }
  else {
    size = malloc_usable_size(newptr);
    if (((oldptr != NULL) && (iVar1 = list_delete(oldptr,"realloc"), iVar1 != 0)) &&
       (oldsize < 0x100000)) {
      mcurr[oldsize >> 10] = mcurr[oldsize >> 10] + -1;
    }
    list_insert(newptr,newsize,size,caller,"realloc");
    if (size < 0x100000) {
      mhist[size >> 10] = mhist[size >> 10] + 1;
      mcurr[size >> 10] = mcurr[size >> 10] + 1;
    }
  }
  return newptr;
}

static void *mmemalign(size_t boundary, size_t size, void *caller)
{
  size_t arena;
  void *ptr;
  uint size_00;
  size_t usize;
  
  arena = get_arena();
  restore_memalign();
  ptr = (void *)memalign(boundary,size);
  override_memalign();
  if (ptr == NULL) {
    ptr = NULL;
  }
  else {
    size_00 = malloc_usable_size(ptr);
    list_insert(ptr,size,size_00,caller,"memalign");
    if (size_00 < 0x100000) {
      mhist[size_00 >> 10] = mhist[size_00 >> 10] + 1;
      mcurr[size_00 >> 10] = mcurr[size_00 >> 10] + 1;
    }
  }
  return ptr;
}

static void mfree(void *ptr, void *caller)
{
  bool bVar1;
  size_t size;
  int iVar2;
  int status;
  
  size = malloc_usable_size(ptr);
  memset(ptr,0x55,size);
  restore_free();
  free(ptr);
  override_free();
  bVar1 = false;
  iVar2 = list_delete(ptr,"free");
  if ((iVar2 != 0) && (size < 0x100000)) {
    bVar1 = true;
  }
  if (bVar1) {
    mcurr[size >> 10] = mcurr[size >> 10] + -1;
  }
  return;
}

void MInfoReset(void)
{
  int index;
  
  if (initialized != 0) {
    head = NULL;
    entries = 0;
    memset(mhist,0,0x66664);
    memset(mcurr,0,0x66664);
    memset(mhole,0,0x66664);
    memset(pool,0,sizeof(pool));
  }
  return;
}

void MInfoEnable(char **rptr)
{
  int status;
  
  if (initialized == 0) {
    initialized = 1;
    override();
  }
  return;
}

void MInfoDisable(void)
{
  if (initialized != 0) {
    initialized = 0;
    restore();
    MInfoReset();
  }
  return;
}

void MInfoStatPrint(char **rptr)
{
  struct LIST_S *pLVar1;
  char *pcVar2;
  size_t sVar3;
  size_t size;
  LIST *next;
  LIST *curr;
  int used;
  int avail;
  int holes;
  int blocks;
  int index;
  char *ptr;
  
  if (initialized == 0) {
    pcVar2 = malloc(0x28);
    *rptr = pcVar2;
    strcpy(*rptr,"malloc profiling not enabled\n");
  }
  else {
    blocks = 0;
    for (index = 0; index < 0x400; index = index + 1) {
      blocks = blocks + mhist[index];
    }
    for (index = 0; index < 0x400; index = index + 1) {
      blocks = blocks + mcurr[index];
    }
    for (curr = head; curr != NULL; curr = curr->next) {
      if ((curr->next != NULL) &&
         ((void *)((char *)curr->addr + curr->size) < curr->next->addr)) {
        blocks = blocks + 1;
      }
    }
    restore_malloc();
    pcVar2 = malloc(blocks * 0x1e + 100);
    *rptr = pcVar2;
    override_malloc();
    strcpy(pcVar2,"cumulative:\n");
    sVar3 = strlen(pcVar2);
    ptr = pcVar2 + sVar3;
    blocks = 0;
    for (index = 0; index < 0x400; index = index + 1) {
      if (mhist[index] != 0) {
        sprintf(ptr,"%4d-%4dK %8d\n",index,index + 1,mhist[index]);
        sVar3 = strlen(ptr);
        ptr = ptr + sVar3;
        blocks = blocks + mhist[index];
      }
    }
    sprintf(ptr,"total %13d\n\n",blocks);
    sVar3 = strlen(ptr);
    pcVar2 = ptr + sVar3;
    strcpy(pcVar2,"current:\n");
    sVar3 = strlen(pcVar2);
    ptr = pcVar2 + sVar3;
    blocks = 0;
    for (index = 0; index < 0x400; index = index + 1) {
      if (mcurr[index] != 0) {
        sprintf(ptr,"%4d-%4dK %8d\n",index,index + 1,mcurr[index]);
        sVar3 = strlen(ptr);
        ptr = ptr + sVar3;
        blocks = blocks + mcurr[index];
      }
    }
    sprintf(ptr,"total %13d\n\n",blocks);
    sVar3 = strlen(ptr);
    pcVar2 = ptr + sVar3;
    strcpy(pcVar2,"holes:\n");
    sVar3 = strlen(pcVar2);
    ptr = pcVar2 + sVar3;
    avail = 0;
    used = 0;
    memset(mhole,0,0x66664);
    for (curr = head; curr != NULL; curr = curr->next) {
      used = used + curr->size;
      pLVar1 = curr->next;
      if ((pLVar1 != NULL) && ((void *)((char *)curr->addr + curr->size) < pLVar1->addr)) {
        size = (int)((char *)pLVar1->addr - ((char *)curr->addr + curr->size));
        mhole[size >> 10] = mhole[size >> 10] + 1;
        avail = avail + size;
      }
    }
    blocks = 0;
    for (index = 0; index < 0x400; index = index + 1) {
      if (mhole[index] != 0) {
        sprintf(ptr,"%4d-%4dK %8d\n",index,index + 1,mhole[index]);
        sVar3 = strlen(ptr);
        ptr = ptr + sVar3;
        blocks = blocks + mhole[index];
      }
    }
    sprintf(ptr,"total %13d\n\n",blocks);
    sVar3 = strlen(ptr);
    pcVar2 = ptr + sVar3;
    sprintf(pcVar2,"available memory %10d\n",avail);
    sVar3 = strlen(pcVar2);
    pcVar2 = pcVar2 + sVar3;
    sprintf(pcVar2,"used memory      %10d\n",used);
    sVar3 = strlen(pcVar2);
    sprintf(pcVar2 + sVar3,"entries          %10d\n",entries);
  }
  return;
}

void MInfoMapPrint(char **rptr)
{
  struct LIST_S *pLVar1;
  char *pcVar2;
  size_t sVar3;
  size_t size;
  LIST *next;
  LIST *curr;
  int holes;
  int index;
  char *ptr;
  
  if (initialized == 0) {
    pcVar2 = malloc(0x28);
    *rptr = pcVar2;
    strcpy(*rptr,"malloc profiling not enabled\n");
  }
  else {
    holes = 0;
    for (curr = head; curr != NULL; curr = curr->next) {
      if ((curr->next != NULL) &&
         ((void *)((char *)curr->addr + curr->size) < curr->next->addr)) {
        holes = holes + 1;
      }
    }
    restore_malloc();
    ptr = malloc((entries + holes * 2) * 0x28 + 100);
    *rptr = ptr;
    override_malloc();
    if ((head == NULL) || (head->next == NULL)) {
      strcpy(ptr,"No memory allocated yet\n");
    }
    else {
      for (curr = head; curr != NULL; curr = curr->next) {
        sprintf(ptr,"%08lx-%08lx %10d %lx\n",(unsigned long)curr->addr,(unsigned long)((char *)curr->addr + curr->size),curr->usize,
                (unsigned long)curr->caller);
        sVar3 = strlen(ptr);
        ptr = ptr + sVar3;
        pLVar1 = curr->next;
        if ((pLVar1 != NULL) && ((void *)((char *)curr->addr + curr->size) < pLVar1->addr)) {
          sprintf(ptr,"%08lx-%08lx %10d HOLE\n",(unsigned long)((char *)curr->addr + curr->size),(unsigned long)pLVar1->addr,
                  (int)((char *)pLVar1->addr - ((char *)curr->addr + curr->size)));
          sVar3 = strlen(ptr);
          ptr = ptr + sVar3;
        }
      }
    }
  }
  return;
}
