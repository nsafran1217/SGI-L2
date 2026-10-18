/*
 * sys_ctrl/common/Router/Event.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Event.c
 *
 * The event loop every tool runs on: callbacks for readable and writable file
 * descriptors (indexed by fd in EventIOList) and timers (EventTimerQueue,
 * sorted by expiry, with a free list of spent entries), driven by select().
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include "Event.h"
#include "EventMsg.h"

#define EVENT_MAX_FD  1024

static void EventIOListAlloc(int fd);
static fd_set fdset_and(fd_set *fd1, fd_set *fd2);
static void EventSetFDRange(int fd);
static void EventQueueTimer(EventTimerEntry *entry);
static void EventRemoveBadFD(void);

EventIOEntry *EventIOList;
int EventIOListSize;
unsigned int EventIOErrors;
unsigned int EventTimerErrors;
long unsigned int EventInputCBCount;
long unsigned int EventOutputCBCount;
long unsigned int EventTimerCBCount;
long unsigned int EventSelectCount;
static int EventFDRange;                /* highest registered fd + 1 */
EventTimerEntry *EventTimerQueue;
EventTimerEntry *EventTimerFreeList;
static fd_set EventReadSet;             /* registered */
static fd_set EventWriteSet;
static fd_set EventReadMask;            /* passed to (and returned by) select() */
static fd_set EventWriteMask;
static int EventStopFlag;

char *EventStats(int clear)
{
  static char buf[80];

  sprintf(buf,"input:%lu    output:%lu    timers:%lu    select:%lu",EventInputCBCount,
          EventOutputCBCount,EventTimerCBCount,EventSelectCount);
  if (clear) {
    EventOutputCBCount = 0;
    EventInputCBCount = 0;
    EventSelectCount = 0;
    EventTimerCBCount = 0;
  }
  return buf;
}

/* make EventIOList[fd] exist (128 entries at first) */
static void EventIOListAlloc(int fd)
{
  int old_size = EventIOListSize;

  if (EventIOListSize == 0) {
    EventIOListSize = fd < 128 ? 128 : fd + 1;
    EventIOList = calloc(EventIOListSize, sizeof(EventIOEntry));
  }
  else if (fd >= EventIOListSize) {
    EventIOListSize = fd + 1;
    EventIOList = realloc(EventIOList, EventIOListSize * sizeof(EventIOEntry));
    /* (the original cleared only entry fd, leaving any between uninitialized) */
    memset(EventIOList + old_size, 0, (EventIOListSize - old_size) * sizeof(EventIOEntry));
  }
}

/* start watching fd for reading */
static void watch_input(int fd)
{
  FD_SET(fd, &EventReadSet);
  if (fd >= EventFDRange)
    EventFDRange = fd + 1;
}

EventID EventAddInput(int fd, void (*input_func)(), EventData client_data, char *desc)
{
  if (fd > EVENT_MAX_FD) {
    LogError(EVENT_ERR_FD_RANGE,"EventAddInput",0,"");
    return EVENT_MAX_FD;
  }
  EventIOListAlloc(fd);
  if (EventIOList[fd].input_func != NULL)
    LogError(EVENT_ERR_INPUT_OVERLAY,"EventAddInput",0,"");
  EventIOList[fd].input_func = input_func;
  EventIOList[fd].input_data = client_data;
  strcpy(EventIOList[fd].input_desc,desc != NULL ? desc : "EventAddInput");
  watch_input(fd);
  return fd;
}

/* replace fd's input callback, returning the old one */
void EventReplaceInput(int fd, void (*new_input_func)(), EventData new_client_data, char *new_desc, void (**old_input_func)(), EventData *old_client_data, char *old_desc)
{
  if (fd > EVENT_MAX_FD) {
    LogError(EVENT_ERR_FD_RANGE,"EventReplaceInput",0,"");
    return;
  }
  EventIOListAlloc(fd);
  if (old_input_func != NULL)
    *old_input_func = EventIOList[fd].input_func;
  if (old_client_data != NULL)
    *old_client_data = EventIOList[fd].input_data;
  if (old_desc != NULL)
    strcpy(old_desc,EventIOList[fd].input_desc);
  EventIOList[fd].input_func = new_input_func;
  EventIOList[fd].input_data = new_client_data;
  strcpy(EventIOList[fd].input_desc,new_desc != NULL ? new_desc : "EventReplaceInput");
  watch_input(fd);
}

/* replace fd's input callback until EventRestoreInputTemp() */
void EventReplaceInputTemp(int fd, void (*new_input_func)(), EventData new_client_data, char *new_desc)
{
  EventIOEntry *e;

  if (fd > EVENT_MAX_FD) {
    LogError(EVENT_ERR_FD_RANGE,"EventReplaceInputTemp",0,"");
    return;
  }
  EventIOListAlloc(fd);
  e = &EventIOList[fd];
  e->input_func_orig = e->input_func;
  e->input_data_orig = e->input_data;
  strcpy(e->input_desc_orig,e->input_desc);
  e->input_func = new_input_func;
  e->input_data = new_client_data;
  strcpy(e->input_desc,new_desc != NULL ? new_desc : "EventReplaceInputTemp");
  watch_input(fd);
}

void EventRestoreInputTemp(int fd)
{
  EventIOEntry *e;

  if (fd > EVENT_MAX_FD) {
    LogError(EVENT_ERR_FD_RANGE,"EventRestoreInputTemp",0,"");
    return;
  }
  EventIOListAlloc(fd);
  e = &EventIOList[fd];
  if (e->input_func_orig != NULL) {
    e->input_func = e->input_func_orig;
    e->input_data = e->input_data_orig;
    strcpy(e->input_desc,e->input_desc_orig);
  }
  e->input_func_orig = NULL;
  e->input_data_orig = NULL;
  e->input_desc_orig[0] = '\0';
  watch_input(fd);
}

void EventRemoveInput(EventID id)
{
  if (id < (unsigned int)EventIOListSize) {
    EventIOList[id].input_func = NULL;
    EventIOList[id].input_data = NULL;
    EventIOList[id].input_desc[0] = '\0';
    FD_CLR(id, &EventReadSet);
    FD_CLR(id, &EventReadMask);
    EventSetFDRange(id);
  }
}

EventID EventAddOutput(int fd, void (*output_func)(), EventData client_data, char *desc)
{
  if (fd > EVENT_MAX_FD) {
    LogError(EVENT_ERR_FD_RANGE,"EventAddOutput",0,"");
    return EVENT_MAX_FD;
  }
  EventIOListAlloc(fd);
  if (EventIOList[fd].output_func != NULL)
    LogError(EVENT_ERR_OUTPUT_OVERLAY,"EventAddOutput",0,"");
  EventIOList[fd].output_func = output_func;
  EventIOList[fd].output_data = client_data;
  strcpy(EventIOList[fd].output_desc,desc != NULL ? desc : "EventAddOutput");
  FD_SET(fd, &EventWriteSet);
  if (fd >= EventFDRange)
    EventFDRange = fd + 1;
  return fd;
}

void EventRemoveOutput(EventID id)
{
  if (id < (unsigned int)EventIOListSize) {
    EventIOList[id].output_func = NULL;
    EventIOList[id].output_data = NULL;
    EventIOList[id].output_desc[0] = '\0';
    FD_CLR(id, &EventWriteSet);
    FD_CLR(id, &EventWriteMask);
    EventSetFDRange(id);
  }
}

/* stop or resume watching a registered fd (the callback stays) */
void EventEnableOutput(EventID id, int enable)
{
  if (enable) {
    FD_SET(id, &EventWriteSet);
  }
  else {
    FD_CLR(id, &EventWriteSet);
    FD_CLR(id, &EventWriteMask);
  }
}

void EventEnableInput(EventID id, int enable)
{
  if (enable) {
    FD_SET(id, &EventReadSet);
  }
  else {
    FD_CLR(id, &EventReadSet);
    FD_CLR(id, &EventReadMask);
  }
}

/* carry/borrow microseconds into seconds; a negative time becomes zero */
static void tv_normalize(struct timeval *tv)
{
  while (tv->tv_usec > 999999) {
    tv->tv_usec -= 1000000;
    tv->tv_sec++;
  }
  while (tv->tv_usec < 0) {
    if (tv->tv_sec < 1) {
      tv->tv_sec = 0;
      tv->tv_usec = 0;
      break;
    }
    tv->tv_usec += 1000000;
    tv->tv_sec--;
  }
}

static int tv_before(const struct timeval *a, const struct timeval *b)
{
  return a->tv_sec < b->tv_sec || (a->tv_sec == b->tv_sec && a->tv_usec < b->tv_usec);
}

/* *diff = later - now (later is not before now) */
static void tv_sub(struct timeval *diff, const struct timeval *later, const struct timeval *now)
{
  diff->tv_usec = later->tv_usec - now->tv_usec;
  diff->tv_sec = later->tv_sec - now->tv_sec;
  if (diff->tv_usec < 0) {
    diff->tv_usec += 1000000;
    diff->tv_sec--;
  }
}

/* call timer_func(client_data) after the given time; returns the timer's id */
EventID EventAddTimeOut(long unsigned int seconds, long unsigned int microseconds, void (*timer_func)(), EventData client_data, char *desc)
{
  EventTimerEntry *entry;

  if (EventTimerFreeList != NULL) {
    entry = EventTimerFreeList;
    EventTimerFreeList = entry->next;
  }
  else {
    entry = malloc(sizeof(EventTimerEntry));
    if (entry == NULL) {
      EventTimerErrors++;
      LogError(EVENT_ERR_MALLOC,"EventAddTimeOut",0,"");
      return 0;
    }
  }
  EventCreateTimeOut(entry,seconds,microseconds,timer_func,client_data,desc);
  EventQueueTimer(entry);
  return (EventID)entry;
}

/* fill in a timer without queueing it (EVENT_TIMER_ARMED; see Event.h) */
int EventCreateTimeOut(EventTimerEntry *entry, long unsigned int seconds, long unsigned int microseconds, void (*timer_func)(), EventData client_data, char *desc)
{
  struct timeval now;

  gettimeofday(&now,NULL);
  entry->timer_value.tv_sec = seconds + now.tv_sec;
  entry->timer_value.tv_usec = microseconds + now.tv_usec;
  tv_normalize(&entry->timer_value);
  entry->timer_func = timer_func;
  entry->timer_data = client_data;
  if (desc == NULL)
    sprintf(entry->desc,"T %lx",(unsigned long)(uintptr_t)entry);
  else
    strcpy(entry->desc,desc);
  entry->next = EVENT_TIMER_ARMED;
  return 0;
}

void EventRemoveTimeOut(EventID id)
{
  EventTimerEntry **link;
  EventTimerEntry *t;

  for (link = &EventTimerQueue; (t = *link) != NULL; link = &t->next) {
    if (t == (EventTimerEntry *)id) {
      *link = t->next;
      t->next = EventTimerFreeList;
      EventTimerFreeList = t;
      return;
    }
  }
}

static fd_set fdset_and(fd_set *fd1, fd_set *fd2)
{
  fd_set outset;
  int i;

  /* NULL means "no restriction": the result is the other set */
  FD_ZERO(&outset);
  if (fd1 != NULL && fd2 == NULL)
    return *fd1;
  if (fd1 == NULL && fd2 != NULL)
    return *fd2;
  if (fd1 == NULL && fd2 == NULL)
    return outset;
  for (i = 0; i < FD_SETSIZE; i++) {
    if (FD_ISSET(i, fd1) && FD_ISSET(i, fd2))
      FD_SET(i, &outset);
  }
  return outset;
}

/*
 * The event loop. Each round fires the timers that are due, then waits in
 * select() for the registered descriptors (limited to rd_subset/wr_subset when
 * given) until the next timer, and calls the callbacks for those that are ready:
 * output first, then input. With oneshot it does one round, waiting at most
 * 10 microseconds. With tlist it runs that private array of tcnt timers (made by
 * EventCreateTimeOut) instead of the timer queue. EventStop() ends it.
 *
 * The locals are static, as in the original: a callback may run a nested event
 * loop (IRouterL3 does), and the outer loop then continues with the nested
 * loop's i.
 */
void event_process(int oneshot, fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt)
{
  static struct timeval cur_time;
  static struct timeval wait_time;
  static struct timeval *timeout;
  static EventTimerEntry *tmp;
  static int nevents;
  static int i;
  struct timeval next_time;
  EventTimerEntry *tptr;
  int tpcnt;
  int loop;

  EventStopFlag = 0;
  for (loop = 1; loop != 0; loop -= oneshot) {
    if (tlist != NULL) {
      /* the private timer list: fire the armed ones that are due */
      next_time.tv_sec = 0x7fffffff;
      next_time.tv_usec = 0;
      gettimeofday(&cur_time,NULL);
      tv_normalize(&cur_time);
      for (tptr = tlist, tpcnt = tcnt; tptr != NULL; tptr++) {
        if (tptr->next == EVENT_TIMER_ARMED) {
          if (tv_before(&tptr->timer_value,&cur_time)) {
            EventTimerCBCount++;
            tptr->timer_func(tptr->timer_data);
            tptr->next = EVENT_TIMER_FIRED;
          }
          else if (tv_before(&tptr->timer_value,&next_time)) {
            next_time = tptr->timer_value;
          }
        }
        if (tpcnt != 0 && --tpcnt == 0)
          break;
      }
      if (EventStopFlag)
        break;
      if (next_time.tv_sec == 0x7fffffff) {
        timeout = NULL;
      }
      else {
        tv_sub(&wait_time,&next_time,&cur_time);
        timeout = &wait_time;
      }
    }
    else if (EventTimerQueue != NULL) {
      /* the timer queue: fire (and free) the timers that are due */
      gettimeofday(&cur_time,NULL);
      tv_normalize(&cur_time);
      while (tv_before(&EventTimerQueue->timer_value,&cur_time)) {
        tmp = EventTimerQueue;
        EventTimerCBCount++;
        EventTimerQueue = tmp->next;
        tmp->timer_func(tmp->timer_data);
        tmp->next = EventTimerFreeList;
        EventTimerFreeList = tmp;
        if (EventTimerQueue == NULL || EventStopFlag)
          break;
      }
      if (EventStopFlag)
        break;
      if (EventTimerQueue == NULL) {
        timeout = NULL;
      }
      else {
        tv_sub(&wait_time,&EventTimerQueue->timer_value,&cur_time);
        timeout = &wait_time;
      }
    }
    else {
      if (EventFDRange < 1)
        return;                 /* nothing to wait for */
      timeout = NULL;
    }

    EventReadMask = fdset_and(&EventReadSet,rd_subset);
    EventWriteMask = fdset_and(&EventWriteSet,wr_subset);
    if (oneshot && (timeout == NULL || timeout->tv_sec * 1000000 + timeout->tv_usec > 10)) {
      wait_time.tv_sec = 0;
      wait_time.tv_usec = 10;
      timeout = &wait_time;
    }
    EventSelectCount++;
    nevents = select(EventFDRange,&EventReadMask,&EventWriteMask,NULL,timeout);
    if (nevents == -1) {
      if (errno == EBADF) {
        EventRemoveBadFD();
      }
      else if (errno != EINTR) {
        LogError(EVENT_ERR_SELECT,"select",errno,"");
        return;
      }
    }
    else if (nevents > 0 && !EventStopFlag) {
      for (i = 0; i < EventFDRange && !EventStopFlag; i++) {
        if (FD_ISSET(i, &EventWriteMask)) {
          if (EventIOList[i].output_func == NULL) {
            LogError(EVENT_ERR_NO_OUTPUT_FUNC,"EventStart",0,"");
            EventRemoveOutput(i);
          }
          else {
            EventOutputCBCount++;
            EventIOList[i].output_func(EventIOList[i].output_data,i);
          }
        }
      }
      for (i = 0; i < EventFDRange && !EventStopFlag; i++) {
        if (FD_ISSET(i, &EventReadMask)) {
          if (EventIOList[i].input_func == NULL) {
            LogError(EVENT_ERR_NO_INPUT_FUNC,"EventStart",0,"");
            EventRemoveInput(i);
          }
          else {
            EventInputCBCount++;
            EventIOList[i].input_func(EventIOList[i].input_data,i);
          }
        }
      }
    }
    if (EventStopFlag)
      break;
  }
  EventStopFlag = 0;
}

void EventStart(void)
{
  event_process(0,NULL,NULL,NULL,0);
}

void EventDispatch(void)
{
  event_process(1,NULL,NULL,NULL,0);
}

void EventStartSubset(fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt)
{
  event_process(0,rd_subset,wr_subset,tlist,tcnt);
}

void EventDispatchSubset(fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt)
{
  event_process(1,rd_subset,wr_subset,tlist,tcnt);
}

void EventStop(void)
{
  EventStopFlag = 1;
}

/* after fd lost its callbacks: shrink EventFDRange if fd was the highest */
static void EventSetFDRange(int fd)
{
  int i;

  if (fd + 1 >= EventFDRange) {
    EventFDRange = 0;
    for (i = fd; i >= 0; i--) {
      if (EventIOList[i].input_func != NULL || EventIOList[i].output_func != NULL) {
        EventFDRange = i + 1;
        return;
      }
    }
  }
}

/* insert into EventTimerQueue after the timers that expire no later */
static void EventQueueTimer(EventTimerEntry *entry)
{
  EventTimerEntry **link = &EventTimerQueue;

  while (*link != NULL && !tv_before(&entry->timer_value,&(*link)->timer_value))
    link = &(*link)->next;
  entry->next = *link;
  *link = entry;
}

/* select() said EBADF: find the descriptors it refuses and give their callbacks
 * the error (or drop them if there is no callback) */
static void EventRemoveBadFD(void)
{
  static struct timeval zero_time;
  int i;

  for (i = 0; i < EventFDRange; i++) {
    if (FD_ISSET(i, &EventReadSet)) {
      FD_ZERO(&EventReadMask);
      FD_SET(i, &EventReadMask);
      if (select(EventFDRange,&EventReadMask,NULL,NULL,&zero_time) < 0) {
        if (EventIOList[i].input_func == NULL) {
          LogError(EVENT_ERR_SELECT,"select",errno,"");
          EventRemoveInput(i);
        }
        else {
          EventIOList[i].input_func(EventIOList[i].input_data,i);
        }
      }
    }
    if (FD_ISSET(i, &EventWriteSet)) {
      FD_ZERO(&EventWriteMask);
      FD_SET(i, &EventWriteMask);
      if (select(EventFDRange,NULL,&EventWriteMask,NULL,&zero_time) < 0) {
        if (EventIOList[i].output_func == NULL) {
          LogError(EVENT_ERR_SELECT,"select",errno,"");
          EventRemoveOutput(i);
        }
        else {
          EventIOList[i].output_func(EventIOList[i].output_data,i);
        }
      }
    }
  }
}
