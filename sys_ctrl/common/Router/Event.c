/*
 * sys_ctrl/common/Router/Event.c
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Event.c
 */

#include "Event.h"
#include "EventMsg.h"
#include <malloc.h>
#include <stddef.h>
#include <errno.h>
#include <sys/types.h>
#include "decomp.h"     /* Ghidra types/macros; remove once the file is cleaned up */

static void EventIOListAlloc(int count);
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
static int EventFDRange;
EventTimerEntry *EventTimerQueue;
EventTimerEntry *EventTimerFreeList;
static int es;
static int ed;
static int ess;
static int eds;
static fd_set EventReadSet;
static fd_set EventWriteSet;
static fd_set EventReadMask;
static fd_set EventWriteMask;
static int EventStopFlag;

char *EventStats(int clear)
{
  static char buf[80];
  
  sprintf((char *)&buf,"input:%d    output:%d    timers:%d    select:%d",EventInputCBCount,
          EventOutputCBCount,EventTimerCBCount,EventSelectCount);
  if (clear != 0) {
    EventOutputCBCount = 0;
    EventInputCBCount = 0;
    EventSelectCount = 0;
    EventTimerCBCount = 0;
  }
  return &buf;
}

static void EventIOListAlloc(int count)
{
  if (EventIOListSize == 0) {
    if (count < 0x80) {
      EventIOListSize = 0x80;
    }
    else {
      EventIOListSize = count + 1;
    }
    EventIOList = malloc(EventIOListSize * 0xd8);
    memset(EventIOList,0,EventIOListSize * 0xd8);
  }
  else if (EventIOListSize <= count) {
    EventIOListSize = count + 1;
    EventIOList = realloc(EventIOList,EventIOListSize * 0xd8);
    memset(EventIOList + count,0,0xd8);
  }
  return;
}

EventID EventAddInput(int fd, void (*input_func)(), EventData client_data, char *desc)
{
  byte *pbVar1;
  char *func_name;
  
  if (fd < 0x401) {
    if (EventIOListSize <= fd) {
      EventIOListAlloc(fd);
    }
    if (EventIOList[fd].input_func != NULL) {
      LogError(-0x1f5,"EventAddInput",0,"");
    }
    EventIOList[fd].input_func = input_func;
    EventIOList[fd].input_data = client_data;
    strcpy(EventIOList[fd].input_desc,"EventAddInput");
    if (desc != NULL) {
      strcpy(EventIOList[fd].input_desc,desc);
    }
    FD_SET(fd, &EventReadSet);
    if (EventFDRange <= fd) {
      EventFDRange = fd + 1;
    }
  }
  else {
    LogError(-500,"EventAddInput",0,"");
    fd = 0x400;
  }
  return fd;
}

void EventReplaceInput(int fd, void (*new_input_func)(), EventData new_client_data, char *new_desc, void (**old_input_func)(), EventData *old_client_data, char *old_desc)
{
  byte *pbVar1;
  char *func_name;
  
  if (fd < 0x401) {
    if (EventIOListSize <= fd) {
      EventIOListAlloc(fd);
    }
    if (old_input_func != NULL) {
      *old_input_func = EventIOList[fd].input_func;
    }
    if (old_client_data != NULL) {
      *old_client_data = EventIOList[fd].input_data;
    }
    if (old_desc != NULL) {
      strcpy(old_desc,EventIOList[fd].input_desc);
    }
    EventIOList[fd].input_func = new_input_func;
    EventIOList[fd].input_data = new_client_data;
    strcpy(EventIOList[fd].input_desc,"EventReplaceInput");
    if (new_desc != NULL) {
      strcpy(EventIOList[fd].input_desc,new_desc);
    }
    FD_SET(fd, &EventReadSet);
    if (EventFDRange <= fd) {
      EventFDRange = fd + 1;
    }
  }
  else {
    LogError(-500,"EventReplaceInput",0,"");
  }
  return;
}

void EventReplaceInputTemp(int fd, void (*new_input_func)(), EventData new_client_data, char *new_desc)
{
  byte *pbVar1;
  char *func_name;
  
  if (fd < 0x401) {
    if (EventIOListSize <= fd) {
      EventIOListAlloc(fd);
    }
    EventIOList[fd].input_func_orig = EventIOList[fd].input_func;
    EventIOList[fd].input_data_orig = EventIOList[fd].input_data;
    strcpy(EventIOList[fd].input_desc_orig,EventIOList[fd].input_desc);
    EventIOList[fd].input_func = new_input_func;
    EventIOList[fd].input_data = new_client_data;
    strcpy(EventIOList[fd].input_desc,"EventReplaceInputTemp");
    if (new_desc != NULL) {
      strcpy(EventIOList[fd].input_desc,new_desc);
    }
    FD_SET(fd, &EventReadSet);
    if (EventFDRange <= fd) {
      EventFDRange = fd + 1;
    }
  }
  else {
    LogError(-500,"EventReplaceInputTemp",0,"");
  }
  return;
}

void EventRestoreInputTemp(int fd)
{
  byte *pbVar1;
  char *func_name;
  
  if (fd < 0x401) {
    if (EventIOListSize <= fd) {
      EventIOListAlloc(fd);
    }
    if (EventIOList[fd].input_func_orig != NULL) {
      EventIOList[fd].input_func = EventIOList[fd].input_func_orig;
      EventIOList[fd].input_data = EventIOList[fd].input_data_orig;
      strcpy(EventIOList[fd].input_desc,EventIOList[fd].input_desc_orig);
    }
    EventIOList[fd].input_func_orig = NULL;
    EventIOList[fd].input_data_orig = (EventData)0x0;
    EventIOList[fd].input_desc_orig[0] = '\0';
    FD_SET(fd, &EventReadSet);
    if (EventFDRange <= fd) {
      EventFDRange = fd + 1;
    }
  }
  else {
    LogError(-500,"EventRestoreInputTemp",0,"");
  }
  return;
}

void EventRemoveInput(EventID id)
{
  byte *pbVar1;
  
  if (id < (uint)EventIOListSize) {
    EventIOList[id].input_func = NULL;
    EventIOList[id].input_data = (EventData)0x0;
    EventIOList[id].input_desc[0] = '\0';
    FD_CLR(id, &EventReadSet);
    FD_CLR(id, &EventReadMask);
    EventSetFDRange(id);
  }
  return;
}

EventID EventAddOutput(int fd, void (*output_func)(), EventData client_data, char *desc)
{
  byte *pbVar1;
  char *func_name;
  
  if (fd < 0x401) {
    if (EventIOListSize <= fd) {
      EventIOListAlloc(fd);
    }
    if (EventIOList[fd].output_func != NULL) {
      LogError(-0x1f6,"EventAddOutput",0,"");
    }
    EventIOList[fd].output_func = output_func;
    EventIOList[fd].output_data = client_data;
    strcpy(EventIOList[fd].output_desc,"EventAddOutput");
    if (desc != NULL) {
      strcpy(EventIOList[fd].output_desc,desc);
    }
    FD_SET(fd, &EventWriteSet);
    if (EventFDRange <= fd) {
      EventFDRange = fd + 1;
    }
  }
  else {
    LogError(-500,"EventAddOutput",0,"");
    fd = 0x400;
  }
  return fd;
}

void EventRemoveOutput(EventID id)
{
  byte *pbVar1;
  
  if (id < (uint)EventIOListSize) {
    EventIOList[id].output_func = NULL;
    EventIOList[id].output_data = (EventData)0x0;
    EventIOList[id].output_desc[0] = '\0';
    FD_CLR(id, &EventWriteSet);
    FD_CLR(id, &EventWriteMask);
    EventSetFDRange(id);
  }
  return;
}

void EventEnableOutput(EventID id, int enable)
{
  byte *pbVar1;
  
  if (enable == 0) {
    FD_CLR(id, &EventWriteSet);
    FD_CLR(id, &EventWriteMask);
  }
  else {
    FD_SET(id, &EventWriteSet);
  }
  return;
}

void EventEnableInput(EventID id, int enable)
{
  byte *pbVar1;
  
  if (enable == 0) {
    FD_CLR(id, &EventReadSet);
    FD_CLR(id, &EventReadMask);
  }
  else {
    FD_SET(id, &EventReadSet);
  }
  return;
}

EventID EventAddTimeOut(long unsigned int seconds, long unsigned int microseconds, void (*timer_func)(), EventData client_data, char *desc)
{
  struct timeval cur_time;
  EventTimerEntry *entry;
  char *func_name;
  
  if (EventTimerFreeList == NULL) {
    entry = malloc(0x54);
    if (entry == NULL) {
      EventTimerErrors = EventTimerErrors + 1;
      LogError(-0x1f7,"EventAddTimeOut",0,"");
      return 0;
    }
  }
  else {
    entry = EventTimerFreeList;
    EventTimerFreeList = EventTimerFreeList->next;
  }
  EventCreateTimeOut(entry,seconds,microseconds,timer_func,client_data,desc);
  EventQueueTimer(entry);
  return (EventID)entry;
}

int EventCreateTimeOut(EventTimerEntry *entry, long unsigned int seconds, long unsigned int microseconds, void (*timer_func)(), EventData client_data, char *desc)
{
  struct timeval cur_time;
  char *func_name;
  
  gettimeofday((struct timeval *)&cur_time,(__timezone_ptr_t)0x0);
  (entry->timer_value).tv_sec = seconds + cur_time.tv_sec;
  (entry->timer_value).tv_usec = microseconds + cur_time.tv_usec;
  while (999999 < (entry->timer_value).tv_usec) {
    (entry->timer_value).tv_usec = (entry->timer_value).tv_usec + -1000000;
    (entry->timer_value).tv_sec = (entry->timer_value).tv_sec + 1;
  }
  do {
    if (-1 < (entry->timer_value).tv_usec) {
LAB_08073238:
      entry->timer_func = timer_func;
      entry->timer_data = client_data;
      if (desc == NULL) {
        sprintf(entry->desc,"T %x",entry);
      }
      else {
        strcpy(entry->desc,desc);
      }
      entry->next = (struct _EventTimerEntry *)0xffffffff;
      return 0;
    }
    if ((entry->timer_value).tv_sec < 1) {
      (entry->timer_value).tv_sec = 0;
      (entry->timer_value).tv_usec = 0;
      goto LAB_08073238;
    }
    (entry->timer_value).tv_usec = (entry->timer_value).tv_usec + 1000000;
    (entry->timer_value).tv_sec = (entry->timer_value).tv_sec + -1;
  } while( true );
}

void EventRemoveTimeOut(EventID id)
{
  EventTimerEntry *last;
  EventTimerEntry *current;
  EventTimerEntry *target;
  
  last = NULL;
  for (current = EventTimerQueue;
      (current != NULL && (current != (EventTimerEntry *)id));
      current = current->next) {
    last = current;
  }
  if (current != NULL) {
    if (last == NULL) {
      EventTimerQueue = current->next;
    }
    else {
      last->next = current->next;
    }
    current->next = EventTimerFreeList;
    EventTimerFreeList = current;
  }
  return;
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

void event_process(int oneshot, fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt)
{
  EventData *ppcVar1;
  code **ppsVar2;
  static struct timeval cur_time;
  static struct timeval wait_time;
  static struct timeval *timeout;
  static EventTimerEntry *tmp;
  static int nevents;
  static int i;
  int *piVar3;
  char *format;
  struct timeval next_time;
  int tpcnt;
  EventTimerEntry *tptr;
  int loop;
  char *func_name;
  
  EventStopFlag = 0;
  loop = 1;
LAB_08073508:
  if (loop == 0) {
    EventStopFlag = 0;
    return;
  }
  if (tlist != NULL) {
    tptr = tlist;
    tpcnt = tcnt;
    next_time.tv_sec = 0x7fffffff;
    next_time.tv_usec = 0;
    gettimeofday((struct timeval *)&cur_time,(__timezone_ptr_t)0x0);
    for (; 999999 < cur_time.tv_usec; cur_time.tv_usec = cur_time.tv_usec + -1000000) {
      cur_time.tv_sec = cur_time.tv_sec + 1;
    }
    for (; cur_time.tv_usec < 0; cur_time.tv_usec = cur_time.tv_usec + 1000000) {
      if (cur_time.tv_sec < 1) {
        cur_time.tv_sec = 0;
        cur_time.tv_usec = 0;
        break;
      }
      cur_time.tv_sec = cur_time.tv_sec + -1;
    }
    do {
      if (tptr == NULL) goto LAB_08073660;
      if (tptr->next == (struct _EventTimerEntry *)0xffffffff) {
        if (((tptr->timer_value).tv_sec < cur_time.tv_sec) ||
           (((tptr->timer_value).tv_sec == cur_time.tv_sec &&
            ((tptr->timer_value).tv_usec < cur_time.tv_usec)))) {
          EventTimerCBCount = EventTimerCBCount + 1;
          (*tptr->timer_func)(tptr->timer_data);
          tptr->next = (struct _EventTimerEntry *)0xfffffffe;
        }
        else if (((tptr->timer_value).tv_sec < next_time.tv_sec) ||
                (((tptr->timer_value).tv_sec == next_time.tv_sec &&
                 ((tptr->timer_value).tv_usec < next_time.tv_usec)))) {
          next_time.tv_sec = (tptr->timer_value).tv_sec;
          next_time.tv_usec = (tptr->timer_value).tv_usec;
        }
      }
      if ((tpcnt != 0) && (tpcnt = tpcnt + -1, tpcnt == 0)) goto LAB_08073660;
      tptr = tptr + 1;
    } while( true );
  }
  if (EventTimerQueue != NULL) {
    gettimeofday((struct timeval *)&cur_time,(__timezone_ptr_t)0x0);
    for (; 999999 < cur_time.tv_usec; cur_time.tv_usec = cur_time.tv_usec + -1000000) {
      cur_time.tv_sec = cur_time.tv_sec + 1;
    }
    for (; cur_time.tv_usec < 0; cur_time.tv_usec = cur_time.tv_usec + 1000000) {
      if (cur_time.tv_sec < 1) {
        cur_time.tv_sec = 0;
        cur_time.tv_usec = 0;
        break;
      }
      cur_time.tv_sec = cur_time.tv_sec + -1;
    }
    do {
      if ((cur_time.tv_sec <= (EventTimerQueue->timer_value).tv_sec) &&
         (((EventTimerQueue->timer_value).tv_sec != cur_time.tv_sec ||
          (cur_time.tv_usec <= (EventTimerQueue->timer_value).tv_usec)))) goto LAB_08073810;
      tmp = EventTimerQueue;
      EventTimerCBCount = EventTimerCBCount + 1;
      ppcVar1 = &EventTimerQueue->timer_data;
      ppsVar2 = &EventTimerQueue->timer_func;
      EventTimerQueue = EventTimerQueue->next;
      (**ppsVar2)(*ppcVar1);
      tmp->next = EventTimerFreeList;
      EventTimerFreeList = tmp;
      if ((EventTimerQueue == NULL) || (EventStopFlag != 0)) goto LAB_08073810;
    } while( true );
  }
  if (EventFDRange < 1) {
    return;
  }
  timeout = NULL;
  goto LAB_080738ba;
LAB_08073660:
  if (EventStopFlag != 0) {
    EventStopFlag = 0;
    return;
  }
  if (next_time.tv_sec == 0x7fffffff) {
    timeout = NULL;
  }
  else {
    wait_time.tv_usec = next_time.tv_usec - cur_time.tv_usec;
    if (wait_time.tv_usec < 0) {
      wait_time.tv_usec = wait_time.tv_usec + 1000000;
      wait_time.tv_sec = (next_time.tv_sec - cur_time.tv_sec) + -1;
    }
    else {
      wait_time.tv_sec = next_time.tv_sec - cur_time.tv_sec;
    }
    timeout = (struct timeval *)&wait_time;
  }
  goto LAB_080738ba;
LAB_08073810:
  if (EventStopFlag != 0) {
    EventStopFlag = 0;
    return;
  }
  if (EventTimerQueue == NULL) {
    timeout = NULL;
  }
  else {
    wait_time.tv_usec = (EventTimerQueue->timer_value).tv_usec - cur_time.tv_usec;
    if (wait_time.tv_usec < 0) {
      wait_time.tv_usec = wait_time.tv_usec + 1000000;
      wait_time.tv_sec = ((EventTimerQueue->timer_value).tv_sec - cur_time.tv_sec) + -1;
    }
    else {
      wait_time.tv_sec = (EventTimerQueue->timer_value).tv_sec - cur_time.tv_sec;
    }
    timeout = (struct timeval *)&wait_time;
  }
LAB_080738ba:
  fdset_and(&EventReadMask,&EventReadSet,rd_subset);
  fdset_and(&EventWriteMask,&EventWriteSet,wr_subset);
  if ((oneshot != 0) &&
     ((timeout == NULL || (10 < timeout->tv_sec * 1000000 + timeout->tv_usec)))) {
    timeout = (struct timeval *)&wait_time;
    wait_time.tv_sec = 0;
    wait_time.tv_usec = 10;
  }
  EventSelectCount = EventSelectCount + 1;
  nevents = select(EventFDRange,(fd_set *)&EventReadMask,(fd_set *)&EventWriteMask,NULL,
                   (struct timeval *)timeout);
  if (nevents == -1) {
    piVar3 = __errno_location();
    if (*piVar3 != 4) {
      if (*piVar3 != 9) {
        format = "";
        piVar3 = __errno_location();
        LogError(-0x1f8,"select",*piVar3,format);
        return;
      }
      EventRemoveBadFD();
    }
  }
  else if ((EventStopFlag == 0) && (0 < nevents)) {
    i = 0;
    while ((i < EventFDRange && (EventStopFlag == 0))) {
      if ((true) &&
         (FD_ISSET(i, &EventWriteMask) != 0)) {
        if (EventIOList[i].output_func == NULL) {
          LogError(-0x1fa,"EventStart",0,"");
          EventRemoveOutput(i);
        }
        else {
          EventOutputCBCount = EventOutputCBCount + 1;
          (*EventIOList[i].output_func)(EventIOList[i].output_data,i);
        }
      }
      i = i + 1;
    }
    i = 0;
    while ((i < EventFDRange && (EventStopFlag == 0))) {
      if ((true) &&
         (FD_ISSET(i, &EventReadMask) != 0)) {
        if (EventIOList[i].input_func == NULL) {
          LogError(-0x1f9,"EventStart",0,"");
          EventRemoveInput(i);
        }
        else {
          EventInputCBCount = EventInputCBCount + 1;
          (*EventIOList[i].input_func)(EventIOList[i].input_data,i);
        }
      }
      i = i + 1;
    }
  }
  if (EventStopFlag != 0) {
    EventStopFlag = 0;
    return;
  }
  loop = loop - oneshot;
  goto LAB_08073508;
}

void EventStart(void)
{
  event_process(0,NULL,NULL,NULL,0);
  return;
}

void EventDispatch(void)
{
  event_process(1,NULL,NULL,NULL,0);
  return;
}

void EventStartSubset(fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt)
{
  event_process(0,rd_subset,wr_subset,tlist,tcnt);
  return;
}

void EventDispatchSubset(fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt)
{
  event_process(1,rd_subset,wr_subset,tlist,tcnt);
  return;
}

void EventStop(void)
{
  EventStopFlag = 1;
  return;
}

static void EventSetFDRange(int fd)
{
  int i;
  
  if (EventFDRange <= fd + 1) {
    EventFDRange = 0;
    for (i = fd; -1 < i; i = i + -1) {
      if ((EventIOList[i].input_func != NULL) ||
         (EventIOList[i].output_func != NULL)) {
        EventFDRange = i + 1;
        return;
      }
    }
  }
  return;
}

static void EventQueueTimer(EventTimerEntry *entry)
{
  EventTimerEntry *current;
  EventTimerEntry **last;
  
  last = &EventTimerQueue;
  current = EventTimerQueue;
  while (((current != NULL &&
          ((current->timer_value).tv_sec <= (entry->timer_value).tv_sec)) &&
         (((entry->timer_value).tv_sec != (current->timer_value).tv_sec ||
          ((current->timer_value).tv_usec <= (entry->timer_value).tv_usec))))) {
    last = &current->next;
    current = *last;
  }
  *last = entry;
  entry->next = current;
  return;
}

static void EventRemoveBadFD(void)
{
  byte *pbVar1;
  static struct timeval zero_time;
  int *piVar2;
  int iVar3;
  __fd_mask *p_Var4;
  int __d1;
  char *pcVar5;
  char __result;
  int __d0;
  int i;
  
  for (i = 0; i < EventFDRange; i = i + 1) {
    if (FD_ISSET(i, &EventReadSet) != 0) {
      FD_ZERO(&EventReadMask);
      FD_SET(i, &EventReadMask);
      iVar3 = select(EventFDRange,(fd_set *)&EventReadMask,NULL,NULL,
                     (struct timeval *)&zero_time);
      if (iVar3 < 0) {
        if (EventIOList[i].input_func == NULL) {
          pcVar5 = "";
          piVar2 = __errno_location();
          LogError(-0x1f8,"select",*piVar2,pcVar5);
          EventRemoveInput(i);
        }
        else {
          (*EventIOList[i].input_func)(EventIOList[i].input_data,i);
        }
      }
    }
    if (FD_ISSET(i, &EventWriteSet) != 0) {
      __d1 = (int)&EventWriteMask;
      for (iVar3 = 0x20; iVar3 != 0; iVar3 = iVar3 + -1) {
        *(undefined4 *)__d1 = 0;
        __d1 = __d1 + 4;
      }
      FD_SET(i, &EventWriteMask);
      iVar3 = select(EventFDRange,NULL,(fd_set *)&EventWriteMask,NULL,
                     (struct timeval *)&zero_time);
      if (iVar3 < 0) {
        if (EventIOList[i].output_func == NULL) {
          pcVar5 = "";
          piVar2 = __errno_location();
          LogError(-0x1f8,"select",*piVar2,pcVar5);
          EventRemoveOutput(i);
        }
        else {
          (*EventIOList[i].output_func)(EventIOList[i].output_data,i);
        }
      }
    }
  }
  return;
}
