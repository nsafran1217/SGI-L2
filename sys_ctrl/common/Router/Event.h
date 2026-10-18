/*
 * sys_ctrl/common/Router/Event.h
 *
 * Reconstructed from the STABS debug info and Ghidra decompilation of l2, l2term, l2cmd, l2passwd.
 * Original: /data/cf/sysco/scs123.patch/sys_ctrl/common/Router/Event.h
 */

#ifndef SYS_CTRL_COMMON_ROUTER_EVENT_H
#define SYS_CTRL_COMMON_ROUTER_EVENT_H

#include <stdint.h>
#include <sys/time.h>
/* An input/output event's file descriptor, or a timer's EventTimerEntry address
 * (STABS: long unsigned int, which on i386 also held the pointer) */
typedef uintptr_t EventID;
typedef char *EventData;
struct _EventIOEntry {
    void (*input_func)();
    EventData input_data;
    char input_desc[64];
    void (*output_func)();
    EventData output_data;
    char output_desc[64];
    void (*input_func_orig)();
    EventData input_data_orig;
    char input_desc_orig[64];
};
typedef struct _EventIOEntry EventIOEntry;
struct _EventTimerEntry {
    struct timeval timer_value;
    void (*timer_func)();
    EventData timer_data;
    char desc[64];
    struct _EventTimerEntry *next;
};
typedef struct _EventTimerEntry EventTimerEntry;
typedef struct _EventTimerEntry EventTimer;

/* (added by the reconstruction) A timer made with EventCreateTimeOut() is not
 * queued: its next field says EVENT_TIMER_ARMED, and a private timer list run by
 * EventStartSubset()/EventDispatchSubset() sets EVENT_TIMER_FIRED when it fires.
 * (SGI's values: 0xffffffff and 0xfffffffe.) */
#define EVENT_TIMER_ARMED  ((EventTimerEntry *)(uintptr_t)0xffffffff)
#define EVENT_TIMER_FIRED  ((EventTimerEntry *)(uintptr_t)0xfffffffe)

/* prototypes (not recorded in STABS; reconstructed from definitions) */
#include <sys/select.h>   /* for the prototypes */
/* Event.c */
extern EventIOEntry *EventIOList;
extern int EventIOListSize;
extern unsigned int EventIOErrors;
extern unsigned int EventTimerErrors;
extern long unsigned int EventInputCBCount;
extern long unsigned int EventOutputCBCount;
extern long unsigned int EventTimerCBCount;
extern long unsigned int EventSelectCount;
extern EventTimerEntry *EventTimerQueue;
extern EventTimerEntry *EventTimerFreeList;
char *EventStats(int clear);
EventID EventAddInput(int fd, void (*input_func)(), EventData client_data, char *desc);
void EventReplaceInput(int fd, void (*new_input_func)(), EventData new_client_data, char *new_desc, void (**old_input_func)(), EventData *old_client_data, char *old_desc);
void EventReplaceInputTemp(int fd, void (*new_input_func)(), EventData new_client_data, char *new_desc);
void EventRestoreInputTemp(int fd);
void EventRemoveInput(EventID id);
EventID EventAddOutput(int fd, void (*output_func)(), EventData client_data, char *desc);
void EventRemoveOutput(EventID id);
void EventEnableOutput(EventID id, int enable);
void EventEnableInput(EventID id, int enable);
EventID EventAddTimeOut(long unsigned int seconds, long unsigned int microseconds, void (*timer_func)(), EventData client_data, char *desc);
int EventCreateTimeOut(EventTimerEntry *entry, long unsigned int seconds, long unsigned int microseconds, void (*timer_func)(), EventData client_data, char *desc);
void EventRemoveTimeOut(EventID id);
void event_process(int oneshot, fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt);
void EventStart(void);
void EventDispatch(void);
void EventStartSubset(fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt);
void EventDispatchSubset(fd_set *rd_subset, fd_set *wr_subset, EventTimerEntry *tlist, int tcnt);
void EventStop(void);

#endif /* SYS_CTRL_COMMON_ROUTER_EVENT_H */
