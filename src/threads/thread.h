#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
#include "threads/fixed-point.h"

/* States in a thread's life cycle. */
enum thread_status {
  THREAD_RUNNING, /* Running thread. */
  THREAD_READY,   /* Not running but ready to run. */
  THREAD_BLOCKED, /* Waiting for an event to trigger. */
  THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread {
  /* Owned by thread.c. */
  tid_t tid;                 /* Thread identifier. */
  enum thread_status status; /* Thread state. */
  char name[16];             /* Name (for debugging purposes). */
  uint8_t* stack;            /* Saved stack pointer. */
  int priority;              /* Priority. */
  struct list_elem allelem;  /* List element for all threads list. */

  /* Shared between thread.c and synch.c. */
  struct list_elem elem; /* List element. */

  /* For Proj2 priority scheduler*/
  int effective_priority;
  struct list donors; /* List of donor threads that donate priority to this thread. */
  struct thread* donated_to; /* The thread holding the lock this thread is waiting on. */
  struct lock* waiting_on;   /* Pointer to the lock that this thread is waiting on. */
  struct lock change_priority_lock; // do we need it?
  struct list_elem ready_queue_elem; /* List elem for appending this thread to ready list*/
  struct list_elem donors_list_elem; /* List elem for appending THIS thread to ANOTHER's list of donors*/

  //struct list_elem cond_waiters_elem;    /* List elem for appending this thread to a cond var's list of waiters. */
  struct list_elem sema_elem;           /* List elem for appending this thread to a semaphore's waiters list. */


#ifdef USERPROG
  /* Owned by process.c. */
  struct process* pcb; /* Process control block if this thread is a userprog */
  int process_thread_id; /* thread's id within a process */
#endif

  /* Owned by thread.c. */
  unsigned magic; /* Detects stack overflow. */

  struct list childs_status_lst;    /* A list of childs */
  struct semaphore child_sema;      /* Semaphore for parent waiting for child */
  struct child_status *self;        /* Store the child_status struct of the thread */
  struct thread* parent;            /* Parent thread of the thread */
  int exit;                         /* Exit status */
  bool execution;                   /* Execution status */


  /* Added by Jimmy for Project 2. Need a seperate list_elem struct so that thread can be used in another list without conflicting with other lists it can be in.*/
  struct list_elem sleep_elem;

  /* Added by Jimmy for PROJECT 2. Need a new attribute to keep track of earliest wakeup time. */
  int64_t wakeup_time;
};

struct child_status
  {
    tid_t tid;                           /* tid of the child thread */
    struct list_elem elem;               /* list of children */
    struct semaphore wait_sema;          /* semaphore for waiting */
    int exit;                            /* the exit code of child thread */
    bool success;                        /* Execution status of child thread*/
  };

/* Types of scheduler that the user can request the kernel
 * use to schedule threads at runtime. */
enum sched_policy {
  SCHED_FIFO,  // First-in, first-out scheduler
  SCHED_PRIO,  // Strict-priority scheduler with round-robin tiebreaking
  SCHED_FAIR,  // Implementation-defined fair scheduler
  SCHED_MLFQS, // Multi-level Feedback Queue Scheduler
};
#define SCHED_DEFAULT SCHED_FIFO

/* Determines which scheduling policy the kernel should use.
 * Controller by the kernel command-line options
 *  "-sched-default", "-sched-fair", "-sched-mlfqs", "-sched-fifo"
 * Is equal to SCHED_FIFO by default. */
extern enum sched_policy active_sched_policy;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void* aux);
tid_t thread_create(const char* name, int priority, thread_func*, void*);

void thread_block(void);
void thread_unblock(struct thread*);

struct thread* thread_current(void);
tid_t thread_tid(void);
const char* thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func(struct thread* t, void* aux);
void thread_foreach(thread_action_func*, void*);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

/* ======================================================================================= */
/*        Function signatures for new functions added for Project 2. Added by Jimmy.       */
/* ======================================================================================= */

void put_me_to_sleep(int64_t ticks, struct thread *thread);
void wake_sleeping_threads(void);

/* ======================================================================================= */

#endif /* threads/thread.h */
