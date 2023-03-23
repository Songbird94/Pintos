#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "lib/kernel/list.h"
#include <stdint.h>

#include "threads/synch.h"

typedef char lock_t;
typedef char sema_t;

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* File descriptor table entry implementing using Pintos list structures. */
struct file_desc_entry {
  int fd;
  const char *file_name;
  struct file* fptr;
  struct list_elem elem;
};

/* An entry that stores the mapping between the lock_t that users interact with
   and the actual lock struct. Added for Project 2. */
struct user_lock_entry {
  lock_t user_lock_id; // Unique char representing a lock for a user.
  struct lock lock; // The actual lock struct (hidden from the user).
  struct list_elem elem; // Compatibility with Pintos lists.
};

/* An entry that stores the mapping between the lock_t that users interact with
   and the actual lock struct. Added for Project 2. */
struct user_sema_entry {
  sema_t user_sema_id; // Unique char representing a sema for a user.
  struct semaphore sema; // The actual sema struct (hidden from the user).
  struct list_elem elem; // Compatibility with Pintos lists.
};

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;          /* Page directory. */
  char process_name[16];      /* Name of the main thread */
  struct thread* main_thread; /* Pointer to main thread */
  
  struct list file_desc_entry_list; /* File descriptor table for this process. */
  int next_available_fd; /* Next available file descriptor for easy assignment when opening new files. */
  struct file *exec; /* Pointer to the current file being executed. */

  /* Added by Jimmy for Project 2. */
  struct list user_locks;
  struct list user_semaphores;
  struct lock syscall_lock;
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
