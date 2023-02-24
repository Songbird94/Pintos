#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

static void syscall_handler(struct intr_frame*);
static int validate_syscall_arg(uint32_t *args UNUSED, int args_count);
static void syscall_halt(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_exit(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_exec(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_wait(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_practice(uint32_t *args UNUSED, uint32_t *eax UNUSED);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  if(!validate_syscall_arg(args,1)){
    thread_current()->exit = -1;
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, -1);
    process_exit();
  }
  uint32_t syscall_num = args[0];
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  /* printf("System call number: %d\n", args[0]); */
  switch(syscall_num){
    case SYS_HALT:
      syscall_halt(args,&f->eax);
      break;
    case SYS_EXIT:
      syscall_exit(args,&f->eax);
      break;
    case SYS_EXEC:
      syscall_exec(args,&f->eax);
      break;
    case SYS_WAIT:
      syscall_wait(args,&f->eax);
      break;
    case SYS_PRACTICE:
      syscall_practice(args,&f->eax);
      break;

    // file stuff
    case SYS_WRITE:
      if (args[1] == 1) {
        putbuf((char *) args[2], args[3]);
      }
      break;

    default:
      syscall_exit(args,&f->eax);
  }
}

static int validate_syscall_arg(uint32_t *args UNUSED, int args_count){
  /** 
    Validate `args_count` number of argument under `args` and check for:
      1. Null Pointer
      2. Whether the addr is in memory or not
  */ 
  int is_valid = 1;
  for(int i = 0; i < args_count + 1; i++){
    if (args == NULL){
      // whether the pointer is NULL pointer.
      is_valid = 0;
      break;
    }
    if (!is_user_vaddr(args)){
      // whether the pointer is in user address.
      is_valid = 0;
      break;
    }
    if (!pagedir_get_page(thread_current()->pcb->pagedir,args)){
      // whether the pointer is unmapped in page table. 
      is_valid = 0;
      break;
    }
    args++;
  }
  return is_valid;
}

static void syscall_halt(uint32_t *args UNUSED, uint32_t *eax UNUSED){
  shutdown_power_off();
}

static void syscall_exit (uint32_t *args UNUSED, uint32_t *eax UNUSED){
  *eax = args[1];
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
  thread_current()->exit = args[1];
  process_exit();
}

static void syscall_exec(uint32_t *args UNUSED, uint32_t *eax UNUSED){
  if (!validate_syscall_arg(args,1)){
    args[1] = -1;
    thread_current()->exit = -1;
    syscall_exit(args,eax);
  }
  *eax = process_execute((char*) args[1]);
}

static void syscall_wait(uint32_t *args UNUSED, uint32_t *eax UNUSED){
  if (!validate_syscall_arg(args,1)){
    args[1] = -1;
    thread_current()->exit = -1;
    syscall_exit(args,eax);
  }
  *eax = process_wait(args[1]);
}

static void syscall_practice(uint32_t *args UNUSED, uint32_t *eax UNUSED){
  if (!validate_syscall_arg(args,1)){
    args[1] = -1;
    thread_current()->exit = -1;
    syscall_exit(args,eax);
  }
  int i = (int)args[1];
  *eax = i + 1;
}

