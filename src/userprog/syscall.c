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
  uint32_t* eax = ((uint32_t*)f->eax);
  uint32_t syscall_num = args[0];
  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }
  /* printf("System call number: %d\n", args[0]); */
  switch(syscall_num){
    case SYS_HALT:
      syscall_halt(args,eax);
      break;
    case SYS_EXIT:
      syscall_exit(args,eax);
      break;
    case SYS_EXEC:
      syscall_exec(args,eax);
      break;
    case SYS_WAIT:
      syscall_wait(args,eax);
      break;
    case SYS_PRACTICE:
      syscall_practice(args,eax);
      break;
    default:
      syscall_exit(args,eax);
  }
}

static int validate_syscall_arg(uint32_t *args UNUSED, int args_count){
  /** 
    Validate `args_count` number of argument under `args` and check for:
      1. Null Pointer
      2. Whether the addr is in memory or not
  */ 

  int is_valid = 1;
  for(int i = 0; i < args_count; i++){
    if (args == NULL){
      // whether the pointer is NULL pointer.
      is_valid = 0;
      break;
    }
    if (!is_user_vaddr((void*)args)){
      // whether the pointer is in user address.
      is_valid = 0;
      break;
    }
    if (!pagedir_get_page(thread_current()->pcb->pagedir,(void*)args)){
      // whether the pointer is unmapped in page table. 
      is_valid = 0;
      break;
    }
  }
  return is_valid;
}

static void syscall_halt(uint32_t *args UNUSED, uint32_t *eax UNUSED){
  shutdown_power_off();
}

static void syscall_exit (uint32_t *args UNUSED, uint32_t *eax UNUSED){
  *eax = (int)args[1];
  printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
  process_exit();
}

static void syscall_exec(uint32_t *args UNUSED, uint32_t *eax UNUSED){
  if (!validate_syscall_arg(args,1)){
    syscall_exit(args,eax);
  }
  char* file_name = (char*) args[1];
  *eax = process_execute(file_name);
}

static void syscall_wait(uint32_t *args UNUSED, uint32_t *eax UNUSED){
}

static void syscall_practice(uint32_t *args UNUSED, uint32_t *eax UNUSED){
  if (!validate_syscall_arg(args,1)){
    syscall_exit(args,eax);
  }
  int i = (int)args[1];
  *eax = i + 1;
}

