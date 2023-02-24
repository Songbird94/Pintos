#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"

#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

static void syscall_handler(struct intr_frame*);
static int validate_syscall_arg(uint32_t *args UNUSED, int args_count);
static void syscall_halt(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_exit(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_exec(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_wait(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_practice(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_create(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_remove(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_open(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_filesize(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_read(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_write(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_seek(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_tell(uint32_t *args UNUSED, uint32_t *eax UNUSED);
static void syscall_close(uint32_t *args UNUSED, uint32_t *eax UNUSED);


struct file_desc_entry *find_entry_by_fd(int fd);
static void find_next_available_fd(void);

bool create(const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell(int fd);
void close (int fd);

struct lock file_global_lock; /* Global file lock. Added by Jimmy. */

/* Helper function for finding entries in the process file descriptor table by their file descriptor number.
   Returns NULL if no file with the specified fd is found.
   Added by Jimmy. */
struct file_desc_entry *find_entry_by_fd(int fd) {
  struct list *table = &thread_current()->pcb->file_desc_entry_list;
  struct list_elem *e;
  for (e = list_begin(table); e != list_end(table); e = list_next(e)) {
    struct file_desc_entry *f = list_entry(e, struct file_desc_entry, elem);
    if (f->fd == fd) {
      return f;
    }
  }
  return NULL;
}


/* Helper function for setting the process' next available file descriptor number for easy bookmarking when adding
  new files in the future.
  Added by Jimmy. */
static void find_next_available_fd() {
  struct list *table = &thread_current()->pcb->file_desc_entry_list;
  struct list_elem *e;
  int current = 2;
  for (e = list_begin(table); e != list_end(table); e = list_next(e)) {
    struct file_desc_entry *f = list_entry(e, struct file_desc_entry, elem);
    if (f->fd > current) {
      thread_current()->pcb->next_available_fd = current;
      return;
    }
    current += 1;
  }
  thread_current()->pcb->next_available_fd = current;
  return;
}


void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_global_lock); /* Initializing the global file lock. Added by Jimmy. */
}

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
    case SYS_CREATE:
      lock_acquire(&file_global_lock);
      syscall_create(args, &f->eax);
      lock_release(&file_global_lock);
      break;
    case SYS_REMOVE:
      lock_acquire(&file_global_lock);
      syscall_remove(args, &f->eax);
      lock_release(&file_global_lock);
      break;
    case SYS_OPEN:
      lock_acquire(&file_global_lock);
      syscall_open(args, &f->eax);
      lock_release(&file_global_lock);
      break;
    case SYS_FILESIZE:
      lock_acquire(&file_global_lock);
      syscall_filesize(args, &f->eax);
      lock_release(&file_global_lock);
      break;
    case SYS_READ:
      lock_acquire(&file_global_lock);
      syscall_read(args, &f->eax);
      lock_release(&file_global_lock);
      break;
    case SYS_WRITE:
      lock_acquire(&file_global_lock);
      if (args[1] == 1) {
        putbuf((char *) args[2], args[3]);
      }
      syscall_write(args, &f->eax);
      lock_release(&file_global_lock);
      break;
    case SYS_SEEK:
      lock_acquire(&file_global_lock);
      syscall_seek(args, &f->eax);
      lock_release(&file_global_lock);
      break;
    case SYS_TELL:
      lock_acquire(&file_global_lock);
      syscall_tell(args, &f->eax);
      lock_release(&file_global_lock);
      break;
    case SYS_CLOSE:
      lock_acquire(&file_global_lock);
      syscall_close(args, &f->eax);
      lock_release(&file_global_lock);
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


/* ================================================================================
 * Filesys functions. Need to wrap a lock_acquire(), lock_release() around these
 * when calling these from syscall_handler(). Written by Jimmy.
 * ================================================================================ */

/* Creates a new file called file initially initial_size bytes in size.
   Returns true if successful, false otherwise.
   Creating a new file does not open it: opening the new file is a separate
   operation which would require an open system call. */
bool create(const char *file, unsigned initial_size) {
  if (file == NULL) {
    return false;
  }
  return filesys_create(file, initial_size);
}

/* Deletes the file named file. Returns true if successful, false otherwise.
   A file may be removed regardless of whether it is open or closed, and removing
   an open file does not close it. */
bool remove(const char *file) {
  if (file == NULL) {
    return false;
  }

  return filesys_remove(file);
}

/* Opens the file named file.
   Returns a nonnegative integer handle called a “file descriptor” (fd),
   or -1 if the file could not be opened.

   File descriptors numbered 0 and 1 are reserved for the console:
   0 (STDIN_FILENO) is standard input and 1 (STDOUT_FILENO) is standard output.
   open should never return either of these file descriptors, which are valid as
   system call arguments only as explicitly described below. */
int open(const char *file) {
  struct file_desc_entry *new_fde = malloc(sizeof(struct file_desc_entry));
  struct file *requested_file = filesys_open(file);
  /* If filesys_open() successful, set attributes of new_fd*/
  if (requested_file == NULL) {
    return -1;
  }

  new_fde->fd = thread_current()->pcb->next_available_fd;
  new_fde->file_name = file;
  new_fde->fptr = requested_file;

  // Find a way to insert in the right place even with gaps in fds.

  find_next_available_fd();
  return 0;
}

/* Returns the size, in bytes, of the open file with file descriptor fd.
   Returns -1 if fd does not correspond to an entry in the file descriptor table. */
int filesize(int fd) {
  struct file_desc_entry *entry = find_entry_by_fd(fd);
  if (entry == NULL) {
    return -1;
  }

  struct file *file = entry->fptr;
  return file_length(file);
}

/* Reads size bytes from the file open as fd into buffer.
   Returns the number of bytes actually read (0 at end of file),
   or -1 if the file could not be read (due to a condition other than end of file,
   such as fd not corresponding to an entry in the file descriptor table).
   STDIN_FILENO reads from the keyboard using the input_getc function in devices/input.c. */
int read(int fd, void *buffer, unsigned size) {
  struct file_desc_entry *entry = find_entry_by_fd(fd);
  if (entry == NULL) {
    return -1;
  }
  struct file *file = entry->fptr;
  int read_bytes = file_read(file, buffer, size);
  return read_bytes;
}

/* Writes size bytes from buffer to the open file with file descriptor fd.
   Returns the number of bytes actually written, which may be less than size if some bytes could not be written.
   Returns -1 if fd does not correspond to an entry in the file descriptor table.

   File descriptor 1 writes to the console. */
int write(int fd, const void *buffer, unsigned size) {
  if (buffer == NULL) {
    return -1;
  }
  if (fd == 1) {
    const char *c_buffer = (const char*) buffer;
    putbuf(c_buffer, size);
    return size;
  }

  struct file_desc_entry *entry = find_entry_by_fd(fd);
  if (entry == NULL) {
    return -1;
  }
  struct file *file = entry->fptr;
  int written_bytes = file_write(file, buffer, size);
  return written_bytes;
}


/* Changes the next byte to be read or written in open file fd to position,
   expressed in bytes from the beginning of the file. Thus, a position of 0 is the file’s start.
   If fd does not correspond to an entry in the file descriptor table, this function should do nothing. */
void seek(int fd, unsigned position) {
  struct file_desc_entry *entry = find_entry_by_fd(fd);
  if (entry == NULL) {
    return;
  }
  struct file *file = entry->fptr;
  file_seek(file, position);
}

/* Returns the position of the next byte to be read or written in open file fd,
   expressed in bytes from the beginning of the file.
   Returns -1 if fd does not correspond to an entry in the file descriptor table. */
unsigned tell(int fd) {
  struct file_desc_entry *entry = find_entry_by_fd(fd);
  if (entry == NULL) {
    return -1;
  }
  struct file *file = entry->fptr;
  unsigned told_bytes = (unsigned) file_tell(file);
  return told_bytes;
}

/* Closes file descriptor fd.
   Exiting or terminating a process must implicitly close all its open file descriptors,
   as if by calling this function for each one.
   Returns -1 if fd does not correspond to an entry in the file descriptor table. */
void close(int fd) {
  struct file_desc_entry *entry = find_entry_by_fd(fd);
  if (entry == NULL) {
    return -1;
  }
  struct file *file = entry->fptr;
  file_close(file);
  return;
}

/* =============================================================================== */
/* syscalls relating to file operations. Added by Jimmy. */
static void syscall_create(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 3)) {
    syscall_exit(args, eax);
  }
  create((char *) args[1], (unsigned) args[2]);
}

static void syscall_remove(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 2)) {
    syscall_exit(args, eax);
  }
  remove((char *) args[1]);
}

static void syscall_open(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 2)) {
    syscall_exit(args, eax);
  }
  open((char *) args[1]);
}

static void syscall_filesize(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 1)) {
    syscall_exit(args, eax);
  }
  filesize((int) args[1]);
}

static void syscall_read(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 4)) {
    syscall_exit(args, eax);
  }
  read((int) args[1], (void *) args[2], (unsigned) args[3]);
}

static void syscall_write(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 4)) {
    syscall_exit(args, eax);
  }
  write((int) args[1], (void *) args[2], (unsigned) args[3]);
}

static void syscall_seek(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 3)) {
    syscall_exit(args, eax);
  }
  seek((int) args[1], (unsigned int) args[2]);
}

static void syscall_tell(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 2)) {
    syscall_exit(args, eax);
  }
  tell((int) args[1]);
}

static void syscall_close(uint32_t *args UNUSED, uint32_t *eax UNUSED) {
  if (!validate_syscall_arg(args, 2)) {
    syscall_exit(args, eax);
  }
  close((int) args[1]);
}